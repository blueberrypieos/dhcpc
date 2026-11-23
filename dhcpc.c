/*
 * SPDX-License-Identifier: BSD-2-Clause AND LicenseRef-BSD-3-Clause-ISC
 * Copyright (c) 2026 The Blueberry Pie OS Authors
 *
 * dhcpc: Blueberry Pie OS's DHCP client (RFC 2131, 2132) for Ethernet
 * interfaces.
 *
 *   dhcpc [-1] [-t SECONDS] INTERFACE
 *   dhcpc -a
 *
 * It gets a lease, gives the interface its address and a subnet route of
 * its own, records the lease in /var/run/dhcpc/INTERFACE, then stays in
 * the background to keep it (-1: exit once configured). -t limits the
 * wait for the first lease (default 30 seconds); the exit status says
 * whether one came. Without one, it goes on asking in the background: at
 * boot the link, a switch port (spanning tree holds a new one for 30 s or
 * more) or the server can take longer than that.
 *
 * It follows the interface. When the interface goes, it keeps the lease.
 * When an interface of that name comes back with the same hardware
 * address, it asks for that lease again, and otherwise for a new one. It
 * brings the interface up, so that the link starts, and waits up to 10 s
 * for the link before it asks. When the link comes back, it asks for the
 * lease again. Without an answer the address stays until a new lease
 * binds or the old one ends. A dhcpc that starts takes over the lease an
 * earlier one left for the interface, if its address is still set. An
 * address the interface has without a record, as after a soft reboot, is
 * asked for again with INIT-REBOOT, and goes if no server confirms it; the
 * default route stays meanwhile. An address that does not go when it
 * should is tried again every 5 s.
 *
 * The default route goes through the lowest-numbered connected Ethernet
 * interface with a lease and a router, en0 before en1, and a lease a
 * server has confirmed goes before one that stays without an answer.
 * /var/run/resolv.conf, which /etc/resolv.conf links to, has that lease's
 * name servers, and mDNSResponder, which resolves names, is told. Every
 * dhcpc chooses again when a lease starts or ends, and when an
 * interface's link or flags change. With no interface to choose, the
 * default route dhcpc set goes and resolv.conf has no name servers.
 *
 * -a starts a dhcpc for each Ethernet interface there is, and for each
 * one that appears later, and stays in the foreground. One dhcpc runs for
 * each interface.
 *
 * dhcpc sends and receives through BPF, since the interface has no
 * address to send from at first. Renewing goes through a UDP socket bound
 * to the leased address and the interface.
 */

#include <sys/types.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/kern_event.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sys_domain.h>
#include <sys/time.h>

#include <net/bpf.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_media.h>
#include <net/if_var.h>
#include <net/net_kev.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "client.h"
#include "msg.h"
#include "state.h"

#define CLIENT_PORT     68
#define SERVER_PORT     67
#define STATE_DIR       "/var/run/dhcpc"
#define CHECK_MS        60000   /* how often a worker looks at its interface without an event */
#define RETRY_MS        5000    /* how often a record or an address that would not go is tried again */

static const char *ifname;
static unsigned int ifindex;    /* the interface the client is on, 0 if none */
static uint8_t mac[6];
static int bpf = -1;
static u_int bpflen;
static uint8_t *bpfbuf;
static FILE *logfile;
static bool foreground = true;
static int kev = -1;
static int sink = -1;           /* port 68, so that unicast replies do not draw port unreachables */
static unsigned int bpf_gen;    /* counts BPF's opens and closes */
static uint32_t bpf_client_gen; /* the client's arrival BPF was opened for */
static bool subnet_added, elect_wanted;
static struct record rec;       /* what /var/run/dhcpc/IF says, or is to say */
static bool rec_dirty;          /* rec could not be written */
static int64_t retry_at;        /* when rec and rec's addresses to remove are tried again */
static struct client cl;

static void elect(void);

static int64_t
uptime(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_UPTIME_RAW, &ts);
	return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void
nap(int64_t ms)
{
	struct timespec ts = { (time_t)(ms / 1000), (long)(ms % 1000) * 1000000 };

	while (ms > 0 && nanosleep(&ts, &ts) != 0 && errno == EINTR) {
	}
}

/* To /var/log/dhcpc.log, and to standard error until dhcpc goes to the background. */
static void
logmsg(const char *fmt, ...)
{
	va_list ap;
	char when[32], text[600];
	time_t now = time(NULL);

	va_start(ap, fmt);
	vsnprintf(text, sizeof(text), fmt, ap);
	va_end(ap);
	if (logfile == NULL && (logfile = fopen("/var/log/dhcpc.log", "a")) != NULL) {
		fcntl(fileno(logfile), F_SETFD, FD_CLOEXEC);
	}
	if (logfile != NULL) {
		strftime(when, sizeof(when), "%b %e %H:%M:%S", localtime(&now));
		fprintf(logfile, "%s dhcpc[%d]: %s\n", when, (int)getpid(), text);
		fflush(logfile);
	}
	if (foreground) {
		fprintf(stderr, "dhcpc: %s\n", text);
	}
}

/* The kernel's data link events: interfaces coming and going, links, flags. */
static void
kev_open(void)
{
	struct kev_request req = { KEV_VENDOR_APPLE, KEV_NETWORK_CLASS, KEV_DL_SUBCLASS };

	kev = socket(PF_SYSTEM, SOCK_RAW, SYSPROTO_EVENT);
	if (kev >= 0 && (ioctl(kev, SIOCSKEVFILT, &req) != 0 || fcntl(kev, F_SETFL, O_NONBLOCK) != 0 ||
	    fcntl(kev, F_SETFD, FD_CLOEXEC) != 0)) {
		close(kev);
		kev = -1;
	}
}

/* Call f with each waiting event's interface name and code. */
static void
kev_read(void (*f)(const char *name, uint32_t code))
{
	union {
		struct kern_event_msg m;
		uint8_t buf[1024];
	} in;

	for (;;) {
		ssize_t n = recv(kev, &in, sizeof(in), 0);
		if (n < (ssize_t)(KEV_MSG_HEADER_SIZE + sizeof(struct net_event_data))) {
			break;
		}
		if (in.m.vendor_code != KEV_VENDOR_APPLE || in.m.kev_class != KEV_NETWORK_CLASS ||
		    in.m.kev_subclass != KEV_DL_SUBCLASS) {
			continue;
		}
		const struct net_event_data *d = (const struct net_event_data *)(const void *)in.m.event_data;
		char name[IFNAMSIZ + 16];
		snprintf(name, sizeof(name), "%.*s%u", IFNAMSIZ, d->if_name, d->if_unit);
		f(name, in.m.event_code);
	}
}

/* The interface's hardware address, if it has one of 6 bytes. */
static bool
get_mac(const char *name, uint8_t out[6])
{
	struct ifaddrs *ifa, *p;
	bool found = false;

	if (getifaddrs(&ifa) != 0) {
		return false;
	}
	for (p = ifa; p; p = p->ifa_next) {
		if (p->ifa_addr && p->ifa_addr->sa_family == AF_LINK && !strcmp(p->ifa_name, name)) {
			struct sockaddr_dl *sdl = (struct sockaddr_dl *)(void *)p->ifa_addr;
			if (sdl->sdl_alen == 6) {
				memcpy(out, LLADDR(sdl), 6);
				found = true;
			}
		}
	}
	freeifaddrs(ifa);
	return found;
}

/* Bring the interface up: the driver then starts its link. */
static void
if_up(void)
{
	struct ifreq ifr;
	int s = socket(AF_INET, SOCK_DGRAM, 0);

	if (s < 0) {
		return;
	}
	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (ioctl(s, SIOCGIFFLAGS, &ifr) == 0 && !(ifr.ifr_flags & IFF_UP)) {
		ifr.ifr_flags |= IFF_UP;
		ioctl(s, SIOCSIFFLAGS, &ifr);
	}
	close(s);
}

/* The link is active, or the driver does not report one. */
static bool
link_now(const char *name)
{
	struct ifmediareq ifmr;
	int s = socket(AF_INET, SOCK_DGRAM, 0);
	bool up = true;

	if (s < 0) {
		return true;
	}
	memset(&ifmr, 0, sizeof(ifmr));
	strlcpy(ifmr.ifm_name, name, sizeof(ifmr.ifm_name));
	if (ioctl(s, SIOCGIFMEDIA, &ifmr) == 0 && (ifmr.ifm_status & IFM_AVALID)) {
		up = (ifmr.ifm_status & IFM_ACTIVE) != 0;
	}
	close(s);
	return up;
}

/*
 * The filter program in bpf_open() is from BSD dhclient's bpf.c, under
 * this notice:
 *
 * Copyright (c) 1995, 1996, 1998, 1999
 * The Internet Software Consortium.    All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of The Internet Software Consortium nor the names
 *    of its contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INTERNET SOFTWARE CONSORTIUM AND
 * CONTRIBUTORS ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE INTERNET SOFTWARE CONSORTIUM OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This software has been written for the Internet Software Consortium
 * by Ted Lemon <mellon@fugue.com> in cooperation with Vixie
 * Enterprises.  To learn more about the Internet Software Consortium,
 * see ``http://www.vix.com/isc''.  To learn more about Vixie
 * Enterprises, see ``http://www.vix.com''.
 */

/* A BPF device on the interface that passes UDP datagrams to port 68. */
static void
bpf_open(void)
{
	static struct bpf_insn filter[] = {
		BPF_STMT(BPF_LD + BPF_H + BPF_ABS, 12),                 /* ethertype */
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ETHERTYPE_IP, 0, 8),
		BPF_STMT(BPF_LD + BPF_B + BPF_ABS, 23),                 /* IP protocol */
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, IPPROTO_UDP, 0, 6),
		BPF_STMT(BPF_LD + BPF_H + BPF_ABS, 20),                 /* fragment offset */
		BPF_JUMP(BPF_JMP + BPF_JSET + BPF_K, 0x1fff, 4, 0),
		BPF_STMT(BPF_LDX + BPF_B + BPF_MSH, 14),                /* IP header length */
		BPF_STMT(BPF_LD + BPF_H + BPF_IND, 16),                 /* UDP destination port */
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, CLIENT_PORT, 0, 1),
		BPF_STMT(BPF_RET + BPF_K, (u_int)-1),
		BPF_STMT(BPF_RET + BPF_K, 0),
	};
	struct bpf_program prog = { sizeof(filter) / sizeof(filter[0]), filter };

	struct ifreq ifr;
	u_int one = 1;
	char dev[16];

	for (int i = 0; i < 256 && bpf < 0; i++) {
		snprintf(dev, sizeof(dev), "/dev/bpf%d", i);
		bpf = open(dev, O_RDWR);
		if (bpf < 0 && errno != EBUSY) {
			break;
		}
	}
	if (bpf < 0) {
		logmsg("%s: no BPF device: %s", ifname, strerror(errno));
		return;
	}
	bpf_gen++;
	bpf_client_gen = cl.gen;
	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (fcntl(bpf, F_SETFL, O_NONBLOCK) != 0 || fcntl(bpf, F_SETFD, FD_CLOEXEC) != 0 ||
	    ioctl(bpf, BIOCSETIF, &ifr) < 0 || ioctl(bpf, BIOCIMMEDIATE, &one) < 0 ||
	    ioctl(bpf, BIOCSHDRCMPLT, &one) < 0 || ioctl(bpf, BIOCSETF, &prog) < 0 ||
	    ioctl(bpf, BIOCGBLEN, &bpflen) < 0 || ioctl(bpf, BIOCFLUSH) < 0) {
		logmsg("%s: BPF: %s", ifname, strerror(errno));
		close(bpf);
		bpf = -1;
		return;
	}
	free(bpfbuf);
	bpfbuf = malloc(bpflen);
	if (bpfbuf == NULL) {
		err(1, "malloc");
	}
}

static void
bpf_close(void)
{
	if (bpf >= 0) {
		close(bpf);
		bpf_gen++;
	}
	bpf = -1;
}

/* BPF is on the interface the client follows: its name, index and hardware address. */
static bool
bpf_is_ours(void)
{
	struct ifreq ifr;
	uint8_t now[6];

	memset(&ifr, 0, sizeof(ifr));
	return bpf >= 0 && ioctl(bpf, BIOCGETIF, &ifr) == 0 &&
	    strncmp(ifr.ifr_name, ifname, sizeof(ifr.ifr_name)) == 0 && if_nametoindex(ifname) == ifindex &&
	    get_mac(ifname, now) && memcmp(now, mac, sizeof(now)) == 0;
}

static struct sockaddr_in
sin_of(struct in_addr a)
{
	struct sockaddr_in s;
	memset(&s, 0, sizeof(s));
	s.sin_len = sizeof(s);
	s.sin_family = AF_INET;
	s.sin_addr = a;
	return s;
}

/*
 * Renewing: m through a UDP socket from port 68 at the leased address to
 * the server, which the kernel routes on this interface.
 */
static void
send_unicast(const struct csend *m, const char *host)
{
	uint8_t d[MSG_DHCP_MAX];
	struct sockaddr_in from = sin_of(m->ciaddr), to = sin_of(m->dst);
	size_t len = msg_payload(d, m, mac, host);
	int one = 1, s = socket(AF_INET, SOCK_DGRAM, 0);

	from.sin_port = htons(CLIENT_PORT);
	to.sin_port = htons(SERVER_PORT);
	if (s < 0 || fcntl(s, F_SETFD, FD_CLOEXEC) != 0 ||
	    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) != 0 ||
	    setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one)) != 0 ||
	    setsockopt(s, IPPROTO_IP, IP_BOUND_IF, &ifindex, sizeof(ifindex)) != 0 ||
	    bind(s, (struct sockaddr *)&from, sizeof(from)) != 0 ||
	    sendto(s, d, len, 0, (struct sockaddr *)&to, sizeof(to)) != (ssize_t)len) {
		logmsg("%s: renewing with %s: %s", ifname, inet_ntoa(m->dst), strerror(errno));
	}
	if (s >= 0) {
		close(s);
	}
}

/* Send m: broadcast through BPF, or through a UDP socket when it is unicast. */
static void
send_msg(const struct csend *m)
{
	uint8_t frame[MSG_FRAME_MAX];
	char host[256];
	size_t len;

	if (gethostname(host, sizeof(host)) != 0) {
		host[0] = '\0';
	}
	host[sizeof(host) - 1] = '\0';
	if (m->unicast) {
		send_unicast(m, host);
		return;
	}
	if (bpf < 0) {
		return;
	}
	len = msg_build(frame, m, mac, host);
	if (write(bpf, frame, len) != (ssize_t)len) {
		logmsg("%s: send: %s", ifname, strerror(errno));
	}
}

static void
del_addr(struct in_addr addr)
{
	struct ifreq ifr;
	int s = socket(AF_INET, SOCK_DGRAM, 0);
	struct sockaddr_in sin = sin_of(addr);

	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	memcpy(&ifr.ifr_addr, &sin, sizeof(sin));
	ioctl(s, SIOCDIFADDR, &ifr);
	close(s);
}

static bool
set_addr(const struct lease *l)
{
	struct ifaliasreq ifra;
	struct in_addr bcast = lease_broadcast(l);
	int s = socket(AF_INET, SOCK_DGRAM, 0);
	bool ok;

	memset(&ifra, 0, sizeof(ifra));
	strlcpy(ifra.ifra_name, ifname, sizeof(ifra.ifra_name));
	struct sockaddr_in a = sin_of(l->addr), m = sin_of(l->mask), b = sin_of(bcast);
	memcpy(&ifra.ifra_addr, &a, sizeof(a));
	memcpy(&ifra.ifra_mask, &m, sizeof(m));
	memcpy(&ifra.ifra_broadaddr, &b, sizeof(b));
	ok = ioctl(s, SIOCAIFADDR, &ifra) == 0;
	if (!ok) {
		logmsg("SIOCAIFADDR: %s", strerror(errno));
	}
	close(s);
	return ok;
}

/* Change the default route to go through the router on interface name, or add it. */
static bool
set_default_route(struct in_addr router, const char *name)
{
	struct {
		struct rt_msghdr rtm;
		struct sockaddr_in dst, gw, mask;
		struct sockaddr_dl ifp;
	} msg;
	int s = socket(PF_ROUTE, SOCK_RAW, AF_INET);
	unsigned int index = if_nametoindex(name);
	bool ok = false;

	if (s < 0 || router.s_addr == 0 || index == 0) {
		if (s >= 0) close(s);
		return false;
	}
	for (int type = RTM_CHANGE;; type = RTM_ADD) {
		struct in_addr any = { 0 };
		memset(&msg, 0, sizeof(msg));
		msg.rtm.rtm_msglen = sizeof(msg);
		msg.rtm.rtm_version = RTM_VERSION;
		msg.rtm.rtm_type = (u_char)type;
		msg.rtm.rtm_flags = RTF_UP | RTF_GATEWAY | RTF_STATIC;
		msg.rtm.rtm_addrs = RTA_DST | RTA_GATEWAY | RTA_NETMASK | RTA_IFP;
		msg.rtm.rtm_seq = 1;
		msg.rtm.rtm_pid = getpid();
		msg.dst = sin_of(any);
		msg.gw = sin_of(router);
		msg.mask = sin_of(any);
		msg.ifp.sdl_len = sizeof(msg.ifp);
		msg.ifp.sdl_family = AF_LINK;
		msg.ifp.sdl_index = (u_short)index;
		if (write(s, &msg, sizeof(msg)) >= 0) {
			ok = true;
			break;
		}
		if (errno != ESRCH || type == RTM_ADD) {
			logmsg("default route: %s", strerror(errno));
			break;
		}
	}
	close(s);
	return ok;
}

/*
 * The lease's subnet route, scoped to the interface, as route add -net
 * NET -interface IF -ifscope IF makes it: xnu adds none for a second
 * interface on a subnet that has one. Deleted only if added here, or
 * found already there, as after a soft reboot.
 */
static void
subnet_route(int type, const struct lease *l)
{
	struct {
		struct rt_msghdr rtm;
		struct sockaddr_in dst;
		struct sockaddr_dl gw;
		struct sockaddr_in mask;
	} msg;
	struct ifaddrs *ifa, *p;
	struct in_addr net = { l->addr.s_addr & l->mask.s_addr };
	unsigned int index = if_nametoindex(ifname);
	int s;

	if (index == 0 || (type == RTM_DELETE && !subnet_added)) {
		return;
	}
	memset(&msg, 0, sizeof(msg));
	msg.gw.sdl_len = sizeof(msg.gw);
	msg.gw.sdl_family = AF_LINK;
	msg.gw.sdl_index = (u_short)index;
	if (getifaddrs(&ifa) == 0) {
		for (p = ifa; p; p = p->ifa_next) {
			if (p->ifa_addr && p->ifa_addr->sa_family == AF_LINK && !strcmp(p->ifa_name, ifname) &&
			    p->ifa_addr->sa_len <= sizeof(msg.gw)) {
				memcpy(&msg.gw, p->ifa_addr, p->ifa_addr->sa_len);
				msg.gw.sdl_len = sizeof(msg.gw);
			}
		}
		freeifaddrs(ifa);
	}
	msg.rtm.rtm_msglen = sizeof(msg);
	msg.rtm.rtm_version = RTM_VERSION;
	msg.rtm.rtm_type = (u_char)type;
	msg.rtm.rtm_flags = RTF_UP | RTF_STATIC | RTF_IFSCOPE;
	msg.rtm.rtm_index = (u_short)index;
	msg.rtm.rtm_addrs = RTA_DST | RTA_GATEWAY | RTA_NETMASK;
	msg.rtm.rtm_seq = 1;
	msg.rtm.rtm_pid = getpid();
	msg.dst = sin_of(net);
	msg.mask = sin_of(l->mask);
	s = socket(PF_ROUTE, SOCK_RAW, AF_INET);
	if (s < 0) {
		return;
	}
	if (write(s, &msg, sizeof(msg)) >= 0 || type == RTM_DELETE) {
		subnet_added = type == RTM_ADD;
	} else if (errno == EEXIST) {
		subnet_added = true;
	} else {
		logmsg("%s: subnet route: %s", ifname, strerror(errno));
	}
	close(s);
}

/*
 * Write /var/run/resolv.conf from interface name's lease, if it changes it,
 * even with no name servers; with l NULL, for no lease.
 */
static void
write_resolv_conf(const char *name, const struct lease *l)
{
	const char *tmp = "/var/run/resolv.conf.dhcpc";
	char text[1024], old[1024];
	size_t len = resolv_text(text, sizeof(text), name, l);
	FILE *f;

	if (len >= sizeof(text)) {
		return;
	}
	f = fopen("/var/run/resolv.conf", "r");
	if (f != NULL) {
		size_t n = fread(old, 1, sizeof(old), f);
		fclose(f);
		if (n == len && memcmp(old, text, len) == 0) {
			return;
		}
	}
	f = fopen(tmp, "w");
	if (f == NULL) {
		logmsg("%s: %s", tmp, strerror(errno));
		return;
	}
	fwrite(text, 1, len, f);
	if (fclose(f) != 0 || rename(tmp, "/var/run/resolv.conf") != 0) {
		logmsg("/var/run/resolv.conf: %s", strerror(errno));
		return;
	}
	/* mDNSResponder re-reads it on a hangup. */
	FILE *pidf = fopen("/var/run/mDNSResponder.pid", "r");
	int pid;
	if (pidf != NULL) {
		if (fscanf(pidf, "%d", &pid) == 1 && pid > 1) {
			kill(pid, SIGHUP);
		}
		fclose(pidf);
	}
}

/* Write len bytes of text to path through path.new and a rename, so that path is whole or as it was. */
static bool
write_file(const char *path, const char *text, size_t len)
{
	char tmp[80];
	bool ok;
	int fd;

	snprintf(tmp, sizeof(tmp), "%s.new", path);
	fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
	if (fd < 0) {
		logmsg("%s: %s", tmp, strerror(errno));
		return false;
	}
	ok = write(fd, text, len) == (ssize_t)len;
	if (close(fd) != 0 || !ok || rename(tmp, path) != 0) {
		logmsg("%s: %s", path, strerror(errno));
		unlink(tmp);
		return false;
	}
	return true;
}

/* path's text into buf, which holds cap bytes: its length, or -1 if it is not there or does not fit. */
static ssize_t
read_file(const char *path, char *buf, size_t cap)
{
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	size_t len = 0;
	ssize_t n;

	if (fd < 0) {
		return -1;
	}
	while (len < cap && (n = read(fd, buf + len, cap - len)) > 0) {
		len += (size_t)n;
	}
	close(fd);
	return len < cap ? (ssize_t)len : -1;
}

/*
 * Write rec to /var/run/dhcpc/IF, for the election and for a dhcpc that
 * takes the interface over. If it cannot be written, it is tried again.
 */
static bool
save(void)
{
	char path[64], text[STATE_TEXT_MAX];
	size_t len;

	memcpy(rec.mac, mac, sizeof(rec.mac));
	rec.ifindex = ifindex;
	if (ifindex == 0) {
		rec.has_lease = false;
	}
	len = record_format(text, sizeof(text), &rec);
	mkdir(STATE_DIR, 0755);
	snprintf(path, sizeof(path), STATE_DIR "/%s", ifname);
	rec_dirty = len >= sizeof(text) || !write_file(path, text, len);
	return !rec_dirty;
}

/* Interface name's record, if there is one and it is whole. */
static bool
read_state(const char *name, struct record *r)
{
	char path[64], text[STATE_TEXT_MAX];
	ssize_t len;

	snprintf(path, sizeof(path), STATE_DIR "/%s", name);
	len = read_file(path, text, sizeof(text));
	return len >= 0 && record_parse(text, (size_t)len, r);
}

#define MARKER  STATE_DIR "/.default"

/* The marker of the default routes dhcpc set, if it is there and whole. */
static bool
read_marker(struct marker *m)
{
	char text[STATE_TEXT_MAX];
	ssize_t len = read_file(MARKER, text, sizeof(text));

	memset(m, 0, sizeof(*m));
	return len >= 0 && marker_parse(text, (size_t)len, m);
}

static bool
write_marker(const struct marker *m)
{
	char text[STATE_TEXT_MAX];
	size_t len = marker_format(text, sizeof(text), m);

	return len < sizeof(text) && write_file(MARKER, text, len);
}

/* Whether interface name has addr, or its addresses could not be read. */
static enum addrstate
addr_state(const char *name, struct in_addr addr)
{
	struct ifaddrs *ifa, *p;
	enum addrstate st = ADDR_ABSENT;

	if (getifaddrs(&ifa) != 0) {
		return ADDR_UNKNOWN;
	}
	for (p = ifa; p; p = p->ifa_next) {
		if (p->ifa_addr && p->ifa_addr->sa_family == AF_INET && !strcmp(p->ifa_name, name) &&
		    ((struct sockaddr_in *)(void *)p->ifa_addr)->sin_addr.s_addr == addr.s_addr) {
			st = ADDR_SET;
		}
	}
	freeifaddrs(ifa);
	return st;
}

/* Interface name has addr. */
static bool
has_addr(const char *name, struct in_addr addr)
{
	return addr_state(name, addr) == ADDR_SET;
}

/* Interface name's first IPv4 address, and its mask. */
static bool
first_inet(const char *name, struct in_addr *addr, struct in_addr *mask)
{
	struct ifaddrs *ifa, *p;
	bool found = false;

	if (getifaddrs(&ifa) != 0) {
		return false;
	}
	for (p = ifa; p && !found; p = p->ifa_next) {
		if (p->ifa_addr && p->ifa_addr->sa_family == AF_INET && !strcmp(p->ifa_name, name)) {
			*addr = ((struct sockaddr_in *)(void *)p->ifa_addr)->sin_addr;
			mask->s_addr = p->ifa_netmask != NULL ?
			    ((struct sockaddr_in *)(void *)p->ifa_netmask)->sin_addr.s_addr : 0;
			found = true;
		}
	}
	freeifaddrs(ifa);
	return found;
}

/* Interface name has addr, with mask and broadcast. */
static bool
addr_as(const char *name, struct in_addr addr, struct in_addr *mask, struct in_addr *broadcast)
{
	struct ifaddrs *ifa, *p;
	bool found = false;

	if (getifaddrs(&ifa) != 0) {
		return false;
	}
	for (p = ifa; p && !found; p = p->ifa_next) {
		if (p->ifa_addr && p->ifa_addr->sa_family == AF_INET && !strcmp(p->ifa_name, name) &&
		    ((struct sockaddr_in *)(void *)p->ifa_addr)->sin_addr.s_addr == addr.s_addr) {
			mask->s_addr = p->ifa_netmask != NULL ?
			    ((struct sockaddr_in *)(void *)p->ifa_netmask)->sin_addr.s_addr : 0;
			broadcast->s_addr = p->ifa_broadaddr != NULL && p->ifa_broadaddr->sa_family == AF_INET ?
			    ((struct sockaddr_in *)(void *)p->ifa_broadaddr)->sin_addr.s_addr : 0;
			found = true;
		}
	}
	freeifaddrs(ifa);
	return found;
}

/* Up, running, and with an active link where the media says. */
static bool
connected(const char *name)
{
	struct ifreq ifr;
	int s = socket(AF_INET, SOCK_DGRAM, 0);
	bool up = false;

	if (s < 0) {
		return false;
	}
	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, name, sizeof(ifr.ifr_name));
	if (ioctl(s, SIOCGIFFLAGS, &ifr) == 0 && (ifr.ifr_flags & (IFF_UP | IFF_RUNNING)) == (IFF_UP | IFF_RUNNING)) {
		up = link_now(name);
	}
	close(s);
	return up;
}

/* An RTM_GET reply: its header, and its addresses, each copied into a whole sockaddr_in. */
struct rtget {
	struct rt_msghdr rtm;
	struct sockaddr_in sa[RTAX_MAX];
};

/* The route to dst with mask, scoped to the interface with index if it is not 0. */
static enum probe
route_get(struct in_addr dst, struct in_addr mask, unsigned int index, struct rtget *g)
{
	struct {
		struct rt_msghdr rtm;
		uint8_t space[512];
	} msg;
	struct sockaddr_in d = sin_of(dst), m = sin_of(mask);
	struct timeval tv = { 1, 0 };
	pid_t pid = getpid();
	enum probe found = PROBE_FAILED;
	int s = socket(PF_ROUTE, SOCK_RAW, AF_INET);

	memset(g, 0, sizeof(*g));
	if (s < 0) {
		return PROBE_FAILED;
	}
	setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	memset(&msg, 0, sizeof(msg));
	msg.rtm.rtm_version = RTM_VERSION;
	msg.rtm.rtm_type = RTM_GET;
	msg.rtm.rtm_addrs = RTA_DST | RTA_NETMASK;
	msg.rtm.rtm_flags = index != 0 ? RTF_IFSCOPE : 0;
	msg.rtm.rtm_index = (u_short)index;
	msg.rtm.rtm_seq = 2;
	msg.rtm.rtm_pid = pid;
	memcpy(msg.space, &d, sizeof(d));
	memcpy(msg.space + sizeof(d), &m, sizeof(m));
	msg.rtm.rtm_msglen = (u_short)(sizeof(msg.rtm) + sizeof(d) + sizeof(m));
	if (write(s, &msg, msg.rtm.rtm_msglen) < 0) {
		found = errno == ESRCH ? PROBE_NONE : PROBE_FAILED;
		close(s);
		return found;
	}
	for (int tries = 0; tries < 50; tries++) {
		ssize_t n = read(s, &msg, sizeof(msg));
		if (n < (ssize_t)sizeof(msg.rtm)) {
			break;
		}
		if (msg.rtm.rtm_type != RTM_GET || msg.rtm.rtm_seq != 2 || msg.rtm.rtm_pid != pid) {
			continue;
		}
		if (msg.rtm.rtm_errno != 0) {
			found = msg.rtm.rtm_errno == ESRCH ? PROBE_NONE : PROBE_FAILED;
			break;
		}
		uint8_t a[RT_ADDRS][16];

		found = PROBE_FOUND;
		g->rtm = msg.rtm;
		rt_addrs(msg.space, (size_t)n - sizeof(msg.rtm), (unsigned int)msg.rtm.rtm_addrs, a);
		for (int bit = 0; bit < RT_ADDRS && bit < RTAX_MAX; bit++) {
			memcpy(&g->sa[bit], a[bit], sizeof(g->sa[bit]));
		}
		break;
	}
	close(s);
	return found;
}

/* The kernel's default route: its IPv4 gateway, or 0 if it has none, and its interface. */
static void
default_route(struct kroute *k)
{
	struct rtget g;

	memset(k, 0, sizeof(*k));
	k->probe = route_get((struct in_addr){ 0 }, (struct in_addr){ 0 }, 0, &g);
	if (k->probe != PROBE_FOUND) {
		return;
	}
	if (g.sa[RTAX_GATEWAY].sin_family == AF_INET) {
		k->r.router = g.sa[RTAX_GATEWAY].sin_addr;
	}
	k->r.ifindex = g.rtm.rtm_index;
	if (if_indextoname(k->r.ifindex, k->r.name) == NULL) {
		k->r.name[0] = '\0';
	}
}

/* l's subnet route, scoped to the interface, is there. */
static bool
subnet_present(const struct lease *l)
{
	struct in_addr net = { l->addr.s_addr & l->mask.s_addr };
	unsigned int index = if_nametoindex(ifname);
	struct rtget g;

	return index != 0 && route_get(net, l->mask, index, &g) == PROBE_FOUND &&
	    (g.rtm.rtm_flags & (RTF_IFSCOPE | RTF_GATEWAY)) == RTF_IFSCOPE && g.rtm.rtm_index == index &&
	    g.sa[RTAX_DST].sin_addr.s_addr == net.s_addr && g.sa[RTAX_NETMASK].sin_addr.s_addr == l->mask.s_addr;
}

/* Add l's subnet route only if it is not there: adding a route clears the ARP entries under it. */
static void
subnet_ensure(const struct lease *l)
{
	if (subnet_present(l)) {
		subnet_added = true;
	} else {
		subnet_route(RTM_ADD, l);
	}
}

/* Remove the default route, which goes through gw: true if it is gone. */
static bool
delete_default_route(struct in_addr gw)
{
	struct {
		struct rt_msghdr rtm;
		struct sockaddr_in dst, gw, mask;
	} msg;
	struct in_addr any = { 0 };
	bool ok;
	int s = socket(PF_ROUTE, SOCK_RAW, AF_INET);

	if (s < 0) {
		return false;
	}
	memset(&msg, 0, sizeof(msg));
	msg.rtm.rtm_msglen = sizeof(msg);
	msg.rtm.rtm_version = RTM_VERSION;
	msg.rtm.rtm_type = RTM_DELETE;
	msg.rtm.rtm_flags = RTF_UP | RTF_GATEWAY | RTF_STATIC;
	msg.rtm.rtm_addrs = RTA_DST | RTA_GATEWAY | RTA_NETMASK;
	msg.rtm.rtm_seq = 3;
	msg.rtm.rtm_pid = getpid();
	msg.dst = sin_of(any);
	msg.gw = sin_of(gw);
	msg.mask = sin_of(any);
	ok = write(s, &msg, sizeof(msg)) >= 0 || errno == ESRCH;
	if (!ok) {
		logmsg("default route: %s", strerror(errno));
	}
	close(s);
	return ok;
}

/*
 * Choose the interface the default route goes through, by elect_choose()
 * over the interfaces whose record is current, and do as elect_plan()
 * says. Every dhcpc runs this, under a lock, and they all agree.
 * /var/run/dhcpc/.default lists the default routes dhcpc set, the new one
 * before the route changes, so that whenever a dhcpc stops, the routes it
 * may have set are listed.
 */
static void
elect(void)
{
	struct candidate cand[32];
	char names[32][IFNAMSIZ];
	struct record recs[32];
	struct ifaddr4 set[32], covered[32];
	struct marker was, m;
	struct droute win;
	struct kroute k;
	struct eplan ep;
	int64_t now = uptime();
	int n = 0, ns = 0, best, lock;
	bool known, found = false, unrecorded = false;
	DIR *d;
	struct dirent *e;

	mkdir(STATE_DIR, 0755);
	lock = open(STATE_DIR "/.lock", O_RDWR | O_CREAT | O_CLOEXEC, 0644);
	if (lock < 0) {
		return;
	}
	flock(lock, LOCK_EX);
	d = opendir(STATE_DIR);
	while (d != NULL && n < 32 && (e = readdir(d)) != NULL) {
		uint8_t hw[6];
		char *end;
		long unit;

		if (strncmp(e->d_name, "en", 2) != 0 || strlen(e->d_name) >= IFNAMSIZ) {
			continue;
		}
		unit = strtol(e->d_name + 2, &end, 10);
		if (end == e->d_name + 2 || *end != '\0' || !read_state(e->d_name, &recs[n]) || !recs[n].has_lease ||
		    !get_mac(e->d_name, hw) || !record_current(&recs[n], hw, if_nametoindex(e->d_name),
		    has_addr(e->d_name, recs[n].l.addr), now)) {
			continue;
		}
		found |= recs[n].status == L_FOUND;
		strlcpy(names[n], e->d_name, sizeof(names[n]));
		strlcpy(covered[n].name, e->d_name, sizeof(covered[n].name));
		covered[n].addr = recs[n].l.addr;
		cand[n].unit = unit;
		cand[n].router = recs[n].l.router.s_addr != 0;
		cand[n].connected = connected(e->d_name);
		cand[n].confirmed = recs[n].status == L_CONFIRMED;
		n++;
	}
	if (d != NULL) {
		closedir(d);
	}
	known = read_marker(&was);
	if (!known) {
		struct ifaddrs *ifa, *p;

		if (getifaddrs(&ifa) != 0) {
			unrecorded = true;
		} else {
			for (p = ifa; p != NULL && ns < 32; p = p->ifa_next) {
				if (p->ifa_addr != NULL && p->ifa_addr->sa_family == AF_INET) {
					strlcpy(set[ns].name, p->ifa_name, sizeof(set[ns].name));
					set[ns++].addr = ((struct sockaddr_in *)(void *)p->ifa_addr)->sin_addr;
				}
			}
			unrecorded = p != NULL || unrecorded_address(set, ns, covered, n);
			freeifaddrs(ifa);
		}
	}
	default_route(&k);
	best = elect_choose(cand, n);
	memset(&win, 0, sizeof(win));
	if (best >= 0) {
		strlcpy(win.name, names[best], sizeof(win.name));
		win.ifindex = recs[best].ifindex;
		win.router = recs[best].l.router;
	}
	elect_plan(best >= 0 ? &win : NULL, found, unrecorded, known ? &was : NULL, &k, &ep);
	if (ep.settle && (!ep.set || (write_marker(&ep.intent) && set_default_route(win.router, win.name)))) {
		memset(&m, 0, sizeof(m));
		marker_add(&m, &win);
		if (write_marker(&m)) {
			logmsg("default route through %s, router %s", win.name, inet_ntoa(win.router));
		}
	}
	if (ep.resolv) {
		write_resolv_conf(names[best], &recs[best].l);
	}
	if (ep.clear) {
		write_resolv_conf(NULL, NULL);
	}
	if ((ep.remove && delete_default_route(k.r.router)) || ep.none) {
		memset(&m, 0, sizeof(m));
		if (write_marker(&m) && (ep.remove || (known && was.n > 0))) {
			logmsg("no interface for the default route");
		}
	}
	flock(lock, LOCK_UN);
	close(lock);
}

/* What the client asks of the interface and the system. */

static void
io_up(void *ctx)
{
	(void)ctx;
	if_up();
}

static bool
io_link(void *ctx)
{
	(void)ctx;
	return link_now(ifname);
}

static void
io_open(void *ctx)
{
	(void)ctx;
	ifindex = if_nametoindex(ifname);
	bpf_close();
	bpf_open();
}

static void
io_close(void *ctx)
{
	(void)ctx;
	bpf_close();
}

static void
io_send(void *ctx, const struct csend *m)
{
	(void)ctx;
	send_msg(m);
}

/*
 * Remove l's subnet route and address. An address that stays, or whose
 * absence cannot be read, is kept in rec and tried again every RETRY_MS
 * until it is known to be gone.
 */
static bool
remove_addr(const struct lease *l)
{
	enum addrstate st;
	bool kept;
	char a[16];

	subnet_route(RTM_DELETE, l);
	del_addr(l->addr);
	st = addr_state(ifname, l->addr);
	kept = record_removed(&rec, l->addr, l->mask, st);
	if (st == ADDR_ABSENT) {
		return true;
	}
	strlcpy(a, inet_ntoa(l->addr), sizeof(a));
	logmsg("%s: %s %s; trying again", ifname, a, st == ADDR_SET ? "did not go" : "may not have gone");
	if (!kept) {
		logmsg("%s: no room to keep %s", ifname, a);
	}
	return false;
}

/* Every RETRY_MS while rec could not be written or has addresses to remove. */
static void
retry(int64_t now)
{
	bool changed = false;

	for (int i = rec.nremove - 1; i >= 0; i--) {
		struct addrmask a = rec.remove[i];
		enum addrstate st;

		if (if_nametoindex(ifname) != 0) {
			del_addr(a.addr);
		}
		st = addr_state(ifname, a.addr);
		if (st == ADDR_ABSENT) {
			logmsg("%s: %s went", ifname, inet_ntoa(a.addr));
			record_removed(&rec, a.addr, a.mask, st);
			changed = true;
		}
	}
	if (changed || rec_dirty) {
		save();
	}
	retry_at = now + RETRY_MS;
}

/*
 * Set l's address and subnet route; false if l's address is not set. A
 * new address is recorded before it is set, so that a dhcpc that takes
 * the interface over finds every address dhcpc set; the record says it is
 * confirmed once it is set. An address that is set already, with the same
 * mask and broadcast, is not set again. The subnet route is looked for at
 * every bind, as the kernel removes it when the interface goes down, and
 * added only if it is not there: either would clear the ARP entries under
 * it.
 */
static bool
io_apply(void *ctx, const struct lease *old, const struct lease *l)
{
	bool moved = old != NULL && old->addr.s_addr != l->addr.s_addr;
	bool remasked = old != NULL && !moved && old->mask.s_addr != l->mask.s_addr;
	struct in_addr m, b;

	(void)ctx;
	if (if_nametoindex(ifname) != ifindex) {
		logmsg("%s: the interface changed; the lease of %s is not applied", ifname, inet_ntoa(l->addr));
		return false;
	}
	if (moved) {
		remove_addr(old);
		rec.has_lease = false;
	} else if (remasked) {
		subnet_route(RTM_DELETE, old);
	}
	if (!record_may_set(&rec, l->addr)) {
		logmsg("%s: %s is not set while %d addresses wait to go", ifname, inet_ntoa(l->addr), rec.nremove);
		elect();
		return false;
	}
	if (!rec.has_lease || rec.l.addr.s_addr != l->addr.s_addr) {
		struct record keep = rec;

		record_lease(&rec, l, L_CHECKING);
		if (!save()) {
			rec = keep;
			rec_dirty = true;
			logmsg("%s: %s is not set, as it cannot be recorded", ifname, inet_ntoa(l->addr));
			elect();
			return false;
		}
	}
	if (!(addr_as(ifname, l->addr, &m, &b) && lease_set_as(l, m, b)) && !set_addr(l)) {
		elect();
		return false;
	}
	subnet_ensure(l);
	record_lease(&rec, l, L_CONFIRMED);
	save();
	elect();
	return true;
}

static void
io_hold(void *ctx, const struct lease *l, enum lstatus s)
{
	(void)ctx;
	record_lease(&rec, l, s);
	save();
	elect();
}

static void
io_drop(void *ctx, const struct lease *l)
{
	(void)ctx;
	remove_addr(l);
	rec.has_lease = false;
	save();
	elect();
}

/*
 * The interface went: its addresses went with it. If it is there still, as
 * when its adapter changed, l's address goes.
 */
static void
io_gone(void *ctx, const struct lease *l)
{
	(void)ctx;
	if (l != NULL && ifindex != 0 && if_nametoindex(ifname) == ifindex) {
		remove_addr(l);
	} else {
		rec.nremove = 0;
	}
	ifindex = 0;
	subnet_added = false;
	rec.has_lease = false;
	save();
	elect();
}

static void
io_log(void *ctx, const char *fmt, ...)
{
	char text[512];
	va_list ap;

	(void)ctx;
	va_start(ap, fmt);
	vsnprintf(text, sizeof(text), fmt, ap);
	va_end(ap);
	logmsg("%s: %s", ifname, text);
}

static uint32_t
io_xid(void *ctx)
{
	(void)ctx;
	return arc4random();
}

static const struct cops io_ops = {
	io_up, io_link, io_open, io_close, io_send, io_apply, io_hold, io_drop, io_gone, io_log, io_xid,
};

/* The interface is there: tell the client, with its hardware address. */
static void
attach_now(int64_t now)
{
	if (get_mac(ifname, mac)) {
		client_attach(&cl, mac, now);
	}
}

static void
worker_event(const char *name, uint32_t code)
{
	int64_t now = uptime();
	bool mine = strcmp(name, ifname) == 0;

	switch (code) {
	case KEV_DL_IF_ATTACHED:
		if (mine && (cl.state == C_GONE || if_nametoindex(ifname) != ifindex)) {
			attach_now(now);
		}
		break;
	case KEV_DL_IF_DETACHING:
	case KEV_DL_IF_DETACHED:
		if (mine) {
			client_detach(&cl, now);
		}
		elect_wanted = true;
		break;
	case KEV_DL_LINK_ON:
	case KEV_DL_LINK_OFF:
		if (mine) {
			client_link(&cl, code == KEV_DL_LINK_ON, now);
		}
		elect_wanted = true;
		break;
	case KEV_DL_SIFFLAGS:
		elect_wanted = true;
		break;
	default:
		break;
	}
}

/*
 * Events can be lost, so the interface is looked at too: a changed index
 * is a departure and a new arrival, and every CHECK_MS an interface that is
 * there but not followed is taken up, and the link is read.
 */
static void
check_interface(int64_t now, bool full)
{
	unsigned int index = if_nametoindex(ifname);

	if (cl.state != C_GONE && index != ifindex) {
		client_detach(&cl, now);
		if (index != 0) {
			attach_now(now);
		}
	} else if (cl.state == C_GONE && index != 0 && full) {
		attach_now(now);
	}
	if (full && cl.state != C_GONE) {
		if (bpf < 0) {
			bpf_open();
		}
		bool up = link_now(ifname);
		if (up != cl.link) {
			client_link(&cl, up, now);
		}
		elect_wanted = true;
	}
}

/* Read the replies BPF has: a departed interface's BPF says ENXIO. */
static void
read_bpf(void)
{
	unsigned int gen = bpf_gen;
	bool checked = false;
	ssize_t n = read(bpf, bpfbuf, bpflen);

	if (n < 0) {
		if (errno == ENXIO) {
			client_detach(&cl, uptime());
		}
		return;
	}
	for (uint8_t *p = bpfbuf; p < bpfbuf + n && bpf_gen == gen;) {
		struct bpf_hdr *bh = (struct bpf_hdr *)(void *)p;
		struct lease l;

		if (msg_parse(p + bh->bh_hdrlen, bh->bh_caplen, cl.xid, mac, &l)) {
			if (!checked && !bpf_is_ours()) {
				client_detach(&cl, uptime());
				if (if_nametoindex(ifname) != 0) {
					attach_now(uptime());
				}
				return;
			}
			checked = true;
			client_reply(&cl, &l, bpf_client_gen, uptime());
		}
		p += BPF_WORDALIGN(bh->bh_hdrlen + bh->bh_caplen);
	}
}

/* Run the client: until it has a lease or until passes, or with until 0 for ever. */
static void
run(int64_t until)
{
	int64_t checked = uptime();

	for (;;) {
		int64_t now = uptime();
		if (until != 0 && (cl.bound_once || now >= until)) {
			return;
		}
		int64_t wake = client_next(&cl);
		bool pending = rec_dirty || rec.nremove > 0;
		if (wake > checked + CHECK_MS) {
			wake = checked + CHECK_MS;
		}
		if (pending && wake > retry_at) {
			wake = retry_at;
		}
		if (until != 0 && wake > until) {
			wake = until;
		}
		int ms = wake > now ? (int)(wake - now) : 0;
		struct pollfd p[3];
		nfds_t n = 0;
		int ki = -1, bi = -1, si = -1;
		unsigned int gen = bpf_gen;
		if (kev >= 0) {
			ki = (int)n;
			p[n++] = (struct pollfd){ kev, POLLIN, 0 };
		}
		if (bpf >= 0) {
			bi = (int)n;
			p[n++] = (struct pollfd){ bpf, POLLIN, 0 };
		}
		if (sink >= 0) {
			si = (int)n;
			p[n++] = (struct pollfd){ sink, POLLIN, 0 };
		}
		bool ready = false;
		if (n == 0) {
			nap(ms);
		} else if (poll(p, n, ms) > 0) {
			if (ki >= 0 && p[ki].revents) {
				kev_read(worker_event);
			}
			if (si >= 0 && p[si].revents) {
				char drop[1500];
				while (recv(sink, drop, sizeof(drop), 0) > 0) {
				}
			}
			ready = bi >= 0 && p[bi].revents != 0;
		}
		now = uptime();
		if (now - checked >= CHECK_MS) {
			check_interface(now, true);
			checked = now;
		} else {
			check_interface(now, false);
		}
		if (ready && bpf >= 0 && bpf_gen == gen) {
			read_bpf();
		}
		client_timer(&cl, now);
		if ((rec_dirty || rec.nremove > 0) && now >= retry_at) {
			retry(now);
		} else if (!rec_dirty && rec.nremove == 0) {
			retry_at = now + RETRY_MS;
		}
		if (elect_wanted) {
			elect_wanted = false;
			elect();
		}
	}
}

/* Port 68 on any address, so that unicast replies are taken and dropped rather than answered with port unreachables. */
static void
sink_open(void)
{
	struct sockaddr_in sin = sin_of((struct in_addr){ INADDR_ANY });
	int one = 1;

	sin.sin_port = htons(68);
	sink = socket(AF_INET, SOCK_DGRAM, 0);
	if (sink >= 0 && (setsockopt(sink, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) != 0 ||
	    setsockopt(sink, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one)) != 0 ||
	    bind(sink, (struct sockaddr *)&sin, sizeof(sin)) != 0 || fcntl(sink, F_SETFL, O_NONBLOCK) != 0 ||
	    fcntl(sink, F_SETFD, FD_CLOEXEC) != 0)) {
		close(sink);
		sink = -1;
	}
}

/*
 * What a dhcpc that ran before this one left for the interface, by
 * plan_takeover(): a recorded lease whose address is set is taken over
 * with its times, and a recorded address that cannot be taken over goes,
 * as do the addresses the record has yet to remove. An address set
 * without any record is asked for again with INIT-REBOOT, and elect()
 * leaves the default route and resolv.conf as they are meanwhile.
 */
static bool
take_over(int64_t now)
{
	struct record r;
	struct plan p;
	struct in_addr first, first_mask = { 0 };
	bool valid, any;
	char a[16];

	ifindex = if_nametoindex(ifname);
	valid = read_state(ifname, &r);
	memset(&rec, 0, sizeof(rec));
	if (valid) {
		record_reconcile(&r);
	}
	for (int i = 0; valid && record_here(&r, mac, ifindex) && i < r.nremove; i++) {
		if (addr_state(ifname, r.remove[i].addr) != ADDR_ABSENT) {
			struct lease x;

			memset(&x, 0, sizeof(x));
			x.addr = r.remove[i].addr;
			x.mask = r.remove[i].mask;
			logmsg("%s: removing %s, which an earlier dhcpc set", ifname, inet_ntoa(x.addr));
			subnet_added = true;
			remove_addr(&x);
		}
	}
	any = first_inet(ifname, &first, &first_mask);
	plan_takeover(valid ? &r : NULL, mac, ifindex,
	    valid && r.has_lease && addr_state(ifname, r.l.addr) != ADDR_ABSENT, any ? &first : NULL, first_mask,
	    now, &p);
	if (p.remove) {
		logmsg("%s: removing %s, which an earlier dhcpc set", ifname, inet_ntoa(p.rm.addr));
		subnet_added = true;
		remove_addr(&p.rm);
	}
	subnet_added = false;
	if (p.what == TAKE_ADOPT) {
		strlcpy(a, inet_ntoa(p.l.addr), sizeof(a));
		if (p.status == L_FOUND && !(valid && r.has_lease)) {
			logmsg("%s: %s is set without a record; asking for it", ifname, a);
		} else {
			logmsg("%s: took over the lease of %s", ifname, a);
		}
		record_lease(&rec, &p.l, p.status);
		save();
		subnet_ensure(&p.l);
		client_adopt(&cl, &p.l, mac, p.status, now);
		elect();
		return true;
	}
	save();
	if (p.what == TAKE_REMEMBER) {
		client_remember(&cl, &p.l, p.mac);
	}
	elect();
	return false;
}

/* The lock that a worker holds for its interface while it runs. */
static int
lock_interface(const char *name)
{
	char path[64];
	int fd;

	mkdir(STATE_DIR, 0755);
	snprintf(path, sizeof(path), STATE_DIR "/%s.lock", name);
	fd = open(path, O_RDWR | O_CREAT, 0644);
	if (fd < 0) {
		return -1;
	}
	for (int i = 0; i < 30; i++) {
		if (flock(fd, LOCK_EX | LOCK_NB) == 0) {
			return fd;
		}
		nap(100);
	}
	close(fd);
	return -1;
}

/* A worker holds name's lock. */
static bool
worker_running(const char *name)
{
	char path[64];
	bool held;
	int fd;

	snprintf(path, sizeof(path), STATE_DIR "/%s.lock", name);
	fd = open(path, O_RDWR | O_CREAT, 0644);
	if (fd < 0) {
		return false;
	}
	held = flock(fd, LOCK_EX | LOCK_NB) != 0;
	close(fd);
	return held;
}

/* dhcpc -a: a dhcpc for each Ethernet interface, now and as they appear. */
static void
start_worker(const char *name)
{
	if (strncmp(name, "en", 2) != 0 || name[2] < '0' || name[2] > '9' || worker_running(name)) {
		return;
	}
	pid_t pid = fork();
	if (pid == 0) {
		execl("/sbin/dhcpc", "dhcpc", "-t", "30", name, (char *)NULL);
		_exit(127);
	}
}

static void
start_workers(void)
{
	struct ifaddrs *ifa, *p;

	if (getifaddrs(&ifa) == 0) {
		for (p = ifa; p; p = p->ifa_next) {
			if (p->ifa_addr && p->ifa_addr->sa_family == AF_LINK) {
				start_worker(p->ifa_name);
			}
		}
		freeifaddrs(ifa);
	}
}

static void
supervisor_event(const char *name, uint32_t code)
{
	if (code == KEV_DL_IF_ATTACHED) {
		start_worker(name);
	}
}

static void
supervise(void)
{
	int lock;

	mkdir(STATE_DIR, 0755);
	lock = open(STATE_DIR "/.supervisor", O_RDWR | O_CREAT, 0644);
	if (lock < 0 || flock(lock, LOCK_EX | LOCK_NB) != 0) {
		errx(0, "dhcpc -a runs already");
	}
	fcntl(lock, F_SETFD, FD_CLOEXEC);
	signal(SIGCHLD, SIG_IGN);
	kev_open();
	if (kev < 0) {
		err(1, "kernel event socket");
	}
	start_workers();
	for (int64_t scanned = uptime();;) {
		struct pollfd pfd = { kev, POLLIN, 0 };
		int64_t left = scanned + CHECK_MS - uptime();
		if (poll(&pfd, 1, left > 0 ? (int)left : 0) > 0) {
			kev_read(supervisor_event);
		}
		if (uptime() - scanned >= CHECK_MS) {
			start_workers();
			scanned = uptime();
		}
	}
}

static void
usage(void)
{
	fprintf(stderr, "usage: dhcpc [-1] [-t seconds] interface\n       dhcpc -a\n");
	exit(2);
}

int
main(int argc, char **argv)
{
	bool once = false, all = false;
	int wait = 30;
	int ch, lock;

	while ((ch = getopt(argc, argv, "1at:")) != -1) {
		switch (ch) {
		case '1':
			once = true;
			break;
		case 'a':
			all = true;
			break;
		case 't':
			wait = atoi(optarg);
			break;
		default:
			usage();
		}
	}
	/*
	 * Started in the background by /etc/rc, dhcpc would get the hangup
	 * that rc's exit sends to its process group.
	 */
	signal(SIGHUP, SIG_IGN);
	if (all) {
		if (argc != optind || once) {
			usage();
		}
		supervise();
	}
	if (argc - optind != 1) {
		usage();
	}
	ifname = argv[optind];
	if (strlen(ifname) >= IFNAMSIZ) {
		usage();
	}
	lock = lock_interface(ifname);
	if (lock < 0) {
		if (once) {
			errx(1, "%s: another dhcpc runs for it", ifname);
		}
		errx(0, "%s: another dhcpc runs for it", ifname);
	}
	kev_open();
	for (int i = 0; !get_mac(ifname, mac); i++) {
		if (i == 10) {
			errx(1, "%s: no such Ethernet interface", ifname);
		}
		nap(200);
	}
	sink_open();
	client_init(&cl, &io_ops, NULL);
	if (!take_over(uptime())) {
		client_attach(&cl, mac, uptime());
	}

	/* The first lease, within about `wait` seconds. */
	run(uptime() + (int64_t)(wait > 0 ? wait : 1) * 1000);
	if (!cl.bound_once && once) {
		errx(1, "%s: no DHCP lease", ifname);
	} else if (!cl.bound_once) {
		warnx("%s: no DHCP lease yet; still asking in the background", ifname);
	}
	if (once) {
		return 0;
	}

	/* In the background: the first lease if it has not come, then keep it, and follow the interface. */
	pid_t pid = fork();
	if (pid < 0) {
		err(1, "fork");
	}
	if (pid > 0) {
		return cl.bound_once ? 0 : 1;
	}
	setsid();
	chdir("/");
	int null = open("/dev/null", O_RDWR);
	if (null >= 0) {
		dup2(null, 0);
		dup2(null, 1);
		dup2(null, 2);
		if (null > 2) {
			close(null);
		}
	}
	foreground = false;
	run(0);
	return 0;
}
