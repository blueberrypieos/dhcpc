/*
 * SPDX-License-Identifier: BSD-2-Clause AND LicenseRef-BSD-3-Clause-ISC
 * Copyright (c) 2026 The Blueberry Pie OS Authors
 *
 * dhcpc: Blueberry Pie OS's DHCP client (RFC 2131, 2132) for one Ethernet
 * interface.
 *
 *   dhcpc [-1] [-t SECONDS] INTERFACE
 *
 * It gets a lease, gives the interface its address, sets the default route
 * and writes /etc/resolv.conf (and tells mDNSResponder, which resolves
 * names), then stays in the background to renew the
 * lease (-1: exit once configured). -t limits the wait for the first lease
 * (default 30 seconds); the exit status says whether one came. Without
 * one, it goes on asking in the background: at boot the link, a switch
 * port (spanning tree holds a new one for 30 s or more) or the server can
 * take longer than that.
 *
 * dhcpc sends and receives through BPF, since the interface has no
 * address to send from at first.
 */

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <net/bpf.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

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

#define SERVER_PORT     67
#define CLIENT_PORT     68
#define DHCP_MAGIC      0x63825363

enum {
	DHCPDISCOVER = 1, DHCPOFFER, DHCPREQUEST, DHCPDECLINE, DHCPACK, DHCPNAK, DHCPRELEASE,
};

enum {
	OPT_PAD = 0, OPT_SUBNET = 1, OPT_ROUTER = 3, OPT_DNS = 6, OPT_HOSTNAME = 12,
	OPT_DOMAIN = 15, OPT_BROADCAST = 28, OPT_REQUESTED_IP = 50, OPT_LEASE = 51,
	OPT_MSG_TYPE = 53, OPT_SERVER_ID = 54, OPT_PARAMS = 55, OPT_MAX_SIZE = 57,
	OPT_T1 = 58, OPT_T2 = 59, OPT_CLIENT_ID = 61, OPT_END = 255,
};

struct dhcp_msg {
	uint8_t op, htype, hlen, hops;
	uint32_t xid;
	uint16_t secs, flags;
	uint32_t ciaddr, yiaddr, siaddr, giaddr;
	uint8_t chaddr[16];
	uint8_t sname[64];
	uint8_t file[128];
	uint32_t magic;
	uint8_t options[312];
} __attribute__((packed));

struct frame {
	struct ether_header eh;
	struct ip ip;
	struct udphdr udp;
	struct dhcp_msg dhcp;
} __attribute__((packed));

/* What a DHCPOFFER or DHCPACK says. */
struct lease {
	int type;
	struct in_addr addr, mask, router, server, broadcast;
	struct in_addr dns[3];
	int ndns;
	char domain[256];
	uint32_t lease, t1, t2;
	int64_t sent;
};

static const char *ifname;
static uint8_t mac[6];
static int bpf = -1;
static u_int bpflen;
static uint8_t *bpfbuf;
static FILE *logfile;

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

static void
logmsg(const char *fmt, ...)
{
	va_list ap;
	FILE *f = logfile ? logfile : stderr;
	char when[32];
	time_t now = time(NULL);

	strftime(when, sizeof(when), "%b %e %H:%M:%S", localtime(&now));
	if (logfile) {
		fprintf(f, "%s dhcpc[%d]: ", when, (int)getpid());
	} else {
		fprintf(f, "dhcpc: ");
	}
	va_start(ap, fmt);
	vfprintf(f, fmt, ap);
	va_end(ap);
	fputc('\n', f);
	fflush(f);
}

static bool
get_mac(void)
{
	struct ifaddrs *ifa, *p;
	bool found = false;

	if (getifaddrs(&ifa) != 0) {
		return false;
	}
	for (p = ifa; p; p = p->ifa_next) {
		if (p->ifa_addr && p->ifa_addr->sa_family == AF_LINK && !strcmp(p->ifa_name, ifname)) {
			struct sockaddr_dl *sdl = (struct sockaddr_dl *)(void *)p->ifa_addr;
			if (sdl->sdl_alen == 6) {
				memcpy(mac, LLADDR(sdl), 6);
				found = true;
			}
		}
	}
	freeifaddrs(ifa);
	return found;
}

/* Bring the interface up (a DHCP exchange needs it running). */
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
		err(1, "no BPF device");
	}
	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (ioctl(bpf, BIOCSETIF, &ifr) < 0) {
		err(1, "BIOCSETIF %s", ifname);
	}
	if (ioctl(bpf, BIOCIMMEDIATE, &one) < 0 || ioctl(bpf, BIOCSHDRCMPLT, &one) < 0 ||
	    ioctl(bpf, BIOCSETF, &prog) < 0 || ioctl(bpf, BIOCGBLEN, &bpflen) < 0) {
		err(1, "BPF setup");
	}
	bpfbuf = malloc(bpflen);
	if (bpfbuf == NULL) {
		err(1, "malloc");
	}
}

static uint16_t
ip_checksum(const void *data, size_t len)
{
	const uint8_t *p = data;
	uint32_t sum = 0;

	for (size_t i = 0; i + 1 < len; i += 2) {
		sum += (uint32_t)(p[i] << 8 | p[i + 1]);
	}
	if (len & 1) {
		sum += (uint32_t)p[len - 1] << 8;
	}
	while (sum >> 16) {
		sum = (sum & 0xffff) + (sum >> 16);
	}
	return htons((uint16_t)~sum);
}

static uint8_t *
put_opt(uint8_t *p, uint8_t code, uint8_t len, const void *data)
{
	*p++ = code;
	*p++ = len;
	memcpy(p, data, len);
	return p + len;
}

/*
 * Broadcast a DISCOVER or REQUEST. ciaddr is our address when renewing;
 * a REQUEST answering an offer names the address and the server.
 */
static void
send_msg(int type, uint32_t xid, uint16_t secs, struct in_addr ciaddr,
    const struct lease *offer)
{
	struct frame f;
	uint8_t *p;
	uint8_t t = (uint8_t)type;
	static const uint8_t params[] = {
		OPT_SUBNET, OPT_ROUTER, OPT_DNS, OPT_DOMAIN, OPT_BROADCAST, OPT_LEASE,
		OPT_SERVER_ID, OPT_T1, OPT_T2,
	};
	uint8_t clientid[7] = { 1 };
	uint16_t maxsize = htons(1500);
	char host[256];

	memset(&f, 0, sizeof(f));
	f.dhcp.op = 1;
	f.dhcp.htype = 1;
	f.dhcp.hlen = 6;
	f.dhcp.xid = xid;
	f.dhcp.secs = htons(secs);
	f.dhcp.flags = htons(0x8000);   /* answer by broadcast */
	f.dhcp.ciaddr = ciaddr.s_addr;
	memcpy(f.dhcp.chaddr, mac, 6);
	f.dhcp.magic = htonl(DHCP_MAGIC);
	p = f.dhcp.options;
	p = put_opt(p, OPT_MSG_TYPE, 1, &t);
	memcpy(clientid + 1, mac, 6);
	p = put_opt(p, OPT_CLIENT_ID, sizeof(clientid), clientid);
	p = put_opt(p, OPT_MAX_SIZE, 2, &maxsize);
	if (offer != NULL) {
		p = put_opt(p, OPT_REQUESTED_IP, 4, &offer->addr);
		p = put_opt(p, OPT_SERVER_ID, 4, &offer->server);
	}
	if (gethostname(host, sizeof(host)) == 0 && host[0] && strlen(host) < 64) {
		p = put_opt(p, OPT_HOSTNAME, (uint8_t)strlen(host), host);
	}
	p = put_opt(p, OPT_PARAMS, sizeof(params), params);
	*p++ = OPT_END;

	size_t dhcplen = (size_t)(p - (uint8_t *)&f.dhcp);
	if (dhcplen < 300) {
		dhcplen = 300;          /* the BOOTP minimum */
	}
	memset(f.eh.ether_dhost, 0xff, 6);
	memcpy(f.eh.ether_shost, mac, 6);
	f.eh.ether_type = htons(ETHERTYPE_IP);
	f.ip.ip_v = 4;
	f.ip.ip_hl = 5;
	f.ip.ip_len = htons((uint16_t)(sizeof(f.ip) + sizeof(f.udp) + dhcplen));
	f.ip.ip_ttl = 64;
	f.ip.ip_p = IPPROTO_UDP;
	f.ip.ip_src = ciaddr;
	f.ip.ip_dst.s_addr = INADDR_BROADCAST;
	f.ip.ip_sum = ip_checksum(&f.ip, sizeof(f.ip));
	f.udp.uh_sport = htons(CLIENT_PORT);
	f.udp.uh_dport = htons(SERVER_PORT);
	f.udp.uh_ulen = htons((uint16_t)(sizeof(f.udp) + dhcplen));
	f.udp.uh_sum = 0;               /* optional over IPv4 */

	size_t len = sizeof(f.eh) + sizeof(f.ip) + sizeof(f.udp) + dhcplen;
	if (write(bpf, &f, len) != (ssize_t)len) {
		logmsg("send: %s", strerror(errno));
	}
}

/* Parse a reply to our xid; true if it is an OFFER, ACK or NAK. */
static bool
parse_reply(const uint8_t *pkt, size_t len, uint32_t xid, struct lease *l)
{
	const struct ether_header *eh = (const void *)pkt;
	if (len < sizeof(*eh) + sizeof(struct ip) || ntohs(eh->ether_type) != ETHERTYPE_IP) {
		return false;
	}
	const struct ip *ip = (const void *)(pkt + sizeof(*eh));
	size_t ihl = (size_t)ip->ip_hl * 4;
	size_t off = sizeof(*eh) + ihl + sizeof(struct udphdr);
	if (ip->ip_p != IPPROTO_UDP || len < off + offsetof(struct dhcp_msg, options)) {
		return false;
	}
	const struct dhcp_msg *m = (const void *)(pkt + off);
	size_t dlen = len - off;
	if (m->op != 2 || m->xid != xid || memcmp(m->chaddr, mac, 6) != 0 ||
	    ntohl(m->magic) != DHCP_MAGIC) {
		return false;
	}

	memset(l, 0, sizeof(*l));
	l->addr.s_addr = m->yiaddr;
	const uint8_t *o = m->options, *end = (const uint8_t *)m + dlen;
	while (o < end && *o != OPT_END) {
		if (*o == OPT_PAD) {
			o++;
			continue;
		}
		if (o + 2 > end || o + 2 + o[1] > end) {
			break;
		}
		uint8_t code = o[0], olen = o[1];
		const uint8_t *v = o + 2;
		uint32_t u32;
		switch (code) {
		case OPT_MSG_TYPE:
			l->type = olen ? v[0] : 0;
			break;
		case OPT_SUBNET:
			if (olen >= 4) memcpy(&l->mask, v, 4);
			break;
		case OPT_ROUTER:
			if (olen >= 4) memcpy(&l->router, v, 4);
			break;
		case OPT_BROADCAST:
			if (olen >= 4) memcpy(&l->broadcast, v, 4);
			break;
		case OPT_SERVER_ID:
			if (olen >= 4) memcpy(&l->server, v, 4);
			break;
		case OPT_DNS:
			for (int i = 0; i + 4 <= olen && l->ndns < 3; i += 4) {
				memcpy(&l->dns[l->ndns++], v + i, 4);
			}
			break;
		case OPT_DOMAIN:
			memcpy(l->domain, v, olen);
			l->domain[olen] = '\0';
			break;
		case OPT_LEASE:
		case OPT_T1:
		case OPT_T2:
			if (olen >= 4) {
				memcpy(&u32, v, 4);
				u32 = ntohl(u32);
				*(code == OPT_LEASE ? &l->lease : code == OPT_T1 ? &l->t1 : &l->t2) = u32;
			}
			break;
		}
		o += 2 + olen;
	}
	return l->type == DHCPOFFER || l->type == DHCPACK || l->type == DHCPNAK;
}

/* Wait up to ms for a reply of one of the wanted types to xid. */
static bool
wait_reply(uint32_t xid, int ms, int want1, int want2, struct in_addr nak_from, struct lease *l)
{
	struct timespec start, now;
	clock_gettime(CLOCK_UPTIME_RAW, &start);

	for (;;) {
		clock_gettime(CLOCK_UPTIME_RAW, &now);
		long left = ms - ((now.tv_sec - start.tv_sec) * 1000 +
		    (now.tv_nsec - start.tv_nsec) / 1000000);
		if (left <= 0) {
			return false;
		}
		struct pollfd pfd = { bpf, POLLIN, 0 };
		if (poll(&pfd, 1, (int)left) <= 0) {
			continue;
		}
		ssize_t n = read(bpf, bpfbuf, bpflen);
		if (n <= 0) {
			continue;
		}
		for (uint8_t *p = bpfbuf; p < bpfbuf + n;) {
			struct bpf_hdr *bh = (struct bpf_hdr *)(void *)p;
			if (parse_reply(p + bh->bh_hdrlen, bh->bh_caplen, xid, l) &&
			    (l->type == want1 || l->type == want2)) {
				if (l->type != DHCPNAK || nak_from.s_addr == 0 ||
				    l->server.s_addr == nak_from.s_addr) {
					return true;
				}
				l->type = 0;
			}
			p += BPF_WORDALIGN(bh->bh_hdrlen + bh->bh_caplen);
		}
	}
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
	struct in_addr bcast = l->broadcast;
	int s = socket(AF_INET, SOCK_DGRAM, 0);
	bool ok;

	if (bcast.s_addr == 0) {
		bcast.s_addr = l->addr.s_addr | ~l->mask.s_addr;
	}
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

/* Add (or change) the default route through the router. */
static void
set_default_route(struct in_addr router)
{
	struct {
		struct rt_msghdr rtm;
		struct sockaddr_in dst, gw, mask;
	} msg;
	int s = socket(PF_ROUTE, SOCK_RAW, AF_INET);

	if (s < 0 || router.s_addr == 0) {
		if (s >= 0) close(s);
		return;
	}
	for (int type = RTM_ADD;; type = RTM_CHANGE) {
		struct in_addr any = { 0 };
		memset(&msg, 0, sizeof(msg));
		msg.rtm.rtm_msglen = sizeof(msg);
		msg.rtm.rtm_version = RTM_VERSION;
		msg.rtm.rtm_type = (u_char)type;
		msg.rtm.rtm_flags = RTF_UP | RTF_GATEWAY | RTF_STATIC;
		msg.rtm.rtm_addrs = RTA_DST | RTA_GATEWAY | RTA_NETMASK;
		msg.rtm.rtm_seq = 1;
		msg.rtm.rtm_pid = getpid();
		msg.dst = sin_of(any);
		msg.gw = sin_of(router);
		msg.mask = sin_of(any);
		if (write(s, &msg, sizeof(msg)) >= 0) {
			break;
		}
		if (errno != EEXIST || type == RTM_CHANGE) {
			logmsg("default route: %s", strerror(errno));
			break;
		}
	}
	close(s);
}

static void
write_resolv_conf(const struct lease *l)
{
	const char *tmp = "/etc/resolv.conf.dhcpc";
	FILE *f;

	if (l->ndns == 0) {
		return;
	}
	f = fopen(tmp, "w");
	if (f == NULL) {
		logmsg("%s: %s", tmp, strerror(errno));
		return;
	}
	fprintf(f, "# written by dhcpc for %s\n", ifname);
	if (l->domain[0]) {
		fprintf(f, "search %s\n", l->domain);
	}
	for (int i = 0; i < l->ndns; i++) {
		fprintf(f, "nameserver %s\n", inet_ntoa(l->dns[i]));
	}
	if (fclose(f) != 0 || rename(tmp, "/etc/resolv.conf") != 0) {
		logmsg("/etc/resolv.conf: %s", strerror(errno));
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

static int
prefix_len(struct in_addr mask)
{
	return __builtin_popcount(mask.s_addr);
}

/*
 * One exchange: DISCOVER, OFFER, REQUEST, ACK. With a current lease
 * (renewing), only REQUEST and ACK. tries bounds the attempts.
 */
static bool
get_lease(struct lease *cur, int tries, int64_t until, struct lease *out)
{
	int timeout = 2000;
	bool refused = false;

	for (int attempt = 0; attempt < tries; attempt++) {
		if (until != 0) {
			int64_t left = until - uptime();
			if (left <= 0) {
				return false;
			}
			if (timeout > left) {
				timeout = (int)left;
			}
		}
		uint32_t xid = arc4random();
		uint16_t secs = (uint16_t)(attempt * 2);
		struct lease offer;
		struct in_addr none = { 0 };
		int64_t sent;

		if (cur == NULL) {
			send_msg(DHCPDISCOVER, xid, secs, none, NULL);
			if (!wait_reply(xid, timeout, DHCPOFFER, DHCPOFFER, none, &offer)) {
				timeout = timeout < 16000 ? timeout * 2 : timeout;
				continue;
			}
			sent = uptime();
			send_msg(DHCPREQUEST, xid, secs, none, &offer);
		} else {
			sent = uptime();
			send_msg(DHCPREQUEST, xid, secs, cur->addr, NULL);
		}
		struct in_addr nak_from = cur != NULL ? cur->server : offer.server;
		if (!wait_reply(xid, timeout, DHCPACK, DHCPNAK, nak_from, out)) {
			timeout = timeout < 16000 ? timeout * 2 : timeout;
			continue;
		}
		if (out->type == DHCPNAK) {
			logmsg("%s: server %s refused the lease", ifname, inet_ntoa(out->server));
			if (cur == NULL && !refused) {
				refused = true;
				tries++;
				continue;
			}
			return false;
		}
		if (out->addr.s_addr == 0 && cur != NULL) {
			out->addr = cur->addr;
		}
		out->sent = sent;
		return true;
	}
	return false;
}

static void
apply(const struct lease *old, struct lease *l)
{
	char addr[16], router[16];

	if (l->mask.s_addr == 0) {
		l->mask.s_addr = htonl(IN_CLASSC_NET);
	}
	if (l->lease == 0) {
		l->lease = 3600;
	}
	if (old != NULL && old->addr.s_addr != l->addr.s_addr) {
		del_addr(old->addr);
	}
	set_addr(l);
	set_default_route(l->router);
	write_resolv_conf(l);
	strlcpy(addr, inet_ntoa(l->addr), sizeof(addr));
	strlcpy(router, inet_ntoa(l->router), sizeof(router));
	logmsg("%s: %s/%d, router %s, %d name server(s), lease %u s", ifname, addr,
	    prefix_len(l->mask), l->router.s_addr ? router : "none", l->ndns, l->lease);
}

static void
usage(void)
{
	fprintf(stderr, "usage: dhcpc [-1] [-t seconds] interface\n");
	exit(2);
}

int
main(int argc, char **argv)
{
	bool once = false;
	int wait = 30;
	int ch;

	while ((ch = getopt(argc, argv, "1t:")) != -1) {
		switch (ch) {
		case '1':
			once = true;
			break;
		case 't':
			wait = atoi(optarg);
			break;
		default:
			usage();
		}
	}
	if (argc - optind != 1) {
		usage();
	}
	ifname = argv[optind];
	/*
	 * Started in the background by /etc/rc, dhcpc would get the hangup
	 * that rc's exit sends to its process group.
	 */
	signal(SIGHUP, SIG_IGN);
	if (!get_mac()) {
		errx(1, "%s: no such Ethernet interface", ifname);
	}
	if_up();
	bpf_open();

	/* The first lease, within about `wait` seconds (tries of 2, 4, 8, 16, 16, ... s). */
	struct lease l, next;
	int tries = 0;
	for (int t = 0, step = 2; t < wait || tries == 0; t += step, step = step < 16 ? step * 2 : step) {
		tries++;
	}
	bool leased = get_lease(NULL, tries, 0, &l);
	if (leased) {
		apply(NULL, &l);
	} else if (once) {
		errx(1, "%s: no DHCP lease", ifname);
	} else {
		warnx("%s: no DHCP lease yet; still asking in the background", ifname);
	}
	if (once) {
		return 0;
	}

	/*
	 * In the background: the first lease if it has not come, then keep it
	 * (renew at T1, start over when it runs out).
	 */
	pid_t pid = fork();
	if (pid < 0) {
		err(1, "fork");
	}
	if (pid > 0) {
		return leased ? 0 : 1;
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
	logfile = fopen("/var/log/dhcpc.log", "a");
	while (!leased) {
		leased = get_lease(NULL, 6, 0, &l);       /* about a minute of DISCOVERs */
		if (leased) {
			apply(NULL, &l);
		} else {
			sleep(5);
		}
	}
	for (;;) {
		uint32_t t1 = l.t1 && l.t1 < l.lease ? l.t1 : l.lease / 2;
		uint32_t t2 = l.t2 > t1 && l.t2 < l.lease ? l.t2 : (uint32_t)((uint64_t)l.lease * 7 / 8);
		if (t2 <= t1) {
			t2 = t1 + (l.lease - t1) / 2;
		}
		int64_t expires = l.sent + (int64_t)l.lease * 1000;
		int64_t rebind = l.sent + (int64_t)t2 * 1000;
		nap(l.sent + (int64_t)t1 * 1000 - uptime());
		bool renewed = false;
		next.type = 0;
		while (!renewed && uptime() < expires) {
			struct lease cur = l;
			int64_t until = expires;
			if (uptime() >= rebind) {
				cur.server.s_addr = 0;
			} else {
				until = rebind;
			}
			if (get_lease(&cur, 3, until, &next)) {
				renewed = true;
			} else if (next.type == DHCPNAK) {
				break;
			} else {
				int64_t left = until - uptime();
				nap(left < 60000 ? left : 60000);
			}
		}
		if (!renewed) {
			if (next.type != DHCPNAK) {
				logmsg("%s: lease of %s expired", ifname, inet_ntoa(l.addr));
			}
			del_addr(l.addr);
			while (!get_lease(NULL, 6, 0, &next)) {
				sleep(30);
			}
			apply(NULL, &next);
		} else {
			apply(&l, &next);
		}
		l = next;
	}
}
