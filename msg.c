/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 The Blueberry Pie OS Authors
 */

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "msg.h"

#define ETH_LEN         14
#define IP_LEN          20
#define UDP_LEN         8
#define DHCP_FIXED      240     /* up to and with the magic cookie */
#define DHCP_MIN        300     /* the BOOTP minimum */

enum {
	OPT_PAD = 0, OPT_SUBNET = 1, OPT_ROUTER = 3, OPT_DNS = 6, OPT_HOSTNAME = 12,
	OPT_DOMAIN = 15, OPT_BROADCAST = 28, OPT_REQUESTED_IP = 50, OPT_LEASE = 51,
	OPT_OVERLOAD = 52, OPT_MSG_TYPE = 53, OPT_SERVER_ID = 54, OPT_PARAMS = 55,
	OPT_MAX_SIZE = 57, OPT_T1 = 58, OPT_T2 = 59, OPT_CLIENT_ID = 61, OPT_END = 255,
};

static void
put16(uint8_t *p, uint16_t v)
{
	p[0] = (uint8_t)(v >> 8);
	p[1] = (uint8_t)v;
}

static uint16_t
get16(const uint8_t *p)
{
	return (uint16_t)(p[0] << 8 | p[1]);
}

static uint32_t
get32(const uint8_t *p)
{
	return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}

/* The 16-bit one's complement sum of len bytes, the last padded with a zero byte if len is odd. */
static uint32_t
sum16(const uint8_t *p, size_t len, uint32_t sum)
{
	for (size_t i = 0; i + 1 < len; i += 2) {
		sum += get16(p + i);
	}
	if (len & 1) {
		sum += (uint32_t)p[len - 1] << 8;
	}
	while (sum >> 16) {
		sum = (sum & 0xffff) + (sum >> 16);
	}
	return sum;
}

/* The one's complement of the one's complement sum of len bytes: 0 over a whole header that is right. */
static uint16_t
ip_checksum(const uint8_t *p, size_t len)
{
	return (uint16_t)~sum16(p, len, 0);
}

/* The same over the UDP datagram at udp, ulen bytes long, with the pseudo-header of the IPv4 header at ip. */
static uint16_t
udp_checksum(const uint8_t *ip, const uint8_t *udp, size_t ulen)
{
	uint8_t pseudo[12];

	memcpy(pseudo, ip + 12, 8);
	pseudo[8] = 0;
	pseudo[9] = 17;
	put16(pseudo + 10, (uint16_t)ulen);
	return (uint16_t)~sum16(udp, ulen, sum16(pseudo, sizeof(pseudo), 0));
}

size_t
msg_payload(uint8_t out[MSG_DHCP_MAX], const struct csend *m, const uint8_t mac[6], const char *host)
{
	static const uint8_t params[] = {
		OPT_SUBNET, OPT_ROUTER, OPT_DNS, OPT_DOMAIN, OPT_BROADCAST, OPT_LEASE,
		OPT_SERVER_ID, OPT_T1, OPT_T2,
	};
	uint8_t *d = out, *o;
	size_t hostlen = host != NULL ? strlen(host) : 0, dlen;

	memset(out, 0, MSG_DHCP_MAX);
	d[0] = 1;
	d[1] = 1;
	d[2] = 6;
	memcpy(d + 4, &m->xid, 4);
	put16(d + 8, m->secs);
	put16(d + 10, m->unicast ? 0 : 0x8000);
	memcpy(d + 12, &m->ciaddr, 4);
	memcpy(d + 28, mac, 6);
	d[236] = 0x63;
	d[237] = 0x82;
	d[238] = 0x53;
	d[239] = 0x63;
	o = d + DHCP_FIXED;
	*o++ = OPT_MSG_TYPE;
	*o++ = 1;
	*o++ = (uint8_t)m->type;
	*o++ = OPT_CLIENT_ID;
	*o++ = 7;
	*o++ = 1;
	memcpy(o, mac, 6);
	o += 6;
	*o++ = OPT_MAX_SIZE;
	*o++ = 2;
	put16(o, 1500);
	o += 2;
	if (m->reqip.s_addr != 0) {
		*o++ = OPT_REQUESTED_IP;
		*o++ = 4;
		memcpy(o, &m->reqip, 4);
		o += 4;
	}
	if (m->server.s_addr != 0) {
		*o++ = OPT_SERVER_ID;
		*o++ = 4;
		memcpy(o, &m->server, 4);
		o += 4;
	}
	if (hostlen > 0 && hostlen < 64) {
		*o++ = OPT_HOSTNAME;
		*o++ = (uint8_t)hostlen;
		memcpy(o, host, hostlen);
		o += hostlen;
	}
	*o++ = OPT_PARAMS;
	*o++ = sizeof(params);
	memcpy(o, params, sizeof(params));
	o += sizeof(params);
	*o++ = OPT_END;
	dlen = (size_t)(o - d);
	return dlen < DHCP_MIN ? DHCP_MIN : dlen;
}

size_t
msg_build(uint8_t out[MSG_FRAME_MAX], const struct csend *m, const uint8_t mac[6], const char *host)
{
	uint8_t *eh = out, *ip = out + ETH_LEN, *udp = ip + IP_LEN;
	size_t dlen;

	memset(out, 0, ETH_LEN + IP_LEN + UDP_LEN);
	dlen = msg_payload(udp + UDP_LEN, m, mac, host);
	put16(udp, 68);
	put16(udp + 2, 67);
	put16(udp + 4, (uint16_t)(UDP_LEN + dlen));
	ip[0] = 0x45;
	put16(ip + 2, (uint16_t)(IP_LEN + UDP_LEN + dlen));
	ip[8] = 64;
	ip[9] = 17;
	memcpy(ip + 12, &m->ciaddr, 4);
	memset(ip + 16, 0xff, 4);
	put16(ip + 10, ip_checksum(ip, IP_LEN));
	memset(eh, 0xff, 6);
	memcpy(eh + 6, mac, 6);
	put16(eh + 12, 0x0800);
	return ETH_LEN + IP_LEN + UDP_LEN + dlen;
}

/* An options field: the options field itself, or file or sname when option 52 says so. */
struct field {
	const uint8_t *p;
	size_t len;
};

/* Each option in f lies within it, up to END or its end. */
static bool
field_ok(const struct field *f)
{
	size_t i = 0;

	while (i < f->len) {
		if (f->p[i] == OPT_END) {
			return true;
		}
		if (f->p[i] == OPT_PAD) {
			i++;
			continue;
		}
		if (i + 2 > f->len || i + 2 + (size_t)f->p[i + 1] > f->len) {
			return false;
		}
		i += 2 + (size_t)f->p[i + 1];
	}
	return true;
}

/*
 * Every instance of option code in the n fields, in their order, joined
 * into one value as RFC 3396 says, into out, which holds cap bytes.
 * Returns the joined length, which can be more than cap, or -1 if the
 * option is not there.
 */
static long
gather(const struct field *f, int n, uint8_t code, uint8_t *out, size_t cap)
{
	long total = -1;

	for (int k = 0; k < n; k++) {
		size_t i = 0;

		while (i < f[k].len && f[k].p[i] != OPT_END) {
			if (f[k].p[i] == OPT_PAD) {
				i++;
				continue;
			}
			size_t olen = f[k].p[i + 1];
			if (f[k].p[i] == code) {
				if (total < 0) {
					total = 0;
				}
				for (size_t j = 0; j < olen; j++) {
					if ((size_t)total + j < cap) {
						out[(size_t)total + j] = f[k].p[i + 2 + j];
					}
				}
				total += (long)olen;
			}
			i += 2 + olen;
		}
	}
	return total;
}

/* Option code, 4 bytes, into out, if it is there; false if it has another length. */
static bool
quad(const struct field *f, int n, uint8_t code, void *out, bool *there)
{
	uint8_t v[8];
	long len = gather(f, n, code, v, sizeof(v));

	*there = len >= 0;
	if (len < 0) {
		return true;
	}
	if (len != 4) {
		return false;
	}
	memcpy(out, v, 4);
	return true;
}

/* The options in the n fields into l: false if one has a length its kind does not allow. */
static bool
options(const struct field *f, int n, struct lease *l, bool *server, bool *lease)
{
	uint8_t v[1536], b[4];
	bool there;
	long len;

	len = gather(f, n, OPT_MSG_TYPE, v, sizeof(v));
	if (len != 1) {
		return false;
	}
	l->type = v[0];
	if (!quad(f, n, OPT_SUBNET, &l->mask, &there) || !quad(f, n, OPT_BROADCAST, &l->broadcast, &there) ||
	    !quad(f, n, OPT_SERVER_ID, &l->server, server)) {
		return false;
	}
	if (!quad(f, n, OPT_LEASE, b, lease)) {
		return false;
	}
	l->lease = *lease ? get32(b) : 0;
	if (!quad(f, n, OPT_T1, b, &there)) {
		return false;
	}
	l->t1 = there ? get32(b) : 0;
	if (!quad(f, n, OPT_T2, b, &there)) {
		return false;
	}
	l->t2 = there ? get32(b) : 0;
	len = gather(f, n, OPT_ROUTER, v, sizeof(v));
	if (len == 0 || (len > 0 && len % 4 != 0)) {
		return false;
	}
	if (len > 0) {
		memcpy(&l->router, v, 4);
	}
	len = gather(f, n, OPT_DNS, v, sizeof(v));
	if (len == 0 || (len > 0 && len % 4 != 0)) {
		return false;
	}
	for (long k = 0; k + 4 <= len && (size_t)k + 4 <= sizeof(v) && l->ndns < 3; k += 4) {
		memcpy(&l->dns[l->ndns++], v + k, 4);
	}
	len = gather(f, n, OPT_DOMAIN, v, sizeof(v));
	while (len > 0 && (size_t)len <= sizeof(v) && v[len - 1] == '\0') {
		len--;
	}
	if (len > 0 && domain_ok((const char *)v, (size_t)len)) {
		memcpy(l->domain, v, (size_t)len);
		l->domain[len] = '\0';
	}
	return true;
}

bool
msg_parse(const uint8_t *f, size_t len, uint32_t xid, const uint8_t mac[6], struct lease *l)
{
	struct field fields[3];
	uint8_t v[4];
	bool server, lease;
	int overload = 0, n = 0;

	memset(l, 0, sizeof(*l));
	if (len < ETH_LEN + IP_LEN || get16(f + 12) != 0x0800) {
		return false;
	}
	const uint8_t *ip = f + ETH_LEN;
	size_t ihl = (size_t)(ip[0] & 0x0f) * 4, iplen = get16(ip + 2);
	if ((ip[0] >> 4) != 4 || ihl < IP_LEN || iplen < ihl + UDP_LEN || iplen > len - ETH_LEN ||
	    ip[9] != 17 || (get16(ip + 6) & 0x3fff) != 0 || ip_checksum(ip, ihl) != 0) {
		return false;
	}
	const uint8_t *udp = ip + ihl;
	size_t ulen = get16(udp + 4);
	if (get16(udp + 2) != 68 || ulen < UDP_LEN + DHCP_FIXED || ulen > iplen - ihl ||
	    (get16(udp + 6) != 0 && udp_checksum(ip, udp, ulen) != 0)) {
		return false;
	}
	const uint8_t *d = udp + UDP_LEN;
	size_t dlen = ulen - UDP_LEN;
	if (d[0] != 2 || d[1] != 1 || d[2] != 6 || memcmp(d + 4, &xid, 4) != 0 || memcmp(d + 28, mac, 6) != 0 ||
	    get32(d + 236) != 0x63825363) {
		return false;
	}
	memcpy(&l->addr, d + 16, 4);
	fields[n++] = (struct field){ d + DHCP_FIXED, dlen - DHCP_FIXED };
	if (!field_ok(&fields[0])) {
		return false;
	}
	long olen = gather(fields, 1, OPT_OVERLOAD, v, sizeof(v));
	if (olen >= 0) {
		if (olen != 1 || v[0] < 1 || v[0] > 3) {
			return false;
		}
		overload = v[0];
	}
	if (overload & 1) {
		fields[n++] = (struct field){ d + 108, 128 };
	}
	if (overload & 2) {
		fields[n++] = (struct field){ d + 44, 64 };
	}
	for (int k = 1; k < n; k++) {
		if (!field_ok(&fields[k])) {
			return false;
		}
	}
	if (!options(fields, n, l, &server, &lease) || (server && l->server.s_addr == 0)) {
		return false;
	}
	switch (l->type) {
	case DHCPOFFER:
	case DHCPACK:
		return l->addr.s_addr != 0 && server && lease && l->lease > 0;
	case DHCPNAK:
		return server;
	default:
		return false;
	}
}
