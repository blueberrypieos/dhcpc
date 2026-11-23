/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 The Blueberry Pie OS Authors
 *
 * usage: test_msg
 *
 * Builds and parses DHCP frames with msg.c on the build machine, and
 * prints each failed check. The exit status is the number of failures.
 */

#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "msg.h"

static int failures;

#define CHECK(cond) do { \
	if (!(cond)) { \
		printf("%s:%d: %s: failed: %s\n", __FILE__, __LINE__, __func__, #cond); \
		failures++; \
	} \
} while (0)

static const uint8_t mac[6] = { 2, 0, 0, 0, 0, 1 };
static const uint8_t smac[6] = { 2, 0, 0, 0, 0, 0x11 };
static const uint32_t xid = 0x12345678;

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
sum(const uint8_t *p, size_t len, uint32_t s)
{
	for (size_t i = 0; i + 1 < len; i += 2) {
		s += get16(p + i);
	}
	if (len & 1) {
		s += (uint32_t)p[len - 1] << 8;
	}
	while (s >> 16) {
		s = (s & 0xffff) + (s >> 16);
	}
	return s;
}

static uint16_t
cksum(const uint8_t *p, size_t len)
{
	return (uint16_t)~sum(p, len, 0);
}

/* Give the UDP datagram in a server_frame() frame its checksum. */
static void
udp_sum(uint8_t *frame)
{
	uint8_t *ip = frame + 14, *udp = ip + 20, pseudo[12];
	size_t ulen = get16(udp + 4);
	uint16_t c;

	memcpy(pseudo, ip + 12, 8);
	pseudo[8] = 0;
	pseudo[9] = 17;
	put16(pseudo + 10, (uint16_t)ulen);
	put16(udp + 6, 0);
	c = (uint16_t)~sum(udp, ulen, sum(pseudo, 12, 0));
	put16(udp + 6, c == 0 ? 0xffff : c);
}

/*
 * A server's frame: opts, olen bytes, in the options field; file and sname,
 * if not NULL, in theirs. Returns its length; frame has room for 1500.
 */
static size_t
server_frame(uint8_t *frame, const uint8_t *opts, size_t olen, const uint8_t *file, size_t flen,
    const uint8_t *sname, size_t slen)
{
	uint8_t *ip = frame + 14, *udp = ip + 20, *d = udp + 8;
	size_t dlen = 240 + olen;

	memset(frame, 0, 1500);
	memcpy(frame, mac, 6);
	memcpy(frame + 6, smac, 6);
	put16(frame + 12, 0x0800);
	d[0] = 2;
	d[1] = 1;
	d[2] = 6;
	memcpy(d + 4, &xid, 4);
	inet_pton(AF_INET, "10.0.0.5", d + 16);
	memcpy(d + 28, mac, 6);
	if (sname != NULL) {
		memcpy(d + 44, sname, slen);
	}
	if (file != NULL) {
		memcpy(d + 108, file, flen);
	}
	d[236] = 0x63;
	d[237] = 0x82;
	d[238] = 0x53;
	d[239] = 0x63;
	memcpy(d + 240, opts, olen);
	put16(udp, 67);
	put16(udp + 2, 68);
	put16(udp + 4, (uint16_t)(8 + dlen));
	ip[0] = 0x45;
	put16(ip + 2, (uint16_t)(28 + dlen));
	ip[8] = 64;
	ip[9] = 17;
	inet_pton(AF_INET, "10.0.0.1", ip + 12);
	inet_pton(AF_INET, "10.0.0.5", ip + 16);
	put16(ip + 10, cksum(ip, 20));
	return 14 + 28 + dlen;
}

#define ACK_TYPE        53, 1, 5
#define SERVER          54, 4, 10, 0, 0, 1
#define LEASE           51, 4, 0, 0, 0x0e, 0x10
#define ROUTER          3, 4, 10, 0, 0, 1
#define MASK            1, 4, 255, 255, 255, 0

static void
test_ack(void)
{
	uint8_t frame[1500];
	struct lease l;
	const uint8_t opts[] = { ACK_TYPE, SERVER, LEASE, ROUTER, MASK, 6, 8, 10, 0, 0, 2, 10, 0, 0, 3,
		15, 4, 'h', 'o', 'm', 'e', 58, 4, 0, 0, 7, 8, 59, 4, 0, 0, 0x0c, 0x4e, 255 };
	size_t len = server_frame(frame, opts, sizeof(opts), NULL, 0, NULL, 0);

	CHECK(msg_parse(frame, len, xid, mac, &l));
	CHECK(l.type == DHCPACK && l.lease == 3600 && l.t1 == 1800 && l.t2 == 3150);
	CHECK(l.addr.s_addr == inet_addr("10.0.0.5") && l.server.s_addr == inet_addr("10.0.0.1"));
	CHECK(l.router.s_addr == inet_addr("10.0.0.1") && l.mask.s_addr == inet_addr("255.255.255.0"));
	CHECK(l.ndns == 2 && l.dns[1].s_addr == inet_addr("10.0.0.3") && strcmp(l.domain, "home") == 0);

	/* Another xid, another hardware address. */
	CHECK(!msg_parse(frame, len, xid + 1, mac, &l));
	CHECK(!msg_parse(frame, len, xid, smac, &l));
}

static void
test_truncated(void)
{
	uint8_t frame[1500];
	struct lease l;

	/* The lease time runs past the end of the options. */
	const uint8_t cut[] = { ACK_TYPE, SERVER, 51, 4, 0, 0 };
	size_t len = server_frame(frame, cut, sizeof(cut), NULL, 0, NULL, 0);
	CHECK(!msg_parse(frame, len, xid, mac, &l));

	/* A length byte that is not there. */
	const uint8_t nolen[] = { ACK_TYPE, SERVER, LEASE, 51 };
	len = server_frame(frame, nolen, sizeof(nolen), NULL, 0, NULL, 0);
	CHECK(!msg_parse(frame, len, xid, mac, &l));

	/* An ACK without a lease time, or without a server identifier. */
	const uint8_t nolease[] = { ACK_TYPE, SERVER, ROUTER, 255 };
	len = server_frame(frame, nolease, sizeof(nolease), NULL, 0, NULL, 0);
	CHECK(!msg_parse(frame, len, xid, mac, &l));
	const uint8_t noserver[] = { ACK_TYPE, LEASE, 255 };
	len = server_frame(frame, noserver, sizeof(noserver), NULL, 0, NULL, 0);
	CHECK(!msg_parse(frame, len, xid, mac, &l));

	/* A mask of the wrong length. */
	const uint8_t badmask[] = { ACK_TYPE, SERVER, LEASE, 1, 3, 255, 255, 255, 255 };
	len = server_frame(frame, badmask, sizeof(badmask), NULL, 0, NULL, 0);
	CHECK(!msg_parse(frame, len, xid, mac, &l));

	/* An OFFER without a server identifier; a NAK with one. */
	const uint8_t offer[] = { 53, 1, 2, LEASE, 255 };
	len = server_frame(frame, offer, sizeof(offer), NULL, 0, NULL, 0);
	CHECK(!msg_parse(frame, len, xid, mac, &l));
	const uint8_t nak[] = { 53, 1, 6, SERVER, 255 };
	len = server_frame(frame, nak, sizeof(nak), NULL, 0, NULL, 0);
	CHECK(msg_parse(frame, len, xid, mac, &l) && l.type == DHCPNAK);
}

static void
test_envelope(void)
{
	uint8_t frame[1500];
	struct lease l;
	const uint8_t opts[] = { ACK_TYPE, SERVER, LEASE, 255 };
	size_t len = server_frame(frame, opts, sizeof(opts), NULL, 0, NULL, 0);

	CHECK(msg_parse(frame, len, xid, mac, &l));
	/* The frame shorter than its IP length. */
	CHECK(!msg_parse(frame, len - 1, xid, mac, &l));
	/* A wrong IP checksum. */
	frame[14 + 10] ^= 1;
	CHECK(!msg_parse(frame, len, xid, mac, &l));
	frame[14 + 10] ^= 1;
	/* A UDP length that leaves no room for the fixed fields. */
	put16(frame + 34 + 4, 8 + 100);
	CHECK(!msg_parse(frame, len, xid, mac, &l));
	put16(frame + 34 + 4, (uint16_t)(len - 34));
	CHECK(msg_parse(frame, len, xid, mac, &l));
	/* A UDP length past the IP datagram's end. */
	put16(frame + 34 + 4, (uint16_t)(len - 34 + 1));
	CHECK(!msg_parse(frame, len, xid, mac, &l));
	/* Another port. */
	put16(frame + 34 + 4, (uint16_t)(len - 34));
	put16(frame + 34 + 2, 69);
	CHECK(!msg_parse(frame, len, xid, mac, &l));
	put16(frame + 34 + 2, 68);

	/* A UDP checksum: 0 is none; one that is right passes; a wrong one does not. */
	CHECK(msg_parse(frame, len, xid, mac, &l));
	udp_sum(frame);
	CHECK(get16(frame + 34 + 6) != 0 && msg_parse(frame, len, xid, mac, &l));
	frame[42 + 240 + 2] ^= 0x10;
	CHECK(!msg_parse(frame, len, xid, mac, &l));
	frame[42 + 240 + 2] ^= 0x10;
	frame[34 + 7] ^= 1;
	CHECK(!msg_parse(frame, len, xid, mac, &l));
	frame[34 + 7] ^= 1;
	CHECK(msg_parse(frame, len, xid, mac, &l));

	/* Ethernet's hardware type and length only. */
	frame[42 + 1] = 6;
	udp_sum(frame);
	CHECK(!msg_parse(frame, len, xid, mac, &l));
	frame[42 + 1] = 1;
	frame[42 + 2] = 8;
	udp_sum(frame);
	CHECK(!msg_parse(frame, len, xid, mac, &l));
	frame[42 + 2] = 6;
	udp_sum(frame);
	CHECK(msg_parse(frame, len, xid, mac, &l));
}

static void
test_overload(void)
{
	uint8_t frame[1500];
	struct lease l;

	/* Option 52 says the file field has options: the lease time and server are there. */
	const uint8_t opts[] = { ACK_TYPE, 52, 1, 1, 255 };
	const uint8_t file[] = { SERVER, LEASE, ROUTER, 255 };
	size_t len = server_frame(frame, opts, sizeof(opts), file, sizeof(file), NULL, 0);
	CHECK(msg_parse(frame, len, xid, mac, &l));
	CHECK(l.lease == 3600 && l.server.s_addr == inet_addr("10.0.0.1"));

	/* Both fields, sname too. */
	const uint8_t opts3[] = { ACK_TYPE, 52, 1, 3, 255 };
	const uint8_t file3[] = { SERVER, 255 };
	const uint8_t sname3[] = { LEASE, 15, 3, 'l', 'a', 'n', 255 };
	len = server_frame(frame, opts3, sizeof(opts3), file3, sizeof(file3), sname3, sizeof(sname3));
	CHECK(msg_parse(frame, len, xid, mac, &l));
	CHECK(l.lease == 3600 && strcmp(l.domain, "lan") == 0);

	/* Without option 52, the fields are not options. */
	const uint8_t opts0[] = { ACK_TYPE, 255 };
	len = server_frame(frame, opts0, sizeof(opts0), file3, sizeof(file3), sname3, sizeof(sname3));
	CHECK(!msg_parse(frame, len, xid, mac, &l));

	/* An option in the file field that runs past it. */
	uint8_t longfile[128];
	memset(longfile, 0, sizeof(longfile));
	longfile[126] = 51;
	longfile[127] = 4;
	const uint8_t opts1[] = { ACK_TYPE, SERVER, LEASE, 52, 1, 1, 255 };
	len = server_frame(frame, opts1, sizeof(opts1), longfile, sizeof(longfile), NULL, 0);
	CHECK(!msg_parse(frame, len, xid, mac, &l));
}

static void
test_concat(void)
{
	uint8_t frame[1500];
	struct lease l;
	size_t len;

	/* A lease time in two parts, 2 and 2 bytes. */
	const uint8_t lease2[] = { ACK_TYPE, SERVER, 51, 2, 0, 0, 51, 2, 0x0e, 0x10, 255 };
	len = server_frame(frame, lease2, sizeof(lease2), NULL, 0, NULL, 0);
	CHECK(msg_parse(frame, len, xid, mac, &l) && l.lease == 3600);

	/* A router list in the options field and in file: the first router stays first. */
	const uint8_t opts[] = { ACK_TYPE, SERVER, LEASE, 3, 4, 10, 0, 0, 1, 52, 1, 1, 255 };
	const uint8_t file[] = { 3, 4, 10, 0, 0, 64, 255 };
	len = server_frame(frame, opts, sizeof(opts), file, sizeof(file), NULL, 0);
	CHECK(msg_parse(frame, len, xid, mac, &l) && l.router.s_addr == inet_addr("10.0.0.1"));

	/* Options field, then file, then sname: a lease time in the options field and sname. */
	const uint8_t opts2[] = { ACK_TYPE, SERVER, 51, 3, 0, 0, 0x0e, 52, 1, 3, 255 };
	const uint8_t file2[] = { 6, 4, 10, 0, 0, 2, 255 };
	const uint8_t sname2[] = { 51, 1, 0x10, 6, 4, 10, 0, 0, 3, 255 };
	len = server_frame(frame, opts2, sizeof(opts2), file2, sizeof(file2), sname2, sizeof(sname2));
	CHECK(msg_parse(frame, len, xid, mac, &l) && l.lease == 3600);
	CHECK(l.ndns == 2 && l.dns[0].s_addr == inet_addr("10.0.0.2") && l.dns[1].s_addr == inet_addr("10.0.0.3"));

	/* A domain in two parts. */
	const uint8_t dom[] = { ACK_TYPE, SERVER, LEASE, 15, 2, 'h', 'o', 15, 2, 'm', 'e', 255 };
	len = server_frame(frame, dom, sizeof(dom), NULL, 0, NULL, 0);
	CHECK(msg_parse(frame, len, xid, mac, &l) && strcmp(l.domain, "home") == 0);

	/* Joined, a message type of 2 bytes, a mask of 5 or a router list of 6 is refused. */
	const uint8_t type2[] = { ACK_TYPE, 53, 1, 5, SERVER, LEASE, 255 };
	len = server_frame(frame, type2, sizeof(type2), NULL, 0, NULL, 0);
	CHECK(!msg_parse(frame, len, xid, mac, &l));
	const uint8_t mask5[] = { ACK_TYPE, SERVER, LEASE, 1, 2, 255, 255, 1, 3, 255, 0, 0, 255 };
	len = server_frame(frame, mask5, sizeof(mask5), NULL, 0, NULL, 0);
	CHECK(!msg_parse(frame, len, xid, mac, &l));
	const uint8_t router6[] = { ACK_TYPE, SERVER, LEASE, 3, 4, 10, 0, 0, 1, 3, 2, 10, 0, 255 };
	len = server_frame(frame, router6, sizeof(router6), NULL, 0, NULL, 0);
	CHECK(!msg_parse(frame, len, xid, mac, &l));

	/* Option 52 in file is not read. */
	const uint8_t opts3[] = { ACK_TYPE, SERVER, LEASE, 52, 1, 1, 255 };
	const uint8_t file3[] = { 52, 1, 2, 255 };
	const uint8_t sname3[] = { 15, 3, 'l', 'a', 'n', 255 };
	len = server_frame(frame, opts3, sizeof(opts3), file3, sizeof(file3), sname3, sizeof(sname3));
	CHECK(msg_parse(frame, len, xid, mac, &l) && l.domain[0] == '\0');
}

static void
test_mandatory(void)
{
	uint8_t frame[1500];
	struct lease l;
	size_t len;

	/* A server identifier of 0.0.0.0 is no server identifier. */
	const uint8_t zero[] = { ACK_TYPE, 54, 4, 0, 0, 0, 0, LEASE, 255 };
	len = server_frame(frame, zero, sizeof(zero), NULL, 0, NULL, 0);
	CHECK(!msg_parse(frame, len, xid, mac, &l));
	const uint8_t nak0[] = { 53, 1, 6, 54, 4, 0, 0, 0, 0, 255 };
	len = server_frame(frame, nak0, sizeof(nak0), NULL, 0, NULL, 0);
	CHECK(!msg_parse(frame, len, xid, mac, &l));

	/* An OFFER needs a lease time too. */
	const uint8_t offer[] = { 53, 1, 2, SERVER, 255 };
	len = server_frame(frame, offer, sizeof(offer), NULL, 0, NULL, 0);
	CHECK(!msg_parse(frame, len, xid, mac, &l));
	const uint8_t offer0[] = { 53, 1, 2, SERVER, 51, 4, 0, 0, 0, 0, 255 };
	len = server_frame(frame, offer0, sizeof(offer0), NULL, 0, NULL, 0);
	CHECK(!msg_parse(frame, len, xid, mac, &l));
	const uint8_t offer1[] = { 53, 1, 2, SERVER, LEASE, 255 };
	len = server_frame(frame, offer1, sizeof(offer1), NULL, 0, NULL, 0);
	CHECK(msg_parse(frame, len, xid, mac, &l) && l.type == DHCPOFFER && l.lease == 3600);

	/* A domain of no bytes, or with other characters, is left out; the reply stands. */
	const uint8_t empty[] = { ACK_TYPE, SERVER, LEASE, 15, 0, 255 };
	len = server_frame(frame, empty, sizeof(empty), NULL, 0, NULL, 0);
	CHECK(msg_parse(frame, len, xid, mac, &l) && l.domain[0] == '\0');
	const uint8_t bad[] = { ACK_TYPE, SERVER, LEASE, 15, 5, 'a', '\n', 'n', 's', ' ', 255 };
	len = server_frame(frame, bad, sizeof(bad), NULL, 0, NULL, 0);
	CHECK(msg_parse(frame, len, xid, mac, &l) && l.domain[0] == '\0');
	const uint8_t nul[] = { ACK_TYPE, SERVER, LEASE, 15, 5, 'h', 'o', 'm', 'e', 0, 255 };
	len = server_frame(frame, nul, sizeof(nul), NULL, 0, NULL, 0);
	CHECK(msg_parse(frame, len, xid, mac, &l) && strcmp(l.domain, "home") == 0);
}

static void
test_build(void)
{
	uint8_t frame[MSG_FRAME_MAX];
	struct csend m;
	size_t len;

	memset(&m, 0, sizeof(m));
	m.type = DHCPREQUEST;
	m.xid = xid;
	inet_pton(AF_INET, "10.0.0.5", &m.reqip);
	len = msg_build(frame, &m, mac, "pie");
	CHECK(len == 14 + 20 + 8 + 300);
	CHECK(memcmp(frame, "\xff\xff\xff\xff\xff\xff", 6) == 0 && memcmp(frame + 6, mac, 6) == 0);
	CHECK(memcmp(frame + 14 + 16, "\xff\xff\xff\xff", 4) == 0 && cksum(frame + 14, 20) == 0);
	CHECK(get16(frame + 42 + 10) == 0x8000);
	CHECK(memmem(frame + 42 + 240, 60, "\x32\x04\x0a\x00\x00\x05", 6) != NULL);
	CHECK(memmem(frame + 42 + 240, 60, "\x0c\x03pie", 5) != NULL);
	CHECK(memmem(frame + 42 + 240, 60, "\x36\x04", 2) == NULL);

	/* Rebinding: broadcast, from the address. */
	memset(&m, 0, sizeof(m));
	m.type = DHCPREQUEST;
	m.xid = xid;
	inet_pton(AF_INET, "10.0.0.5", &m.ciaddr);
	len = msg_build(frame, &m, mac, NULL);
	CHECK(memcmp(frame, "\xff\xff\xff\xff\xff\xff", 6) == 0 && memcmp(frame + 14 + 12, "\x0a\x00\x00\x05", 4) == 0);
	CHECK(memcmp(frame + 14 + 16, "\xff\xff\xff\xff", 4) == 0 && cksum(frame + 14, 20) == 0);

	/* Renewing: the message alone, for the UDP socket, without the broadcast flag. */
	uint8_t d[MSG_DHCP_MAX];
	m.unicast = true;
	inet_pton(AF_INET, "10.0.0.1", &m.dst);
	len = msg_payload(d, &m, mac, "pie");
	CHECK(len == 300 && d[0] == 1 && d[1] == 1 && d[2] == 6 && memcmp(d + 4, &xid, 4) == 0);
	CHECK(get16(d + 10) == 0 && memcmp(d + 12, "\x0a\x00\x00\x05", 4) == 0 && memcmp(d + 28, mac, 6) == 0);
	CHECK(memcmp(d + 236, "\x63\x82\x53\x63", 4) == 0 && memcmp(d + 240, "\x35\x01\x03", 3) == 0);
	CHECK(memmem(d + 240, 60, "\x32\x04", 2) == NULL && memmem(d + 240, 60, "\x36\x04", 2) == NULL);
}

int
main(void)
{
	test_ack();
	test_truncated();
	test_envelope();
	test_overload();
	test_concat();
	test_mandatory();
	test_build();
	printf("test_msg: %d failure(s)\n", failures);
	return failures;
}
