/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 The Blueberry Pie OS Authors
 *
 * usage: test_state
 *
 * Writes and reads lease records and default-route markers with state.c
 * on the build machine, and prints each failed check. The exit status is
 * the number of failures.
 */

#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "state.h"

static int failures;

#define CHECK(cond) do { \
	if (!(cond)) { \
		printf("%s:%d: %s: failed: %s\n", __FILE__, __LINE__, __func__, #cond); \
		failures++; \
	} \
} while (0)

static const uint8_t mac1[6] = { 0x52, 0x54, 0x00, 0x12, 0xab, 0x56 };
static const uint8_t mac2[6] = { 2, 0, 0, 0, 0, 2 };

static struct in_addr
a4(const char *s)
{
	struct in_addr a;

	inet_pton(AF_INET, s, &a);
	return a;
}

static bool
same(struct in_addr x, const char *s)
{
	return x.s_addr == a4(s).s_addr;
}

/* A lease of 10.0.2.15 for 86400 s, asked for at 12345 ms, on interface 4. */
static struct record
sample(void)
{
	struct record r;

	memset(&r, 0, sizeof(r));
	r.l.type = DHCPACK;
	r.l.addr = a4("10.0.2.15");
	r.l.mask = a4("255.255.255.0");
	r.l.router = a4("10.0.2.2");
	r.l.server = a4("10.0.2.2");
	r.l.ndns = 1;
	r.l.dns[0] = a4("10.0.2.3");
	strcpy(r.l.domain, "example");
	r.l.lease = 86400;
	r.l.t1 = 43200;
	r.l.sent = 12345;
	memcpy(r.mac, mac1, 6);
	r.ifindex = 4;
	r.status = L_CONFIRMED;
	r.has_lease = true;
	return r;
}

static bool
same_record(const struct record *a, const struct record *b)
{
	return a->l.addr.s_addr == b->l.addr.s_addr && a->l.mask.s_addr == b->l.mask.s_addr &&
	    a->l.router.s_addr == b->l.router.s_addr && a->l.server.s_addr == b->l.server.s_addr &&
	    a->l.broadcast.s_addr == b->l.broadcast.s_addr && a->l.ndns == b->l.ndns &&
	    (a->l.ndns == 0 || a->l.dns[0].s_addr == b->l.dns[0].s_addr) && strcmp(a->l.domain, b->l.domain) == 0 &&
	    a->l.lease == b->l.lease && a->l.t1 == b->l.t1 && a->l.t2 == b->l.t2 && a->l.sent == b->l.sent &&
	    memcmp(a->mac, b->mac, 6) == 0 && a->ifindex == b->ifindex && a->status == b->status &&
	    a->has_lease == b->has_lease && a->nremove == b->nremove &&
	    (a->nremove == 0 || (a->remove[0].addr.s_addr == b->remove[0].addr.s_addr &&
	    a->remove[0].mask.s_addr == b->remove[0].mask.s_addr));
}

/* The end line state.c writes, after body: FNV-1a over it. */
static size_t
seal(char *text, size_t cap)
{
	uint32_t h = 2166136261u;
	size_t len = strlen(text);

	for (size_t i = 0; i < len; i++) {
		h ^= (uint8_t)text[i];
		h *= 16777619u;
	}
	snprintf(text + len, cap - len, "end %08x\n", (unsigned int)h);
	return strlen(text);
}

static const char body[] =
    "address 10.0.2.15\nmask 255.255.255.0\nrouter 10.0.2.2\nserver 10.0.2.2\nbroadcast 0.0.0.0\n"
    "lease 86400\nt1 0\nt2 0\nsent 12345\nmac 52:54:00:12:ab:56\nifindex 4\nstatus held\n";

/* body with one line replaced by with, or left out if with is empty, sealed. */
static bool
parses_with(const char *line, const char *with)
{
	char text[STATE_TEXT_MAX];
	struct record r;
	const char *at = strstr(body, line);
	size_t pre;

	if (at == NULL) {
		return true;
	}
	pre = (size_t)(at - body);
	memcpy(text, body, pre);
	snprintf(text + pre, sizeof(text) - pre, "%s%s", with, at + strlen(line));
	return record_parse(text, seal(text, sizeof(text)), &r);
}

static void
test_record(void)
{
	struct record r = sample(), back;
	char text[STATE_TEXT_MAX];
	size_t len = record_format(text, sizeof(text), &r);
	int cut = 0;

	CHECK(len < sizeof(text) && record_parse(text, len, &back) && same_record(&r, &back));
	CHECK(strstr(text, "status confirmed\nmac 52:54:00:12:ab:56\nifindex 4\nend ") != NULL &&
	    text[len - 1] == '\n');

	/* Cut short anywhere, before its last line or within it: not a record. */
	for (size_t n = 0; n < len; n++) {
		cut += record_parse(text, n, &back);
	}
	CHECK(cut == 0);

	/* A byte changed. */
	char *addr = strstr(text, "10.0.2.15");
	addr[8] = '6';
	CHECK(!record_parse(text, len, &back));
	addr[8] = '5';
	CHECK(record_parse(text, len, &back));

	/* Each status, and no name servers or domain. */
	r.status = L_CHECKING;
	r.l.ndns = 0;
	r.l.domain[0] = '\0';
	len = record_format(text, sizeof(text), &r);
	CHECK(record_parse(text, len, &back) && back.status == L_CHECKING && back.l.ndns == 0);
	r.status = L_HELD;
	len = record_format(text, sizeof(text), &r);
	CHECK(record_parse(text, len, &back) && back.status == L_HELD);

	/* Too small a buffer. */
	CHECK(record_format(text, 40, &r) >= 40);

	/* Found, and with addresses to remove. */
	r.status = L_FOUND;
	CHECK(record_pend(&r, a4("10.0.9.7"), a4("255.255.0.0")) && record_pend(&r, a4("10.0.9.7"), a4("255.0.0.0")));
	CHECK(r.nremove == 1);
	len = record_format(text, sizeof(text), &r);
	CHECK(strstr(text, "status found\nremove 10.0.9.7/16\nmac ") != NULL);
	CHECK(record_parse(text, len, &back) && back.status == L_FOUND && same_record(&r, &back));

	/* No lease: only the addresses to remove and the interface, whose index is 0 once it went. */
	memset(&r, 0, sizeof(r));
	memcpy(r.mac, mac1, 6);
	len = record_format(text, sizeof(text), &r);
	CHECK(len == 32 + 13 && strncmp(text, "mac 52:54:00:12:ab:56\nifindex 0\nend ", 36) == 0);
	CHECK(record_parse(text, len, &back) && !back.has_lease && back.ifindex == 0 && back.nremove == 0);
	record_pend(&r, a4("10.0.2.15"), a4("255.255.255.0"));
	len = record_format(text, sizeof(text), &r);
	CHECK(record_parse(text, len, &back) && !back.has_lease && back.nremove == 1 &&
	    same(back.remove[0].addr, "10.0.2.15") && same(back.remove[0].mask, "255.255.255.0"));
	record_unpend(&r, a4("10.0.2.15"));
	CHECK(r.nremove == 0);
	for (int i = 0; i < REMOVE_MAX; i++) {
		struct in_addr x = { htonl(0x0a000100u + (uint32_t)i) };
		CHECK(record_pend(&r, x, a4("255.255.255.0")));
	}
	CHECK(!record_pend(&r, a4("10.9.9.9"), a4("255.255.255.0")) && r.nremove == REMOVE_MAX);

	/* The record of an earlier dhcpc 4 build, without an end line, is no record. */
	const char old[] = "address 10.0.2.15\nmask 255.255.255.0\nlease 86400\nconfirmed 1\n";
	CHECK(!record_parse(old, strlen(old), &back));
}

static void
test_record_fields(void)
{
	char text[STATE_TEXT_MAX];
	struct record r;

	strcpy(text, body);
	CHECK(record_parse(text, seal(text, sizeof(text)), &r) && r.status == L_HELD && r.ifindex == 4);

	/* Each field is needed, the status too. */
	CHECK(!parses_with("status held\n", ""));
	CHECK(!parses_with("sent 12345\n", ""));
	CHECK(!parses_with("mac 52:54:00:12:ab:56\n", ""));
	CHECK(!parses_with("ifindex 4\n", ""));
	CHECK(!parses_with("lease 86400\n", ""));

	/* Once each, known, and valid. */
	CHECK(!parses_with("mask 255.255.255.0\n", "mask 255.255.255.0\nmask 255.255.255.0\n"));
	CHECK(!parses_with("status held\n", "status held\nconfirmed 1\n"));
	CHECK(!parses_with("status held\n", "status maybe\n"));
	CHECK(!parses_with("lease 86400\n", "lease 86400x\n"));
	CHECK(!parses_with("lease 86400\n", "lease 4294967296\n"));
	CHECK(!parses_with("lease 86400\n", "lease 0\n"));
	CHECK(!parses_with("lease 86400\n", "lease \n"));
	CHECK(!parses_with("sent 12345\n", "sent -1\n"));
	CHECK(!parses_with("ifindex 4\n", "ifindex 0\n"));
	CHECK(!parses_with("mac 52:54:00:12:ab:56\n", "mac 52:54:00:12:ab\n"));
	CHECK(!parses_with("mac 52:54:00:12:ab:56\n", "mac 52-54-00-12-ab-56\n"));
	CHECK(!parses_with("mask 255.255.255.0\n", "mask 255.0.255.0\n"));
	CHECK(!parses_with("address 10.0.2.15\n", "address 0.0.0.0\n"));
	CHECK(!parses_with("address 10.0.2.15\n", "address 10.0.2\n"));
	CHECK(!parses_with("router 10.0.2.2\n", "router  10.0.2.2\n"));
	CHECK(!parses_with("status held\n", "status held\ndomain a\\b\n"));
	CHECK(!parses_with("status held\n",
	    "status held\nnameserver 1.1.1.1\nnameserver 1.1.1.2\nnameserver 1.1.1.3\nnameserver 1.1.1.4\n"));
	CHECK(parses_with("status held\n", "status held\ndomain home.example\nnameserver 10.0.2.3\n"));
	CHECK(parses_with("lease 86400\n", "lease 4294967295\n"));

	/* A lease is whole or not there; the index is 0 only without one. */
	CHECK(!parses_with("lease 86400\n", ""));
	CHECK(!parses_with("ifindex 4\n", "ifindex 0\n"));
	CHECK(parses_with("status held\n", "status found\n"));
	CHECK(!parses_with("status held\n", "status lost\n"));

	/* Addresses to remove: a.b.c.d/len, each once, no more than REMOVE_MAX. */
	CHECK(parses_with("ifindex 4\n", "ifindex 4\nremove 10.0.2.16/24\nremove 10.0.3.1/32\n"));
	CHECK(!parses_with("ifindex 4\n", "ifindex 4\nremove 10.0.2.16/24\nremove 10.0.2.16/24\n"));
	CHECK(!parses_with("ifindex 4\n", "ifindex 4\nremove 10.0.2.16\n"));
	CHECK(!parses_with("ifindex 4\n", "ifindex 4\nremove 10.0.2.16/0\n"));
	CHECK(!parses_with("ifindex 4\n", "ifindex 4\nremove 10.0.2.16/33\n"));
	CHECK(!parses_with("ifindex 4\n", "ifindex 4\nremove 0.0.0.0/24\n"));
	CHECK(!parses_with("ifindex 4\n", "ifindex 4\nremove 10.0.2.16 /24\n"));
	char many[400] = "ifindex 4\n";
	for (int i = 0; i <= REMOVE_MAX; i++) {
		snprintf(many + strlen(many), sizeof(many) - strlen(many), "remove 10.0.1.%d/24\n", i + 1);
	}
	CHECK(!parses_with("ifindex 4\n", many));

	/* Without a lease: no lease field, name server or domain. */
	strcpy(text, "remove 10.0.2.15/24\nmac 52:54:00:12:ab:56\nifindex 0\n");
	CHECK(record_parse(text, seal(text, sizeof(text)), &r) && !r.has_lease && r.nremove == 1);
	strcpy(text, "nameserver 10.0.2.3\nmac 52:54:00:12:ab:56\nifindex 0\n");
	CHECK(!record_parse(text, seal(text, sizeof(text)), &r));
	strcpy(text, "status held\nmac 52:54:00:12:ab:56\nifindex 5\n");
	CHECK(!record_parse(text, seal(text, sizeof(text)), &r));
	strcpy(text, "mac 52:54:00:12:ab:56\n");
	CHECK(!record_parse(text, seal(text, sizeof(text)), &r));
}

static void
test_current(void)
{
	struct record r = sample();

	CHECK(record_current(&r, mac1, 4, true, 20000));
	/* Ended, asked for later than now, on another interface or adapter, or its address gone. */
	CHECK(!record_current(&r, mac1, 4, true, 12345 + 86400000));
	CHECK(!record_current(&r, mac1, 4, true, 12000));
	CHECK(!record_current(&r, mac1, 5, true, 20000));
	CHECK(!record_current(&r, mac1, 0, true, 20000));
	CHECK(!record_current(&r, mac2, 4, true, 20000));
	CHECK(!record_current(&r, mac1, 4, false, 20000));
}

static void
test_takeover(void)
{
	struct record r = sample(), none;
	struct in_addr first = a4("10.0.2.15"), m24 = a4("255.255.255.0");
	struct plan p;

	/* Current: taken over with its status and times. */
	r.status = L_CHECKING;
	plan_takeover(&r, mac1, 4, true, &first, m24, 20000, &p);
	CHECK(p.what == TAKE_ADOPT && p.status == L_CHECKING && !p.remove);
	CHECK(p.l.sent == 12345 && p.l.lease == 86400 && same(p.l.router, "10.0.2.2"));
	r.status = L_CONFIRMED;
	plan_takeover(&r, mac1, 4, true, &first, m24, 20000, &p);
	CHECK(p.what == TAKE_ADOPT && p.status == L_CONFIRMED);

	/* Its interface came again with the same adapter and address: taken over, and asked for again. */
	plan_takeover(&r, mac1, 5, true, &first, m24, 20000, &p);
	CHECK(p.what == TAKE_ADOPT && p.status == L_CHECKING && !p.remove && p.l.sent == 12345);
	r.status = L_FOUND;
	plan_takeover(&r, mac1, 5, true, &first, m24, 20000, &p);
	CHECK(p.what == TAKE_ADOPT && p.status == L_FOUND);
	r.status = L_CONFIRMED;

	/* Ended with its address set: the address goes, and the lease is remembered for a hint. */
	plan_takeover(&r, mac1, 4, true, &first, m24, 12345 + 86400000, &p);
	CHECK(p.what == TAKE_REMEMBER && p.remove && same(p.rm.addr, "10.0.2.15") && same(p.rm.mask, "255.255.255.0"));
	plan_takeover(&r, mac1, 5, true, &first, m24, 12345 + 86400000, &p);
	CHECK(p.what == TAKE_REMEMBER && p.remove);

	/* Another adapter on the same interface, with the address set: it goes. On a new interface it stays. */
	plan_takeover(&r, mac2, 4, true, &first, m24, 20000, &p);
	CHECK(p.what == TAKE_REMEMBER && p.remove && memcmp(p.mac, mac1, 6) == 0);
	plan_takeover(&r, mac2, 5, true, &first, m24, 20000, &p);
	CHECK(p.what == TAKE_REMEMBER && !p.remove);

	/* The address went: remembered for INIT-REBOOT, nothing removed. */
	plan_takeover(&r, mac1, 5, false, NULL, m24, 20000, &p);
	CHECK(p.what == TAKE_REMEMBER && !p.remove);
	plan_takeover(&r, mac1, 4, false, &first, m24, 20000, &p);
	CHECK(p.what == TAKE_REMEMBER && !p.remove);

	/* A record without a lease: this dhcpc set nothing here, so an address there is not taken. */
	memset(&none, 0, sizeof(none));
	memcpy(none.mac, mac1, 6);
	none.ifindex = 4;
	plan_takeover(&none, mac1, 4, false, &first, m24, 20000, &p);
	CHECK(p.what == TAKE_NONE && !p.remove);

	/* No record, as after a soft reboot or with one cut short, and an address set: found, asked for with INIT-REBOOT. */
	plan_takeover(NULL, mac1, 4, false, &first, m24, 20000, &p);
	CHECK(p.what == TAKE_ADOPT && p.status == L_FOUND && !p.remove);
	CHECK(memcmp(p.mac, mac1, 6) == 0);
	CHECK(same(p.l.addr, "10.0.2.15") && same(p.l.mask, "255.255.255.0") && p.l.router.s_addr == 0);
	CHECK(p.l.sent == 20000 && p.l.lease == REBOOT_WAIT_S && lease_end(&p.l) == 20000 + REBOOT_WAIT_S * 1000);
	plan_takeover(NULL, mac1, 4, false, &first, a4("255.0.255.0"), 20000, &p);
	CHECK(same(p.l.mask, "255.255.255.0"));

	/* A record asked for later than now is as none. */
	plan_takeover(&r, mac1, 4, true, &first, m24, 12000, &p);
	CHECK(p.what == TAKE_ADOPT && p.status == L_FOUND && p.l.lease == REBOOT_WAIT_S);

	/* No record and no address: a new lease. */
	plan_takeover(NULL, mac1, 4, false, NULL, m24, 20000, &p);
	CHECK(p.what == TAKE_NONE && !p.remove);
}

static void
test_removed(void)
{
	struct record r;
	struct in_addr a = a4("10.0.2.16"), m = a4("255.255.255.0");

	/* An address leaves the addresses to remove only when it is known to be gone. */
	memset(&r, 0, sizeof(r));
	CHECK(record_removed(&r, a, m, ADDR_SET) && r.nremove == 1);
	CHECK(record_removed(&r, a, m, ADDR_UNKNOWN) && r.nremove == 1);
	CHECK(record_removed(&r, a, m, ADDR_ABSENT) && r.nremove == 0);
	CHECK(record_removed(&r, a, m, ADDR_UNKNOWN) && r.nremove == 1 && same(r.remove[0].addr, "10.0.2.16"));
}

static void
test_may_set(void)
{
	struct record r = sample();

	/* With every slot taken, no new address is set; the lease's own address may be set again. */
	for (int i = 0; i < REMOVE_MAX; i++) {
		struct in_addr x = { htonl(0x0a000100u + (uint32_t)i) };
		CHECK(record_may_set(&r, a4("10.0.9.7")));
		record_pend(&r, x, a4("255.255.255.0"));
	}
	CHECK(r.nremove == REMOVE_MAX && !record_may_set(&r, a4("10.0.9.7")));
	CHECK(record_may_set(&r, a4("10.0.2.15")));
	r.has_lease = false;
	CHECK(!record_may_set(&r, a4("10.0.2.15")));
}

static void
test_here(void)
{
	struct record r = sample();

	/* The same adapter, or the same interface with another adapter, is here; neither is not. */
	CHECK(record_here(&r, mac1, 4) && record_here(&r, mac1, 5) && record_here(&r, mac2, 4));
	CHECK(!record_here(&r, mac2, 5) && !record_here(&r, mac2, 0));
}

static void
test_lease_pending(void)
{
	char text[STATE_TEXT_MAX];
	struct record r = sample(), back;
	struct plan p;
	size_t len;

	/* A lease whose address waited to go: the same write keeps it as the lease's. */
	r.has_lease = false;
	record_pend(&r, a4("10.0.2.15"), a4("255.255.255.0"));
	record_pend(&r, a4("10.0.3.9"), a4("255.255.255.0"));
	struct record s = sample();
	record_lease(&r, &s.l, L_CHECKING);
	CHECK(r.has_lease && r.status == L_CHECKING && r.nremove == 1 && same(r.remove[0].addr, "10.0.3.9"));
	len = record_format(text, sizeof(text), &r);
	CHECK(record_parse(text, len, &back) && back.nremove == 1 && strstr(text, "remove 10.0.2.15") == NULL);

	/* A record that has both is read with the lease winning, so a takeover keeps the address. */
	record_pend(&r, a4("10.0.2.15"), a4("255.255.255.0"));
	CHECK(r.nremove == 2);
	record_reconcile(&r);
	CHECK(r.nremove == 1 && same(r.remove[0].addr, "10.0.3.9"));
	plan_takeover(&r, mac1, 4, true, NULL, a4("255.255.255.0"), 20000, &p);
	CHECK(p.what == TAKE_ADOPT && same(p.l.addr, "10.0.2.15") && !p.remove);
}

static void
test_set_as(void)
{
	struct record r = sample();

	/* Set already with this mask and broadcast: nothing to set again. */
	CHECK(same(lease_broadcast(&r.l), "10.0.2.255"));
	CHECK(lease_set_as(&r.l, a4("255.255.255.0"), a4("10.0.2.255")));
	CHECK(!lease_set_as(&r.l, a4("255.255.0.0"), a4("10.0.255.255")));
	CHECK(!lease_set_as(&r.l, a4("255.255.255.0"), a4("10.0.2.254")));
	r.l.broadcast = a4("10.0.2.254");
	CHECK(lease_set_as(&r.l, a4("255.255.255.0"), a4("10.0.2.254")));
}

static void
test_marker(void)
{
	struct droute r0, r1, r2, r3, r4;
	struct marker m, back, one, none;
	char text[STATE_TEXT_MAX];
	size_t len;
	int cut = 0;

	memset(&m, 0, sizeof(m));
	memset(&r0, 0, sizeof(r0));
	strcpy(r0.name, "en0");
	r0.ifindex = 4;
	r0.router = a4("10.0.2.2");
	r1 = r0;
	strcpy(r1.name, "en1");
	r1.ifindex = 5;

	/* None. */
	len = marker_format(text, sizeof(text), &m);
	CHECK(marker_parse(text, len, &back) && back.n == 0);

	/* While the route changes: the route there and the new one. */
	marker_add(&m, &r0);
	marker_add(&m, &r1);
	marker_add(&m, &r0);
	CHECK(m.n == 2);
	len = marker_format(text, sizeof(text), &m);
	CHECK(strncmp(text, "route en0 4 10.0.2.2\nroute en1 5 10.0.2.2\nend ", 46) == 0);
	CHECK(marker_parse(text, len, &back) && back.n == 2 && strcmp(back.r[1].name, "en1") == 0 &&
	    back.r[1].ifindex == 5 && same(back.r[1].router, "10.0.2.2"));
	for (size_t n = 0; n < len; n++) {
		cut += marker_parse(text, n, &back);
	}
	CHECK(cut == 0);

	/* Full: nothing goes, and no more is added. */
	r2 = r1;
	r2.ifindex = 6;
	r3 = r1;
	r3.ifindex = 7;
	r4 = r1;
	r4.ifindex = 8;
	CHECK(marker_add(&m, &r2) && marker_add(&m, &r3) && marker_add(&m, &r0));
	CHECK(!marker_add(&m, &r4) && m.n == MARKER_MAX && m.r[0].ifindex == 4 && m.r[MARKER_MAX - 1].ifindex == 7);

	/* dhcpc's: its router through its interface. The same router through another is not. */
	memset(&one, 0, sizeof(one));
	marker_add(&one, &r0);
	CHECK(marker_owns(&one, a4("10.0.2.2"), 4, "en0"));
	CHECK(!marker_owns(&one, a4("10.0.2.2"), 5, "en1"));
	CHECK(!marker_owns(&one, a4("10.0.2.2"), 4, "en1"));
	CHECK(!marker_owns(&one, a4("10.0.2.9"), 4, "en0"));
	memset(&none, 0, sizeof(none));
	CHECK(!marker_owns(&none, a4("10.0.2.2"), 4, "en0"));

	/* No marker: a route through an Ethernet interface is an earlier dhcpc's. */
	CHECK(marker_owns(NULL, a4("10.0.2.2"), 4, "en0"));
	CHECK(!marker_owns(NULL, a4("10.0.2.2"), 9, "utun0"));
	CHECK(!marker_owns(NULL, a4("0.0.0.0"), 4, "en0"));
	CHECK(!marker_owns(NULL, a4("10.0.2.2"), 0, "en0"));

	/* The marker of an earlier dhcpc 4 build, and lines that are not routes, are no marker. */
	CHECK(!marker_parse("en0 10.0.2.2\n", 13, &back));
	strcpy(text, "route en0 4 10.0.2.2 x\n");
	CHECK(!marker_parse(text, seal(text, sizeof(text)), &back));
	strcpy(text, "route en0 0 10.0.2.2\n");
	CHECK(!marker_parse(text, seal(text, sizeof(text)), &back));
	strcpy(text, "route en0 4 10.0.2\n");
	CHECK(!marker_parse(text, seal(text, sizeof(text)), &back));
	strcpy(text, "route  en0 4 10.0.2.2\n");
	CHECK(!marker_parse(text, seal(text, sizeof(text)), &back));
	strcpy(text, "route en0 4 10.0.2.2\n");
	CHECK(marker_parse(text, seal(text, sizeof(text)), &back) && back.n == 1);
}

static struct droute
route(const char *name, unsigned int ifindex, const char *router)
{
	struct droute r;

	memset(&r, 0, sizeof(r));
	strcpy(r.name, name);
	r.ifindex = ifindex;
	r.router = a4(router);
	return r;
}

static struct kroute
kernel(enum probe probe, const char *name, unsigned int ifindex, const char *router)
{
	struct kroute k;

	memset(&k, 0, sizeof(k));
	k.probe = probe;
	if (probe == PROBE_FOUND) {
		k.r = route(name, ifindex, router);
	}
	return k;
}

static void
test_elect_plan(void)
{
	struct droute en0 = route("en0", 4, "10.0.2.2"), en1 = route("en1", 5, "10.0.3.1");
	struct droute en1same = route("en1", 5, "10.0.2.2");
	struct marker was, full;
	struct kroute k;
	struct eplan p;

	/* The winner's route is there and listed alone: only resolv.conf. */
	memset(&was, 0, sizeof(was));
	marker_add(&was, &en0);
	k = kernel(PROBE_FOUND, "en0", 4, "10.0.2.2");
	elect_plan(&en0, false, false, &was, &k, &p);
	CHECK(p.resolv && !p.set && !p.settle && !p.clear && !p.remove && !p.none);

	/* There, but not listed, as after a soft reboot: listed now. */
	elect_plan(&en0, false, false, NULL, &k, &p);
	CHECK(p.resolv && !p.set && p.settle);

	/* dhcpc's route on en0, the winner en1: the old and the new listed before the change. */
	elect_plan(&en1, false, false, &was, &k, &p);
	CHECK(p.set && p.settle && p.intent.n == 2 && p.intent.r[0].ifindex == 4 && p.intent.r[1].ifindex == 5);

	/* Another's route: only the new one listed. No route: the same. */
	k = kernel(PROBE_FOUND, "utun0", 9, "10.8.0.1");
	elect_plan(&en0, false, false, &was, &k, &p);
	CHECK(p.set && p.intent.n == 1 && p.intent.r[0].ifindex == 4);
	k = kernel(PROBE_NONE, "", 0, "0.0.0.0");
	elect_plan(&en1, false, false, &was, &k, &p);
	CHECK(p.set && p.intent.n == 1 && p.intent.r[0].ifindex == 5);

	/* The route cannot be read: every listed route stays listed with the new one. */
	k = kernel(PROBE_FAILED, "", 0, "0.0.0.0");
	elect_plan(&en1, false, false, &was, &k, &p);
	CHECK(p.set && p.intent.n == 2 && p.intent.r[0].ifindex == 4);
	/* ... and without a marker, or with a full one, nothing changes. */
	elect_plan(&en1, false, false, NULL, &k, &p);
	CHECK(!p.set && !p.settle && p.resolv);
	memset(&full, 0, sizeof(full));
	for (unsigned int i = 0; i < MARKER_MAX; i++) {
		struct droute x = route("en2", 10 + i, "10.0.4.1");
		marker_add(&full, &x);
	}
	elect_plan(&en1, false, false, &full, &k, &p);
	CHECK(!p.set && !p.settle);

	/* Read again, a full marker is made the route there and the new one. */
	k = kernel(PROBE_FOUND, "en2", 12, "10.0.4.1");
	elect_plan(&en1, false, false, &full, &k, &p);
	CHECK(p.set && p.intent.n == 2 && p.intent.r[0].ifindex == 12 && p.intent.r[1].ifindex == 5);

	/* No winner, dhcpc's route: it goes, and resolv.conf is cleared. */
	k = kernel(PROBE_FOUND, "en0", 4, "10.0.2.2");
	elect_plan(NULL, false, false, &was, &k, &p);
	CHECK(p.clear && p.remove && !p.none && !p.resolv);

	/* The same router through another interface is not dhcpc's: it stays; the marker lists none. */
	memset(&was, 0, sizeof(was));
	marker_add(&was, &en1same);
	elect_plan(NULL, false, false, &was, &k, &p);
	CHECK(p.clear && !p.remove && p.none);

	/* No marker: a route through an Ethernet interface is an earlier dhcpc's. */
	elect_plan(NULL, false, false, NULL, &k, &p);
	CHECK(p.clear && p.remove);
	k = kernel(PROBE_FOUND, "utun0", 9, "10.8.0.1");
	elect_plan(NULL, false, false, NULL, &k, &p);
	CHECK(p.clear && !p.remove && p.none);

	/* The route cannot be read: the marker stays, to try again; resolv.conf is cleared. */
	k = kernel(PROBE_FAILED, "", 0, "0.0.0.0");
	elect_plan(NULL, false, false, &was, &k, &p);
	CHECK(p.clear && !p.remove && !p.none);

	/* No route, a marker listing none: nothing to write. */
	memset(&was, 0, sizeof(was));
	k = kernel(PROBE_NONE, "", 0, "0.0.0.0");
	elect_plan(NULL, false, false, &was, &k, &p);
	CHECK(p.clear && !p.remove && !p.none);

	/* An address found without a record is being asked for: nothing changes meanwhile. */
	k = kernel(PROBE_FOUND, "en0", 4, "10.0.2.2");
	elect_plan(NULL, true, false, NULL, &k, &p);
	CHECK(!p.clear && !p.remove && !p.none && !p.set && !p.resolv);
	elect_plan(&en1, true, false, NULL, &k, &p);
	CHECK(p.set && p.resolv);

	/*
	 * No marker, as after a soft reboot with two interfaces: en1's address has no record yet, as its
	 * worker has still to save it. No change meanwhile; with a marker, the rule is not needed.
	 */
	k = kernel(PROBE_FOUND, "en1", 5, "10.0.3.1");
	elect_plan(NULL, false, true, NULL, &k, &p);
	CHECK(!p.clear && !p.remove && !p.none);
	elect_plan(NULL, false, false, NULL, &k, &p);
	CHECK(p.clear && p.remove);
	memset(&was, 0, sizeof(was));
	marker_add(&was, &en1);
	elect_plan(NULL, false, true, &was, &k, &p);
	CHECK(p.clear && p.remove);
	elect_plan(&en0, false, true, NULL, &k, &p);
	CHECK(p.set && p.resolv);
}

static void
test_unrecorded_address(void)
{
	struct ifaddr4 set[3], covered[1];

	memset(set, 0, sizeof(set));
	strcpy(set[0].name, "lo0");
	set[0].addr = a4("127.0.0.1");
	strcpy(set[1].name, "utun0");
	set[1].addr = a4("10.8.0.2");
	strcpy(set[2].name, "en1");
	set[2].addr = a4("10.0.3.7");
	memset(covered, 0, sizeof(covered));
	strcpy(covered[0].name, "en1");
	covered[0].addr = a4("10.0.3.7");

	/* Only an Ethernet interface's address counts, and only when no current record has it. */
	CHECK(unrecorded_address(set, 3, NULL, 0));
	CHECK(!unrecorded_address(set, 3, covered, 1));
	CHECK(!unrecorded_address(set, 2, NULL, 0));
	strcpy(covered[0].name, "en0");
	CHECK(unrecorded_address(set, 3, covered, 1));
	strcpy(covered[0].name, "en1");
	covered[0].addr = a4("10.0.3.8");
	CHECK(unrecorded_address(set, 3, covered, 1));
}

static void
test_rt_addrs(void)
{
	uint8_t a[RT_ADDRS][16], msg[64];
	size_t n = 0;

	/* A scoped subnet route's RTM_GET reply: the destination, a link gateway of 20 bytes, and a mask trimmed to 7. */
	memset(msg, 0, sizeof(msg));
	msg[n] = 16;
	msg[n + 1] = 2;
	memcpy(msg + n + 4, "\x0a\x00\x02\x00", 4);
	n += 16;
	msg[n] = 20;
	msg[n + 1] = 18;
	msg[n + 2] = 4;
	n += 20;
	memcpy(msg + n, "\x07\xff\xff\xff\xff\xff\xff", 7);
	n += 8;
	rt_addrs(msg, n, 1 | 2 | 4, a);
	CHECK(a[0][0] == 16 && memcmp(a[0] + 4, "\x0a\x00\x02\x00", 4) == 0);
	CHECK(a[1][0] == 20 && a[1][1] == 18 && a[1][2] == 4);
	CHECK(a[2][0] == 7 && memcmp(a[2] + 4, "\xff\xff\xff\x00", 4) == 0);
	CHECK(a[3][0] == 0);

	/* The same with the mask's padding cut: the 7 bytes are read still. */
	rt_addrs(msg, n - 1, 1 | 2 | 4, a);
	CHECK(memcmp(a[2] + 4, "\xff\xff\xff\x00", 4) == 0);

	/* A default route's: destination, gateway, and a mask of length 0, which takes 4 bytes. */
	memset(msg, 0, sizeof(msg));
	msg[0] = 16;
	msg[1] = 2;
	msg[16] = 16;
	msg[17] = 2;
	memcpy(msg + 20, "\x0a\x00\x02\x02", 4);
	rt_addrs(msg, 36, 1 | 2 | 4 | 16, a);
	CHECK(memcmp(a[1] + 4, "\x0a\x00\x02\x02", 4) == 0 && a[2][0] == 0 && a[4][0] == 0);

	/* An address longer than what is left: only what is there. */
	memset(msg, 0, sizeof(msg));
	msg[0] = 16;
	msg[1] = 2;
	msg[4] = 10;
	msg[8] = 10;
	rt_addrs(msg, 6, 1, a);
	CHECK(a[0][0] == 16 && a[0][4] == 10 && a[0][8] == 0);
}

int
main(void)
{
	test_record();
	test_record_fields();
	test_current();
	test_takeover();
	test_set_as();
	test_removed();
	test_may_set();
	test_here();
	test_lease_pending();
	test_marker();
	test_elect_plan();
	test_unrecorded_address();
	test_rt_addrs();
	printf("test_state: %d failure(s)\n", failures);
	return failures;
}
