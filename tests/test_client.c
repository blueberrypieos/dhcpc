/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 The Blueberry Pie OS Authors
 *
 * usage: test_client
 *
 * Runs the client of client.c on the build machine, with a fake interface
 * and fake servers, and prints each failed check. The exit status is the
 * number of failures.
 */

#include <arpa/inet.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "client.h"

static int failures;

#define CHECK(cond) do { \
	if (!(cond)) { \
		printf("%s:%d: %s: failed: %s\n", __FILE__, __LINE__, __func__, #cond); \
		failures++; \
	} \
} while (0)

struct fake {
	bool link;
	int apply_fails;        /* this many applies fail */
	int ups, opens, closes, gones, applies, holds, drops;
	struct csend sent[1024], lastmsg;
	int nsent;
	bool applied_old, gone_had;
	struct lease old, applied, held, dropped, gone_lease;
	enum lstatus hold_status;
	uint32_t xid;
	char log[8192];
};

static struct fake f;
static struct client c;
static const uint8_t mac1[6] = { 2, 0, 0, 0, 0, 1 };
static const uint8_t mac2[6] = { 2, 0, 0, 0, 0, 2 };

static void f_up(void *ctx) { (void)ctx; f.ups++; }
static bool f_link(void *ctx) { (void)ctx; return f.link; }
static void f_open(void *ctx) { (void)ctx; f.opens++; }
static void f_close(void *ctx) { (void)ctx; f.closes++; }
static uint32_t f_xid(void *ctx) { (void)ctx; return ++f.xid; }

static void
f_send(void *ctx, const struct csend *m)
{
	(void)ctx;
	if (f.nsent < 1024) {
		f.sent[f.nsent] = *m;
	}
	f.lastmsg = *m;
	f.nsent++;
}

static bool
f_apply(void *ctx, const struct lease *old, const struct lease *l)
{
	(void)ctx;
	f.applies++;
	f.applied_old = old != NULL;
	if (old != NULL) {
		f.old = *old;
	}
	f.applied = *l;
	if (f.apply_fails > 0) {
		f.apply_fails--;
		return false;
	}
	return true;
}

static void
f_hold(void *ctx, const struct lease *l, enum lstatus s)
{
	(void)ctx;
	f.holds++;
	f.held = *l;
	f.hold_status = s;
}

static void f_drop(void *ctx, const struct lease *l) { (void)ctx; f.drops++; f.dropped = *l; }

static void
f_gone(void *ctx, const struct lease *l)
{
	(void)ctx;
	f.gones++;
	f.gone_had = l != NULL;
	if (l != NULL) {
		f.gone_lease = *l;
	}
}

static void
f_log(void *ctx, const char *fmt, ...)
{
	va_list ap;
	size_t len = strlen(f.log);

	(void)ctx;
	va_start(ap, fmt);
	vsnprintf(f.log + len, sizeof(f.log) - len, fmt, ap);
	va_end(ap);
	len = strlen(f.log);
	if (len + 1 < sizeof(f.log)) {
		f.log[len] = '\n';
		f.log[len + 1] = '\0';
	}
}

static const struct cops ops = {
	f_up, f_link, f_open, f_close, f_send, f_apply, f_hold, f_drop, f_gone, f_log, f_xid,
};

static struct in_addr
a4(const char *s)
{
	struct in_addr a;

	inet_aton(s, &a);
	return a;
}

static bool
same(struct in_addr x, const char *s)
{
	return x.s_addr == a4(s).s_addr;
}

static const struct csend *
last(void)
{
	return f.nsent > 0 ? &f.lastmsg : NULL;
}

static struct lease
reply(int type, const char *addr, const char *server, uint32_t secs)
{
	struct lease l;

	memset(&l, 0, sizeof(l));
	l.type = type;
	l.addr = a4(addr);
	l.server = a4(server);
	l.router = a4("10.0.0.1");
	l.mask = a4("255.255.255.0");
	l.lease = secs;
	return l;
}

/* Run the client's timers up to and including time t. */
static int64_t
run_to(int64_t now, int64_t t)
{
	for (int i = 0; i < 100000; i++) {
		int64_t n = client_next(&c);
		if (n > t) {
			break;
		}
		now = n > now ? n : now;
		client_timer(&c, now);
	}
	return t > now ? t : now;
}

static void
fresh(bool link)
{
	memset(&f, 0, sizeof(f));
	f.link = link;
	client_init(&c, &ops, NULL);
}

/* A lease of 10.0.0.5 from 10.0.0.1, 3600 s, bound at time 0. */
static void
bound(void)
{
	struct lease r;

	fresh(true);
	client_attach(&c, mac1, 0);
	r = reply(DHCPOFFER, "10.0.0.5", "10.0.0.1", 3600);
	client_reply(&c, &r, c.gen, 0);
	r.type = DHCPACK;
	client_reply(&c, &r, c.gen, 0);
}

static void
test_first_lease(void)
{
	struct lease r;

	fresh(true);
	client_attach(&c, mac1, 1000);
	CHECK(f.ups == 1 && f.opens == 1);
	CHECK(c.state == C_INIT && f.nsent == 1 && last()->type == DHCPDISCOVER);
	CHECK(last()->reqip.s_addr == 0 && last()->ciaddr.s_addr == 0 && last()->server.s_addr == 0);
	r = reply(DHCPOFFER, "10.0.0.5", "10.0.0.1", 3600);
	r.t1 = 1000;
	r.t2 = 2000;
	client_reply(&c, &r, c.gen, 1500);
	CHECK(c.state == C_REQUESTING && f.nsent == 2 && last()->type == DHCPREQUEST);
	CHECK(same(last()->reqip, "10.0.0.5") && same(last()->server, "10.0.0.1"));
	CHECK(last()->ciaddr.s_addr == 0 && last()->xid == f.sent[0].xid);
	r.type = DHCPACK;
	client_reply(&c, &r, c.gen, 1600);
	CHECK(c.state == C_BOUND && f.applies == 1 && !f.applied_old);
	CHECK(same(f.applied.addr, "10.0.0.5") && f.applied.sent == 1500);
	CHECK(c.status == L_CONFIRMED && c.addr_on && c.have);
	CHECK(client_next(&c) == 1500 + 1000 * 1000);
}

static void
test_link_wait(void)
{
	fresh(false);
	client_attach(&c, mac1, 0);
	CHECK(c.state == C_WAITLINK && f.nsent == 0 && f.ups == 1 && f.opens == 1);
	client_link(&c, true, 3000);
	CHECK(c.state == C_INIT && f.nsent == 1 && last()->type == DHCPDISCOVER);

	fresh(false);
	client_attach(&c, mac1, 0);
	run_to(0, 9999);
	CHECK(f.nsent == 0);
	run_to(9999, 10000);
	CHECK(c.state == C_INIT && f.nsent == 1);
}

static void
test_discover_backoff(void)
{
	fresh(true);
	client_attach(&c, mac1, 0);
	run_to(0, 100000);
	/* Sent at 0, 2, 6, 14, 30, 46, 62, 78, 94 s. */
	CHECK(f.nsent == 9);
	CHECK(c.state == C_INIT && last()->type == DHCPDISCOVER);
	CHECK(f.sent[0].xid != f.sent[1].xid);
	CHECK(f.sent[3].secs == 14);

	/* An OFFER 1.2 s after that DISCOVER: the REQUEST has the DISCOVER's secs, as RFC 2131 section 3.1 says. */
	struct lease r = reply(DHCPOFFER, "10.0.0.5", "10.0.0.1", 3600);
	fresh(true);
	client_attach(&c, mac1, 0);
	run_to(0, 14000);
	CHECK(last()->type == DHCPDISCOVER && last()->secs == 14);
	r.type = DHCPOFFER;
	client_reply(&c, &r, c.gen, 15200);
	CHECK(c.state == C_REQUESTING && last()->type == DHCPREQUEST && last()->secs == 14);
}

static void
test_gone_during_exchange(void)
{
	fresh(true);
	client_attach(&c, mac1, 0);
	CHECK(f.nsent == 1);
	client_detach(&c, 500);
	CHECK(c.state == C_GONE && f.closes == 1 && f.gones == 1 && !f.gone_had);
	run_to(500, 600000);
	CHECK(f.nsent == 1 && f.drops == 0);
	client_detach(&c, 600001);
	CHECK(f.closes == 1 && f.gones == 1);
}

static void
test_gone_while_leased(void)
{
	bound();
	client_detach(&c, 10000);
	CHECK(c.state == C_GONE && f.closes == 1 && f.gones == 1);
	CHECK(c.have && !c.addr_on && f.gone_had && same(f.gone_lease.addr, "10.0.0.5"));
	CHECK(f.drops == 0);
	run_to(10000, 1000000);
	CHECK(f.nsent == 2);
	CHECK(client_next(&c) == 3600 * 1000);
}

static void
test_back_same_mac(void)
{
	struct lease r;

	/* An ACK. */
	bound();
	client_detach(&c, 10000);
	client_attach(&c, mac1, 20000);
	CHECK(f.ups == 2 && f.opens == 2);
	CHECK(c.state == C_REBOOTING && last()->type == DHCPREQUEST);
	CHECK(same(last()->reqip, "10.0.0.5") && last()->ciaddr.s_addr == 0 &&
	    last()->server.s_addr == 0);
	CHECK(strstr(f.log, "gone\nasking for 10.0.0.5 again\n") != NULL);
	r = reply(DHCPACK, "10.0.0.5", "10.0.0.1", 3600);
	client_reply(&c, &r, c.gen, 20100);
	CHECK(c.state == C_BOUND && f.applies == 2 && !f.applied_old && c.status == L_CONFIRMED);
	CHECK(f.applied.sent == 20000);

	/* A NAK: no address to remove, and a new lease without a hint. */
	bound();
	client_detach(&c, 10000);
	client_attach(&c, mac1, 20000);
	r = reply(DHCPNAK, "0.0.0.0", "10.0.0.1", 0);
	client_reply(&c, &r, c.gen, 20100);
	CHECK(f.drops == 0 && !c.have);
	CHECK(c.state == C_INIT && last()->type == DHCPDISCOVER && last()->reqip.s_addr == 0);

	/* Silence: a new lease, with the old address as a hint, and nothing added. */
	bound();
	client_detach(&c, 10000);
	client_attach(&c, mac1, 20000);
	int before = f.nsent;
	run_to(20000, 33999);
	CHECK(f.nsent == before + 2 && c.state == C_REBOOTING);
	CHECK(f.sent[before].type == DHCPREQUEST && f.sent[before + 1].type == DHCPREQUEST);
	run_to(33999, 34000);
	CHECK(c.state == C_INIT && last()->type == DHCPDISCOVER && same(last()->reqip, "10.0.0.5"));
	CHECK(f.holds == 0 && f.applies == 1 && f.drops == 0 && !c.have && !c.addr_on);
}

static void
test_back_other_mac(void)
{
	bound();
	client_detach(&c, 10000);
	client_attach(&c, mac2, 20000);
	CHECK(!c.have && c.state == C_INIT && last()->type == DHCPDISCOVER);
	CHECK(last()->reqip.s_addr == 0);
	CHECK(memcmp(c.mac, mac2, 6) == 0);
}

static void
test_link_bounce(void)
{
	struct lease r;

	/* An ACK keeps the address. */
	bound();
	client_link(&c, false, 10000);
	CHECK(f.nsent == 2 && c.state == C_BOUND && c.addr_on);
	client_link(&c, true, 20000);
	CHECK(c.state == C_REBOOTING && last()->type == DHCPREQUEST && same(last()->reqip, "10.0.0.5"));
	CHECK(last()->ciaddr.s_addr == 0);
	r = reply(DHCPACK, "10.0.0.5", "10.0.0.1", 3600);
	client_reply(&c, &r, c.gen, 20100);
	CHECK(c.state == C_BOUND && f.applies == 2 && f.applied_old && same(f.old.addr, "10.0.0.5"));
	CHECK(f.drops == 0 && c.status == L_CONFIRMED);

	/* A NAK removes the address at once. */
	bound();
	client_link(&c, false, 10000);
	client_link(&c, true, 20000);
	r = reply(DHCPNAK, "0.0.0.0", "10.0.9.1", 0);
	client_reply(&c, &r, c.gen, 20100);
	CHECK(f.drops == 1 && same(f.dropped.addr, "10.0.0.5") && !c.addr_on && !c.have);
	CHECK(c.state == C_INIT && last()->type == DHCPDISCOVER && last()->reqip.s_addr == 0);

	/* Silence: the address stays, unconfirmed, until a new lease binds. */
	bound();
	client_link(&c, false, 10000);
	client_link(&c, true, 20000);
	run_to(20000, 34000);
	CHECK(f.holds == 2 && same(f.held.addr, "10.0.0.5") && f.drops == 0);
	CHECK(c.state == C_INIT && c.addr_on && c.have && c.status == L_HELD && f.hold_status == L_HELD);
	CHECK(last()->type == DHCPDISCOVER && same(last()->reqip, "10.0.0.5"));
	r = reply(DHCPOFFER, "10.0.9.7", "10.0.9.1", 600);
	client_reply(&c, &r, c.gen, 35000);
	r.type = DHCPACK;
	client_reply(&c, &r, c.gen, 35100);
	CHECK(c.state == C_BOUND && f.applied_old && same(f.old.addr, "10.0.0.5"));
	CHECK(same(f.applied.addr, "10.0.9.7") && c.status == L_CONFIRMED && f.drops == 0);

	/* Silence, then no lease before the old one ends: then it goes. */
	bound();
	client_link(&c, false, 10000);
	client_link(&c, true, 20000);
	run_to(20000, 3599999);
	CHECK(f.holds == 2 && f.drops == 0 && c.addr_on);
	run_to(3599999, 3600000);
	CHECK(f.drops == 1 && !c.addr_on && !c.have && c.state == C_INIT);

	/* A held lease is asked for again when the link comes back once more. */
	bound();
	client_link(&c, false, 10000);
	client_link(&c, true, 20000);
	run_to(20000, 34000);
	client_link(&c, false, 40000);
	client_link(&c, true, 50000);
	CHECK(c.state == C_REBOOTING && same(last()->reqip, "10.0.0.5"));
	r = reply(DHCPACK, "10.0.0.5", "10.0.0.1", 3600);
	client_reply(&c, &r, c.gen, 50100);
	CHECK(c.state == C_BOUND && c.status == L_CONFIRMED && f.applied_old);
}

static void
test_ends_while_gone(void)
{
	bound();
	client_detach(&c, 10000);
	run_to(10000, 3600000);
	CHECK(!c.have && f.drops == 0);
	CHECK(strstr(f.log, "lease of 10.0.0.5 ended") != NULL);
	client_attach(&c, mac1, 4000000);
	CHECK(c.state == C_INIT && last()->type == DHCPDISCOVER && same(last()->reqip, "10.0.0.5"));
}

static void
test_lost_events(void)
{
	/* The interface came again without a departure seen: treated as one. */
	bound();
	client_attach(&c, mac1, 10000);
	CHECK(f.closes == 1 && f.gones == 1 && f.opens == 2 && f.ups == 2);
	CHECK(c.state == C_REBOOTING && same(last()->reqip, "10.0.0.5"));

	/* A link-on without a link-off: asked for again. */
	bound();
	client_link(&c, true, 10000);
	CHECK(c.state == C_REBOOTING);

	/* Link events while gone do nothing. */
	bound();
	client_detach(&c, 10000);
	int n = f.nsent;
	client_link(&c, true, 11000);
	client_link(&c, false, 12000);
	CHECK(c.state == C_GONE && f.nsent == n);
}

static void
test_renew(void)
{
	struct lease r;

	/* T1 1800 s, T2 3150 s. Renewing: bursts of 3 a minute apart; others' refusals ignored. */
	bound();
	run_to(0, 1800000);
	CHECK(c.state == C_RENEWING && last()->type == DHCPREQUEST && same(last()->ciaddr, "10.0.0.5"));
	CHECK(last()->reqip.s_addr == 0 && last()->server.s_addr == 0);
	int n = f.nsent;
	run_to(1800000, 1814000);
	CHECK(f.nsent == n + 2);
	run_to(1814000, 1873999);
	CHECK(f.nsent == n + 2);
	run_to(1873999, 1874000);
	CHECK(f.nsent == n + 3);
	r = reply(DHCPNAK, "0.0.0.0", "10.0.9.1", 0);
	client_reply(&c, &r, c.gen, 1874100);
	CHECK(c.state == C_RENEWING && c.addr_on);
	r = reply(DHCPACK, "10.0.0.5", "10.0.0.1", 3600);
	client_reply(&c, &r, c.gen, 1874200);
	CHECK(c.state == C_BOUND && f.applies == 2 && f.applied_old && f.applied.sent == 1874000);

	/* After T2 any server's refusal ends the lease. */
	bound();
	run_to(0, 3150000);
	CHECK(c.state == C_REBINDING);
	r = reply(DHCPNAK, "0.0.0.0", "10.0.9.1", 0);
	client_reply(&c, &r, c.gen, 3150100);
	CHECK(f.drops == 1 && c.state == C_INIT && last()->type == DHCPDISCOVER);

	/* Before T2 the lease's server ends it. */
	bound();
	run_to(0, 1800000);
	r = reply(DHCPNAK, "0.0.0.0", "10.0.0.1", 0);
	client_reply(&c, &r, c.gen, 1800100);
	CHECK(f.drops == 1 && !c.have && c.state == C_INIT);

	/* No answer at all: the lease ends on time. */
	bound();
	run_to(0, 3599999);
	CHECK(c.addr_on && f.drops == 0);
	run_to(3599999, 3600000);
	CHECK(f.drops == 1 && c.state == C_INIT && last()->type == DHCPDISCOVER);
	CHECK(same(last()->reqip, "10.0.0.5"));
}

static void
test_refusals(void)
{
	struct lease r;

	fresh(true);
	client_attach(&c, mac1, 0);
	r = reply(DHCPOFFER, "10.0.0.5", "10.0.0.1", 3600);
	client_reply(&c, &r, c.gen, 100);
	r = reply(DHCPNAK, "0.0.0.0", "10.0.9.1", 0);
	client_reply(&c, &r, c.gen, 200);
	CHECK(c.state == C_REQUESTING);
	r = reply(DHCPNAK, "0.0.0.0", "10.0.0.1", 0);
	client_reply(&c, &r, c.gen, 300);
	CHECK(c.state == C_INIT && f.nsent == 3 && last()->type == DHCPDISCOVER);
	r = reply(DHCPOFFER, "10.0.0.5", "10.0.0.1", 3600);
	client_reply(&c, &r, c.gen, 400);
	r = reply(DHCPNAK, "0.0.0.0", "10.0.0.1", 0);
	client_reply(&c, &r, c.gen, 500);
	CHECK(c.state == C_INIT && f.nsent == 4);
	run_to(500, 30499);
	CHECK(f.nsent == 4);
	run_to(30499, 30500);
	CHECK(f.nsent == 5 && last()->type == DHCPDISCOVER);
}

static void
test_requesting_timeout(void)
{
	struct lease r;

	fresh(true);
	client_attach(&c, mac1, 0);
	run_to(0, 2000);
	r = reply(DHCPOFFER, "10.0.0.5", "10.0.0.1", 3600);
	client_reply(&c, &r, c.gen, 2500);
	CHECK(c.state == C_REQUESTING);
	run_to(2500, 6499);
	CHECK(c.state == C_REQUESTING);
	run_to(6499, 6500);
	CHECK(c.state == C_INIT && last()->type == DHCPDISCOVER);
}

static void
test_elect(void)
{
	struct candidate a[] = {
		{ 1, true, true, true }, { 0, true, false, true }, { 2, true, true, true },
	};
	CHECK(elect_choose(a, 3) == 0);
	struct candidate b[] = {
		{ 0, true, true, false }, { 1, true, true, true },
	};
	CHECK(elect_choose(b, 2) == 1);
	struct candidate d[] = {
		{ 1, true, true, false }, { 0, true, true, false }, { 2, false, true, true },
	};
	CHECK(elect_choose(d, 3) == 1);
	struct candidate e[] = {
		{ 0, false, true, true }, { 1, true, false, true },
	};
	CHECK(elect_choose(e, 2) == -1);
	CHECK(elect_choose(NULL, 0) == -1);
}

static void
test_lease_times(void)
{
	struct lease l;

	memset(&l, 0, sizeof(l));
	l.sent = 1000;
	l.lease = 100;
	CHECK(lease_renew(&l) == 51000 && lease_rebind(&l) == 88000 && lease_end(&l) == 101000);
	l.t1 = 100;
	l.t2 = 20;
	CHECK(lease_renew(&l) == 51000 && lease_rebind(&l) == 88000);
	l.t1 = 30;
	l.t2 = 60;
	CHECK(lease_renew(&l) == 31000 && lease_rebind(&l) == 61000);
}

static void
test_nak_requesting_held(void)
{
	struct lease r;

	/* Held after silence, then the new offer's server refuses: the held address goes too. */
	bound();
	client_link(&c, false, 10000);
	client_link(&c, true, 20000);
	run_to(20000, 34000);
	CHECK(f.holds == 2 && f.hold_status == L_HELD && c.addr_on);
	r = reply(DHCPOFFER, "10.0.9.7", "10.0.9.1", 600);
	client_reply(&c, &r, c.gen, 35000);
	CHECK(c.state == C_REQUESTING);
	r = reply(DHCPNAK, "0.0.0.0", "10.0.9.1", 0);
	client_reply(&c, &r, c.gen, 35100);
	CHECK(f.drops == 1 && same(f.dropped.addr, "10.0.0.5") && !c.addr_on && !c.have);
	CHECK(c.state == C_INIT && last()->type == DHCPDISCOVER && last()->reqip.s_addr == 0);
}

static void
test_link_on_after_end(void)
{
	/* The link comes back after the lease's end, before any timer ran: the address goes. */
	bound();
	client_link(&c, false, 10000);
	client_link(&c, true, 3600000);
	CHECK(f.drops == 1 && same(f.dropped.addr, "10.0.0.5") && !c.addr_on && !c.have);
	CHECK(c.state == C_INIT && last()->type == DHCPDISCOVER && same(last()->reqip, "10.0.0.5"));

	bound();
	client_link(&c, false, 10000);
	client_link(&c, true, 7200000);
	CHECK(f.drops == 1 && c.state == C_INIT);
}

static void
test_stale_reply(void)
{
	struct lease r;

	/* A reply read from the BPF of an earlier arrival is not used. */
	bound();
	uint32_t old = c.gen;
	client_detach(&c, 10000);
	client_attach(&c, mac1, 20000);
	CHECK(c.gen == old + 1 && c.state == C_REBOOTING);
	r = reply(DHCPACK, "10.0.0.5", "10.0.0.1", 3600);
	client_reply(&c, &r, old, 20100);
	CHECK(c.state == C_REBOOTING && f.applies == 1);
	client_reply(&c, &r, c.gen, 20200);
	CHECK(c.state == C_BOUND && f.applies == 2);
}

static void
test_renew_unicast(void)
{
	struct lease l = reply(DHCPACK, "10.0.0.5", "0.0.0.0", 3600);

	/* Renewing: unicast to the lease's server, from the address, without options 50 and 54. */
	bound();
	run_to(0, 1800000);
	CHECK(c.state == C_RENEWING && last()->unicast && same(last()->dst, "10.0.0.1"));
	CHECK(same(last()->ciaddr, "10.0.0.5") && last()->reqip.s_addr == 0 && last()->server.s_addr == 0);
	run_to(1800000, 3150000);
	CHECK(c.state == C_REBINDING && !last()->unicast && same(last()->ciaddr, "10.0.0.5"));

	/* INIT-REBOOT broadcasts. */
	bound();
	client_link(&c, true, 10000);
	CHECK(c.state == C_REBOOTING && !last()->unicast);

	/* A lease without a server identifier is renewed by broadcast. */
	l.sent = 0;
	fresh(true);
	client_adopt(&c, &l, mac1, L_CONFIRMED, 2000000);
	CHECK(c.state == C_RENEWING && !last()->unicast);
}

static void
test_adopt(void)
{
	struct lease l = reply(DHCPACK, "10.0.0.5", "10.0.0.1", 3600);

	/* Before T1: bound, nothing sent, renewing at T1. */
	l.sent = 1000;
	fresh(true);
	client_adopt(&c, &l, mac1, L_CONFIRMED, 600000);
	CHECK(c.state == C_BOUND && c.addr_on && c.have && c.status == L_CONFIRMED && c.bound_once);
	CHECK(f.nsent == 0 && f.opens == 1 && f.drops == 0 && f.applies == 0);
	CHECK(client_next(&c) == 1000 + 1800000);
	run_to(600000, 1801000);
	CHECK(c.state == C_RENEWING && f.nsent == 1);

	/* Between T1 and T2: renewing at once. */
	fresh(true);
	client_adopt(&c, &l, mac1, L_CONFIRMED, 2000000);
	CHECK(c.state == C_RENEWING && f.nsent == 1 && same(last()->ciaddr, "10.0.0.5"));

	/* Held: asking for a new lease, the address kept. */
	fresh(true);
	client_adopt(&c, &l, mac1, L_HELD, 600000);
	CHECK(c.state == C_INIT && c.addr_on && c.status == L_HELD && f.drops == 0 && !c.bound_once);
	CHECK(last()->type == DHCPDISCOVER && same(last()->reqip, "10.0.0.5"));
	run_to(600000, 3601000);
	CHECK(f.drops == 1 && !c.addr_on);

	/* Ended: the address goes. */
	fresh(true);
	client_adopt(&c, &l, mac1, L_CONFIRMED, 3601000);
	CHECK(f.drops == 1 && !c.addr_on && c.state == C_INIT);
}

static void
test_link_status(void)
{
	struct lease r, l = reply(DHCPACK, "10.0.0.5", "10.0.0.1", 3600);

	/* Link down: the lease is recorded as being checked. Link up: INIT-REBOOT. */
	bound();
	client_link(&c, false, 10000);
	CHECK(c.state == C_BOUND && f.holds == 1 && f.hold_status == L_CHECKING && c.status == L_CHECKING);
	client_link(&c, true, 20000);
	CHECK(c.state == C_REBOOTING && f.holds == 1);
	r = reply(DHCPACK, "10.0.0.5", "10.0.0.1", 3600);
	client_reply(&c, &r, c.gen, 20100);
	CHECK(c.state == C_BOUND && c.status == L_CONFIRMED && f.applies == 2);

	/* A link-on without a link-off: recorded as being checked from the first REQUEST. */
	bound();
	client_link(&c, true, 10000);
	CHECK(c.state == C_REBOOTING && f.holds == 1 && f.hold_status == L_CHECKING);

	/* Taken over while being checked: INIT-REBOOT again, the address and the lease's end kept. */
	l.sent = 1000;
	fresh(true);
	client_adopt(&c, &l, mac1, L_CHECKING, 20000);
	CHECK(c.state == C_REBOOTING && c.addr_on && f.nsent == 1 && last()->type == DHCPREQUEST);
	CHECK(same(last()->reqip, "10.0.0.5") && last()->ciaddr.s_addr == 0 && last()->server.s_addr == 0);
	CHECK(f.holds == 0 && f.applies == 0 && !c.bound_once && client_next(&c) == 22000);
	run_to(20000, 34000);
	CHECK(c.state == C_INIT && c.addr_on && f.holds == 1 && f.hold_status == L_HELD && f.drops == 0);
	run_to(34000, 3601000);
	CHECK(f.drops == 1 && !c.addr_on);

	/* Taken over as confirmed while the link is down: checked when the link comes. */
	fresh(false);
	client_adopt(&c, &l, mac1, L_CONFIRMED, 20000);
	CHECK(c.state == C_WAITLINK && f.nsent == 0 && f.holds == 1 && f.hold_status == L_CHECKING);
	CHECK(!c.bound_once && c.addr_on);
	f.link = true;
	client_link(&c, true, 21000);
	CHECK(c.state == C_REBOOTING && last()->type == DHCPREQUEST && same(last()->reqip, "10.0.0.5"));
}

static void
test_unrecorded(void)
{
	struct lease r, p;

	/* An address set without a record: INIT-REBOOT for it, kept for as long as that asks. */
	memset(&p, 0, sizeof(p));
	p.addr = a4("10.0.0.5");
	p.mask = a4("255.255.255.0");
	p.lease = REBOOT_WAIT_S;
	p.sent = 5000;
	fresh(true);
	client_adopt(&c, &p, mac1, L_CHECKING, 5000);
	CHECK(c.state == C_REBOOTING && c.addr_on && same(last()->reqip, "10.0.0.5"));
	run_to(5000, 18999);
	CHECK(c.addr_on && f.drops == 0 && f.nsent == 3);
	run_to(18999, 19000);
	CHECK(f.drops == 1 && same(f.dropped.addr, "10.0.0.5") && !c.addr_on && !c.have);
	CHECK(c.state == C_INIT && last()->type == DHCPDISCOVER && same(last()->reqip, "10.0.0.5"));

	/* A server confirms it: the lease binds over it. */
	fresh(true);
	client_adopt(&c, &p, mac1, L_CHECKING, 5000);
	r = reply(DHCPACK, "10.0.0.5", "10.0.0.1", 3600);
	client_reply(&c, &r, c.gen, 5100);
	CHECK(c.state == C_BOUND && c.status == L_CONFIRMED && f.applied_old && same(f.old.addr, "10.0.0.5"));
	CHECK(f.drops == 0 && c.bound_once && client_next(&c) == 5000 + 1800000);

	/* A server refuses it: it goes at once. */
	fresh(true);
	client_adopt(&c, &p, mac1, L_CHECKING, 5000);
	r = reply(DHCPNAK, "0.0.0.0", "10.0.0.1", 0);
	client_reply(&c, &r, c.gen, 5100);
	CHECK(f.drops == 1 && !c.addr_on && c.state == C_INIT && last()->reqip.s_addr == 0);
}

static void
test_remember(void)
{
	struct lease l = reply(DHCPACK, "10.0.0.5", "10.0.0.1", 3600);

	/* An earlier dhcpc's lease whose address went: INIT-REBOOT at the arrival. */
	l.sent = 1000;
	fresh(true);
	client_remember(&c, &l, mac1);
	client_attach(&c, mac1, 5000);
	CHECK(c.state == C_REBOOTING && same(last()->reqip, "10.0.0.5") && f.drops == 0);

	/* Another adapter: a new lease. */
	fresh(true);
	client_remember(&c, &l, mac1);
	client_attach(&c, mac2, 5000);
	CHECK(c.state == C_INIT && last()->reqip.s_addr == 0);
}

static void
test_resolv(void)
{
	char text[256];
	struct lease l = reply(DHCPACK, "10.0.0.5", "10.0.0.1", 3600);

	CHECK(resolv_text(text, sizeof(text), "en0", &l) == strlen("# written by dhcpc for en0\n") &&
	    strcmp(text, "# written by dhcpc for en0\n") == 0);
	l.ndns = 2;
	l.dns[0] = a4("10.0.0.2");
	l.dns[1] = a4("10.0.0.3");
	strcpy(l.domain, "home");
	resolv_text(text, sizeof(text), "en1", &l);
	CHECK(strcmp(text, "# written by dhcpc for en1\nsearch home\nnameserver 10.0.0.2\nnameserver 10.0.0.3\n") == 0);
	resolv_text(text, sizeof(text), NULL, NULL);
	CHECK(strcmp(text, "# written by dhcpc\n") == 0);
	CHECK(resolv_text(text, 10, "en1", &l) >= 10);
}

static void
test_apply_fails(void)
{
	struct lease r;

	/* A first lease whose address cannot be set: not bound, asked for again with INIT-REBOOT in 5 s. */
	fresh(true);
	client_attach(&c, mac1, 0);
	r = reply(DHCPOFFER, "10.0.0.5", "10.0.0.1", 3600);
	client_reply(&c, &r, c.gen, 100);
	f.apply_fails = 1;
	r.type = DHCPACK;
	client_reply(&c, &r, c.gen, 200);
	CHECK(f.applies == 1 && !c.bound_once && !c.addr_on && c.have && c.state == C_REBOOTING);
	CHECK(client_next(&c) == 5200 && f.nsent == 2);
	run_to(200, 5199);
	CHECK(f.nsent == 2);
	run_to(5199, 5200);
	CHECK(f.nsent == 3 && last()->type == DHCPREQUEST && same(last()->reqip, "10.0.0.5") &&
	    last()->ciaddr.s_addr == 0);
	client_reply(&c, &r, c.gen, 5300);
	CHECK(c.state == C_BOUND && c.bound_once && c.addr_on && c.status == L_CONFIRMED && f.applies == 2);
	CHECK(f.applied.sent == 5200 && client_next(&c) == 5200 + 1800000);

	/* A renewal whose apply fails: the address and the lease's times stay, and renewing goes on. */
	bound();
	run_to(0, 1800000);
	CHECK(c.state == C_RENEWING);
	f.apply_fails = 1;
	r = reply(DHCPACK, "10.0.0.5", "10.0.0.1", 3600);
	client_reply(&c, &r, c.gen, 1800100);
	CHECK(c.state == C_RENEWING && c.addr_on && c.cur.sent == 0 && f.drops == 0 && client_next(&c) == 1805100);
	run_to(1800100, 1805100);
	CHECK(c.state == C_RENEWING && last()->unicast);
	client_reply(&c, &r, c.gen, 1805200);
	CHECK(c.state == C_BOUND && c.cur.sent == 1805100);

	/* A new address that cannot be set after a refusal of the old: the old one went with the refusal. */
	bound();
	client_link(&c, false, 10000);
	client_link(&c, true, 20000);
	run_to(20000, 34000);
	r = reply(DHCPOFFER, "10.0.9.7", "10.0.9.1", 600);
	client_reply(&c, &r, c.gen, 35000);
	f.apply_fails = 1;
	r.type = DHCPACK;
	client_reply(&c, &r, c.gen, 35100);
	CHECK(f.applied_old && same(f.old.addr, "10.0.0.5") && !c.addr_on && same(c.cur.addr, "10.0.9.7"));
	CHECK(c.state == C_REBOOTING && client_next(&c) == 35100 + 5000 && f.drops == 0);
}

static void
test_apply_fails_t2(void)
{
	struct lease r;

	/* An 8 s lease, T1 4 s, T2 7 s: a renewal that cannot be applied still rebinds at T2, before the end. */
	fresh(true);
	client_attach(&c, mac1, 0);
	r = reply(DHCPOFFER, "10.0.0.5", "10.0.0.1", 8);
	client_reply(&c, &r, c.gen, 0);
	r.type = DHCPACK;
	client_reply(&c, &r, c.gen, 0);
	run_to(0, 4000);
	CHECK(c.state == C_RENEWING && last()->unicast);
	f.apply_fails = 1;
	client_reply(&c, &r, c.gen, 4100);
	CHECK(c.state == C_RENEWING && c.addr_on && client_next(&c) == 7000);
	run_to(4100, 7000);
	CHECK(c.state == C_REBINDING && !last()->unicast && same(last()->ciaddr, "10.0.0.5") && f.drops == 0);
	client_reply(&c, &r, c.gen, 7100);
	CHECK(c.state == C_BOUND && c.cur.sent == 7000 && f.drops == 0);
}

static void
test_found(void)
{
	struct lease p;

	/* Found without a record: it stays found while it is asked for, through a link change too. */
	memset(&p, 0, sizeof(p));
	p.addr = a4("10.0.0.5");
	p.mask = a4("255.255.255.0");
	p.lease = REBOOT_WAIT_S;
	p.sent = 5000;
	fresh(true);
	client_adopt(&c, &p, mac1, L_FOUND, 8000);
	CHECK(c.state == C_REBOOTING && c.status == L_FOUND && f.holds == 0 && same(last()->reqip, "10.0.0.5"));
	client_link(&c, false, 9000);
	client_link(&c, true, 10000);
	CHECK(c.status == L_FOUND && f.holds == 0 && c.state == C_REBOOTING);
	run_to(10000, 18999);
	CHECK(c.addr_on && f.drops == 0);
	run_to(18999, 19000);
	CHECK(f.drops == 1 && !c.addr_on);

	/* Found, with the link down: it waits for the link, still found. */
	fresh(false);
	client_adopt(&c, &p, mac1, L_FOUND, 6000);
	CHECK(c.state == C_WAITLINK && c.status == L_FOUND && f.holds == 0 && f.nsent == 0);
}

static void
test_domain(void)
{
	CHECK(domain_ok("home.example", 12) && domain_ok("a-b_c.d", 7));
	CHECK(!domain_ok("", 0) && !domain_ok("a b", 3) && !domain_ok("a\nb", 3) && !domain_ok("a;b", 3));
	char longname[300];
	memset(longname, 'a', sizeof(longname));
	CHECK(domain_ok(longname, 255) && !domain_ok(longname, 256));
}

int
main(void)
{
	test_first_lease();
	test_link_wait();
	test_discover_backoff();
	test_gone_during_exchange();
	test_gone_while_leased();
	test_back_same_mac();
	test_back_other_mac();
	test_link_bounce();
	test_ends_while_gone();
	test_lost_events();
	test_renew();
	test_refusals();
	test_requesting_timeout();
	test_elect();
	test_lease_times();
	test_nak_requesting_held();
	test_link_on_after_end();
	test_stale_reply();
	test_renew_unicast();
	test_adopt();
	test_remember();
	test_resolv();
	test_link_status();
	test_unrecorded();
	test_apply_fails();
	test_apply_fails_t2();
	test_found();
	test_domain();
	printf("test_client: %d failure(s)\n", failures);
	return failures;
}
