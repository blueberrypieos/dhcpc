/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 The Blueberry Pie OS Authors
 */

#include <arpa/inet.h>
#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "client.h"

#define WAIT_LINK_MS    10000   /* the longest wait for the link before the first send */
#define FIRST_WAIT_MS   2000
#define LONGEST_WAIT_MS 16000
#define REBOOT_SENDS    3       /* INIT-REBOOT: sent at 0, 2 and 6 s, given up at 14 s */
#define BURST_SENDS     3       /* renewing: bursts of 3, a minute apart */
#define BURST_GAP_MS    60000
#define REFUSED_WAIT_MS 30000   /* after a second refusal of a first request */
#define APPLY_RETRY_MS  5000    /* after a lease's address could not be set */

static const char *
ip(struct in_addr a, char buf[16])
{
	const uint8_t *b = (const uint8_t *)&a.s_addr;

	snprintf(buf, 16, "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
	return buf;
}

static uint32_t
t1_of(const struct lease *l)
{
	return l->t1 && l->t1 < l->lease ? l->t1 : l->lease / 2;
}

static uint32_t
t2_of(const struct lease *l)
{
	uint32_t t1 = t1_of(l);
	uint32_t t2 = l->t2 > t1 && l->t2 < l->lease ? l->t2 : (uint32_t)((uint64_t)l->lease * 7 / 8);

	if (t2 <= t1) {
		t2 = t1 + (l->lease - t1) / 2;
	}
	return t2;
}

int64_t
lease_renew(const struct lease *l)
{
	return l->sent + (int64_t)t1_of(l) * 1000;
}

int64_t
lease_rebind(const struct lease *l)
{
	return l->sent + (int64_t)t2_of(l) * 1000;
}

int64_t
lease_end(const struct lease *l)
{
	return l->sent + (int64_t)l->lease * 1000;
}

void
client_init(struct client *c, const struct cops *ops, void *ctx)
{
	memset(c, 0, sizeof(*c));
	c->ops = ops;
	c->ctx = ctx;
	c->state = C_GONE;
}

/* Send this state's message, and set when to send again or give up. */
static void
transmit(struct client *c, int64_t now)
{
	struct csend m;
	int64_t secs = (now - c->start) / 1000;

	memset(&m, 0, sizeof(m));
	c->xid = c->ops->xid(c->ctx);
	m.xid = c->xid;
	m.secs = (uint16_t)(secs > 65535 ? 65535 : secs);
	switch (c->state) {
	case C_INIT:
		m.type = DHCPDISCOVER;
		m.reqip = c->hint;
		c->secs = m.secs;
		break;
	case C_REBOOTING:
		m.type = DHCPREQUEST;
		m.reqip = c->cur.addr;
		break;
	case C_RENEWING:
	case C_REBINDING:
		m.type = DHCPREQUEST;
		m.ciaddr = c->cur.addr;
		if (c->state == C_RENEWING && c->cur.server.s_addr != 0) {
			m.unicast = true;
			m.dst = c->cur.server;
		}
		break;
	default:
		return;
	}
	if (m.type == DHCPREQUEST) {
		c->sent = now;
	}
	c->ops->send(c->ctx, &m);
	c->sends++;
	c->wait = c->timeout;
	c->next = now + c->wait;
	if (c->state == C_RENEWING && c->next > lease_rebind(&c->cur)) {
		c->next = lease_rebind(&c->cur);
	}
	c->timeout = c->timeout < LONGEST_WAIT_MS ? c->timeout * 2 : LONGEST_WAIT_MS;
}

static void
begin(struct client *c, enum cstate s, int64_t now)
{
	c->state = s;
	c->start = now;
	c->sends = 0;
	c->timeout = FIRST_WAIT_MS;
	transmit(c, now);
}

/* cur's address stays without a confirmation, as s says. */
static void
hold(struct client *c, enum lstatus s)
{
	if (c->status != s) {
		c->status = s;
		c->ops->hold(c->ctx, &c->cur, s);
	}
}

/*
 * Ask again from the start: for the remembered lease if it has not ended,
 * else for a new one. A set address is no longer confirmed.
 */
static void lose(struct client *c);

static void
start(struct client *c, int64_t now)
{
	char a[16];

	if (c->have && now >= lease_end(&c->cur)) {
		c->ops->log(c->ctx, "lease of %s ended", ip(c->cur.addr, a));
		lose(c);
		c->hint = c->cur.addr;
	}
	if (c->have) {
		c->ops->log(c->ctx, "asking for %s again", ip(c->cur.addr, a));
		if (c->addr_on && c->status != L_FOUND) {
			hold(c, L_CHECKING);
		}
	}
	begin(c, c->have ? C_REBOOTING : C_INIT, now);
}

/* The lease is refused or ended: its address and routes go. */
static void
lose(struct client *c)
{
	if (c->addr_on) {
		c->ops->drop(c->ctx, &c->cur);
	}
	c->addr_on = false;
	c->have = false;
	c->hint.s_addr = 0;
}

/*
 * Bind r's lease once its address is set. If it cannot be set, the lease
 * is asked for again with INIT-REBOOT soon; a lease with the address that
 * is set already keeps it, and asks again where it was, renewing no later
 * than T2, when rebinding starts.
 */
static void
bind_lease(struct client *c, const struct lease *r, int64_t now)
{
	struct lease l = *r;
	char a[16], b[16];

	if (l.mask.s_addr == 0) {
		l.mask.s_addr = htonl(0xffffff00u);
	}
	l.sent = c->sent;
	if (!c->ops->apply(c->ctx, c->addr_on ? &c->cur : NULL, &l)) {
		c->ops->log(c->ctx, "%s could not be set; asking again in %d s", ip(l.addr, a), APPLY_RETRY_MS / 1000);
		if (!c->addr_on || c->cur.addr.s_addr != l.addr.s_addr) {
			c->cur = l;
			memcpy(c->cur_mac, c->mac, sizeof(c->mac));
			c->have = true;
			c->addr_on = false;
			c->hint.s_addr = 0;
			c->state = C_REBOOTING;
			c->start = now;
		}
		c->sends = 0;
		c->timeout = FIRST_WAIT_MS;
		c->next = now + APPLY_RETRY_MS;
		if (c->state == C_RENEWING && c->next > lease_rebind(&c->cur)) {
			c->next = lease_rebind(&c->cur);
		}
		return;
	}
	c->ops->log(c->ctx, "%s/%d, router %s, %d name server(s), lease %u s", ip(l.addr, a),
	    __builtin_popcount(l.mask.s_addr), l.router.s_addr ? ip(l.router, b) : "none", l.ndns,
	    l.lease);
	c->cur = l;
	memcpy(c->cur_mac, c->mac, sizeof(c->mac));
	c->have = c->addr_on = c->bound_once = true;
	c->status = L_CONFIRMED;
	c->hint.s_addr = 0;
	c->refusals = 0;
	c->state = C_BOUND;
	c->sends = 0;
	c->next = lease_renew(&l);
}

void
client_attach(struct client *c, const uint8_t mac[6], int64_t now)
{
	char a[16];

	if (c->state != C_GONE) {
		client_detach(c, now);
	}
	if (c->have && memcmp(c->cur_mac, mac, sizeof(c->cur_mac)) != 0) {
		c->ops->log(c->ctx, "another adapter has the name; its lease of %s is not asked for",
		    ip(c->cur.addr, a));
		c->have = false;
		c->hint.s_addr = 0;
	} else if (c->have && now >= lease_end(&c->cur)) {
		lose(c);
		c->hint = c->cur.addr;
	}
	memcpy(c->mac, mac, sizeof(c->mac));
	c->gen++;
	c->ops->up(c->ctx);
	c->ops->open(c->ctx);
	c->link = c->ops->link(c->ctx);
	if (c->link) {
		start(c, now);
	} else {
		c->state = C_WAITLINK;
		c->next = now + WAIT_LINK_MS;
	}
}

void
client_detach(struct client *c, int64_t now)
{
	bool had = c->addr_on;

	(void)now;
	if (c->state == C_GONE) {
		return;
	}
	c->ops->close(c->ctx);
	c->addr_on = false;
	c->link = false;
	c->state = C_GONE;
	c->ops->gone(c->ctx, had ? &c->cur : NULL);
	c->ops->log(c->ctx, "gone");
}

/*
 * A lease whose address an earlier dhcpc set, as s says: its address
 * stays, and its times go on. A lease being checked, or found set without
 * a record, is asked for again with INIT-REBOOT; a confirmed one whose
 * link is down now, once the link comes.
 */
void
client_adopt(struct client *c, const struct lease *l, const uint8_t mac[6], enum lstatus s,
    int64_t now)
{
	memcpy(c->mac, mac, sizeof(c->mac));
	memcpy(c->cur_mac, mac, sizeof(c->cur_mac));
	c->cur = *l;
	c->have = c->addr_on = true;
	c->status = s;
	c->hint.s_addr = 0;
	c->gen++;
	c->ops->up(c->ctx);
	c->ops->open(c->ctx);
	c->link = c->ops->link(c->ctx);
	if (now >= lease_end(l)) {
		start(c, now);
	} else if (s == L_HELD) {
		c->hint = l->addr;
		begin(c, C_INIT, now);
	} else if (!c->link) {
		if (s == L_CONFIRMED) {
			hold(c, L_CHECKING);
		}
		c->state = C_WAITLINK;
		c->next = now + WAIT_LINK_MS;
	} else if (s != L_CONFIRMED) {
		start(c, now);
	} else {
		c->bound_once = true;
		if (now >= lease_rebind(l)) {
			begin(c, C_REBINDING, now);
		} else if (now >= lease_renew(l)) {
			begin(c, C_RENEWING, now);
		} else {
			c->state = C_BOUND;
			c->sends = 0;
			c->next = lease_renew(l);
		}
	}
}

/* A lease that an earlier dhcpc had, whose address is no longer set: it is asked for again at the next arrival. */
void
client_remember(struct client *c, const struct lease *l, const uint8_t mac[6])
{
	c->cur = *l;
	memcpy(c->cur_mac, mac, sizeof(c->cur_mac));
	c->have = true;
	c->addr_on = false;
}

void
client_link(struct client *c, bool up, int64_t now)
{
	if (c->state == C_GONE) {
		return;
	}
	c->link = up;
	c->ops->log(c->ctx, up ? "link up" : "link down");
	if (up) {
		start(c, now);
	} else if (c->addr_on && c->status == L_CONFIRMED) {
		hold(c, L_CHECKING);
	}
}

void
client_reply(struct client *c, const struct lease *r, uint32_t gen, int64_t now)
{
	char a[16];

	if (gen != c->gen) {
		return;
	}
	switch (c->state) {
	case C_INIT:
		if (r->type == DHCPOFFER) {
			struct csend m;

			c->offer = *r;
			memset(&m, 0, sizeof(m));
			m.type = DHCPREQUEST;
			m.xid = c->xid;
			m.secs = c->secs;
			m.reqip = r->addr;
			m.server = r->server;
			c->sent = now;
			c->ops->send(c->ctx, &m);
			c->state = C_REQUESTING;
			c->next = now + c->wait;
		}
		break;
	case C_REQUESTING:
		if (r->type == DHCPACK) {
			bind_lease(c, r, now);
		} else if (r->type == DHCPNAK && r->server.s_addr == c->offer.server.s_addr) {
			c->ops->log(c->ctx, "server %s refused the lease", ip(r->server, a));
			lose(c);
			if (++c->refusals < 2) {
				begin(c, C_INIT, now);
			} else {
				c->refusals = 0;
				c->state = C_INIT;
				c->start = now;
				c->sends = 0;
				c->timeout = FIRST_WAIT_MS;
				c->next = now + REFUSED_WAIT_MS;
			}
		}
		break;
	case C_REBOOTING:
		if (r->type == DHCPACK) {
			bind_lease(c, r, now);
		} else if (r->type == DHCPNAK) {
			char b[16];

			c->ops->log(c->ctx, "server %s refused %s", ip(r->server, a), ip(c->cur.addr, b));
			lose(c);
			begin(c, C_INIT, now);
		}
		break;
	case C_RENEWING:
	case C_REBINDING:
		if (r->type == DHCPACK) {
			bind_lease(c, r, now);
		} else if (r->type == DHCPNAK &&
		    (c->state == C_REBINDING || r->server.s_addr == c->cur.server.s_addr)) {
			c->ops->log(c->ctx, "server %s refused the lease", ip(r->server, a));
			lose(c);
			begin(c, C_INIT, now);
		}
		break;
	default:
		break;
	}
}

void
client_timer(struct client *c, int64_t now)
{
	char a[16];

	if (c->have && now >= lease_end(&c->cur)) {
		bool asked = c->state == C_BOUND || c->state == C_RENEWING || c->state == C_REBINDING ||
		    c->state == C_REBOOTING;

		c->ops->log(c->ctx, "lease of %s ended", ip(c->cur.addr, a));
		lose(c);
		c->hint = c->cur.addr;
		if (asked) {
			begin(c, C_INIT, now);
			return;
		}
	}
	if (c->state == C_GONE || now < c->next) {
		return;
	}
	switch (c->state) {
	case C_WAITLINK:
		start(c, now);
		break;
	case C_INIT:
		transmit(c, now);
		break;
	case C_REQUESTING:
		c->state = C_INIT;
		transmit(c, now);
		break;
	case C_REBOOTING:
		if (c->sends < REBOOT_SENDS) {
			transmit(c, now);
			break;
		}
		c->hint = c->cur.addr;
		if (c->addr_on) {
			c->ops->log(c->ctx, "no answer for %s; it stays until a lease binds or it ends",
			    ip(c->cur.addr, a));
			hold(c, L_HELD);
		} else {
			c->ops->log(c->ctx, "no answer for %s; asking for a new lease", ip(c->cur.addr, a));
			c->have = false;
		}
		begin(c, C_INIT, now);
		break;
	case C_BOUND:
		begin(c, C_RENEWING, now);
		break;
	case C_RENEWING:
		if (now >= lease_rebind(&c->cur)) {
			begin(c, C_REBINDING, now);
			break;
		}
		/* FALLTHROUGH */
	case C_REBINDING:
		if (c->sends < BURST_SENDS) {
			transmit(c, now);
		} else {
			int64_t edge = c->state == C_RENEWING ? lease_rebind(&c->cur) : lease_end(&c->cur);

			c->sends = 0;
			c->timeout = FIRST_WAIT_MS;
			c->next = now + BURST_GAP_MS < edge ? now + BURST_GAP_MS : edge;
		}
		break;
	default:
		break;
	}
}

int64_t
client_next(const struct client *c)
{
	int64_t t = c->state == C_GONE ? INT64_MAX : c->next;

	if (c->have && lease_end(&c->cur) < t) {
		t = lease_end(&c->cur);
	}
	return t;
}

int
elect_choose(const struct candidate *c, int n)
{
	bool confirmed = false;
	int best = -1;

	for (int i = 0; i < n; i++) {
		if (c[i].router && c[i].connected && c[i].confirmed) {
			confirmed = true;
		}
	}
	for (int i = 0; i < n; i++) {
		if (!c[i].router || !c[i].connected || (confirmed && !c[i].confirmed)) {
			continue;
		}
		if (best < 0 || c[i].unit < c[best].unit) {
			best = i;
		}
	}
	return best;
}

size_t
resolv_text(char *out, size_t cap, const char *name, const struct lease *l)
{
	size_t len = 0;
	char a[16];
	int n;

	n = snprintf(out, cap, "# written by dhcpc%s%s\n", name != NULL ? " for " : "",
	    name != NULL ? name : "");
	len += n > 0 ? (size_t)n : 0;
	if (l != NULL && l->domain[0] && len < cap) {
		n = snprintf(out + len, cap - len, "search %s\n", l->domain);
		len += n > 0 ? (size_t)n : 0;
	}
	for (int i = 0; l != NULL && i < l->ndns && len < cap; i++) {
		n = snprintf(out + len, cap - len, "nameserver %s\n", ip(l->dns[i], a));
		len += n > 0 ? (size_t)n : 0;
	}
	return len;
}

bool
domain_ok(const char *s, size_t len)
{
	if (len == 0 || len > 255) {
		return false;
	}
	for (size_t i = 0; i < len; i++) {
		unsigned char ch = (unsigned char)s[i];
		if (!isalnum(ch) && ch != '-' && ch != '.' && ch != '_') {
			return false;
		}
	}
	return true;
}
