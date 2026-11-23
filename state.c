/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 The Blueberry Pie OS Authors
 */

#include <arpa/inet.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "state.h"

static const char *const status_words[] = { "confirmed", "checking", "held", "found" };

/* A text being written: its length goes on counting past cap. */
struct out {
	char *p;
	size_t cap, len;
};

static void
put(struct out *o, const char *fmt, ...) __attribute__((format(printf, 2, 3)));

static void
put(struct out *o, const char *fmt, ...)
{
	va_list ap;
	int n;

	va_start(ap, fmt);
	n = vsnprintf(o->len < o->cap ? o->p + o->len : NULL, o->len < o->cap ? o->cap - o->len : 0, fmt, ap);
	va_end(ap);
	o->len += n > 0 ? (size_t)n : 0;
}

static void
put_addr(struct out *o, const char *key, struct in_addr a)
{
	const uint8_t *b = (const uint8_t *)&a.s_addr;

	put(o, "%s %u.%u.%u.%u\n", key, b[0], b[1], b[2], b[3]);
}

/* FNV-1a over len bytes. */
static uint32_t
check_of(const char *p, size_t len)
{
	uint32_t h = 2166136261u;

	for (size_t i = 0; i < len; i++) {
		h ^= (uint8_t)p[i];
		h *= 16777619u;
	}
	return h;
}

/* The end line, which checks the text before it. */
static size_t
put_end(struct out *o)
{
	if (o->len < o->cap) {
		put(o, "end %08x\n", (unsigned int)check_of(o->p, o->len));
	} else {
		o->len += 13;
	}
	return o->len;
}

/*
 * The lines of text, len bytes, before its end line, if that line is
 * there and checks them: their length, or -1.
 */
static long
body_of(const char *text, size_t len)
{
	size_t start;
	unsigned int check = 0;

	if (len < 13 || text[len - 1] != '\n') {
		return -1;
	}
	start = len - 13;
	if ((start > 0 && text[start - 1] != '\n') || memcmp(text + start, "end ", 4) != 0) {
		return -1;
	}
	for (size_t i = start + 4; i < len - 1; i++) {
		char ch = text[i];
		if (ch >= '0' && ch <= '9') {
			check = check << 4 | (unsigned int)(ch - '0');
		} else if (ch >= 'a' && ch <= 'f') {
			check = check << 4 | (unsigned int)(ch - 'a' + 10);
		} else {
			return -1;
		}
	}
	return check == check_of(text, start) ? (long)start : -1;
}

/* The next line of text[*i, end): its key and value, one space apart, into key and val. */
static bool
next_line(const char *text, size_t end, size_t *i, char key[16], char val[260])
{
	const char *line = text + *i, *nl = memchr(line, '\n', end - *i), *sp;
	size_t klen, vlen;

	if (nl == NULL) {
		return false;
	}
	sp = memchr(line, ' ', (size_t)(nl - line));
	if (sp == NULL) {
		return false;
	}
	klen = (size_t)(sp - line);
	vlen = (size_t)(nl - sp - 1);
	if (klen == 0 || klen >= 16 || vlen == 0 || vlen >= 260 || memchr(sp + 1, ' ', vlen) != NULL) {
		return false;
	}
	memcpy(key, line, klen);
	key[klen] = '\0';
	memcpy(val, sp + 1, vlen);
	val[vlen] = '\0';
	*i = (size_t)(nl - text) + 1;
	return true;
}

/* A decimal number of at most max, without sign or spaces. */
static bool
number(const char *s, uint64_t max, uint64_t *v)
{
	uint64_t n = 0;

	if (*s == '\0' || strlen(s) > 20) {
		return false;
	}
	for (; *s != '\0'; s++) {
		if (*s < '0' || *s > '9' || n > (max - (uint64_t)(*s - '0')) / 10) {
			return false;
		}
		n = n * 10 + (uint64_t)(*s - '0');
	}
	*v = n;
	return true;
}

static bool
address(const char *s, struct in_addr *a)
{
	return inet_pton(AF_INET, s, a) == 1;
}

static bool
hardware(const char *s, uint8_t mac[6])
{
	static const char hex[] = "0123456789abcdef";

	if (strlen(s) != 17) {
		return false;
	}
	for (int i = 0; i < 6; i++) {
		const char *hi = memchr(hex, s[3 * i], 16), *lo = memchr(hex, s[3 * i + 1], 16);
		if (s[3 * i] == '\0' || s[3 * i + 1] == '\0' || hi == NULL || lo == NULL ||
		    (i < 5 && s[3 * i + 2] != ':')) {
			return false;
		}
		mac[i] = (uint8_t)((hi - hex) << 4 | (lo - hex));
	}
	return true;
}

/* A netmask: its ones first. */
static bool
mask_ok(struct in_addr m)
{
	uint32_t h = ntohl(m.s_addr);

	return h != 0 && (~h & (~h + 1)) == 0;
}

size_t
record_format(char *out, size_t cap, const struct record *r)
{
	struct out o = { out, cap, 0 };
	const uint8_t *m = r->mac;

	if (r->has_lease) {
		put_addr(&o, "address", r->l.addr);
		put_addr(&o, "mask", r->l.mask);
		put_addr(&o, "router", r->l.router);
		put_addr(&o, "server", r->l.server);
		put_addr(&o, "broadcast", r->l.broadcast);
		for (int i = 0; i < r->l.ndns && i < 3; i++) {
			put_addr(&o, "nameserver", r->l.dns[i]);
		}
		if (r->l.domain[0] != '\0') {
			put(&o, "domain %s\n", r->l.domain);
		}
		put(&o, "lease %u\nt1 %u\nt2 %u\nsent %lld\n", r->l.lease, r->l.t1, r->l.t2, (long long)r->l.sent);
		put(&o, "status %s\n", status_words[r->status]);
	}
	for (int i = 0; i < r->nremove && i < REMOVE_MAX; i++) {
		const uint8_t *b = (const uint8_t *)&r->remove[i].addr.s_addr;
		put(&o, "remove %u.%u.%u.%u/%d\n", b[0], b[1], b[2], b[3],
		    __builtin_popcount(ntohl(r->remove[i].mask.s_addr)));
	}
	put(&o, "mac %02x:%02x:%02x:%02x:%02x:%02x\n", m[0], m[1], m[2], m[3], m[4], m[5]);
	put(&o, "ifindex %u\n", r->ifindex);
	return put_end(&o);
}

enum {
	F_ADDRESS = 1, F_MASK = 2, F_ROUTER = 4, F_SERVER = 8, F_BROADCAST = 16, F_DOMAIN = 32,
	F_LEASE = 64, F_T1 = 128, F_T2 = 256, F_SENT = 512, F_MAC = 1024, F_IFINDEX = 2048,
	F_STATUS = 4096,
	F_LEASE_ALL = F_ADDRESS | F_MASK | F_ROUTER | F_SERVER | F_BROADCAST | F_LEASE | F_T1 | F_T2 | F_SENT |
	    F_STATUS,
};

/* A netmask of len ones. */
static struct in_addr
mask_of(int len)
{
	struct in_addr m = { htonl(len >= 32 ? 0xffffffffu : ~(0xffffffffu >> len)) };

	return m;
}

/* An address to remove, "a.b.c.d/len", into r. */
static bool
remove_field(struct record *r, const char *val)
{
	const char *slash = strchr(val, '/');
	char a[16];
	struct in_addr addr;
	uint64_t len;

	if (slash == NULL || (size_t)(slash - val) >= sizeof(a) || r->nremove == REMOVE_MAX) {
		return false;
	}
	memcpy(a, val, (size_t)(slash - val));
	a[slash - val] = '\0';
	if (!address(a, &addr) || addr.s_addr == 0 || !number(slash + 1, 32, &len) || len == 0) {
		return false;
	}
	for (int i = 0; i < r->nremove; i++) {
		if (r->remove[i].addr.s_addr == addr.s_addr) {
			return false;
		}
	}
	r->remove[r->nremove].addr = addr;
	r->remove[r->nremove].mask = mask_of((int)len);
	r->nremove++;
	return true;
}

/* One of a record's lines into r; seen has a bit for each field read. */
static bool
record_field(struct record *r, const char *key, const char *val, unsigned int *seen)
{
	static const struct {
		const char *key;
		unsigned int bit;
	} keys[] = {
		{ "address", F_ADDRESS }, { "mask", F_MASK }, { "router", F_ROUTER }, { "server", F_SERVER },
		{ "broadcast", F_BROADCAST }, { "domain", F_DOMAIN }, { "lease", F_LEASE }, { "t1", F_T1 },
		{ "t2", F_T2 }, { "sent", F_SENT }, { "mac", F_MAC }, { "ifindex", F_IFINDEX },
		{ "status", F_STATUS },
	};
	unsigned int bit = 0;
	uint64_t v;

	if (strcmp(key, "nameserver") == 0) {
		return r->l.ndns < 3 && address(val, &r->l.dns[r->l.ndns++]);
	}
	if (strcmp(key, "remove") == 0) {
		return remove_field(r, val);
	}
	for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
		if (strcmp(key, keys[i].key) == 0) {
			bit = keys[i].bit;
		}
	}
	if (bit == 0 || (*seen & bit) != 0) {
		return false;
	}
	*seen |= bit;
	switch (bit) {
	case F_ADDRESS:
		return address(val, &r->l.addr);
	case F_MASK:
		return address(val, &r->l.mask);
	case F_ROUTER:
		return address(val, &r->l.router);
	case F_SERVER:
		return address(val, &r->l.server);
	case F_BROADCAST:
		return address(val, &r->l.broadcast);
	case F_DOMAIN:
		if (!domain_ok(val, strlen(val))) {
			return false;
		}
		strcpy(r->l.domain, val);
		return true;
	case F_LEASE:
	case F_T1:
	case F_T2:
		if (!number(val, UINT32_MAX, &v)) {
			return false;
		}
		*(bit == F_LEASE ? &r->l.lease : bit == F_T1 ? &r->l.t1 : &r->l.t2) = (uint32_t)v;
		return true;
	case F_SENT:
		if (!number(val, INT64_MAX, &v)) {
			return false;
		}
		r->l.sent = (int64_t)v;
		return true;
	case F_MAC:
		return hardware(val, r->mac);
	case F_IFINDEX:
		if (!number(val, UINT32_MAX, &v)) {
			return false;
		}
		r->ifindex = (unsigned int)v;
		return true;
	case F_STATUS:
		for (int s = L_CONFIRMED; s <= L_FOUND; s++) {
			if (strcmp(val, status_words[s]) == 0) {
				r->status = (enum lstatus)s;
				return true;
			}
		}
		return false;
	default:
		return false;
	}
}

bool
record_parse(const char *text, size_t len, struct record *r)
{
	char key[16], val[260];
	unsigned int seen = 0;
	long body = body_of(text, len);
	bool ok;

	memset(r, 0, sizeof(*r));
	if (body < 0) {
		return false;
	}
	for (size_t i = 0; i < (size_t)body;) {
		if (!next_line(text, (size_t)body, &i, key, val) || !record_field(r, key, val, &seen)) {
			memset(r, 0, sizeof(*r));
			return false;
		}
	}
	r->has_lease = (seen & F_LEASE_ALL) == F_LEASE_ALL;
	r->l.type = DHCPACK;
	if (r->has_lease) {
		ok = r->l.addr.s_addr != 0 && mask_ok(r->l.mask) && r->l.lease != 0 && r->ifindex != 0;
	} else {
		ok = (seen & (F_LEASE_ALL | F_DOMAIN)) == 0 && r->l.ndns == 0;
	}
	if (!ok || (seen & (F_MAC | F_IFINDEX)) != (F_MAC | F_IFINDEX)) {
		memset(r, 0, sizeof(*r));
		return false;
	}
	return true;
}

bool
record_pend(struct record *r, struct in_addr addr, struct in_addr mask)
{
	for (int i = 0; i < r->nremove; i++) {
		if (r->remove[i].addr.s_addr == addr.s_addr) {
			return true;
		}
	}
	if (r->nremove == REMOVE_MAX || addr.s_addr == 0) {
		return false;
	}
	r->remove[r->nremove].addr = addr;
	r->remove[r->nremove].mask = mask_ok(mask) ? mask : mask_of(32);
	r->nremove++;
	return true;
}

void
record_unpend(struct record *r, struct in_addr addr)
{
	for (int i = 0; i < r->nremove; i++) {
		if (r->remove[i].addr.s_addr == addr.s_addr) {
			memmove(&r->remove[i], &r->remove[i + 1], sizeof(r->remove[0]) * (size_t)(r->nremove - i - 1));
			r->nremove--;
			return;
		}
	}
}

bool
record_removed(struct record *r, struct in_addr addr, struct in_addr mask, enum addrstate st)
{
	if (st == ADDR_ABSENT) {
		record_unpend(r, addr);
		return true;
	}
	return record_pend(r, addr, mask);
}

bool
record_may_set(const struct record *r, struct in_addr addr)
{
	return (r->has_lease && r->l.addr.s_addr == addr.s_addr) || r->nremove < REMOVE_MAX;
}

void
record_lease(struct record *r, const struct lease *l, enum lstatus s)
{
	r->has_lease = true;
	r->l = *l;
	r->status = s;
	record_unpend(r, l->addr);
}

bool
record_here(const struct record *r, const uint8_t mac[6], unsigned int ifindex)
{
	return memcmp(r->mac, mac, sizeof(r->mac)) == 0 || (ifindex != 0 && r->ifindex == ifindex);
}

void
record_reconcile(struct record *r)
{
	if (r->has_lease) {
		record_unpend(r, r->l.addr);
	}
}

bool
record_current(const struct record *r, const uint8_t mac[6], unsigned int ifindex, bool addr_set,
    int64_t now)
{
	return r->has_lease && r->l.sent <= now && now < lease_end(&r->l) && ifindex != 0 &&
	    r->ifindex == ifindex && memcmp(r->mac, mac, sizeof(r->mac)) == 0 && addr_set;
}

void
plan_takeover(const struct record *r, const uint8_t mac[6], unsigned int ifindex, bool addr_set,
    const struct in_addr *first, struct in_addr first_mask, int64_t now, struct plan *p)
{
	memset(p, 0, sizeof(*p));
	if (r != NULL && !r->has_lease) {
		return;
	}
	if (r != NULL && r->l.sent <= now) {
		bool same_mac = memcmp(r->mac, mac, sizeof(r->mac)) == 0;

		if (addr_set && same_mac && now < lease_end(&r->l)) {
			p->what = TAKE_ADOPT;
			p->l = r->l;
			p->status = r->status;
			if (r->ifindex != ifindex && p->status == L_CONFIRMED) {
				p->status = L_CHECKING;
			}
			memcpy(p->mac, mac, sizeof(p->mac));
			return;
		}
		p->what = TAKE_REMEMBER;
		p->l = r->l;
		memcpy(p->mac, r->mac, sizeof(p->mac));
		if (addr_set && record_here(r, mac, ifindex)) {
			p->remove = true;
			p->rm = r->l;
		}
		return;
	}
	if (first != NULL) {
		p->what = TAKE_ADOPT;
		p->l.type = DHCPACK;
		p->l.addr = *first;
		p->l.mask = mask_ok(first_mask) ? first_mask : mask_of(24);
		p->l.lease = REBOOT_WAIT_S;
		p->l.sent = now;
		p->status = L_FOUND;
		memcpy(p->mac, mac, sizeof(p->mac));
	}
}

struct in_addr
lease_broadcast(const struct lease *l)
{
	struct in_addr b = l->broadcast;

	if (b.s_addr == 0) {
		b.s_addr = l->addr.s_addr | ~l->mask.s_addr;
	}
	return b;
}

bool
lease_set_as(const struct lease *l, struct in_addr mask, struct in_addr broadcast)
{
	return mask.s_addr == l->mask.s_addr && broadcast.s_addr == lease_broadcast(l).s_addr;
}

size_t
marker_format(char *out, size_t cap, const struct marker *m)
{
	struct out o = { out, cap, 0 };

	for (int i = 0; i < m->n; i++) {
		const uint8_t *b = (const uint8_t *)&m->r[i].router.s_addr;
		put(&o, "route %s %u %u.%u.%u.%u\n", m->r[i].name, m->r[i].ifindex, b[0], b[1], b[2], b[3]);
	}
	return put_end(&o);
}

bool
marker_parse(const char *text, size_t len, struct marker *m)
{
	long body = body_of(text, len);

	memset(m, 0, sizeof(*m));
	if (body < 0) {
		return false;
	}
	for (size_t i = 0; i < (size_t)body;) {
		const char *line = text + i, *nl = memchr(line, '\n', (size_t)body - i);
		char buf[80], again[80], name[16], idx[16], router[16], extra;
		struct droute *r = &m->r[m->n];
		uint64_t v;
		size_t n;

		if (nl == NULL || (n = (size_t)(nl - line)) >= sizeof(buf) || m->n == MARKER_MAX) {
			memset(m, 0, sizeof(*m));
			return false;
		}
		memcpy(buf, line, n);
		buf[n] = '\0';
		i += n + 1;
		if (sscanf(buf, "route %15s %15s %15s %c", name, idx, router, &extra) != 3 ||
		    !number(idx, UINT32_MAX, &v) || v == 0 || !address(router, &r->router) ||
		    snprintf(again, sizeof(again), "route %s %s %s", name, idx, router) != (int)n ||
		    strcmp(again, buf) != 0) {
			memset(m, 0, sizeof(*m));
			return false;
		}
		strcpy(r->name, name);
		r->ifindex = (unsigned int)v;
		m->n++;
	}
	return true;
}

static bool
same_route(const struct droute *a, const struct droute *b)
{
	return strcmp(a->name, b->name) == 0 && a->ifindex == b->ifindex && a->router.s_addr == b->router.s_addr;
}

bool
marker_add(struct marker *m, const struct droute *r)
{
	for (int i = 0; i < m->n; i++) {
		if (same_route(&m->r[i], r)) {
			return true;
		}
	}
	if (m->n == MARKER_MAX) {
		return false;
	}
	m->r[m->n++] = *r;
	return true;
}

/* An Ethernet interface's name: en and a number. */
static bool
ethernet(const char *name)
{
	return strncmp(name, "en", 2) == 0 && name[2] >= '0' && name[2] <= '9';
}

bool
marker_owns(const struct marker *m, struct in_addr gw, unsigned int ifindex, const char *name)
{
	if (gw.s_addr == 0 || ifindex == 0) {
		return false;
	}
	if (m == NULL) {
		return ethernet(name);
	}
	for (int i = 0; i < m->n; i++) {
		if (m->r[i].router.s_addr == gw.s_addr && m->r[i].ifindex == ifindex &&
		    strcmp(m->r[i].name, name) == 0) {
			return true;
		}
	}
	return false;
}

bool
unrecorded_address(const struct ifaddr4 *set, int n, const struct ifaddr4 *covered, int m)
{
	for (int i = 0; i < n; i++) {
		bool known = !ethernet(set[i].name);

		for (int j = 0; j < m && !known; j++) {
			known = strcmp(set[i].name, covered[j].name) == 0 && set[i].addr.s_addr == covered[j].addr.s_addr;
		}
		if (!known) {
			return true;
		}
	}
	return false;
}

void
elect_plan(const struct droute *win, bool found, bool unrecorded, const struct marker *was,
    const struct kroute *k, struct eplan *p)
{
	bool ours = k->probe == PROBE_FOUND && marker_owns(was, k->r.router, k->r.ifindex, k->r.name);

	memset(p, 0, sizeof(*p));
	if (win != NULL) {
		p->resolv = true;
		if (k->probe == PROBE_FOUND && same_route(&k->r, win)) {
			p->settle = !(was != NULL && was->n == 1 && same_route(&was->r[0], win));
			return;
		}
		if (k->probe == PROBE_FAILED) {
			if (was == NULL) {
				return;
			}
			p->intent = *was;
		} else if (ours) {
			marker_add(&p->intent, &k->r);
		}
		if (marker_add(&p->intent, win)) {
			p->set = p->settle = true;
		}
		return;
	}
	if (found || (was == NULL && unrecorded)) {
		return;
	}
	p->clear = true;
	if (k->probe == PROBE_FAILED) {
		return;
	}
	if (ours) {
		p->remove = true;
		return;
	}
	p->none = !(was != NULL && was->n == 0);
}

void
rt_addrs(const uint8_t *p, size_t n, unsigned int addrs, uint8_t out[RT_ADDRS][16])
{
	size_t i = 0;

	memset(out, 0, RT_ADDRS * 16);
	for (int bit = 0; bit < RT_ADDRS && i < n; bit++) {
		if (!(addrs & (1u << bit))) {
			continue;
		}
		size_t len = p[i], take = len < 16 ? len : 16;
		if (take > n - i) {
			take = n - i;
		}
		memcpy(out[bit], p + i, take);
		i += len > 0 ? (len + 3) & ~(size_t)3 : 4;
	}
}
