/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 The Blueberry Pie OS Authors
 *
 * What dhcpc keeps in /var/run/dhcpc, without I/O: each interface's
 * record, which the election and a dhcpc that takes the interface over
 * read, and the marker of the default routes dhcpc set; and what dhcpc
 * does with them. Each text ends with a line that checks the rest, so
 * that one cut short or changed is not used.
 */

#ifndef DHCPC_STATE_H
#define DHCPC_STATE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "client.h"

#define STATE_TEXT_MAX  1024
#define REMOVE_MAX      8

struct addrmask {
	struct in_addr addr, mask;
};

/*
 * An interface's record: the lease whose address dhcpc set, if it has
 * one, with its status; the addresses dhcpc set that did not go yet; and
 * the interface's hardware address and index, 0 once it went. Without a
 * lease, it says that this dhcpc set no address that stays.
 */
struct record {
	bool has_lease;
	struct lease l;
	enum lstatus status;
	int nremove;
	struct addrmask remove[REMOVE_MAX];
	uint8_t mac[6];
	unsigned int ifindex;
};

/* r's text into out, which holds cap bytes. Returns its length, cap or more if it did not fit. */
size_t record_format(char *out, size_t cap, const struct record *r);

/* Read text, len bytes, into r: true if it is a whole record, every field there as often as it may be and valid. */
bool record_parse(const char *text, size_t len, struct record *r);

/* Add addr to r's addresses to remove, if it is not there: false if there is no room. */
bool record_pend(struct record *r, struct in_addr addr, struct in_addr mask);

/* Take addr from r's addresses to remove. */
void record_unpend(struct record *r, struct in_addr addr);

/* Whether an address is set on an interface; ADDR_UNKNOWN when its addresses could not be read. */
enum addrstate {
	ADDR_UNKNOWN,
	ADDR_ABSENT,
	ADDR_SET,
};

/*
 * After an attempt to remove addr, st says whether it is set: it leaves
 * r's addresses to remove only when it is known to be gone, and stays
 * among them otherwise. False if it stays and there is no room for it.
 */
bool record_removed(struct record *r, struct in_addr addr, struct in_addr mask, enum addrstate st);

/*
 * r has room for addr to be set: addr is r's lease's, or there is room to
 * remove one more address, so that whatever is set can always be removed.
 */
bool record_may_set(const struct record *r, struct in_addr addr);

/* r's lease is l, with status s, in the same write that stops l's address from being one to remove. */
void record_lease(struct record *r, const struct lease *l, enum lstatus s);

/*
 * r is the record of the interface that has hardware address mac and
 * index ifindex now: the same adapter, or the same interface.
 */
bool record_here(const struct record *r, const uint8_t mac[6], unsigned int ifindex);

/* A record whose lease's address is also among its addresses to remove keeps it as the lease's. */
void record_reconcile(struct record *r);

/*
 * r's lease is current at now on the interface that has hardware address
 * mac and index ifindex: it has not ended, it was not asked for later than
 * now, it is for that interface, and addr_set says the address is set.
 */
bool record_current(const struct record *r, const uint8_t mac[6], unsigned int ifindex, bool addr_set,
    int64_t now);

/* What a dhcpc that starts does with what an earlier one left. */
enum take {
	TAKE_NONE,      /* a new lease */
	TAKE_ADOPT,     /* client_adopt() l with status */
	TAKE_REMEMBER,  /* client_remember() l for mac */
};

struct plan {
	enum take what;
	struct lease l;
	enum lstatus status;
	uint8_t mac[6];
	bool remove;            /* first remove rm's address and subnet route */
	struct lease rm;
};

/*
 * The plan for an interface with hardware address mac and index ifindex,
 * at now. r is its record, or NULL if none parses; addr_set says the
 * interface has r's address. A record is the interface's by its name, and
 * by its hardware address and lease address when the index changed: its
 * lease is then asked for again. first, if not NULL, is the interface's
 * first IPv4 address, with mask first_mask: without a record, it is taken
 * for an earlier dhcpc's, with status L_FOUND.
 */
void plan_takeover(const struct record *r, const uint8_t mac[6], unsigned int ifindex, bool addr_set,
    const struct in_addr *first, struct in_addr first_mask, int64_t now, struct plan *p);

/* The broadcast address of l's address. */
struct in_addr lease_broadcast(const struct lease *l);

/* An address that has mask and broadcast is set as l would set it. */
bool lease_set_as(const struct lease *l, struct in_addr mask, struct in_addr broadcast);

/* A default route: through router on interface name, whose index is ifindex. */
struct droute {
	char name[16];
	unsigned int ifindex;
	struct in_addr router;
};

/* The default routes dhcpc set: none, one, or more while it changes the route. */
#define MARKER_MAX      4

struct marker {
	int n;
	struct droute r[MARKER_MAX];
};

size_t marker_format(char *out, size_t cap, const struct marker *m);
bool marker_parse(const char *text, size_t len, struct marker *m);

/* Add r to m if it is not there: false if m is full. */
bool marker_add(struct marker *m, const struct droute *r);

/*
 * The default route through gw on the interface with index ifindex, named
 * name, is dhcpc's: m lists it. With m NULL, when there is no marker, as
 * at boot or after a soft reboot, a route through an Ethernet interface is
 * taken for an earlier dhcpc's.
 */
bool marker_owns(const struct marker *m, struct in_addr gw, unsigned int ifindex, const char *name);

/*
 * The addresses of a routing message, n bytes at p, which addrs has a bit
 * for each of: each into out[bit], as much of it as fits in 16 bytes, the
 * rest zero. Each address takes its first byte's length in p, rounded up
 * to 4 bytes, and 4 bytes if that is 0; a short last one, as a trimmed
 * mask is, is read too.
 */
#define RT_ADDRS        8

void rt_addrs(const uint8_t *p, size_t n, unsigned int addrs, uint8_t out[RT_ADDRS][16]);

/* The kernel's default route, as RTM_GET found it; r.router is 0 if it has no IPv4 gateway. */
enum probe {
	PROBE_FAILED,
	PROBE_NONE,
	PROBE_FOUND,
};

struct kroute {
	enum probe probe;
	struct droute r;
};

/* An IPv4 address on an interface. */
struct ifaddr4 {
	char name[16];
	struct in_addr addr;
};

/* Some address of the n in set is on an Ethernet interface and is none of the m in covered. */
bool unrecorded_address(const struct ifaddr4 *set, int n, const struct ifaddr4 *covered, int m);

/* What the election does. */
struct eplan {
	bool set;               /* write intent, then set the default route to the winner's */
	struct marker intent;
	bool settle;            /* then, once it is set, the marker lists the winner's route alone */
	bool resolv;            /* resolv.conf from the winner's lease */
	bool clear;             /* resolv.conf without name servers */
	bool remove;            /* delete the kernel's default route; once it is gone, the marker lists none */
	bool none;              /* the marker lists none */
};

/*
 * What the election does with the default route, the marker and
 * resolv.conf. win is the winner's route, or NULL for none; found says an
 * address set without a record is being asked for; unrecorded says an
 * Ethernet interface has an IPv4 address that no current record covers;
 * was is the marker, or NULL if there is none; k is the kernel's default
 * route. The marker always lists every route of dhcpc's that may be set:
 * with no room, or with the kernel's route not known and not listed, the
 * route stays as it is. With no winner, nothing changes while found, or
 * while unrecorded with no marker, as when a worker has yet to record the
 * address it found after a soft reboot; the marker stays if the route
 * cannot be read, and only dhcpc's route goes.
 */
void elect_plan(const struct droute *win, bool found, bool unrecorded, const struct marker *was,
    const struct kroute *k, struct eplan *p);

#endif
