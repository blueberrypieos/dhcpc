/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 The Blueberry Pie OS Authors
 *
 * The DHCP client of one interface, without I/O: the caller passes in the
 * interface's arrival and departure, its link, the replies and the time,
 * and the client asks for what it needs through struct cops. Times are
 * milliseconds since the system started.
 */

#ifndef DHCPC_CLIENT_H
#define DHCPC_CLIENT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <netinet/in.h>

enum {
	DHCPDISCOVER = 1, DHCPOFFER, DHCPREQUEST, DHCPDECLINE, DHCPACK, DHCPNAK, DHCPRELEASE,
};

/* How long INIT-REBOOT asks before it gives up: REQUESTs at 0, 2 and 6 s. */
#define REBOOT_WAIT_S   14

/* What a DHCPOFFER, DHCPACK or DHCPNAK says. sent: when the request it answers went out. */
struct lease {
	int type;
	struct in_addr addr, mask, router, server, broadcast;
	struct in_addr dns[3];
	int ndns;
	char domain[256];
	uint32_t lease, t1, t2;
	int64_t sent;
};

/* Whether a server confirmed a lease whose address is set. */
enum lstatus {
	L_CONFIRMED,    /* since the interface or its link came */
	L_CHECKING,     /* asked for again with INIT-REBOOT */
	L_HELD,         /* no answer: kept until a new lease binds or it ends */
	L_FOUND,        /* set without a record: asked for with INIT-REBOOT for REBOOT_WAIT_S at most */
};

enum cstate {
	C_GONE,         /* the interface is not there */
	C_WAITLINK,     /* it came; waiting a while for its link */
	C_INIT,         /* DISCOVER sent, waiting for an offer */
	C_REQUESTING,   /* REQUEST for an offer sent */
	C_REBOOTING,    /* INIT-REBOOT: REQUEST for the remembered address sent */
	C_BOUND,
	C_RENEWING,     /* after T1: REQUEST with ciaddr, refused only by the lease's server */
	C_REBINDING,    /* after T2: refused by any server */
};

/*
 * A message to send. reqip is option 50, server option 54; 0 leaves them
 * out. unicast sends it to the server dst from ciaddr, else it is
 * broadcast.
 */
struct csend {
	int type;
	uint32_t xid;
	uint16_t secs;
	struct in_addr ciaddr, reqip, server;
	bool unicast;
	struct in_addr dst;
};

struct cops {
	void (*up)(void *ctx);
	bool (*link)(void *ctx);        /* the link is up, or the driver reports none */
	void (*open)(void *ctx);
	void (*close)(void *ctx);
	void (*send)(void *ctx, const struct csend *m);
	/*
	 * Set l's address and routes; old, if not NULL, is the lease whose
	 * address is set. False if l's address is not set: old's address then
	 * stays if it is l's, else it goes.
	 */
	bool (*apply)(void *ctx, const struct lease *old, const struct lease *l);
	/* l's address stays without a confirmation, as s says. */
	void (*hold)(void *ctx, const struct lease *l, enum lstatus s);
	void (*drop)(void *ctx, const struct lease *l);   /* remove l's address and its routes */
	/* The interface went; l, if not NULL, is the lease whose address was set. */
	void (*gone)(void *ctx, const struct lease *l);
	void (*log)(void *ctx, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
	uint32_t (*xid)(void *ctx);
};

struct client {
	const struct cops *ops;
	void *ctx;
	enum cstate state;
	bool link;
	uint8_t mac[6];
	bool have;              /* cur is a lease that has not ended */
	struct lease cur;
	uint8_t cur_mac[6];     /* the hardware address cur is for */
	bool addr_on;           /* cur's address is on the interface */
	enum lstatus status;    /* cur's, while its address is on */
	bool bound_once;
	struct in_addr hint;    /* asked for in DISCOVERs */
	struct lease offer;
	uint32_t xid;
	uint16_t secs;          /* the last DISCOVER's, which its REQUEST has too */
	uint32_t gen;           /* counts the arrivals; a reply is for one of them */
	int wait, timeout;      /* the current wait and the next one, ms */
	int sends;              /* sends in this exchange, or this burst when renewing */
	int refusals;
	int64_t start, next, sent;
};

void client_init(struct client *c, const struct cops *ops, void *ctx);
void client_attach(struct client *c, const uint8_t mac[6], int64_t now);
void client_detach(struct client *c, int64_t now);
void client_link(struct client *c, bool up, int64_t now);
void client_reply(struct client *c, const struct lease *r, uint32_t gen, int64_t now);
void client_adopt(struct client *c, const struct lease *l, const uint8_t mac[6], enum lstatus s,
    int64_t now);
void client_remember(struct client *c, const struct lease *l, const uint8_t mac[6]);
void client_timer(struct client *c, int64_t now);
int64_t client_next(const struct client *c);

int64_t lease_renew(const struct lease *l);
int64_t lease_rebind(const struct lease *l);
int64_t lease_end(const struct lease *l);

/* An interface the default route could go through. */
struct candidate {
	long unit;
	bool router, connected, confirmed;
};

int elect_choose(const struct candidate *c, int n);

/*
 * /var/run/resolv.conf's text for interface name's lease l, or with l
 * NULL for no lease, into out. Returns its length, cap or more if it did
 * not fit.
 */
size_t resolv_text(char *out, size_t cap, const char *name, const struct lease *l);

/* s, len bytes, is a domain name: up to 255 letters, digits, hyphens, dots and underscores. */
bool domain_ok(const char *s, size_t len);

#endif
