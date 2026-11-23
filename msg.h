/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 The Blueberry Pie OS Authors
 *
 * DHCP messages, without I/O: msg_payload() makes a DISCOVER or REQUEST,
 * msg_build() puts it in an Ethernet frame to broadcast, and msg_parse()
 * reads an OFFER, ACK or NAK from a frame and checks it.
 */

#ifndef DHCPC_MSG_H
#define DHCPC_MSG_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "client.h"

#define MSG_DHCP_MAX    548     /* the longest DHCP message msg_payload() makes */
#define MSG_FRAME_MAX   590     /* with Ethernet, IPv4 and UDP headers */

/*
 * The DHCP message of m from mac into out; host is option 12 if it is
 * shorter than 64 bytes. The broadcast flag is set unless m is unicast.
 * Returns the message's length.
 */
size_t msg_payload(uint8_t out[MSG_DHCP_MAX], const struct csend *m, const uint8_t mac[6], const char *host);

/*
 * m from mac, broadcast: its message in a UDP datagram from port 68 at
 * m->ciaddr to port 67 at 255.255.255.255, in an Ethernet frame, into out.
 * Returns the frame's length.
 */
size_t msg_build(uint8_t out[MSG_FRAME_MAX], const struct csend *m, const uint8_t mac[6], const char *host);

/*
 * Read frame, len bytes, into l: true if it is an OFFER, ACK or NAK for
 * xid and mac, whose headers, checksums and options are whole, and which
 * has the fields RFC 2131 makes mandatory for it. Repeated options are
 * joined as RFC 3396 says: the options field, then file and sname when
 * option 52 says so.
 */
bool msg_parse(const uint8_t *frame, size_t len, uint32_t xid, const uint8_t mac[6], struct lease *l);

#endif
