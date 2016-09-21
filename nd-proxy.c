/**
 * @file nd-proxy.c
 *
 * Copyright 2016, Allied Telesis Labs New Zealand, Ltd
 *
 *                               +---------+
 *                          If A |         | If B
 *             A-----------------|  PROXY  |-----------------B
 *                               |         |
 *                               +---------+
 *         IPv6: A      IPv6: PA            IPv6: PB      IPv6: B
 *         L2: a        L2: pa              L2: pb        L2: b
 *
 * RS/RA proxy
 *                                   RS
 *                         -------------------->
 *     L3src=A, L3dst=AllR                   L3src=A,  L3dst=AllR
 *     L2src=a, L2dst=allr, SLL=a            L2src=pb, L2dst=allr, SLL=pb
 *
 *                                   RA
 *                         <--------------------
 *     L3src=B,  L3dst=AllN                  L3src=B, L3dst=AllN
 *     L2src=pa, L2dst=alln, SLL=pa          L2src=b, L2dst=alln, SLL=b
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <syslog.h>
#include <glib.h>
#include <glib-unix.h>

#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/ether.h>
#include <netpacket/packet.h>

#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/poll.h>

#include <linux/filter.h>

/* Mode */
#define PROXY_RS    (1 << 0)
#define PROXY_RA    (1 << 1)
#define PROXY_NS    (1 << 2)
#define PROXY_NA    (1 << 3)
#define PROXY_RD    (1 << 4)

/* Debug macros */
#define DEBUG(fmt, args...) if (debug) printf (fmt, ## args)
#define ERROR(fmt, args...) \
{ \
	syslog(LOG_ERR, fmt, ## args); \
	fprintf(stderr, fmt, ## args); \
}

/* Proxy interface */
typedef struct _iface_t {
	char *name;
	uint32_t flags;
	int ifindex;
	uint8_t hwaddr[ETH_ALEN];
	int fd;
	guint src;
} iface_t;

/* Globals */
static bool debug = false;
static GList *ifaces = NULL;

/* Find the specified option in the ICMPv6 message */
static struct nd_opt_hdr *
find_option(struct icmp6_hdr *icmp6_hdr, int len, uint8_t type)
{
	struct nd_opt_hdr *nd_opt;
	int icmp_hlen;

	/* Each ND type has a different offest to the options */
	switch (icmp6_hdr->icmp6_type) {
	case ND_ROUTER_SOLICIT:
		icmp_hlen = sizeof(struct nd_router_solicit);
		break;
	case ND_ROUTER_ADVERT:
		icmp_hlen = sizeof(struct nd_router_advert);
		break;
	case ND_NEIGHBOR_SOLICIT:
		icmp_hlen = sizeof(struct nd_neighbor_solicit);
		break;
	case ND_NEIGHBOR_ADVERT:
		icmp_hlen = sizeof(struct nd_neighbor_advert);
		break;
	case ND_REDIRECT:
		icmp_hlen = sizeof(struct nd_redirect);
		break;
	default:
		return NULL;
	}

	/* Find the option */
	nd_opt = (struct nd_opt_hdr *)((uint8_t *)icmp6_hdr + icmp_hlen);
	len -= icmp_hlen;
	while (len > 0) {
		int opt_len = nd_opt->nd_opt_len * 8;
		if (nd_opt->nd_opt_type == type)
			return nd_opt;
		nd_opt = (struct nd_opt_hdr *)((uint8_t *)nd_opt +
					sizeof(struct nd_opt_hdr) + opt_len);
		len -= (sizeof(struct nd_opt_hdr) + opt_len);
	}
	return NULL;
}

/* Update the SLLA option in the packet (and checksum) */
static void
update_slla_option(struct icmp6_hdr *icmp6_hdr, int len, uint8_t *mac)
{
	struct nd_opt_hdr *nd_opt;

	/* Find the "source link-layer address" option */
	nd_opt = find_option(icmp6_hdr, len, ND_OPT_SOURCE_LINKADDR);

	/* Update the slla if we found it */
	if (nd_opt) {
		/* Option data is the mac address - it is always 16-bit aligned */
		uint8_t *slla = (uint8_t *)nd_opt + sizeof(struct nd_opt_hdr);

		/* Update ICMPv6 header checksum based on the old and new mac adddress */
		uint16_t *omac = (uint16_t *)slla;
		uint16_t *nmac = (uint16_t *)mac;
		int i;
		for (i = 0; i < ETH_ALEN / 2; i++) {
			uint16_t hc_complement = ~ntohs(icmp6_hdr->icmp6_cksum);
			uint16_t m_complement = ~ntohs(omac[i]);
			uint16_t m_prime = ntohs(nmac[i]);
			uint32_t sum = hc_complement + m_complement + m_prime;
			while (sum >> 16) {
				sum = (sum & 0xffff) + (sum >> 16);
			}
			icmp6_hdr->icmp6_cksum = htons(~((uint16_t)sum));
		}

		/* Copy the outgoing interface's hw addr into the
		 * "source link-layer address" option in the pkt. */
		memcpy(slla, mac, ETH_ALEN);
	}
}

/* Proxying of both RS and RA */
static void
proxy_rsra(iface_t *iface, uint8_t *msg, int len)
{
	struct ether_header *eth_hdr;
	struct ip6_hdr *ip6;
	struct icmp6_hdr *icmp6_hdr;
	struct sockaddr_ll socket_address;

	/* Parse the packet */
	eth_hdr = (struct ether_header *)msg;
	ip6 = (struct ip6_hdr *)(msg + sizeof(struct ether_header));
	icmp6_hdr = (struct icmp6_hdr *)(msg + sizeof(struct ether_header) +
				sizeof(struct ip6_hdr));

	DEBUG("Tx(%s): %s\n", iface->name,
			icmp6_hdr->icmp6_type == ND_ROUTER_SOLICIT ?
					"ND_ROUTER_SOLICIT" : "ND_ROUTER_ADVERT");

	/* Avoid proxying spoofed packets */
	if (IN6_IS_ADDR_MULTICAST(&ip6->ip6_src)) {
		DEBUG("Tx(%s): Ignoring RS/RA from spoofed address\n", iface->name);
		return;
	}

	/* RS should be sent to "All Routers Address" FF02::2 */
	/* RA should be sent to "All Nodes Address" FF02::1 */
	/* Can only proxy to multicast L2 destinations 33:33:.. */
	if (!IN6_IS_ADDR_MULTICAST(&ip6->ip6_dst) ||
		(eth_hdr->ether_dhost[0] != 0x33 && eth_hdr->ether_dhost[1] != 0x33)) {
		DEBUG("Tx(%s): Ignoring RS/RA to non-multicast address\n", iface->name);
		return;
	}

	/* Copy the outgoing interface's hw addr into the
	 * "source link-layer address" option in the pkt */
	update_slla_option(icmp6_hdr, len - ((uint8_t *)icmp6_hdr - msg), iface->hwaddr);

	/* Copy the outgoing interface's hw addr into the
	 * MAC source address in the pkt. */
	memcpy((uint8_t *)(eth_hdr->ether_shost), iface->hwaddr, ETH_ALEN);

	/* Send the packet */
	socket_address.sll_ifindex = iface->ifindex;
	socket_address.sll_halen = ETH_ALEN;
	memcpy((uint8_t *)socket_address.sll_addr, iface->hwaddr, ETH_ALEN);
	if (sendto (iface->fd, msg, len, 0, (struct sockaddr *)&socket_address,
			sizeof(struct sockaddr_ll)) < 0) {
		ERROR("Tx(%s): Failed to send packet\n", iface->name);
		return;
	}
}

static gboolean
handle_fd(gint fd, GIOCondition condition, gpointer data)
{
	iface_t *iface = (iface_t *)data;
	struct msghdr mhdr;
	struct iovec iov;
	struct sockaddr_ll t_saddr;
	uint8_t msg[4096];
	int size = 4096;
	int len;

	/* Receive a packet */
	iov.iov_len = size;
	iov.iov_base = (caddr_t)msg;
	memset(&mhdr, 0, sizeof(mhdr));
	mhdr.msg_name = (caddr_t)&t_saddr;
	mhdr.msg_namelen = sizeof(struct sockaddr);
	mhdr.msg_iov = &iov;
	mhdr.msg_iovlen = 1;
	if ((len = recvmsg(fd, &mhdr, 0)) < 0) {
		ERROR("Rx(%s):Interface has gone away\n", iface->name);
		exit(-1);
	}

	/* Check we have at least the icmp header */
	if ((size_t) len < (ETH_HLEN + sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr))) {
		ERROR("Rx(%s): Ignoring short packet (%d bytes)\n", iface->name, len);
		return true;
	}

	struct icmp6_hdr *icmp6_hdr = (struct icmp6_hdr *)(msg + ETH_HLEN + sizeof(struct ip6_hdr));
	uint8_t icmp6_type = icmp6_hdr->icmp6_type;
	switch (icmp6_type) {
	case ND_ROUTER_SOLICIT:
		DEBUG("Rx(%s): ND_ROUTER_SOLICIT\n", iface->name);
		if (iface->flags & PROXY_RS) {
			GList *iter;
			for (iter = ifaces; iter; iter = g_list_next(iter)) {
				iface_t *oiface = (iface_t *)iter->data;
				if (oiface != iface)
					proxy_rsra(oiface, msg, len);
			}
		}
		break;
	case ND_ROUTER_ADVERT:
		DEBUG("Rx(%s): ND_ROUTER_ADVERT\n", iface->name);
		if (iface->flags & PROXY_RA) {
			GList *iter;
			for (iter = ifaces; iter; iter = g_list_next(iter)) {
				iface_t *oiface = (iface_t *)iter->data;
				if (oiface != iface)
					proxy_rsra(oiface, msg, len);
			}
		}
		break;
	case ND_NEIGHBOR_SOLICIT:
	case ND_NEIGHBOR_ADVERT:
	case ND_REDIRECT:
	default:
		DEBUG("Rx(%s): ignoring ICMPv6 packets of type %d\n", iface->name, icmp6_type);
		break;
	}

	return true;
}

static char *flags_to_string(uint32_t flags)
{
	static char sbuffer[256];
	sbuffer[0] = '\0';
	if (flags == 0)
		sprintf(sbuffer, "no packets");
	if (flags & PROXY_NS)
		sprintf(sbuffer + strlen(sbuffer), "%sNS",
			strlen(sbuffer) ? "," : "");
	if (flags & PROXY_NA)
		sprintf(sbuffer + strlen(sbuffer), "%sNA",
			strlen(sbuffer) ? "," : "");
	if (flags & PROXY_RS)
		sprintf(sbuffer + strlen(sbuffer), "%sRS",
			strlen(sbuffer) ? "," : "");
	if (flags & PROXY_RA)
		sprintf(sbuffer + strlen(sbuffer), "%sRA",
			strlen(sbuffer) ? "," : "");
	if (flags & PROXY_RD)
		sprintf(sbuffer + strlen(sbuffer), "%sRD",
			strlen(sbuffer) ? "," : "");
	return sbuffer;
}

static struct sock_filter bpf_filter[] = {
	/* Load the ether_type. */
	BPF_STMT(BPF_LD | BPF_H | BPF_ABS,
		 offsetof(struct ether_header, ether_type)),
	/* Bail if it's* not* ETHERTYPE_IPV6. */
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ETHERTYPE_IPV6, 0, 9),
	/* Load the next header type. */
	BPF_STMT(BPF_LD | BPF_B | BPF_ABS,
		 sizeof(struct ether_header) + offsetof(struct ip6_hdr,
							ip6_nxt)),
	/* Bail if it's* not* IPPROTO_ICMPV6. */
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, IPPROTO_ICMPV6, 0, 7),
	/* Load the ICMPv6 type. */
	BPF_STMT(BPF_LD | BPF_B | BPF_ABS,
		 sizeof(struct ether_header) + sizeof(struct ip6_hdr) +
		 offsetof(struct icmp6_hdr, icmp6_type)),
	/* Bail if it's* not* ND */
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ND_ROUTER_SOLICIT, 4, 0),
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ND_ROUTER_ADVERT, 3, 0),
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ND_NEIGHBOR_SOLICIT, 2, 0),
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ND_NEIGHBOR_ADVERT, 1, 0),
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ND_REDIRECT, 0, 1),
	/* Keep packet. */
	BPF_STMT(BPF_RET | BPF_K, (u_int32_t)-1),
	/* Drop packet. */
	BPF_STMT(BPF_RET | BPF_K, 0)
};

static void iface_open(gpointer data, gpointer user)
{
	iface_t *iface = (iface_t *)data;
	struct sockaddr_ll lladdr;
	struct sock_fprog fprog;
	struct ifreq ifr;
	int on = 1;
	int fd;

	DEBUG("Open(%s): %s\n", iface->name, flags_to_string(iface->flags));

	/* Check the interface exists by getting its ifindex */
	iface->ifindex = if_nametoindex(iface->name);
	if (!iface->ifindex) {
		ERROR("Open(%s): Could not find interface\n", iface->name);
		exit(-1);
	}

	/* Create raw socket for tx/rx of IPv6 packets */
	if ((fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IPV6))) < 0) {
		ERROR("Open(%s): Unable to create socket\n", iface->name);
		exit(-1);
	}

	/* Bind the socket to the specified interface */
	memset(&lladdr, 0, sizeof(struct sockaddr_ll));
	lladdr.sll_family = AF_PACKET;
	lladdr.sll_protocol = htons(ETH_P_IPV6);
	lladdr.sll_ifindex = iface->ifindex;
	if (bind(fd, (struct sockaddr *)&lladdr, sizeof(struct sockaddr_ll)) < 0) {
		close(fd);
		ERROR("Open(%s): Failed to bind to interface\n", iface->name);
		exit(-1);
	}

	/* Set the socket non-blocking */
	if (ioctl(fd, FIONBIO, (char *)&on) < 0) {
		close(fd);
		ERROR("Open(%s): Failed to make interface non-blocking\n", iface->name);
		exit(-1);
	}

	/* Setup a filter to only receive ND packets */
	fprog.len = sizeof(bpf_filter) / sizeof(bpf_filter[0]);
	fprog.filter = bpf_filter;
	if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &fprog, sizeof(fprog)) < 0) {
		close(fd);
		ERROR("Open(%s): Failed to set filter for ND packets\n", iface->name);
		exit(-1);
	}

	/* Enable all multicast for this interface */
	memset(&ifr, 0, sizeof(struct ifreq));
	strncpy(ifr.ifr_name, iface->name, IFNAMSIZ - 1);
	if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) {
		close(fd);
		ERROR("Open(%s): Failed to get flags for interface\n", iface->name);
		exit(-1);
	}
	ifr.ifr_flags |= IFF_ALLMULTI;
	if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0) {
		close(fd);
		ERROR("Open(%s): Failed to set flags for interface\n", iface->name);
		exit(-1);
	}

	/* Get the hwaddr of the interface */
	memset(&ifr, 0, sizeof(struct ifreq));
	strncpy(ifr.ifr_name, iface->name, IFNAMSIZ - 1);
	if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
		ERROR("Open(%s): Failed to get interface hwaddr\n", iface->name);
		exit(-1);
	}
	memcpy(iface->hwaddr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

	/* Watch for packets */
	iface->fd = fd;
	iface->src = g_unix_fd_add(fd, G_IO_IN, handle_fd, iface);
}

static void iface_close(gpointer data)
{
	iface_t *iface = (iface_t *)data;
	DEBUG("Close(%s)\n", iface->name);
	g_source_remove(iface->src);
	close(iface->fd);
	free(iface->name);
	free(iface);
}

static iface_t *parse_interface(char *desc)
{
	char *name = NULL;
	uint32_t flags = PROXY_RS | PROXY_RA;
	char *pflags = strchr(desc, ':');

	if (pflags) {
		char *token = strtok(pflags + 1, ",");
		flags = 0;
		while (token != NULL) {
			if (strcmp("NS", token) == 0)
				flags |= PROXY_NS;
			else if (strcmp("NA", token) == 0)
				flags |= PROXY_NA;
			else if (strcmp("RA", token) == 0)
				flags |= PROXY_RA;
			else if (strcmp("RS", token) == 0)
				flags |= PROXY_RS;
			else if (strcmp("RD", token) == 0)
				flags |= PROXY_RD;
			else
				return NULL;
			token = strtok(NULL, ",");
		}
		name = strndup(desc, pflags - desc);
	} else {
		name = strdup(desc);
	}
	iface_t *iface = (iface_t *)g_malloc0(sizeof(iface_t));
	iface->name = name;
	iface->flags = flags;
	iface->fd = -1;
	iface->src = 0;
	return iface;
}

static gboolean termination_handler(gpointer arg1)
{
	GMainLoop *loop = (GMainLoop *) arg1;
	g_main_loop_quit(loop);
	return false;
}

void help(char *app_name)
{
	printf("Usage: %s [-h] [-b] [-d] -i <interface>[:<type>[,<type>]..]\n"
	       "  -h   show this help\n"
	       "  -b   background mode\n"
	       "  -d   enable verbose debug\n"
	       "  -i   proxy [NS,NA,RS,RA,RD] messages received on <interface>\n"
	       "\n" "e.g %s -i eth1:RS -i eth2:RA\n", app_name, app_name);
}

int main(int argc, char *argv[])
{
	int i = 0;
	bool background = false;
	GMainLoop *loop = NULL;

	/* Parse options */
	while ((i = getopt(argc, argv, "hdbi:")) != -1) {
		switch (i) {
		case 'd':
			debug = true;
			background = false;
			break;
		case 'b':
			background = true;
			break;
		case 'i':
			{
				iface_t *iface = parse_interface(optarg);
				if (!iface) {
					help(argv[0]);
					ERROR("ERROR: Invalid interface specification (%s)\n", optarg);
					return 0;
				}
				ifaces = g_list_prepend(ifaces, iface);
				break;
			}
		case '?':
		case 'h':
		default:
			help(argv[0]);
			return 0;
		}
	}

	/* Check required */
	if (g_list_length(ifaces) < 2) {
		help(argv[0]);
		ERROR("ERROR: Require at least 2 interfaces.\n");
		return 0;
	}

	/* Daemonize */
	if (background && fork() != 0) {
		/* Parent */
		return 0;
	}

	/* Main loop instance */
	loop = g_main_loop_new(NULL, true);

	/* Handle SIGTERM/SIGINT/SIGPIPE gracefully */
	g_unix_signal_add(SIGINT, termination_handler, loop);
	g_unix_signal_add(SIGTERM, termination_handler, loop);

	/* Startup */
	g_list_foreach(ifaces, iface_open, NULL);

	/* Loop while not terminated */
	g_main_loop_run(loop);

	/* Shutdown */
	g_list_free_full(ifaces, iface_close);

	/* Free the glib main loop */
	if (loop)
		g_main_loop_unref(loop);

	return 0;
}
