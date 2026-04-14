#include "ip.h"
#include "icmp.h"
#include "arpcache.h"
#include "rtable.h"
#include "arp.h"
#include "log.h"
#include <stdlib.h>
#include <assert.h>

// ip.c

void ip_forward_packet(u32 ip_dst, char *packet, int len);

void handle_ip_packet(iface_info_t *iface, char *packet, int len)
{
	struct iphdr *ip = packet_to_ip_hdr(packet);
	u32 dst = ntohl(ip->daddr);

	if (dst == iface->ip) {
		if (ip->protocol == IPPROTO_ICMP) {
			struct icmphdr *icmp = (struct icmphdr *)IP_DATA(ip);
			if (icmp->type == ICMP_ECHOREQUEST) {
				icmp_send_packet(packet, len, ICMP_ECHOREPLY, 0);
				free(packet);
				return;
			}
		}

		free(packet);
		return;
	}

	ip_forward_packet(dst, packet, len);
}

void ip_forward_packet(u32 ip_dst, char *packet, int len)
{
	struct iphdr *ip = packet_to_ip_hdr(packet);

	if (ip->ttl <= 1) {
		icmp_send_packet(packet, len, ICMP_TIME_EXCEEDED, ICMP_EXC_TTL);
		free(packet);
		return;
	}

	ip->ttl -= 1;
	ip->checksum = ip_checksum(ip);

	rt_entry_t *entry = longest_prefix_match(ip_dst);
	if (!entry) {
		icmp_send_packet(packet, len, ICMP_DEST_UNREACH, ICMP_NET_UNREACH);
		free(packet);
		return;
	}

	u32 next_hop = entry->gw ? entry->gw : ip_dst;
	iface_send_packet_by_arp(entry->iface, next_hop, packet, len);
}