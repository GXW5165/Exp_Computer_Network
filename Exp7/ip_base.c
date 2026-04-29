#include "ip.h"
#include "icmp.h"
#include "arpcache.h"
#include "rtable.h"
#include "arp.h"
#include "log.h"
#include <stdlib.h>
#include <assert.h>

// initialize ip header 
void ip_init_hdr(struct iphdr *ip, u32 saddr, u32 daddr, u16 len, u8 proto)
{
	ip->version = 4;
	ip->ihl = 5;
	ip->tos = 0;
	ip->tot_len = htons(len);
	ip->id = rand();
	ip->frag_off = htons(IP_DF);
	ip->ttl = DEFAULT_TTL;
	ip->protocol = proto;
	ip->saddr = htonl(saddr);
	ip->daddr = htonl(daddr);
	ip->checksum = ip_checksum(ip);
}

// ip_base.c

rt_entry_t *longest_prefix_match(u32 dst)
{
	rt_entry_t *entry = NULL;
	rt_entry_t *best = NULL;

	if (list_empty(&rtable))
		return NULL;

	list_for_each_entry(entry, &rtable, list) {
		if ((dst & entry->mask) == (entry->dest & entry->mask)) {
			if (!best || entry->mask > best->mask)
				best = entry;
		}
	}

	return best;
}

void ip_send_packet(char *packet, int len)
{
	struct iphdr *ip = packet_to_ip_hdr(packet);
	u32 dst = ntohl(ip->daddr);

	rt_entry_t *entry = longest_prefix_match(dst);
	if (!entry) {
		free(packet);
		return;
	}

	u32 next_hop = entry->gw ? entry->gw : dst;
	iface_send_packet_by_arp(entry->iface, next_hop, packet, len);
}

void ip_forward_packet(u32 dst, char *packet, int len)
{
	struct iphdr *ip = packet_to_ip_hdr(packet);

	if (ip->ttl <= 1) {
		icmp_send_packet(packet, len, ICMP_TIME_EXCEEDED, ICMP_EXC_TTL);
		free(packet);
		return;
	}

	rt_entry_t *entry = longest_prefix_match(dst);
	if (!entry) {
		icmp_send_packet(packet, len, ICMP_DEST_UNREACH, ICMP_NET_UNREACH);
		free(packet);
		return;
	}

	ip->ttl -= 1;
	ip->checksum = ip_checksum(ip);

	u32 next_hop = entry->gw ? entry->gw : dst;
	iface_send_packet_by_arp(entry->iface, next_hop, packet, len);
}