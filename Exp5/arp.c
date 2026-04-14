#include "arp.h"
#include "base.h"
#include "types.h"
#include "ether.h"
#include "arpcache.h"
#include "log.h"
#include <stdlib.h>
#include <string.h>
#include <assert.h>

void arp_send_reply(iface_info_t *iface, struct ether_arp *req_hdr);

void handle_arp_packet(iface_info_t *iface, char *packet, int len)
{
	struct ether_arp *arp = packet_to_ether_arp(packet);
	u32 target_ip = ntohl(arp->arp_tpa);
	if (target_ip != iface->ip) {
		free(packet);
		return;
	}

	u32 sender_ip = ntohl(arp->arp_spa);
	arpcache_insert(sender_ip, arp->arp_sha);

	u16 op = ntohs(arp->arp_op);
	if (op == ARPOP_REQUEST)
		arp_send_reply(iface, arp);

	free(packet);
}

void arp_send_reply(iface_info_t *iface, struct ether_arp *req_hdr)
{
	int len = ETHER_HDR_SIZE + sizeof(struct ether_arp);
	char *packet = malloc(len);
	bzero(packet, len);

	struct ether_header *eh = (struct ether_header *)packet;
	memcpy(eh->ether_dhost, req_hdr->arp_sha, ETH_ALEN);
	memcpy(eh->ether_shost, iface->mac, ETH_ALEN);
	eh->ether_type = htons(ETH_P_ARP);

	struct ether_arp *arp = packet_to_ether_arp(packet);
	arp->arp_hrd = htons(ARPHRD_ETHER);
	arp->arp_pro = htons(ETH_P_IP);
	arp->arp_hln = ETH_ALEN;
	arp->arp_pln = 4;
	arp->arp_op = htons(ARPOP_REPLY);
	memcpy(arp->arp_sha, iface->mac, ETH_ALEN);
	arp->arp_spa = htonl(iface->ip);
	memcpy(arp->arp_tha, req_hdr->arp_sha, ETH_ALEN);
	arp->arp_tpa = req_hdr->arp_spa;

	iface_send_packet(iface, packet, len);
}

void arp_send_request(iface_info_t *iface, u32 dst_ip)
{
	int len = ETHER_HDR_SIZE + sizeof(struct ether_arp);
	char *packet = malloc(len);
	bzero(packet, len);

	struct ether_header *eh = (struct ether_header *)packet;
	memset(eh->ether_dhost, 0xff, ETH_ALEN);
	memcpy(eh->ether_shost, iface->mac, ETH_ALEN);
	eh->ether_type = htons(ETH_P_ARP);

	struct ether_arp *arp = packet_to_ether_arp(packet);
	arp->arp_hrd = htons(ARPHRD_ETHER);
	arp->arp_pro = htons(ETH_P_IP);
	arp->arp_hln = ETH_ALEN;
	arp->arp_pln = 4;
	arp->arp_op = htons(ARPOP_REQUEST);
	memcpy(arp->arp_sha, iface->mac, ETH_ALEN);
	arp->arp_spa = htonl(iface->ip);
	memset(arp->arp_tha, 0x00, ETH_ALEN);
	arp->arp_tpa = htonl(dst_ip);

	iface_send_packet(iface, packet, len);
}

void iface_send_packet_by_arp(iface_info_t *iface, u32 dst_ip, char *packet, int len)
{
	u8 mac[ETH_ALEN];

	if (arpcache_lookup(dst_ip, mac)) {
		struct ether_header *eh = (struct ether_header *)packet;
		memcpy(eh->ether_dhost, mac, ETH_ALEN);
		memcpy(eh->ether_shost, iface->mac, ETH_ALEN);
		eh->ether_type = htons(ETH_P_IP);
		iface_send_packet(iface, packet, len);
	} else {
		arpcache_append_packet(iface, dst_ip, packet, len);
	}
}
