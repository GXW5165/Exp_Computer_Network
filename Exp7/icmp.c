#include "icmp.h"
#include "ip.h"
#include "rtable.h"
#include "arp.h"
#include "base.h"
#include "log.h"
#include <stdlib.h>
#include <assert.h>

// icmp.c

void icmp_send_packet(const char *in_pkt, int len, u8 type, u8 code)
{
	struct iphdr *old_ip = packet_to_ip_hdr(in_pkt);
	u32 src_ip = ntohl(old_ip->saddr);
	u32 dst_ip = ntohl(old_ip->daddr);

	if (type == ICMP_ECHOREPLY) {
		int old_ip_len = IP_HDR_SIZE(old_ip);
		int icmp_len = ntohs(old_ip->tot_len) - old_ip_len;
		int pkt_len = ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + icmp_len;
		char *packet = malloc(pkt_len);
		bzero(packet, pkt_len);

		struct iphdr *ip = packet_to_ip_hdr(packet);
		ip_init_hdr(ip, dst_ip, src_ip, IP_BASE_HDR_SIZE + icmp_len, IPPROTO_ICMP);

		struct icmphdr *icmp = (struct icmphdr *)IP_DATA(ip);
		memcpy(icmp, (char *)old_ip + old_ip_len, icmp_len);
		icmp->type = type;
		icmp->code = code;
		icmp->checksum = icmp_checksum(icmp, icmp_len);

		ip_send_packet(packet, pkt_len);
		return;
	}

	rt_entry_t *entry = longest_prefix_match(src_ip);
	if (!entry)
		return;

	int copied_len = IP_HDR_SIZE(old_ip) + ICMP_COPIED_DATA_LEN;
	int old_tot_len = ntohs(old_ip->tot_len);
	if (copied_len > old_tot_len)
		copied_len = old_tot_len;

	int icmp_len = ICMP_HDR_SIZE + copied_len;
	int pkt_len = ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + icmp_len;
	char *packet = malloc(pkt_len);
	bzero(packet, pkt_len);

	struct iphdr *ip = packet_to_ip_hdr(packet);
	ip_init_hdr(ip, entry->iface->ip, src_ip, IP_BASE_HDR_SIZE + icmp_len, IPPROTO_ICMP);

	struct icmphdr *icmp = (struct icmphdr *)IP_DATA(ip);
	icmp->type = type;
	icmp->code = code;
	icmp->icmp_identifier = 0;
	icmp->icmp_sequence = 0;
	memcpy((char *)icmp + ICMP_HDR_SIZE, old_ip, copied_len);
	icmp->checksum = icmp_checksum(icmp, icmp_len);

	ip_send_packet(packet, pkt_len);
}
