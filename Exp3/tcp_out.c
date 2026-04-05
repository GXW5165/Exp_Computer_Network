#include "tcp.h"
#include "tcp_sock.h"
#include "tcp_timer.h"
#include "ip.h"
#include "ether.h"

#include "log.h"
#include "list.h"

#include <stdlib.h>
#include <string.h>

static void tcp_init_hdr(struct tcphdr *tcp, u16 sport, u16 dport, u32 seq, u32 ack,
		u8 flags, u16 rwnd)
{
	memset((char *)tcp, 0, TCP_BASE_HDR_SIZE);

	tcp->sport = htons(sport);
	tcp->dport = htons(dport);
	tcp->seq = htonl(seq);
	tcp->ack = htonl(ack);
	tcp->off = TCP_HDR_OFFSET;
	tcp->flags = flags;
	tcp->rwnd = htons(rwnd);
}

void tcp_send_buffer_add_packet(struct tcp_sock *tsk, char *packet, int len)
{
	struct send_buffer_entry *entry = malloc(sizeof(struct send_buffer_entry));
	if (!entry)
		return;

	memset(entry, 0, sizeof(*entry));
	entry->packet = malloc(len);
	if (!entry->packet) {
		free(entry);
		return;
	}

	memcpy(entry->packet, packet, len);
	entry->len = len;

	struct iphdr *ip = packet_to_ip_hdr(entry->packet);
	struct tcphdr *tcp = packet_to_tcp_hdr(entry->packet);
	int pl_len = ntohs(ip->tot_len) - IP_HDR_SIZE(ip) - TCP_HDR_SIZE(tcp);

	entry->seq = ntohl(tcp->seq);
	entry->seq_end = entry->seq + pl_len + ((tcp->flags & (TCP_SYN | TCP_FIN)) ? 1 : 0);

	pthread_mutex_lock(&tsk->send_buf_lock);
	list_add_tail(&entry->list, &tsk->send_buf);
	pthread_mutex_unlock(&tsk->send_buf_lock);
}

int tcp_update_send_buffer(struct tcp_sock *tsk, u32 ack)
{
	int removed = 0;

	pthread_mutex_lock(&tsk->send_buf_lock);

	struct send_buffer_entry *entry, *q;
	list_for_each_entry_safe(entry, q, &tsk->send_buf, list)
	{
		if (less_or_equal_32b(entry->seq_end, ack)) {
			list_delete_entry(&entry->list);
			free(entry->packet);
			free(entry);
			removed++;
		}
	}

	pthread_mutex_unlock(&tsk->send_buf_lock);
	return removed;
}

int tcp_retrans_send_buffer(struct tcp_sock *tsk)
{
	struct send_buffer_entry *entry;
	char *packet;
	int len;

	pthread_mutex_lock(&tsk->send_buf_lock);
	if (list_empty(&tsk->send_buf)) {
		pthread_mutex_unlock(&tsk->send_buf_lock);
		return -1;
	}

	entry = list_entry(tsk->send_buf.next, struct send_buffer_entry, list);
	len = entry->len;
	packet = malloc(len);
	if (!packet) {
		pthread_mutex_unlock(&tsk->send_buf_lock);
		return -1;
	}
	memcpy(packet, entry->packet, len);
	pthread_mutex_unlock(&tsk->send_buf_lock);

	pthread_mutex_lock(&tsk->sk_lock);
	struct iphdr *ip = packet_to_ip_hdr(packet);
	struct tcphdr *tcp = packet_to_tcp_hdr(packet);

	tcp->ack = htonl(tsk->rcv_nxt);
	tcp->rwnd = htons(tsk->rcv_wnd);
	tcp->checksum = tcp_checksum(ip, tcp);
	ip->checksum = ip_checksum(ip);
	pthread_mutex_unlock(&tsk->sk_lock);

	ip_send_packet(packet, len);
	return 0;
}

void tcp_send_probe_packet(struct tcp_sock *tsk)
{
	int pkt_size = ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + TCP_BASE_HDR_SIZE + 1;
	char *packet = calloc(1, pkt_size);
	if (!packet)
		return;

	struct iphdr *ip = packet_to_ip_hdr(packet);
	struct tcphdr *tcp = (struct tcphdr *)((char *)ip + IP_BASE_HDR_SIZE);
	char *payload = (char *)tcp + TCP_BASE_HDR_SIZE;
	payload[0] = 'P';

	ip_init_hdr(ip, tsk->sk_sip, tsk->sk_dip,
		IP_BASE_HDR_SIZE + TCP_BASE_HDR_SIZE + 1, IPPROTO_TCP);
	tcp_init_hdr(tcp, tsk->sk_sport, tsk->sk_dport,
		tsk->snd_una, tsk->rcv_nxt, TCP_ACK, tsk->rcv_wnd);

	tcp->checksum = tcp_checksum(ip, tcp);
	ip->checksum = ip_checksum(ip);
	ip_send_packet(packet, pkt_size);
}

void tcp_send_packet(struct tcp_sock *tsk, char *packet, int len)
{
	struct iphdr *ip = packet_to_ip_hdr(packet);
	struct tcphdr *tcp = (struct tcphdr *)((char *)ip + IP_BASE_HDR_SIZE);

	int ip_tot_len = len - ETHER_HDR_SIZE;
	int tcp_data_len = ip_tot_len - IP_BASE_HDR_SIZE - TCP_BASE_HDR_SIZE;

	ip_init_hdr(ip, tsk->sk_sip, tsk->sk_dip, ip_tot_len, IPPROTO_TCP);
	tcp_init_hdr(tcp, tsk->sk_sport, tsk->sk_dport,
		tsk->snd_nxt, tsk->rcv_nxt, TCP_PSH | TCP_ACK, tsk->rcv_wnd);

	tcp->checksum = tcp_checksum(ip, tcp);
	ip->checksum = ip_checksum(ip);

	tcp_send_buffer_add_packet(tsk, packet, len);
	tcp_set_retrans_timer(tsk);
	tsk->snd_nxt += tcp_data_len;

	ip_send_packet(packet, len);
}

void tcp_send_control_packet(struct tcp_sock *tsk, u8 flags)
{
	int pkt_size = ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + TCP_BASE_HDR_SIZE;
	char *packet = calloc(1, pkt_size);
	if (!packet) {
		log(ERROR, "malloc tcp control packet failed.");
		return;
	}

	struct iphdr *ip = packet_to_ip_hdr(packet);
	struct tcphdr *tcp = (struct tcphdr *)((char *)ip + IP_BASE_HDR_SIZE);

	ip_init_hdr(ip, tsk->sk_sip, tsk->sk_dip,
		IP_BASE_HDR_SIZE + TCP_BASE_HDR_SIZE, IPPROTO_TCP);
	tcp_init_hdr(tcp, tsk->sk_sport, tsk->sk_dport,
		tsk->snd_nxt, tsk->rcv_nxt, flags, tsk->rcv_wnd);

	tcp->checksum = tcp_checksum(ip, tcp);
	ip->checksum = ip_checksum(ip);

	if (flags & (TCP_SYN | TCP_FIN)) {
		tcp_send_buffer_add_packet(tsk, packet, pkt_size);
		tcp_set_retrans_timer(tsk);
		tsk->snd_nxt += 1;
	}

	ip_send_packet(packet, pkt_size);
}

void tcp_send_reset(struct tcp_cb *cb)
{
	int pkt_size = ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + TCP_BASE_HDR_SIZE;
	char *packet = calloc(1, pkt_size);
	if (!packet) {
		log(ERROR, "malloc tcp reset packet failed.");
		return;
	}

	struct iphdr *ip = packet_to_ip_hdr(packet);
	struct tcphdr *tcp = (struct tcphdr *)((char *)ip + IP_BASE_HDR_SIZE);

	ip_init_hdr(ip, cb->daddr, cb->saddr,
		IP_BASE_HDR_SIZE + TCP_BASE_HDR_SIZE, IPPROTO_TCP);
	tcp_init_hdr(tcp, cb->dport, cb->sport,
		0, cb->seq_end, TCP_RST | TCP_ACK, 0);

	tcp->checksum = tcp_checksum(ip, tcp);
	ip->checksum = ip_checksum(ip);
	ip_send_packet(packet, pkt_size);
}