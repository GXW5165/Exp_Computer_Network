#include "ip.h"
#include "tcp.h"
#include "tcp_sock.h"

#include "log.h"

#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>

const char *tcp_state_str[] = {
	"CLOSED", "LISTEN", "SYN_RECV", "SYN_SENT", "ESTABLISHED",
	"CLOSE_WAIT", "LAST_ACK", "FIN_WAIT-1", "FIN_WAIT-2",
	"CLOSING", "TIME_WAIT",
};

u32 tcp_new_iss()
{
	return (u32)rand();
}

static int copy_flag_str(u8 flags, int flag, char *buf, int start,
		const char *str, int len)
{
	if (flags & flag) {
		strcpy(buf + start, str);
		return len;
	}

	return 0;
}

void tcp_copy_flags_to_str(u8 flags, char buf[])
{
	int len = 0;
	memset(buf, 0, 32);

	len += copy_flag_str(flags, TCP_FIN, buf, len, "FIN|", 4);
	len += copy_flag_str(flags, TCP_SYN, buf, len, "SYN|", 4);
	len += copy_flag_str(flags, TCP_RST, buf, len, "RST|", 4);
	len += copy_flag_str(flags, TCP_PSH, buf, len, "PSH|", 4);
	len += copy_flag_str(flags, TCP_ACK, buf, len, "ACK|", 4);
	len += copy_flag_str(flags, TCP_URG, buf, len, "URG|", 4);

	if (len != 0)
		buf[len - 1] = '\0';
}

void tcp_cb_init(struct iphdr *ip, struct tcphdr *tcp, struct tcp_cb *cb)
{
	int len = ntohs(ip->tot_len) - IP_HDR_SIZE(ip) - TCP_HDR_SIZE(tcp);

	cb->saddr = ntohl(ip->saddr);
	cb->daddr = ntohl(ip->daddr);
	cb->sport = ntohs(tcp->sport);
	cb->dport = ntohs(tcp->dport);
	cb->seq = ntohl(tcp->seq);
	cb->seq_end = cb->seq + len + ((tcp->flags & (TCP_SYN | TCP_FIN)) ? 1 : 0);
	cb->ack = ntohl(tcp->ack);
	cb->rwnd = ntohs(tcp->rwnd);
	cb->flags = tcp->flags;
	cb->ip = ip;
	cb->tcp = tcp;
	cb->payload = (char *)tcp + TCP_HDR_SIZE(tcp);
	cb->pl_len = len;
}

void handle_tcp_packet(char *packet, struct iphdr *ip, struct tcphdr *tcp)
{
	if (tcp_checksum(ip, tcp) != tcp->checksum) {
		log(ERROR, "received tcp packet with invalid checksum, drop it.");
		return;
	}

	struct tcp_cb cb;
	tcp_cb_init(ip, tcp, &cb);

	struct tcp_sock *tsk = tcp_sock_lookup(&cb);
	if (tsk) {
		tsk->ref_cnt += 1;
		pthread_mutex_lock(&tsk->sk_lock);
	}

	tcp_process(tsk, &cb, packet);

	if (tsk) {
		pthread_mutex_unlock(&tsk->sk_lock);
		free_tcp_sock(tsk);
	}
}
