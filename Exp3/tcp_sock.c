#include "tcp.h"
#include "tcp_hash.h"
#include "tcp_sock.h"
#include "tcp_timer.h"
#include "ip.h"
#include "rtable.h"
#include "log.h"

#include <string.h>
#include <stdlib.h>

struct tcp_hash_table tcp_sock_table;
#define tcp_established_sock_table tcp_sock_table.established_table
#define tcp_listen_sock_table tcp_sock_table.listen_table
#define tcp_bind_sock_table tcp_sock_table.bind_table

inline void tcp_set_state(struct tcp_sock *tsk, int state)
{
	log(DEBUG, IP_FMT ":%hu switch state, from %s to %s.",
		HOST_IP_FMT_STR(tsk->sk_sip), tsk->sk_sport,
		tcp_state_str[tsk->state], tcp_state_str[state]);
	tsk->state = state;
}

void init_tcp_stack()
{
	for (int i = 0; i < TCP_HASH_SIZE; i++)
		init_list_head(&tcp_established_sock_table[i]);
	for (int i = 0; i < TCP_HASH_SIZE; i++)
		init_list_head(&tcp_listen_sock_table[i]);
	for (int i = 0; i < TCP_HASH_SIZE; i++)
		init_list_head(&tcp_bind_sock_table[i]);

	pthread_t timer;
	pthread_create(&timer, NULL, tcp_timer_thread, NULL);
}

struct tcp_sock *alloc_tcp_sock()
{
	struct tcp_sock *tsk = malloc(sizeof(struct tcp_sock));
	memset(tsk, 0, sizeof(struct tcp_sock));

	tsk->state = TCP_CLOSED;
	tsk->rcv_wnd = TCP_DEFAULT_WINDOW;
	tsk->cwnd = 0x7f7f7f7f;
	tsk->ssthresh = 0x7f7f7f7f;

	init_list_head(&tsk->hash_list);
	init_list_head(&tsk->bind_hash_list);
	init_list_head(&tsk->list);
	init_list_head(&tsk->listen_queue);
	init_list_head(&tsk->accept_queue);
	init_list_head(&tsk->send_buf);
	init_list_head(&tsk->rcv_ofo_buf);
	init_list_head(&tsk->timewait.list);
	init_list_head(&tsk->retrans_timer.list);
	init_list_head(&tsk->persist_timer.list);

	pthread_mutex_init(&tsk->sk_lock, NULL);
	pthread_mutex_init(&tsk->rcv_buf_lock, NULL);
	pthread_mutex_init(&tsk->send_buf_lock, NULL);

	tsk->rcv_buf = alloc_ring_buffer(tsk->rcv_wnd);
	tsk->wait_connect = alloc_wait_struct();
	tsk->wait_accept = alloc_wait_struct();
	tsk->wait_recv = alloc_wait_struct();
	tsk->wait_send = alloc_wait_struct();

	return tsk;
}

void free_tcp_sock(struct tcp_sock *tsk)
{
	tsk->ref_cnt--;
	if (tsk->ref_cnt > 0)
		return;

	struct send_buffer_entry *s, *sq;
	list_for_each_entry_safe(s, sq, &tsk->send_buf, list)
	{
		list_delete_entry(&s->list);
		free(s->packet);
		free(s);
	}

	struct recv_ofo_buf_entry *r, *rq;
	list_for_each_entry_safe(r, rq, &tsk->rcv_ofo_buf, list)
	{
		list_delete_entry(&r->list);
		free(r->packet);
		free(r);
	}

	if (tsk->rcv_buf)
		free_ring_buffer(tsk->rcv_buf);
	if (tsk->wait_connect)
		free_wait_struct(tsk->wait_connect);
	if (tsk->wait_accept)
		free_wait_struct(tsk->wait_accept);
	if (tsk->wait_recv)
		free_wait_struct(tsk->wait_recv);
	if (tsk->wait_send)
		free_wait_struct(tsk->wait_send);

	pthread_mutex_destroy(&tsk->sk_lock);
	pthread_mutex_destroy(&tsk->rcv_buf_lock);
	pthread_mutex_destroy(&tsk->send_buf_lock);
	free(tsk);
}

struct tcp_sock *tcp_sock_lookup_established(u32 saddr, u32 daddr, u16 sport, u16 dport)
{
	int hash = tcp_hash_function(saddr, daddr, sport, dport);
	struct list_head *list = &tcp_established_sock_table[hash];

	struct tcp_sock *tsk;
	list_for_each_entry(tsk, list, hash_list)
	{
		if (tsk->sk_sip == saddr && tsk->sk_dip == daddr &&
			tsk->sk_sport == sport && tsk->sk_dport == dport)
			return tsk;
	}

	return NULL;
}

struct tcp_sock *tcp_sock_lookup_listen(u32 saddr, u16 sport)
{
	int hash = tcp_hash_function(0, 0, sport, 0);
	struct list_head *list = &tcp_listen_sock_table[hash];

	struct tcp_sock *tsk;
	list_for_each_entry(tsk, list, hash_list)
	{
		if (tsk->sk_sport == sport)
			return tsk;
	}

	return NULL;
}

struct tcp_sock *tcp_sock_lookup(struct tcp_cb *cb)
{
	u32 saddr = cb->daddr, daddr = cb->saddr;
	u16 sport = cb->dport, dport = cb->sport;

	struct tcp_sock *tsk = tcp_sock_lookup_established(saddr, daddr, sport, dport);
	if (!tsk)
		tsk = tcp_sock_lookup_listen(saddr, sport);
	return tsk;
}

static int tcp_bind_hash(struct tcp_sock *tsk)
{
	int bind_hash_value = tcp_hash_function(0, 0, tsk->sk_sport, 0);
	struct list_head *list = &tcp_bind_sock_table[bind_hash_value];
	list_add_head(&tsk->bind_hash_list, list);
	tsk->ref_cnt += 1;
	return 0;
}

void tcp_bind_unhash(struct tcp_sock *tsk)
{
	if (!list_empty(&tsk->bind_hash_list)) {
		list_delete_entry(&tsk->bind_hash_list);
		init_list_head(&tsk->bind_hash_list);
		free_tcp_sock(tsk);
	}
}

static int tcp_port_in_use(u16 sport)
{
	int value = tcp_hash_function(0, 0, sport, 0);
	struct list_head *list = &tcp_bind_sock_table[value];
	struct tcp_sock *tsk;
	list_for_each_entry(tsk, list, bind_hash_list)
	{
		if (tsk->sk_sport == sport)
			return 1;
	}

	return 0;
}

static u16 tcp_get_port()
{
	for (u16 port = PORT_MIN; port < PORT_MAX; port++) {
		if (!tcp_port_in_use(port))
			return port;
	}
	return 0;
}

static int tcp_sock_set_sport(struct tcp_sock *tsk, u16 port)
{
	if ((port && tcp_port_in_use(port)) || (!port && !(port = tcp_get_port())))
		return -1;

	tsk->sk_sport = port;
	tcp_bind_hash(tsk);
	return 0;
}

int tcp_hash(struct tcp_sock *tsk)
{
	struct list_head *list;
	int hash;

	if (tsk->state == TCP_CLOSED)
		return -1;

	if (tsk->state == TCP_LISTEN) {
		hash = tcp_hash_function(0, 0, tsk->sk_sport, 0);
		list = &tcp_listen_sock_table[hash];
	} else {
		hash = tcp_hash_function(tsk->sk_sip, tsk->sk_dip,
					tsk->sk_sport, tsk->sk_dport);
		list = &tcp_established_sock_table[hash];

		struct tcp_sock *tmp;
		list_for_each_entry(tmp, list, hash_list)
		{
			if (tsk->sk_sip == tmp->sk_sip && tsk->sk_dip == tmp->sk_dip &&
				tsk->sk_sport == tmp->sk_sport && tsk->sk_dport == tmp->sk_dport)
				return -1;
		}
	}

	list_add_head(&tsk->hash_list, list);
	tsk->ref_cnt += 1;
	return 0;
}

void tcp_unhash(struct tcp_sock *tsk)
{
	if (!list_empty(&tsk->hash_list)) {
		list_delete_entry(&tsk->hash_list);
		init_list_head(&tsk->hash_list);
		free_tcp_sock(tsk);
	}
}

int tcp_sock_bind(struct tcp_sock *tsk, struct sock_addr *skaddr)
{
	return tcp_sock_set_sport(tsk, ntohs(skaddr->port));
}

int tcp_sock_connect(struct tcp_sock *tsk, struct sock_addr *skaddr)
{
	tsk->sk_dip = ntohl(skaddr->ip);
	tsk->sk_dport = ntohs(skaddr->port);

	if (tcp_sock_set_sport(tsk, 0) < 0)
		return -1;

	rt_entry_t *entry = longest_prefix_match(tsk->sk_dip);
	if (!entry)
		return -1;
	tsk->sk_sip = entry->iface->ip;

	tsk->iss = tcp_new_iss();
	tsk->snd_nxt = tsk->iss;
	tsk->snd_una = tsk->iss;

	tcp_set_state(tsk, TCP_SYN_SENT);
	if (tcp_hash(tsk) < 0)
		return -1;

	pthread_mutex_lock(&tsk->sk_lock);
	tcp_send_control_packet(tsk, TCP_SYN);
	pthread_mutex_unlock(&tsk->sk_lock);

	sleep_on(tsk->wait_connect);
	return tsk->state == TCP_ESTABLISHED ? 0 : -1;
}

int tcp_sock_listen(struct tcp_sock *tsk, int backlog)
{
	tsk->backlog = backlog > TCP_MAX_BACKLOG ? TCP_MAX_BACKLOG : backlog;
	tcp_set_state(tsk, TCP_LISTEN);
	return tcp_hash(tsk);
}

inline int tcp_sock_accept_queue_full(struct tcp_sock *tsk)
{
	if (tsk->accept_backlog >= tsk->backlog) {
		log(ERROR, "tcp accept queue (%d) is full.", tsk->accept_backlog);
		return 1;
	}
	return 0;
}

int tcp_tx_window_test(struct tcp_sock *tsk)
{
	int32_t usable = (int32_t)(tsk->snd_una + tsk->snd_wnd - tsk->snd_nxt);
	return usable >= TCP_MSS;
}

int tcp_sock_read(struct tcp_sock *tsk, char *buf, int len)
{
	while (1) {
		pthread_mutex_lock(&tsk->rcv_buf_lock);
		if (!ring_buffer_empty(tsk->rcv_buf)) {
			int rlen = read_ring_buffer(tsk->rcv_buf, buf, len);
			pthread_mutex_unlock(&tsk->rcv_buf_lock);

			pthread_mutex_lock(&tsk->sk_lock);
			u16 old_wnd = tsk->rcv_wnd;
			tsk->rcv_wnd += rlen;
			if (old_wnd < TCP_MSS && tsk->rcv_wnd >= TCP_MSS)
				tcp_send_control_packet(tsk, TCP_ACK);
			pthread_mutex_unlock(&tsk->sk_lock);
			return rlen;
		}
		pthread_mutex_unlock(&tsk->rcv_buf_lock);

		if (tsk->state == TCP_CLOSE_WAIT || tsk->state == TCP_CLOSED)
			return 0;

		sleep_on(tsk->wait_recv);
	}
}

int tcp_sock_write(struct tcp_sock *tsk, char *buf, int len)
{
	if (tsk->state != TCP_ESTABLISHED && tsk->state != TCP_CLOSE_WAIT)
		return -1;

	int off = 0;
	pthread_mutex_lock(&tsk->sk_lock);

	while (off < len) {
		int chunk = min(TCP_MSS, len - off);
		// 检查窗口：剩余窗口是否至少能发送 chunk 字节
		while ((int32_t)(tsk->snd_una + tsk->snd_wnd - tsk->snd_nxt) < chunk) {
			pthread_mutex_unlock(&tsk->sk_lock);
			sleep_on(tsk->wait_send);
			pthread_mutex_lock(&tsk->sk_lock);
			if (tsk->state != TCP_ESTABLISHED && tsk->state != TCP_CLOSE_WAIT) {
				pthread_mutex_unlock(&tsk->sk_lock);
				return off > 0 ? off : -1;
			}
			chunk = min(TCP_MSS, len - off);
		}

		int pkt_size = ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + TCP_BASE_HDR_SIZE + chunk;
		char *packet = calloc(1, pkt_size);
		if (!packet) {
			pthread_mutex_unlock(&tsk->sk_lock);
			return off > 0 ? off : -1;
		}

		char *payload = packet + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + TCP_BASE_HDR_SIZE;
		memcpy(payload, buf + off, chunk);
		tcp_send_packet(tsk, packet, pkt_size);
		off += chunk;
	}

	pthread_mutex_unlock(&tsk->sk_lock);
	return off;
}
inline void tcp_sock_accept_enqueue(struct tcp_sock *tsk)
{
	if (!list_empty(&tsk->list))
		list_delete_entry(&tsk->list);
	list_add_tail(&tsk->list, &tsk->parent->accept_queue);
	tsk->parent->accept_backlog += 1;
}

inline struct tcp_sock *tcp_sock_accept_dequeue(struct tcp_sock *tsk)
{
	struct tcp_sock *new_tsk = list_entry(tsk->accept_queue.next, struct tcp_sock, list);
	list_delete_entry(&new_tsk->list);
	init_list_head(&new_tsk->list);
	tsk->accept_backlog -= 1;
	return new_tsk;
}

struct tcp_sock *tcp_sock_accept(struct tcp_sock *tsk)
{
	while (list_empty(&tsk->accept_queue))
		sleep_on(tsk->wait_accept);
	return tcp_sock_accept_dequeue(tsk);
}

void tcp_sock_close(struct tcp_sock *tsk)
{
	int release_immediately = 0;

	pthread_mutex_lock(&tsk->sk_lock);
	tcp_unset_persist_timer(tsk);

	if (tsk->state == TCP_ESTABLISHED) {
		tcp_send_control_packet(tsk, TCP_FIN | TCP_ACK);
		tcp_set_state(tsk, TCP_FIN_WAIT_1);
	} else if (tsk->state == TCP_CLOSE_WAIT) {
		tcp_send_control_packet(tsk, TCP_FIN | TCP_ACK);
		tcp_set_state(tsk, TCP_LAST_ACK);
	} else if (tsk->state == TCP_SYN_SENT || tsk->state == TCP_LISTEN) {
		tcp_set_state(tsk, TCP_CLOSED);
		release_immediately = 1;
	}

	pthread_mutex_unlock(&tsk->sk_lock);

	if (release_immediately) {
		tcp_unhash(tsk);
		tcp_bind_unhash(tsk);
	}
}
