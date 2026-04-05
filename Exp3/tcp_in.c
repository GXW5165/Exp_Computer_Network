#include "tcp.h"
#include "tcp_sock.h"
#include "tcp_timer.h"

#include "log.h"
#include "ring_buffer.h"

#include <stdlib.h>
#include <string.h>

static inline void tcp_update_window(struct tcp_sock *tsk, struct tcp_cb *cb)
{
	int old_can_send = tcp_tx_window_test(tsk);

	tsk->snd_una = cb->ack;
	tsk->adv_wnd = cb->rwnd;
	tsk->snd_wnd = (tsk->cwnd < (u32)tsk->adv_wnd) ? tsk->cwnd : (u32)tsk->adv_wnd;

	if (tsk->snd_wnd < TCP_MSS)
		tcp_set_persist_timer(tsk);
	else
		tcp_unset_persist_timer(tsk);

	if (!old_can_send && tcp_tx_window_test(tsk))
		wake_up(tsk->wait_send);
}

static inline void tcp_update_window_safe(struct tcp_sock *tsk, struct tcp_cb *cb)
{
	if (less_or_equal_32b(tsk->snd_una, cb->ack) &&
		less_or_equal_32b(cb->ack, tsk->snd_nxt))
		tcp_update_window(tsk, cb);
}

#ifndef max
#define max(x, y) ((x) > (y) ? (x) : (y))
#endif

static inline int is_tcp_seq_valid(struct tcp_sock *tsk, struct tcp_cb *cb)
{
	u32 rcv_end = tsk->rcv_nxt + max(tsk->rcv_wnd, 1);
	if (less_than_32b(cb->seq, rcv_end) &&
		less_or_equal_32b(tsk->rcv_nxt, cb->seq_end))
		return 1;

	log(ERROR, "received packet with invalid seq, drop it.");
	return 0;
}

int tcp_move_recv_ofo_buffer(struct tcp_sock *tsk)
{
	int moved = 0;

	pthread_mutex_lock(&tsk->rcv_buf_lock);
	struct recv_ofo_buf_entry *entry, *q;
	list_for_each_entry_safe(entry, q, &tsk->rcv_ofo_buf, list)
	{
		if (entry->seq != tsk->rcv_nxt)
			break;
		if (ring_buffer_free(tsk->rcv_buf) < entry->pl_len)
			break;

		struct tcphdr *tcp = packet_to_tcp_hdr(entry->packet);
		char *payload = (char *)tcp + TCP_HDR_SIZE(tcp);
		write_ring_buffer(tsk->rcv_buf, payload, entry->pl_len);
		tsk->rcv_nxt = entry->seq_end;
		tsk->rcv_wnd -= entry->pl_len;
		moved += entry->pl_len;

		list_delete_entry(&entry->list);
		free(entry->packet);
		free(entry);
	}
	pthread_mutex_unlock(&tsk->rcv_buf_lock);

	if (moved > 0)
		wake_up(tsk->wait_recv);
	return moved;
}

int tcp_recv_ofo_buffer_add_packet(struct tcp_sock *tsk, struct tcp_cb *cb)
{
	int pkt_len = ETHER_HDR_SIZE + ntohs(cb->ip->tot_len);
	char *pkt = (char *)cb->ip - ETHER_HDR_SIZE;

	struct recv_ofo_buf_entry *entry = malloc(sizeof(struct recv_ofo_buf_entry));
	if (!entry)
		return -1;

	memset(entry, 0, sizeof(*entry));
	entry->packet = malloc(pkt_len);
	if (!entry->packet) {
		free(entry);
		return -1;
	}

	memcpy(entry->packet, pkt, pkt_len);
	entry->len = pkt_len;
	entry->seq = cb->seq;
	entry->seq_end = cb->seq + cb->pl_len;
	entry->pl_len = cb->pl_len;

	struct recv_ofo_buf_entry *pos, *q;
	int inserted = 0;
	list_for_each_entry_safe(pos, q, &tsk->rcv_ofo_buf, list)
	{
		if (less_or_equal_32b(entry->seq_end, pos->seq)) {
			list_insert(&entry->list, pos->list.prev, &pos->list);
			inserted = 1;
			break;
		}
		if (less_or_equal_32b(pos->seq_end, entry->seq))
			continue;

		if (greater_or_equal_32b(entry->seq, pos->seq) &&
			less_or_equal_32b(entry->seq_end, pos->seq_end)) {
			free(entry->packet);
			free(entry);
			return 0;
		}
		if (less_or_equal_32b(entry->seq, pos->seq) &&
			greater_or_equal_32b(entry->seq_end, pos->seq_end)) {
			list_delete_entry(&pos->list);
			free(pos->packet);
			free(pos);
			continue;
		}

		free(entry->packet);
		free(entry);
		return 0;
	}

	if (!inserted)
		list_add_tail(&entry->list, &tsk->rcv_ofo_buf);

	tcp_move_recv_ofo_buffer(tsk);
	return 0;
}

static void tcp_handle_text(struct tcp_sock *tsk, struct tcp_cb *cb)
{
	if (cb->pl_len <= 0)
		return;
	if (!is_tcp_seq_valid(tsk, cb))
		return;

	u32 data_end = cb->seq + cb->pl_len;
	if (less_or_equal_32b(data_end, tsk->rcv_nxt))
		tcp_send_control_packet(tsk, TCP_ACK);
	else {
		tcp_recv_ofo_buffer_add_packet(tsk, cb);
		tcp_send_control_packet(tsk, TCP_ACK);
	}
}

static int tcp_handle_fin_common(struct tcp_sock *tsk, struct tcp_cb *cb)
{
	if (!(cb->flags & TCP_FIN))
		return 0;

	u32 fin_seq = cb->seq + cb->pl_len;
	if (fin_seq != tsk->rcv_nxt)
		return 0;

	tsk->rcv_nxt = fin_seq + 1;
	tcp_send_control_packet(tsk, TCP_ACK);
	return 1;
}

void tcp_process(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet)
{
	if (!tsk) {
		if (!(cb->flags & TCP_RST))
			tcp_send_reset(cb);
		return;
	}

	if (cb->flags & TCP_RST) {
		tcp_set_state(tsk, TCP_CLOSED);
		tcp_unset_retrans_timer(tsk);
		tcp_unset_persist_timer(tsk);
		tcp_unhash(tsk);
		tcp_bind_unhash(tsk);
		return;
	}

	switch (tsk->state) {
	case TCP_LISTEN:
		if ((cb->flags & TCP_SYN) && !tcp_sock_accept_queue_full(tsk)) {
			struct tcp_sock *csk = alloc_tcp_sock();
			csk->parent = tsk;
			csk->sk_sip = cb->daddr;
			csk->sk_dip = cb->saddr;
			csk->sk_sport = cb->dport;
			csk->sk_dport = cb->sport;
			csk->rcv_nxt = cb->seq + 1;
			csk->iss = tcp_new_iss();
			csk->snd_nxt = csk->iss;
			csk->snd_una = csk->iss;
			csk->adv_wnd = cb->rwnd;
			csk->snd_wnd = (csk->cwnd < (u32)csk->adv_wnd) ? csk->cwnd : (u32)csk->adv_wnd;
			if (csk->snd_wnd < TCP_MSS)
				tcp_set_persist_timer(csk);
			tcp_set_state(csk, TCP_SYN_RECV);
			tcp_hash(csk);
			tcp_send_control_packet(csk, TCP_SYN | TCP_ACK);
		}
		break;

	case TCP_SYN_SENT:
		if ((cb->flags & (TCP_SYN | TCP_ACK)) == (TCP_SYN | TCP_ACK) &&
			cb->ack == tsk->snd_nxt) {
			tcp_update_send_buffer(tsk, cb->ack);
			tcp_update_retrans_timer(tsk);
			tsk->rcv_nxt = cb->seq + 1;
			tcp_update_window_safe(tsk, cb);
			tcp_send_control_packet(tsk, TCP_ACK);
			tcp_set_state(tsk, TCP_ESTABLISHED);
			wake_up(tsk->wait_connect);
		}
		break;

	case TCP_SYN_RECV:
		if (cb->flags & TCP_ACK) {
			tcp_update_send_buffer(tsk, cb->ack);
			tcp_update_retrans_timer(tsk);
			tcp_update_window_safe(tsk, cb);
			if (cb->ack == tsk->snd_nxt) {
				tcp_set_state(tsk, TCP_ESTABLISHED);
				tcp_sock_accept_enqueue(tsk);
				wake_up(tsk->parent->wait_accept);
			}
		}
		break;

	case TCP_ESTABLISHED:
		if (cb->flags & TCP_ACK) {
			tcp_update_send_buffer(tsk, cb->ack);
			tcp_update_retrans_timer(tsk);
			tcp_update_window_safe(tsk, cb);
		}
		tcp_handle_text(tsk, cb);
		if (tcp_handle_fin_common(tsk, cb)) {
			tcp_set_state(tsk, TCP_CLOSE_WAIT);
			wake_up(tsk->wait_recv);
		}
		break;

	case TCP_FIN_WAIT_1:
		if (cb->flags & TCP_ACK) {
			tcp_update_send_buffer(tsk, cb->ack);
			tcp_update_retrans_timer(tsk);
			tcp_update_window_safe(tsk, cb);
			if (cb->ack == tsk->snd_nxt)
				tcp_set_state(tsk, TCP_FIN_WAIT_2);
		}
		tcp_handle_text(tsk, cb);
		if (tcp_handle_fin_common(tsk, cb)) {
			if (tsk->state == TCP_FIN_WAIT_2)
				tcp_set_state(tsk, TCP_TIME_WAIT);
			else
				tcp_set_state(tsk, TCP_CLOSING);
			tcp_set_timewait_timer(tsk);
		}
		break;

	case TCP_FIN_WAIT_2:
		if (cb->flags & TCP_ACK)
			tcp_update_window_safe(tsk, cb);
		tcp_handle_text(tsk, cb);
		if (tcp_handle_fin_common(tsk, cb)) {
			tcp_set_state(tsk, TCP_TIME_WAIT);
			tcp_set_timewait_timer(tsk);
		}
		break;

	case TCP_CLOSING:
		if (cb->flags & TCP_ACK) {
			tcp_update_send_buffer(tsk, cb->ack);
			tcp_update_retrans_timer(tsk);
			tcp_update_window_safe(tsk, cb);
			if (cb->ack == tsk->snd_nxt) {
				tcp_set_state(tsk, TCP_TIME_WAIT);
				tcp_set_timewait_timer(tsk);
			}
		}
		break;

	case TCP_CLOSE_WAIT:
		if (cb->flags & TCP_ACK) {
			tcp_update_send_buffer(tsk, cb->ack);
			tcp_update_retrans_timer(tsk);
			tcp_update_window_safe(tsk, cb);
		}
		break;

	case TCP_LAST_ACK:
		if (cb->flags & TCP_ACK) {
			tcp_update_send_buffer(tsk, cb->ack);
			tcp_update_retrans_timer(tsk);
			tcp_update_window_safe(tsk, cb);
			if (cb->ack == tsk->snd_nxt) {
				tcp_set_state(tsk, TCP_CLOSED);
				tcp_unset_persist_timer(tsk);
				tcp_unhash(tsk);
				tcp_bind_unhash(tsk);
			}
		}
		break;

	case TCP_TIME_WAIT:
		if (cb->flags & TCP_FIN) {
			u32 fin_seq = cb->seq + cb->pl_len;
			if (fin_seq == tsk->rcv_nxt - 1) {
				tcp_send_control_packet(tsk, TCP_ACK);
				tcp_set_timewait_timer(tsk);
			}
		}
		break;

	default:
		break;
	}
}
