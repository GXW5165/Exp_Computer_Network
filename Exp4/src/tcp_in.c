#include "tcp.h"
#include "tcp_sock.h"
#include "tcp_timer.h"

#include "ring_buffer.h"

#include <stdlib.h>
#include <string.h>
#ifndef max
#define max(x, y) ((x) > (y) ? (x) : (y))
#endif

static inline u32 tcp_cc_flight_size(struct tcp_sock *tsk)
{
	return tsk->snd_nxt - tsk->snd_una;
}

static inline void tcp_refresh_send_window(struct tcp_sock *tsk)
{
	tsk->snd_wnd = min(tsk->cwnd, (u32)tsk->adv_wnd);

	if (tsk->adv_wnd == 0)
		tcp_set_persist_timer(tsk);
	else
		tcp_unset_persist_timer(tsk);
}

static inline void tcp_update_window(struct tcp_sock *tsk, struct tcp_cb *cb)
{
	tsk->snd_una = cb->ack;
	tsk->adv_wnd = cb->rwnd;
	tcp_refresh_send_window(tsk);

	wake_up(tsk->wait_send);
}

static inline void tcp_update_window_safe(struct tcp_sock *tsk, struct tcp_cb *cb)
{
	if (less_or_equal_32b(tsk->snd_una, cb->ack) &&
		less_or_equal_32b(cb->ack, tsk->snd_nxt))
		tcp_update_window(tsk, cb);
}

static inline int tcp_handle_ack(struct tcp_sock *tsk, struct tcp_cb *cb)
{
	if (less_than_32b(cb->ack, tsk->snd_una) ||
		greater_than_32b(cb->ack, tsk->snd_nxt))
		return 0;

	tcp_update_window_safe(tsk, cb);

	int removed = tcp_update_send_buffer(tsk, cb->ack);
	if (removed > 0)
		tcp_update_retrans_timer(tsk);

	return removed;
}

static inline void tcp_cc_on_new_ack(struct tcp_sock *tsk, struct tcp_cb *cb)
{
	if (tsk->c_state == TCP_CC_RECOVERY) {
		if (greater_or_equal_32b(cb->ack, tsk->recovery_point)) {
			tsk->cwnd = max(tsk->ssthresh, (u32)TCP_MSS);
			tsk->dup_ack_cnt = 0;
			tsk->c_state = TCP_CC_OPEN;
			tcp_refresh_send_window(tsk);
			return;
		} else {
			tsk->cwnd = tsk->ssthresh + TCP_MSS;
			tcp_refresh_send_window(tsk);
			tcp_retrans_send_buffer(tsk);
			return;
		}
	}

	tsk->dup_ack_cnt = 0;
	tsk->c_state = TCP_CC_OPEN;

	if (tsk->cwnd < tsk->ssthresh)
		tsk->cwnd += TCP_MSS;
	else
		tsk->cwnd += max((u32)1,
			((u32)TCP_MSS * (u32)TCP_MSS) / max(tsk->cwnd, (u32)1));

	tcp_refresh_send_window(tsk);
}

static inline void tcp_cc_on_dup_ack(struct tcp_sock *tsk)
{
	tsk->dup_ack_cnt++;

	if (tsk->c_state == TCP_CC_RECOVERY) {
		tsk->cwnd += TCP_MSS;
		tcp_refresh_send_window(tsk);
		return;
	}

	if (tsk->dup_ack_cnt < 3) {
		tsk->c_state = TCP_CC_DISORDER;
		tcp_refresh_send_window(tsk);
		return;
	}

	u32 flight = tcp_cc_flight_size(tsk);
	tsk->ssthresh = max(flight / 2, (u32)(2 * TCP_MSS));
	tsk->cwnd = tsk->ssthresh + 3 * TCP_MSS;
	tsk->recovery_point = tsk->snd_nxt;
	tsk->c_state = TCP_CC_RECOVERY;

	tcp_refresh_send_window(tsk);
	tcp_retrans_send_buffer(tsk);
}

static inline int is_tcp_seq_valid(struct tcp_sock *tsk, struct tcp_cb *cb)
{
	u32 rcv_end = tsk->rcv_nxt + max(tsk->rcv_wnd, 1);

	if (less_than_32b(cb->seq, rcv_end) &&
		less_or_equal_32b(tsk->rcv_nxt, cb->seq_end))
		return 1;

	return 0;
}

static inline void tcp_ack_now(struct tcp_sock *tsk)
{
	tcp_send_control_packet(tsk, TCP_ACK);
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

		if (tsk->rcv_wnd < entry->pl_len)
			break;

		struct tcphdr *tcp = packet_to_tcp_hdr(entry->packet);
		char *payload = (char *)tcp + TCP_HDR_SIZE(tcp);

		write_ring_buffer(tsk->rcv_buf, payload, entry->pl_len);

		tsk->rcv_wnd -= entry->pl_len;

		tsk->rcv_nxt = entry->seq_end;

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

static int tcp_ofo_insert_piece(struct tcp_cb *cb, u32 piece_seq, u32 piece_end,
				struct list_head *prev, struct list_head *next)
{
	int pl_len = (int)(piece_end - piece_seq);
	int hdr_len = ETHER_HDR_SIZE + IP_HDR_SIZE(cb->ip) + TCP_HDR_SIZE(cb->tcp);
	char *orig_pkt = (char *)cb->ip - ETHER_HDR_SIZE;
	int payload_off = (int)(piece_seq - cb->seq);

	struct recv_ofo_buf_entry *entry = malloc(sizeof(struct recv_ofo_buf_entry));
	if (!entry)
		return -1;

	memset(entry, 0, sizeof(*entry));
	init_list_head(&entry->list);

	entry->packet = malloc(hdr_len + pl_len);
	if (!entry->packet) {
		free(entry);
		return -1;
	}

	memcpy(entry->packet, orig_pkt, hdr_len);
	memcpy(entry->packet + hdr_len, cb->payload + payload_off, pl_len);

	struct iphdr *ip = packet_to_ip_hdr(entry->packet);
	struct tcphdr *tcp = packet_to_tcp_hdr(entry->packet);

	ip->tot_len = htons(IP_HDR_SIZE(ip) + TCP_HDR_SIZE(tcp) + pl_len);
	tcp->seq = htonl(piece_seq);

	entry->len = hdr_len + pl_len;
	entry->seq = piece_seq;
	entry->seq_end = piece_end;
	entry->pl_len = pl_len;

	list_insert(&entry->list, prev, next);
	return 0;
}

int tcp_recv_ofo_buffer_add_packet(struct tcp_sock *tsk, struct tcp_cb *cb)
{
	if (cb->pl_len <= 0)
		return 0;

	u32 seg_start = cb->seq;
	u32 seg_end = cb->seq + cb->pl_len;

	pthread_mutex_lock(&tsk->rcv_buf_lock);

	u32 wnd_end = tsk->rcv_nxt + max(tsk->rcv_wnd, 1);

	if (less_or_equal_32b(seg_end, tsk->rcv_nxt)) {
		pthread_mutex_unlock(&tsk->rcv_buf_lock);
		return 0;
	}

	if (less_than_32b(seg_start, tsk->rcv_nxt))
		seg_start = tsk->rcv_nxt;

	if (!less_than_32b(seg_start, wnd_end)) {
		pthread_mutex_unlock(&tsk->rcv_buf_lock);
		return 0;
	}

	if (greater_than_32b(seg_end, wnd_end))
		seg_end = wnd_end;

	if (!less_than_32b(seg_start, seg_end)) {
		pthread_mutex_unlock(&tsk->rcv_buf_lock);
		return 0;
	}

	u32 cur = seg_start;
	struct list_head *iter = tsk->rcv_ofo_buf.next;

	while (iter != &tsk->rcv_ofo_buf) {
		struct recv_ofo_buf_entry *pos =
			list_entry(iter, struct recv_ofo_buf_entry, list);

		if (less_or_equal_32b(pos->seq_end, cur)) {
			iter = iter->next;
			continue;
		}

		if (less_or_equal_32b(seg_end, pos->seq))
			break;

		if (less_than_32b(cur, pos->seq)) {
			if (tcp_ofo_insert_piece(cb, cur, pos->seq, pos->list.prev, &pos->list) < 0) {
				pthread_mutex_unlock(&tsk->rcv_buf_lock);
				return -1;
			}
		}

		if (less_or_equal_32b(seg_end, pos->seq_end)) {
			cur = seg_end;
			break;
		}

		cur = pos->seq_end;
		iter = pos->list.next;
	}

	if (less_than_32b(cur, seg_end)) {
		if (tcp_ofo_insert_piece(cb, cur, seg_end, iter->prev, iter) < 0) {
			pthread_mutex_unlock(&tsk->rcv_buf_lock);
			return -1;
		}
	}

	pthread_mutex_unlock(&tsk->rcv_buf_lock);

	tcp_move_recv_ofo_buffer(tsk);
	return 0;
}

static void tcp_process_text(struct tcp_sock *tsk, struct tcp_cb *cb)
{
	u32 data_end = cb->seq + cb->pl_len;

	if (cb->pl_len <= 0)
		return;

	if (!is_tcp_seq_valid(tsk, cb)) {
		tcp_ack_now(tsk);
		return;
	}

	if (less_or_equal_32b(data_end, tsk->rcv_nxt)) {
		tcp_ack_now(tsk);
		return;
	}

	tcp_recv_ofo_buffer_add_packet(tsk, cb);
	tcp_ack_now(tsk);
}

static int tcp_process_fin(struct tcp_sock *tsk, struct tcp_cb *cb)
{
	if (!(cb->flags & TCP_FIN))
		return 0;

	u32 fin_seq = cb->seq + cb->pl_len;

	if (fin_seq == tsk->rcv_nxt) {
		tsk->rcv_nxt = fin_seq + 1;
		tcp_ack_now(tsk);
		return 1;
	}

	tcp_ack_now(tsk);
	return 0;
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

	switch (tsk->state)
	{
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
			tcp_refresh_send_window(csk);

			tcp_set_state(csk, TCP_SYN_RECV);
			tcp_hash(csk);
			tcp_send_control_packet(csk, TCP_SYN | TCP_ACK);
		}
		break;

	case TCP_SYN_SENT:
		if ((cb->flags & (TCP_SYN | TCP_ACK)) == (TCP_SYN | TCP_ACK) &&
			cb->ack == tsk->snd_nxt)
		{
			tcp_handle_ack(tsk, cb);

			tsk->rcv_nxt = cb->seq + 1;
			tcp_send_control_packet(tsk, TCP_ACK);
			tcp_set_state(tsk, TCP_ESTABLISHED);

			wake_up(tsk->wait_connect);
		}
		break;

	case TCP_SYN_RECV:
		if ((cb->flags & TCP_ACK) && cb->ack == tsk->snd_nxt)
		{
			tcp_handle_ack(tsk, cb);

			tcp_set_state(tsk, TCP_ESTABLISHED);
			tcp_sock_accept_enqueue(tsk);
			wake_up(tsk->parent->wait_accept);
		}
		break;

	case TCP_ESTABLISHED:
	if (cb->flags & TCP_ACK) {
		u32 old_una = tsk->snd_una;
		u16 old_wnd = tsk->adv_wnd;

		int ack_valid = !less_than_32b(cb->ack, old_una) &&
		                !greater_than_32b(cb->ack, tsk->snd_nxt);

		int pure_ack = (cb->pl_len == 0) &&
		               !(cb->flags & (TCP_SYN | TCP_FIN));

		tcp_handle_ack(tsk, cb);

		if (ack_valid) {
			if (greater_than_32b(cb->ack, old_una)) {
				tcp_cc_on_new_ack(tsk, cb);
			} else if (pure_ack &&
			           cb->ack == old_una &&
			           cb->rwnd == old_wnd &&
			           less_than_32b(old_una, tsk->snd_nxt)) {
				tcp_cc_on_dup_ack(tsk);
			}
		}
	}

	tcp_process_text(tsk, cb);

	if (tcp_process_fin(tsk, cb)) {
		tcp_set_state(tsk, TCP_CLOSE_WAIT);
		wake_up(tsk->wait_recv);
	}
	break;

	case TCP_FIN_WAIT_1:
		if (cb->flags & TCP_ACK) {
			tcp_handle_ack(tsk, cb);

			if (cb->ack == tsk->snd_nxt)
				tcp_set_state(tsk, TCP_FIN_WAIT_2);
		}

		tcp_process_text(tsk, cb);

		if (tcp_process_fin(tsk, cb)) {
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

		tcp_process_text(tsk, cb);

		if (tcp_process_fin(tsk, cb)) {
			tcp_set_state(tsk, TCP_TIME_WAIT);
			tcp_set_timewait_timer(tsk);
		}
		break;

	case TCP_CLOSING:
		if (cb->flags & TCP_ACK) {
			tcp_handle_ack(tsk, cb);

			if (cb->ack == tsk->snd_nxt) {
				tcp_set_state(tsk, TCP_TIME_WAIT);
				tcp_set_timewait_timer(tsk);
			}
		}

		tcp_process_text(tsk, cb);
		break;

	case TCP_CLOSE_WAIT:
		if (cb->flags & TCP_ACK)
			tcp_handle_ack(tsk, cb);

		tcp_process_text(tsk, cb);
		if (cb->flags & TCP_FIN)
			tcp_ack_now(tsk);
		break;

	case TCP_LAST_ACK:
		if (cb->flags & TCP_ACK) {
			tcp_handle_ack(tsk, cb);

			if (cb->ack == tsk->snd_nxt) {
				tcp_set_state(tsk, TCP_CLOSED);
				tcp_unset_persist_timer(tsk);
				tcp_unhash(tsk);
				tcp_bind_unhash(tsk);
			}
		}

		tcp_process_text(tsk, cb);
		if (cb->flags & TCP_FIN)
			tcp_ack_now(tsk);
		break;

	case TCP_TIME_WAIT:
		tcp_process_text(tsk, cb);

		if (cb->flags & TCP_FIN) {
			tcp_ack_now(tsk);
			tcp_set_timewait_timer(tsk);
		}
		break;

	default:
		break;
	}
}