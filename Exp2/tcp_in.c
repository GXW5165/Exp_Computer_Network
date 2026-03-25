#include "tcp.h"
#include "tcp_sock.h"
#include "tcp_timer.h"

#include "log.h"
#include "ring_buffer.h"

#include <stdlib.h>
// update the snd_wnd of tcp_sock
//
// if the snd_wnd before updating is zero, notify tcp_sock_send (wait_send)
static inline void tcp_update_window(struct tcp_sock *tsk, struct tcp_cb *cb)
{
	u16 old_snd_wnd = tsk->snd_wnd;
	tsk->snd_wnd = cb->rwnd;
	if (old_snd_wnd == 0)
		wake_up(tsk->wait_send);
}

// update the snd_wnd safely: cb->ack should be between snd_una and snd_nxt
static inline void tcp_update_window_safe(struct tcp_sock *tsk, struct tcp_cb *cb)
{
	if (less_or_equal_32b(tsk->snd_una, cb->ack) && less_or_equal_32b(cb->ack, tsk->snd_nxt))
		tcp_update_window(tsk, cb);
}

#ifndef max
#define max(x, y) ((x) > (y) ? (x) : (y))
#endif

// check whether the sequence number of the incoming packet is in the receiving
// window
static inline int is_tcp_seq_valid(struct tcp_sock *tsk, struct tcp_cb *cb)
{
	u32 rcv_end = tsk->rcv_nxt + max(tsk->rcv_wnd, 1);
	if (less_than_32b(cb->seq, rcv_end) && less_or_equal_32b(tsk->rcv_nxt, cb->seq_end))
	{
		return 1;
	}
	else
	{
		log(ERROR, "received packet with invalid seq, drop it.");
		return 0;
	}
}

// Process the incoming packet according to TCP state machine.
void tcp_process(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet)
{
	// no matched socket
	if (!tsk)
	{
		if (!(cb->flags & TCP_RST))
			tcp_send_reset(cb);
		return;
	}

	// ignore reset for this lab's minimal implementation
	if (cb->flags & TCP_RST)
	{
		tcp_set_state(tsk, TCP_CLOSED);
		tcp_unhash(tsk);
		return;
	}

	switch (tsk->state)
	{

	case TCP_LISTEN:
		// passive open: receive SYN, create child socket
		if (cb->flags & TCP_SYN)
		{
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

			tcp_set_state(csk, TCP_SYN_RECV);
			tcp_hash(csk);

			tcp_send_control_packet(csk, TCP_SYN | TCP_ACK);
		}
		break;

	case TCP_SYN_SENT:
		// active open: receive SYN+ACK
		if ((cb->flags & (TCP_SYN | TCP_ACK)) == (TCP_SYN | TCP_ACK))
		{
			tsk->rcv_nxt = cb->seq + 1;
			tsk->snd_una = cb->ack;

			tcp_send_control_packet(tsk, TCP_ACK);
			tcp_set_state(tsk, TCP_ESTABLISHED);

			wake_up(tsk->wait_connect);
		}
		break;

	case TCP_SYN_RECV:
		// receive the third handshake ACK
		if (cb->flags & TCP_ACK)
		{
			tsk->snd_una = cb->ack;
			tcp_set_state(tsk, TCP_ESTABLISHED);

			tcp_sock_accept_enqueue(tsk);
			wake_up(tsk->parent->wait_accept);
		}
		break;

	case TCP_ESTABLISHED:
		// 1. process ACK
		if (cb->flags & TCP_ACK)
		{
			tcp_update_window_safe(tsk, cb);
			tsk->snd_una = cb->ack;
		}

		// 2. process payload
		if (cb->pl_len > 0)
		{
			if (is_tcp_seq_valid(tsk, cb))
			{
				if (cb->seq == tsk->rcv_nxt)
				{
					if (ring_buffer_free(tsk->rcv_buf) >= cb->pl_len)
					{
						write_ring_buffer(tsk->rcv_buf, cb->payload, cb->pl_len);
						tsk->rcv_nxt = cb->seq_end;
						tsk->rcv_wnd -= cb->pl_len;

						tcp_send_control_packet(tsk, TCP_ACK);
						wake_up(tsk->wait_recv);
					}
					else
					{
						// no enough recv window, just ACK current rcv_nxt
						tcp_send_control_packet(tsk, TCP_ACK);
					}
				}
				else
				{
					// out-of-order packet: for this lab, no reordering buffer logic
					tcp_send_control_packet(tsk, TCP_ACK);
				}
			}
		}

		// 3. process FIN
		if (cb->flags & TCP_FIN)
		{
			tsk->rcv_nxt = cb->seq + 1;
			tcp_send_control_packet(tsk, TCP_ACK);
			tcp_set_state(tsk, TCP_CLOSE_WAIT);
			wake_up(tsk->wait_recv);
		}
		break;

	case TCP_FIN_WAIT_1:
		// our FIN has been ACKed
		if (cb->flags & TCP_ACK)
		{
			tcp_update_window_safe(tsk, cb);
			tsk->snd_una = cb->ack;
			tcp_set_state(tsk, TCP_FIN_WAIT_2);
		}

		// peer also sends FIN (possible FIN|ACK merged)
		if (cb->flags & TCP_FIN)
		{
			tsk->rcv_nxt = cb->seq + 1;
			tcp_send_control_packet(tsk, TCP_ACK);
			tcp_set_state(tsk, TCP_TIME_WAIT);
			tcp_set_timewait_timer(tsk);
		}
		break;

	case TCP_FIN_WAIT_2:
		if (cb->flags & TCP_ACK)
		{
			tcp_update_window_safe(tsk, cb);
			tsk->snd_una = cb->ack;
		}

		if (cb->flags & TCP_FIN)
		{
			tsk->rcv_nxt = cb->seq + 1;
			tcp_send_control_packet(tsk, TCP_ACK);
			tcp_set_state(tsk, TCP_TIME_WAIT);
			tcp_set_timewait_timer(tsk);
		}
		break;

	case TCP_CLOSE_WAIT:
		// passive closer can still receive ACK/data in a fuller implementation
		if (cb->flags & TCP_ACK)
		{
			tcp_update_window_safe(tsk, cb);
			tsk->snd_una = cb->ack;
		}
		break;

	case TCP_LAST_ACK:
		if (cb->flags & TCP_ACK)
		{
			tcp_update_window_safe(tsk, cb);
			tsk->snd_una = cb->ack;
			tcp_set_state(tsk, TCP_CLOSED);
			tcp_unhash(tsk);
		}
		break;

	case TCP_TIME_WAIT:
		// if duplicate FIN arrives, ACK again
		if (cb->flags & TCP_FIN)
		{
			tsk->rcv_nxt = cb->seq + 1;
			tcp_send_control_packet(tsk, TCP_ACK);
		}
		break;

	default:
		break;
	}
}