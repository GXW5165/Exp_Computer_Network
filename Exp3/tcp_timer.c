#include "tcp.h"
#include "tcp_timer.h"
#include "tcp_sock.h"

#include <stdio.h>
#include <unistd.h>
#include <pthread.h>

static struct list_head timer_list = { &timer_list, &timer_list };
pthread_mutex_t timer_list_lock = PTHREAD_MUTEX_INITIALIZER;

static void tcp_handle_retrans_timeout(struct tcp_sock *tsk)
{
	pthread_mutex_lock(&tsk->sk_lock);

	if (tsk->state == TCP_CLOSED) {
		pthread_mutex_unlock(&tsk->sk_lock);
		tcp_unset_retrans_timer(tsk);
		return;
	}

	if (tsk->retrans_timer.retrans_count >= TCP_RETRANS_MAX_RETRIES) {
		tcp_send_control_packet(tsk, TCP_RST | TCP_ACK);
		tcp_set_state(tsk, TCP_CLOSED);
		pthread_mutex_unlock(&tsk->sk_lock);

		tcp_unset_retrans_timer(tsk);
		tcp_unset_persist_timer(tsk);

		wake_up(tsk->wait_connect);
		wake_up(tsk->wait_accept);
		wake_up(tsk->wait_recv);
		wake_up(tsk->wait_send);

		tcp_unhash(tsk);
		tcp_bind_unhash(tsk);
		return;
	}

	pthread_mutex_unlock(&tsk->sk_lock);

	if (tcp_retrans_send_buffer(tsk) < 0) {
		tcp_unset_retrans_timer(tsk);
		return;
	}

	pthread_mutex_lock(&timer_list_lock);
	if (tsk->retrans_timer.enable) {
		tsk->retrans_timer.retrans_count++;
		tsk->retrans_timer.timeout =
			TCP_RETRANS_INTERVAL_INITIAL << tsk->retrans_timer.retrans_count;
	}
	pthread_mutex_unlock(&timer_list_lock);
}

static void tcp_handle_persist_timeout(struct tcp_sock *tsk)
{
	pthread_mutex_lock(&tsk->sk_lock);

	if (tsk->state == TCP_CLOSED) {
		pthread_mutex_unlock(&tsk->sk_lock);
		tcp_unset_persist_timer(tsk);
		return;
	}

	if (tsk->snd_wnd < TCP_MSS) {
		tcp_send_probe_packet(tsk);

		pthread_mutex_lock(&timer_list_lock);
		if (tsk->persist_timer.enable)
			tsk->persist_timer.timeout = TCP_PERSIST_INTERVAL_INITIAL;
		pthread_mutex_unlock(&timer_list_lock);

		pthread_mutex_unlock(&tsk->sk_lock);
		return;
	}

	pthread_mutex_unlock(&tsk->sk_lock);
	tcp_unset_persist_timer(tsk);
}

void tcp_scan_timer_list()
{
	struct tcp_sock *timewait_expired[128];
	struct tcp_sock *retrans_expired[128];
	struct tcp_sock *persist_expired[128];
	int tw_cnt = 0, rt_cnt = 0, pt_cnt = 0;

	pthread_mutex_lock(&timer_list_lock);

	struct tcp_timer *timer, *q;
	list_for_each_entry_safe(timer, q, &timer_list, list)
	{
		timer->timeout -= TCP_TIMER_SCAN_INTERVAL;

		if (timer->timeout > 0)
			continue;

		if (timer->type == TCP_TIMER_TYPE_TIMEWAIT) {
			list_delete_entry(&timer->list);
			init_list_head(&timer->list);
			timer->enable = 0;
			timewait_expired[tw_cnt++] = timewait_to_tcp_sock(timer);
		}
		else if (timer->type == TCP_TIMER_TYPE_RETRANS) {
			retrans_expired[rt_cnt++] = retranstimer_to_tcp_sock(timer);
		}
		else if (timer->type == TCP_TIMER_TYPE_PERSIST) {
			persist_expired[pt_cnt++] = persisttimer_to_tcp_sock(timer);
		}
	}

	pthread_mutex_unlock(&timer_list_lock);

	for (int i = 0; i < tw_cnt; i++) {
		struct tcp_sock *tsk = timewait_expired[i];
		tcp_unhash(tsk);
		tcp_bind_unhash(tsk);
	}

	for (int i = 0; i < rt_cnt; i++)
		tcp_handle_retrans_timeout(retrans_expired[i]);

	for (int i = 0; i < pt_cnt; i++)
		tcp_handle_persist_timeout(persist_expired[i]);
}

void tcp_set_timewait_timer(struct tcp_sock *tsk)
{
	pthread_mutex_lock(&timer_list_lock);

	if (tsk->timewait.enable) {
		tsk->timewait.timeout = TCP_TIMEWAIT_TIMEOUT;
		pthread_mutex_unlock(&timer_list_lock);
		return;
	}

	tsk->timewait.type = TCP_TIMER_TYPE_TIMEWAIT;
	tsk->timewait.timeout = TCP_TIMEWAIT_TIMEOUT;
	tsk->timewait.enable = 1;
	tsk->timewait.retrans_count = 0;

	list_add_tail(&tsk->timewait.list, &timer_list);

	pthread_mutex_unlock(&timer_list_lock);
}

void tcp_set_retrans_timer(struct tcp_sock *tsk)
{
	pthread_mutex_lock(&timer_list_lock);

	if (tsk->retrans_timer.enable) {
		tsk->retrans_timer.timeout =
			TCP_RETRANS_INTERVAL_INITIAL << tsk->retrans_timer.retrans_count;
		pthread_mutex_unlock(&timer_list_lock);
		return;
	}

	tsk->retrans_timer.type = TCP_TIMER_TYPE_RETRANS;
	tsk->retrans_timer.timeout = TCP_RETRANS_INTERVAL_INITIAL;
	tsk->retrans_timer.enable = 1;
	tsk->retrans_timer.retrans_count = 0;

	list_add_tail(&tsk->retrans_timer.list, &timer_list);
	tsk->ref_cnt += 1;

	pthread_mutex_unlock(&timer_list_lock);
}

void tcp_unset_retrans_timer(struct tcp_sock *tsk)
{
	pthread_mutex_lock(&timer_list_lock);

	if (!tsk->retrans_timer.enable) {
		pthread_mutex_unlock(&timer_list_lock);
		return;
	}

	tsk->retrans_timer.enable = 0;
	list_delete_entry(&tsk->retrans_timer.list);
	init_list_head(&tsk->retrans_timer.list);

	pthread_mutex_unlock(&timer_list_lock);

	free_tcp_sock(tsk);
}

void tcp_update_retrans_timer(struct tcp_sock *tsk)
{
	pthread_mutex_lock(&timer_list_lock);

	if (!tsk->retrans_timer.enable) {
		pthread_mutex_unlock(&timer_list_lock);
		return;
	}

	pthread_mutex_lock(&tsk->send_buf_lock);
	int empty = list_empty(&tsk->send_buf);
	pthread_mutex_unlock(&tsk->send_buf_lock);

	if (empty) {
		pthread_mutex_unlock(&timer_list_lock);
		tcp_unset_retrans_timer(tsk);
		wake_up(tsk->wait_send);
		return;
	}

	tsk->retrans_timer.timeout = TCP_RETRANS_INTERVAL_INITIAL;
	tsk->retrans_timer.retrans_count = 0;

	pthread_mutex_unlock(&timer_list_lock);
}

void tcp_set_persist_timer(struct tcp_sock *tsk)
{
	pthread_mutex_lock(&timer_list_lock);

	if (tsk->persist_timer.enable) {
		pthread_mutex_unlock(&timer_list_lock);
		return;
	}

	tsk->persist_timer.type = TCP_TIMER_TYPE_PERSIST;
	tsk->persist_timer.timeout = TCP_PERSIST_INTERVAL_INITIAL;
	tsk->persist_timer.enable = 1;
	tsk->persist_timer.retrans_count = 0;

	list_add_tail(&tsk->persist_timer.list, &timer_list);
	tsk->ref_cnt += 1;

	pthread_mutex_unlock(&timer_list_lock);
}

void tcp_unset_persist_timer(struct tcp_sock *tsk)
{
	pthread_mutex_lock(&timer_list_lock);

	if (!tsk->persist_timer.enable) {
		pthread_mutex_unlock(&timer_list_lock);
		return;
	}

	tsk->persist_timer.enable = 0;
	list_delete_entry(&tsk->persist_timer.list);
	init_list_head(&tsk->persist_timer.list);

	pthread_mutex_unlock(&timer_list_lock);

	free_tcp_sock(tsk);
}

void *tcp_timer_thread(void *arg)
{
	while (1)
	{
		usleep(TCP_TIMER_SCAN_INTERVAL);
		tcp_scan_timer_list();
	}

	return NULL;
}
