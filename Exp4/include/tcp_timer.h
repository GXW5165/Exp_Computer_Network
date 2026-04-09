#ifndef __TCP_TIMER_H__
#define __TCP_TIMER_H__

#include "list.h"

#include <stddef.h>

#define TCP_TIMER_TYPE_TIMEWAIT 0
#define TCP_TIMER_TYPE_RETRANS  1
#define TCP_TIMER_TYPE_PERSIST  2

struct tcp_timer {
	int type;
	int timeout;	// in micro second
	struct list_head list;
	int enable;
	int retrans_count;
};

struct tcp_sock;
#define timewait_to_tcp_sock(t) \
	(struct tcp_sock *)((char *)(t) - offsetof(struct tcp_sock, timewait))

#define retranstimer_to_tcp_sock(t) \
	(struct tcp_sock *)((char *)(t) - offsetof(struct tcp_sock, retrans_timer))

#define persisttimer_to_tcp_sock(t) \
	(struct tcp_sock *)((char *)(t) - offsetof(struct tcp_sock, persist_timer))

#define TCP_TIMER_SCAN_INTERVAL 100000
#define TCP_MSL			1000000
#define TCP_TIMEWAIT_TIMEOUT	(2 * TCP_MSL)
#define TCP_RETRANS_INTERVAL_INITIAL 200000
#define TCP_RETRANS_MAX_RETRIES 5
#define TCP_PERSIST_INTERVAL_INITIAL 200000

void *tcp_timer_thread(void *arg);

void tcp_set_timewait_timer(struct tcp_sock *tsk);

void tcp_set_retrans_timer(struct tcp_sock *tsk);
void tcp_unset_retrans_timer(struct tcp_sock *tsk);
void tcp_update_retrans_timer(struct tcp_sock *tsk);

void tcp_set_persist_timer(struct tcp_sock *tsk);
void tcp_unset_persist_timer(struct tcp_sock *tsk);

#endif