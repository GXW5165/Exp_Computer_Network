#ifndef __TCP_SOCK_H__
#define __TCP_SOCK_H__

#include "types.h"
#include "list.h"
#include "tcp.h"
#include "tcp_timer.h"
#include "ring_buffer.h"

#include "synch_wait.h"

#include <pthread.h>

#define PORT_MIN	12345
#define PORT_MAX	23456

#define TCP_MSS (ETH_FRAME_LEN - ETHER_HDR_SIZE - IP_BASE_HDR_SIZE - TCP_BASE_HDR_SIZE)

struct sock_addr {
	u32 ip;
	u16 port;
} __attribute__((packed));

struct send_buffer_entry {
	struct list_head list;
	char *packet;
	int len;
	u32 seq;
	u32 seq_end;
};

struct recv_ofo_buf_entry {
	struct list_head list;
	char *packet;
	int len;
	u32 seq;
	u32 seq_end;
	int pl_len;
};

enum tcp_cc_state {
	TCP_CC_OPEN = 0,
	TCP_CC_DISORDER,
	TCP_CC_RECOVERY,
};

struct tcp_sock {
	struct sock_addr local;
	struct sock_addr peer;
#define sk_sip local.ip
#define sk_sport local.port
#define sk_dip peer.ip
#define sk_dport peer.port

	struct tcp_sock *parent;

	int ref_cnt;

	struct list_head hash_list;
	struct list_head bind_hash_list;

	struct list_head listen_queue;
	struct list_head accept_queue;

#define TCP_MAX_BACKLOG 128
	int accept_backlog;
	int backlog;

	struct list_head list;
	struct tcp_timer timewait;
	struct tcp_timer retrans_timer;
	struct tcp_timer persist_timer;

	struct synch_wait *wait_connect;
	struct synch_wait *wait_accept;
	struct synch_wait *wait_recv;
	struct synch_wait *wait_send;

	pthread_mutex_t sk_lock;
	pthread_mutex_t rcv_buf_lock;
	pthread_mutex_t send_buf_lock;

	struct ring_buffer *rcv_buf;
	struct list_head send_buf;
	struct list_head rcv_ofo_buf;

	int state;

	u32 iss;
	u32 snd_una;
	u32 snd_nxt;
	u32 rcv_nxt;
	u32 recovery_point;
	int c_state;
	int dup_ack_cnt;
	int cwnd_record_on;

	u32 snd_wnd;
	u16 adv_wnd;

	u16 rcv_wnd;

	u32 cwnd;
	u32 ssthresh;
};

void tcp_set_state(struct tcp_sock *tsk, int state);

int tcp_sock_accept_queue_full(struct tcp_sock *tsk);
void tcp_sock_accept_enqueue(struct tcp_sock *tsk);
struct tcp_sock *tcp_sock_accept_dequeue(struct tcp_sock *tsk);

int tcp_hash(struct tcp_sock *tsk);
void tcp_unhash(struct tcp_sock *tsk);
void tcp_bind_unhash(struct tcp_sock *tsk);
struct tcp_sock *alloc_tcp_sock();
void free_tcp_sock(struct tcp_sock *tsk);
struct tcp_sock *tcp_sock_lookup(struct tcp_cb *cb);

u32 tcp_new_iss();

void tcp_send_reset(struct tcp_cb *cb);

void tcp_send_control_packet(struct tcp_sock *tsk, u8 flags);
void tcp_send_packet(struct tcp_sock *tsk, char *packet, int len);
int tcp_send_data(struct tcp_sock *tsk, char *buf, int len);
void tcp_send_probe_packet(struct tcp_sock *tsk);

void tcp_send_buffer_add_packet(struct tcp_sock *tsk, char *packet, int len);
int tcp_update_send_buffer(struct tcp_sock *tsk, u32 ack);
int tcp_retrans_send_buffer(struct tcp_sock *tsk);

int tcp_recv_ofo_buffer_add_packet(struct tcp_sock *tsk, struct tcp_cb *cb);
int tcp_move_recv_ofo_buffer(struct tcp_sock *tsk);

void tcp_process(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet);

void init_tcp_stack();

int tcp_sock_bind(struct tcp_sock *tsk, struct sock_addr *skaddr);
int tcp_sock_listen(struct tcp_sock *tsk, int backlog);
int tcp_sock_connect(struct tcp_sock *tsk, struct sock_addr *skaddr);
struct tcp_sock *tcp_sock_accept(struct tcp_sock *tsk);
int tcp_sock_wait_all_acked(struct tcp_sock *tsk);
void tcp_sock_close(struct tcp_sock *tsk);

int tcp_sock_read(struct tcp_sock *tsk, char *buf, int len);
int tcp_sock_write(struct tcp_sock *tsk, char *buf, int len);

int tcp_tx_window_test(struct tcp_sock *tsk);

#endif