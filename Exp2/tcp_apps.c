#include "tcp_sock.h"

#include "log.h"

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static char data[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

void *tcp_server(void *arg)
{
	u16 port = *(u16 *)arg;
	struct tcp_sock *tsk = alloc_tcp_sock();

	struct sock_addr addr;
	addr.ip = htonl(0);
	addr.port = port;
	if (tcp_sock_bind(tsk, &addr) < 0)
	{
		log(ERROR, "tcp_sock bind to port %hu failed", ntohs(port));
		exit(1);
	}

	if (tcp_sock_listen(tsk, 3) < 0)
	{
		log(ERROR, "tcp_sock listen failed");
		exit(1);
	}

	log(DEBUG, "listen to port %hu.", ntohs(port));

	struct tcp_sock *csk = tcp_sock_accept(tsk);
	log(DEBUG, "accept a connection.");

	char recvbuf[2048];
	while (1)
	{
		int rlen = tcp_sock_read(csk, recvbuf, sizeof(recvbuf) - 1);
		if (rlen <= 0)
			break;

		recvbuf[rlen] = '\0';

		char sendbuf[4096];
		snprintf(sendbuf, sizeof(sendbuf), "server echoes: %s", recvbuf);

		if (tcp_sock_write(csk, sendbuf, strlen(sendbuf)) < 0)
		{
			log(ERROR, "tcp_sock_write failed in server.");
			break;
		}
	}

	tcp_sock_close(csk);
	return NULL;
}

void *tcp_client(void *arg)
{
	struct sock_addr *skaddr = arg;

	struct tcp_sock *tsk = alloc_tcp_sock();

	if (tcp_sock_connect(tsk, skaddr) < 0)
	{
		log(ERROR, "tcp_sock connect to server (" IP_FMT ":%hu) failed.",
			NET_IP_FMT_STR(skaddr->ip), ntohs(skaddr->port));
		exit(1);
	}

	int data_len = strlen(data);
	char sendbuf[128];
	char recvbuf[2048];

	for (int i = 0; i < 5; i++)
	{
		for (int j = 0; j < data_len; j++)
		{
			sendbuf[j] = data[(i + j) % data_len];
		}
		sendbuf[data_len] = '\0';

		if (tcp_sock_write(tsk, sendbuf, data_len) < 0)
		{
			log(ERROR, "tcp_sock_write failed in client.");
			break;
		}

		int rlen = tcp_sock_read(tsk, recvbuf, sizeof(recvbuf) - 1);
		if (rlen <= 0)
			break;

		recvbuf[rlen] = '\0';
		printf("%s\n", recvbuf);

		sleep(1);
	}

	tcp_sock_close(tsk);
	return NULL;
}