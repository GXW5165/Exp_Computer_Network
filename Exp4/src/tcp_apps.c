#include "tcp_sock.h"

#include "log.h"

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

void *tcp_server(void *arg)
{
	u16 port = *(u16 *)arg;
	free(arg);

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

	struct tcp_sock *csk = tcp_sock_accept(tsk);

	FILE *fp = fopen("server-output.dat", "wb");
	if (!fp)
	{
		log(ERROR, "open server-output.dat failed");
		exit(1);
	}

	char recvbuf[2048];
	while (1)
	{
		int rlen = tcp_sock_read(csk, recvbuf, sizeof(recvbuf));
		if (rlen <= 0)
			break;

		fwrite(recvbuf, 1, rlen, fp);
		fflush(fp);
	}

	fclose(fp);
	tcp_sock_close(csk);
	return NULL;
}

void *tcp_client(void *arg)
{
	struct sock_addr skaddr = *(struct sock_addr *)arg;
	free(arg);

	struct tcp_sock *tsk = alloc_tcp_sock();

	if (tcp_sock_connect(tsk, &skaddr) < 0)
	{
		log(ERROR, "tcp_sock connect to server (" IP_FMT ":%hu) failed.",
			NET_IP_FMT_STR(skaddr.ip), ntohs(skaddr.port));
		exit(1);
	}

	FILE *fp = fopen("client-input.dat", "rb");
	if (!fp)
	{
		log(ERROR, "open client-input.dat failed");
		exit(1);
	}

	char sendbuf[TCP_MSS];
	while (1)
	{
		int rlen = fread(sendbuf, 1, sizeof(sendbuf), fp);
		if (rlen <= 0)
			break;

		if (tcp_sock_write(tsk, sendbuf, rlen) < 0)
		{
			log(ERROR, "tcp_sock_write failed in client.");
			break;
		}
	}

	fclose(fp);

	if (tcp_sock_wait_all_acked(tsk) == 0)
		tcp_sock_close(tsk);

	return NULL;
}