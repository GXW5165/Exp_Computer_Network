#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <resolv.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/stat.h>
#include "openssl/ssl.h"
#include "openssl/err.h"

SSL_CTX *ctx;

long get_file_size(FILE *fp)
{
	fseek(fp, 0, SEEK_END);
	long size = ftell(fp);
	rewind(fp);
	return size;
}

int parse_range(const char *buf, long *start, long *end, long file_size)
{
	const char *range_str = strstr(buf, "Range: bytes=");
	if (!range_str)
		return 0;

	range_str += strlen("Range: bytes=");
	long s = 0, e = file_size - 1;
	if (sscanf(range_str, "%ld-%ld", &s, &e) == 2)
	{
		// 完整范围
	}
	else if (sscanf(range_str, "%ld-", &s) == 1)
	{
		e = file_size - 1;
	}
	else
	{
		return -1; // 格式错误
	}
	// 验证范围
	if (s < 0)
		s = 0;
	if (e >= file_size)
		e = file_size - 1;
	if (s > e)
		return -1;
	*start = s;
	*end = e;
	return 1;
}

void send_file_range(SSL *ssl, FILE *fp, long start, long end)
{
	fseek(fp, start, SEEK_SET);
	long len = end - start + 1;
	char send_buf[4096];
	long remaining = len;
	while (remaining > 0)
	{
		int to_read = (remaining > sizeof(send_buf)) ? sizeof(send_buf) : remaining;
		int n = fread(send_buf, 1, to_read, fp);
		if (n <= 0)
			break;
		SSL_write(ssl, send_buf, n);
		remaining -= n;
	}
}

// 处理 HTTPS 请求（443 端口）
void handle_https_request(SSL *ssl)
{
	char buf[4096] = {0};
	int bytes = SSL_read(ssl, buf, sizeof(buf) - 1);
	if (bytes <= 0)
	{
		int sock = SSL_get_fd(ssl);
		SSL_free(ssl);
		close(sock);
		return;
	}
	buf[bytes] = '\0';

	// 1. 解析请求行
	char method[16], path[256], version[16];
	if (sscanf(buf, "%15s %255s %15s", method, path, version) != 3)
	{
		const char *resp = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n";
		SSL_write(ssl, resp, strlen(resp));
		int sock = SSL_get_fd(ssl);
		SSL_free(ssl);
		close(sock);
		return;
	}

	// 只支持 GET
	if (strcmp(method, "GET") != 0)
	{
		const char *resp = "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n";
		SSL_write(ssl, resp, strlen(resp));
		int sock = SSL_get_fd(ssl);
		SSL_free(ssl);
		close(sock);
		return;
	}

	// 2. 构造本地文件路径
	char filepath[512];
	if (strcmp(path, "/") == 0)
	{
		snprintf(filepath, sizeof(filepath), "index.html");
	}
	else
	{
		snprintf(filepath, sizeof(filepath), ".%s", path); // 如 "./index.html"
	}

	// 3. 尝试打开文件
	FILE *fp = fopen(filepath, "rb");
	if (!fp)
	{
		const char *resp = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
		SSL_write(ssl, resp, strlen(resp));
		int sock = SSL_get_fd(ssl);
		SSL_free(ssl);
		close(sock);
		return;
	}

	long file_size = get_file_size(fp);

	// 4. 检查 Range 头
	long start = 0, end = file_size - 1;
	int range_status = parse_range(buf, &start, &end, file_size);

	if (range_status == -1)
	{
		fclose(fp);
		const char *resp = "HTTP/1.1 416 Range Not Satisfiable\r\nContent-Length: 0\r\n\r\n";
		SSL_write(ssl, resp, strlen(resp));
		int sock = SSL_get_fd(ssl);
		SSL_free(ssl);
		close(sock);
		return;
	}

	// 5. 构造响应头
	char header[512];
	int header_len;
	if (range_status == 1)
	{
		header_len = snprintf(header, sizeof(header),
							  "HTTP/1.1 206 Partial Content\r\n"
							  "Content-Range: bytes %ld-%ld/%ld\r\n"
							  "Content-Length: %ld\r\n"
							  "Content-Type: text/html\r\n"
							  "\r\n",
							  start, end, file_size, end - start + 1);
	}
	else
	{
		header_len = snprintf(header, sizeof(header),
							  "HTTP/1.1 200 OK\r\n"
							  "Content-Length: %ld\r\n"
							  "Content-Type: text/html\r\n"
							  "\r\n",
							  file_size);
	}

	// 6. 发送响应头
	SSL_write(ssl, header, header_len);

	// 7. 发送文件内容
	send_file_range(ssl, fp, start, end);

	// 8. 清理
	fclose(fp);
	int sock = SSL_get_fd(ssl);
	SSL_free(ssl);
	close(sock);
}

// HTTP 线程（80 端口）：返回 301 重定向
void *http_thread(void *arg)
{
	int sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0)
	{
		perror("http socket");
		exit(1);
	}

	int enable = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0)
	{
		perror("http setsockopt");
		exit(1);
	}

	struct sockaddr_in addr;
	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(80);

	if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
	{
		perror("http bind");
		exit(1);
	}

	if (listen(sock, 10) < 0)
	{
		perror("http listen");
		exit(1);
	}

	printf("HTTP server listening on port 80\n");

	while (1)
	{
		struct sockaddr_in caddr;
		socklen_t len = sizeof(caddr);
		int client = accept(sock, (struct sockaddr *)&caddr, &len);
		if (client < 0)
		{
			perror("http accept");
			continue;
		}

		char buf[1024] = {0};
		int bytes = read(client, buf, sizeof(buf) - 1);
		if (bytes <= 0)
		{
			close(client);
			continue;
		}
		buf[bytes] = '\0';

		char method[16], path[256], version[16];
		if (sscanf(buf, "%15s %255s %15s", method, path, version) != 3)
		{
			close(client);
			continue;
		}

		char response[1024];
		int len_resp = snprintf(response, sizeof(response),
								"HTTP/1.1 301 Moved Permanently\r\n"
								"Location: https://10.0.0.1%s\r\n"
								"Content-Length: 0\r\n"
								"\r\n",
								path);

		write(client, response, len_resp);
		close(client);
	}

	close(sock);
	return NULL;
}

// HTTPS 线程（443 端口）
void *https_thread(void *arg)
{
	int sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0)
	{
		perror("https socket");
		exit(1);
	}

	int enable = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0)
	{
		perror("https setsockopt");
		exit(1);
	}

	struct sockaddr_in addr;
	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(443);

	if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
	{
		perror("https bind");
		exit(1);
	}

	if (listen(sock, 10) < 0)
	{
		perror("https listen");
		exit(1);
	}

	printf("HTTPS server listening on port 443\n");

	while (1)
	{
		struct sockaddr_in caddr;
		socklen_t len = sizeof(caddr);
		int client = accept(sock, (struct sockaddr *)&caddr, &len);
		if (client < 0)
		{
			perror("https accept");
			continue;
		}

		SSL *ssl = SSL_new(ctx);
		SSL_set_fd(ssl, client);

		if (SSL_accept(ssl) <= 0)
		{
			ERR_print_errors_fp(stderr);
			SSL_free(ssl);
			close(client);
			continue;
		}

		handle_https_request(ssl); // 内部会释放 ssl 和关闭 client
	}

	close(sock);
	return NULL;
}

int main()
{
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();

	const SSL_METHOD *method = TLS_server_method();
	ctx = SSL_CTX_new(method);
	if (ctx == NULL)
	{
		ERR_print_errors_fp(stderr);
		exit(1);
	}

	if (SSL_CTX_use_certificate_file(ctx, "./keys/cnlab.cert", SSL_FILETYPE_PEM) <= 0)
	{
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	if (SSL_CTX_use_PrivateKey_file(ctx, "./keys/cnlab.prikey", SSL_FILETYPE_PEM) <= 0)
	{
		ERR_print_errors_fp(stderr);
		exit(1);
	}

	pthread_t tid_http, tid_https;
	if (pthread_create(&tid_http, NULL, http_thread, NULL) != 0)
	{
		perror("pthread_create http");
		exit(1);
	}
	if (pthread_create(&tid_https, NULL, https_thread, NULL) != 0)
	{
		perror("pthread_create https");
		exit(1);
	}

	pthread_join(tid_http, NULL);
	pthread_join(tid_https, NULL);

	SSL_CTX_free(ctx);
	return 0;
}