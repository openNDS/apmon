/*
 * apmond minimal blocking HTTP/1.1 POST client (one request per connection)
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "apmond.h"

#define MAX_RESPONSE 65536

static int connect_to(const char *host, int port, int timeout_s)
{
	struct addrinfo hints;
	struct addrinfo *res = NULL;
	struct addrinfo *ai;
	struct timeval tv;
	char port_str[8];
	int fd = -1;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_NUMERICHOST;
	snprintf(port_str, sizeof(port_str), "%d", port);

	if (getaddrinfo(host, port_str, &hints, &res) != 0) {
		return -1;
	}

	tv.tv_sec = timeout_s;
	tv.tv_usec = 0;

	for (ai = res; ai != NULL; ai = ai->ai_next) {
		fd = socket(ai->ai_family, ai->ai_socktype | SOCK_CLOEXEC, ai->ai_protocol);
		if (fd < 0) {
			continue;
		}
		setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
		setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
		if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) {
			break;
		}
		close(fd);
		fd = -1;
	}

	freeaddrinfo(res);
	return fd;
}

static int write_all(int fd, const void *buf, size_t len)
{
	const uint8_t *p = buf;

	while (len > 0) {
		ssize_t n = write(fd, p, len);

		if (n <= 0) {
			return -1;
		}
		p += n;
		len -= (size_t)n;
	}
	return 0;
}

int apmond_http_post(const char *host, int port, const char *path, const uint8_t *body, size_t len,
		     int timeout_s, int *status, uint8_t **resp, size_t *resp_len)
{
	char head[512];
	uint8_t *buf;
	size_t got = 0;
	char *end_of_head;
	int head_len;
	int fd;
	int ret = -1;

	*status = 0;
	*resp = NULL;
	*resp_len = 0;

	fd = connect_to(host, port, timeout_s);
	if (fd < 0) {
		return -1;
	}

	if (strchr(host, ':') != NULL) {
		head_len = snprintf(head, sizeof(head),
				    "POST %s HTTP/1.1\r\nHost: [%s]:%d\r\nContent-Type: %s\r\n"
				    "Content-Length: %zu\r\nConnection: close\r\n\r\n",
				    path, host, port, APMON_CONTENT_TYPE, len);
	} else {
		head_len = snprintf(head, sizeof(head),
				    "POST %s HTTP/1.1\r\nHost: %s:%d\r\nContent-Type: %s\r\n"
				    "Content-Length: %zu\r\nConnection: close\r\n\r\n",
				    path, host, port, APMON_CONTENT_TYPE, len);
	}

	buf = malloc(MAX_RESPONSE + 1);
	if (buf == NULL) {
		close(fd);
		return -1;
	}

	if (write_all(fd, head, (size_t)head_len) != 0) {
		goto out;
	}
	if (write_all(fd, body, len) != 0) {
		goto out;
	}

	while (got < MAX_RESPONSE) {
		ssize_t n = read(fd, buf + got, MAX_RESPONSE - got);

		if (n <= 0) {
			break;
		}
		got += (size_t)n;
	}
	buf[got] = '\0';

	if (sscanf((char *)buf, "HTTP/1.%*d %d", status) != 1) {
		goto out;
	}

	end_of_head = strstr((char *)buf, "\r\n\r\n");
	if (end_of_head == NULL) {
		goto out;
	}
	end_of_head += 4;

	*resp_len = got - (size_t)(end_of_head - (char *)buf);
	if (*resp_len > 0) {
		*resp = malloc(*resp_len);
		if (*resp == NULL) {
			*resp_len = 0;
			goto out;
		}
		memcpy(*resp, end_of_head, *resp_len);
	}
	ret = 0;

out:
	free(buf);
	close(fd);
	return ret;
}
