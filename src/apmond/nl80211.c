/*
 * Wi-Fi state straight from the kernel over generic netlink (nl80211): no iwinfo, no rpcd,
 * no libnl, never forks iw. Dumps need no capability.
 * Parsing is in libapmon (wifi_parse.c) so it is host tested.
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <errno.h>
#include <linux/genetlink.h>
#include <linux/netlink.h>
#include <linux/nl80211.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "apmond.h"

#define NL_BUF 32768

struct nl80211 {
	int fd;
	uint16_t family;
	uint32_t seq;
};

typedef int (*nl_cb)(const void *attrs, size_t len, void *arg);

static int nl_send(struct nl80211 *nl, uint16_t type, uint16_t flags, uint8_t cmd, const void *attrs, size_t alen)
{
	unsigned char buf[256];
	struct nlmsghdr *h = (struct nlmsghdr *)buf;
	struct genlmsghdr *g = (struct genlmsghdr *)NLMSG_DATA(h);
	struct sockaddr_nl to;
	size_t len = NLMSG_LENGTH(GENL_HDRLEN) + alen;

	if (len > sizeof(buf)) {
		return -1;
	}
	memset(buf, 0, sizeof(buf));
	nl->seq++;
	h->nlmsg_len = (uint32_t)len;
	h->nlmsg_type = type;
	h->nlmsg_flags = (uint16_t)(NLM_F_REQUEST | flags);
	h->nlmsg_seq = nl->seq;
	g->cmd = cmd;
	g->version = 1;
	if (alen > 0) {
		memcpy(buf + NLMSG_LENGTH(GENL_HDRLEN), attrs, alen);
	}
	memset(&to, 0, sizeof(to));
	to.nl_family = AF_NETLINK;
	if (sendto(nl->fd, buf, len, 0, (struct sockaddr *)&to, sizeof(to)) < 0) {
		return -1;
	}
	return 0;
}

/* Reads replies to the last request until DONE/ACK/error; cb gets each message's attributes */
static int nl_recv(struct nl80211 *nl, nl_cb cb, void *arg)
{
	unsigned char *buf = malloc(NL_BUF);
	int ret = -1;

	if (buf == NULL) {
		return -1;
	}
	for (;;) {
		ssize_t n = recv(nl->fd, buf, NL_BUF, 0);
		struct nlmsghdr *h;
		size_t left;

		if (n < 0) {
			if (errno == EINTR) {
				continue;
			}
			break;
		}
		left = (size_t)n;
		for (h = (struct nlmsghdr *)buf; NLMSG_OK(h, left); h = NLMSG_NEXT(h, left)) {
			if (h->nlmsg_seq != nl->seq) {
				continue;
			}
			if (h->nlmsg_type == NLMSG_DONE) {
				ret = 0;
				goto out;
			}
			if (h->nlmsg_type == NLMSG_ERROR) {
				struct nlmsgerr *e = (struct nlmsgerr *)NLMSG_DATA(h);

				ret = (e->error == 0) ? 0 : -1;
				goto out;
			}
			if (h->nlmsg_len >= NLMSG_LENGTH(GENL_HDRLEN) && cb != NULL) {
				const unsigned char *attrs = (const unsigned char *)NLMSG_DATA(h) + GENL_HDRLEN;
				size_t alen = h->nlmsg_len - NLMSG_LENGTH(GENL_HDRLEN);

				cb(attrs, alen, arg);
			}
			if (!(h->nlmsg_flags & NLM_F_MULTI)) {
				ret = 0;
				goto out;
			}
		}
	}
out:
	free(buf);
	return ret;
}

static int family_cb(const void *attrs, size_t len, void *arg)
{
	size_t n;
	const void *id = apmon_nla_find(attrs, len, CTRL_ATTR_FAMILY_ID, &n);

	if (id != NULL && n >= 2) {
		memcpy(arg, id, 2);
	}
	return 0;
}

static size_t put_attr(unsigned char *buf, size_t at, int type, const void *data, size_t dlen)
{
	struct nlattr *a = (struct nlattr *)(buf + at);

	a->nla_type = (uint16_t)type;
	a->nla_len = (uint16_t)(NLA_HDRLEN + dlen);
	memcpy(buf + at + NLA_HDRLEN, data, dlen);
	return at + NLA_ALIGN(a->nla_len);
}

static int nl_open(struct nl80211 *nl)
{
	struct sockaddr_nl local;
	struct timeval tv = { 2, 0 };
	unsigned char attrs[32];
	size_t alen;

	memset(nl, 0, sizeof(*nl));
	nl->fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_GENERIC);
	if (nl->fd < 0) {
		return -1;
	}
	memset(&local, 0, sizeof(local));
	local.nl_family = AF_NETLINK;
	if (bind(nl->fd, (struct sockaddr *)&local, sizeof(local)) < 0) {
		close(nl->fd);
		return -1;
	}
	setsockopt(nl->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

	memset(attrs, 0, sizeof(attrs));
	alen = put_attr(attrs, 0, CTRL_ATTR_FAMILY_NAME, NL80211_GENL_NAME, sizeof(NL80211_GENL_NAME));
	if (nl_send(nl, GENL_ID_CTRL, 0, CTRL_CMD_GETFAMILY, attrs, alen) != 0 ||
	    nl_recv(nl, family_cb, &nl->family) != 0 || nl->family == 0) {
		close(nl->fd);
		return -1;
	}
	return 0;
}

/* ---------- public ---------- */

struct iface_list {
	struct apmon_wifi_iface *ifs;
	int max;
	int count;
};

static int iface_cb(const void *attrs, size_t len, void *arg)
{
	struct iface_list *l = arg;

	if (l->count >= l->max) {
		return 0;
	}
	if (apmon_nl80211_parse_iface(attrs, len, &l->ifs[l->count]) == 0) {
		l->count++;
	}
	return 0;
}

static int wiphy_cb(const void *attrs, size_t len, void *arg)
{
	struct apmond_wiphy_caps *c = arg;
	size_t n;
	uint32_t idx;
	const void *v = apmon_nla_find(attrs, len, NL80211_ATTR_WIPHY, &n);
	int i;

	if (v == NULL || n < 4) {
		return 0;
	}
	memcpy(&idx, v, 4);
	for (i = 0; i < c->count; i++) {
		if (c->wiphy[i] == (int)idx) {
			break;
		}
	}
	if (i == c->count) {
		if (c->count >= APMOND_MAX_WIPHY) {
			return 0;
		}
		c->wiphy[i] = (int)idx;
		memset(c->family[i], 0, sizeof(c->family[i]));
		c->count++;
	}
	apmon_nl80211_parse_wiphy(attrs, len, c->family[i]);
	return 0;
}

int apmond_nl80211_snapshot(struct apmon_wifi_iface *ifs, int max, int *count, struct apmond_wiphy_caps *caps)
{
	struct nl80211 nl;
	struct iface_list l = { ifs, max, 0 };
	unsigned char attrs[16];
	size_t alen;
	int ret = 0;

	*count = 0;
	caps->count = 0;
	if (nl_open(&nl) != 0) {
		LOG_DEBUG_("nl80211: generic netlink unavailable");
		return -1;
	}
	if (nl_send(&nl, nl.family, NLM_F_DUMP, NL80211_CMD_GET_INTERFACE, NULL, 0) != 0 ||
	    nl_recv(&nl, iface_cb, &l) != 0) {
		ret = -1;
	}
	*count = l.count;

	memset(attrs, 0, sizeof(attrs));
	alen = put_attr(attrs, 0, NL80211_ATTR_SPLIT_WIPHY_DUMP, "", 0);
	if (nl_send(&nl, nl.family, NLM_F_DUMP, NL80211_CMD_GET_WIPHY, attrs, alen) == 0) {
		nl_recv(&nl, wiphy_cb, caps);
	}
	close(nl.fd);
	return ret;
}

struct sta_list {
	struct apmon_wifi_sta *stas;
	int max;
	int count;
};

static int sta_cb(const void *attrs, size_t len, void *arg)
{
	struct sta_list *l = arg;

	if (l->count >= l->max) {
		return 0;
	}
	if (apmon_nl80211_parse_station(attrs, len, &l->stas[l->count]) == 0) {
		l->count++;
	}
	return 0;
}

int apmond_nl80211_stations(int ifindex, struct apmon_wifi_sta *stas, int max)
{
	struct nl80211 nl;
	struct sta_list l = { stas, max, 0 };
	unsigned char attrs[16];
	uint32_t idx = (uint32_t)ifindex;
	size_t alen;

	if (nl_open(&nl) != 0) {
		return -1;
	}
	memset(attrs, 0, sizeof(attrs));
	alen = put_attr(attrs, 0, NL80211_ATTR_IFINDEX, &idx, 4);
	if (nl_send(&nl, nl.family, NLM_F_DUMP, NL80211_CMD_GET_STATION, attrs, alen) != 0 ||
	    nl_recv(&nl, sta_cb, &l) != 0) {
		close(nl.fd);
		return -1;
	}
	close(nl.fd);
	return l.count;
}
