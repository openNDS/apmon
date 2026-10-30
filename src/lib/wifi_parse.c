/*
 * nl80211 attribute parsing and Wi-Fi mode mapping, with no OpenWrt libraries
 * (unit tested on the host with hand-built attribute buffers).
 * The daemon's nl80211.c does the generic netlink I/O and hands the attributes here.
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <linux/netlink.h>
#include <linux/nl80211.h>
#include <stdio.h>
#include <string.h>

#include "apmon.h"

/* ---------- attribute walking ---------- */

/* First attribute of 'type' in [data, data + len), or NULL; *out_len = payload length */
const void *apmon_nla_find(const void *data, size_t len, int type, size_t *out_len)
{
	const unsigned char *p = data;
	size_t left = len;

	while (left >= NLA_HDRLEN) {
		const struct nlattr *a = (const struct nlattr *)p;
		size_t alen = a->nla_len;
		size_t step;

		if (alen < NLA_HDRLEN || alen > left) {
			return NULL;
		}
		if ((a->nla_type & NLA_TYPE_MASK) == type) {
			*out_len = alen - NLA_HDRLEN;
			return p + NLA_HDRLEN;
		}
		step = NLA_ALIGN(alen);
		if (step > left) {
			return NULL;
		}
		p += step;
		left -= step;
	}
	return NULL;
}

static int get_u32(const void *data, size_t len, int type, uint32_t *out)
{
	size_t n;
	const void *v = apmon_nla_find(data, len, type, &n);

	if (v == NULL || n < 4) {
		return -1;
	}
	memcpy(out, v, 4);
	return 0;
}

static int get_u16(const void *data, size_t len, int type, uint16_t *out)
{
	size_t n;
	const void *v = apmon_nla_find(data, len, type, &n);

	if (v == NULL || n < 2) {
		return -1;
	}
	memcpy(out, v, 2);
	return 0;
}

static int get_u64(const void *data, size_t len, int type, uint64_t *out)
{
	size_t n;
	const void *v = apmon_nla_find(data, len, type, &n);

	if (v == NULL || n < 8) {
		return -1;
	}
	memcpy(out, v, 8);
	return 0;
}

static int get_s8(const void *data, size_t len, int type, int *out)
{
	size_t n;
	const signed char *v = apmon_nla_find(data, len, type, &n);

	if (v == NULL || n < 1) {
		return -1;
	}
	*out = v[0];
	return 0;
}

/* ---------- interfaces ---------- */

int apmon_nl80211_parse_iface(const void *attrs, size_t len, struct apmon_wifi_iface *out)
{
	const void *v;
	size_t n;
	uint32_t u;

	memset(out, 0, sizeof(*out));
	out->width = -1;
	out->wiphy = -1;

	if (get_u32(attrs, len, NL80211_ATTR_IFINDEX, &u) != 0) {
		return -1;
	}
	out->ifindex = (int)u;

	v = apmon_nla_find(attrs, len, NL80211_ATTR_IFNAME, &n);
	if (v != NULL && n > 0) {
		if (n >= sizeof(out->ifname)) {
			n = sizeof(out->ifname) - 1;
		}
		memcpy(out->ifname, v, n);
		out->ifname[n] = '\0';
	}

	v = apmon_nla_find(attrs, len, NL80211_ATTR_MAC, &n);
	if (v != NULL && n == APMON_ID_LEN) {
		memcpy(out->mac, v, APMON_ID_LEN);
		out->have_mac = 1;
	}

	v = apmon_nla_find(attrs, len, NL80211_ATTR_SSID, &n);
	if (v != NULL) {
		if (n >= sizeof(out->ssid)) {
			n = sizeof(out->ssid) - 1;
		}
		memcpy(out->ssid, v, n);
		out->ssid[n] = '\0';
		out->have_ssid = 1;
	}

	if (get_u32(attrs, len, NL80211_ATTR_IFTYPE, &u) == 0) {
		out->iftype = (int)u;
	}
	if (get_u32(attrs, len, NL80211_ATTR_WIPHY, &u) == 0) {
		out->wiphy = (int)u;
	}
	if (get_u32(attrs, len, NL80211_ATTR_WIPHY_FREQ, &u) == 0) {
		out->freq = (int)u;
	}
	if (get_u32(attrs, len, NL80211_ATTR_CHANNEL_WIDTH, &u) == 0) {
		out->width = (int)u;
	}
	if (get_u32(attrs, len, NL80211_ATTR_WIPHY_TX_POWER_LEVEL, &u) == 0) {
		out->txpower_mbm = (int)u;
		out->have_txpower = 1;
	}
	return 0;
}

/* ---------- stations ---------- */

/* NL80211_RATE_INFO_*: BITRATE32 (100 kbit/s units), else the old 16 bit BITRATE */
static int rate_kbps(const void *sinfo, size_t len, int type, uint32_t *kbps)
{
	size_t n;
	const void *rate = apmon_nla_find(sinfo, len, type, &n);
	uint32_t r32;
	uint16_t r16;

	if (rate == NULL) {
		return -1;
	}
	if (get_u32(rate, n, NL80211_RATE_INFO_BITRATE32, &r32) == 0) {
		*kbps = r32 * 100;
		return 0;
	}
	if (get_u16(rate, n, NL80211_RATE_INFO_BITRATE, &r16) == 0) {
		*kbps = (uint32_t)r16 * 100;
		return 0;
	}
	return -1;
}

int apmon_nl80211_parse_station(const void *attrs, size_t len, struct apmon_wifi_sta *out)
{
	const void *v;
	const void *sinfo;
	size_t n;
	size_t slen;
	uint32_t u;
	uint64_t u64;

	memset(out, 0, sizeof(*out));

	v = apmon_nla_find(attrs, len, NL80211_ATTR_MAC, &n);
	if (v == NULL || n != APMON_ID_LEN) {
		return -1;
	}
	memcpy(out->mac, v, APMON_ID_LEN);

	sinfo = apmon_nla_find(attrs, len, NL80211_ATTR_STA_INFO, &slen);
	if (sinfo == NULL) {
		return 0;
	}

	if (get_u32(sinfo, slen, NL80211_STA_INFO_INACTIVE_TIME, &u) == 0) {
		out->inactive_ms = u;
		out->have |= APMON_STA_INACTIVE;
	}
	if (get_u32(sinfo, slen, NL80211_STA_INFO_CONNECTED_TIME, &u) == 0) {
		out->connected_s = u;
		out->have |= APMON_STA_CONNECTED;
	}
	if (get_u64(sinfo, slen, NL80211_STA_INFO_RX_BYTES64, &u64) == 0) {
		out->rx_bytes = u64;
		out->have |= APMON_STA_RX_BYTES;
	} else if (get_u32(sinfo, slen, NL80211_STA_INFO_RX_BYTES, &u) == 0) {
		out->rx_bytes = u;
		out->have |= APMON_STA_RX_BYTES;
	}
	if (get_u64(sinfo, slen, NL80211_STA_INFO_TX_BYTES64, &u64) == 0) {
		out->tx_bytes = u64;
		out->have |= APMON_STA_TX_BYTES;
	} else if (get_u32(sinfo, slen, NL80211_STA_INFO_TX_BYTES, &u) == 0) {
		out->tx_bytes = u;
		out->have |= APMON_STA_TX_BYTES;
	}
	if (get_u32(sinfo, slen, NL80211_STA_INFO_TX_RETRIES, &u) == 0) {
		out->tx_retries = u;
		out->have |= APMON_STA_TX_RETRIES;
	}
	if (get_s8(sinfo, slen, NL80211_STA_INFO_SIGNAL, &out->signal) == 0) {
		out->have |= APMON_STA_SIGNAL;
	}
	if (get_s8(sinfo, slen, NL80211_STA_INFO_SIGNAL_AVG, &out->signal_avg) == 0) {
		out->have |= APMON_STA_SIGNAL_AVG;
	}
	if (get_s8(sinfo, slen, NL80211_STA_INFO_ACK_SIGNAL_AVG, &out->ack_signal_avg) == 0) {
		out->have |= APMON_STA_ACK_SIGNAL_AVG;
	}
	if (rate_kbps(sinfo, slen, NL80211_STA_INFO_TX_BITRATE, &out->tx_rate_kbps) == 0) {
		out->have |= APMON_STA_TX_RATE;
	}
	if (rate_kbps(sinfo, slen, NL80211_STA_INFO_RX_BITRATE, &out->rx_rate_kbps) == 0) {
		out->have |= APMON_STA_RX_RATE;
	}
	return 0;
}

/* ---------- wiphy capabilities ---------- */

/*
 * One message of a (split) NL80211_CMD_GET_WIPHY dump: raise families[band] to the highest
 * mode the band supports (HT capa, VHT capa, HE/EHT in the iftype data).
 * Returns the wiphy index, or -1.
 */
int apmon_nl80211_parse_wiphy(const void *attrs, size_t len, int families[APMON_BANDS])
{
	const unsigned char *bands;
	size_t blen;
	uint32_t wiphy;

	if (get_u32(attrs, len, NL80211_ATTR_WIPHY, &wiphy) != 0) {
		return -1;
	}
	bands = apmon_nla_find(attrs, len, NL80211_ATTR_WIPHY_BANDS, &blen);
	while (bands != NULL && blen >= NLA_HDRLEN) {
		const struct nlattr *band = (const struct nlattr *)bands;
		const void *b = bands + NLA_HDRLEN;
		size_t bl;
		int idx;
		int fam = APMON_FAMILY_NONE;
		size_t n;
		const unsigned char *it;
		size_t step;

		if (band->nla_len < NLA_HDRLEN || band->nla_len > blen) {
			break;
		}
		bl = band->nla_len - NLA_HDRLEN;
		idx = band->nla_type & NLA_TYPE_MASK;

		if (apmon_nla_find(b, bl, NL80211_BAND_ATTR_HT_CAPA, &n) != NULL) {
			fam = APMON_FAMILY_HT;
		}
		if (apmon_nla_find(b, bl, NL80211_BAND_ATTR_VHT_CAPA, &n) != NULL) {
			fam = APMON_FAMILY_VHT;
		}
		it = apmon_nla_find(b, bl, NL80211_BAND_ATTR_IFTYPE_DATA, &n);
		while (it != NULL && n >= NLA_HDRLEN) {
			const struct nlattr *entry = (const struct nlattr *)it;
			size_t el;
			size_t dummy;
			size_t estep;

			if (entry->nla_len < NLA_HDRLEN || entry->nla_len > n) {
				break;
			}
			el = entry->nla_len - NLA_HDRLEN;
			if (apmon_nla_find(it + NLA_HDRLEN, el, NL80211_BAND_IFTYPE_ATTR_HE_CAP_PHY, &dummy) != NULL &&
			    fam < APMON_FAMILY_HE) {
				fam = APMON_FAMILY_HE;
			}
			if (apmon_nla_find(it + NLA_HDRLEN, el, NL80211_BAND_IFTYPE_ATTR_EHT_CAP_PHY, &dummy) != NULL) {
				fam = APMON_FAMILY_EHT;
			}
			estep = NLA_ALIGN(entry->nla_len);
			if (estep >= n) {
				break;
			}
			it += estep;
			n -= estep;
		}

		if (idx >= 0 && idx < APMON_BANDS && fam > families[idx]) {
			families[idx] = fam;
		}
		step = NLA_ALIGN(band->nla_len);
		if (step >= blen) {
			break;
		}
		bands += step;
		blen -= step;
	}
	return (int)wiphy;
}

/* ---------- frequencies and modes ---------- */

int apmon_freq_band(int freq)
{
	if (freq >= 2400 && freq < 2500) {
		return NL80211_BAND_2GHZ;
	}
	if (freq >= 5925 && freq <= 7125) {
		return NL80211_BAND_6GHZ;
	}
	if (freq >= 4900 && freq < 5925) {
		return NL80211_BAND_5GHZ;
	}
	if (freq >= 58000 && freq <= 71000) {
		return NL80211_BAND_60GHZ;
	}
	return -1;
}

/* As iw's ieee80211_frequency_to_channel */
int apmon_freq_to_channel(int freq)
{
	if (freq == 2484) {
		return 14;
	}
	if (freq == 5935) {
		return 2;
	}
	if (freq >= 2407 && freq < 2484) {
		return (freq - 2407) / 5;
	}
	if (freq >= 4910 && freq <= 4980) {
		return (freq - 4000) / 5;
	}
	if (freq >= 5950 && freq <= 7115) {
		return (freq - 5950) / 5;
	}
	if (freq > 5000 && freq < 5950) {
		return (freq - 5000) / 5;
	}
	if (freq >= 58320 && freq <= 70200) {
		return (freq - 56160) / 2160;
	}
	return 0;
}

/* Family named by a uci htmode (HT40, VHT80, HE160, EHT320, NOHT); -1 if empty or unknown */
int apmon_htmode_family(const char *htmode)
{
	if (htmode == NULL || htmode[0] == '\0') {
		return -1;
	}
	if (strncmp(htmode, "EHT", 3) == 0) {
		return APMON_FAMILY_EHT;
	}
	if (strncmp(htmode, "HE", 2) == 0) {
		return APMON_FAMILY_HE;
	}
	if (strncmp(htmode, "VHT", 3) == 0) {
		return APMON_FAMILY_VHT;
	}
	if (strncmp(htmode, "HT", 2) == 0) {
		return APMON_FAMILY_HT;
	}
	if (strcmp(htmode, "NOHT") == 0) {
		return APMON_FAMILY_NONE;
	}
	return -1;
}

/* Width in MHz of an nl80211 channel width; 0 for 20_NOHT, -1 unknown */
static int width_mhz(int width)
{
	switch (width) {
	case NL80211_CHAN_WIDTH_20_NOHT:
		return 0;
	case NL80211_CHAN_WIDTH_20:
		return 20;
	case NL80211_CHAN_WIDTH_40:
		return 40;
	case NL80211_CHAN_WIDTH_80:
		return 80;
	case NL80211_CHAN_WIDTH_80P80:
		return 8080;
	case NL80211_CHAN_WIDTH_160:
		return 160;
	case NL80211_CHAN_WIDTH_320:
		return 320;
	default:
		return -1;
	}
}

/* Wider of two nl80211 channel widths (by MHz); unknown (-1) loses */
int apmon_wider_width(int a, int b)
{
	int ma = width_mhz(a);
	int mb = width_mhz(b);

	if (ma < 0) {
		return b;
	}
	if (mb < 0) {
		return a;
	}
	if (mb > ma) {
		return b;
	}
	return a;
}

/*
 * "<family><MHz>" as uci and iwinfo write it (HE80, VHT160, HT40, EHT320), "NOHT" for a
 * 20 MHz non-HT channel. Returns -1 (no htmode) if the width or family is unknown.
 */
int apmon_htmode_string(int family, int width, char *out, size_t len)
{
	static const char *const names[] = { "NOHT", "HT", "VHT", "HE", "EHT" };
	int mhz = width_mhz(width);

	if (mhz < 0) {
		return -1;
	}
	if (mhz == 0 || family == APMON_FAMILY_NONE) {
		snprintf(out, len, "NOHT");
		return 0;
	}
	if (family < APMON_FAMILY_HT || family > APMON_FAMILY_EHT) {
		return -1;
	}
	if (mhz == 8080) {
		snprintf(out, len, "%s80+80", names[family]);
		return 0;
	}
	snprintf(out, len, "%s%d", names[family], mhz);
	return 0;
}

const char *apmon_iftype_name(int iftype)
{
	switch (iftype) {
	case NL80211_IFTYPE_AP:
		return "ap";
	case NL80211_IFTYPE_MESH_POINT:
		return "mesh";
	case NL80211_IFTYPE_STATION:
		return "sta";
	case NL80211_IFTYPE_MONITOR:
		return "monitor";
	case NL80211_IFTYPE_AP_VLAN:
		return "ap_vlan";
	case NL80211_IFTYPE_ADHOC:
		return "adhoc";
	default:
		return "other";
	}
}
