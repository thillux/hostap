/*
 * WPA Supplicant - background scan and roaming module: learn_11k
 * Copyright (c) 2009-2010, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"

#include "common.h"
#include "eloop.h"
#include "list.h"
#include "common/ieee802_11_defs.h"
#include "common/ieee802_11_common.h"
#include "drivers/driver.h"
#include "config_ssid.h"
#include "wpa_supplicant_i.h"
#include "driver_i.h"
#include "scan.h"
#include "bgscan.h"
#include "bss.h"

struct bgscan_learn_11k_bss {
	struct dl_list list;
	u8 bssid[ETH_ALEN];
	int freq;
	u8 *neigh; /* num_neigh * ETH_ALEN buffer */
	size_t num_neigh;
	int has_11k_neighbor;
};

struct bgscan_learn_11k_data {
	struct wpa_supplicant *wpa_s;
	const struct wpa_ssid *ssid;

	struct dl_list bss;

	int scan_interval;
	int neighbor_rep_interval;
	int short_interval; /* use if signal < threshold */
	int long_interval; /* use if signal > threshold */
	
	int *supp_freqs;
	int probe_idx;
	
	int last_signal;
	int last_snr;
	
	int signal_hysteresis;
	int signal_threshold;
	
	int roam_threshold_rssi;
	int roam_threshold_time;

	int num_fast_scans;
	
	struct os_reltime last_bgscan;
	struct os_reltime last_roam;

	int use_11k;
	int got_neighbor_report;
	int num_11k_neighbors;
};


static void bss_free(struct bgscan_learn_11k_bss *bss)
{
	os_free(bss->neigh);
	os_free(bss);
}


static int bssid_in_array(u8 *array, size_t array_len, const u8 *bssid)
{
	size_t i;

	if (array == NULL || array_len == 0)
		return 0;

	for (i = 0; i < array_len; i++) {
		if (os_memcmp(array + i * ETH_ALEN, bssid, ETH_ALEN) == 0)
			return 1;
	}

	return 0;
}


static int bgscan_learn_11k_add_neighbor(struct bgscan_learn_11k_bss *bss,
				      const u8 *bssid)
{
	u8 *n;

	if (os_memcmp(bss->bssid, bssid, ETH_ALEN) == 0)
		return 0;
	if (bssid_in_array(bss->neigh, bss->num_neigh, bssid))
		return 0;

	n = os_realloc_array(bss->neigh, bss->num_neigh + 1, ETH_ALEN);
	if (n == NULL)
		return 0;

	os_memcpy(n + bss->num_neigh * ETH_ALEN, bssid, ETH_ALEN);
	bss->neigh = n;
	bss->num_neigh++;

	return 1;
}


static struct bgscan_learn_11k_bss * bgscan_learn_11k_get_bss(
	struct bgscan_learn_11k_data *data, const u8 *bssid)
{
	struct bgscan_learn_11k_bss *bss;

	dl_list_for_each(bss, &data->bss, struct bgscan_learn_11k_bss, list) {
		if (os_memcmp(bss->bssid, bssid, ETH_ALEN) == 0)
			return bss;
	}
	return NULL;
}


static int in_array(int *array, int val)
{
	int i;

	if (array == NULL)
		return 0;

	for (i = 0; array[i]; i++) {
		if (array[i] == val)
			return 1;
	}

	return 0;
}


static int * bgscan_learn_11k_get_freqs(struct bgscan_learn_11k_data *data,
				    size_t *count)
{
	struct bgscan_learn_11k_bss *bss;
	int *freqs = NULL, *n;
	*count = 0;

	dl_list_for_each(bss, &data->bss, struct bgscan_learn_11k_bss, list) {
		if (in_array(freqs, bss->freq))
			continue;
		if (data->num_11k_neighbors > 1 && !bss->has_11k_neighbor)
			continue;
		if (!in_array(data->supp_freqs, bss->freq))
			continue;
		n = os_realloc_array(freqs, *count + 2, sizeof(int));
		if (n == NULL)
			return freqs;
		freqs = n;
		freqs[*count] = bss->freq;
		(*count)++;
		freqs[*count] = 0;
	}

	return freqs;
}


static int * bgscan_learn_11k_get_probe_freq(struct bgscan_learn_11k_data *data,
					 int *freqs, size_t count)
{
	int idx, *n;

	if (data->supp_freqs == NULL)
		return freqs;

	idx = data->probe_idx;
	do {
		if (!in_array(freqs, data->supp_freqs[idx])) {
			wpa_printf(MSG_DEBUG, "bgscan learn 11k: Probe new freq "
				   "%u", data->supp_freqs[idx]);
			data->probe_idx = idx + 1;
			if (data->supp_freqs[data->probe_idx] == 0)
				data->probe_idx = 0;
			n = os_realloc_array(freqs, count + 2, sizeof(int));
			if (n == NULL)
				return freqs;
			freqs = n;
			freqs[count] = data->supp_freqs[idx];
			count++;
			freqs[count] = 0;
			break;
		}

		idx++;
		if (data->supp_freqs[idx] == 0)
			idx = 0;
	} while (idx != data->probe_idx);

	return freqs;
}


static void bgscan_learn_11k_scan_timeout(void *eloop_ctx, void *timeout_ctx)
{
	struct bgscan_learn_11k_data *data = eloop_ctx;
	struct wpa_supplicant *wpa_s = data->wpa_s;
	struct wpa_driver_scan_params params;
	int *freqs = NULL;
	size_t count, i;
	char msg[100], *pos;

	os_memset(&params, 0, sizeof(params));
	params.num_ssids = 1;
	params.ssids[0].ssid = data->ssid->ssid;
	params.ssids[0].ssid_len = data->ssid->ssid_len;
	if (data->ssid->scan_freq)
		params.freqs = data->ssid->scan_freq;
	else {
		freqs = bgscan_learn_11k_get_freqs(data, &count);
		wpa_printf(MSG_DEBUG, "bgscan learn 11k: BSSes in this ESS have "
			   "been seen on %u channels", (unsigned int) count);
		if(data->num_11k_neighbors < 2)
			freqs = bgscan_learn_11k_get_probe_freq(data, freqs, count);

		msg[0] = '\0';
		pos = msg;
		for (i = 0; freqs && freqs[i]; i++) {
			int ret;
			ret = os_snprintf(pos, msg + sizeof(msg) - pos, " %d",
					  freqs[i]);
			if (os_snprintf_error(msg + sizeof(msg) - pos, ret))
				break;
			pos += ret;
		}
		pos[0] = '\0';
		wpa_printf(MSG_DEBUG, "bgscan learn 11k: Scanning frequencies:%s",
			   msg);
		params.freqs = freqs;
	}

	wpa_printf(MSG_DEBUG, "bgscan learn 11k: Request a background scan");
	if (wpa_supplicant_trigger_scan(wpa_s, &params)) {
		wpa_printf(MSG_DEBUG, "bgscan learn 11k: Failed to trigger scan");
		eloop_register_timeout(data->scan_interval, 0,
				       bgscan_learn_11k_scan_timeout, data, NULL);
	} else
		os_get_reltime(&data->last_bgscan);
	os_free(freqs);
}

static void bgscan_learn_11k_neighbor_cb(void *ctx, struct wpabuf *neighbor_rep)
{
	struct bgscan_learn_11k_data *bgscan_data = ctx;
	struct wpa_supplicant *wpa_s = bgscan_data->wpa_s;
	struct bgscan_learn_11k_bss *bss;
	int operclass;
	int chan;
	int freq;
	size_t len;
	const u8 *data;

	/*
	 * Neighbor Report element (IEEE P802.11-REVmc/D5.0)
	 * BSSID[6]
	 * BSSID Information[4]
	 * Operating Class[1]
	 * Channel Number[1]
	 * PHY Type[1]
	 * Optional Subelements[variable]
	 */
#define NR_IE_MIN_LEN (ETH_ALEN + 4 + 1 + 1 + 1)

	if (!neighbor_rep || wpabuf_len(neighbor_rep) == 0) {
		wpa_msg_ctrl(wpa_s, MSG_INFO, RRM_EVENT_NEIGHBOR_REP_FAILED);
		goto out;
	}

	bgscan_data->got_neighbor_report = 1;

	data = wpabuf_head_u8(neighbor_rep);
	len = wpabuf_len(neighbor_rep);

	while (len >= 2 + NR_IE_MIN_LEN) {
		const u8 *nr;
		char lci[256 * 2 + 1];
		char civic[256 * 2 + 1];
		u8 nr_len = data[1];
		const u8 *pos = data, *end;

		if (pos[0] != WLAN_EID_NEIGHBOR_REPORT ||
		    nr_len < NR_IE_MIN_LEN) {
			wpa_dbg(wpa_s, MSG_DEBUG,
				"CTRL: Invalid Neighbor Report element: id=%u len=%u",
				data[0], nr_len);
			goto out;
		}

		if (2U + nr_len > len) {
			wpa_dbg(wpa_s, MSG_DEBUG,
				"CTRL: Invalid Neighbor Report element: id=%u len=%zu nr_len=%u",
				data[0], len, nr_len);
			goto out;
		}
		pos += 2;
		end = pos + nr_len;

		nr = pos;
		pos += NR_IE_MIN_LEN;

		lci[0] = '\0';
		civic[0] = '\0';
		while (end - pos > 2) {
			u8 s_id, s_len;

			s_id = *pos++;
			s_len = *pos++;
			if (s_len > end - pos)
				goto out;
			if (s_id == WLAN_EID_MEASURE_REPORT && s_len > 3) {
				/* Measurement Token[1] */
				/* Measurement Report Mode[1] */
				/* Measurement Type[1] */
				/* Measurement Report[variable] */
				switch (pos[2]) {
				case MEASURE_TYPE_LCI:
					if (lci[0])
						break;
					wpa_snprintf_hex(lci, sizeof(lci),
							 pos, s_len);
					break;
				case MEASURE_TYPE_LOCATION_CIVIC:
					if (civic[0])
						break;
					wpa_snprintf_hex(civic, sizeof(civic),
							 pos, s_len);
					break;
				}
			}

			pos += s_len;
		}

		operclass = nr[ETH_ALEN + 4];
		chan = nr[ETH_ALEN + 5];
		freq = ieee80211_chan_to_freq(NULL, operclass, chan);

		if(freq < 0) {
			wpa_printf(MSG_DEBUG, "bgscan learn 11k: unknown operclass %i chan %i", operclass, chan);
		} else {
			bss = bgscan_learn_11k_get_bss(bgscan_data, nr);
			if (bss && bss->freq != freq) {
				wpa_printf(MSG_DEBUG, "bgscan learn 11k: Update BSS "
				   MACSTR " freq %d -> %d",
					   MAC2STR(nr), bss->freq, freq);
				bss->freq = freq;
			} else if (!bss) {
				wpa_printf(MSG_DEBUG, "bgscan learn 11k: Add BSS " MACSTR
					   " freq=%d", MAC2STR(nr), freq);
				bss = os_zalloc(sizeof(*bss));
				if (!bss)
					continue;
				os_memcpy(bss->bssid, nr, ETH_ALEN);
				bss->freq = freq;
				dl_list_add(&bgscan_data->bss, &bss->list);
			}
			bgscan_data->num_11k_neighbors += bss->has_11k_neighbor == 0;
			bss->has_11k_neighbor = 1;
		}
		data = end;
		len -= 2 + nr_len;
	}

out:
	wpabuf_free(neighbor_rep);
}

static void bgscan_learn_11k_neighbor_timeout(void *eloop_ctx, void *timeout_ctx)
{
	struct bgscan_learn_11k_data *data = eloop_ctx;

	if(data->use_11k) {
		eloop_cancel_timeout(bgscan_learn_11k_neighbor_timeout, data, NULL);
		if (data->got_neighbor_report)
			eloop_register_timeout(data->neighbor_rep_interval, 0, bgscan_learn_11k_neighbor_timeout,
					       data, NULL);
		else
			eloop_register_timeout(2, 0, bgscan_learn_11k_neighbor_timeout,
					       data, NULL);

		wpas_rrm_send_neighbor_rep_request(data->wpa_s, NULL, 0, 0, bgscan_learn_11k_neighbor_cb, data);
	}
}

static int * bgscan_learn_11k_get_supp_freqs(struct wpa_supplicant *wpa_s)
{
	struct hostapd_hw_modes *modes;
	int i, j, *freqs = NULL, *n;
	size_t count = 0;

	modes = wpa_s->hw.modes;
	if (modes == NULL)
		return NULL;

	for (i = 0; i < wpa_s->hw.num_modes; i++) {
		for (j = 0; j < modes[i].num_channels; j++) {
			if (modes[i].channels[j].flag & HOSTAPD_CHAN_DISABLED)
				continue;
			/* some hw modes (e.g. 11b & 11g) contain same freqs */
			if (in_array(freqs, modes[i].channels[j].freq))
				continue;
			n = os_realloc_array(freqs, count + 2, sizeof(int));
			if (n == NULL)
				continue;

			freqs = n;
			freqs[count] = modes[i].channels[j].freq;
			count++;
			freqs[count] = 0;
		}
	}

	return freqs;
}

static void * bgscan_learn_11k_init(struct wpa_supplicant *wpa_s,
				const char *params,
				const struct wpa_ssid *ssid)
{
	struct bgscan_learn_11k_data *data;

	data = os_zalloc(sizeof(*data));
	if (data == NULL)
		return NULL;
	dl_list_init(&data->bss);
	data->wpa_s = wpa_s;
	data->ssid = ssid;
	data->short_interval = 5;
	data->signal_threshold = -60;
	data->long_interval = 30; //300;
	data->signal_hysteresis = 4;
	data->roam_threshold_rssi = 10;
	data->roam_threshold_time = 5;
	data->use_11k = wpa_s->rrm.rrm_used;

	wpa_printf(MSG_DEBUG, "bgscan learn 11k: Signal strength threshold %d  "
		   "Short bgscan interval %d  Long bgscan interval %d use 11k %d",
		   data->signal_threshold, data->short_interval,
		   data->long_interval, data->use_11k);

	if (data->signal_threshold &&
	    wpa_drv_signals_monitor(wpa_s, &data->signal_threshold, 1, data->signal_hysteresis) < 0) {
		wpa_printf(MSG_ERROR, "bgscan learn 11k: Failed to enable "
			   "signal strength monitoring");
	}

	data->supp_freqs = bgscan_learn_11k_get_supp_freqs(wpa_s);
	data->scan_interval = data->short_interval;
	data->neighbor_rep_interval = 60;
	if (data->signal_threshold) {
		/* Poll for signal info to set initial scan interval */
		struct wpa_signal_info siginfo;
		if (wpa_drv_signal_poll(wpa_s, &siginfo) == 0 &&
		    siginfo.current_signal >= data->signal_threshold)
			data->scan_interval = data->long_interval;
	}

	eloop_register_timeout(data->scan_interval, 0, bgscan_learn_11k_scan_timeout,
			       data, NULL);

	if(data->use_11k) {
		wpas_rrm_send_neighbor_rep_request(wpa_s, NULL, 0, 0, bgscan_learn_11k_neighbor_cb, data);
		if (data->got_neighbor_report)
			eloop_register_timeout(data->neighbor_rep_interval, 0, bgscan_learn_11k_neighbor_timeout,
					       data, NULL);
		else
			eloop_register_timeout(2, 0, bgscan_learn_11k_neighbor_timeout,
					       data, NULL);
	}

	/*
	 * This function is called immediately after an association, so it is
	 * reasonable to assume that a scan was completed recently. This makes
	 * us skip an immediate new scan in cases where the current signal
	 * level is below the bgscan threshold.
	 */
	os_get_reltime(&data->last_bgscan);

	os_get_reltime(&data->last_roam);

	return data;
}


static void bgscan_learn_11k_deinit(void *priv)
{
	struct bgscan_learn_11k_data *data = priv;
	struct bgscan_learn_11k_bss *bss, *n;

	eloop_cancel_timeout(bgscan_learn_11k_scan_timeout, data, NULL);
	eloop_cancel_timeout(bgscan_learn_11k_neighbor_timeout, data, NULL);
	wpas_rrm_reset(data->wpa_s);
	if (data->signal_threshold)
		wpa_drv_signals_monitor(data->wpa_s, NULL, 0, 0);
	dl_list_for_each_safe(bss, n, &data->bss, struct bgscan_learn_11k_bss,
			      list) {
		dl_list_del(&bss->list);
		bss_free(bss);
	}
	os_free(data->supp_freqs);
	os_free(data);
}


static int bgscan_learn_11k_bss_match(struct bgscan_learn_11k_data *data,
				  struct wpa_scan_res *bss)
{
	const u8 *ie;

	ie = wpa_scan_get_ie(bss, WLAN_EID_SSID);
	if (ie == NULL)
		return 0;

	if (data->ssid->ssid_len != ie[1] ||
	    os_memcmp(data->ssid->ssid, ie + 2, ie[1]) != 0)
		return 0; /* SSID mismatch */

	return 1;
}


static int bgscan_learn_11k_should_roam(struct bgscan_learn_11k_data *data, struct wpa_scan_res *res)
{
	struct os_reltime now;

	if (data->last_snr >= 25) {
		wpa_printf(MSG_DEBUG, "bgscan learn 11k: don't roam, snr too good %d > 25", data->last_snr);
		return 0;
	}

	os_get_reltime(&now);
	if (now.sec <= data->last_roam.sec + data->roam_threshold_time) {
		wpa_printf(MSG_DEBUG, "bgscan learn 11k: don't roam, last roam was %li s ago", now.sec - data->last_roam.sec);
		return 0;
	}

	return data->last_signal <= data->signal_threshold &&
	       res->level > data->last_signal + data->roam_threshold_rssi;
}


static int bgscan_learn_11k_notify_scan(void *priv,
				    struct wpa_scan_results *scan_res)
{
	struct bgscan_learn_11k_data *data = priv;
	size_t i, j;
#define MAX_BSS 50
	u8 bssid[MAX_BSS * ETH_ALEN];
	size_t num_bssid = 0;
	struct wpa_bss *roam_bss = NULL;
	struct wpa_ssid *ssid = data->wpa_s->current_ssid;
	struct wpa_signal_info siginfo;

	wpa_printf(MSG_DEBUG, "bgscan learn 11k: scan result notification");

	if (wpa_drv_signal_poll(data->wpa_s, &siginfo) == 0) {
		data->last_signal = siginfo.current_signal;
		if (siginfo.current_noise != WPA_INVALID_NOISE)
			data->last_snr = siginfo.current_signal - siginfo.current_noise;
		else
			data->last_snr = -1;
	}

	eloop_cancel_timeout(bgscan_learn_11k_scan_timeout, data, NULL);
	eloop_register_timeout(data->scan_interval, 0, bgscan_learn_11k_scan_timeout,
			       data, NULL);

	for (i = 0; i < scan_res->num; i++) {
		struct wpa_scan_res *res = scan_res->res[i];
		if (!bgscan_learn_11k_bss_match(data, res))
			continue;

		if (num_bssid < MAX_BSS) {
			os_memcpy(bssid + num_bssid * ETH_ALEN, res->bssid,
				  ETH_ALEN);
			num_bssid++;
		}
	}
	wpa_printf(MSG_DEBUG, "bgscan learn 11k: %u matching BSSes in scan "
		   "results", (unsigned int) num_bssid);

	for (i = 0; i < scan_res->num; i++) {
		struct wpa_scan_res *res = scan_res->res[i];
		struct bgscan_learn_11k_bss *bss;

		if (!bgscan_learn_11k_bss_match(data, res))
			continue;

		bss = bgscan_learn_11k_get_bss(data, res->bssid);
		if (bss && bss->freq != res->freq) {
			wpa_printf(MSG_DEBUG, "bgscan learn 11k: Update BSS "
			   MACSTR " freq %d -> %d",
				   MAC2STR(res->bssid), bss->freq, res->freq);
			bss->freq = res->freq;
		} else if (!bss) {
			wpa_printf(MSG_DEBUG, "bgscan learn 11k: Add BSS " MACSTR
				   " freq=%d", MAC2STR(res->bssid), res->freq);
			bss = os_zalloc(sizeof(*bss));
			if (!bss)
				continue;
			os_memcpy(bss->bssid, res->bssid, ETH_ALEN);
			bss->freq = res->freq;
			dl_list_add(&data->bss, &bss->list);
		}

		for (j = 0; j < num_bssid; j++) {
			u8 *addr = bssid + j * ETH_ALEN;
			bgscan_learn_11k_add_neighbor(bss, addr);
		}

		if (bgscan_learn_11k_should_roam(data, res)) {
			roam_bss = wpa_bss_get(data->wpa_s, res->bssid, ssid->ssid, ssid->ssid_len);
		}
	}

	if(roam_bss) {
		data->wpa_s->reassociate = 1;
		os_get_reltime(&data->last_roam);
		wpa_supplicant_connect(data->wpa_s, roam_bss, ssid);
	}

	return 1;
}


static void bgscan_learn_11k_notify_beacon_loss(void *priv)
{
	struct bgscan_learn_11k_data *data = priv;

	wpa_printf(MSG_DEBUG, "bgscan learn 11k: beacon loss");

	if(data->num_fast_scans < 3) {
		data->num_fast_scans++;
		wpa_printf(MSG_DEBUG, "bgscan learn 11k: Trigger immediate scan");
		eloop_cancel_timeout(bgscan_learn_11k_scan_timeout, data, NULL);
		eloop_register_timeout(0, 0, bgscan_learn_11k_scan_timeout, data, NULL);
	}
}


static void bgscan_learn_11k_notify_signal_change(void *priv, int above,
					      int current_signal,
					      int current_noise,
					      int current_txrate)
{
	struct bgscan_learn_11k_data *data = priv;
	int scan = 0;
	struct os_reltime now;

	if (data->short_interval == data->long_interval ||
	    data->signal_threshold == 0)
		return;

	wpa_printf(MSG_DEBUG, "bgscan learn 11k: signal level changed "
		   "(above=%d current_signal=%d current_noise=%d "
		   "current_txrate=%d)", above, current_signal,
		   current_noise, current_txrate);
	if (data->scan_interval == data->long_interval && !above) {
		wpa_printf(MSG_DEBUG, "bgscan learn 11k: Start using short bgscan "
			   "interval");
		data->scan_interval = data->short_interval;
		data->num_fast_scans = 0;
		os_get_reltime(&now);
		if (now.sec > data->last_bgscan.sec + 1)
			scan = 1;
	} else if (data->scan_interval == data->short_interval && above) {
		wpa_printf(MSG_DEBUG, "bgscan learn 11k: Start using long bgscan "
			   "interval");
		data->scan_interval = data->long_interval;
		data->num_fast_scans = 0;
		eloop_cancel_timeout(bgscan_learn_11k_scan_timeout, data, NULL);
		eloop_register_timeout(data->scan_interval, 0,
				       bgscan_learn_11k_scan_timeout, data, NULL);
	} else if (!above) {
		const int wait_threshold = data->num_fast_scans > 3 ? 10 : 2;

		/*
		 * Signal dropped further 4 dB. Request a new scan if we have
		 * not yet scanned in a while.
		 */
		os_get_reltime(&now);
		if (now.sec > data->last_bgscan.sec + wait_threshold) {
			data->num_fast_scans++;
			scan = 1;
		}
	}

	if (scan) {
		wpa_printf(MSG_DEBUG, "bgscan learn 11k: Trigger immediate scan");
		eloop_cancel_timeout(bgscan_learn_11k_scan_timeout, data, NULL);
		eloop_register_timeout(0, 0, bgscan_learn_11k_scan_timeout, data, NULL);
	}
}


const struct bgscan_ops bgscan_learn_11k_ops = {
	.name = "learn_11k",
	.init = bgscan_learn_11k_init,
	.deinit = bgscan_learn_11k_deinit,
	.notify_scan = bgscan_learn_11k_notify_scan,
	.notify_beacon_loss = bgscan_learn_11k_notify_beacon_loss,
	.notify_signal_change = bgscan_learn_11k_notify_signal_change,
};
