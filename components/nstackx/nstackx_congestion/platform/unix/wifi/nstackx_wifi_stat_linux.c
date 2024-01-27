/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "nstackx_wifi_stat_linux.h"

#include <ctype.h>
#include <errno.h>

#include <netlink/attr.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/genl.h>
#include <netlink/socket.h>

#include <linux/socket.h>

#include "nstackx_congestion.h"
#include "nstackx_error.h"
#include "nstackx_log.h"
#include "securec.h"

#define TAG "nStackXCongestion"
#define NETLINK_SOCKET_BUFFER_SIZE 8192

static inline int32_t CheckNl80211MsgBss(struct nlattr *bss[])
{
    if (!bss[NL80211_BSS_BSSID] || !bss[NL80211_BSS_STATUS]) {
        return NSTACKX_EFAILED;
    }
    return NSTACKX_EOK;
}

static inline int32_t CheckNl80211MsgBssStatus(struct nlattr *bss[])
{
    switch (nla_get_u32(bss[NL80211_BSS_STATUS])) {
        case NL80211_BSS_STATUS_ASSOCIATED:
        case NL80211_BSS_STATUS_IBSS_JOINED:
            break;
        default:
            return NSTACKX_EFAILED;
    }
    return NSTACKX_EOK;
}

static int32_t GetScanInfo(struct nl_msg *msg, void *arg)
{
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));

    struct nlattr *tb[NL80211_ATTR_MAX + 1] = {0};
    struct nlattr *bss[NL80211_BSS_MAX + 1] = {0};
    struct nla_policy bssPolicy[NL80211_BSS_MAX + 1] = {
        [NL80211_BSS_FREQUENCY] = { .type = NLA_U32 },
        [NL80211_BSS_BSSID] = { },
        [NL80211_BSS_STATUS] = { .type = NLA_U32 },
    };

    int32_t ret = nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);
    if (ret < 0) {
        LOGE(TAG, "nla_parse failed! %d", ret);
        return NL_SKIP;
    }

    if (!tb[NL80211_ATTR_BSS] || nla_parse_nested(bss, NL80211_BSS_MAX, tb[NL80211_ATTR_BSS], bssPolicy) ||
        CheckNl80211MsgBss(bss) != NSTACKX_EOK) {
        return NL_SKIP;
    }

    if (CheckNl80211MsgBssStatus(bss) != NSTACKX_EOK) {
        return NL_SKIP;
    }

    CallbackResult *cbRes = (CallbackResult *)arg;
    if (memcpy_s(cbRes->mac, ETH_ALEN, nla_data(bss[NL80211_BSS_BSSID]), ETH_ALEN) != NSTACKX_EOK) {
        LOGE(TAG, "memcpy_s failed");
    }
    return NL_SKIP;
}

static inline uint32_t ResolveBitrateInfoInner(struct nlattr *rInfo[])
{
    uint32_t rate;
    if (rInfo[NL80211_RATE_INFO_BITRATE32])
        rate = nla_get_u32(rInfo[NL80211_RATE_INFO_BITRATE32]);
    else if (rInfo[NL80211_RATE_INFO_BITRATE])
        rate = (uint32_t)nla_get_u16(rInfo[NL80211_RATE_INFO_BITRATE]);
    else
        rate = 0;
    return rate;
}

static int32_t ResolveBitrateInfo(struct nlattr *bitrateAttr, WifiRateInfo *rateInfo)
{
    struct nlattr *rInfo[NL80211_RATE_INFO_MAX + 1] = {0};
    static struct nla_policy ratePolicy[NL80211_RATE_INFO_MAX + 1] = {
        [NL80211_RATE_INFO_BITRATE] = { .type = NLA_U16 },
        [NL80211_RATE_INFO_BITRATE32] = { .type = NLA_U32 },
        [NL80211_RATE_INFO_MCS] = { .type = NLA_U8 },
        [NL80211_RATE_INFO_40_MHZ_WIDTH] = { .type = NLA_FLAG },
    };

    if (nla_parse_nested(rInfo, NL80211_RATE_INFO_MAX, bitrateAttr, ratePolicy)) {
        LOGE(TAG, "nla_parse_nested failed");
        return NSTACKX_EFAILED;
    }
    rateInfo->rateBitrate = ResolveBitrateInfoInner(rInfo);
    return NSTACKX_EOK;
}

static inline void GetStationInfoRateSignal(WifiStationInfo *wifiStationInfo, struct nlattr *sinfo[])
{
    if (sinfo[NL80211_STA_INFO_SIGNAL]) {
        wifiStationInfo->signal = (int32_t)((int8_t)nla_get_u8(sinfo[NL80211_STA_INFO_SIGNAL]));
    }
}

static inline void GetStationInfoRateRx(WifiStationInfo *wifiStationInfo, struct nlattr *sinfo[])
{
    if (sinfo[NL80211_STA_INFO_RX_BITRATE]) {
        WifiRateInfo rxRateInfo;
        if (ResolveBitrateInfo(sinfo[NL80211_STA_INFO_RX_BITRATE], &rxRateInfo) == NSTACKX_EOK) {
            wifiStationInfo->rxRate = rxRateInfo.rateBitrate / WIFI_NEGO_RATE_ACCURACY;
        }
    }
}

static inline void GetStationInfoRateTx(WifiStationInfo *wifiStationInfo, struct nlattr *sinfo[])
{
    if (sinfo[NL80211_STA_INFO_TX_BITRATE]) {
        WifiRateInfo txRateInfo;
        if (ResolveBitrateInfo(sinfo[NL80211_STA_INFO_TX_BITRATE], &txRateInfo) == NSTACKX_EOK) {
            wifiStationInfo->txRate = txRateInfo.rateBitrate / WIFI_NEGO_RATE_ACCURACY;
        }
    }
}

static void GetStationInfoRate(WifiStationInfo *wifiStationInfo, struct nlattr *sinfo[])
{
    GetStationInfoRateSignal(wifiStationInfo, sinfo);
    GetStationInfoRateRx(wifiStationInfo, sinfo);
    GetStationInfoRateTx(wifiStationInfo, sinfo);
    return;
}

static int32_t GetStationInfo(struct nl_msg *msg, void *arg)
{
    struct nlattr *tb[NL80211_ATTR_MAX + 1] = {0};

    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    struct nlattr *sinfo[NL80211_STA_INFO_MAX + 1] = {0};
    static struct nla_policy statsPolicy[NL80211_STA_INFO_MAX + 1] = {
        [NL80211_STA_INFO_SIGNAL] = { .type = NLA_U8 },
        [NL80211_STA_INFO_RX_BITRATE] = { .type = NLA_NESTED },
        [NL80211_STA_INFO_TX_BITRATE] = { .type = NLA_NESTED },
    };

    int32_t ret = nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);
    if (ret < 0) {
        LOGE(TAG, "nla_parse failed! %d", ret);
        return NL_SKIP;
    }

    if (!tb[NL80211_ATTR_STA_INFO] ||
        nla_parse_nested(sinfo, NL80211_STA_INFO_MAX, tb[NL80211_ATTR_STA_INFO], statsPolicy)) {
        LOGE(TAG, "sta stats missing! or failed to parse nested attributes!\n");
        return NL_SKIP;
    }

    CallbackResult *cbRes = (CallbackResult *)arg;
    WifiStationInfo *wifiStationInfo = &cbRes->wifiStationInfo;
    GetStationInfoRate(wifiStationInfo, sinfo);
    return NL_SKIP;
}

int32_t Nl80211Msg(Nl80211MsgSet *nl80211MsgSet)
{
    struct nl_msg *msg = nlmsg_alloc();

    if (!msg) {
        LOGE(TAG, "nlmsg_alloc failed.");
        return NSTACKX_ENOMEM;
    }

    void *fret = genlmsg_put(msg, 0, 0, nl80211MsgSet->nlDevInfo.nl80211_id, 0, nl80211MsgSet->flags,
                             nl80211MsgSet->cmd, 0);
    if (fret == NULL) {
        LOGE(TAG, "genlmsg_put failed");
        goto FAIL_EXIT;
    }

    int32_t ret = nla_put_u32(msg, NL80211_ATTR_IFINDEX, nl80211MsgSet->nlDevInfo.if_index);
    if (ret < 0) {
        LOGE(TAG, "nla_put_u32 failed");
        goto FAIL_EXIT;
    }

    if (nl80211MsgSet->handle != NULL) {
        nl80211MsgSet->handle(msg, &nl80211MsgSet->handleParam);
    }

    int32_t err = nl_send_auto_complete(nl80211MsgSet->nlDevInfo.nl_sock, msg);
    if (err < 0) {
        LOGE(TAG, "send failed.%d", err);
        goto FAIL_EXIT;
    }

    struct nl_cb *cb = nl_cb_alloc(NL_CB_DEBUG);
    if (cb == NULL) {
        LOGE(TAG, "nl_cb alloc failed");
        goto FAIL_EXIT;
    }

    ret = nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, nl80211MsgSet->func, &nl80211MsgSet->cbRes);
    if (ret < 0) {
        LOGE(TAG, "nl_cb_set failed! %d", ret);
        nl_cb_put(cb);
        goto FAIL_EXIT;
    }

    ret = nl_recvmsgs(nl80211MsgSet->nlDevInfo.nl_sock, cb);
    if (ret < 0 || errno) {
        LOGE(TAG, "err .%d errno %d ret is %d", err, errno, ret);
        nl_cb_put(cb);
        goto FAIL_EXIT;
    }

    nl_cb_put(cb);
    nlmsg_free(msg);
    return NSTACKX_EOK;

FAIL_EXIT:
    nlmsg_free(msg);
    return NSTACKX_EFAILED;
}

int32_t GetStationHandler(struct nl_msg *msg, HandleParam *handleParam)
{
    NLA_PUT(msg, NL80211_ATTR_MAC, ETH_ALEN, handleParam->mac);
    return 0;
}

int32_t GetWifiStaInfo(const NLDevInfo nlDevInfo, WifiStationInfo *wifiStationInfo)
{
    Nl80211MsgSet nl80211MsgSet;
    nl80211MsgSet.nlDevInfo.nl_sock = nlDevInfo.nl_sock;
    nl80211MsgSet.nlDevInfo.if_index = nlDevInfo.if_index;
    nl80211MsgSet.nlDevInfo.nl80211_id = nlDevInfo.nl80211_id;

    nl80211MsgSet.cmd = NL80211_CMD_GET_SCAN;
    nl80211MsgSet.flags = NLM_F_DUMP;
    nl80211MsgSet.handle = NULL;
    nl80211MsgSet.func = GetScanInfo;
    (void)memset_s(&nl80211MsgSet.cbRes, sizeof(nl80211MsgSet.cbRes), 0, sizeof(nl80211MsgSet.cbRes));
    int32_t ret = Nl80211Msg(&nl80211MsgSet);
    if (ret != NSTACKX_EOK) {
        return ret;
    }

    char macAddr[ETH_ALEN];
    ret = memcpy_s(macAddr, ETH_ALEN, nl80211MsgSet.cbRes.mac, ETH_ALEN);
    if (ret != NSTACKX_EOK) {
        return ret;
    }

    nl80211MsgSet.cmd = NL80211_CMD_GET_STATION;
    nl80211MsgSet.flags = 0;
    nl80211MsgSet.handle = GetStationHandler;
    nl80211MsgSet.func = GetStationInfo;
    nl80211MsgSet.handleParam.mac = macAddr;
    ret = Nl80211Msg(&nl80211MsgSet);
    if (ret == NSTACKX_EOK) {
        ret = memcpy_s(wifiStationInfo, sizeof(WifiStationInfo),
            &nl80211MsgSet.cbRes.wifiStationInfo, sizeof(WifiStationInfo));
    }
    return ret;
}

static int32_t GetNlDevInfo(NLDevInfo *nlDevInfo, const char *devName)
{
    nlDevInfo->nl_sock = nl_socket_alloc();
    if (nlDevInfo->nl_sock == NULL) {
        LOGE(TAG, "create netlink.error no is %d", errno);
        return NSTACKX_EFAILED;
    }
    if (genl_connect(nlDevInfo->nl_sock)) {
        LOGE(TAG, "Failed to connect to generic netlink.error no is %d", errno);
        goto FAIL_EXIT;
    }

    nl_socket_enable_msg_peek(nlDevInfo->nl_sock);
    int32_t ret = nl_socket_set_buffer_size(nlDevInfo->nl_sock, NETLINK_SOCKET_BUFFER_SIZE, NETLINK_SOCKET_BUFFER_SIZE);
    if (ret < 0) {
        goto FAIL_EXIT;
    }

    int32_t err = 1;
    ret = setsockopt(nl_socket_get_fd(nlDevInfo->nl_sock), SOL_NETLINK, NETLINK_EXT_ACK, &err, sizeof(err));
    if (ret == -1) {
        goto FAIL_EXIT;
    }

    nlDevInfo->nl80211_id = genl_ctrl_resolve(nlDevInfo->nl_sock, "nl80211");
    if (nlDevInfo->nl80211_id < 0) {
        LOGE(TAG, "nl80211 id get fail.");
        goto FAIL_EXIT;
    }

    nlDevInfo->if_index = if_nametoindex(devName);
    if (nlDevInfo->if_index == 0) {
        LOGE(TAG, "if_index is 0 dev is not exist");
        goto FAIL_EXIT;
    }
    return NSTACKX_EOK;

FAIL_EXIT:
    nl_socket_free(nlDevInfo->nl_sock);
    return NSTACKX_EFAILED;
}

static void FreeNlDevInfo(NLDevInfo *nlDevInfo)
{
    if (nlDevInfo->nl_sock != NULL) {
        nl_socket_free(nlDevInfo->nl_sock);
        nlDevInfo->nl_sock = NULL;
    }
}

int32_t GetWifiInfoFromLinux(const char *devName, WifiStationInfo *wifiStationInfo)
{
    NLDevInfo nlDevInfo;
    (void)memset_s(&nlDevInfo, sizeof(nlDevInfo), 0, sizeof(nlDevInfo));
    int32_t ret = GetNlDevInfo(&nlDevInfo, devName);
    if (ret != NSTACKX_EOK) {
        LOGE(TAG, "GetNlDevInfo failed.error no is %d", errno);
        return ret;
    }

    ret = GetWifiStaInfo(nlDevInfo, wifiStationInfo);
    if (ret != NSTACKX_EOK || CheckWlanNegoRateValid(wifiStationInfo->txRate) != NSTACKX_EOK) {
        LOGE(TAG, "getWifiStaInfo fail.or wifiStationInfo->txRate %u", wifiStationInfo->txRate);
        ret = NSTACKX_EFAILED;
        goto FAIL_EXIT;
    }

FAIL_EXIT:
    FreeNlDevInfo(&nlDevInfo);
    return ret;
}
