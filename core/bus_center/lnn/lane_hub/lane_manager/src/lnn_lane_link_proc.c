/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "lnn_lane_link_proc.h"

#include <securec.h>

#include "bus_center_info_key.h"
#include "bus_center_manager.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_lane_def.h"
#include "lnn_lane_link.h"
#include "lnn_lane_score.h"
#include "lnn_local_net_ledger.h"
#include "lnn_net_capability.h"
#include "lnn_network_manager.h"
#include "lnn_node_info.h"
#include "lnn_physical_subnet_manager.h"
#include "softbus_adapter_mem.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_network_utils.h"
#include "softbus_protocol_def.h"
#include "softbus_utils.h"
#include "wifi_device.h"

typedef int32_t (*LaneLinkByType)(uint32_t reqId, const LinkRequest *reqInfo, const LaneLinkCb *callback);

static bool LinkTypeCheck(LaneLinkType type)
{
    LaneLinkType supportList[] = {LANE_P2P, LANE_WLAN_2P4G, LANE_WLAN_5G, LANE_BR};
    uint32_t size = sizeof(supportList) / sizeof(LaneLinkType);
    for (uint32_t i = 0; i < size; i++) {
        if (supportList[i] == type) {
            return true;
        }
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "link type[%d] is not supported", type);
    return false;
}

static int32_t IsLinkRequestValid(const LinkRequest *reqInfo)
{
    if (reqInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "the reqInfo is invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    return SOFTBUS_OK;
}

static int32_t LaneLinkOfBr(uint32_t reqId, const LinkRequest *reqInfo, const LaneLinkCb *callback)
{
    if (IsLinkRequestValid(reqInfo) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    LaneLinkInfo linkInfo;
    (void)memset_s(&linkInfo, sizeof(LaneLinkInfo), 0, sizeof(LaneLinkInfo));
    int32_t ret = LnnGetRemoteStrInfo(reqInfo->peerNetworkId, STRING_KEY_BT_MAC,
        linkInfo.linkInfo.br.brMac, BT_MAC_LEN);
    if (ret != SOFTBUS_OK || strlen(linkInfo.linkInfo.br.brMac) == 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "LnnGetRemoteStrInfo brmac is failed");
        return SOFTBUS_ERR;
    }
    linkInfo.type = LANE_BR;
    callback->OnLaneLinkSuccess(reqId, &linkInfo);
    return SOFTBUS_OK;
}

static int32_t LaneLinkP2pConn(const LinkRequest *reqInfo, uint32_t reqId, const LaneLinkCb *callback)
{
    LnnLaneP2pInfo p2pInfo;
    int32_t ret = LnnConnectP2p(reqInfo->peerNetworkId, reqInfo->pid, &p2pInfo);
    if (ret != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    LaneLinkInfo linkInfo;
    (void)memset_s(&linkInfo, sizeof(LaneLinkInfo), 0, sizeof(LaneLinkInfo));
    linkInfo.type = LANE_P2P;
    linkInfo.linkInfo.p2p.bw = LANE_BW_RANDOM;
    P2pConnInfo *p2p = (P2pConnInfo *)&(linkInfo.linkInfo.p2p.connInfo);
    if (memcpy_s(p2p->localIp, sizeof(p2p->localIp), p2pInfo.localIp, sizeof(p2pInfo.localIp)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "memcpy local failed.");
        return SOFTBUS_MEM_ERR;
    }
    if (memcpy_s(p2p->peerIp, sizeof(p2p->peerIp), p2pInfo.peerIp, sizeof(p2pInfo.peerIp)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "memcpy peer failed.");
        return SOFTBUS_MEM_ERR;
    }
    callback->OnLaneLinkSuccess(reqId, &linkInfo);
    return SOFTBUS_OK;
}

static int32_t LaneLinkOfP2p(uint32_t reqId, const LinkRequest *reqInfo, const LaneLinkCb *callback)
{
    if (IsLinkRequestValid(reqInfo) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    return LaneLinkP2pConn(reqInfo, reqId, callback);
}

static int32_t GetWlanLinkedAttribute(int32_t *channel, bool *is5GBand, bool *isConnected)
{
    LnnWlanLinkedInfo info;
    int32_t ret = LnnGetWlanLinkedInfo(&info);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "LnnGetWlanLinkedInfo fail, ret:%d", ret);
        return SOFTBUS_ERR;
    }
    *isConnected = info.isConnected;

    if (info.band == 1) {
        *is5GBand = false;
    } else {
        *is5GBand = true;
    }

    *channel = SoftBusFrequencyToChannel(info.frequency);
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "wlan current channel is %d", *channel);
    return SOFTBUS_OK;
}

struct SelectProtocolReq {
    LnnNetIfType localIfType;
    ProtocolType selectedProtocol;
    ProtocolType remoteSupporttedProtocol;
    uint8_t currPri;
};

VisitNextChoice FindBestProtocol(const LnnPhysicalSubnet *subnet, void *priv)
{
    if (subnet == NULL || priv == NULL || subnet->protocol == NULL) {
        return CHOICE_FINISH_VISITING;
    }
    struct SelectProtocolReq *req = (struct SelectProtocolReq *)priv;
    if (subnet->status == LNN_SUBNET_RUNNING && (subnet->protocol->supportedNetif & req->localIfType) != 0 &&
        subnet->protocol->pri > req->currPri && (subnet->protocol->id & req->remoteSupporttedProtocol) != 0) {
        req->currPri = subnet->protocol->pri;
        req->selectedProtocol = subnet->protocol->id;
    }

    return CHOICE_VISIT_NEXT;
}

static ProtocolType LnnLaneSelectProtocol(LnnNetIfType ifType, const char *netWorkId, ProtocolType acceptableProtocols)
{
    NodeInfo *remoteNodeInfo = LnnGetNodeInfoById(netWorkId, CATEGORY_NETWORK_ID);
    if (remoteNodeInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "%s: no such network id.", __func__);
        return SOFTBUS_ERR;
    }

    const NodeInfo *localNode = LnnGetLocalNodeInfo();
    if (localNode == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "%s: get local node info failed!", __func__);
        return SOFTBUS_ERR;
    }

    struct SelectProtocolReq req = {
        .localIfType = ifType,
        .remoteSupporttedProtocol = remoteNodeInfo->supportedProtocols & acceptableProtocols,
        .selectedProtocol = 0,
        .currPri = 0,
    };

    if ((req.remoteSupporttedProtocol & LNN_PROTOCOL_NIP) != 0 &&
        (strcmp(remoteNodeInfo->nodeAddress, NODE_ADDR_LOOPBACK) == 0 ||
            strcmp(localNode->nodeAddress, NODE_ADDR_LOOPBACK) == 0)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_WARN, "%s: newip temporarily unavailable!", __func__);
        req.remoteSupporttedProtocol ^= LNN_PROTOCOL_NIP;
    }

    (void)LnnVisitPhysicalSubnet(FindBestProtocol, &req);

    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "LnnLaneSelectProtocol protocol = %lld", req.selectedProtocol);
    return LNN_PROTOCOL_IP;
}

static void FillWlanLinkInfo(
    LaneLinkInfo *linkInfo, bool is5GBand, int32_t channel, uint16_t port, ProtocolType protocol)
{
    if (is5GBand) {
        linkInfo->type = LANE_WLAN_5G;
    } else {
        linkInfo->type = LANE_WLAN_2P4G;
    }
    WlanLinkInfo *wlan = &(linkInfo->linkInfo.wlan);
    wlan->channel = channel;
    wlan->bw = LANE_BW_RANDOM;
    wlan->connInfo.protocol = protocol;
    wlan->connInfo.port = port;
}

static int32_t LaneLinkOfWlan(uint32_t reqId, const LinkRequest *reqInfo, const LaneLinkCb *callback)
{
    if (IsLinkRequestValid(reqInfo) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    LaneLinkInfo linkInfo;
    int32_t port = 0;
    int32_t ret = SOFTBUS_OK;
    ProtocolType acceptableProtocols = LNN_PROTOCOL_ALL;
    if (reqInfo->transType != LANE_T_MSG && reqInfo->transType != LANE_T_BYTE) {
        acceptableProtocols ^= LNN_PROTOCOL_NIP;
    }
    ProtocolType protocol =
        LnnLaneSelectProtocol(LNN_NETIF_TYPE_WLAN | LNN_NETIF_TYPE_ETH, reqInfo->peerNetworkId, acceptableProtocols);
    if (protocol == LNN_PROTOCOL_IP) {
        ret = LnnGetRemoteStrInfo(reqInfo->peerNetworkId, STRING_KEY_WLAN_IP, linkInfo.linkInfo.wlan.connInfo.addr,
            sizeof(linkInfo.linkInfo.wlan.connInfo.addr));
        if (ret != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "LnnGetRemote wlan ip error, ret: %d", ret);
            return SOFTBUS_ERR;
        }
        if (strnlen(linkInfo.linkInfo.wlan.connInfo.addr, sizeof(linkInfo.linkInfo.wlan.connInfo.addr)) == 0 ||
            strncmp(linkInfo.linkInfo.wlan.connInfo.addr, "127.0.0.1", strlen("127.0.0.1")) == 0) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "Wlan ip not found.");
            return SOFTBUS_ERR;
        }
    } else {
        ret = LnnGetRemoteStrInfo(reqInfo->peerNetworkId, STRING_KEY_NODE_ADDR, linkInfo.linkInfo.wlan.connInfo.addr,
            sizeof(linkInfo.linkInfo.wlan.connInfo.addr));
        if (ret != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "LnnGetRemote wlan addr error, ret: %d", ret);
            return SOFTBUS_ERR;
        }
    }
    if (reqInfo->transType == LANE_T_MSG) {
        ret = LnnGetRemoteNumInfo(reqInfo->peerNetworkId, NUM_KEY_PROXY_PORT, &port);
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "LnnGetRemote proxy port");
    } else {
        ret = LnnGetRemoteNumInfo(reqInfo->peerNetworkId, NUM_KEY_SESSION_PORT, &port);
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "LnnGetRemote session port");
    }
    if (ret < 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "LnnGetRemote is failed.");
        return SOFTBUS_ERR;
    }
    int32_t channel = -1;
    bool is5GBand = false;
    bool isConnected = false;
    if (GetWlanLinkedAttribute(&channel, &is5GBand, &isConnected) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get wlan linked info fail");
    }
    if (!isConnected) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "wlan is disconnected");
    }

    FillWlanLinkInfo(&linkInfo, is5GBand, channel, (uint16_t)port, protocol);
    callback->OnLaneLinkSuccess(reqId, &linkInfo);
    return SOFTBUS_OK;
}

static LaneLinkByType g_linkTable[LANE_LINK_TYPE_BUTT] = {
    [LANE_BR] = LaneLinkOfBr,
    [LANE_P2P] = LaneLinkOfP2p,
    [LANE_WLAN_5G] = LaneLinkOfWlan,
    [LANE_WLAN_2P4G] = LaneLinkOfWlan,
};

int32_t BuildLink(const LinkRequest *reqInfo, uint32_t reqId, const LaneLinkCb *callback)
{
    if (IsLinkRequestValid(reqInfo) != SOFTBUS_OK || LinkTypeCheck(reqInfo->linkType) == false) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "the reqInfo or type is invalid.");
        return SOFTBUS_INVALID_PARAM;
    }
    if (callback == NULL || callback->OnLaneLinkSuccess == NULL ||
        callback->OnLaneLinkFail == NULL || callback->OnLaneLinkException == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "the callback is invalid.");
        return SOFTBUS_INVALID_PARAM;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "build link, linktype:%d", reqInfo->linkType);
    if (g_linkTable[reqInfo->linkType](reqId, reqInfo, callback) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "lane link is failed");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

void DestroyLink(uint32_t reqId, LaneLinkType type, int32_t pid,
    const char *mac, const char *networkId)
{
    (void)reqId;
    if (networkId == NULL || mac == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "DestroyLink, the networkId or mac is invalid.");
        return;
    }
    if (type == LANE_P2P) {
        (void)LnnDisconnectP2p(networkId, pid, mac);
    }
}

int32_t InitLaneLink(void)
{
    return SOFTBUS_OK;
}

void DeinitLaneLink(void)
{
    return;
}