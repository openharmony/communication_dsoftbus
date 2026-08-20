/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "lnn_lane_link.h"

#include <securec.h>

#include "anonymizer.h"
#include "bus_center_manager.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_lane_reliability.h"
#include "lnn_local_net_ledger.h"
#include "lnn_log.h"
#include "lnn_physical_subnet_manager.h"
#include "lnn_trans_lane.h"
#include "softbus_adapter_mem.h"
#include "softbus_utils.h"

#define TYPE_BUF_LEN 2
#define LANE_ID_BUF_LEN (UDID_BUF_LEN + UDID_BUF_LEN + TYPE_BUF_LEN)
#define LANE_ID_HASH_LEN 32

typedef int32_t (*LaneLinkByType)(uint32_t reqId, const LinkRequest *reqInfo, const LaneLinkCb *callback);

uint64_t GenerateLaneId(const char *localUdid, const char *remoteUdid, LaneLinkType linkType)
{
    if (localUdid == NULL || remoteUdid == NULL) {
        LNN_LOGE(LNN_LANE, "udid is NULL");
        return SOFTBUS_INVALID_PARAM;
    }
    const char *bigUdid = NULL;
    const char *smallUdid = NULL;
    if (strcmp(localUdid, remoteUdid) >= 0) {
        bigUdid = localUdid;
        smallUdid = remoteUdid;
    } else {
        bigUdid = remoteUdid;
        smallUdid = localUdid;
    }
    uint8_t laneIdParamBytes[LANE_ID_BUF_LEN];
    (void)memset_s(laneIdParamBytes, sizeof(laneIdParamBytes), 0, sizeof(laneIdParamBytes));
    uint64_t laneId = INVALID_LANE_ID;
    uint16_t type = (uint16_t)linkType;
    // sharded copy, LANE_ID_BUF_LEN = UDID_BUF_LEN + UDID_BUF_LEN + TYPE_BUF_LEN
    if (memcpy_s(laneIdParamBytes, UDID_BUF_LEN, bigUdid, strlen(bigUdid)) == EOK &&
        memcpy_s(laneIdParamBytes + UDID_BUF_LEN, UDID_BUF_LEN, smallUdid, strlen(smallUdid)) == EOK &&
        memcpy_s(laneIdParamBytes + UDID_BUF_LEN + UDID_BUF_LEN, TYPE_BUF_LEN, &type, sizeof(type)) == EOK) {
        uint8_t laneIdHash[LANE_ID_HASH_LEN] = {0};
        if (SoftBusGenerateStrHash(laneIdParamBytes, LANE_ID_BUF_LEN, laneIdHash) != SOFTBUS_OK) {
            LNN_LOGE(LNN_LANE, "generate laneId hash fail");
            return INVALID_LANE_ID;
        }
        uint32_t len = sizeof(laneId) <= LANE_ID_HASH_LEN ? sizeof(laneId) : LANE_ID_HASH_LEN;
        if (memcpy_s(&laneId, sizeof(laneId), laneIdHash, len) != EOK) {
            LNN_LOGE(LNN_LANE, "memcpy laneId hash fail");
            return INVALID_LANE_ID;
        }
        char *anonyLocalUdid = NULL;
        char *anonyRemoteUdid = NULL;
        Anonymize(localUdid, &anonyLocalUdid);
        Anonymize(remoteUdid, &anonyRemoteUdid);
        LNN_LOGI(LNN_LANE, "generate laneId=%{public}" PRIu64 " with localUdid=%{public}s,"
            "remoteUdid=%{public}s, linkType=%{public}d",
            laneId, AnonymizeWrapper(anonyLocalUdid), AnonymizeWrapper(anonyRemoteUdid), linkType);
        AnonymizeFree(anonyLocalUdid);
        AnonymizeFree(anonyRemoteUdid);
        return laneId;
    }
    LNN_LOGE(LNN_LANE, "memcpy laneId param bytes fail");
    return INVALID_LANE_ID;
}

static bool LinkTypeCheck(LaneLinkType type)
{
    static const LaneLinkType supportList[] = { LANE_WLAN_2P4G, LANE_WLAN_5G };
    uint32_t size = sizeof(supportList) / sizeof(LaneLinkType);
    for (uint32_t i = 0; i < size; i++) {
        if (supportList[i] == type) {
            return true;
        }
    }
    LNN_LOGE(LNN_LANE, "linkType not supported, linkType=%{public}d", type);
    return false;
}

static int32_t IsLinkRequestValid(const LinkRequest *reqInfo)
{
    if (reqInfo == NULL) {
        LNN_LOGE(LNN_LANE, "reqInfo is nullptr");
        return SOFTBUS_INVALID_PARAM;
    }
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
    NodeInfo remoteNodeInfo;
    (void)memset_s(&remoteNodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    int ret = LnnGetRemoteNodeInfoById(netWorkId, CATEGORY_NETWORK_ID, &remoteNodeInfo);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "no such network id");
        return SOFTBUS_LANE_GET_LEDGER_INFO_ERR;
    }

    const NodeInfo *localNode = LnnGetLocalNodeInfo();
    if (localNode == NULL) {
        LNN_LOGE(LNN_LANE, "get local node info failed!");
        return SOFTBUS_LANE_GET_LEDGER_INFO_ERR;
    }

    struct SelectProtocolReq req = {
        .localIfType = ifType,
        .remoteSupporttedProtocol = remoteNodeInfo.supportedProtocols & acceptableProtocols,
        .selectedProtocol = 0,
        .currPri = 0,
    };

    if ((req.remoteSupporttedProtocol & LNN_PROTOCOL_NIP) != 0 &&
        (strcmp(remoteNodeInfo.nodeAddress, NODE_ADDR_LOOPBACK) == 0 ||
            strcmp(localNode->nodeAddress, NODE_ADDR_LOOPBACK) == 0)) {
        LNN_LOGW(LNN_LANE, "newip temporarily unavailable!");
        req.remoteSupporttedProtocol ^= LNN_PROTOCOL_NIP;
    }

    (void)LnnVisitPhysicalSubnet(FindBestProtocol, &req);
    char *anonyNetworkId = NULL;
    Anonymize(netWorkId, &anonyNetworkId);
    LNN_LOGI(LNN_LANE, "networkId=%{public}s select protocol=%{public}d, pri=%{public}u",
        AnonymizeWrapper(anonyNetworkId), req.selectedProtocol, req.currPri);
    AnonymizeFree(anonyNetworkId);
    if (req.selectedProtocol == 0) {
        req.selectedProtocol = LNN_PROTOCOL_IP;
    }

    return req.selectedProtocol;
}

static int32_t FillWlanLinkInfo(ProtocolType protocol, const LinkRequest *reqInfo, LaneLinkInfo *linkInfo)
{
    int32_t ret = SOFTBUS_LANE_GET_LEDGER_INFO_ERR;
    int32_t port = 0;

    if (reqInfo->isInnerCalled) {
        ret = LnnGetRemoteNumInfoByIfnameIdx(reqInfo->peerNetworkId, NUM_KEY_PROXY_PORT, &port, WLAN_IF);
        LNN_LOGI(LNN_LANE, "get remote proxy port, port=%{public}d, ret=%{public}d", port, ret);
    } else {
        ret = LnnGetRemoteNumInfoByIfnameIdx(reqInfo->peerNetworkId, NUM_KEY_SESSION_PORT, &port, WLAN_IF);
        LNN_LOGI(LNN_LANE, "get remote session port, port=%{public}d, ret=%{public}d", port, ret);
    }
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    linkInfo->type = reqInfo->linkType;
    WlanLinkInfo *wlan = &(linkInfo->linkInfo.wlan);
    wlan->channel = -1;
    wlan->bw = LANE_BW_RANDOM;
    wlan->connInfo.protocol = protocol;
    wlan->connInfo.port = port;
    return SOFTBUS_OK;
}

static int32_t CreateWlanLinkInfo(ProtocolType protocol, const LinkRequest *reqInfo, LaneLinkInfo *linkInfo)
{
    if (LnnGetRemoteStrInfo(reqInfo->peerNetworkId, STRING_KEY_DEV_UDID,
        linkInfo->peerUdid, UDID_BUF_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get udid error");
        return SOFTBUS_LANE_GET_LEDGER_INFO_ERR;
    }
    LNN_LOGI(LNN_LANE, "get remote wlan ip with protocol=%{public}u", protocol);
    if (protocol == LNN_PROTOCOL_IP) {
        if (LnnGetRemoteStrInfoByIfnameIdx(reqInfo->peerNetworkId, STRING_KEY_IP, linkInfo->linkInfo.wlan.connInfo.addr,
            sizeof(linkInfo->linkInfo.wlan.connInfo.addr), WLAN_IF) != SOFTBUS_OK) {
            LNN_LOGE(LNN_LANE, "get remote wlan ip fail");
            return SOFTBUS_LANE_GET_LEDGER_INFO_ERR;
        }
        if (strnlen(linkInfo->linkInfo.wlan.connInfo.addr, sizeof(linkInfo->linkInfo.wlan.connInfo.addr)) == 0 ||
            strnlen(linkInfo->linkInfo.wlan.connInfo.addr,
            sizeof(linkInfo->linkInfo.wlan.connInfo.addr)) == MAX_SOCKET_ADDR_LEN ||
            strncmp(linkInfo->linkInfo.wlan.connInfo.addr, "127.0.0.1", strlen("127.0.0.1")) == 0) {
            LNN_LOGE(LNN_LANE, "Wlan ip not found");
            return SOFTBUS_LANE_GET_LEDGER_INFO_ERR;
        }
    } else {
        if (LnnGetRemoteStrInfo(reqInfo->peerNetworkId, STRING_KEY_NODE_ADDR, linkInfo->linkInfo.wlan.connInfo.addr,
            sizeof(linkInfo->linkInfo.wlan.connInfo.addr)) != SOFTBUS_OK) {
            LNN_LOGE(LNN_LANE, "get remote wlan ip fail");
            return SOFTBUS_LANE_GET_LEDGER_INFO_ERR;
        }
    }
    return FillWlanLinkInfo(protocol, reqInfo, linkInfo);
}

static int32_t LaneLinkOfWlan(uint32_t reqId, const LinkRequest *reqInfo, const LaneLinkCb *callback)
{
    LaneLinkInfo linkInfo;
    ProtocolType acceptableProtocols = LNN_PROTOCOL_ALL ^ LNN_PROTOCOL_NIP;
    if (reqInfo->transType == LANE_T_MSG || reqInfo->transType == LANE_T_BYTE) {
        acceptableProtocols |= LNN_PROTOCOL_NIP;
    }
    acceptableProtocols = acceptableProtocols & reqInfo->acceptableProtocols;
    ProtocolType protocol =
        LnnLaneSelectProtocol(LNN_NETIF_TYPE_WLAN | LNN_NETIF_TYPE_ETH, reqInfo->peerNetworkId, acceptableProtocols);
    if (protocol == 0) {
        LNN_LOGE(LNN_LANE, "protocal is invalid!");
        return SOFTBUS_LANE_GET_LEDGER_INFO_ERR;
    }
    int32_t ret = CreateWlanLinkInfo(protocol, reqInfo, &linkInfo);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "CreateWlanLinkInfo fail, laneReqId=%{public}u", reqId);
        return ret;
    }
    ret = LaneDetectReliability(reqId, &linkInfo, callback);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lane detect reliability fail, laneReqId=%{public}u", reqId);
        return ret;
    }
    return SOFTBUS_OK;
}

static LaneLinkByType g_linkTable[LANE_LINK_TYPE_BUTT] = {
    [LANE_WLAN_2P4G] = LaneLinkOfWlan,
    [LANE_WLAN_5G] = LaneLinkOfWlan,
};

int32_t BuildLink(const LinkRequest *reqInfo, uint32_t reqId, const LaneLinkCb *callback)
{
    if (IsLinkRequestValid(reqInfo) != SOFTBUS_OK || !LinkTypeCheck(reqInfo->linkType)) {
        LNN_LOGE(LNN_LANE, "the reqInfo or type is invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    if (callback == NULL || callback->onLaneLinkSuccess == NULL ||
        callback->onLaneLinkFail == NULL) {
        LNN_LOGE(LNN_LANE, "the callback is invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    char *anonyNetworkId = NULL;
    Anonymize(reqInfo->peerNetworkId, &anonyNetworkId);
    LNN_LOGI(LNN_LANE, "build link, linktype=%{public}d, laneReqId=%{public}u, peerNetworkId=%{public}s",
        reqInfo->linkType, reqId, AnonymizeWrapper(anonyNetworkId));
    AnonymizeFree(anonyNetworkId);
    int32_t ret = g_linkTable[reqInfo->linkType](reqId, reqInfo, callback);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lane link is failed");
        return ret;
    }
    return SOFTBUS_OK;
}

int32_t DestroyLink(const char *networkId, uint32_t laneReqId, LaneLinkType type)
{
    LNN_LOGI(LNN_LANE, "destroy link=%{public}d, laneReqId=%{public}u", type, laneReqId);
    (void)networkId;
    return SOFTBUS_OK;
}
