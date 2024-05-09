/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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
#include "lnn_lane.h"
#include "lnn_lane_common.h"
#include "lnn_lane_def.h"
#include "lnn_lane_score.h"
#include "lnn_lane_link_p2p.h"
#include "lnn_lane_reliability.h"
#include "lnn_local_net_ledger.h"
#include "lnn_log.h"
#include "lnn_net_capability.h"
#include "lnn_network_manager.h"
#include "lnn_node_info.h"
#include "lnn_physical_subnet_manager.h"
#include "lnn_trans_lane.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_crypto.h"
#include "softbus_conn_ble_connection.h"
#include "softbus_conn_ble_manager.h"
#include "softbus_network_utils.h"
#include "softbus_protocol_def.h"

#define IF_NAME_BR  "br0"
#define IF_NAME_BLE "ble0"
#define IF_NAME_P2P "p2p0"
#define IF_NAME_HML "chba0"
#define TYPE_BUF_LEN 2
#define LANE_ID_BUF_LEN (UDID_BUF_LEN + UDID_BUF_LEN + TYPE_BUF_LEN)
#define LANE_ID_HASH_LEN 32

typedef int32_t (*LaneLinkByType)(uint32_t reqId, const LinkRequest *reqInfo, const LaneLinkCb *callback);

static SoftBusList g_laneResource;

static int32_t LaneLock(void)
{
    return SoftBusMutexLock(&g_laneResource.lock);
}

static void LaneUnlock(void)
{
    (void)SoftBusMutexUnlock(&g_laneResource.lock);
}

uint64_t ApplyLaneId(const char *localUdid, const char *remoteUdid, LaneLinkType linkType)
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
        if (memcpy_s(&laneId, sizeof(laneId), laneIdHash, sizeof(laneId)) != EOK) {
            LNN_LOGE(LNN_LANE, "memcpy laneId hash fail");
            return INVALID_LANE_ID;
        }
        char *anonyLocalUdid = NULL;
        char *anonyRemoteUdid = NULL;
        Anonymize(localUdid, &anonyLocalUdid);
        Anonymize(remoteUdid, &anonyRemoteUdid);
        LNN_LOGI(LNN_LANE, "apply laneId=%{public}" PRIu64 " with localUdid=%{public}s,"
            "remoteUdid=%{public}s, linkType=%{public}d", laneId, anonyLocalUdid, anonyRemoteUdid, linkType);
        AnonymizeFree(anonyLocalUdid);
        AnonymizeFree(anonyRemoteUdid);
        return laneId;
    }
    LNN_LOGE(LNN_LANE, "memcpy laneId param bytes fail");
    return INVALID_LANE_ID;
}

static bool isValidLinkAddr(const LaneResource *resourceItem, const LaneLinkInfo *linkInfoItem)
{
    switch (resourceItem->link.type) {
        case LANE_BR:
            if (strncmp(resourceItem->link.linkInfo.br.brMac, linkInfoItem->linkInfo.br.brMac, BT_MAC_LEN) != 0) {
                break;
            }
            return true;
        case LANE_BLE:
        case LANE_COC:
            if (strncmp(resourceItem->link.linkInfo.ble.bleMac, linkInfoItem->linkInfo.ble.bleMac, BT_MAC_LEN) != 0) {
                break;
            }
            return true;
        case LANE_P2P:
        case LANE_HML:
            if (strncmp(resourceItem->link.linkInfo.p2p.connInfo.peerIp,
                linkInfoItem->linkInfo.p2p.connInfo.peerIp, IP_LEN) != 0) {
                break;
            }
            return true;
        case LANE_BLE_DIRECT:
        case LANE_COC_DIRECT:
            if (strncmp(resourceItem->link.linkInfo.bleDirect.networkId, linkInfoItem->linkInfo.bleDirect.networkId,
                NETWORK_ID_BUF_LEN) != 0) {
                break;
            }
            return true;
        case LANE_WLAN_5G:
        case LANE_WLAN_2P4G:
        case LANE_ETH:
            if (strncmp(resourceItem->link.linkInfo.wlan.connInfo.addr,
                linkInfoItem->linkInfo.wlan.connInfo.addr, MAX_SOCKET_ADDR_LEN) != 0) {
                break;
            }
            return true;
        default:
            LNN_LOGE(LNN_LANE, "invalid linkType=%{public}d", resourceItem->link.type);
            return false;
    }
    LNN_LOGE(LNN_LANE, "lane resource is different form input link addr, laneId=%{public}" PRIu64 "",
        resourceItem->laneId);
    return false;
}

static LaneResource* GetValidLaneResource(const LaneLinkInfo *linkInfoItem)
{
    LaneResource *item = NULL;
    LaneResource *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_laneResource.list, LaneResource, node) {
        if (linkInfoItem->type == item->link.type &&
            strncmp(item->link.peerUdid, linkInfoItem->peerUdid, UDID_BUF_LEN) == 0 &&
            isValidLinkAddr(item, linkInfoItem)) {
            return item;
        }
    }
    return NULL;
}

static int32_t CreateNewLaneResource(const LaneLinkInfo *linkInfo, uint64_t laneId, bool isServerSide)
{
    LaneResource* resourceItem = (LaneResource *)SoftBusCalloc(sizeof(LaneResource));
    if (resourceItem == NULL) {
        LNN_LOGE(LNN_LANE, "resourceItem malloc fail");
        return SOFTBUS_MALLOC_ERR;
    }
    if (memcpy_s(&(resourceItem->link), sizeof(LaneLinkInfo), linkInfo, sizeof(LaneLinkInfo)) != EOK) {
        LNN_LOGE(LNN_LANE, "link info convert to lane resource fail");
        SoftBusFree(resourceItem);
        return SOFTBUS_MEM_ERR;
    }
    resourceItem->laneId = laneId;
    resourceItem->isServerSide = isServerSide;
    resourceItem->clientRef = isServerSide ? 0 : 1;
    if (LaneLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lane lock fail");
        SoftBusFree(resourceItem);
        return SOFTBUS_LOCK_ERR;
    }
    ListAdd(&g_laneResource.list, &resourceItem->node);
    g_laneResource.cnt++;
    LaneUnlock();
    LNN_LOGI(LNN_LANE, "create new laneId=%{public}" PRIu64 " to resource pool succ, isServerSide=%{public}u,"
        "clientRef=%{public}u", resourceItem->laneId, isServerSide, resourceItem->clientRef);
    return SOFTBUS_OK;
}

int32_t AddLaneResourceToPool(const LaneLinkInfo *linkInfo, uint64_t laneId, bool isServerSide)
{
    if (linkInfo == NULL || laneId == INVALID_LANE_ID) {
        LNN_LOGE(LNN_LANE, "linkInfo is nullptr");
        return SOFTBUS_INVALID_PARAM;
    }
    if (LaneLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lane lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    LaneResource* resourceItem = GetValidLaneResource(linkInfo);
    if (resourceItem != NULL) {
        if (isServerSide) {
            if (resourceItem->isServerSide) {
                LNN_LOGE(LNN_LANE, "server laneId=%{public}" PRIu64 " is existed, add server lane resource fail",
                resourceItem->laneId);
                LaneUnlock();
                return SOFTBUS_LANE_TRIGGER_LINK_FAIL;
            } else {
                resourceItem->isServerSide = true;
                LNN_LOGI(LNN_LANE, "add server laneId=%{public}" PRIu64 " to resource pool succ", resourceItem->laneId);
                LaneUnlock();
                return SOFTBUS_OK;
            }
        } else {
            resourceItem->clientRef++;
            LNN_LOGI(LNN_LANE, "add client laneId=%{public}" PRIu64 " to resource pool succ, clientRef=%{public}u",
                resourceItem->laneId, resourceItem->clientRef);
            LaneUnlock();
            return SOFTBUS_OK;
        }
    }
    LaneUnlock();
    return CreateNewLaneResource(linkInfo, laneId, isServerSide);
}

static bool IsNeedDelResource(uint64_t laneId, bool isServerSide, LaneResource *item)
{
    if (item->laneId != laneId) {
        return false;
    }
    uint32_t ref = 0;
    bool isServer = false;
    if (isServerSide) {
        ref = item->clientRef;
        if (item->clientRef == 0) {
            ListDelete(&item->node);
            SoftBusFree(item);
            g_laneResource.cnt--;
        } else {
            item->isServerSide = false;
        }
    } else {
        isServer = item->isServerSide;
        ref = --item->clientRef;
        if (!isServer && ref == 0) {
            ListDelete(&item->node);
            SoftBusFree(item);
            g_laneResource.cnt--;
        }
    }
    LNN_LOGI(LNN_LANE, "del laneId=%{public}" PRIu64 " resource, isServer=%{public}d, clientRef=%{public}u",
        laneId, isServer, ref);
    return true;
}

int32_t DelLaneResourceByLaneId(uint64_t laneId, bool isServerSide)
{
    if (LaneLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lane lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    LNN_LOGI(LNN_LANE, "start to del laneId=%{public}" PRIu64 " resource, isServer=%{public}d ",
            laneId, isServerSide);
    LaneResource *next = NULL;
    LaneResource *item = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_laneResource.list, LaneResource, node) {
        if (IsNeedDelResource(laneId, isServerSide, item)) {
            LaneUnlock();
            return SOFTBUS_OK;
        }
    }
    LaneUnlock();
    LNN_LOGI(LNN_LANE, "not found laneId=%{public}" PRIu64 " resource when del", laneId);
    return SOFTBUS_OK;
}

int32_t ClearLaneResourceByLaneId(uint64_t laneId)
{
    if (LaneLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lane lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    LaneResource *next = NULL;
    LaneResource *item = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_laneResource.list, LaneResource, node) {
        if (item->laneId == laneId) {
            ListDelete(&item->node);
            SoftBusFree(item);
            g_laneResource.cnt--;
            LaneUnlock();
            LNN_LOGI(LNN_LANE, "clear laneId=%{public}" PRIu64 " resource succ", laneId);
            return SOFTBUS_OK;
        }
    }
    LaneUnlock();
    LNN_LOGI(LNN_LANE, "not found laneId=%{public}" PRIu64 " resource when clear", laneId);
    return SOFTBUS_OK;
}

static bool LinkTypeCheck(LaneLinkType type)
{
    static const LaneLinkType supportList[] = { LANE_P2P, LANE_HML, LANE_WLAN_2P4G, LANE_WLAN_5G, LANE_BR, LANE_BLE,
        LANE_BLE_DIRECT, LANE_P2P_REUSE, LANE_COC, LANE_COC_DIRECT, LANE_BLE_REUSE };
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

int32_t FindLaneResourceByLinkType(const char *peerUdid, LaneLinkType type, LaneResource *resource)
{
    if (peerUdid == NULL || type >= LANE_LINK_TYPE_BUTT || resource == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (LaneLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lane lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    LaneResource *item = NULL;
    LaneResource *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_laneResource.list, LaneResource, node) {
        if (strcmp(peerUdid, item->link.peerUdid) == 0 && type == item->link.type) {
            if (memcpy_s(resource, sizeof(LaneResource), item, sizeof(LaneResource)) != EOK) {
                LNN_LOGE(LNN_LANE, "memcpy lane resource fail");
                LaneUnlock();
                return SOFTBUS_MEM_ERR;
            }
            LaneUnlock();
            return SOFTBUS_OK;
        }
    }
    LaneUnlock();
    char *anonyPeerUdid = NULL;
    Anonymize(peerUdid, &anonyPeerUdid);
    LNN_LOGE(LNN_LANE, "no find lane resource by linktype=%{public}d, peerUdid=%{public}s", type, anonyPeerUdid);
    AnonymizeFree(anonyPeerUdid);
    return SOFTBUS_ERR;
}

int32_t FindLaneResourceByLinkAddr(const LaneLinkInfo *info, LaneResource *resource)
{
    if (info == NULL || resource == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (LaneLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lane lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    LaneResource* item = GetValidLaneResource(info);
    if (item == NULL) {
        LNN_LOGE(LNN_LANE, "no found lane resource by link info");
        LaneUnlock();
        return SOFTBUS_ERR;
    }
    if (memcpy_s(resource, sizeof(LaneResource), item, sizeof(LaneResource)) != EOK) {
        LNN_LOGE(LNN_LANE, "memcpy lane resource fail");
        LaneUnlock();
        return SOFTBUS_MEM_ERR;
    }
    LaneUnlock();
    return SOFTBUS_OK;
}

int32_t FindLaneResourceByLaneId(uint64_t laneId, LaneResource *resource)
{
    if (resource == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (LaneLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lane lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    LaneResource *item = NULL;
    LaneResource *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_laneResource.list, LaneResource, node) {
        if (item->laneId == laneId) {
            if (memcpy_s(resource, sizeof(LaneResource), item, sizeof(LaneResource)) != EOK) {
                LNN_LOGE(LNN_LANE, "memcpy lane resource fail");
                LaneUnlock();
                return SOFTBUS_MEM_ERR;
            }
            LaneUnlock();
            return SOFTBUS_OK;
        }
    }
    LaneUnlock();
    LNN_LOGE(LNN_LANE, "no found lane resource by laneId=%{public}" PRIu64 "", laneId);
    return SOFTBUS_ERR;
}

static int32_t LaneLinkOfBr(uint32_t reqId, const LinkRequest *reqInfo, const LaneLinkCb *callback)
{
    LaneLinkInfo linkInfo;
    (void)memset_s(&linkInfo, sizeof(LaneLinkInfo), 0, sizeof(LaneLinkInfo));
    if (LnnGetRemoteStrInfo(reqInfo->peerNetworkId, STRING_KEY_DEV_UDID,
        linkInfo.peerUdid, UDID_BUF_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get udid error");
        return SOFTBUS_LANE_GET_LEDGER_INFO_ERR;
    }
    if (LnnGetRemoteStrInfo(reqInfo->peerNetworkId, STRING_KEY_BT_MAC, linkInfo.linkInfo.br.brMac,
        BT_MAC_LEN) != SOFTBUS_OK || strlen(linkInfo.linkInfo.br.brMac) == 0) {
        LNN_LOGE(LNN_LANE, "LnnGetRemoteStrInfo brmac is failed");
        return SOFTBUS_LANE_GET_LEDGER_INFO_ERR;
    }
    linkInfo.type = LANE_BR;
    callback->OnLaneLinkSuccess(reqId, linkInfo.type, &linkInfo);
    return SOFTBUS_OK;
}

typedef struct P2pAddrNode {
    ListNode node;
    char networkId[NETWORK_ID_BUF_LEN];
    char addr[MAX_SOCKET_ADDR_LEN];
    uint16_t port;
    uint16_t cnt;
} P2pAddrNode;

static SoftBusList g_P2pAddrList;

static void LaneInitP2pAddrList()
{
    ListInit(&g_P2pAddrList.list);
    g_P2pAddrList.cnt = 0;
    SoftBusMutexInit(&g_P2pAddrList.lock, NULL);
}

void LaneDeleteP2pAddress(const char *networkId, bool isDestroy)
{
    P2pAddrNode *item = NULL;
    P2pAddrNode *nextItem = NULL;

    if (networkId == NULL) {
        LNN_LOGE(LNN_LANE, "networkId invalid");
        return;
    }
    if (SoftBusMutexLock(&g_P2pAddrList.lock) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "SoftBusMutexLock fail");
        return;
    }
    LIST_FOR_EACH_ENTRY_SAFE(item, nextItem, &g_P2pAddrList.list, P2pAddrNode, node) {
        if (strcmp(item->networkId, networkId) == 0) {
            if (isDestroy || (--item->cnt) == 0) {
                ListDelete(&item->node);
                SoftBusFree(item);
            }
        }
    }
    SoftBusMutexUnlock(&g_P2pAddrList.lock);
}

void LaneAddP2pAddress(const char *networkId, const char *ipAddr, uint16_t port)
{
    if (networkId == NULL || ipAddr == NULL) {
        LNN_LOGE(LNN_LANE, "invalid parameter");
        return;
    }
    P2pAddrNode *item = NULL;
    P2pAddrNode *nextItem = NULL;
    bool find = false;

    if (SoftBusMutexLock(&g_P2pAddrList.lock) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "SoftBusMutexLock fail");
        return;
    }

    LIST_FOR_EACH_ENTRY_SAFE(item, nextItem, &g_P2pAddrList.list, P2pAddrNode, node) {
        if (strcmp(item->networkId, networkId) == 0) {
            find = true;
            break;
        }
    }
    if (find) {
        if (strcpy_s(item->addr, MAX_SOCKET_ADDR_LEN, ipAddr) != EOK) {
            SoftBusMutexUnlock(&g_P2pAddrList.lock);
            return;
        }
        item->port = port;
        item->cnt++;
    } else {
        P2pAddrNode *p2pAddrNode = (P2pAddrNode *)SoftBusMalloc(sizeof(P2pAddrNode));
        if (p2pAddrNode == NULL) {
            SoftBusMutexUnlock(&g_P2pAddrList.lock);
            return;
        }
        if (strcpy_s(p2pAddrNode->networkId, NETWORK_ID_BUF_LEN, networkId) != EOK) {
            SoftBusMutexUnlock(&g_P2pAddrList.lock);
            SoftBusFree(p2pAddrNode);
            return;
        }
        if (strcpy_s(p2pAddrNode->addr, MAX_SOCKET_ADDR_LEN, ipAddr) != EOK) {
            SoftBusMutexUnlock(&g_P2pAddrList.lock);
            SoftBusFree(p2pAddrNode);
            return;
        }
        p2pAddrNode->port = port;
        p2pAddrNode->cnt = 1;
        ListAdd(&g_P2pAddrList.list, &p2pAddrNode->node);
    }

    SoftBusMutexUnlock(&g_P2pAddrList.lock);
}

void LaneAddP2pAddressByIp(const char *ipAddr, uint16_t port)
{
    if (ipAddr == NULL) {
        return;
    }
    P2pAddrNode *item = NULL;
    P2pAddrNode *nextItem = NULL;
    bool find = false;

    if (SoftBusMutexLock(&g_P2pAddrList.lock) != SOFTBUS_OK) {
        return;
    }

    LIST_FOR_EACH_ENTRY_SAFE(item, nextItem, &g_P2pAddrList.list, P2pAddrNode, node) {
        if (strcmp(item->addr, ipAddr) == 0) {
            find = true;
            break;
        }
    }
    if (find) {
        item->port = port;
        item->cnt++;
    } else {
        P2pAddrNode *p2pAddrNode = (P2pAddrNode *)SoftBusMalloc(sizeof(P2pAddrNode));
        if (p2pAddrNode == NULL) {
            SoftBusMutexUnlock(&g_P2pAddrList.lock);
            return;
        }
        if (strcpy_s(p2pAddrNode->addr, MAX_SOCKET_ADDR_LEN, ipAddr) != EOK) {
            SoftBusMutexUnlock(&g_P2pAddrList.lock);
            SoftBusFree(p2pAddrNode);
            return;
        }
        p2pAddrNode->networkId[0] = 0;
        p2pAddrNode->port = port;
        p2pAddrNode->cnt = 1;
        ListAdd(&g_P2pAddrList.list, &p2pAddrNode->node);
    }

    SoftBusMutexUnlock(&g_P2pAddrList.lock);
}

void LaneUpdateP2pAddressByIp(const char *ipAddr, const char *networkId)
{
    if (ipAddr == NULL || networkId == NULL) {
        LNN_LOGE(LNN_LANE, "invalid parameter");
        return;
    }
    P2pAddrNode *item = NULL;
    P2pAddrNode *nextItem = NULL;

    if (SoftBusMutexLock(&g_P2pAddrList.lock) != SOFTBUS_OK) {
        return;
    }

    LIST_FOR_EACH_ENTRY_SAFE(item, nextItem, &g_P2pAddrList.list, P2pAddrNode, node) {
        if (strcmp(item->addr, ipAddr) == 0) {
            if (strcpy_s(item->networkId, NETWORK_ID_BUF_LEN, networkId) != EOK) {
                SoftBusMutexUnlock(&g_P2pAddrList.lock);
                return;
            }
        }
    }
    SoftBusMutexUnlock(&g_P2pAddrList.lock);
}

static bool LaneGetP2PReuseMac(const char *networkId, char *ipAddr, uint32_t maxLen, uint16_t *port)
{
    P2pAddrNode *item = NULL;
    P2pAddrNode *nextItem = NULL;
    if (SoftBusMutexLock(&g_P2pAddrList.lock) != SOFTBUS_OK) {
        return false;
    }
    LIST_FOR_EACH_ENTRY_SAFE(item, nextItem, &g_P2pAddrList.list, P2pAddrNode, node) {
        if (strcmp(item->networkId, networkId) == 0) {
            if (strcpy_s(ipAddr, maxLen, item->addr) != EOK) {
                SoftBusMutexUnlock(&g_P2pAddrList.lock);
                return false;
            }
            *port = item->port;
            SoftBusMutexUnlock(&g_P2pAddrList.lock);
            return true;
        }
    }
    SoftBusMutexUnlock(&g_P2pAddrList.lock);
    return false;
}

static int32_t LaneLinkOfBleReuseCommon(uint32_t reqId, const LinkRequest *reqInfo, const LaneLinkCb *callback,
    BleProtocolType type)
{
    const char *udid = LnnConvertDLidToUdid(reqInfo->peerNetworkId, CATEGORY_NETWORK_ID);
    ConnBleConnection *connection = ConnBleGetConnectionByUdid(NULL, udid, type);
    if ((connection == NULL) || (connection->state != BLE_CONNECTION_STATE_EXCHANGED_BASIC_INFO)) {
        return SOFTBUS_INVALID_PARAM;
    }
    LaneLinkInfo linkInfo;
    (void)memset_s(&linkInfo, sizeof(LaneLinkInfo), 0, sizeof(LaneLinkInfo));
    if (LnnGetRemoteStrInfo(reqInfo->peerNetworkId, STRING_KEY_DEV_UDID,
        linkInfo.peerUdid, UDID_BUF_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get udid error");
        return SOFTBUS_LANE_GET_LEDGER_INFO_ERR;
    }
    (void)memcpy_s(linkInfo.linkInfo.ble.bleMac, BT_MAC_LEN, connection->addr, BT_MAC_LEN);
    int32_t ret = SoftBusGenerateStrHash((uint8_t*)connection->udid, strlen(connection->udid),
        (uint8_t*)linkInfo.linkInfo.ble.deviceIdHash);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "generate deviceId hash err");
        ConnBleReturnConnection(&connection);
        return ret;
    }
    linkInfo.linkInfo.ble.protoType = type;
    if (type == BLE_COC) {
        linkInfo.type = LANE_COC;
        linkInfo.linkInfo.ble.psm = connection->psm;
    } else if (type == BLE_GATT) {
        linkInfo.type = LANE_BLE;
    }
    ConnBleReturnConnection(&connection);
    callback->OnLaneLinkSuccess(reqId, linkInfo.type, &linkInfo);
    return SOFTBUS_OK;
}

static int32_t LaneLinkOfBleReuse(uint32_t reqId, const LinkRequest *reqInfo, const LaneLinkCb *callback)
{
    return LaneLinkOfBleReuseCommon(reqId, reqInfo, callback, BLE_GATT);
}

static int32_t LaneLinkSetBleMac(const LinkRequest *reqInfo, LaneLinkInfo *linkInfo)
{
    NodeInfo node;
    (void)memset_s(&node, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    if (LnnGetRemoteNodeInfoById(reqInfo->peerNetworkId, CATEGORY_NETWORK_ID, &node) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "can not find node");
        return SOFTBUS_LANE_GET_LEDGER_INFO_ERR;
    }
    if (node.bleMacRefreshSwitch == 0 && strlen(node.connectInfo.bleMacAddr) > 0) {
        if (strcpy_s(linkInfo->linkInfo.ble.bleMac, BT_MAC_LEN, node.connectInfo.bleMacAddr) == EOK) {
            return SOFTBUS_OK;
        }
    }
    return SOFTBUS_MEM_ERR;
}

static int32_t LaneLinkOfBle(uint32_t reqId, const LinkRequest *reqInfo, const LaneLinkCb *callback)
{
    LaneLinkInfo linkInfo;
    (void)memset_s(&linkInfo, sizeof(LaneLinkInfo), 0, sizeof(LaneLinkInfo));
    if (LnnGetRemoteStrInfo(reqInfo->peerNetworkId, STRING_KEY_DEV_UDID,
        linkInfo.peerUdid, UDID_BUF_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get udid error");
        return SOFTBUS_LANE_GET_LEDGER_INFO_ERR;
    }
    if (memcpy_s(linkInfo.linkInfo.ble.bleMac, BT_MAC_LEN, reqInfo->peerBleMac, BT_MAC_LEN) != EOK) {
        LNN_LOGE(LNN_LANE, "memcpy peerBleMac error");
        return SOFTBUS_MEM_ERR;
    }
    if (strlen(linkInfo.linkInfo.ble.bleMac) == 0) {
        if (LaneLinkSetBleMac(reqInfo, &linkInfo) != SOFTBUS_OK) {
            LNN_LOGE(LNN_LANE, "get peerBleMac error");
            return SOFTBUS_LANE_GET_LEDGER_INFO_ERR;
        }
    }
    char peerUdid[UDID_BUF_LEN] = {0};
    if (LnnGetRemoteStrInfo(reqInfo->peerNetworkId, STRING_KEY_DEV_UDID, peerUdid, UDID_BUF_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get udid error");
        return SOFTBUS_LANE_GET_LEDGER_INFO_ERR;
    }
    int32_t ret = SoftBusGenerateStrHash((uint8_t*)peerUdid, strlen(peerUdid),
        (uint8_t*)linkInfo.linkInfo.ble.deviceIdHash);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "generate deviceId hash err");
        return ret;
    }
    linkInfo.linkInfo.ble.protoType = BLE_GATT;
    linkInfo.linkInfo.ble.psm = 0;
    linkInfo.type = LANE_BLE;
    callback->OnLaneLinkSuccess(reqId, linkInfo.type, &linkInfo);
    return SOFTBUS_OK;
}

static int32_t LaneLinkOfGattDirect(uint32_t reqId, const LinkRequest *reqInfo, const LaneLinkCb *callback)
{
    LaneLinkInfo linkInfo;
    (void)memset_s(&linkInfo, sizeof(LaneLinkInfo), 0, sizeof(LaneLinkInfo));
    if (LnnGetRemoteStrInfo(reqInfo->peerNetworkId, STRING_KEY_DEV_UDID,
        linkInfo.peerUdid, UDID_BUF_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get udid error");
        return SOFTBUS_LANE_GET_LEDGER_INFO_ERR;
    }
    if (strcpy_s(linkInfo.linkInfo.bleDirect.networkId, NETWORK_ID_BUF_LEN, reqInfo->peerNetworkId) != EOK) {
        LNN_LOGE(LNN_LANE, "copy networkId fail");
        return SOFTBUS_MEM_ERR;
    }
    linkInfo.type = LANE_BLE_DIRECT;
    linkInfo.linkInfo.bleDirect.protoType = BLE_GATT;
    callback->OnLaneLinkSuccess(reqId, linkInfo.type, &linkInfo);
    return SOFTBUS_OK;
}

static int32_t LaneLinkOfP2p(uint32_t reqId, const LinkRequest *reqInfo, const LaneLinkCb *callback)
{
    LinkRequest linkInfo;
    if (memcpy_s(&linkInfo, sizeof(LinkRequest), reqInfo, sizeof(LinkRequest)) != EOK) {
        LNN_LOGE(LNN_LANE, "p2p copy linkreqinfo fail");
        return SOFTBUS_MEM_ERR;
    }
    linkInfo.linkType = LANE_P2P;
    return LnnConnectP2p(&linkInfo, reqId, callback);
}

static int32_t LaneLinkOfHml(uint32_t reqId, const LinkRequest *reqInfo, const LaneLinkCb *callback)
{
    LinkRequest linkInfo;
    if (memcpy_s(&linkInfo, sizeof(LinkRequest), reqInfo, sizeof(LinkRequest)) != EOK) {
        LNN_LOGE(LNN_LANE, "hml copy linkreqinfo fail");
        return SOFTBUS_MEM_ERR;
    }
    linkInfo.linkType = LANE_HML;
    return LnnConnectP2p(&linkInfo, reqId, callback);
}

static int32_t LaneLinkOfP2pReuse(uint32_t reqId, const LinkRequest *reqInfo, const LaneLinkCb *callback)
{
    LaneLinkInfo linkInfo;
    if (LnnGetRemoteStrInfo(reqInfo->peerNetworkId, STRING_KEY_DEV_UDID,
        linkInfo.peerUdid, UDID_BUF_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get udid error");
        return SOFTBUS_LANE_GET_LEDGER_INFO_ERR;
    }
    linkInfo.type = LANE_P2P_REUSE;
    char ipAddr[MAX_SOCKET_ADDR_LEN];
    uint16_t port;
    if (!LaneGetP2PReuseMac(reqInfo->peerNetworkId, ipAddr, MAX_SOCKET_ADDR_LEN, &port)) {
        LNN_LOGE(LNN_LANE, "p2p resue get addr failed");
        return SOFTBUS_NOT_FIND;
    }
    linkInfo.linkInfo.wlan.connInfo.protocol = LNN_PROTOCOL_IP;
    linkInfo.linkInfo.wlan.connInfo.port = port;
    if (memcpy_s(linkInfo.linkInfo.wlan.connInfo.addr, MAX_SOCKET_ADDR_LEN, ipAddr, MAX_SOCKET_ADDR_LEN) != EOK) {
        return SOFTBUS_MEM_ERR;
    }
    callback->OnLaneLinkSuccess(reqId, linkInfo.type, &linkInfo);
    return SOFTBUS_OK;
}

static int32_t GetWlanLinkedAttribute(int32_t *channel, bool *is5GBand, bool *isConnected)
{
    LnnWlanLinkedInfo info;
    int32_t ret = LnnGetWlanLinkedInfo(&info);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "LnnGetWlanLinkedInfo fail, ret=%{public}d", ret);
        return SOFTBUS_ERR;
    }
    *isConnected = info.isConnected;
    *is5GBand = (info.band != 1);

    *channel = SoftBusFrequencyToChannel(info.frequency);
    LNN_LOGI(LNN_LANE, "wlan current channel=%{public}d", *channel);
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
        return SOFTBUS_ERR;
    }

    const NodeInfo *localNode = LnnGetLocalNodeInfo();
    if (localNode == NULL) {
        LNN_LOGE(LNN_LANE, "get local node info failed!");
        return SOFTBUS_ERR;
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
        anonyNetworkId, req.selectedProtocol, req.currPri);
    AnonymizeFree(anonyNetworkId);
    if (req.selectedProtocol == 0) {
        req.selectedProtocol = LNN_PROTOCOL_IP;
    }
 
    return req.selectedProtocol;
}

static int32_t FillWlanLinkInfo(ProtocolType protocol, const LinkRequest *reqInfo, LaneLinkInfo *linkInfo)
{
    int32_t ret = SOFTBUS_OK;
    int32_t port = 0;
    if (reqInfo->transType == LANE_T_MSG) {
        ret = LnnGetRemoteNumInfo(reqInfo->peerNetworkId, NUM_KEY_PROXY_PORT, &port);
        LNN_LOGI(LNN_LANE, "get remote proxy port, port=%{public}d, ret=%{public}d", port, ret);
    } else {
        ret = LnnGetRemoteNumInfo(reqInfo->peerNetworkId, NUM_KEY_SESSION_PORT, &port);
        LNN_LOGI(LNN_LANE, "get remote session port, port=%{public}d, ret=%{public}d", port, ret);
    }
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    int32_t channel = -1;
    bool is5GBand = false;
    bool isConnected = false;
    if (GetWlanLinkedAttribute(&channel, &is5GBand, &isConnected) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get wlan attr info fail");
    }
    if (!isConnected) {
        LNN_LOGE(LNN_LANE, "wlan is disconnected");
    }
    linkInfo->type = reqInfo->linkType;
    WlanLinkInfo *wlan = &(linkInfo->linkInfo.wlan);
    wlan->channel = channel;
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
        if (LnnGetRemoteStrInfo(reqInfo->peerNetworkId, STRING_KEY_WLAN_IP, linkInfo->linkInfo.wlan.connInfo.addr,
            sizeof(linkInfo->linkInfo.wlan.connInfo.addr)) != SOFTBUS_OK) {
            LNN_LOGE(LNN_LANE, "get remote wlan ip fail");
            return SOFTBUS_LANE_GET_LEDGER_INFO_ERR;
        }
        if (strnlen(linkInfo->linkInfo.wlan.connInfo.addr, sizeof(linkInfo->linkInfo.wlan.connInfo.addr)) == 0 ||
            strncmp(linkInfo->linkInfo.wlan.connInfo.addr, "127.0.0.1", strlen("127.0.0.1")) == 0) {
            LNN_LOGE(LNN_LANE, "Wlan ip not found");
            return SOFTBUS_MEM_ERR;
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

static int32_t LaneLinkOfCoc(uint32_t reqId, const LinkRequest *reqInfo, const LaneLinkCb *callback)
{
    LaneLinkInfo linkInfo;
    (void)memset_s(&linkInfo, sizeof(LaneLinkInfo), 0, sizeof(LaneLinkInfo));
    if (LnnGetRemoteStrInfo(reqInfo->peerNetworkId, STRING_KEY_DEV_UDID,
        linkInfo.peerUdid, UDID_BUF_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get udid error");
        return SOFTBUS_LANE_GET_LEDGER_INFO_ERR;
    }
    if (memcpy_s(linkInfo.linkInfo.ble.bleMac, BT_MAC_LEN, reqInfo->peerBleMac, BT_MAC_LEN) != EOK) {
        LNN_LOGE(LNN_LANE, "memcpy peerBleMac error");
        return SOFTBUS_MEM_ERR;
    }
    linkInfo.linkInfo.ble.psm = reqInfo->psm;
    if (strlen(linkInfo.linkInfo.ble.bleMac) == 0) {
        LNN_LOGE(LNN_LANE, "get peerBleMac error");
        return SOFTBUS_MEM_ERR;
    }
    char peerUdid[UDID_BUF_LEN] = {0};
    if (LnnGetRemoteStrInfo(reqInfo->peerNetworkId, STRING_KEY_DEV_UDID, peerUdid, UDID_BUF_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get udid error");
        return SOFTBUS_LANE_GET_LEDGER_INFO_ERR;
    }
    int32_t ret = SoftBusGenerateStrHash((uint8_t*)peerUdid, strlen(peerUdid),
        (uint8_t*)linkInfo.linkInfo.ble.deviceIdHash);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "generate deviceId hash err");
        return ret;
    }
    linkInfo.linkInfo.ble.protoType = BLE_COC;
    linkInfo.type = LANE_COC;
    callback->OnLaneLinkSuccess(reqId, linkInfo.type, &linkInfo);
    return SOFTBUS_OK;
}

static int32_t LaneLinkOfCocDirect(uint32_t reqId, const LinkRequest *reqInfo, const LaneLinkCb *callback)
{
    LaneLinkInfo linkInfo;
    (void)memset_s(&linkInfo, sizeof(LaneLinkInfo), 0, sizeof(LaneLinkInfo));
    if (LnnGetRemoteStrInfo(reqInfo->peerNetworkId, STRING_KEY_DEV_UDID,
        linkInfo.peerUdid, UDID_BUF_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get udid error");
        return SOFTBUS_LANE_GET_LEDGER_INFO_ERR;
    }
    if (strcpy_s(linkInfo.linkInfo.bleDirect.networkId, NETWORK_ID_BUF_LEN, reqInfo->peerNetworkId) != EOK) {
        LNN_LOGE(LNN_LANE, "copy networkId fail");
        return SOFTBUS_MEM_ERR;
    }
    linkInfo.type = LANE_COC_DIRECT;
    linkInfo.linkInfo.bleDirect.protoType = BLE_COC;

    callback->OnLaneLinkSuccess(reqId, linkInfo.type, &linkInfo);
    return SOFTBUS_OK;
}

static LaneLinkByType g_linkTable[LANE_LINK_TYPE_BUTT] = {
    [LANE_BR] = LaneLinkOfBr,
    [LANE_BLE] = LaneLinkOfBle,
    [LANE_P2P] = LaneLinkOfP2p,
    [LANE_WLAN_2P4G] = LaneLinkOfWlan,
    [LANE_WLAN_5G] = LaneLinkOfWlan,
    [LANE_BLE_REUSE] = LaneLinkOfBleReuse,
    [LANE_P2P_REUSE] = LaneLinkOfP2pReuse,
    [LANE_BLE_DIRECT] = LaneLinkOfGattDirect,
    [LANE_COC] = LaneLinkOfCoc,
    [LANE_COC_DIRECT] = LaneLinkOfCocDirect,
    [LANE_HML] = LaneLinkOfHml,
};

int32_t BuildLink(const LinkRequest *reqInfo, uint32_t reqId, const LaneLinkCb *callback)
{
    if (IsLinkRequestValid(reqInfo) != SOFTBUS_OK || !LinkTypeCheck(reqInfo->linkType)) {
        LNN_LOGE(LNN_LANE, "the reqInfo or type is invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    if (callback == NULL || callback->OnLaneLinkSuccess == NULL ||
        callback->OnLaneLinkFail == NULL) {
        LNN_LOGE(LNN_LANE, "the callback is invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    char *anonyNetworkId = NULL;
    Anonymize(reqInfo->peerNetworkId, &anonyNetworkId);
    LNN_LOGI(LNN_LANE, "build link, linktype=%{public}d, laneReqId=%{public}u, peerNetworkId=%{public}s",
        reqInfo->linkType, reqId, anonyNetworkId);
    AnonymizeFree(anonyNetworkId);
    int32_t ret = g_linkTable[reqInfo->linkType](reqId, reqInfo, callback);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lane link is failed");
        return ret;
    }
    return SOFTBUS_OK;
}

void DestroyLink(const char *networkId, uint32_t laneReqId, LaneLinkType type)
{
    LNN_LOGI(LNN_LANE, "destroy link=%{public}d, laneReqId=%{public}u", type, laneReqId);
    if (networkId == NULL) {
        LNN_LOGE(LNN_LANE, "the networkId is nullptr");
        return;
    }
    if (type == LANE_P2P || type == LANE_HML) {
        LaneDeleteP2pAddress(networkId, false);
        LnnDisconnectP2p(networkId, laneReqId);
    } else {
        LNN_LOGI(LNN_LANE, "ignore destroy linkType=%{public}d, laneReqId=%{public}u", type, laneReqId);
    }
}

int32_t InitLaneLink(void)
{
    LaneInitP2pAddrList();
    if (SoftBusMutexInit(&g_laneResource.lock, NULL) != SOFTBUS_OK) {
        LNN_LOGI(LNN_LANE, "lane resource mutex init fail");
        return SOFTBUS_ERR;
    }
    ListInit(&g_laneResource.list);
    g_laneResource.cnt = 0;
    return SOFTBUS_OK;
}

void DeinitLaneLink(void)
{
    LnnDestroyP2p();
}
