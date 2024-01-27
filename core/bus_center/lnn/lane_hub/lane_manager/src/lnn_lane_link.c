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

#include "lnn_trans_lane.h"
#include "anonymizer.h"
#include "bus_center_manager.h"
#include "lnn_distributed_net_ledger.h"
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
#include "lnn_lane_common.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_crypto.h"
#include "softbus_conn_ble_connection.h"
#include "softbus_conn_ble_manager.h"
#include "softbus_network_utils.h"
#include "softbus_protocol_def.h"

#define DELAY_DESTROY_LANE_TIME 5000
#define LANE_RELIABILITY_TIME 4

typedef int32_t (*LaneLinkByType)(uint32_t reqId, const LinkRequest *reqInfo, const LaneLinkCb *callback);

static SoftBusMutex g_laneResourceMutex;
static ListNode g_laneResourceList;
static ListNode g_LinkInfoList;

static int32_t LaneLock(void)
{
    return SoftBusMutexLock(&g_laneResourceMutex);
}

static void LaneUnlock(void)
{
    (void)SoftBusMutexUnlock(&g_laneResourceMutex);
}

static bool FindLaneResource(const LaneResource *resourceItem, LaneResource *item)
{
    switch (resourceItem->type) {
        case LANE_BR:
            if (strncmp(resourceItem->linkInfo.br.brMac, item->linkInfo.br.brMac, BT_MAC_LEN) != 0) {
                return false;
            }
            break;
        case LANE_BLE:
        case LANE_COC:
            if (strncmp(resourceItem->linkInfo.ble.bleMac, item->linkInfo.ble.bleMac, BT_MAC_LEN) != 0) {
                return false;
            }
            break;
        case LANE_P2P:
        case LANE_HML:
            if (strncmp(resourceItem->linkInfo.p2p.connInfo.peerIp,
                item->linkInfo.p2p.connInfo.peerIp, IP_LEN) != 0) {
                return false;
            }
            break;
        case LANE_WLAN_5G:
        case LANE_WLAN_2P4G:
        case LANE_P2P_REUSE:
            if (strncmp(resourceItem->linkInfo.wlan.connInfo.addr,
                item->linkInfo.wlan.connInfo.addr, MAX_SOCKET_ADDR_LEN) != 0) {
                return false;
            }
            break;
        case LANE_BLE_DIRECT:
        case LANE_COC_DIRECT:
            if (strcmp(resourceItem->linkInfo.bleDirect.networkId, item->linkInfo.bleDirect.networkId) != 0) {
                return false;
            }
            break;
        default:
            return false;
    }
    return true;
}

static LaneResource* LaneResourceIsExist(const LaneResource *resourceItem)
{
    LaneResource *item = NULL;
    LaneResource *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_laneResourceList, LaneResource, node) {
        if (resourceItem->type == item->type) {
            if (FindLaneResource(resourceItem, item)) {
                return item;
            }
        }
    }
    return NULL;
}

static int32_t CreateResourceItem(const LaneResource *inputResource, LaneResource *outputResource)
{
    switch (inputResource->type) {
        case LANE_BR:
            if (memcpy_s(&(outputResource->linkInfo.br), sizeof(BrLinkInfo),
                &(inputResource->linkInfo.br), sizeof(BrLinkInfo)) != EOK) {
                return SOFTBUS_ERR;
            }
            break;
        case LANE_BLE:
        case LANE_COC:
            if (memcpy_s(&(outputResource->linkInfo.ble), sizeof(BleLinkInfo),
                &(inputResource->linkInfo.ble), sizeof(BleLinkInfo)) != EOK) {
                return SOFTBUS_ERR;
            }
            break;
        case LANE_P2P:
        case LANE_HML:
            if (memcpy_s(&(outputResource->linkInfo.p2p), sizeof(P2pLinkInfo),
                &(inputResource->linkInfo.p2p), sizeof(P2pLinkInfo)) != EOK) {
                return SOFTBUS_ERR;
            }
            break;
        case LANE_WLAN_5G:
        case LANE_WLAN_2P4G:
        case LANE_P2P_REUSE:
            if (memcpy_s(&(outputResource->linkInfo.wlan), sizeof(WlanLinkInfo),
                &(inputResource->linkInfo.wlan), sizeof(WlanLinkInfo)) != EOK) {
                return SOFTBUS_ERR;
            }
            break;
        case LANE_BLE_DIRECT:
        case LANE_COC_DIRECT:
            if (memcpy_s(&(outputResource->linkInfo.bleDirect), sizeof(BleDirectInfo),
                &(inputResource->linkInfo.bleDirect), sizeof(BleDirectInfo)) != EOK) {
                return SOFTBUS_ERR;
            }
            break;
        default:
            return SOFTBUS_ERR;
    }
    outputResource->type = inputResource->type;
    outputResource->isReliable = inputResource->isReliable;
    outputResource->laneTimeliness = inputResource->laneTimeliness;
    outputResource->laneScore = inputResource->laneScore;
    outputResource->laneFload = inputResource->laneFload;
    outputResource->laneRef = inputResource->laneRef;
    return SOFTBUS_OK;
}

int32_t AddLaneResourceItem(const LaneResource *inputResource)
{
    if (inputResource == NULL) {
        LNN_LOGE(LNN_LANE, "inputResource is nullptr");
        return SOFTBUS_INVALID_PARAM;
    }
    LaneResource *resourceItem = (LaneResource *)SoftBusMalloc(sizeof(LaneResource));
    if (resourceItem == NULL) {
        LNN_LOGE(LNN_LANE, "resourceItem malloc fail");
        return SOFTBUS_MALLOC_ERR;
    }
    if (CreateResourceItem(inputResource, resourceItem) != SOFTBUS_OK) {
        SoftBusFree(resourceItem);
        LNN_LOGE(LNN_LANE, "create resourceItem fail");
        return SOFTBUS_ERR;
    }
    if (LaneLock() != SOFTBUS_OK) {
        SoftBusFree(resourceItem);
        LNN_LOGE(LNN_LANE, "lane lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    LaneResource* item = LaneResourceIsExist(resourceItem);
    if (item != NULL) {
        item->laneRef++;
        item->isReliable = true;
        SoftBusFree(resourceItem);
    } else {
        ListAdd(&g_laneResourceList, &resourceItem->node);
    }
    LaneUnlock();
    return SOFTBUS_OK;
}

static int32_t StartDelayDestroyLink(uint32_t laneId, LaneResource* item)
{
    LaneResource* resourceItem = (LaneResource *)SoftBusMalloc(sizeof(LaneResource));
    if (resourceItem == NULL) {
        LNN_LOGE(LNN_LANE, "resourceItem malloc fail");
        return SOFTBUS_MALLOC_ERR;
    }
    if (memcpy_s(resourceItem, sizeof(LaneResource), item, sizeof(LaneResource)) != EOK) {
        LNN_LOGE(LNN_LANE, "memcpy LaneResource error");
        SoftBusFree(resourceItem);
        return SOFTBUS_MEM_ERR;
    }
    if (PostDelayDestroyMessage(laneId, resourceItem, DELAY_DESTROY_LANE_TIME) != SOFTBUS_OK) {
        SoftBusFree(resourceItem);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t DelLaneResourceItemWithDelay(LaneResource *resourceItem, uint32_t laneId, bool *isDelayDestroy)
{
    if (resourceItem == NULL || isDelayDestroy == NULL) {
        LNN_LOGE(LNN_LANE, "resourceItem or isDelayDestroy is nullptr");
        return SOFTBUS_INVALID_PARAM;
    }
    if (LaneLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lane lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    LaneResource* item = LaneResourceIsExist(resourceItem);
    if (item != NULL) {
        LNN_LOGI(LNN_LANE, "link=%{public}d, ref=%{public}d", item->type, item->laneRef);
        if (item->type == LANE_HML && item->laneRef == 1) {
            if (StartDelayDestroyLink(laneId, item) == SOFTBUS_OK) {
                *isDelayDestroy = true;
                LaneUnlock();
                return SOFTBUS_OK;
            }
        }
        if ((--item->laneRef) == 0) {
            ListDelete(&item->node);
            SoftBusFree(item);
        }
    }
    *isDelayDestroy = false;
    LaneUnlock();
    return SOFTBUS_OK;
}

int32_t DelLaneResourceItem(const LaneResource *resourceItem)
{
    if (resourceItem == NULL) {
        LNN_LOGE(LNN_LANE, "resourceItem is nullptr");
        return SOFTBUS_INVALID_PARAM;
    }
    if (LaneLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lane lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    LaneResource* item = LaneResourceIsExist(resourceItem);
    if (item != NULL) {
        LNN_LOGI(LNN_LANE, "link=%{public}d, ref=%{public}d", item->type, item->laneRef);
        if ((--item->laneRef) == 0) {
            ListDelete(&item->node);
            SoftBusFree(item);
        }
    }
    LaneUnlock();
    return SOFTBUS_OK;
}

void HandleLaneReliabilityTime(void)
{
    if (LaneLock() != SOFTBUS_OK) {
        return;
    }
    LaneResource *item = NULL;
    LaneResource *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_laneResourceList, LaneResource, node) {
        item->laneTimeliness++;
        if (item->laneTimeliness >= LANE_RELIABILITY_TIME) {
            item->laneTimeliness = 0;
            item->isReliable = false;
        }
    }
    LaneUnlock();
}

static int32_t CreateLinkInfoItem(const LaneLinkInfo *inputLinkInfo, LaneLinkInfo *outputLinkInfo)
{
    switch (inputLinkInfo->type) {
        case LANE_BR:
            if (memcpy_s(&(outputLinkInfo->linkInfo.br), sizeof(BrLinkInfo),
                &(inputLinkInfo->linkInfo.br), sizeof(BrLinkInfo)) != EOK) {
                return SOFTBUS_ERR;
            }
            break;
        case LANE_BLE:
        case LANE_COC:
            if (memcpy_s(&(outputLinkInfo->linkInfo.ble), sizeof(BleLinkInfo),
                &(inputLinkInfo->linkInfo.ble), sizeof(BleLinkInfo)) != EOK) {
                return SOFTBUS_ERR;
            }
            break;
        case LANE_P2P:
        case LANE_HML:
            if (memcpy_s(&(outputLinkInfo->linkInfo.p2p), sizeof(P2pLinkInfo),
                &(inputLinkInfo->linkInfo.p2p), sizeof(P2pLinkInfo)) != EOK) {
                return SOFTBUS_ERR;
            }
            break;
        case LANE_WLAN_5G:
        case LANE_WLAN_2P4G:
        case LANE_P2P_REUSE:
            if (memcpy_s(&(outputLinkInfo->linkInfo.wlan), sizeof(WlanLinkInfo),
                &(inputLinkInfo->linkInfo.wlan), sizeof(WlanLinkInfo)) != EOK) {
                return SOFTBUS_ERR;
            }
            break;
        case LANE_BLE_DIRECT:
        case LANE_COC_DIRECT:
            if (memcpy_s(&(outputLinkInfo->linkInfo.bleDirect), sizeof(BleDirectInfo),
                &(inputLinkInfo->linkInfo.bleDirect), sizeof(BleDirectInfo)) != EOK) {
                return SOFTBUS_ERR;
            }
            break;
        default:
            return SOFTBUS_ERR;
    }
    outputLinkInfo->type = inputLinkInfo->type;
    outputLinkInfo->laneId = inputLinkInfo->laneId;
    return SOFTBUS_OK;
}

int32_t AddLinkInfoItem(const LaneLinkInfo *inputLinkInfo)
{
    if (inputLinkInfo == NULL) {
        LNN_LOGE(LNN_LANE, "inputLinkInfo is nullptr");
        return SOFTBUS_INVALID_PARAM;
    }
    LaneLinkInfo *linkInfoItem = (LaneLinkInfo *)SoftBusMalloc(sizeof(LaneLinkInfo));
    if (linkInfoItem == NULL) {
        LNN_LOGE(LNN_LANE, "linkInfoItem malloc fail");
        return SOFTBUS_MALLOC_ERR;
    }
    if (CreateLinkInfoItem(inputLinkInfo, linkInfoItem) != SOFTBUS_OK) {
        SoftBusFree(linkInfoItem);
        LNN_LOGE(LNN_LANE, "create linkInfoItem fail");
        return SOFTBUS_ERR;
    }
    if (LaneLock() != SOFTBUS_OK) {
        SoftBusFree(linkInfoItem);
        LNN_LOGE(LNN_LANE, "lane lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    ListAdd(&g_LinkInfoList, &linkInfoItem->node);
    LaneUnlock();
    return SOFTBUS_OK;
}

int32_t DelLinkInfoItem(uint32_t laneId)
{
    if (laneId == INVALID_LANE_ID) {
        LNN_LOGE(LNN_LANE, "laneId is invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    if (LaneLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lane lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    LaneLinkInfo *item = NULL;
    LaneLinkInfo *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_LinkInfoList, LaneLinkInfo, node) {
        if (item->laneId == laneId) {
            ListDelete(&item->node);
            SoftBusFree(item);
        }
    }
    LaneUnlock();
    return SOFTBUS_OK;
}

int32_t FindLaneLinkInfoByLaneId(uint32_t laneId, LaneLinkInfo *linkInfoitem)
{
    if (laneId == INVALID_LANE_ID || linkInfoitem == NULL) {
        LNN_LOGE(LNN_LANE, "laneId or linkInfoItem is invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    if (LaneLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lane lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    LaneLinkInfo *item = NULL;
    LaneLinkInfo *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_LinkInfoList, LaneLinkInfo, node) {
        if (item->laneId == laneId) {
            if (CreateLinkInfoItem(item, linkInfoitem) != SOFTBUS_OK) {
                LaneUnlock();
                LNN_LOGE(LNN_LANE, "create linkInfoItem fail");
                return SOFTBUS_ERR;
            }
            LaneUnlock();
            return SOFTBUS_OK;
        }
    }
    LaneUnlock();
    LNN_LOGE(LNN_LANE, "find laneLinkInfo by laneId fail");
    return SOFTBUS_ERR;
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

int32_t ConvertToLaneResource(const LaneLinkInfo *linkInfo, LaneResource *laneResourceInfo)
{
    if (linkInfo == NULL || laneResourceInfo == NULL) {
        LNN_LOGE(LNN_LANE, "linkInfo or laneResourceInfo is nullptr");
        return SOFTBUS_INVALID_PARAM;
    }
    laneResourceInfo->type = linkInfo->type;
    switch (linkInfo->type) {
        case LANE_BR:
            if (memcpy_s(&(laneResourceInfo->linkInfo.br), sizeof(BrLinkInfo),
                &(linkInfo->linkInfo.br), sizeof(BrLinkInfo)) != EOK) {
                LNN_LOGE(LNN_LANE, "linkInfo br memcpy_s fail, linkInfo type=%{public}d", linkInfo->type);
                return SOFTBUS_ERR;
            }
            break;
        case LANE_BLE:
        case LANE_COC:
            if (memcpy_s(&(laneResourceInfo->linkInfo.ble), sizeof(BleLinkInfo),
                &(linkInfo->linkInfo.ble), sizeof(BleLinkInfo)) != EOK) {
                LNN_LOGE(LNN_LANE, "linkInfo ble memcpy_s fail, linkInfo type=%{public}d", linkInfo->type);
                return SOFTBUS_ERR;
            }
            break;
        case LANE_P2P:
        case LANE_HML:
            if (memcpy_s(&(laneResourceInfo->linkInfo.p2p), sizeof(P2pConnInfo),
                &(linkInfo->linkInfo.p2p), sizeof(P2pConnInfo)) != EOK) {
                LNN_LOGE(LNN_LANE, "linkInfo p2p memcpy_s fail, linkInfo type=%{public}d", linkInfo->type);
                return SOFTBUS_ERR;
            }
            break;
        case LANE_WLAN_5G:
        case LANE_WLAN_2P4G:
        case LANE_P2P_REUSE:
            if (memcpy_s(&(laneResourceInfo->linkInfo.wlan), sizeof(WlanLinkInfo),
                &(linkInfo->linkInfo.wlan), sizeof(WlanLinkInfo)) != EOK) {
                LNN_LOGE(LNN_LANE, "linkInfo wlan memcpy_s fail, linkInfo type=%{public}d", linkInfo->type);
                return SOFTBUS_ERR;
            }
            break;
        case LANE_BLE_DIRECT:
        case LANE_COC_DIRECT:
            if (memcpy_s(&(laneResourceInfo->linkInfo.bleDirect), sizeof(BleDirectInfo),
                &(linkInfo->linkInfo.bleDirect), sizeof(BleDirectInfo)) != EOK) {
                LNN_LOGE(LNN_LANE, "linkInfo bleDirect memcpy_s fail, linkInfo type=%{public}d", linkInfo->type);
                return SOFTBUS_ERR;
            }
            break;
        default:
            LNN_LOGE(LNN_LANE, "curr link type is not supported, linkInfo type=%{public}d", linkInfo->type);
            return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t FindLaneResourceByLinkInfo(const LaneLinkInfo *linkInfoItem, LaneResource *laneResourceItem)
{
    if (linkInfoItem == NULL || laneResourceItem == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    LaneResource laneResourceInfo;
    (void)memset_s(&laneResourceInfo, sizeof(LaneResource), 0, sizeof(LaneResource));
    if (ConvertToLaneResource(linkInfoItem, &laneResourceInfo) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    if (LaneLock() != SOFTBUS_OK) {
        return SOFTBUS_LOCK_ERR;
    }
    LaneResource* item = LaneResourceIsExist(&laneResourceInfo);
    if (item == NULL) {
        LaneUnlock();
        return SOFTBUS_ERR;
    }
    if (CreateResourceItem(item, laneResourceItem) != SOFTBUS_OK) {
        LaneUnlock();
        return SOFTBUS_ERR;
    }
    LaneUnlock();
    return SOFTBUS_OK;
}

static int32_t LaneLinkOfBr(uint32_t reqId, const LinkRequest *reqInfo, const LaneLinkCb *callback)
{
    LaneLinkInfo linkInfo;
    (void)memset_s(&linkInfo, sizeof(LaneLinkInfo), 0, sizeof(LaneLinkInfo));
    int32_t ret = LnnGetRemoteStrInfo(reqInfo->peerNetworkId, STRING_KEY_BT_MAC,
        linkInfo.linkInfo.br.brMac, BT_MAC_LEN);
    if (ret != SOFTBUS_OK || strlen(linkInfo.linkInfo.br.brMac) == 0) {
        LNN_LOGE(LNN_LANE, "LnnGetRemoteStrInfo brmac is failed");
        return SOFTBUS_ERR;
    }
    linkInfo.type = LANE_BR;
    callback->OnLaneLinkSuccess(reqId, &linkInfo);
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
        return SOFTBUS_ERR;
    }
    LaneLinkInfo linkInfo;
    (void)memset_s(&linkInfo, sizeof(LaneLinkInfo), 0, sizeof(LaneLinkInfo));
    (void)memcpy_s(linkInfo.linkInfo.ble.bleMac, BT_MAC_LEN, connection->addr, BT_MAC_LEN);
    if (SoftBusGenerateStrHash((uint8_t*)connection->udid, strlen(connection->udid),
        (uint8_t*)linkInfo.linkInfo.ble.deviceIdHash) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "generate deviceId hash err");
        ConnBleReturnConnection(&connection);
        return SOFTBUS_ERR;
    }
    linkInfo.linkInfo.ble.protoType = type;
    if (type == BLE_COC) {
        linkInfo.type = LANE_COC;
        linkInfo.linkInfo.ble.psm = connection->psm;
    } else if (type == BLE_GATT) {
        linkInfo.type = LANE_BLE;
    }
    ConnBleReturnConnection(&connection);
    callback->OnLaneLinkSuccess(reqId, &linkInfo);
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
        return SOFTBUS_ERR;
    }
    if (node.bleMacRefreshSwitch == 0 && strlen(node.connectInfo.bleMacAddr) > 0) {
        if (strcpy_s(linkInfo->linkInfo.ble.bleMac, BT_MAC_LEN, node.connectInfo.bleMacAddr) == EOK) {
            return SOFTBUS_OK;
        }
    }
    return SOFTBUS_ERR;
}

static int32_t LaneLinkOfBle(uint32_t reqId, const LinkRequest *reqInfo, const LaneLinkCb *callback)
{
    LaneLinkInfo linkInfo;
    (void)memset_s(&linkInfo, sizeof(LaneLinkInfo), 0, sizeof(LaneLinkInfo));
    if (memcpy_s(linkInfo.linkInfo.ble.bleMac, BT_MAC_LEN, reqInfo->peerBleMac, BT_MAC_LEN) != EOK) {
        LNN_LOGE(LNN_LANE, "memcpy peerBleMac error");
        return SOFTBUS_MEM_ERR;
    }
    if (strlen(linkInfo.linkInfo.ble.bleMac) == 0) {
        if (LaneLinkSetBleMac(reqInfo, &linkInfo) != SOFTBUS_OK) {
            LNN_LOGE(LNN_LANE, "get peerBleMac error");
            return SOFTBUS_ERR;
        }
    }
    char peerUdid[UDID_BUF_LEN] = {0};
    if (LnnGetRemoteStrInfo(reqInfo->peerNetworkId, STRING_KEY_DEV_UDID, peerUdid, UDID_BUF_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get udid error");
        return SOFTBUS_ERR;
    }
    if (SoftBusGenerateStrHash((uint8_t*)peerUdid, strlen(peerUdid),
        (uint8_t*)linkInfo.linkInfo.ble.deviceIdHash) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "generate deviceId hash err");
        return SOFTBUS_ERR;
    }
    linkInfo.linkInfo.ble.protoType = BLE_GATT;
    linkInfo.linkInfo.ble.psm = 0;
    linkInfo.type = LANE_BLE;
    callback->OnLaneLinkSuccess(reqId, &linkInfo);
    return SOFTBUS_OK;
}

static int32_t LaneLinkOfGattDirect(uint32_t reqId, const LinkRequest *reqInfo, const LaneLinkCb *callback)
{
    LaneLinkInfo linkInfo;
    (void)memset_s(&linkInfo, sizeof(LaneLinkInfo), 0, sizeof(LaneLinkInfo));
    if (strcpy_s(linkInfo.linkInfo.bleDirect.networkId, NETWORK_ID_BUF_LEN, reqInfo->peerNetworkId) != EOK) {
        LNN_LOGE(LNN_LANE, "copy networkId fail");
        return SOFTBUS_MEM_ERR;
    }
    linkInfo.type = LANE_BLE_DIRECT;
    linkInfo.linkInfo.bleDirect.protoType = BLE_GATT;
    callback->OnLaneLinkSuccess(reqId, &linkInfo);
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
    linkInfo.type = LANE_P2P_REUSE;
    char ipAddr[MAX_SOCKET_ADDR_LEN];
    uint16_t port;
    if (!LaneGetP2PReuseMac(reqInfo->peerNetworkId, ipAddr, MAX_SOCKET_ADDR_LEN, &port)) {
        LNN_LOGE(LNN_LANE, "p2p resue get addr failed");
        return SOFTBUS_ERR;
    }
    linkInfo.linkInfo.wlan.connInfo.protocol = LNN_PROTOCOL_IP;
    linkInfo.linkInfo.wlan.connInfo.port = port;
    if (memcpy_s(linkInfo.linkInfo.wlan.connInfo.addr, MAX_SOCKET_ADDR_LEN, ipAddr, MAX_SOCKET_ADDR_LEN) != EOK) {
        return SOFTBUS_ERR;
    }
    callback->OnLaneLinkSuccess(reqId, &linkInfo);
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

    LNN_LOGI(LNN_LANE, "protocol=%{public}d", req.selectedProtocol);
    if (req.selectedProtocol == 0) {
        req.selectedProtocol = LNN_PROTOCOL_IP;
    }
 
    return req.selectedProtocol;
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
    LaneLinkInfo linkInfo;
    int32_t port = 0;
    int32_t ret = SOFTBUS_OK;
    ProtocolType acceptableProtocols = LNN_PROTOCOL_ALL ^ LNN_PROTOCOL_NIP;
    if (reqInfo->transType == LANE_T_MSG || reqInfo->transType == LANE_T_BYTE) {
        acceptableProtocols |= LNN_PROTOCOL_NIP;
    }
    acceptableProtocols = acceptableProtocols & reqInfo->acceptableProtocols;
    ProtocolType protocol =
        LnnLaneSelectProtocol(LNN_NETIF_TYPE_WLAN | LNN_NETIF_TYPE_ETH, reqInfo->peerNetworkId, acceptableProtocols);
    if (protocol == 0) {
        LNN_LOGE(LNN_LANE, "protocal is invalid!");
        return SOFTBUS_ERR;
    }
    if (protocol == LNN_PROTOCOL_IP) {
        ret = LnnGetRemoteStrInfo(reqInfo->peerNetworkId, STRING_KEY_WLAN_IP, linkInfo.linkInfo.wlan.connInfo.addr,
            sizeof(linkInfo.linkInfo.wlan.connInfo.addr));
        if (ret != SOFTBUS_OK) {
            LNN_LOGE(LNN_LANE, "LnnGetRemote wlan ip error, ret=%{public}d", ret);
            return SOFTBUS_ERR;
        }
        if (strnlen(linkInfo.linkInfo.wlan.connInfo.addr, sizeof(linkInfo.linkInfo.wlan.connInfo.addr)) == 0 ||
            strncmp(linkInfo.linkInfo.wlan.connInfo.addr, "127.0.0.1", strlen("127.0.0.1")) == 0) {
            LNN_LOGE(LNN_LANE, "Wlan ip not found");
            return SOFTBUS_ERR;
        }
    } else {
        ret = LnnGetRemoteStrInfo(reqInfo->peerNetworkId, STRING_KEY_NODE_ADDR, linkInfo.linkInfo.wlan.connInfo.addr,
            sizeof(linkInfo.linkInfo.wlan.connInfo.addr));
        if (ret != SOFTBUS_OK) {
            LNN_LOGE(LNN_LANE, "LnnGetRemote wlan addr error, ret=%{public}d", ret);
            return SOFTBUS_ERR;
        }
    }
    if (reqInfo->transType == LANE_T_MSG) {
        ret = LnnGetRemoteNumInfo(reqInfo->peerNetworkId, NUM_KEY_PROXY_PORT, &port);
        LNN_LOGI(LNN_LANE, "LnnGetRemote proxy port");
    } else {
        ret = LnnGetRemoteNumInfo(reqInfo->peerNetworkId, NUM_KEY_SESSION_PORT, &port);
        LNN_LOGI(LNN_LANE, "LnnGetRemote session port");
    }
    if (ret < 0) {
        LNN_LOGE(LNN_LANE, "LnnGetRemote is failed.");
        return SOFTBUS_ERR;
    }
    int32_t channel = -1;
    bool is5GBand = false;
    bool isConnected = false;
    if (GetWlanLinkedAttribute(&channel, &is5GBand, &isConnected) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get wlan linked info fail");
    }
    if (!isConnected) {
        LNN_LOGE(LNN_LANE, "wlan is disconnected");
    }
    FillWlanLinkInfo(&linkInfo, is5GBand, channel, (uint16_t)port, protocol);

    ret = LaneDetectReliability(reqId, &linkInfo, callback);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lane detect reliability fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t LaneLinkOfCoc(uint32_t reqId, const LinkRequest *reqInfo, const LaneLinkCb *callback)
{
    LaneLinkInfo linkInfo;
    (void)memset_s(&linkInfo, sizeof(LaneLinkInfo), 0, sizeof(LaneLinkInfo));
    if (memcpy_s(linkInfo.linkInfo.ble.bleMac, BT_MAC_LEN, reqInfo->peerBleMac, BT_MAC_LEN) != EOK) {
        LNN_LOGE(LNN_LANE, "memcpy peerBleMac error");
        return SOFTBUS_MEM_ERR;
    }
    linkInfo.linkInfo.ble.psm = reqInfo->psm;
    if (strlen(linkInfo.linkInfo.ble.bleMac) == 0) {
        LNN_LOGE(LNN_LANE, "get peerBleMac error");
        return SOFTBUS_ERR;
    }
    char peerUdid[UDID_BUF_LEN] = {0};
    if (LnnGetRemoteStrInfo(reqInfo->peerNetworkId, STRING_KEY_DEV_UDID, peerUdid, UDID_BUF_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get udid error");
        return SOFTBUS_ERR;
    }
    if (SoftBusGenerateStrHash((uint8_t*)peerUdid, strlen(peerUdid),
        (uint8_t*)linkInfo.linkInfo.ble.deviceIdHash) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "generate deviceId hash err");
        return SOFTBUS_ERR;
    }
    linkInfo.linkInfo.ble.protoType = BLE_COC;
    linkInfo.type = LANE_COC;
    callback->OnLaneLinkSuccess(reqId, &linkInfo);
    return SOFTBUS_OK;
}

static int32_t LaneLinkOfCocDirect(uint32_t reqId, const LinkRequest *reqInfo, const LaneLinkCb *callback)
{
    LaneLinkInfo linkInfo;
    (void)memset_s(&linkInfo, sizeof(LaneLinkInfo), 0, sizeof(LaneLinkInfo));
    if (strcpy_s(linkInfo.linkInfo.bleDirect.networkId, NETWORK_ID_BUF_LEN, reqInfo->peerNetworkId) != EOK) {
        LNN_LOGE(LNN_LANE, "copy networkId fail");
        return SOFTBUS_MEM_ERR;
    }
    linkInfo.type = LANE_COC_DIRECT;
    linkInfo.linkInfo.bleDirect.protoType = BLE_COC;

    callback->OnLaneLinkSuccess(reqId, &linkInfo);
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
        callback->OnLaneLinkFail == NULL || callback->OnLaneLinkException == NULL) {
        LNN_LOGE(LNN_LANE, "the callback is invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    char *anonyNetworkId = NULL;
    Anonymize(reqInfo->peerNetworkId, &anonyNetworkId);
    LNN_LOGI(LNN_LANE, "build link, linktype=%{public}d, laneId=%{public}u, peerNetworkId=%{public}s",
        reqInfo->linkType, reqId, anonyNetworkId);
    AnonymizeFree(anonyNetworkId);
    if (g_linkTable[reqInfo->linkType](reqId, reqInfo, callback) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lane link is failed");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

void DestroyLink(const char *networkId, uint32_t reqId, LaneLinkType type, int32_t pid)
{
    LNN_LOGI(LNN_LANE, "type=%{public}d", type);
    if (networkId == NULL) {
        LNN_LOGE(LNN_LANE, "the networkId is nullptr");
        return;
    }
    if (type == LANE_P2P || type == LANE_HML) {
        LaneDeleteP2pAddress(networkId, false);
        LnnDisconnectP2p(networkId, pid, reqId);
    } else {
        LNN_LOGI(LNN_LANE, "ignore this link request, linkType=%{public}d", type);
    }
}

int32_t InitLaneLink(void)
{
    LaneInitP2pAddrList();
    if (SoftBusMutexInit(&g_laneResourceMutex, NULL) != SOFTBUS_OK) {
        LNN_LOGI(LNN_LANE, "g_laneResourceMutex init fail");
        return SOFTBUS_ERR;
    }
    ListInit(&g_laneResourceList);
    ListInit(&g_LinkInfoList);
    return SOFTBUS_OK;
}

void DeinitLaneLink(void)
{
    LnnDestroyP2p();
}
