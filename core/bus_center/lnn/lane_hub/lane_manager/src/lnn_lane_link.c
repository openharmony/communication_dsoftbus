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
#include "bus_center_info_key.h"
#include "bus_center_manager.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_lane.h"
#include "lnn_lane_common.h"
#include "lnn_lane_def.h"
#include "lnn_lane_score.h"
#include "lnn_lane_link_p2p.h"
#include "lnn_parameter_utils.h"
#include "lnn_lane_power_control.h"
#include "lnn_lane_reliability.h"
#include "lnn_lane_vap_info.h"
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
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_network_utils.h"
#include "softbus_protocol_def.h"
#include "softbus_utils.h"
#include "trans_network_statistics.h"
#include "wifi_direct_manager.h"

#define IF_NAME_BR  "br0"
#define IF_NAME_BLE "ble0"
#define IF_NAME_P2P "p2p0"
#define IF_NAME_HML "chba0"
#define TYPE_BUF_LEN 2
#define LANE_ID_BUF_LEN (UDID_BUF_LEN + UDID_BUF_LEN + TYPE_BUF_LEN)
#define LANE_ID_HASH_LEN 32
#define UDID_SHORT_HASH_HEXSTR_LEN_TMP 16
#define UDID_SHORT_HASH_LEN_TMP 8

static bool g_enabledLowPower = false;

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

static bool IsValidLinkAddr(const LaneLinkInfo *sourceLink, const LaneLinkInfo *linkInfoItem)
{
    switch (sourceLink->type) {
        case LANE_BR:
            if (strncmp(sourceLink->linkInfo.br.brMac, linkInfoItem->linkInfo.br.brMac, BT_MAC_LEN) != 0) {
                break;
            }
            return true;
        case LANE_BLE:
        case LANE_COC:
            if (strncmp(sourceLink->linkInfo.ble.bleMac, linkInfoItem->linkInfo.ble.bleMac, BT_MAC_LEN) != 0) {
                break;
            }
            return true;
        case LANE_P2P:
        case LANE_HML:
            if (strncmp(sourceLink->linkInfo.p2p.connInfo.peerIp,
                linkInfoItem->linkInfo.p2p.connInfo.peerIp, IP_LEN) != 0) {
                break;
            }
            return true;
        case LANE_BLE_DIRECT:
        case LANE_COC_DIRECT:
            if (strncmp(sourceLink->linkInfo.bleDirect.networkId, linkInfoItem->linkInfo.bleDirect.networkId,
                NETWORK_ID_BUF_LEN) != 0) {
                break;
            }
            return true;
        case LANE_WLAN_5G:
        case LANE_WLAN_2P4G:
        case LANE_ETH:
            if (strncmp(sourceLink->linkInfo.wlan.connInfo.addr,
                linkInfoItem->linkInfo.wlan.connInfo.addr, MAX_SOCKET_ADDR_LEN) != 0) {
                break;
            }
            return true;
        default:
            LNN_LOGE(LNN_LANE, "invalid linkType=%{public}d", sourceLink->type);
            return false;
    }
    LNN_LOGE(LNN_LANE, "lane resource is different form input link addr, linkType=%{public}d", sourceLink->type);
    return false;
}

static LaneResource* GetValidLaneResource(const LaneLinkInfo *linkInfoItem)
{
    LaneResource *item = NULL;
    LaneResource *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_laneResource.list, LaneResource, node) {
        if (linkInfoItem->type == item->link.type &&
            strncmp(item->link.peerUdid, linkInfoItem->peerUdid, UDID_BUF_LEN) == 0 &&
            IsValidLinkAddr(&(item->link), linkInfoItem)) {
            return item;
        }
    }
    return NULL;
}

static LnnVapType GetVapType(LaneLinkType linkType)
{
    switch (linkType) {
        case LANE_HML:
            return LNN_VAP_HML;
        case LANE_P2P:
            return LNN_VAP_P2P;
        default:
            LNN_LOGE(LNN_LANE, "unexcepted linkType=%{public}d", linkType);
            return LNN_VAP_UNKNOWN;
    }
}

static void AddVapInfo(const LaneLinkInfo *linkInfo)
{
    LnnVapType vapType = GetVapType(linkInfo->type);
    if (vapType == LNN_VAP_UNKNOWN) {
        LNN_LOGE(LNN_LANE, "addVap fail, vapType unknown");
        return;
    }
    LnnVapAttr vapAttr;
    (void)memset_s(&vapAttr, sizeof(vapAttr), 0, sizeof(vapAttr));
    vapAttr.isEnable = true;
    vapAttr.channelId = linkInfo->linkInfo.p2p.channel;
    int32_t ret = LnnAddLocalVapInfo(vapType, (const LnnVapAttr *)&vapAttr);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "add vapInfo err, ret=%{public}d", ret);
    }
}

static void DeleteVapInfo(LaneLinkType linkType)
{
    LnnVapType vapType = GetVapType(linkType);
    if (vapType == LNN_VAP_UNKNOWN) {
        LNN_LOGE(LNN_LANE, "deleteVap fail, vapType unknown");
        return;
    }
    int32_t ret = LnnDeleteLocalVapInfo(vapType);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "delete vapInfo fail=%{public}d", linkType);
    }
}

static int32_t GetRemoteMacAddrByLocalIp(const char *localIp, char *macAddr, uint32_t macAddrLen)
{
    struct WifiDirectManager *wifiDirectMgr = GetWifiDirectManager();
    if (wifiDirectMgr == NULL) {
        LNN_LOGE(LNN_LANE, "get wifi direct manager fail");
        return SOFTBUS_NOT_FIND;
    }
    char localMac[LNN_MAC_LEN];
    (void)memset_s(localMac, sizeof(localMac), 0, sizeof(localMac));
    int32_t ret = wifiDirectMgr->getLocalAndRemoteMacByLocalIp(localIp, localMac, LNN_MAC_LEN,
        macAddr, macAddrLen);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get macAddr by localIp fail, ret=%{public}d", ret);
        return ret;
    }
    return SOFTBUS_OK;
}

static void SetWifiDirectLinkInfo(P2pLinkInfo *p2pInfo, WifiDirectLinkInfo *wifiDirectInfo, uint32_t bandWidth)
{
    wifiDirectInfo->linkType = LANE_HML;
    wifiDirectInfo->bandWidth = bandWidth;
    int32_t ret = GetRemoteMacAddrByLocalIp(p2pInfo->connInfo.localIp,
        wifiDirectInfo->wifiDirectMac, LNN_MAC_LEN);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get hml macAddr fail=%{public}d", ret);
        return;
    }
}

static void SetLanePowerStatus(bool status)
{
    if (LaneLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lane lock fail");
        return;
    }
    g_enabledLowPower = status;
    LaneUnlock();
}

static void HandleDetectWifiDirectApply(bool isDisableLowPower,  WifiDirectLinkInfo *wifiDirectInfo)
{
    if (wifiDirectInfo == NULL) {
        LNN_LOGE(LNN_LANE, "invalid param");
        return;
    }
    if (isDisableLowPower) {
        DisablePowerControl(wifiDirectInfo);
        SetLanePowerStatus(false);
    } else {
        int32_t ret = EnablePowerControl(wifiDirectInfo);
        SetLanePowerStatus(true);
        if (ret != SOFTBUS_OK) {
            LNN_LOGE(LNN_LANE, "enable fail, ret=%{public}d", ret);
            SetLanePowerStatus(false);
        }
    }
}

void DetectDisableWifiDirectApply(void)
{
    if (!g_enabledLowPower) {
        LNN_LOGI(LNN_LANE, "low power not enabled");
        return;
    }
    WifiDirectLinkInfo wifiDirectInfo;
    (void)memset_s(&wifiDirectInfo, sizeof(wifiDirectInfo), 0, sizeof(wifiDirectInfo));
    if (LaneLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lane lock fail");
        return;
    }
    LaneResource *item = NULL;
    LaneResource *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_laneResource.list, LaneResource, node) {
        LNN_LOGI(LNN_LANE, "link.type=%{public}d, link.bw=%{public}d", item->link.type, item->link.linkInfo.p2p.bw);
        if (item->link.type == LANE_HML && (item->link.linkInfo.p2p.bw == LANE_BW_160M ||
            item->link.linkInfo.p2p.bw == LANE_BW_80P80M)) {
            SetWifiDirectLinkInfo(&item->link.linkInfo.p2p, &wifiDirectInfo, item->link.linkInfo.p2p.bw);
        }
    }
    LaneUnlock();
    HandleDetectWifiDirectApply(true, &wifiDirectInfo);
}

void DetectEnableWifiDirectApply(void)
{
    int32_t activeHml = 0;
    int32_t rawHml = 0;
    bool isDisableLowPower = false;
    WifiDirectLinkInfo wifiDirectInfo;
    (void)memset_s(&wifiDirectInfo, sizeof(wifiDirectInfo), 0, sizeof(wifiDirectInfo));
    if (LaneLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lane lock fail");
        return;
    }
    LaneResource *item = NULL;
    LaneResource *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_laneResource.list, LaneResource, node) {
        LNN_LOGI(LNN_LANE, "link.type=%{public}d, link.bw=%{public}d", item->link.type, item->link.linkInfo.p2p.bw);
        if (item->link.type == LANE_HML && (item->link.linkInfo.p2p.bw == LANE_BW_160M ||
            item->link.linkInfo.p2p.bw == LANE_BW_80P80M)) {
            if (item->clientRef > 0) {
                activeHml++;
            }
            SetWifiDirectLinkInfo(&item->link.linkInfo.p2p, &wifiDirectInfo, item->link.linkInfo.p2p.bw);
        }
        if (item->link.type == LANE_HML_RAW) {
            rawHml++;
        }
    }
    if ((g_enabledLowPower || rawHml > 0) || (!g_enabledLowPower && activeHml > 1)) {
        isDisableLowPower = true;
    }
    LaneUnlock();
    LNN_LOGI(LNN_LANE, "activeHml=%{public}d, rawHml=%{public}d, isDisableLowPower=%{public}d",
        activeHml, rawHml, isDisableLowPower);
    HandleDetectWifiDirectApply(isDisableLowPower, &wifiDirectInfo);
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
    AddVapInfo(linkInfo);
    return SOFTBUS_OK;
}

static void AddNetworkResourceInner(const LaneLinkInfo *linkInfo, uint64_t laneId)
{
    if (linkInfo == NULL) {
        LNN_LOGE(LNN_LANE, "invalid param");
        return;
    }
    if (linkInfo->type != LANE_BR && linkInfo->type != LANE_BLE && linkInfo->type != LANE_P2P &&
        linkInfo->type != LANE_HML) {
        return;
    }

    NetworkResource *networkResource = (NetworkResource *)SoftBusCalloc(sizeof(NetworkResource));
    if (networkResource == NULL) {
        LNN_LOGE(LNN_LANE, "malloc network resource fail");
        return;
    }
    LnnGetLocalStrInfo(STRING_KEY_NETWORKID, networkResource->localUdid, NETWORK_ID_BUF_LEN);
    networkResource->laneId = laneId;
    networkResource->laneLinkType = linkInfo->type;
    char *anonyLocalUdid = NULL;
    char *anonyRemoteUdid = NULL;
    Anonymize(networkResource->localUdid, &anonyLocalUdid);
    Anonymize(linkInfo->peerUdid, &anonyRemoteUdid);
    if (anonyLocalUdid == NULL || strcpy_s(networkResource->localUdid, NETWORK_ID_BUF_LEN, anonyLocalUdid) != EOK) {
        LNN_LOGE(LNN_LANE, "strcpy localUdid fail");
    }
    if (anonyRemoteUdid == NULL || strcpy_s(networkResource->peerUdid, NETWORK_ID_BUF_LEN, anonyRemoteUdid) != EOK) {
        LNN_LOGE(LNN_LANE, "strcpy peerUdid fail");
    }
    AddNetworkResource(networkResource);
    SoftBusFree(networkResource);
    AnonymizeFree(anonyLocalUdid);
    AnonymizeFree(anonyRemoteUdid);
}

static int32_t UpdateExistLaneResource(LaneResource *resourceItem, bool isServerSide)
{
    if (isServerSide) {
        if (resourceItem->isServerSide) {
            LNN_LOGE(LNN_LANE, "server laneId=%{public}" PRIu64 " is existed, add server lane resource fail",
            resourceItem->laneId);
            return SOFTBUS_LANE_TRIGGER_LINK_FAIL;
        }
        resourceItem->isServerSide = true;
        LNN_LOGI(LNN_LANE, "add server laneId=%{public}" PRIu64 " to resource pool succ",
            resourceItem->laneId);
        return SOFTBUS_OK;
    }
    resourceItem->clientRef++;
    LNN_LOGI(LNN_LANE, "add client laneId=%{public}" PRIu64 " to resource pool succ, clientRef=%{public}u",
        resourceItem->laneId, resourceItem->clientRef);
    return SOFTBUS_OK;
}

int32_t AddLaneResourceToPool(const LaneLinkInfo *linkInfo, uint64_t laneId, bool isServerSide)
{
    if (linkInfo == NULL || laneId == INVALID_LANE_ID) {
        LNN_LOGE(LNN_LANE, "linkInfo is nullptr or invalid laneId");
        return SOFTBUS_INVALID_PARAM;
    }
    if (LaneLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lane lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    int32_t addResult = SOFTBUS_LANE_RESOURCE_EXCEPT;
    LaneResource* resourceItem = GetValidLaneResource(linkInfo);
    if (resourceItem != NULL) {
        addResult = UpdateExistLaneResource(resourceItem, isServerSide);
        LaneUnlock();
        return addResult;
    }
    LaneUnlock();
    addResult = CreateNewLaneResource(linkInfo, laneId, isServerSide);
    if (addResult != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "create laneResource fail, result=%{public}d", addResult);
        return addResult;
    }
    if (!isServerSide) {
        AddNetworkResourceInner(linkInfo, laneId);
    }
    return SOFTBUS_OK;
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
            if (g_laneResource.cnt != 0) {
                g_laneResource.cnt--;
            }
        } else {
            item->isServerSide = false;
        }
    } else {
        isServer = item->isServerSide;
        ref = item->clientRef;
        if (item->clientRef != 0) {
            ref = --item->clientRef;
        }
        if (!isServer && ref == 0) {
            DeleteNetworkResourceByLaneId(laneId);
            ListDelete(&item->node);
            SoftBusFree(item);
            if (g_laneResource.cnt != 0) {
                g_laneResource.cnt--;
            }
        }
    }
    LNN_LOGI(LNN_LANE, "del laneId=%{public}" PRIu64 " resource, isServer=%{public}d, clientRef=%{public}u",
        laneId, isServer, ref);
    return true;
}

static void DumpWifiDirectInfo(const LaneLinkInfo *resource)
{
    char *anonyPeerUdid = NULL;
    Anonymize(resource->peerUdid, &anonyPeerUdid);
    LNN_LOGI(LNN_LANE, "peerUdid=%{public}s, linkType=%{public}s, channel=%{public}d", AnonymizeWrapper(anonyPeerUdid),
        resource->type == LANE_HML ? "hml" : "p2p", resource->linkInfo.p2p.channel);
    AnonymizeFree(anonyPeerUdid);
}

static void ProcessVapInfo(void)
{
    bool hasHmlVap = false;
    bool hasP2pVap = false;
    if (LaneLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lane lock fail");
        return;
    }
    LaneResource *next = NULL;
    LaneResource *item = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_laneResource.list, LaneResource, node) {
        if ((item->clientRef != 0 || item->isServerSide) && item->link.type == LANE_HML) {
            hasHmlVap = true;
            LNN_LOGI(LNN_LANE, "HML use: ref=%{public}d, server=%{public}d", item->clientRef, item->isServerSide);
            DumpWifiDirectInfo((const LaneLinkInfo *)&item->link);
        }
        if (item->clientRef != 0 && item->link.type == LANE_P2P) {
            hasP2pVap = true;
            LNN_LOGI(LNN_LANE, "P2p use: ref=%{public}d", item->clientRef);
            DumpWifiDirectInfo((const LaneLinkInfo *)&item->link);
        }
        if (hasHmlVap && hasP2pVap) {
            break;
        }
    }
    LaneUnlock();
    if (!hasHmlVap) {
        LNN_LOGI(LNN_LANE, "delete hml vap info");
        DeleteVapInfo(LANE_HML);
    }
    if (!hasP2pVap) {
        LNN_LOGI(LNN_LANE, "delete p2p vap info");
        DeleteVapInfo(LANE_P2P);
    }
}

int32_t DelLaneResourceByLaneId(uint64_t laneId, bool isServerSide)
{
    if (LaneLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lane lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    LNN_LOGI(LNN_LANE, "start to del laneId=%{public}" PRIu64 " resource, isServer=%{public}d",
            laneId, isServerSide);
    LaneResource *next = NULL;
    LaneResource *item = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_laneResource.list, LaneResource, node) {
        if (IsNeedDelResource(laneId, isServerSide, item)) {
            LaneUnlock();
            ProcessVapInfo();
            return SOFTBUS_OK;
        }
    }
    LaneUnlock();
    LNN_LOGI(LNN_LANE, "not found laneId=%{public}" PRIu64 " resource when del", laneId);
    return SOFTBUS_LANE_RESOURCE_NOT_FOUND;
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
            ProcessVapInfo();
            return SOFTBUS_OK;
        }
    }
    LaneUnlock();
    LNN_LOGI(LNN_LANE, "not found laneId=%{public}" PRIu64 " resource when clear", laneId);
    return SOFTBUS_LANE_RESOURCE_NOT_FOUND;
}

static bool LinkTypeCheck(LaneLinkType type)
{
    static const LaneLinkType supportList[] = { LANE_P2P, LANE_HML, LANE_WLAN_2P4G, LANE_WLAN_5G, LANE_BR, LANE_BLE,
        LANE_BLE_DIRECT, LANE_P2P_REUSE, LANE_COC, LANE_COC_DIRECT, LANE_BLE_REUSE, LANE_HML_RAW };
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
    LNN_LOGE(LNN_LANE, "no find lane resource by linktype=%{public}d, peerUdid=%{public}s",
        type, AnonymizeWrapper(anonyPeerUdid));
    AnonymizeFree(anonyPeerUdid);
    return SOFTBUS_LANE_RESOURCE_NOT_FOUND;
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
        return SOFTBUS_LANE_RESOURCE_NOT_FOUND;
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
    return SOFTBUS_LANE_RESOURCE_NOT_FOUND;
}

int32_t UpdateLaneResourceLaneId(uint64_t oldLaneId, uint64_t newLaneId, const char *peerUdid)
{
    if (oldLaneId == INVALID_LANE_ID || newLaneId == INVALID_LANE_ID || peerUdid == NULL) {
        LNN_LOGE(LNN_LANE, "get invalid laneId");
        return SOFTBUS_INVALID_PARAM;
    }
    if (LaneLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lane lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    LaneResource *item = NULL;
    LaneResource *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_laneResource.list, LaneResource, node) {
        if (item->laneId == oldLaneId) {
            if (strcpy_s(item->link.peerUdid, UDID_BUF_LEN, peerUdid) != EOK) {
                LNN_LOGE(LNN_LANE, "strcpy udid fail");
                LaneUnlock();
                return SOFTBUS_STRCPY_ERR;
            }
            item->laneId = newLaneId;
            LNN_LOGI(LNN_LANE, "find and refresh oldLaneId=%{public}" PRIu64 ", newLaneId=%{public}" PRIu64,
                oldLaneId, newLaneId);
            LaneUnlock();
            return SOFTBUS_OK;
        }
    }
    LaneUnlock();
    LNN_LOGE(LNN_LANE, "no found lane resource by laneId=%{public}" PRIu64 "", oldLaneId);
    return SOFTBUS_NOT_FIND;
}

int32_t CheckLaneResourceNumByLinkType(const char *peerUdid, LaneLinkType type, int32_t *laneNum)
{
    if (peerUdid == NULL || type >= LANE_LINK_TYPE_BUTT) {
        return SOFTBUS_INVALID_PARAM;
    }
    uint32_t num = 0;
    if (LaneLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lane lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    LaneResource *item = NULL;
    LaneResource *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_laneResource.list, LaneResource, node) {
        if (strcmp(peerUdid, item->link.peerUdid) == 0 && type == item->link.type) {
            num++;
            LaneUnlock();
            *laneNum = num;
            return SOFTBUS_OK;
        }
    }
    LaneUnlock();
    char *anonyPeerUdid = NULL;
    Anonymize(peerUdid, &anonyPeerUdid);
    LNN_LOGE(LNN_LANE, "no find lane resource by linktype=%{public}d, peerUdid=%{public}s",
        type, AnonymizeWrapper(anonyPeerUdid));
    AnonymizeFree(anonyPeerUdid);
    return SOFTBUS_NOT_FIND;
}

static int32_t CopyAllDevIdWithoutLock(LaneLinkType type, uint8_t resourceNum, char **devIdList, uint8_t *devIdCnt)
{
    char (*itemList)[NETWORK_ID_BUF_LEN] =
        (char (*)[NETWORK_ID_BUF_LEN])SoftBusCalloc(resourceNum * NETWORK_ID_BUF_LEN);
    if (itemList == NULL) {
        LNN_LOGE(LNN_LANE, "device id list calloc fail");
        return SOFTBUS_MALLOC_ERR;
    }
    char (*tmpList)[NETWORK_ID_BUF_LEN] = itemList;
    char networkId[NETWORK_ID_BUF_LEN] = {0};
    uint8_t tmpCnt = 0;
    LaneResource *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_laneResource.list, LaneResource, node) {
        if (item->link.type == type) {
            if (LnnGetNetworkIdByUdid(item->link.peerUdid, networkId, NETWORK_ID_BUF_LEN) != SOFTBUS_OK) {
                LNN_LOGE(LNN_LANE, "get networkid fail");
                continue;
            }
            if (memcpy_s(*tmpList, NETWORK_ID_BUF_LEN, networkId, NETWORK_ID_BUF_LEN) != EOK) {
                LNN_LOGE(LNN_LANE, "memcpy networkid fail");
                continue;
            }
            char *anonyNetworkId = NULL;
            Anonymize(networkId, &anonyNetworkId);
            LNN_LOGI(LNN_LANE, "networkId=%{public}s exist link=%{public}d", AnonymizeWrapper(anonyNetworkId), type);
            AnonymizeFree(anonyNetworkId);
            tmpList += 1;
            tmpCnt += 1;
        }
    }
    if (tmpCnt == 0) {
        SoftBusFree(itemList);
        return SOFTBUS_LANE_GET_LEDGER_INFO_ERR;
    }
    *devIdList = (char *)itemList;
    *devIdCnt = tmpCnt;
    return SOFTBUS_OK;
}

int32_t GetAllDevIdWithLinkType(LaneLinkType type, char **devIdList, uint8_t *devIdCnt)
{
    if (devIdList == NULL || devIdCnt == NULL || type == LANE_LINK_TYPE_BUTT) {
        LNN_LOGE(LNN_LANE, "invalid parem");
        return SOFTBUS_INVALID_PARAM;
    }
    if (LaneLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lane lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    uint8_t resourceNum = 0;
    LaneResource *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_laneResource.list, LaneResource, node) {
        if (item->link.type == type) {
            ++resourceNum;
        }
    }
    if (resourceNum == 0) {
        LaneUnlock();
        LNN_LOGE(LNN_LANE, "lane resource no link=%{public}d", type);
        return SOFTBUS_LANE_RESOURCE_NOT_FOUND;
    }
    LNN_LOGE(LNN_LANE, "lane resource exist link=%{public}d, num=%{public}u", type, resourceNum);
    int32_t ret = CopyAllDevIdWithoutLock(type, resourceNum, devIdList, devIdCnt);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "cpoy all device id fail");
    }
    LaneUnlock();
    return ret;
}

static int32_t ConvertUdidToHexStr(const char *peerUdid, char *udidHashStr, uint32_t hashStrLen)
{
    if (peerUdid == NULL || udidHashStr == NULL) {
        LNN_LOGE(LNN_LANE, "invalid parem");
        return SOFTBUS_INVALID_PARAM;
    }
    uint8_t peerUdidHash[UDID_HASH_LEN] = {0};
    int32_t ret = SoftBusGenerateStrHash((const unsigned char*)peerUdid, strlen(peerUdid), peerUdidHash);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "generate udidHash fail, ret=%{public}d", ret);
        return ret;
    }
    ret = ConvertBytesToHexString(udidHashStr, hashStrLen, peerUdidHash, UDID_SHORT_HASH_LEN_TMP);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "convert bytes to string fail, ret=%{public}d", ret);
        return ret;
    }
    return SOFTBUS_OK;
}

static int32_t FetchLaneResourceByDevId(const char *peerNetworkId, LaneLinkType type, bool isSameDevice)
{
    if (peerNetworkId == NULL) {
        LNN_LOGE(LNN_LANE, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    char peerUdid[UDID_BUF_LEN] = {0};
    if (LnnGetRemoteStrInfo(peerNetworkId, STRING_KEY_DEV_UDID, peerUdid, UDID_BUF_LEN) != SOFTBUS_OK) {
        char *anonyPeerNetworkId = NULL;
        Anonymize(peerNetworkId, &anonyPeerNetworkId);
        LNN_LOGI(LNN_LANE, "get peerUdid fail, peerNetworkId=%{public}s", AnonymizeWrapper(anonyPeerNetworkId));
        AnonymizeFree(anonyPeerNetworkId);
        return SOFTBUS_LANE_GET_LEDGER_INFO_ERR;
    }
    if (LaneLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lane lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    LaneResource *item = NULL;
    LaneResource *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_laneResource.list, LaneResource, node) {
        if (type != item->link.type) {
            continue;
        }
        if ((!isSameDevice && strcmp(peerUdid, item->link.peerUdid) != 0) ||
            (isSameDevice && strcmp(peerUdid, item->link.peerUdid) == 0)) {
            LaneUnlock();
            LNN_LOGI(LNN_LANE, "match expected laneLink by networkId, linkType=%{public}d, isSameDevice=%{public}d",
                type, isSameDevice);
            return SOFTBUS_OK;
        }
    }
    LaneUnlock();
    LNN_LOGI(LNN_LANE, "not found lane resource, linkType=%{public}d, isSameDevice=%{public}d", type, isSameDevice);
    return SOFTBUS_LANE_RESOURCE_NOT_FOUND;
}

static int32_t FetchLaneResourceByDevIdHash(const char *udidHashStr, LaneLinkType type, bool isSameDevice)
{
    if (udidHashStr == NULL) {
        LNN_LOGE(LNN_LANE, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (LaneLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lane lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    LaneResource *item = NULL;
    LaneResource *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_laneResource.list, LaneResource, node) {
        if (type != item->link.type) {
            continue;
        }
        char hashHexStr[UDID_SHORT_HASH_HEXSTR_LEN_TMP + 1] = {0};
        if (ConvertUdidToHexStr(item->link.peerUdid, hashHexStr, UDID_SHORT_HASH_HEXSTR_LEN_TMP + 1) != SOFTBUS_OK) {
            continue;
        }
        if ((!isSameDevice && strcmp(hashHexStr, udidHashStr) != 0) ||
            (isSameDevice && strcmp(hashHexStr, udidHashStr) == 0)) {
            LaneUnlock();
            LNN_LOGI(LNN_LANE, "match expected laneLink by udidHashStr, linkType=%{public}d,"
                " isSameDevice=%{public}d", type, isSameDevice);
            return SOFTBUS_OK;
        }
    }
    LaneUnlock();
    LNN_LOGI(LNN_LANE, "not found lane resource, linkType=%{public}d, isSameDevice=%{public}d", type, isSameDevice);
    return SOFTBUS_LANE_RESOURCE_NOT_FOUND;
}

int32_t QueryOtherLaneResource(const DevIdentifyInfo *inputInfo, LaneLinkType type)
{
    if (inputInfo == NULL || type >= LANE_LINK_TYPE_BUTT) {
        LNN_LOGE(LNN_LANE, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (inputInfo->type == IDENTIFY_TYPE_DEV_ID) {
        return FetchLaneResourceByDevId(inputInfo->devInfo.peerDevId, type, false);
    } else if (inputInfo->type == IDENTIFY_TYPE_UDID_HASH && strlen(inputInfo->devInfo.udidHash) > 0) {
        return FetchLaneResourceByDevIdHash(inputInfo->devInfo.udidHash, type, false);
    }
    LNN_LOGE(LNN_LANE, "no fetch lane resource");
    return SOFTBUS_LANE_RESOURCE_NOT_FOUND;
}

bool FindLaneResourceByDevInfo(const DevIdentifyInfo *inputInfo, LaneLinkType type)
{
    if (inputInfo == NULL || type >= LANE_LINK_TYPE_BUTT) {
        LNN_LOGE(LNN_LANE, "invalid param");
        return false;
    }
    int32_t ret = SOFTBUS_OK;
    if (inputInfo->type == IDENTIFY_TYPE_DEV_ID) {
        ret = FetchLaneResourceByDevId(inputInfo->devInfo.peerDevId, type, true);
        if (ret != SOFTBUS_OK) {
            return false;
        }
        return true;
    } else if (inputInfo->type == IDENTIFY_TYPE_UDID_HASH && strlen(inputInfo->devInfo.udidHash) > 0) {
        ret = FetchLaneResourceByDevIdHash(inputInfo->devInfo.udidHash, type, true);
        if (ret != SOFTBUS_OK) {
            return false;
        }
        return true;
    }
    LNN_LOGE(LNN_LANE, "no fetch lane resource");
    return false;
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
    callback->onLaneLinkSuccess(reqId, linkInfo.type, &linkInfo);
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

static void LaneDeinitP2pAddrList(void)
{
    if (SoftBusMutexLock(&g_P2pAddrList.lock) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "SoftBusMutexLock fail");
        return;
    }
    P2pAddrNode *item = NULL;
    P2pAddrNode *nextItem = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, nextItem, &g_P2pAddrList.list, P2pAddrNode, node) {
        ListDelete(&item->node);
        SoftBusFree(item);
    }
    g_P2pAddrList.cnt = 0;
    SoftBusMutexUnlock(&g_P2pAddrList.lock);
    (void)SoftBusMutexDestroy(&g_P2pAddrList.lock);
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
        P2pAddrNode *p2pAddrNode = (P2pAddrNode *)SoftBusCalloc(sizeof(P2pAddrNode));
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
        P2pAddrNode *p2pAddrNode = (P2pAddrNode *)SoftBusCalloc(sizeof(P2pAddrNode));
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
        linkInfo.linkInfo.ble.psm = (int32_t)connection->psm;
    } else if (type == BLE_GATT) {
        linkInfo.type = LANE_BLE;
    }
    ConnBleReturnConnection(&connection);
    callback->onLaneLinkSuccess(reqId, linkInfo.type, &linkInfo);
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
            return SOFTBUS_INVALID_PARAM;
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
    callback->onLaneLinkSuccess(reqId, linkInfo.type, &linkInfo);
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
        return SOFTBUS_STRCPY_ERR;
    }
    linkInfo.type = LANE_BLE_DIRECT;
    linkInfo.linkInfo.bleDirect.protoType = BLE_GATT;
    callback->onLaneLinkSuccess(reqId, linkInfo.type, &linkInfo);
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

static int32_t LaneLinkOfHmlRaw(uint32_t reqId, const LinkRequest *reqInfo, const LaneLinkCb *callback)
{
    LinkRequest linkInfo;
    if (memcpy_s(&linkInfo, sizeof(LinkRequest), reqInfo, sizeof(LinkRequest)) != EOK) {
        LNN_LOGE(LNN_LANE, "hml copy linkreqinfo fail");
        return SOFTBUS_MEM_ERR;
    }
    linkInfo.linkType = LANE_HML_RAW;
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
        return SOFTBUS_LANE_NOT_FOUND;
    }
    linkInfo.linkInfo.wlan.connInfo.protocol = LNN_PROTOCOL_IP;
    linkInfo.linkInfo.wlan.connInfo.port = port;
    if (memcpy_s(linkInfo.linkInfo.wlan.connInfo.addr, MAX_SOCKET_ADDR_LEN, ipAddr, MAX_SOCKET_ADDR_LEN) != EOK) {
        return SOFTBUS_MEM_ERR;
    }
    callback->onLaneLinkSuccess(reqId, linkInfo.type, &linkInfo);
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
        ret = LnnGetRemoteNumInfo(reqInfo->peerNetworkId, NUM_KEY_PROXY_PORT, &port);
        LNN_LOGI(LNN_LANE, "get remote proxy port, port=%{public}d, ret=%{public}d", port, ret);
    } else {
        ret = LnnGetRemoteNumInfo(reqInfo->peerNetworkId, NUM_KEY_SESSION_PORT, &port);
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
        if (LnnGetRemoteStrInfo(reqInfo->peerNetworkId, STRING_KEY_WLAN_IP, linkInfo->linkInfo.wlan.connInfo.addr,
            sizeof(linkInfo->linkInfo.wlan.connInfo.addr)) != SOFTBUS_OK) {
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
        return SOFTBUS_INVALID_PARAM;
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
    callback->onLaneLinkSuccess(reqId, linkInfo.type, &linkInfo);
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
        return SOFTBUS_STRCPY_ERR;
    }
    linkInfo.type = LANE_COC_DIRECT;
    linkInfo.linkInfo.bleDirect.protoType = BLE_COC;

    callback->onLaneLinkSuccess(reqId, linkInfo.type, &linkInfo);
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
    [LANE_HML_RAW] = LaneLinkOfHmlRaw,
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
    if (networkId == NULL) {
        LNN_LOGE(LNN_LANE, "the networkId is nullptr");
        return SOFTBUS_INVALID_PARAM;
    }
    if (type == LANE_HML && IsPowerControlEnabled()) {
        DetectDisableWifiDirectApply();
    }
    if (type == LANE_P2P || type == LANE_HML || type == LANE_HML_RAW) {
        LaneDeleteP2pAddress(networkId, false);
        int32_t errCode = LnnDisconnectP2p(networkId, laneReqId);
        if (errCode != SOFTBUS_OK) {
            return errCode;
        }
    } else {
        LNN_LOGI(LNN_LANE, "ignore destroy linkType=%{public}d, laneReqId=%{public}u", type, laneReqId);
        PostDelayDestroyMessage(laneReqId, INVALID_LANE_ID, 0);
    }
    return SOFTBUS_OK;
}

int32_t InitLaneLink(void)
{
    LaneInitP2pAddrList();
    if (SoftBusMutexInit(&g_laneResource.lock, NULL) != SOFTBUS_OK) {
        LNN_LOGI(LNN_LANE, "lane resource mutex init fail");
        return SOFTBUS_NO_INIT;
    }
    ListInit(&g_laneResource.list);
    g_laneResource.cnt = 0;
    return SOFTBUS_OK;
}

void DeinitLaneLink(void)
{
    LaneDeinitP2pAddrList();
    if (LaneLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lane lock fail");
        return;
    }
    LaneResource *item = NULL;
    LaneResource *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_laneResource.list, LaneResource, node) {
        ListDelete(&item->node);
        SoftBusFree(item);
    }
    g_laneResource.cnt = 0;
    LaneUnlock();
    LnnDestroyP2p();
    (void)SoftBusMutexDestroy(&g_laneResource.lock);
}
