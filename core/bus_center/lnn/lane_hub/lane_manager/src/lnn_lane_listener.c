/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "lnn_lane_listener.h"

#include <securec.h>

#include "anonymizer.h"
#include "bus_center_manager.h"
#include "common_list.h"
#include "lnn_lane.h"
#include "lnn_lane_common.h"
#include "lnn_lane_def.h"
#include "lnn_lane_interface.h"
#include "lnn_log.h"
#include "message_handler.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "wifi_direct_manager.h"

static SoftBusMutex g_laneStateListenerMutex;
static ListNode g_laneListenerList;
static ListNode g_laneTypeInfoList;
static ListNode g_laneStatusNotifyStateList;

static int32_t LaneListenerLock(void)
{
    return SoftBusMutexLock(&g_laneStateListenerMutex);
}

static void LaneListenerUnlock(void)
{
    (void)SoftBusMutexUnlock(&g_laneStateListenerMutex);
}

static bool LaneTypeCheck(LaneType type)
{
    static const LaneType supportList[] = {LANE_TYPE_HDLC, LANE_TYPE_TRANS, LANE_TYPE_CTRL};
    uint32_t size = sizeof(supportList) / sizeof(LaneType);
    for (uint32_t i = 0; i < size; i++) {
        if (supportList[i] == type) {
            return true;
        }
    }
    LNN_LOGE(LNN_LANE, "LaneType=%{public}d not supported", type);
    return false;
}

static LaneTypeInfo* LaneTypeInfoIsExist(const LaneTypeInfo *laneTypeInfo)
{
    LaneTypeInfo *item = NULL;
    LaneTypeInfo *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_laneTypeInfoList, LaneTypeInfo, node) {
        if (laneTypeInfo->laneType == item->laneType &&
            laneTypeInfo->laneLinkInfo.type == item->laneLinkInfo.type) {
            return item;
        }
    }
    return NULL;
}

static int32_t CreateLaneTypeInfoItem(const LaneLinkInfo *inputLinkInfo, LaneTypeInfo *outputLaneTypeInfo)
{
    switch (inputLinkInfo->type) {
        case LANE_BR:
            if (memcpy_s(&(outputLaneTypeInfo->laneLinkInfo.linkInfo.br), sizeof(BrLinkInfo),
                &(inputLinkInfo->linkInfo.br), sizeof(BrLinkInfo)) != EOK) {
                return SOFTBUS_ERR;
            }
            break;
        case LANE_BLE:
        case LANE_COC:
            if (memcpy_s(&(outputLaneTypeInfo->laneLinkInfo.linkInfo.ble), sizeof(BleLinkInfo),
                &(inputLinkInfo->linkInfo.ble), sizeof(BleLinkInfo)) != EOK) {
                return SOFTBUS_ERR;
            }
            break;
        case LANE_P2P:
        case LANE_HML:
            if (memcpy_s(&(outputLaneTypeInfo->laneLinkInfo.linkInfo.p2p), sizeof(P2pLinkInfo),
                &(inputLinkInfo->linkInfo.p2p), sizeof(P2pLinkInfo)) != EOK) {
                return SOFTBUS_ERR;
            }
            break;
        case LANE_WLAN_5G:
        case LANE_WLAN_2P4G:
        case LANE_P2P_REUSE:
            if (memcpy_s(&(outputLaneTypeInfo->laneLinkInfo.linkInfo.wlan), sizeof(WlanLinkInfo),
                &(inputLinkInfo->linkInfo.wlan), sizeof(WlanLinkInfo)) != EOK) {
                return SOFTBUS_ERR;
            }
            break;
        case LANE_BLE_DIRECT:
        case LANE_COC_DIRECT:
            if (memcpy_s(&(outputLaneTypeInfo->laneLinkInfo.linkInfo.bleDirect), sizeof(BleDirectInfo),
                &(inputLinkInfo->linkInfo.bleDirect), sizeof(BleDirectInfo)) != EOK) {
                return SOFTBUS_ERR;
            }
            break;
        default:
            return SOFTBUS_ERR;
    }
    outputLaneTypeInfo->laneLinkInfo.type = inputLinkInfo->type;
    outputLaneTypeInfo->laneLinkInfo.laneReqId = inputLinkInfo->laneReqId;
    return SOFTBUS_OK;
}

static int32_t AddLaneTypeInfoItem(const LaneTypeInfo *laneTypeInfo)
{
    if (laneTypeInfo == NULL) {
        LNN_LOGE(LNN_LANE, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    LaneTypeInfo *laneTypeInfoItem = (LaneTypeInfo *)SoftBusMalloc(sizeof(LaneTypeInfo));
    if (laneTypeInfoItem == NULL) {
        LNN_LOGE(LNN_LANE, "laneTypeInfoItem malloc fail");
        return SOFTBUS_MALLOC_ERR;
    }
    if (CreateLaneTypeInfoItem(&laneTypeInfo->laneLinkInfo, laneTypeInfoItem) != SOFTBUS_OK) {
        SoftBusFree(laneTypeInfoItem);
        LNN_LOGE(LNN_LANE, "create resourceItem fail");
        return SOFTBUS_ERR;
    }
    laneTypeInfoItem->laneType = laneTypeInfo->laneType;
    laneTypeInfoItem->ref = laneTypeInfo->ref;

    if (LaneListenerLock() != SOFTBUS_OK) {
        SoftBusFree(laneTypeInfoItem);
        LNN_LOGE(LNN_LANE, "lane lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    LaneTypeInfo* item = LaneTypeInfoIsExist(laneTypeInfo);
    if (item != NULL) {
        item->ref++;
        SoftBusFree(laneTypeInfoItem);
    } else {
        ListAdd(&g_laneTypeInfoList, &laneTypeInfoItem->node);
    }
    LaneListenerUnlock();
    return SOFTBUS_OK;
}

int32_t AddLaneTypeInfo(const LaneLinkInfo *linkInfo)
{
    if (linkInfo == NULL) {
        LNN_LOGE(LNN_LANE, "[CreateLaneType]invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    LaneType laneType;
    if (ParseLaneTypeByLaneReqId(linkInfo->laneReqId, &laneType) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "parse lanetype fail");
        return SOFTBUS_ERR;
    }
    LaneTypeInfo laneTypeInfo;
    (void)memset_s(&laneTypeInfo, sizeof(LaneTypeInfo), 0, sizeof(LaneTypeInfo));
    if (CreateLaneTypeInfoItem(linkInfo, &laneTypeInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "create resourceItem fail");
        return SOFTBUS_ERR;
    }
    laneTypeInfo.laneType = laneType;
    laneTypeInfo.ref = 1;
    if (AddLaneTypeInfoItem(&laneTypeInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "add lanetype info fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t DelLaneTypeInfoItem(uint32_t laneReqId)
{
    if (laneReqId == INVALID_LANE_REQ_ID) {
        LNN_LOGE(LNN_LANE, "laneReqId is invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    LaneLinkInfo laneLinkInfo;
    (void)memset_s(&laneLinkInfo, sizeof(LaneLinkInfo), 0, sizeof(LaneLinkInfo));
    FindLaneLinkInfoByLaneReqId(laneReqId, &laneLinkInfo);

    LaneType laneType;
    if (ParseLaneTypeByLaneReqId(laneReqId, &laneType) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "parse lanetype fail");
        return SOFTBUS_ERR;
    }
    LaneTypeInfo laneTypeInfo;
    (void)memset_s(&laneTypeInfo, sizeof(LaneTypeInfo), 0, sizeof(LaneTypeInfo));
    laneTypeInfo.laneType = laneType;
    laneTypeInfo.laneLinkInfo.type = laneLinkInfo.type;

    if (LaneListenerLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lane lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    LaneTypeInfo* item = LaneTypeInfoIsExist(&laneLinkInfo);
    if (item != NULL) {
        LNN_LOGI(LNN_LANE, "laneType=%{public}d, linkType=%{public}d, ref=%{public}d",
            item->laneLinkInfo.type, item->laneType, item->ref);
        if ((--item->ref) == 0) {
            ListDelete(&item->node);
            SoftBusFree(item);
        }
    }
    LaneListenerUnlock();
    return SOFTBUS_OK;
}

static bool FindLaneTypeItemById(LaneTypeInfoQuery *laneTypeInfoQuery, const LaneTypeInfo *item) {
    switch (item->laneLinkInfo.type) {
        case LANE_BR:
            if (laneTypeInfoQuery->linkInfoIdType != LANE_LINK_INFO_ID_BR_MAC ||
                strncmp(item->laneLinkInfo.linkInfo.br.brMac, laneTypeInfoQuery->linkInfoId.brMac, BT_MAC_LEN) != 0) {
                return false;
            }
            break;
        case LANE_BLE:
        case LANE_COC:
            if (laneTypeInfoQuery->linkInfoIdType != LANE_LINK_INFO_ID_BLE_MAC ||
                strncmp(item->laneLinkInfo.linkInfo.ble.bleMac, laneTypeInfoQuery->linkInfoId.bleMac, BT_MAC_LEN) != 0) {
                return false;
            }
            break;
        case LANE_P2P:
        case LANE_HML:
            if (laneTypeInfoQuery->linkInfoIdType != LANE_LINK_INFO_ID_PEER_IP ||
                strncmp(item->laneLinkInfo.linkInfo.p2p.connInfo.peerIp,
                laneTypeInfoQuery->linkInfoId.peerIp, IP_LEN) != 0) {
                return false;
            }
            break;
        case LANE_WLAN_5G:
        case LANE_WLAN_2P4G:
        case LANE_P2P_REUSE:
            if (laneTypeInfoQuery->linkInfoIdType != LANE_LINK_INFO_ID_WLAN_ADDR ||
                strncmp(item->laneLinkInfo.linkInfo.wlan.connInfo.addr,
                laneTypeInfoQuery->linkInfoId.addr, MAX_SOCKET_ADDR_LEN) != 0) {
                return false;
            }
            break;
        case LANE_BLE_DIRECT:
        case LANE_COC_DIRECT:
            if (laneTypeInfoQuery->linkInfoIdType != LANE_LINK_INFO_ID_NETWORK_ID ||
                strcmp(item->laneLinkInfo.linkInfo.bleDirect.networkId,
                laneTypeInfoQuery->linkInfoId.networkId) != 0) {
                return false;
            }
            break;
        default:
            return false;
    }
    return true;
}

static int32_t FindLaneTypeInfoById(LaneTypeInfoQuery *laneTypeInfoQuery, LaneTypeInfoList *laneTypeInfoList)
{
    if (laneTypeInfoQuery == NULL || laneTypeInfoList == NULL) {
        LNN_LOGE(LNN_LANE, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (LaneListenerLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lane listener lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    uint32_t resNum = 0;
    LaneTypeInfo *item = NULL;
    LaneTypeInfo *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_laneTypeInfoList, LaneTypeInfo, node) {
        if (FindLaneTypeItemById(laneTypeInfoQuery, item)) {
            laneTypeInfoList->laneTypeInfo[resNum].laneLinkInfo.type = item->laneLinkInfo.type;
            laneTypeInfoList->laneTypeInfo[resNum].laneType = item->laneType;
            laneTypeInfoList->laneTypeInfo[resNum].ref = item->ref;
            resNum++;
        }
    }
    laneTypeInfoList->laneTypeNum = resNum;
    LaneListenerUnlock();
    return SOFTBUS_OK;
}

static int32_t AddLaneStatusNotifyInfo(const LaneStatusNotifyInfo *inputLaneStatusNotifyInfo)
{
    if (inputLaneStatusNotifyInfo == NULL) {
        LNN_LOGE(LNN_LANE, "inputLaneStatusNotifyInfo is invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    LaneStatusNotifyInfo *laneStatusNotifyInfoItem = (LaneStatusNotifyInfo *)SoftBusMalloc(sizeof(LaneStatusNotifyInfo));
    if (laneStatusNotifyInfoItem == NULL) {
        LNN_LOGE(LNN_LANE, "laneStatusNotifyInfoItem malloc fail");
        return SOFTBUS_MALLOC_ERR;
    }
    if (memcpy_s(laneStatusNotifyInfoItem, sizeof(LaneStatusNotifyInfo), inputLaneStatusNotifyInfo, sizeof(LaneStatusNotifyInfo)) != EOK) {
        SoftBusFree(laneStatusNotifyInfoItem);
        LNN_LOGE(LNN_LANE, "memcpy_s fail");
        return SOFTBUS_MEM_ERR;
    }
    if (LaneListenerLock() != SOFTBUS_OK) {
        SoftBusFree(laneStatusNotifyInfoItem);
        LNN_LOGE(LNN_LANE, "lane lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    ListAdd(&g_laneStatusNotifyStateList, &laneStatusNotifyInfoItem->node);
    LaneListenerUnlock();
    return SOFTBUS_OK;
}

static int32_t UpdateLaneStatusNotifyState(const char *peerIp, const char *peerUuid)
{
    if (peerIp == NULL || peerUuid == NULL) {
        LNN_LOGE(LNN_LANE, "peerIp is invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    if (LaneListenerLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lane listener lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    LaneStatusNotifyInfo *item = NULL;
    LaneStatusNotifyInfo *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_laneStatusNotifyStateList, LaneStatusNotifyInfo, node) {
        if (strncmp(item->peerIp, peerIp, IP_LEN) == 0) {
            if (strncpy_s(item->peerUuid, UUID_BUF_LEN, peerUuid, UUID_BUF_LEN) != EOK) {
                LNN_LOGE(LNN_STATE, "copy peerIp fail");
                LaneListenerUnlock();
                return SOFTBUS_ERR;
            }
            LaneListenerUnlock();
            return SOFTBUS_OK;
        }
    }
    LaneListenerUnlock();
    char *anonyIp = NULL;
    Anonymize(peerIp, &anonyIp);
    LNN_LOGE(LNN_STATE, "lane status notify item not exists, peerIp=%{public}s", anonyIp);
    AnonymizeFree(anonyIp);
    return SOFTBUS_ERR;
}

static int32_t DelLaneStatusNotifyInfo(const char *peerIp)
{
    if (peerIp == NULL) {
        LNN_LOGE(LNN_LANE, "peerIp is invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    if (LaneListenerLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lane listener lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    LaneStatusNotifyInfo *item = NULL;
    LaneStatusNotifyInfo *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_laneStatusNotifyStateList, LaneStatusNotifyInfo, node) {
        if (strncmp(item->peerIp, peerIp, IP_LEN) == 0) {
            ListDelete(&item->node);
            SoftBusFree(item);
        }
    }
    LaneListenerUnlock();
    return SOFTBUS_OK;
}

static LaneStatusNotifyInfo *LaneStatusNotifyIsExist(const char *peerIp)
{
    if (peerIp == NULL) {
        LNN_LOGE(LNN_LANE, "invalid param");
        return NULL;
    }
    LaneStatusNotifyInfo *item = NULL;
    LaneStatusNotifyInfo *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_laneStatusNotifyStateList, LaneStatusNotifyInfo, node) {
        if (strncmp(item->peerIp, peerIp, IP_LEN) == 0) {
            return item;
        }
    }
    return NULL;
}

static LaneListenerInfo *LaneListenerIsExist(const LaneType type)
{
    LaneListenerInfo *item = NULL;
    LaneListenerInfo *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_laneListenerList, LaneListenerInfo, node) {
        if (type == item->type) {
            return item;
        }
    }
    return NULL;
}

static int32_t FindLaneListenerInfoByLaneType(const LaneType type, LaneListenerInfo *outLaneListener)
{
    if (!LaneTypeCheck(type) || outLaneListener == NULL) {
        LNN_LOGE(LNN_LANE, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (LaneListenerLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lane listener lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    LaneListenerInfo* item = LaneListenerIsExist(type);
    if (item == NULL) {
        LaneListenerUnlock();
        LNN_LOGE(LNN_LANE, "lane listener is not exist");
        return SOFTBUS_ERR;
    }
    if (memcpy_s(outLaneListener, sizeof(LaneListenerInfo), item, sizeof(LaneListenerInfo)) != EOK) {
        LaneListenerUnlock();
        return SOFTBUS_MEM_ERR;
    }
    LaneListenerUnlock();
    return SOFTBUS_OK;
}

int32_t RegisterLaneListener(const LaneType type, const LaneStatusListener *listener)
{
    if (!LaneTypeCheck(type)) {
        return SOFTBUS_INVALID_PARAM;
    }
    LaneListenerInfo *laneListenerItem = (LaneListenerInfo *)SoftBusMalloc(sizeof(LaneListenerInfo));
    if (laneListenerItem == NULL) {
        LNN_LOGE(LNN_LANE, "lane listener malloc fail");
        return SOFTBUS_MALLOC_ERR;
    }
    laneListenerItem->type = type;
    laneListenerItem->laneStatusListen = *listener;
    if (LaneListenerLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lane listener lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    LaneListenerInfo* item = LaneListenerIsExist(laneListenerItem->type);
    if (item != NULL) {
        SoftBusFree(laneListenerItem);
    } else {
        ListAdd(&g_laneListenerList, &laneListenerItem->node);
    }
    LaneListenerUnlock();
    return SOFTBUS_OK;
}

int32_t UnRegisterLaneListener(const LaneType type)
{
    if (!LaneTypeCheck(type)) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (LaneListenerLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lane listener lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    LaneListenerInfo* item = LaneListenerIsExist(type);
    if (item != NULL) {
        ListDelete(&item->node);
        SoftBusFree(item);
    }
    LaneListenerUnlock();
    return SOFTBUS_OK;
}

static void OnWifiDirectDeviceOffLineNotify(const LaneTypeInfo *laneTypeInfo, const char *peerUuid)
{
    if (peerUuid == NULL || laneTypeInfo == NULL) {
        LNN_LOGE(LNN_LANE, "invalid param");
        return;
    }
    LaneListenerInfo laneListener;
    LaneStatusInfoOff laneStatusInfoOff;
    if (strncpy_s(laneStatusInfoOff.peerUuid, UUID_BUF_LEN, peerUuid, UUID_BUF_LEN) != EOK) {
        LNN_LOGE(LNN_STATE, "copy peerUuid fail");
        return;
    }
    laneStatusInfoOff.type = laneTypeInfo->laneLinkInfo.type;
    if (FindLaneListenerInfoByLaneType(laneTypeInfo->laneType, &laneListener) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "find lane listener fail, laneType=%{public}d", laneTypeInfo->laneType);
        return;
    }
    if (laneListener.laneStatusListen.onLaneOffLine == NULL) {
        LNN_LOGE(LNN_STATE, "invalid lane status listen");
        return;
    }
    laneListener.laneStatusListen.onLaneOffLine(&laneStatusInfoOff);
}

static void LnnOnWifiDirectDeviceOffLine(const char *peerMac, const char *peerIp, const char *peerUuid)
{
    if (peerUuid == NULL || peerIp == NULL) {
        LNN_LOGE(LNN_LANE, "invalid param");
        return;
    }

    LaneTypeInfoQuery laneTypeInfoQuery;
    (void)memset_s(&laneTypeInfoQuery, sizeof(LaneTypeInfoQuery), 0, sizeof(LaneTypeInfoQuery));
    laneTypeInfoQuery.linkInfoIdType = LANE_LINK_INFO_ID_PEER_IP;
    if (strncpy_s(laneTypeInfoQuery.linkInfoId.peerIp, IP_LEN, peerIp, IP_LEN) != EOK) {
        LNN_LOGE(LNN_STATE, "copy peerIp fail");
        return;
    }
    LaneTypeInfoList laneTypeInfoList;
    (void)memset_s(&laneTypeInfoList, sizeof(LaneTypeInfoList), 0, sizeof(LaneTypeInfoList));
    if (FindLaneTypeInfoById(&laneTypeInfoQuery, &laneTypeInfoList) != SOFTBUS_OK) {
        char *anonyIp = NULL;
        Anonymize(peerIp, &anonyIp);
        LNN_LOGE(LNN_STATE, "find lane type fail, peerIp=%{public}s", anonyIp);
        AnonymizeFree(anonyIp);
        return;
    }
    DelLaneStatusNotifyInfo(peerIp);
    for (uint32_t i=0; i<laneTypeInfoList.laneTypeNum; i++) {
        OnWifiDirectDeviceOffLineNotify(&laneTypeInfoList.laneTypeInfo[i], peerUuid);
    }
}

static void LnnOnWifiDirectRoleChange(enum WifiDirectRole myRole)
{
    LaneStatusInfoChange laneStatusInfoChange;
    laneStatusInfoChange.laneStatusChangeType = LANE_STATUS_CHANGE_TYPE_P2P;
    laneStatusInfoChange.laneStatusInfo.role = myRole;

    if (LaneListenerLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lane listener lock fail");
        return;
    }
    LaneListenerInfo *item = NULL;
    LaneListenerInfo *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_laneListenerList, LaneListenerInfo, node) {
        if (item->laneStatusListen.onLaneStateChange != NULL) {
            item->laneStatusListen.onLaneStateChange(&laneStatusInfoChange);
        }
    }
    LaneListenerUnlock();
}

static void LnnOnWifiDirectDeviceOnLine(const char *peerMac, const char *peerIp, const char *peerUuid)
{
    if (peerUuid == NULL || peerIp == NULL) {
        LNN_LOGE(LNN_LANE, "invalid param");
        return;
    }
    LaneStatusNotifyInfo *laneStatusNotifyInfo = LaneStatusNotifyIsExist(peerIp);
    if (laneStatusNotifyInfo != NULL) {
        if (UpdateLaneStatusNotifyState(peerIp, peerUuid) != SOFTBUS_OK) {
            LNN_LOGE(LNN_LANE, "update lane status notify state err");
            return;
        }
        return;
    }
    LaneStatusNotifyInfo inputLaneStatusNotifyInfo;
    if (strncpy_s(inputLaneStatusNotifyInfo.peerIp, IP_LEN, peerIp, IP_LEN) != EOK) {
        LNN_LOGE(LNN_STATE, "copy peerIp fail");
        return;
    }
    if (strncpy_s(inputLaneStatusNotifyInfo.peerUuid, UUID_BUF_LEN, peerUuid, UUID_BUF_LEN) != EOK) {
        LNN_LOGE(LNN_STATE, "copy peerUuid fail");
        return;
    }
    if (AddLaneStatusNotifyInfo(&inputLaneStatusNotifyInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "add lane status notify info err");
        return;
    }
}

int32_t LnnOnWifiDirectDeviceOnLineNotify(const LaneLinkInfo *linkInfo)
{
    if (linkInfo == NULL) {
        LNN_LOGE(LNN_LANE, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (linkInfo->type != LANE_P2P && linkInfo->type != LANE_HML) {
        LNN_LOGI(LNN_LANE, "no need to notify");
        return SOFTBUS_OK;
    }
    LaneResource laneResourceInfo;
    (void)memset_s(&laneResourceInfo, sizeof(LaneResource), 0, sizeof(LaneResource));
    if (FindLaneResourceByLinkInfo(linkInfo, &laneResourceInfo) != SOFTBUS_OK ||
        --laneResourceInfo.laneRef != 0) {
        LNN_LOGI(LNN_LANE, "no need to notify");
        return SOFTBUS_OK;
    }
    LaneStatusNotifyInfo *laneStatusNotifyInfo = LaneStatusNotifyIsExist(linkInfo->linkInfo.p2p.connInfo.peerIp);
    if (laneStatusNotifyInfo == NULL) {
        LNN_LOGI(LNN_LANE, "no need to notify lane status");
        return SOFTBUS_OK;
    }
    LaneStatusInfoOn laneStatusInfoOn;
    if (strncpy_s(laneStatusInfoOn.peerUuid, UUID_BUF_LEN, laneStatusNotifyInfo->peerUuid, UUID_BUF_LEN) != EOK) {
        LNN_LOGE(LNN_STATE, "copy peerUuid fail");
        return SOFTBUS_ERR;
    }
    laneStatusInfoOn.type = linkInfo->type;

    if (LaneListenerLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lane listener lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    LaneListenerInfo *item = NULL;
    LaneListenerInfo *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_laneListenerList, LaneListenerInfo, node) {
        if (item->laneStatusListen.onLaneOnLine != NULL) {
            item->laneStatusListen.onLaneOnLine(&laneStatusInfoOn);
        }
    }
    LaneListenerUnlock();
    return SOFTBUS_OK;
}

static void LnnReqLinkListener(void)
{
    struct WifiDirectStatusListener listener = {
        .onDeviceOffLine = LnnOnWifiDirectDeviceOffLine,
        .onLocalRoleChange = LnnOnWifiDirectRoleChange,
        .onDeviceOnLine = LnnOnWifiDirectDeviceOnLine,
    };
    struct WifiDirectManager *mgr = GetWifiDirectManager();
    if (mgr != NULL && mgr->registerStatusListener != NULL) {
        mgr->registerStatusListener(LNN_LANE_MODULE, &listener);
    }
}

int32_t InitLaneListener(void)
{
    if (SoftBusMutexInit(&g_laneStateListenerMutex, NULL) != SOFTBUS_OK) {
        LNN_LOGI(LNN_LANE, "g_laneStateListenerMutex init fail");
        return SOFTBUS_ERR;
    }
    ListInit(&g_laneListenerList);
    ListInit(&g_laneTypeInfoList);
    ListInit(&g_laneStatusNotifyStateList);

    LnnReqLinkListener();
    return SOFTBUS_OK;
}