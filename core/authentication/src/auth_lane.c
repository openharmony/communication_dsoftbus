/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "auth_lane.h"

#include <securec.h>

#include "auth_connection.h"
#include "auth_device.h"
#include "auth_log.h"
#include "bus_center_manager.h"
#include "lnn_ctrl_lane.h"
#include "lnn_lane_interface.h"
#include "lnn_lane_link.h"
#include "lnn_local_net_ledger.h"
#include "lnn_feature_capability.h"
#include "lnn_heartbeat_ctrl.h"
#include "lnn_map.h"
#include "lnn_net_builder.h"
#include "softbus_adapter_mem.h"

static SoftBusList *g_authReqList;

typedef struct {
    ListNode node;
    uint32_t laneHandle;
    uint64_t laneId;
    uint32_t authRequestId;
    int64_t authId;
    uint32_t authLinkType;
    char networkId[NETWORK_ID_BUF_LEN];
    AuthConnCallback callback;
} AuthReqInfo;

int32_t GetAuthConn(const char *uuid, LaneLinkType laneType, AuthConnInfo *connInfo)
{
    if (uuid == NULL || connInfo == NULL) {
        AUTH_LOGE(AUTH_CONN, "param invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    AuthLinkType authType = AUTH_LINK_TYPE_MAX;
    switch (laneType) {
        case LANE_BR:
            authType = AUTH_LINK_TYPE_BR;
            break;
        case LANE_BLE:
            authType = AUTH_LINK_TYPE_BLE;
            break;
        case LANE_P2P:
            authType = AUTH_LINK_TYPE_P2P;
            break;
        case LANE_HML:
            authType = AUTH_LINK_TYPE_ENHANCED_P2P;
            break;
        case LANE_WLAN_2P4G:
        case LANE_WLAN_5G:
            authType = AUTH_LINK_TYPE_WIFI;
            break;
        default:
            return SOFTBUS_AUTH_CONN_TYPE_INVALID;
    }
    AUTH_LOGI(AUTH_CONN, "convert authType=%{public}d", authType);
    return GetAuthConnInfoByUuid(uuid, authType, connInfo);
}

int32_t GetAuthLinkTypeList(const char *networkId, AuthLinkTypeList *linkTypeList)
{
    if (networkId == NULL || linkTypeList == NULL) {
        AUTH_LOGE(AUTH_CONN, "param invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    char uuid[UUID_BUF_LEN] = {0};
    if (LnnGetRemoteStrInfo(networkId, STRING_KEY_UUID, uuid, UUID_BUF_LEN) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "get peer uuid fail");
        return SOFTBUS_LANE_GET_LEDGER_INFO_ERR;
    }
    AuthLinkType linkList[] = {AUTH_LINK_TYPE_ENHANCED_P2P, AUTH_LINK_TYPE_WIFI,
        AUTH_LINK_TYPE_P2P, AUTH_LINK_TYPE_BR, AUTH_LINK_TYPE_BLE};
    AuthConnInfo connInfo;
    if (memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo)) != EOK) {
        AUTH_LOGE(AUTH_CONN, "memset_s AuthConnInfo fail");
        return SOFTBUS_MEM_ERR;
    }
    linkTypeList->linkTypeNum = 0;
    for (uint32_t i = 0; i < sizeof(linkList) / sizeof(linkList[0]); ++i) {
        if (GetAuthConnInfoByUuid(uuid, linkList[i], &connInfo) != SOFTBUS_OK) {
            continue;
        }
        if ((linkList[i] == AUTH_LINK_TYPE_BLE || linkList[i] == AUTH_LINK_TYPE_BR) &&
            !CheckActiveAuthConnection(&connInfo)) {
            AUTH_LOGI(AUTH_CONN, "auth ble connection not active");
            continue;
        }
        AUTH_LOGI(AUTH_CONN, "select auth type. i=%{public}d, authLinkType=%{public}d", i, linkList[i]);
        linkTypeList->linkType[linkTypeList->linkTypeNum] = linkList[i];
        linkTypeList->linkTypeNum++;
    }
    if (linkTypeList->linkTypeNum == 0) {
        if (TryGetBrConnInfo(uuid, &connInfo) == SOFTBUS_OK) {
            linkTypeList->linkType[linkTypeList->linkTypeNum] = AUTH_LINK_TYPE_BR;
            linkTypeList->linkTypeNum++;
            return SOFTBUS_OK;
        }
        AUTH_LOGE(AUTH_CONN, "no available auth link");
        return SOFTBUS_AUTH_LINK_NOT_EXIST;
    }
    return SOFTBUS_OK;
}

void InitAuthReqInfo(void)
{
    if (g_authReqList == NULL) {
        g_authReqList = CreateSoftBusList();
        if (g_authReqList == NULL) {
            AUTH_LOGE(AUTH_CONN, "create g_authReqList fail");
            return;
        }
    }
    AUTH_LOGI(AUTH_CONN, "g_authReqList init success");
}

void DeInitAuthReqInfo(void)
{
    if (g_authReqList == NULL) {
        AUTH_LOGE(AUTH_CONN, "g_authReqList is NULL");
        return;
    }
    AuthReqInfo *item = NULL;
    AuthReqInfo *next = NULL;
    if (SoftBusMutexLock(&g_authReqList->lock) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "get lock fail");
        return;
    }
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_authReqList->list, AuthReqInfo, node) {
        ListDelete(&item->node);
        SoftBusFree(item);
    }
    (void)SoftBusMutexUnlock(&g_authReqList->lock);
    DestroySoftBusList(g_authReqList);
    g_authReqList = NULL;
    AUTH_LOGI(AUTH_CONN, "g_authReqList deinit success");
}

static int32_t AddAuthReqNode(const char *networkId, uint32_t laneHandle, uint32_t authRequestId,
    AuthConnCallback *callback)
{
    if (networkId == NULL || laneHandle == INVALID_LANE_REQ_ID || callback == NULL) {
        AUTH_LOGE(AUTH_CONN, "param invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    AuthReqInfo *newItem = (AuthReqInfo *)SoftBusCalloc(sizeof(AuthReqInfo));
    if (newItem == NULL) {
        AUTH_LOGE(AUTH_CONN, "AuthReqInfo calloc fail");
        return SOFTBUS_MALLOC_ERR;
    }
    newItem->callback = *callback;
    if (memcpy_s(&newItem->networkId, NETWORK_ID_BUF_LEN, networkId, NETWORK_ID_BUF_LEN) != EOK) {
        AUTH_LOGE(AUTH_CONN, "memcpy_s networkId fail");
        SoftBusFree(newItem);
        return SOFTBUS_MEM_ERR;
    }
    newItem->laneHandle = laneHandle;
    newItem->authRequestId = authRequestId;
    ListInit(&newItem->node);

    if (SoftBusMutexLock(&g_authReqList->lock) != SOFTBUS_OK) {
        AUTH_LOGI(AUTH_CONN, "get lock fail");
        SoftBusFree(newItem);
        return SOFTBUS_LOCK_ERR;
    }
    ListTailInsert(&g_authReqList->list, &newItem->node);
    (void)SoftBusMutexUnlock(&g_authReqList->lock);
    return SOFTBUS_OK;
}

int32_t DelAuthReqInfoByAuthHandle(const AuthHandle *authHandle)
{
    if (authHandle == NULL) {
        AUTH_LOGE(AUTH_CONN, "authHandle is null");
        return SOFTBUS_INVALID_PARAM;
    }
    AUTH_LOGI(AUTH_CONN, "delete authReqInfo by authId=%{public}" PRId64, authHandle->authId);
    AuthReqInfo *item = NULL;
    AuthReqInfo *next = NULL;
    if (SoftBusMutexLock(&g_authReqList->lock) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "get lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_authReqList->list, AuthReqInfo, node) {
        if (item->authId == authHandle->authId && item->authLinkType == authHandle->type) {
            ListDelete(&item->node);
            SoftBusFree(item);
            break;
        }
    }
    (void)SoftBusMutexUnlock(&g_authReqList->lock);
    return SOFTBUS_OK;
}

void AuthFreeLane(const AuthHandle *authHandle)
{
    uint32_t laneHandle = INVALID_LANE_REQ_ID;
    AuthReqInfo *item = NULL;
    AuthReqInfo *next = NULL;
    if (SoftBusMutexLock(&g_authReqList->lock) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "get lock fail");
        return;
    }
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_authReqList->list, AuthReqInfo, node) {
        if (item->authId == authHandle->authId && item->authLinkType == authHandle->type) {
            laneHandle = item->laneHandle;
            break;
        }
    }
    (void)SoftBusMutexUnlock(&g_authReqList->lock);

    if (laneHandle != INVALID_LANE_REQ_ID) {
        GetLaneManager()->lnnFreeLane(laneHandle);
        AUTH_LOGI(AUTH_CONN, "auth free lane, laneHandle=%{public}u", laneHandle);
    }
}

static void DelAuthRequestItem(uint32_t laneHandle)
{
    AuthReqInfo *item = NULL;
    AuthReqInfo *next = NULL;
    if (SoftBusMutexLock(&g_authReqList->lock) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "get lock fail");
        return;
    }
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_authReqList->list, AuthReqInfo, node) {
        if (item->laneHandle == laneHandle) {
            ListDelete(&item->node);
            SoftBusFree(item);
            break;
        }
    }
    (void)SoftBusMutexUnlock(&g_authReqList->lock);
}

static void OnAuthConnOpenedSucc(uint32_t authRequestId, AuthHandle authHandle)
{
    AUTH_LOGI(AUTH_CONN, "open auth success with authRequestId=%{public}u", authRequestId);
    AuthConnCallback cb;
    cb.onConnOpened = NULL;
    AuthReqInfo *item = NULL;
    AuthReqInfo *next = NULL;
    if (SoftBusMutexLock(&g_authReqList->lock) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "get lock fail");
        return;
    }
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_authReqList->list, AuthReqInfo, node) {
        if (item->authRequestId == authRequestId) {
            item->authId = authHandle.authId;
            item->authLinkType = authHandle.type;
            cb.onConnOpened = item->callback.onConnOpened;
            break;
        }
    }
    (void)SoftBusMutexUnlock(&g_authReqList->lock);
    if (cb.onConnOpened != NULL) {
        cb.onConnOpened(authRequestId, authHandle);
    }
}

static void OnAuthConnOpenedFail(uint32_t authRequestId, int32_t reason)
{
    AUTH_LOGI(AUTH_CONN, "open auth fail with authRequestId=%{public}u", authRequestId);
    uint32_t laneHandle = 0;
    AuthConnCallback cb;
    cb.onConnOpenFailed = NULL;
    AuthReqInfo *item = NULL;
    AuthReqInfo *next = NULL;
    if (SoftBusMutexLock(&g_authReqList->lock) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "get lock fail");
        return;
    }
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_authReqList->list, AuthReqInfo, node) {
        if (item->authRequestId == authRequestId) {
            laneHandle = item->laneHandle;
            cb.onConnOpenFailed = item->callback.onConnOpenFailed;
            ListDelete(&item->node);
            SoftBusFree(item);
            break;
        }
    }
    (void)SoftBusMutexUnlock(&g_authReqList->lock);
    if (cb.onConnOpenFailed != NULL) {
        cb.onConnOpenFailed(authRequestId, reason);
    }
    GetLaneManager()->lnnFreeLane(laneHandle);
}

static void AuthOnLaneAllocSuccess(uint32_t laneHandle, const LaneConnInfo *laneConnInfo)
{
    AUTH_LOGI(AUTH_CONN, "auth request success, laneHandle=%{public}u", laneHandle);
    AuthReqInfo *item = NULL;
    AuthReqInfo *next = NULL;
    uint32_t authRequestId = 0;
    if (SoftBusMutexLock(&g_authReqList->lock) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "get lock fail");
        return;
    }
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_authReqList->list, AuthReqInfo, node) {
        if (item->laneHandle == laneHandle) {
            authRequestId = item->authRequestId;
            item->laneId = laneConnInfo->laneId;
            break;
        }
    }
    char uuid[UUID_BUF_LEN] = {0};
    if (LnnGetRemoteStrInfo(item->networkId, STRING_KEY_UUID, uuid, UUID_BUF_LEN) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "get peer uuid fail");
        (void)SoftBusMutexUnlock(&g_authReqList->lock);
        return;
    }
    (void)SoftBusMutexUnlock(&g_authReqList->lock);
    AuthConnInfo authConnInfo;
    if (memset_s(&authConnInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo)) != EOK) {
        AUTH_LOGE(AUTH_CONN, "memset_s authConnInfo fail");
        return;
    }
    if (GetAuthConn(uuid, laneConnInfo->type, &authConnInfo) != SOFTBUS_OK &&
        laneConnInfo->type == LANE_BR && TryGetBrConnInfo(uuid, &authConnInfo) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "GetAuthConn fail");
        return;
    }

    AuthConnCallback cb = {
        .onConnOpened = OnAuthConnOpenedSucc,
        .onConnOpenFailed = OnAuthConnOpenedFail,
    };
    AUTH_LOGI(AUTH_CONN, "open auth with authRequestId=%{public}u", authRequestId);
    if (AuthOpenConn(&authConnInfo, authRequestId, &cb, false) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "open auth conn fail");
        DelAuthRequestItem(laneHandle);
    }
}

static void AuthOnLaneAllocFail(uint32_t laneHandle, int32_t reason)
{
    AUTH_LOGI(AUTH_CONN, "auth request failed, laneHandle=%{public}u, reason=%{public}d", laneHandle, reason);
    AuthConnCallback cb;
    cb.onConnOpenFailed = NULL;
    AuthReqInfo *item = NULL;
    AuthReqInfo *next = NULL;
    uint32_t authRequestId = 0;
    if (SoftBusMutexLock(&g_authReqList->lock) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "get lock fail");
        return;
    }
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_authReqList->list, AuthReqInfo, node) {
        if (item->laneHandle == laneHandle) {
            authRequestId = item->authRequestId;
            cb.onConnOpenFailed = item->callback.onConnOpenFailed;
            ListDelete(&item->node);
            SoftBusFree(item);
            break;
        }
    }
    (void)SoftBusMutexUnlock(&g_authReqList->lock);
    if (cb.onConnOpenFailed != NULL) {
        cb.onConnOpenFailed(authRequestId, reason);
    }
}

static int32_t AuthGetLaneAllocInfo(const char *networkId, LaneAllocInfo *allocInfo)
{
    if (networkId == NULL || allocInfo == NULL) {
        AUTH_LOGE(AUTH_CONN, "param invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    if (memcpy_s(allocInfo->networkId, NETWORK_ID_BUF_LEN, networkId, NETWORK_ID_BUF_LEN) != EOK) {
        AUTH_LOGE(AUTH_CONN, "networkId memcpy_s fail");
        return SOFTBUS_MEM_ERR;
    }

#define DEFAULT_PID 0
    allocInfo->type = LANE_TYPE_CTRL;
    allocInfo->pid = DEFAULT_PID;
    allocInfo->extendInfo.networkDelegate = false;
    allocInfo->transType = LANE_T_MSG;
    allocInfo->acceptableProtocols = LNN_PROTOCOL_ALL ^ LNN_PROTOCOL_NIP;
    allocInfo->qosRequire.maxLaneLatency = 0;
    allocInfo->qosRequire.minBW = 0;
    allocInfo->qosRequire.minLaneLatency = 0;
    char uuid[UUID_BUF_LEN] = {0};
    if (LnnGetRemoteStrInfo(networkId, STRING_KEY_UUID, uuid, UUID_BUF_LEN) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "get peer uuid fail");
        return SOFTBUS_LANE_GET_LEDGER_INFO_ERR;
    }
    AuthConnInfo connInfo;
    if (memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo)) != EOK) {
        AUTH_LOGE(AUTH_CONN, "memset_s AuthConnInfo fail");
        return SOFTBUS_MEM_ERR;
    }
    if (GetAuthConnInfoByUuid(uuid, AUTH_LINK_TYPE_BLE, &connInfo) == SOFTBUS_OK &&
        CheckActiveAuthConnection(&connInfo)) {
        if (memcpy_s(allocInfo->extendInfo.peerBleMac, BT_MAC_LEN, connInfo.info.bleInfo.bleMac, BT_MAC_LEN) != EOK) {
            AUTH_LOGE(AUTH_CONN, "memcpy_s fail");
            return SOFTBUS_MEM_ERR;
        }
    }
    return SOFTBUS_OK;
}

int32_t AuthAllocLane(const char *networkId, uint32_t authRequestId, AuthConnCallback *callback)
{
    if (networkId == NULL || callback == NULL) {
        AUTH_LOGE(AUTH_CONN, "param invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    uint32_t laneHandle = GetLaneManager()->lnnGetLaneHandle(LANE_TYPE_CTRL);
    if (AddAuthReqNode(networkId, laneHandle, authRequestId, callback) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "add auth request node fail");
        GetLaneManager()->lnnFreeLane(laneHandle);
        return SOFTBUS_AUTH_ALLOC_LANE_FAIL;
    }

    LaneAllocInfo allocInfo;
    if (memset_s(&allocInfo, sizeof(LaneAllocInfo), 0, sizeof(LaneAllocInfo) != EOK)) {
        AUTH_LOGE(AUTH_CONN, "LaneRequestOption memset_s fail");
        GetLaneManager()->lnnFreeLane(laneHandle);
        return SOFTBUS_MEM_ERR;
    }

    if (AuthGetLaneAllocInfo(networkId, &allocInfo) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "auth get requestOption fail");
        GetLaneManager()->lnnFreeLane(laneHandle);
        return SOFTBUS_AUTH_ALLOC_LANE_FAIL;
    }

    LaneAllocListener listener;
    listener.onLaneAllocSuccess = AuthOnLaneAllocSuccess;
    listener.onLaneAllocFail = AuthOnLaneAllocFail;
    AUTH_LOGI(AUTH_CONN, "auth alloc lane, laneHandle=%{public}u, authRequestId=%{public}u", laneHandle, authRequestId);
    if (GetLaneManager()->lnnAllocLane(laneHandle, &allocInfo, &listener) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "auth alloc lane fail");
        return SOFTBUS_AUTH_ALLOC_LANE_FAIL;
    }
    return SOFTBUS_OK;
}
