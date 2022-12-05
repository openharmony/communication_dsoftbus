/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include <sys/time.h>
#include <securec.h>

#include "auth_interface.h"
#include "bus_center_manager.h"
#include "common_list.h"
#include "lnn_net_capability.h"
#include "p2plink_interface.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_utils.h"

typedef struct {
    int32_t requestId;
    int32_t pid;
    char networkId[NETWORK_ID_BUF_LEN];
    char p2pMac[P2P_MAC_LEN];
    int64_t authId;
    bool isResultSet;
    bool isConnected;
    LnnLaneP2pInfo p2pInfo;
    SoftBusCond cond;
    ListNode node;
} ConnRequestItem;

static SoftBusList *g_pendingList = NULL;

static ConnRequestItem *GetConnRequestItem(int32_t requestId)
{
    ConnRequestItem *item = NULL;
    ConnRequestItem *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_pendingList->list, ConnRequestItem, node) {
        if (item->requestId == requestId) {
            return item;
        }
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "conn request item not found, requestId = %d.", requestId);
    return NULL;
}

static int32_t AddConnRequestItem(int32_t requestId, const char *networkId, int32_t pid, const char *mac)
{
    ConnRequestItem *item = (ConnRequestItem *)SoftBusCalloc(sizeof(ConnRequestItem));
    if (item == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "malloc conn request item err.");
        return SOFTBUS_MALLOC_ERR;
    }
    if (strcpy_s(item->networkId, sizeof(item->networkId), networkId) != EOK) {
        SoftBusFree(item);
        return SOFTBUS_MEM_ERR;
    }
    if (strcpy_s(item->p2pMac, sizeof(item->p2pMac), mac) != EOK) {
        SoftBusFree(item);
        return SOFTBUS_MEM_ERR;
    }
    if (SoftBusCondInit(&item->cond) != 0) {
        SoftBusFree(item);
        return SOFTBUS_LOCK_ERR;
    }
    item->requestId = requestId;
    item->pid = pid;
    item->isResultSet = false;
    item->authId = SOFTBUS_ERR;

    if (SoftBusMutexLock(&g_pendingList->lock) != 0) {
        SoftBusFree(item);
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "lock fail.");
        return SOFTBUS_LOCK_ERR;
    }
    ListNodeInsert(&g_pendingList->list, &item->node);
    (void)SoftBusMutexUnlock(&g_pendingList->lock);
    return SOFTBUS_OK;
}

static void DelConnRequestItem(int32_t requestId)
{
    if (SoftBusMutexLock(&g_pendingList->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "lock fail.");
        return;
    }
    ConnRequestItem *item = GetConnRequestItem(requestId);
    if (item == NULL) {
        (void)SoftBusMutexUnlock(&g_pendingList->lock);
        return;
    }
    ListDelete(&item->node);
    (void)SoftBusCondDestroy(&item->cond);
    SoftBusFree(item);
    (void)SoftBusMutexUnlock(&g_pendingList->lock);
}

static void SetAuthIdToItem(int32_t requestId, int64_t authId)
{
    if (SoftBusMutexLock(&g_pendingList->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "lock fail.");
        return;
    }
    ConnRequestItem *item = GetConnRequestItem(requestId);
    if (item == NULL) {
        (void)SoftBusMutexUnlock(&g_pendingList->lock);
        return;
    }
    item->authId = authId;
    (void)SoftBusMutexUnlock(&g_pendingList->lock);
}

static int64_t GetAuthIdFromItem(int32_t requestId)
{
    int64_t authId;
    if (SoftBusMutexLock(&g_pendingList->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "lock fail.");
        return SOFTBUS_ERR;
    }
    ConnRequestItem *item = GetConnRequestItem(requestId);
    if (item == NULL) {
        (void)SoftBusMutexUnlock(&g_pendingList->lock);
        return SOFTBUS_ERR;
    }
    authId = item->authId;
    (void)SoftBusMutexUnlock(&g_pendingList->lock);
    return authId;
}

int32_t LnnLanePendingInit(void)
{
    if (g_pendingList != NULL) {
        return SOFTBUS_OK;
    }
    g_pendingList = CreateSoftBusList();
    if (g_pendingList == NULL) {
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

void LnnLanePendingDeinit(void)
{
    if (g_pendingList == NULL) {
        return;
    }
    if (SoftBusMutexLock(&g_pendingList->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "lock fail.");
        return;
    }
    ConnRequestItem *item = NULL;
    while (!IsListEmpty(&g_pendingList->list)) {
        item = LIST_ENTRY(GET_LIST_HEAD(&g_pendingList->list), ConnRequestItem, node);
        (void)SoftBusCondDestroy(&item->cond);
        SoftBusFree(item);
    }
    (void)SoftBusMutexUnlock(&g_pendingList->lock);
    DestroySoftBusList(g_pendingList);
    g_pendingList = NULL;
}

static int32_t GetExpectedP2pRole(void)
{
    return ROLE_AUTO;
}

static int32_t GetP2pMacAndPid(int32_t requestId, char *mac, uint32_t size, int32_t *pid)
{
    ConnRequestItem *item = NULL;
    ConnRequestItem *next = NULL;
    if (SoftBusMutexLock(&g_pendingList->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "lock fail.");
        return SOFTBUS_LOCK_ERR;
    }
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_pendingList->list, ConnRequestItem, node) {
        if (item->requestId != requestId) {
            continue;
        }
        if (strcpy_s(mac, size, item->p2pMac) != EOK) {
            LLOGE("p2pMac cpy err");
            return SOFTBUS_MEM_ERR;
        }
        *pid = item->pid;
        (void)SoftBusMutexUnlock(&g_pendingList->lock);
        return SOFTBUS_OK;
    }
    (void)SoftBusMutexUnlock(&g_pendingList->lock);
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "request item not found, requestId = %d.", requestId);
    return SOFTBUS_ERR;
}

static void GetConnectDeviceResult(const ConnRequestItem *item, bool *isConnected, LnnLaneP2pInfo *p2pInfo)
{
    *isConnected = item->isConnected;
    if (*isConnected) {
        if (memcpy_s(p2pInfo, sizeof(LnnLaneP2pInfo), &item->p2pInfo, sizeof(item->p2pInfo)) != EOK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "copy p2p ip fail.");
        }
    }
}

static int32_t WaitConnectDeviceResult(int32_t requestId, bool *isConnected, LnnLaneP2pInfo *p2pInfo)
{
    if (SoftBusMutexLock(&g_pendingList->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "lock fail.");
        return SOFTBUS_LOCK_ERR;
    }
    ConnRequestItem *item = GetConnRequestItem(requestId);
    if (item == NULL) {
        (void)SoftBusMutexUnlock(&g_pendingList->lock);
        return SOFTBUS_ERR;
    }
    if (item->isResultSet) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "p2p connect result has been set, requestId = %d, result = %d.",
            requestId, item->isConnected);
        GetConnectDeviceResult(item, isConnected, p2pInfo);
        (void)SoftBusMutexUnlock(&g_pendingList->lock);
        return SOFTBUS_OK;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "wait p2p connect signal, requestId = %d.", requestId);
    int32_t ret = SoftBusCondWait(&item->cond, &g_pendingList->lock, NULL);
    if (ret != 0) {
        (void)SoftBusMutexUnlock(&g_pendingList->lock);
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "wait p2p connect signal err: %d, requestId = %d.",
            ret, requestId);
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "recv p2p connect signal, requestId = %d, result = %d.",
        requestId, item->isConnected);
    GetConnectDeviceResult(item, isConnected, p2pInfo);
    (void)SoftBusMutexUnlock(&g_pendingList->lock);
    return SOFTBUS_OK;
}

static void SetConnectDeviceResult(int32_t requestId, bool isConnected, const char *myIp, const char *peerIp)
{
    if (g_pendingList == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "pending not init.");
        return;
    }
    if (SoftBusMutexLock(&g_pendingList->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "lock fail.");
        return;
    }
    ConnRequestItem *item = GetConnRequestItem(requestId);
    if (item == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "conn request not found, requestId = %d.", requestId);
        (void)SoftBusMutexUnlock(&g_pendingList->lock);
        return;
    }
    if (isConnected) {
        if (strcpy_s(item->p2pInfo.localIp, IP_LEN, myIp) != EOK ||
            strcpy_s(item->p2pInfo.peerIp, IP_LEN, peerIp) != EOK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "copy p2p ip fail.");
            (void)SoftBusMutexUnlock(&g_pendingList->lock);
            return;
        }
    }
    item->isConnected = isConnected;
    item->isResultSet = true;
    (void)SoftBusCondSignal(&item->cond);
    (void)SoftBusMutexUnlock(&g_pendingList->lock);
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "send p2p connect signal, requestId = %d, result = %d.",
        requestId, isConnected);
}

static void OnP2pConnected(int32_t requestId, const char *myIp, const char *peerIp)
{
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "OnP2pConnected: requestId = %d.", requestId);
    if (myIp == NULL || peerIp == NULL) {
        return;
    }
    SetConnectDeviceResult(requestId, true, myIp, peerIp);
}

static void OnP2pConnectFailed(int32_t requestId, int32_t reason)
{
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "OnP2pConnectFailed: requestId = %d, reason = %d.",
        requestId, reason);
    SetConnectDeviceResult(requestId, false, NULL, NULL);
}

static void OnConnOpened(uint32_t requestId, int64_t authId)
{
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "OnConnOpened: requestId = %d, authId = %" PRId64 ".",
        requestId, authId);
    SetAuthIdToItem(requestId, authId);
    P2pLinkConnectInfo info = {0};
    info.requestId = (int32_t)requestId;
    info.authId = authId;
    if (GetP2pMacAndPid(requestId, info.peerMac, sizeof(info.peerMac), &info.pid) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get p2p mac fail.");
        SetConnectDeviceResult(requestId, false, NULL, NULL);
        return;
    }
    info.expectedRole = (P2pLinkRole)GetExpectedP2pRole();
    info.cb.onConnected = OnP2pConnected;
    info.cb.onConnectFailed = OnP2pConnectFailed;
    (void)AuthSetP2pMac(authId, info.peerMac);
    if (P2pLinkConnectDevice(&info) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "connect p2p device err.");
        SetConnectDeviceResult(requestId, false, NULL, NULL);
    }
}

static void OnConnOpenFailed(uint32_t requestId, int32_t reason)
{
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "OnConnOpenFailed: requestId = %d, reason = %d.",
        requestId, reason);
    SetAuthIdToItem(requestId, SOFTBUS_ERR);
    SetConnectDeviceResult(requestId, false, NULL, NULL);
}

static int32_t GetPreferAuthConnInfo(const char *networkId, AuthConnInfo *connInfo, bool isMetaAuth)
{
    char uuid[UDID_BUF_LEN] = {0};
    if (LnnGetRemoteStrInfo(networkId, STRING_KEY_UUID, uuid, sizeof(uuid)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get peer uuid fail.");
        return SOFTBUS_ERR;
    }
    return AuthGetPreferConnInfo(uuid, connInfo, isMetaAuth);
}

static bool GetChannelAuthType(const char *peerNetWorkId)
{
    int32_t value = 0;
    int32_t ret = LnnGetRemoteNumInfo(peerNetWorkId, NUM_KEY_META_NODE, &value);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "GetChannelAuthType fail ,ret=%d", ret);
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "GetChannelAuthType success ,value=%d", value);
    return ((1 << ONLINE_METANODE) == value) ? true : false;
}

static int32_t OpenAuthConnToConnectP2p(const char *networkId, int32_t pid, LnnLaneP2pInfo *p2pInfo)
{
    AuthConnInfo connInfo;
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    bool isMetaAuth = GetChannelAuthType(networkId);
    if (GetPreferAuthConnInfo(networkId, &connInfo, isMetaAuth) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "no auth conn exist.");
        return SOFTBUS_ERR;
    }
    char mac[P2P_MAC_LEN] = {0};
    if (LnnGetRemoteStrInfo(networkId, STRING_KEY_P2P_MAC, mac, sizeof(mac)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get remote p2p mac fail.");
        return SOFTBUS_ERR;
    }
    int32_t requestId = P2pLinkGetRequestId();
    if (AddConnRequestItem(requestId, networkId, pid, mac) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "add pending item fail.");
        return SOFTBUS_ERR;
    }
    AuthConnCallback cb = {
        .onConnOpened = OnConnOpened,
        .onConnOpenFailed = OnConnOpenFailed
    };
    if (AuthOpenConn(&connInfo, requestId, &cb, isMetaAuth) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "open auth conn fail.");
        DelConnRequestItem(requestId);
        return SOFTBUS_ERR;
    }
    bool isConnected = false;
    if (WaitConnectDeviceResult(requestId, &isConnected, p2pInfo) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "WaitConnectDeviceResult fail, requestId = %d.", requestId);
    }
    int64_t authId = GetAuthIdFromItem(requestId);
    if (authId != SOFTBUS_ERR) {
        AuthCloseConn(authId);
    }
    DelConnRequestItem(requestId);
    if (!isConnected) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "p2p connect fail, requestId = %d.", requestId);
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "p2p connect succ, requestId = %d.", requestId);
    return SOFTBUS_OK;
}

static void OnConnOpenedForDisconnect(uint32_t requestId, int64_t authId)
{
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "OnConnOpened: requestId = %d, authId = %" PRId64 ".",
        requestId, authId);
    P2pLinkDisconnectInfo info = {0};
    info.authId = authId;
    if (GetP2pMacAndPid(requestId, info.peerMac, sizeof(info.peerMac), &info.pid) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get p2p mac fail.");
        AuthCloseConn(authId);
        DelConnRequestItem(requestId);
        return;
    }
    (void)AuthSetP2pMac(authId, info.peerMac);
    if (P2pLinkDisconnectDevice(&info) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "disconnect p2p device err.");
        AuthCloseConn(authId);
    }
    DelConnRequestItem(requestId);
}

static void OnConnOpenFailedForDisconnect(uint32_t requestId, int32_t reason)
{
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "OnConnOpenFailed: requestId = %d, reason = %d.",
        requestId, reason);
    P2pLinkDisconnectInfo info = {0};
    info.authId = -1;
    if (GetP2pMacAndPid(requestId, info.peerMac, sizeof(info.peerMac), &info.pid) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get p2p mac fail.");
        DelConnRequestItem(requestId);
        return;
    }
    if (P2pLinkDisconnectDevice(&info) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "disconnect p2p device err.");
    }
    DelConnRequestItem(requestId);
}

static void DisconenctP2pWithoutAuthConn(const char *networkId, int32_t pid, const char *mac)
{
    P2pLinkDisconnectInfo info = {0};
    info.authId = -1;
    info.pid = pid;
    if (strcpy_s(info.peerMac, P2P_MAC_LEN, mac)!= EOK) {
        LLOGE("p2p mac cpy err");
        return;
    }
    if (P2pLinkDisconnectDevice(&info) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "disconnect p2p device err.");
    }
}

static int32_t OpenAuthConnToDisconnectP2p(const char *networkId, int32_t pid, const char *mac)
{
    char uuid[UDID_BUF_LEN] = {0};
    if (LnnGetRemoteStrInfo(networkId, STRING_KEY_UUID, uuid, sizeof(uuid)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get peer uuid fail.");
        return SOFTBUS_ERR;
    }
    AuthConnInfo connInfo;
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    bool isMetaAuth = GetChannelAuthType(networkId);
    if (GetPreferAuthConnInfo(networkId, &connInfo, isMetaAuth) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "no auth conn exist.");
        return SOFTBUS_ERR;
    }
    int32_t requestId = P2pLinkGetRequestId();
    if (AddConnRequestItem(requestId, networkId, pid, mac) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "add pending item fail.");
        return SOFTBUS_ERR;
    }
    AuthConnCallback cb = {
        .onConnOpened = OnConnOpenedForDisconnect,
        .onConnOpenFailed = OnConnOpenFailedForDisconnect
    };
    if (AuthOpenConn(&connInfo, requestId, &cb, isMetaAuth) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "open auth conn fail.");
        DelConnRequestItem(requestId);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t LnnConnectP2p(const char *networkId, int32_t pid, LnnLaneP2pInfo *p2pInfo)
{
    if (networkId == NULL || p2pInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "%s:invalid param.", __func__);
        return SOFTBUS_INVALID_PARAM;
    }
    if (g_pendingList == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "pending not init.");
        return SOFTBUS_ERR;
    }
    return OpenAuthConnToConnectP2p(networkId, pid, p2pInfo);
}

int32_t LnnDisconnectP2p(const char *networkId, int32_t pid, const char *mac)
{
    if (networkId == NULL || mac == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "%s:invalid param.", __func__);
        return SOFTBUS_INVALID_PARAM;
    }
    if (g_pendingList == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "pending not init.");
        return SOFTBUS_ERR;
    }
    if (OpenAuthConnToDisconnectP2p(networkId, pid, mac) != SOFTBUS_OK) {
        LLOGE("DisconenctP2pWithoutAuthConn enter");
        DisconenctP2pWithoutAuthConn(networkId, pid, mac);
    }
    return SOFTBUS_OK;
}