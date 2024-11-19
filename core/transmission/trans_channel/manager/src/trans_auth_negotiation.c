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

#include "trans_auth_negotiation.h"

#include <securec.h>

#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"
#include "softbus_utils.h"
#include "trans_log.h"

#include "softbus_proxychannel_manager.h"
#include "softbus_proxychannel_transceiver.h"

#define AUTH_NEGOTIATION_TIMEOUT_MS 10000 // Generate auth key timeout period, unit ms
#define AUTH_NEGOTIATION_CHECK_INTERVAL 100 // Auth status check interval, unit ms

static SoftBusList *g_reqAuthPendingList = NULL;

typedef struct {
    ListNode node;
    uint32_t authRequestId;
    uint32_t cnt;
    int32_t errCode;
    bool isFinished;
} TransReqAuthItem;

int32_t TransReqAuthPendingInit(void)
{
    TRANS_CHECK_AND_RETURN_RET_LOGW(g_reqAuthPendingList == NULL, SOFTBUS_OK, TRANS_SVC, "auth pending already init");

    g_reqAuthPendingList = CreateSoftBusList();
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        g_reqAuthPendingList != NULL, SOFTBUS_TRANS_LIST_INIT_FAILED, TRANS_SVC, "auth pending list init failed");

    return SOFTBUS_OK;
}

void TransReqAuthPendingDeinit(void)
{
    TRANS_LOGW(TRANS_SVC, "deinit auth request pending list");
    TRANS_CHECK_AND_RETURN_LOGW(g_reqAuthPendingList != NULL, TRANS_SVC, "auth pending already deinit");

    int32_t ret = SoftBusMutexLock(&g_reqAuthPendingList->lock);
    TRANS_CHECK_AND_RETURN_LOGE(ret == SOFTBUS_OK, TRANS_SVC, "lock auth pending list failed");

    TransReqAuthItem *item = NULL;
    TransReqAuthItem *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_reqAuthPendingList->list, TransReqAuthItem, node) {
        ListDelete(&item->node);
        SoftBusFree(item);
    }
    (void)SoftBusMutexUnlock(&g_reqAuthPendingList->lock);
    DestroySoftBusList(g_reqAuthPendingList);
    g_reqAuthPendingList = NULL;
}

static int32_t TransAddAuthReqToPendingList(uint32_t authRequestId)
{
    TRANS_CHECK_AND_RETURN_RET_LOGE(authRequestId != 0, SOFTBUS_INVALID_PARAM, TRANS_SVC, "invalid auth requestId");
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        g_reqAuthPendingList != NULL, SOFTBUS_NO_INIT, TRANS_SVC, "auth pending list no init");

    TransReqAuthItem *item = (TransReqAuthItem *)SoftBusCalloc(sizeof(TransReqAuthItem));
    TRANS_CHECK_AND_RETURN_RET_LOGE(item != NULL, SOFTBUS_MALLOC_ERR, TRANS_SVC, "malloc auth request item failed");
    item->authRequestId = authRequestId;
    item->cnt = 0;
    item->errCode = SOFTBUS_TRANS_AUTH_REQUEST_NOT_FOUND;
    item->isFinished = false;

    if (SoftBusMutexLock(&g_reqAuthPendingList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "lock auth pending list failed");
        SoftBusFree(item);
        return SOFTBUS_LOCK_ERR;
    }
    ListInit(&item->node);
    ListAdd(&g_reqAuthPendingList->list, &item->node);
    g_reqAuthPendingList->cnt++;
    (void)SoftBusMutexUnlock(&g_reqAuthPendingList->lock);
    TRANS_LOGI(TRANS_SVC, "add auth request to pending success, authRequestId=%{public}u", authRequestId);
    return SOFTBUS_OK;
}

static void TransDelAuthReqFromPendingList(uint32_t authRequestId)
{
    TRANS_CHECK_AND_RETURN_LOGE(authRequestId != 0, TRANS_SVC, "invalid auth requestId");
    TRANS_CHECK_AND_RETURN_LOGE(g_reqAuthPendingList != NULL, TRANS_SVC, "auth pending list no init");

    int32_t ret = SoftBusMutexLock(&g_reqAuthPendingList->lock);
    TRANS_CHECK_AND_RETURN_LOGE(ret == SOFTBUS_OK, TRANS_SVC, "lock auth pending list failed");
    TransReqAuthItem *item = NULL;
    TransReqAuthItem *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_reqAuthPendingList->list, TransReqAuthItem, node) {
        if (item->authRequestId == authRequestId) {
            ListDelete(&item->node);
            SoftBusFree(item);
            g_reqAuthPendingList->cnt--;
            (void)SoftBusMutexUnlock(&g_reqAuthPendingList->lock);
            TRANS_LOGI(TRANS_SVC, "delete auth request by authRequestId=%{public}u", authRequestId);
            return;
        }
    }
    (void)SoftBusMutexUnlock(&g_reqAuthPendingList->lock);
    TRANS_LOGW(TRANS_SVC, "auth request not found by authRequestId=%{public}u", authRequestId);
}

static int32_t TransUpdateAuthInfo(uint32_t authRequestId, int32_t errCode)
{
    TRANS_CHECK_AND_RETURN_RET_LOGE(authRequestId != 0, SOFTBUS_INVALID_PARAM, TRANS_SVC, "invalid auth requestId");
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        g_reqAuthPendingList != NULL, SOFTBUS_NO_INIT, TRANS_SVC, "auth pending list no init");

    int32_t ret = SoftBusMutexLock(&g_reqAuthPendingList->lock);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_LOCK_ERR, TRANS_SVC, "lock auth pending list failed");
    TransReqAuthItem *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_reqAuthPendingList->list, TransReqAuthItem, node) {
        if (item->authRequestId == authRequestId) {
            item->errCode = errCode;
            item->isFinished = true;
            (void)SoftBusMutexUnlock(&g_reqAuthPendingList->lock);
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&g_reqAuthPendingList->lock);
    TRANS_LOGE(TRANS_SVC, "auth request not found by authRequestId=%{public}u", authRequestId);
    return SOFTBUS_TRANS_AUTH_REQUEST_NOT_FOUND;
}

static int32_t TransCheckAuthNegoStatusByReqId(uint32_t authRequestId, bool *isFinished, int32_t *errCode, int32_t *cnt)
{
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        g_reqAuthPendingList != NULL, SOFTBUS_NO_INIT, TRANS_SVC, "auth pending list no init");

    int32_t ret = SoftBusMutexLock(&g_reqAuthPendingList->lock);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_LOCK_ERR, TRANS_SVC, "lock auth pending list failed");
    TransReqAuthItem *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_reqAuthPendingList->list, TransReqAuthItem, node) {
        if (item->authRequestId == authRequestId) {
            *isFinished = item->isFinished;
            *errCode = item->errCode;
            *cnt = ++item->cnt;
            (void)SoftBusMutexUnlock(&g_reqAuthPendingList->lock);
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&g_reqAuthPendingList->lock);
    TRANS_LOGE(TRANS_SVC, "auth request not found by authRequestId=%{public}u", authRequestId);
    return SOFTBUS_TRANS_AUTH_REQUEST_NOT_FOUND;
}

static int32_t WaitingForAuthNegoToBeDone(uint32_t authRequestId, int32_t channelId)
{
    int32_t ret = TransAddAuthReqToPendingList(authRequestId);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "channelId=%{public}d add authRequestId=%{public}u to pending fail, ret=%{public}d",
            channelId, authRequestId, ret);
        return ret;
    }
    TransProxyPostAuthNegoMsgToLooperDelay(authRequestId, channelId, AUTH_NEGOTIATION_CHECK_INTERVAL);
    return SOFTBUS_OK;
}

static void OnAuthSessionKeyGenSucc(uint32_t authRequestId, AuthHandle authHandle)
{
    (void)authHandle;
    TRANS_LOGI(TRANS_SVC, "authKey gen success, authRequestId=%{public}u", authRequestId);
    TransUpdateAuthInfo(authRequestId, SOFTBUS_OK);
}

static void OnAuthSessionKeyGenFail(uint32_t authRequestId, int32_t errCode)
{
    TRANS_LOGE(TRANS_SVC, "authKey gen failure, authRequestId=%{public}u errCode=%{public}d", authRequestId, errCode);
    TransUpdateAuthInfo(authRequestId, errCode);
}

// update session key, no need to notify request
static void OnUpdateSessionKeySucc(uint32_t authRequestId, AuthHandle authHandle)
{
    (void)authRequestId;
    (void)authHandle;
    TRANS_LOGI(TRANS_SVC, "update success, authRequestId=%{public}u", authRequestId);
}

// update session key, no need to notify request
static void OnUpdateSessionKeyFail(uint32_t authRequestId, int32_t errCode)
{
    (void)authRequestId;
    (void)errCode;
    TRANS_LOGE(TRANS_SVC, "update failure, authRequestId=%{public}u errCode=%{public}d", authRequestId, errCode);
}

int32_t TransNegotiateSessionKey(const AuthConnInfo *authConnInfo, int32_t channelId, const char *peerNetworkId)
{
    TRANS_CHECK_AND_RETURN_RET_LOGE((authConnInfo != NULL && peerNetworkId != NULL),
        SOFTBUS_INVALID_PARAM, TRANS_SVC, "invalid param");

    // Meta's peerNetworkId is empty in dSoftBus, and meta no need to negotiate, just skip
    if (strlen(peerNetworkId) == 0) {
        TRANS_LOGI(TRANS_SVC, "channelId=%{public}d peerNetworkId is empty, skip negotiate", channelId);
        TransProxyNegoSessionKeySucc(channelId);
        return SOFTBUS_OK;
    }

    int32_t ret = AuthCheckSessionKeyValidByConnInfo(peerNetworkId, authConnInfo);
    if (ret == SOFTBUS_AUTH_SESSION_KEY_INVALID || ret == SOFTBUS_AUTH_SESSION_KEY_TOO_OLD) {
        uint32_t authRequestId = AuthGenRequestId();
        bool isFastAuth = true;
        if (ret == SOFTBUS_AUTH_SESSION_KEY_TOO_OLD) {
            TRANS_LOGI(TRANS_SVC, "sessionKey older, update it, authRequestId=%{public}u", authRequestId);
            TransProxyNegoSessionKeySucc(channelId); // if sessionKey older, use old key to handshake first
            AuthConnCallback authCallback = {
                .onConnOpened = OnUpdateSessionKeySucc,
                .onConnOpenFailed = OnUpdateSessionKeyFail,
            };
            AuthStartConnVerify(authConnInfo, authRequestId, &authCallback, AUTH_MODULE_TRANS, isFastAuth);
            return SOFTBUS_OK;
        }
        TRANS_LOGI(TRANS_SVC, "no session key, start generation, authRequestId=%{public}u", authRequestId);
        AuthConnCallback authCallback = {
            .onConnOpened = OnAuthSessionKeyGenSucc,
            .onConnOpenFailed = OnAuthSessionKeyGenFail,
        };
        AuthStartConnVerify(authConnInfo, authRequestId, &authCallback, AUTH_MODULE_TRANS, isFastAuth);
        return WaitingForAuthNegoToBeDone(authRequestId, channelId);
    }
    TransProxyNegoSessionKeySucc(channelId);
    return SOFTBUS_OK;
}

int32_t TransReNegotiateSessionKey(const AuthConnInfo *authConnInfo, int32_t channelId)
{
    TRANS_CHECK_AND_RETURN_RET_LOGE(authConnInfo != NULL, SOFTBUS_INVALID_PARAM, TRANS_SVC, "invalid param");

    uint32_t authRequestId = AuthGenRequestId();
    bool isFastAuth = true;
    TRANS_LOGI(TRANS_SVC, "server side no session key, renegotiate, authRequestId=%{public}u", authRequestId);
    AuthConnCallback authCallback = {
        .onConnOpened = OnAuthSessionKeyGenSucc,
        .onConnOpenFailed = OnAuthSessionKeyGenFail,
    };
    AuthStartConnVerify(authConnInfo, authRequestId, &authCallback, AUTH_MODULE_TRANS, isFastAuth);
    return WaitingForAuthNegoToBeDone(authRequestId, channelId);
}

static int32_t SetWlanAuthConnInfo(const struct ConnSocketInfo *socketInfo, AuthConnInfo *authConnInfo)
{
    if (socketInfo->protocol != LNN_PROTOCOL_IP) {
        TRANS_LOGE(TRANS_SVC, "tcp protocol=%{public}d not support", socketInfo->protocol);
        return SOFTBUS_FUNC_NOT_SUPPORT;
    }

    authConnInfo->type = AUTH_LINK_TYPE_WIFI;
    if (strcpy_s(authConnInfo->info.ipInfo.ip, IP_LEN, socketInfo->addr) != EOK) {
        TRANS_LOGE(TRANS_SVC, "strcpy_s ip addr failed");
        return SOFTBUS_STRCPY_ERR;
    }
    authConnInfo->info.ipInfo.port = socketInfo->port;
    authConnInfo->info.ipInfo.moduleId = (ListenerModule)socketInfo->moduleId;

    return SOFTBUS_OK;
}

static int32_t SetBrAuthConnInfo(const struct BrInfo *brInfo, AuthConnInfo *authConnInfo)
{
    authConnInfo->type = AUTH_LINK_TYPE_BR;
    if (strcpy_s(authConnInfo->info.brInfo.brMac, BT_MAC_LEN, brInfo->brMac) != EOK) {
        TRANS_LOGE(TRANS_SVC, "strcpy_s br mac failed");
        return SOFTBUS_STRCPY_ERR;
    }

    return SOFTBUS_OK;
}

static int32_t SetBleAuthConnInfo(const struct BleInfo *bleInfo, AuthConnInfo *authConnInfo)
{
    authConnInfo->type = AUTH_LINK_TYPE_BLE;
    if (strcpy_s(authConnInfo->info.bleInfo.bleMac, BT_MAC_LEN, bleInfo->bleMac) != EOK ||
        memcpy_s(authConnInfo->info.bleInfo.deviceIdHash,
            UDID_HASH_LEN,
            bleInfo->deviceIdHash,
            UDID_HASH_LEN) != EOK) {
        TRANS_LOGE(TRANS_SVC, "copy ble mac or deviceId hash failed");
        return SOFTBUS_MEM_ERR;
    }
    authConnInfo->info.bleInfo.protocol = bleInfo->protocol;
    authConnInfo->info.bleInfo.psm = bleInfo->psm;

    return SOFTBUS_OK;
}

static int32_t ConvertConnInfoToAuthConnInfo(const ConnectionInfo *connInfo, AuthConnInfo *authConnInfo)
{
    switch (connInfo->type) {
        case CONNECT_TCP:
            return SetWlanAuthConnInfo(&(connInfo->socketInfo), authConnInfo);
        case CONNECT_BR:
            return SetBrAuthConnInfo(&(connInfo->brInfo), authConnInfo);
        case CONNECT_BLE:
            return SetBleAuthConnInfo(&(connInfo->bleInfo), authConnInfo);
        default:
            TRANS_LOGE(TRANS_SVC, "not support connection type=%{public}d", connInfo->type);
            return SOFTBUS_FUNC_NOT_SUPPORT;
    }
}

int32_t GetAuthConnInfoByConnId(uint32_t connectionId, AuthConnInfo *authConnInfo)
{
    TRANS_CHECK_AND_RETURN_RET_LOGE(authConnInfo != NULL, SOFTBUS_INVALID_PARAM, TRANS_SVC, "invalid param");

    ConnectionInfo connInfo;
    (void)memset_s(&connInfo, sizeof(ConnectionInfo), 0, sizeof(ConnectionInfo));
    int32_t ret = ConnGetConnectionInfo(connectionId, &connInfo);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get ConnectionInfo by connId=%{public}u failed, ret=%{public}d", connectionId, ret);
        return ret;
    }

    ret = ConvertConnInfoToAuthConnInfo(&connInfo, authConnInfo);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "convert connInfo to authConnInfo failed, ret=%{public}d", ret);
        return ret;
    }

    return SOFTBUS_OK;
}

void TransAuthNegoTaskManager(uint32_t authRequestId, int32_t channelId)
{
    TRANS_CHECK_AND_RETURN_LOGE(authRequestId != 0, TRANS_SVC, "invalid param");
    bool isFinished = false;
    int32_t errCode = SOFTBUS_TRANS_AUTH_NEGO_TASK_NOT_FOUND;
    int32_t cnt = 0;
    int32_t ret = TransCheckAuthNegoStatusByReqId(authRequestId, &isFinished, &errCode, &cnt);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "check auth status by authRequestId=%{public}u failed", authRequestId);
        return;
    }

    if (!isFinished) {
        int32_t timeoutCnt = AUTH_NEGOTIATION_TIMEOUT_MS / AUTH_NEGOTIATION_CHECK_INTERVAL;
        if (cnt >= timeoutCnt) {
            TRANS_LOGE(TRANS_SVC, "authRequestId=%{public}u timeout, cnt=%{public}d", authRequestId, cnt);
            TransProxyNegoSessionKeyFail(channelId, SOFTBUS_TRANS_AUTH_NEGOTIATE_SK_TIMEOUT);
            TransDelAuthReqFromPendingList(authRequestId);
            return;
        }
        TRANS_LOGD(TRANS_SVC, "authRequestId=%{public}u not finished, generate new task and waiting", authRequestId);
        TransProxyPostAuthNegoMsgToLooperDelay(authRequestId, channelId, AUTH_NEGOTIATION_CHECK_INTERVAL);
        return;
    }

    if (errCode != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "authRequestId=%{public}u negotiate failed, errCode=%{public}d", authRequestId, errCode);
        TransProxyNegoSessionKeyFail(channelId, errCode);
        TransDelAuthReqFromPendingList(authRequestId);
        return;
    }

    TransProxyNegoSessionKeySucc(channelId);
    TransDelAuthReqFromPendingList(authRequestId);
}
