/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "auth_manager.h"

#include <securec.h>
#include <stddef.h>

#include "auth_common.h"
#include "auth_connection.h"
#include "auth_p2p.h"
#include "auth_sessionkey.h"
#include "auth_socket.h"
#include "device_auth_defines.h"
#include "lnn_connection_addr_utils.h"
#include "message_handler.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_base_listener.h"
#include "softbus_conn_interface.h"
#include "softbus_errcode.h"
#include "softbus_json_utils.h"
#include "softbus_log.h"

static ListNode g_authClientHead;
static ListNode g_authServerHead;
static VerifyCallback *g_verifyCallback = NULL;
static AuthTransCallback *g_transCallback = NULL;
static ConnectCallback g_connCallback = {0};
static ConnectResult g_connResult = {0};
static const GroupAuthManager *g_hichainGaInstance = NULL;
static const DeviceGroupManager *g_hichainGmInstance = NULL;
static DeviceAuthCallback g_hichainCallback = {0};
static DataChangeListener g_hichainListener = {0};
static SoftBusHandler g_authHandler = {0};

static SoftBusMutex g_authLock;
static bool g_isAuthInit = false;

#define INITIAL_STATE 0
#define RECV_ENCRYPT_DATA_STATE 1
#define KEY_GENERATEG_STATE 2
#define RETRY_TIMES 16
#define RETRY_MILLSECONDS 500

#define AUTH_THOUSANDS_MULTIPLIER 1000LL
#define AUTH_CLOSE_CONN_DELAY_TIME 10000
#define AUTH_FREE_INVALID_MGR_DELAY_LEN 30

typedef enum {
    AUTH_TIMEOUT = 0,
    AUTH_DISCONNECT_DEVICE,
    AUTH_FREE_INVALID_MGR,
} AuthEventType;

int32_t __attribute__ ((weak)) HandleIpVerifyDevice(AuthManager *auth, const ConnectOption *option)
{
    (void)auth;
    (void)option;
    return SOFTBUS_ERR;
}

void __attribute__ ((weak)) AuthCloseTcpFd(int32_t fd)
{
    (void)fd;
    return;
}

int32_t __attribute__ ((weak)) OpenAuthServer(void)
{
    return SOFTBUS_ERR;
}

static int32_t EventInLooper(uint16_t id)
{
    SoftBusMessage *msgDelay = (SoftBusMessage *)SoftBusMalloc(sizeof(SoftBusMessage));
    if (msgDelay == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "SoftBusMalloc failed");
        return SOFTBUS_ERR;
    }
    (void)memset_s(msgDelay, sizeof(SoftBusMessage), 0, sizeof(SoftBusMessage));
    msgDelay->what = AUTH_TIMEOUT;
    msgDelay->arg1 = id;
    msgDelay->handler = &g_authHandler;
    if (g_authHandler.looper == NULL || g_authHandler.looper->PostMessageDelay == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "softbus handler is null");
        SoftBusFree(msgDelay);
        return SOFTBUS_ERR;
    }
    g_authHandler.looper->PostMessageDelay(g_authHandler.looper, msgDelay, AUTH_DELAY_MS);
    return SOFTBUS_OK;
}

static int32_t CustomFunc(const SoftBusMessage *msg, void *para)
{
    if (msg == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "invalid parameter");
        return SOFTBUS_ERR;
    }
    uint16_t id = (uint16_t)para;
    if (msg->what == AUTH_TIMEOUT && (uint16_t)(msg->arg1) == id) {
        return SOFTBUS_OK;
    }
    return SOFTBUS_ERR;
}

static void EventRemove(uint16_t id)
{
    g_authHandler.looper->RemoveMessageCustom(g_authHandler.looper, &g_authHandler,
        CustomFunc, (void *)(uintptr_t)id);
}

static int32_t PostDisconnectDeviceEvent(uint32_t connectionId)
{
    SoftBusMessage *msg = (SoftBusMessage *)SoftBusMalloc(sizeof(SoftBusMessage));
    if (msg == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "SoftBusMalloc failed");
        return SOFTBUS_ERR;
    }
    (void)memset_s(msg, sizeof(SoftBusMessage), 0, sizeof(SoftBusMessage));
    msg->what = AUTH_DISCONNECT_DEVICE;
    msg->arg1 = connectionId;
    msg->handler = &g_authHandler;
    if (g_authHandler.looper == NULL || g_authHandler.looper->PostMessageDelay == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "softbus handler is null");
        SoftBusFree(msg);
        return SOFTBUS_ERR;
    }
    g_authHandler.looper->PostMessageDelay(g_authHandler.looper, msg, AUTH_CLOSE_CONN_DELAY_TIME);
    return SOFTBUS_OK;
}

static int32_t PostFreeAuthManagerEvent(void)
{
    SoftBusMessage *msg = (SoftBusMessage *)SoftBusCalloc(sizeof(SoftBusMessage));
    if (msg == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "SoftBusCalloc failed");
        return SOFTBUS_MEM_ERR;
    }
    msg->what = AUTH_FREE_INVALID_MGR;
    msg->handler = &g_authHandler;
    if (g_authHandler.looper == NULL || g_authHandler.looper->PostMessageDelay == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "softbus handler is null");
        SoftBusFree(msg);
        return SOFTBUS_ERR;
    }
    g_authHandler.looper->PostMessageDelay(g_authHandler.looper, msg,
        AUTH_FREE_INVALID_MGR_DELAY_LEN * AUTH_THOUSANDS_MULTIPLIER);
    return SOFTBUS_OK;
}

static void HandleAuthTimeout(uint16_t connId)
{
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "auth process timeout, auth conn id = %u", connId);
    AuthManager *auth = AuthGetManagerByConnId(connId);
    if (auth == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "no match auth found");
        return;
    }
    if (auth->cb->onDeviceVerifyFail != NULL) {
        auth->cb->onDeviceVerifyFail(auth->authId, SOFTBUS_AUTH_TIMEOUT);
    }
    if (auth->connCb.onConnOpenFailed != NULL) {
        auth->connCb.onConnOpenFailed(auth->requestId, SOFTBUS_AUTH_TIMEOUT);
        auth->connCb.onConnOpenFailed = NULL;
    }
}

static void HandleAuthDisconnectDevice(uint32_t connectionId)
{
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "auth disconnect device, connectionId = %u.", connectionId);
    if (ConnDisconnectDevice(connectionId) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "conn disconnect device fail.");
    }
}

static void DeleteAuthLocked(AuthManager *auth)
{
    ListDelete(&auth->node);
    if (auth->encryptDevData != NULL) {
        SoftBusFree(auth->encryptDevData);
        auth->encryptDevData = NULL;
    }
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "delete auth manager, authId is %lld", auth->authId);
    SoftBusFree(auth);
}

static void HandleFreeAuthManager(void)
{
    uint64_t nowTime;
    ListNode *item = NULL;
    ListNode *tmp = NULL;
    AuthManager *auth = NULL;

    if (SoftBusMutexLock(&g_authLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "lock mutex failed");
        return;
    }
    SoftBusSysTime times;
    SoftBusGetTime(&times);
    nowTime = (uint64_t)times.sec;
    LIST_FOR_EACH_SAFE(item, tmp, &g_authClientHead) {
        auth = LIST_ENTRY(item, AuthManager, node);
        if (auth->isValid) {
            continue;
        }
        if (nowTime - auth->timeStamp > AUTH_FREE_INVALID_MGR_DELAY_LEN) {
            DeleteAuthLocked(auth);
        }
    }
    LIST_FOR_EACH_SAFE(item, tmp, &g_authServerHead) {
        auth = LIST_ENTRY(item, AuthManager, node);
        if (auth->isValid) {
            continue;
        }
        if (nowTime - auth->timeStamp > AUTH_FREE_INVALID_MGR_DELAY_LEN) {
            DeleteAuthLocked(auth);
        }
    }
    (void)SoftBusMutexUnlock(&g_authLock);

    // post next period free auth manager event
    PostFreeAuthManagerEvent();
}

static void AuthHandler(SoftBusMessage *msg)
{
    if (msg == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "invalid param.");
        return;
    }
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "auth message: what = %d.", msg->what);
    switch (msg->what) {
        case AUTH_TIMEOUT:
            return HandleAuthTimeout((uint16_t)(msg->arg1));
        case AUTH_DISCONNECT_DEVICE:
            return HandleAuthDisconnectDevice((uint32_t)(msg->arg1));
        case AUTH_FREE_INVALID_MGR:
            return HandleFreeAuthManager();
        default:
            SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "unknown auth message.");
            break;
    }
}

static void AuthLooperInit(void)
{
    g_authHandler.name = "auth_handler";
    g_authHandler.HandleMessage = AuthHandler;
    g_authHandler.looper = GetLooper(LOOP_TYPE_DEFAULT);

    // Preiodically release unavailable AuthManager memory
    PostFreeAuthManagerEvent();
}

AuthManager *AuthGetManagerByAuthId(int64_t authId)
{
    ListNode *item = NULL;
    AuthManager *auth = NULL;
    if (SoftBusMutexLock(&g_authLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "lock mutex failed");
        return NULL;
    }
    LIST_FOR_EACH(item, &g_authClientHead) {
        auth = LIST_ENTRY(item, AuthManager, node);
        if (!auth->isValid) {
            continue;
        }
        if (auth->authId == authId) {
            (void)SoftBusMutexUnlock(&g_authLock);
            return auth;
        }
    }

    LIST_FOR_EACH(item, &g_authServerHead) {
        auth = LIST_ENTRY(item, AuthManager, node);
        if (!auth->isValid) {
            continue;
        }
        if (auth->authId == authId) {
            (void)SoftBusMutexUnlock(&g_authLock);
            return auth;
        }
    }
    (void)SoftBusMutexUnlock(&g_authLock);
    return NULL;
}

AuthManager *AuthGetManagerByConnId(uint16_t id)
{
    ListNode *item = NULL;
    AuthManager *auth = NULL;
    if (SoftBusMutexLock(&g_authLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "lock mutex failed");
        return NULL;
    }
    LIST_FOR_EACH(item, &g_authClientHead) {
        auth = LIST_ENTRY(item, AuthManager, node);
        if (!auth->isValid) {
            continue;
        }
        if (auth->id == id) {
            (void)SoftBusMutexUnlock(&g_authLock);
            return auth;
        }
    }

    LIST_FOR_EACH(item, &g_authServerHead) {
        auth = LIST_ENTRY(item, AuthManager, node);
        if (!auth->isValid) {
            continue;
        }
        if (auth->id == id) {
            (void)SoftBusMutexUnlock(&g_authLock);
            return auth;
        }
    }
    (void)SoftBusMutexUnlock(&g_authLock);
    return NULL;
}

AuthManager *AuthGetManagerByFd(int32_t fd)
{
    ListNode *item = NULL;
    AuthManager *auth = NULL;
    if (SoftBusMutexLock(&g_authLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "lock mutex failed");
        return NULL;
    }
    LIST_FOR_EACH(item, &g_authClientHead) {
        auth = LIST_ENTRY(item, AuthManager, node);
        if (!auth->isValid) {
            continue;
        }
        if (auth->fd == fd) {
            (void)SoftBusMutexUnlock(&g_authLock);
            return auth;
        }
    }

    LIST_FOR_EACH(item, &g_authServerHead) {
        auth = LIST_ENTRY(item, AuthManager, node);
        if (!auth->isValid) {
            continue;
        }
        if (auth->fd == fd) {
            (void)SoftBusMutexUnlock(&g_authLock);
            return auth;
        }
    }
    (void)SoftBusMutexUnlock(&g_authLock);
    return NULL;
}

AuthManager *AuthGetManagerByConnectionId(uint32_t connectionId)
{
    ListNode *item = NULL;
    AuthManager *auth = NULL;
    if (SoftBusMutexLock(&g_authLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "lock mutex failed");
        return NULL;
    }
    LIST_FOR_EACH(item, &g_authClientHead) {
        auth = LIST_ENTRY(item, AuthManager, node);
        if (!auth->isValid) {
            continue;
        }
        if (auth->connectionId == connectionId) {
            (void)SoftBusMutexUnlock(&g_authLock);
            return auth;
        }
    }

    LIST_FOR_EACH(item, &g_authServerHead) {
        auth = LIST_ENTRY(item, AuthManager, node);
        if (!auth->isValid) {
            continue;
        }
        if (auth->connectionId == connectionId) {
            (void)SoftBusMutexUnlock(&g_authLock);
            return auth;
        }
    }
    (void)SoftBusMutexUnlock(&g_authLock);
    return NULL;
}

static bool CheckConnectionInfo(const ConnectOption *option, const ConnectionInfo *info)
{
    switch (option->type) {
        case CONNECT_TCP: {
            if (info->type == CONNECT_TCP &&
                strcmp(option->info.ipOption.ip, info->info.ipInfo.ip) == 0) {
                return true;
            }
            break;
        }
        case CONNECT_BR: {
            if (info->type == CONNECT_BR &&
                strcmp(option->info.brOption.brMac, info->info.brInfo.brMac) == 0) {
                return true;
            }
            break;
        }
        case CONNECT_BLE: {
            if (info->type == CONNECT_BLE &&
                strcmp(option->info.bleOption.bleMac, info->info.bleInfo.bleMac) == 0) {
                return true;
            }
            break;
        }
        default:
            break;
    }
    return false;
}

static AuthManager *AuthGetManagerByChannel(uint32_t connectionId)
{
    ListNode *item = NULL;
    AuthManager *auth = NULL;
    ConnectionInfo info = {0};
    if (ConnGetConnectionInfo(connectionId, &info) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "auth ConnGetConnectionInfo failed");
        return NULL;
    }
    if (SoftBusMutexLock(&g_authLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "lock mutex failed");
        return NULL;
    }
    LIST_FOR_EACH(item, &g_authClientHead) {
        auth = LIST_ENTRY(item, AuthManager, node);
        if (!auth->isValid) {
            continue;
        }
        if (CheckConnectionInfo(&auth->option, &info)) {
            (void)SoftBusMutexUnlock(&g_authLock);
            return auth;
        }
    }
    LIST_FOR_EACH(item, &g_authServerHead) {
        auth = LIST_ENTRY(item, AuthManager, node);
        if (!auth->isValid) {
            continue;
        }
        if (CheckConnectionInfo(&auth->option, &info)) {
            (void)SoftBusMutexUnlock(&g_authLock);
            return auth;
        }
    }
    (void)SoftBusMutexUnlock(&g_authLock);
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "auth not found by channel, connectionId = %u.", connectionId);
    return NULL;
}

static AuthManager *GetAuthByPeerUdid(const char *peerUdid)
{
    ListNode *item = NULL;
    AuthManager *auth = NULL;
    if (SoftBusMutexLock(&g_authLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "lock mutex failed");
        return NULL;
    }
    LIST_FOR_EACH(item, &g_authClientHead) {
        auth = LIST_ENTRY(item, AuthManager, node);
        if (!auth->isValid) {
            continue;
        }
        if (strncmp(auth->peerUdid, peerUdid, strlen(peerUdid)) == 0) {
            (void)SoftBusMutexUnlock(&g_authLock);
            return auth;
        }
    }

    LIST_FOR_EACH(item, &g_authServerHead) {
        auth = LIST_ENTRY(item, AuthManager, node);
        if (!auth->isValid) {
            continue;
        }
        if (strncmp(auth->peerUdid, peerUdid, strlen(peerUdid)) == 0) {
            (void)SoftBusMutexUnlock(&g_authLock);
            return auth;
        }
    }
    (void)SoftBusMutexUnlock(&g_authLock);
    return NULL;
}

static VerifyCallback *GetAuthCallback(uint32_t moduleId)
{
    if (moduleId >= VERIFY_MODULE_NUM) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "invalid parameter");
        return NULL;
    }
    if (g_verifyCallback == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "verify callback is null");
        return NULL;
    }
    return &g_verifyCallback[moduleId];
}

AuthManager *AuthGetManagerByRequestId(uint32_t requestId)
{
    ListNode *item = NULL;
    if (SoftBusMutexLock(&g_authLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "lock mutex failed");
        return NULL;
    }
    LIST_FOR_EACH(item, &g_authClientHead) {
        AuthManager *auth = LIST_ENTRY(item, AuthManager, node);
        if (!auth->isValid) {
            continue;
        }
        if (auth->requestId == requestId) {
            (void)SoftBusMutexUnlock(&g_authLock);
            return auth;
        }
    }
    (void)SoftBusMutexUnlock(&g_authLock);
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "cannot find auth by requestId, requestId is %u", requestId);
    return NULL;
}

static void MarkDeleteAuth(AuthManager *auth)
{
    if (SoftBusMutexLock(&g_authLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "lock mutex failed");
        return;
    }
    if (!auth->isValid) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "auth manager has delay delete, authId is %lld", auth->authId);
        (void)SoftBusMutexUnlock(&g_authLock);
        return;
    }
    auth->isValid = false;
    SoftBusSysTime times;
    SoftBusGetTime(&times);
    auth->timeStamp = (uint64_t)times.sec;
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "delay delete auth manager, authId is %lld", auth->authId);
    (void)SoftBusMutexUnlock(&g_authLock);
}

void AuthHandleFail(AuthManager *auth, int32_t reason)
{
    if (auth == NULL || auth->cb->onDeviceVerifyFail == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "auth is NULL or device verify fail Callback is NULL!");
        return;
    }
    EventRemove(auth->id);
    auth->cb->onDeviceVerifyFail(auth->authId, reason);
    if (auth->connCb.onConnOpenFailed != NULL) {
        auth->connCb.onConnOpenFailed(auth->requestId, reason);
        auth->connCb.onConnOpenFailed = NULL;
        MarkDeleteAuth(auth);
    }
}

int32_t AuthHandleLeaveLNN(int64_t authId)
{
    AuthManager *auth = NULL;
    auth = AuthGetManagerByAuthId(authId);
    if (auth == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "no match auth(%llu) found, AuthHandleLeaveLNN failed",
            authId);
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "auth handle leave LNN, authId is %lld", authId);
    if (SoftBusMutexLock(&g_authLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "lock mutex failed");
        return SOFTBUS_ERR;
    }
    AuthClearSessionKeyBySeq((int32_t)authId);
    (void)SoftBusMutexUnlock(&g_authLock);
    if (IsWiFiLink(auth)) {
        AuthCloseTcpFd(auth->fd);
        MarkDeleteAuth(auth);
    } else if (auth->status != AUTH_PASSED || auth->option.type == CONNECT_BR) {
        ConnDisconnectDevice(auth->connectionId);
    } else {
        MarkDeleteAuth(auth);
    }

    return SOFTBUS_OK;
}

static int32_t InitNewAuthManager(AuthManager *auth, uint32_t moduleId, AuthSideFlag side)
{
    if (side == CLIENT_SIDE_FLAG) {
        auth->authId = GetSeq(CLIENT_SIDE_FLAG);
    }
    auth->side = side;
    auth->cb = GetAuthCallback(moduleId);
    if (auth->cb == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "get auth callback failed");
        return SOFTBUS_ERR;
    }
    auth->status = WAIT_CONNECTION_ESTABLISHED;
    auth->softbusVersion = SOFT_BUS_NEW_V1;
    if (g_hichainGaInstance == NULL || g_hichainGmInstance == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "need to call HichainServiceInit!");
        return SOFTBUS_ERR;
    }
    auth->hichain = g_hichainGaInstance;
    auth->id = AuthGetNextConnectionId();
    auth->isAuthP2p = (moduleId == VERIFY_P2P_DEVICE);
    auth->isValid = true;
    return SOFTBUS_OK;
}

static AuthManager *InitClientAuthManager(AuthVerifyModule moduleId, const ConnectOption *option,
    uint32_t requestId, const char *peerUid)
{
    if (SoftBusMutexLock(&g_authLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "lock mutex failed");
        return NULL;
    }
    AuthManager *auth = (AuthManager *)SoftBusMalloc(sizeof(AuthManager));
    if (auth == NULL) {
        (void)SoftBusMutexUnlock(&g_authLock);
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "SoftBusMalloc failed");
        return NULL;
    }
    (void)memset_s(auth, sizeof(AuthManager), 0, sizeof(AuthManager));

    auth->requestId = requestId;
    auth->option = *option;
    if (memcpy_s(auth->peerUid, MAX_ACCOUNT_HASH_LEN, peerUid, MAX_ACCOUNT_HASH_LEN) != 0) {
        (void)SoftBusMutexUnlock(&g_authLock);
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "memcpy_s faield");
        SoftBusFree(auth);
        return NULL;
    }
    if (InitNewAuthManager(auth, moduleId, CLIENT_SIDE_FLAG) != SOFTBUS_OK) {
        (void)SoftBusMutexUnlock(&g_authLock);
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "client side, auth init new AuthManager failed");
        SoftBusFree(auth);
        return NULL;
    }
    ListNodeInsert(&g_authClientHead, &auth->node);
    (void)SoftBusMutexUnlock(&g_authLock);
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "create auth as client side, authId = %lld.", auth->authId);
    return auth;
}

int64_t AuthVerifyDevice(AuthVerifyModule moduleId, const ConnectionAddr *addr)
{
    if (addr == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "invalid parameter");
        return SOFTBUS_INVALID_PARAM;
    }
    ConnectOption option = {0};
    if (!LnnConvertAddrToOption(addr, &option)) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "auth LnnConverAddrToOption failed");
        return SOFTBUS_ERR;
    }
    AuthManager *auth = NULL;
    auth = InitClientAuthManager(moduleId, &option, AuthGenRequestId(), addr->peerUid);
    if (auth == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "auth InitClientAuthManager failed");
        return SOFTBUS_ERR;
    }
    if (option.type == CONNECT_TCP) {
        if (HandleIpVerifyDevice(auth, &option) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "HandleIpVerifyDevice failed");
            (void)AuthHandleLeaveLNN(auth->authId);
            return SOFTBUS_ERR;
        }
    } else if (option.type == CONNECT_BR || option.type == CONNECT_BLE) {
        int64_t authId = auth->authId;
        if (ConnConnectDevice(&option, auth->requestId, &g_connResult) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "auth ConnConnectDevice failed");
            (void)AuthHandleLeaveLNN(authId);
            return SOFTBUS_ERR;
        }
    } else {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "auth conn type %d is not support", option.type);
        MarkDeleteAuth(auth);
        return SOFTBUS_ERR;
    }
    if (EventInLooper(auth->id) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "auth EventInLooper failed");
        (void)AuthHandleLeaveLNN(auth->authId);
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "start authentication process, authId is %lld", auth->authId);
    return auth->authId;
}

void AuthOnConnectSuccessful(uint32_t requestId, uint32_t connectionId, const ConnectionInfo *info)
{
    (void)info;
    AuthManager *auth = NULL;
    auth = AuthGetManagerByRequestId(requestId);
    if (auth == NULL) {
        return;
    }
    auth->connectionId = connectionId;
    if (AuthSyncDeviceUuid(auth) != SOFTBUS_OK) {
        AuthHandleFail(auth, SOFTBUS_AUTH_SYNC_DEVID_FAILED);
    }
}

void AuthOnConnectFailed(uint32_t requestId, int reason)
{
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "auth create connection failed, fail reason is %d", reason);
    AuthManager *auth = NULL;
    auth = AuthGetManagerByRequestId(requestId);
    if (auth == NULL) {
        return;
    }
    AuthHandleFail(auth, reason);
}

void HandleReceiveAuthData(AuthManager *auth, int32_t module, uint8_t *data, uint32_t dataLen)
{
    if (auth == NULL || data == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "invalid parameter");
        return;
    }
    if (module == MODULE_AUTH_SDK) {
        if (auth->hichain->processData(auth->authId, data, dataLen, &g_hichainCallback) != 0) {
            SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "Hichain process data failed");
            AuthHandleFail(auth, SOFTBUS_AUTH_HICHAIN_PROCESS_FAILED);
        }
    } else {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "unknown auth data module");
    }
}

static void StartAuth(AuthManager *auth, char *groupId, bool isDeviceLevel, bool isClient)
{
    (void)groupId;
    char *authParams = NULL;
    if (isDeviceLevel) {
        authParams = AuthGenDeviceLevelParam(auth, isClient);
    } else {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "not supported session level");
        return;
    }
    if (authParams == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "generate auth param failed");
        return;
    }
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "start auth device, enter hichain process");
    int32_t ret;
    for (int i = 0; i < RETRY_TIMES; i++) {
        ret = auth->hichain->authDevice(ANY_OS_ACCOUNT, auth->authId, authParams, &g_hichainCallback);
        if (ret == HC_SUCCESS) {
            SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "hichain authDevice sucess, time = %d", i+1);
            cJSON_free(authParams);
            return;
        }
        if (ret == HC_ERR_INVALID_PARAMS) {
            SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR,
                "hichain authDevice need account service, retry time = %d, err = %d", i+1, ret);
            (void)SoftBusSleepMs(RETRY_MILLSECONDS);
        } else {
            break;
        }
    }
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "hichain authDevice fail, err = %d", ret);
    cJSON_free(authParams);
    AuthHandleFail(auth, SOFTBUS_AUTH_HICHAIN_AUTH_DEVICE_FAILED);
}

static void VerifyDeviceDevLvl(AuthManager *auth)
{
    if (auth->side == CLIENT_SIDE_FLAG) {
        StartAuth(auth, NULL, true, true);
    } else {
        StartAuth(auth, NULL, true, false);
    }
}

static void AuthOnSessionKeyReturned(int64_t authId, const uint8_t *sessionKey, uint32_t sessionKeyLen)
{
    if (sessionKey == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "invalid parameter");
        return;
    }
    AuthManager *auth = NULL;
    auth = AuthGetManagerByAuthId(authId);
    if (auth == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "no match auth(%llu) found on sessionkey returned", authId);
        return;
    }
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "auth get session key succ, authId is %lld", authId);
    NecessaryDevInfo devInfo = {0};
    if (AuthGetDeviceKey(devInfo.deviceKey, MAX_DEVICE_KEY_LEN, &devInfo.deviceKeyLen, &auth->option) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "auth get device key failed");
        return;
    }
    if (SoftBusMutexLock(&g_authLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "lock mutex failed");
        return;
    }
    devInfo.type = auth->option.type;
    devInfo.side = auth->side;
    devInfo.seq = (int32_t)((uint64_t)authId & LOW_32_BIT);
    auth->status = IN_SYNC_PROGRESS;
    AuthSetLocalSessionKey(&devInfo, auth->peerUdid, sessionKey, sessionKeyLen);
    (void)SoftBusMutexUnlock(&g_authLock);
    if (auth->cb->onKeyGenerated == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "auth Key Generated Callback is NULL!");
        return;
    }
    if (IsWiFiLink(auth) && auth->side == SERVER_SIDE_FLAG) {
        if (auth->encryptInfoStatus == INITIAL_STATE) {
            SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "wait client send encrypt dev info");
            auth->encryptInfoStatus = KEY_GENERATEG_STATE;
        } else if (auth->encryptInfoStatus == RECV_ENCRYPT_DATA_STATE) {
            SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "recv peer dev info already");
            auth->cb->onKeyGenerated(authId, &auth->option, auth->peerVersion);
        } else {
            SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "auth encrypt info state error!");
        }
    } else {
        auth->cb->onKeyGenerated(authId, &auth->option, auth->peerVersion);
    }
}

void HandleReceiveDeviceId(AuthManager *auth, uint8_t *data)
{
    if (auth == NULL || data == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "invalid parameter");
        return;
    }
    if (AuthUnpackDeviceInfo(auth, data) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "AuthUnpackDeviceInfo failed");
        AuthHandleFail(auth, SOFTBUS_AUTH_UNPACK_DEVID_FAILED);
        return;
    }
    if (auth->side == SERVER_SIDE_FLAG) {
        if (EventInLooper(auth->id) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "auth EventInLooper failed");
            AuthHandleFail(auth, SOFTBUS_MALLOC_ERR);
            return;
        }
        if (AuthSyncDeviceUuid(auth) != SOFTBUS_OK) {
            AuthHandleFail(auth, SOFTBUS_AUTH_SYNC_DEVID_FAILED);
        }
        return;
    }
    VerifyDeviceDevLvl(auth);
}

static void TryRemoveOldAuthManager(const AuthManager *auth, bool isClientSide)
{
    AuthManager *item = NULL;
    AuthManager *next = NULL;
    ListNode *listHead = (isClientSide ? (&g_authClientHead) : (&g_authServerHead));
    if (SoftBusMutexLock(&g_authLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "lock mutex failed");
        return;
    }
    LIST_FOR_EACH_ENTRY_SAFE(item, next, listHead, AuthManager, node) {
        if (!item->isValid) {
            SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "auth manager has delay remove, authId = %lld", item->authId);
            continue;
        }
        if (CompareConnectOption(&item->option, &auth->option) && item->authId != auth->authId) {
            item->isValid = false;
            SoftBusSysTime times;
            SoftBusGetTime(&times);
            item->timeStamp = (uint64_t)times.sec;
            SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "delay remove auth manager, authId is %lld", item->authId);
        }
    }
    (void)SoftBusMutexUnlock(&g_authLock);
}

static void TryRemoveConnection(const AuthManager *auth)
{
    TryRemoveOldAuthManager(auth, true);
    TryRemoveOldAuthManager(auth, false);
    if (auth->connCb.onConnOpened != NULL) {
        auth->connCb.onConnOpened(auth->requestId, auth->authId);
        /* AuthOpenConn start verify process, just return. */
        return;
    }
    if (auth->option.type == CONNECT_BLE && auth->side == CLIENT_SIDE_FLAG) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "try remove ble connection, authId = %lld.", auth->authId);
        if (ConnDisconnectDevice(auth->connectionId) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "disconnect ble device fail.");
        }
    }
}

static void ReceiveCloseAck(AuthManager *auth)
{
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO,
        "receive close ack, status = %d, connType = %d, authId = %lld.",
        auth->status, auth->option.type, auth->authId);
    if (auth->status == WAIT_CLOSE_ACK) {
        EventRemove(auth->id);
        auth->status = AUTH_PASSED;
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "auth passed, authId = %lld.", auth->authId);
        if (auth->cb->onDeviceVerifyPass != NULL) {
            auth->cb->onDeviceVerifyPass(auth->authId);
        }
        TryRemoveConnection(auth);
    } else {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "close ack received before device info, authId = %lld.",
            auth->authId);
        auth->status = WAIT_PEER_DEV_INFO;
    }
}

static void AuthReportSyncDeviceInfoResults(AuthManager *auth, uint8_t *data, uint32_t len)
{
    if (auth->cb->onRecvSyncDeviceInfo != NULL) {
        auth->cb->onRecvSyncDeviceInfo(auth->authId, auth->side, auth->peerUuid, data, len);
    }

    if (IsWiFiLink(auth)) {
        /* For WIFI_WLAN device do verfiy, it means verify pass that received device info from peer device. */
        EventRemove(auth->id);
        auth->status = AUTH_PASSED;
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "auth passed, authId = %lld.", auth->authId);
        if (auth->cb->onDeviceVerifyPass != NULL) {
            auth->cb->onDeviceVerifyPass(auth->authId);
        }
    } else if (auth->status == SYNC_FINISH) {
        /* For device info already received from peer device. */
        AuthSendCloseAck(auth->connectionId, auth->side, auth->authId);
        auth->status = WAIT_CLOSE_ACK;
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "wait close ack from peer device, authId = %lld.", auth->authId);
    } else if (auth->status == WAIT_PEER_DEV_INFO) {
        /* For close ack already received from peer device. */
        AuthSendCloseAck(auth->connectionId, auth->side, auth->authId);
        EventRemove(auth->id);
        auth->status = AUTH_PASSED;
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "auth passed, authId = %lld.", auth->authId);
        if (auth->cb->onDeviceVerifyPass != NULL) {
            auth->cb->onDeviceVerifyPass(auth->authId);
        }
        TryRemoveConnection(auth);
    } else {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR,
            "unexpected auth status, status = %d, authId = %lld.", auth->status, auth->authId);
    }
}

static bool IsReportKeyGeneratedInTcpServer(AuthManager *auth)
{
    if (!IsWiFiLink(auth)) {
        return false;
    }
    if (auth->side == SERVER_SIDE_FLAG && auth->encryptInfoStatus == KEY_GENERATEG_STATE &&
        auth->status == IN_SYNC_PROGRESS) {
        return true;
    }
    return false;
}

void AuthHandlePeerSyncDeviceInfo(AuthManager *auth, uint8_t *data, uint32_t len)
{
    if (auth == NULL || data == NULL || len == 0 || len > AUTH_MAX_DATA_LEN) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "invalid parameter");
        return;
    }

    if (AuthIsSeqInKeyList((int32_t)(auth->authId)) == false ||
        auth->status == IN_SYNC_PROGRESS) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "auth saved encrypted data first");
        if (auth->encryptDevData != NULL) {
            SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_WARN, "encrypted data is not null");
            SoftBusFree(auth->encryptDevData);
            auth->encryptDevData = NULL;
        }
        auth->encryptDevData = (uint8_t *)SoftBusMalloc(len);
        if (auth->encryptDevData == NULL) {
            SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "SoftBusMalloc failed");
            AuthHandleFail(auth, SOFTBUS_MALLOC_ERR);
            return;
        }
        (void)memset_s(auth->encryptDevData, len, 0, len);
        if (memcpy_s(auth->encryptDevData, len, data, len) != EOK) {
            SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "memcpy_s failed");
            AuthHandleFail(auth, SOFTBUS_MEM_ERR);
            return;
        }
        auth->encryptLen = len;

        if (!IsWiFiLink(auth)) {
            /* If WIFI_P2P/BR/BLR do verify, save peerDevData until localDevData send succ, just return here. */
            return;
        } else if (auth->side == SERVER_SIDE_FLAG && auth->encryptInfoStatus == INITIAL_STATE) {
            auth->encryptInfoStatus = RECV_ENCRYPT_DATA_STATE;
            return;
        }
    }
    if (IsReportKeyGeneratedInTcpServer(auth) && auth->cb->onKeyGenerated != NULL) {
        auth->encryptInfoStatus = RECV_ENCRYPT_DATA_STATE;
        auth->cb->onKeyGenerated(auth->authId, &auth->option, auth->peerVersion);
        return;
    }

    AuthReportSyncDeviceInfoResults(auth, data, len);
}

static void HandleReceiveConnectionData(const AuthManager *auth, const AuthDataInfo *info, uint8_t *data)
{
    ConnPktHead head = {0};
    head.magic = MAGIC_NUMBER;
    head.module = info->module;
    head.seq = info->seq;
    head.flag = info->flag;
    head.len = info->dataLen;
    AuthHandleTransInfo(auth, &head, (char *)data);
}

static int32_t AnalysisData(char *data, uint32_t len, AuthDataInfo *info)
{
    if (len < sizeof(AuthDataInfo)) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "AnalysisData: invalid length.");
        return SOFTBUS_ERR;
    }
    info->type = *(uint32_t *)data;
    data += sizeof(uint32_t);
    info->module = *(int32_t *)data;
    data += sizeof(int32_t);
    info->seq = *(int64_t *)data;
    data += sizeof(int64_t);
    info->flag = *(int32_t *)data;
    data += sizeof(int32_t);
    info->dataLen = *(uint32_t *)data;
    if ((info->dataLen + sizeof(AuthDataInfo)) > len) {
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static AuthManager *CreateServerAuth(uint32_t connectionId, AuthDataInfo *authDataInfo)
{
    ConnectionInfo connInfo = {0};
    if (ConnGetConnectionInfo(connectionId, &connInfo) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "auth ConnGetConnectionInfo failed");
        return NULL;
    }
    AuthManager *auth = NULL;
    if (SoftBusMutexLock(&g_authLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "lock mutex failed");
        return NULL;
    }
    auth = (AuthManager *)SoftBusMalloc(sizeof(AuthManager));
    if (auth == NULL) {
        (void)SoftBusMutexUnlock(&g_authLock);
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "SoftBusMalloc failed");
        return NULL;
    }
    (void)memset_s(auth, sizeof(AuthManager), 0, sizeof(AuthManager));
    auth->authId = authDataInfo->seq;
    auth->connectionId = connectionId;
    AuthVerifyModule moduleId = (connInfo.type == CONNECT_TCP) ? VERIFY_P2P_DEVICE : LNN;
    if (InitNewAuthManager(auth, moduleId, SERVER_SIDE_FLAG) != SOFTBUS_OK) {
        (void)SoftBusMutexUnlock(&g_authLock);
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "br server create auth failed");
        SoftBusFree(auth);
        return NULL;
    }
    ConnectOption option;
    (void)memset_s(&option, sizeof(ConnectOption), 0, sizeof(ConnectOption));
    if (AuthConvertConnInfo(&option, &connInfo) != SOFTBUS_OK) {
        (void)SoftBusMutexUnlock(&g_authLock);
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "AuthConvertConnInfo failed");
        SoftBusFree(auth);
        return NULL;
    }
    auth->option = option;
    ListNodeInsert(&g_authServerHead, &auth->node);
    (void)SoftBusMutexUnlock(&g_authLock);
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "create auth as server side, authId is %lld", auth->authId);
    return auth;
}

static void HandleReceiveData(AuthManager *auth, const AuthDataInfo *info, uint8_t *recvData)
{
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "auth recv data, type = %u, authId = %lld, seq = %lld, flag = %d.",
        info->type, auth->authId, info->seq, info->flag);
    switch (info->type) {
        case DATA_TYPE_DEVICE_ID: {
            HandleReceiveDeviceId(auth, recvData);
            break;
        }
        case DATA_TYPE_AUTH: {
            HandleReceiveAuthData(auth, info->module, recvData, info->dataLen);
            break;
        }
        case DATA_TYPE_SYNC: {
            AuthHandlePeerSyncDeviceInfo(auth, recvData, info->dataLen);
            break;
        }
        case DATA_TYPE_CLOSE_ACK: {
            ReceiveCloseAck(auth);
            break;
        }
        case DATA_TYPE_CONNECTION: {
            HandleReceiveConnectionData(auth, info, recvData);
            break;
        }
        default: {
            SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "unknown data type");
            break;
        }
    }
}

void AuthOnDataReceived(uint32_t connectionId, ConnModule moduleId, int64_t seq, char *data, int32_t len)
{
    if (data == NULL || moduleId != MODULE_DEVICE_AUTH || len <= 0) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "invalid parameter");
        return;
    }
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO,
        "auth receive data, connectionId is %u, moduleId is %d, seq is %lld", connectionId, moduleId, seq);
    AuthDataInfo info = {0};
    if (AnalysisData(data, (uint32_t)len, &info) != SOFTBUS_OK) {
        return;
    }
    AuthManager *auth = AuthGetManagerByConnectionId(connectionId);
    if (auth == NULL) {
        if (info.type == DATA_TYPE_DEVICE_ID && AuthGetSideByRemoteSeq(seq) == SERVER_SIDE_FLAG &&
            AuthIsSupportServerSide()) {
            auth = CreateServerAuth(connectionId, &info);
        } else if (info.type == DATA_TYPE_CLOSE_ACK) {
            auth = AuthGetManagerByConnectionId(connectionId);
        } else if (info.type == DATA_TYPE_CONNECTION) {
            auth = AuthGetManagerByChannel(connectionId);
            SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "get auth by channel, connectionId is %u.", connectionId);
        }
    }
    if (auth == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "auth manager not found/create.");
        return;
    }
    HandleReceiveData(auth, &info, (uint8_t *)(data + sizeof(AuthDataInfo)));
}

static void AuthOnError(int64_t authId, int operationCode, int errorCode, const char *errorReturn)
{
    (void)operationCode;
    (void)errorReturn;
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "HiChain auth failed, errorCode is %d", errorCode);
    AuthManager *auth = NULL;
    auth = AuthGetManagerByAuthId(authId);
    if (auth == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "no match auth(%llu) found, AuthOnError failed", authId);
        return;
    }
    AuthHandleFail(auth, SOFTBUS_AUTH_HICHAIN_AUTH_ERROR);
}

static char *AuthOnRequest(int64_t authReqId, int authForm, const char *reqParams)
{
    AuthManager *auth = NULL;
    auth = AuthGetManagerByAuthId(authReqId);
    if (auth == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "no match auth(%llu) found, AuthOnRequest failed", authReqId);
        return NULL;
    }
    cJSON *msg = cJSON_CreateObject();
    if (msg == NULL) {
        return NULL;
    }
    if (!AddNumberToJsonObject(msg, FIELD_CONFIRMATION, REQUEST_ACCEPTED) ||
        !AddStringToJsonObject(msg, FIELD_SERVICE_PKG_NAME, AUTH_APPID) ||
        !AddStringToJsonObject(msg, FIELD_PEER_CONN_DEVICE_ID, auth->peerUdid)) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "pack AuthOnRequest Fail.");
        cJSON_Delete(msg);
        return NULL;
    }
    char *msgStr = cJSON_PrintUnformatted(msg);
    if (msgStr == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "cJSON_PrintUnformatted failed");
        cJSON_Delete(msg);
        return NULL;
    }
    cJSON_Delete(msg);
    return msgStr;
}

static void AuthOnFinish(int64_t authId, int operationCode, const char *returnData)
{
    (void)authId;
    (void)operationCode;
    (void)returnData;
}

static void AuthOnConnected(uint32_t connectionId, const ConnectionInfo *info)
{
    (void)connectionId;
    (void)info;
}

static void AuthOnDisConnect(uint32_t connectionId, const ConnectionInfo *info)
{
    (void)info;
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "auth disconnect, connectionId = %u.", connectionId);
    AuthManager *auth = AuthGetManagerByConnectionId(connectionId);
    if (auth == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "auth already removed, connectionId = %u.", connectionId);
        return;
    }
    AuthNotifyTransDisconn(auth->authId);
    if (!IsP2PLink(auth)) {
        return;
    }
    EventRemove(auth->id);
    if (SoftBusMutexLock(&g_authLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "lock mutex failed");
        return;
    }
    AuthClearSessionKeyBySeq((int32_t)auth->authId);
    (void)SoftBusMutexUnlock(&g_authLock);
    MarkDeleteAuth(auth);
}

static void AuthOnGroupCreated(const char *groupInfo)
{
    if (groupInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "hichain transmit invalid parameter");
        return;
    }
    cJSON *msg = cJSON_Parse(groupInfo);
    if (msg == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "json parse failed");
        return;
    }
    char groupId[GROUPID_BUF_LEN] = {0};
    if (!GetJsonObjectStringItem(msg, FIELD_GROUP_ID, groupId, GROUPID_BUF_LEN)) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "auth get groupId tag failed");
        cJSON_Delete(msg);
        return;
    }
    int32_t groupType;
    if (!GetJsonObjectNumberItem(msg, FIELD_GROUP_TYPE, &groupType)) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "auth get groupType tag failed");
        cJSON_Delete(msg);
        return;
    }
    cJSON_Delete(msg);
    if (groupType == IDENTICAL_ACCOUNT_GROUP) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "auth group count create, groupType = %d", groupType);
        if (g_verifyCallback[BUSCENTER_MONITOR].onGroupCreated != NULL) {
            g_verifyCallback[BUSCENTER_MONITOR].onGroupCreated(groupId);
        }
    }
}

static void AuthOnGroupDeleted(const char *groupInfo)
{
    (void)groupInfo;
}

static void AuthOnDeviceNotTrusted(const char *peerUdid)
{
    AuthManager *auth = NULL;
    auth = GetAuthByPeerUdid(peerUdid);
    if (auth == NULL || auth->cb->onDeviceNotTrusted == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "GetAuthByPeerUdid failed");
        return;
    }
    auth->cb->onDeviceNotTrusted(peerUdid);
}

static int32_t HichainServiceInit(void)
{
    if (InitDeviceAuthService() != 0) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "auth InitDeviceAuthService failed");
        return SOFTBUS_ERR;
    }
    g_hichainGaInstance = GetGaInstance();
    if (g_hichainGaInstance == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "auth GetGaInstance failed");
        return SOFTBUS_ERR;
    }
    g_hichainGmInstance = GetGmInstance();
    if (g_hichainGmInstance == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "auth GetGmInstance failed");
        return SOFTBUS_ERR;
    }
    (void)memset_s(&g_hichainCallback, sizeof(DeviceAuthCallback), 0, sizeof(DeviceAuthCallback));
    g_hichainCallback.onTransmit = AuthOnTransmit;
    g_hichainCallback.onSessionKeyReturned = AuthOnSessionKeyReturned;
    g_hichainCallback.onFinish = AuthOnFinish;
    g_hichainCallback.onError = AuthOnError;
    g_hichainCallback.onRequest = AuthOnRequest;

    (void)memset_s(&g_hichainListener, sizeof(DataChangeListener), 0, sizeof(DataChangeListener));
    g_hichainListener.onGroupCreated = AuthOnGroupCreated;
    g_hichainListener.onGroupDeleted = AuthOnGroupDeleted;
    g_hichainListener.onDeviceNotTrusted = AuthOnDeviceNotTrusted;
    if (g_hichainGmInstance->regDataChangeListener(AUTH_APPID, &g_hichainListener) != 0) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "auth RegDataChangeListener failed");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

void AuthHandleTransInfo(const AuthManager *auth, const ConnPktHead *head, char *data)
{
    int32_t i;
    if (g_transCallback == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "auth trans callback is null");
        return;
    }
    for (i = 0; i < TRANS_MODULE_NUM; i++) {
        if (g_transCallback[i].onTransUdpDataRecv != NULL) {
            AuthTransDataInfo info = {0};
            info.module = head->module;
            info.flags = head->flag;
            info.seq = head->seq;
            info.data = data;
            info.len = head->len;
            g_transCallback[i].onTransUdpDataRecv(auth->authId, &(auth->option), &info);
        }
    }
}

int32_t AuthTransDataRegCallback(AuthTransModule moduleId, AuthTransCallback *cb)
{
    if (cb == NULL || moduleId >= TRANS_MODULE_NUM) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "invalid parameter");
        return SOFTBUS_INVALID_PARAM;
    }
    if (g_transCallback == NULL) {
        g_transCallback = (AuthTransCallback *)SoftBusMalloc(sizeof(AuthTransCallback) * TRANS_MODULE_NUM);
        if (g_transCallback == NULL) {
            SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "SoftBusMalloc failed");
            return SOFTBUS_ERR;
        }
        (void)memset_s(g_transCallback, sizeof(AuthTransCallback) * TRANS_MODULE_NUM, 0,
            sizeof(AuthTransCallback) * TRANS_MODULE_NUM);
    }
    if (cb->onTransUdpDataRecv != NULL) {
        g_transCallback[moduleId].onTransUdpDataRecv = cb->onTransUdpDataRecv;
    }
    if (cb->onAuthChannelClose != NULL) {
        g_transCallback[moduleId].onAuthChannelClose = cb->onAuthChannelClose;
    }
    return SOFTBUS_OK;
}

void AuthTransDataUnRegCallback(AuthTransModule moduleId)
{
    if (g_transCallback == NULL) {
        return;
    }
    if (moduleId >= TRANS_MODULE_NUM) {
        SoftBusFree(g_transCallback);
        g_transCallback = NULL;
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "unregister all auth trans callbacks.");
        return;
    }
    g_transCallback[moduleId].onTransUdpDataRecv = NULL;
    g_transCallback[moduleId].onAuthChannelClose = NULL;
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "unregister auth trans callback, module = %d.", moduleId);
}

int32_t AuthRegCallback(AuthVerifyModule moduleId, VerifyCallback *cb)
{
    if (cb == NULL || moduleId >= VERIFY_MODULE_NUM) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "invalid parameter");
        return SOFTBUS_INVALID_PARAM;
    }
    if (g_verifyCallback == NULL) {
        g_verifyCallback = (VerifyCallback *)SoftBusMalloc(sizeof(VerifyCallback) * VERIFY_MODULE_NUM);
        if (g_verifyCallback == NULL) {
            SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "SoftBusMalloc failed");
            return SOFTBUS_ERR;
        }
        (void)memset_s(g_verifyCallback, sizeof(VerifyCallback) * VERIFY_MODULE_NUM, 0,
            sizeof(VerifyCallback) * VERIFY_MODULE_NUM);
    }
    g_verifyCallback[moduleId].onKeyGenerated = cb->onKeyGenerated;
    g_verifyCallback[moduleId].onDeviceVerifyFail = cb->onDeviceVerifyFail;
    g_verifyCallback[moduleId].onRecvSyncDeviceInfo = cb->onRecvSyncDeviceInfo;
    g_verifyCallback[moduleId].onDeviceVerifyPass = cb->onDeviceVerifyPass;
    g_verifyCallback[moduleId].onDeviceNotTrusted = cb->onDeviceNotTrusted;
    g_verifyCallback[moduleId].onDisconnect = cb->onDisconnect;
    g_verifyCallback[moduleId].onGroupCreated = cb->onGroupCreated;
    g_verifyCallback[moduleId].onGroupDeleted = cb->onGroupDeleted;
    return SOFTBUS_OK;
}

static int32_t RegisterConnCallback(ConnectCallback *connCb, ConnectResult *connResult)
{
    connCb->OnConnected = AuthOnConnected;
    connCb->OnDisconnected = AuthOnDisConnect;
    connCb->OnDataReceived = AuthOnDataReceived;
    if (ConnSetConnectCallback(MODULE_DEVICE_AUTH, connCb) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "auth ConnSetConnectCallback failed");
        return SOFTBUS_ERR;
    }
    connResult->OnConnectSuccessed = AuthOnConnectSuccessful;
    connResult->OnConnectFailed = AuthOnConnectFailed;
    return SOFTBUS_OK;
}

static void AuthListInit(void)
{
    ListInit(&g_authClientHead);
    ListInit(&g_authServerHead);
    AuthSessionKeyListInit();
}

int32_t CreateServerIpAuth(int32_t cfd, const char *ip, int32_t port)
{
    AuthManager *auth = NULL;

    if (SoftBusMutexLock(&g_authLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "lock mutex failed");
        return SOFTBUS_ERR;
    }
    auth = (AuthManager *)SoftBusMalloc(sizeof(AuthManager));
    if (auth == NULL) {
        (void)SoftBusMutexUnlock(&g_authLock);
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "SoftBusMalloc failed");
        return SOFTBUS_ERR;
    }
    (void)memset_s(auth, sizeof(AuthManager), 0, sizeof(AuthManager));

    auth->fd = cfd;
    auth->authId = cfd;
    auth->encryptInfoStatus = INITIAL_STATE;
    if (InitNewAuthManager(auth, LNN, SERVER_SIDE_FLAG) != SOFTBUS_OK) {
        (void)SoftBusMutexUnlock(&g_authLock);
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "ServerIpAuthInit failed");
        SoftBusFree(auth);
        return SOFTBUS_ERR;
    }
    ConnectOption option;
    (void)memset_s(&option, sizeof(ConnectOption), 0, sizeof(ConnectOption));
    option.type = CONNECT_TCP;
    if (strncpy_s(option.info.ipOption.ip, IP_LEN, ip, strlen(ip))) {
        (void)SoftBusMutexUnlock(&g_authLock);
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "strncpy_s failed");
        SoftBusFree(auth);
        return SOFTBUS_ERR;
    }
    option.info.ipOption.port = port;
    auth->option = option;
    ListNodeInsert(&g_authServerHead, &auth->node);
    (void)SoftBusMutexUnlock(&g_authLock);
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "create ip auth as server side");
    return SOFTBUS_OK;
}

int64_t AuthOpenChannel(const ConnectOption *option)
{
    if (option == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "invalid parameter");
        return SOFTBUS_ERR;
    }
    int32_t fd;
    fd = AuthOpenTcpChannel(option, false);
    if (fd < 0) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "auth AuthOpenTcpChannel failed");
        return SOFTBUS_ERR;
    }
    if (SoftBusMutexLock(&g_authLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "lock mutex failed");
        return SOFTBUS_ERR;
    }
    AuthManager *auth = (AuthManager *)SoftBusCalloc(sizeof(AuthManager));
    if (auth == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "SoftBusCalloc failed");
        return SOFTBUS_ERR;
    }

    auth->side = CLIENT_SIDE_FLAG;
    auth->authId = GetSeq(CLIENT_SIDE_FLAG);
    auth->softbusVersion = SOFT_BUS_NEW_V1;
    auth->option = *option;
    auth->fd = fd;
    auth->hichain = g_hichainGaInstance;
    auth->id = AuthGetNextConnectionId();
    auth->isValid = true;
    ListNodeInsert(&g_authClientHead, &auth->node);
    (void)SoftBusMutexUnlock(&g_authLock);
    return auth->authId;
}

int32_t AuthCloseChannel(int64_t authId)
{
    return AuthHandleLeaveLNN(authId);
}

void AuthNotifyLnnDisconn(const AuthManager *auth)
{
    if (auth == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "invalid parameter");
        return;
    }
    EventRemove(auth->id);
    if (auth->side == SERVER_SIDE_FLAG && auth->status < IN_SYNC_PROGRESS) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "auth no need to notify lnn disconn");
        (void)AuthHandleLeaveLNN(auth->authId);
    } else {
        if (auth->cb != NULL && auth->cb->onDisconnect != NULL) {
            auth->cb->onDisconnect(auth->authId);
        }
    }
}

void AuthNotifyTransDisconn(int64_t authId)
{
    int32_t i;
    if (g_transCallback == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "auth trans callback is null");
        return;
    }
    for (i = 0; i < TRANS_MODULE_NUM; i++) {
        if (g_transCallback[i].onAuthChannelClose != NULL) {
            g_transCallback[i].onAuthChannelClose(authId);
        }
    }
}

int32_t AuthGetIdByOption(const ConnectOption *option, int64_t *authId)
{
    AuthManager *item = NULL;
    if (SoftBusMutexLock(&g_authLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "lock mutex failed");
        return SOFTBUS_ERR;
    }
    LIST_FOR_EACH_ENTRY(item, &g_authClientHead, AuthManager, node) {
        if (!item->isValid) {
            continue;
        }
        if (item->status == AUTH_PASSED && CompareConnectOption(&item->option, option)) {
            *authId = item->authId;
            (void)SoftBusMutexUnlock(&g_authLock);
            return SOFTBUS_OK;
        }
    }
    LIST_FOR_EACH_ENTRY(item, &g_authServerHead, AuthManager, node) {
        if (!item->isValid) {
            continue;
        }
        if (item->status == AUTH_PASSED && CompareConnectOption(&item->option, option)) {
            *authId = item->authId;
            (void)SoftBusMutexUnlock(&g_authLock);
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&g_authLock);
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "auth get id by option failed");
    return SOFTBUS_ERR;
}

int32_t AuthGetServerSideByOption(const ConnectOption *option, bool *isServerSide)
{
    AuthManager *item = NULL;
    if (SoftBusMutexLock(&g_authLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "lock mutex failed");
        return SOFTBUS_ERR;
    }
    LIST_FOR_EACH_ENTRY(item, &g_authClientHead, AuthManager, node) {
        if (!item->isValid) {
            continue;
        }
        if (item->status == AUTH_PASSED && CompareConnectOption(&item->option, option)) {
            *isServerSide = (item->side == SERVER_SIDE_FLAG);
            (void)SoftBusMutexUnlock(&g_authLock);
            return SOFTBUS_OK;
        }
    }
    LIST_FOR_EACH_ENTRY(item, &g_authServerHead, AuthManager, node) {
        if (!item->isValid) {
            continue;
        }
        if (item->status == AUTH_PASSED && CompareConnectOption(&item->option, option)) {
            *isServerSide = (item->side == SERVER_SIDE_FLAG);
            (void)SoftBusMutexUnlock(&g_authLock);
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&g_authLock);
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "auth get server side by option failed");
    return SOFTBUS_ERR;
}

int32_t AuthGetUuidByOption(const ConnectOption *option, char *buf, uint32_t bufLen)
{
    AuthManager *auth = NULL;
    ListNode *item = NULL;
    ListNode *tmp = NULL;
    if (SoftBusMutexLock(&g_authLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "lock mutex failed");
        return SOFTBUS_ERR;
    }
    LIST_FOR_EACH_SAFE(item, tmp, &g_authClientHead) {
        auth = LIST_ENTRY(item, AuthManager, node);
        if (!auth->isValid) {
            continue;
        }
        if (auth->status == AUTH_PASSED && CompareConnectOption(&auth->option, option)) {
            if (strlen(auth->peerUuid) == 0) {
                SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "client list no peerUuid");
                break;
            }
            if (strncpy_s(buf, bufLen, auth->peerUuid, strlen(auth->peerUuid)) != EOK) {
                (void)SoftBusMutexUnlock(&g_authLock);
                SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "memcpy_s failed");
                return SOFTBUS_ERR;
            }
            (void)SoftBusMutexUnlock(&g_authLock);
            return SOFTBUS_OK;
        }
    }
    LIST_FOR_EACH_SAFE(item, tmp, &g_authServerHead) {
        auth = LIST_ENTRY(item, AuthManager, node);
        if (!auth->isValid) {
            continue;
        }
        if (auth->status == AUTH_PASSED && CompareConnectOption(&auth->option, option)) {
            if (strlen(auth->peerUuid) == 0) {
                SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "server list no peerUuid");
                break;
            }
            if (strncpy_s(buf, bufLen, auth->peerUuid, strlen(auth->peerUuid)) != EOK) {
                (void)SoftBusMutexUnlock(&g_authLock);
                SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "memcpy_s failed");
                return SOFTBUS_ERR;
            }
            (void)SoftBusMutexUnlock(&g_authLock);
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&g_authLock);
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "auth get uuid by option failed");
    return SOFTBUS_ERR;
}

int32_t AuthGetDeviceUuid(int64_t authId, char *buf, uint32_t size)
{
    AuthManager *item = NULL;
    AuthManager *next = NULL;
    if (buf == NULL || size < UUID_BUF_LEN) {
        return SOFTBUS_INVALID_PARAM;
    }

    if (SoftBusMutexLock(&g_authLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "lock mutex failed");
        return SOFTBUS_ERR;
    }
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_authClientHead, AuthManager, node) {
        if (!item->isValid) {
            continue;
        }
        if (item->authId == authId) {
            if (strlen(item->peerUuid) == 0) {
                SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "client list no peerUuid");
                break;
            }
            if (strncpy_s(buf, size, item->peerUuid, strlen(item->peerUuid)) != EOK) {
                SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "strncpy_s failed");
                break;
            }
            (void)SoftBusMutexUnlock(&g_authLock);
            return SOFTBUS_OK;
        }
    }
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_authServerHead, AuthManager, node) {
        if (!item->isValid) {
            continue;
        }
        if (item->authId == authId) {
            if (strlen(item->peerUuid) == 0) {
                SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "server list no peerUuid");
                break;
            }
            if (strncpy_s(buf, size, item->peerUuid, strlen(item->peerUuid)) != EOK) {
                SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "strncpy_s failed");
                break;
            }
            (void)SoftBusMutexUnlock(&g_authLock);
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&g_authLock);
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "auth get device uuid failed");
    return SOFTBUS_ERR;
}

static void ClearAuthManager(void)
{
    AuthManager *auth = NULL;
    ListNode *item = NULL;
    ListNode *tmp = NULL;
    LIST_FOR_EACH_SAFE(item, tmp, &g_authClientHead) {
        auth = LIST_ENTRY(item, AuthManager, node);
        ListDelete(&auth->node);
        if (auth->encryptDevData != NULL) {
            SoftBusFree(auth->encryptDevData);
            auth->encryptDevData = NULL;
        }
        if (IsWiFiLink(auth)) {
            AuthCloseTcpFd(auth->fd);
        } else {
            ConnDisconnectDevice(auth->connectionId);
        }
        EventRemove(auth->id);
        SoftBusFree(auth);
        auth = NULL;
    }
    LIST_FOR_EACH_SAFE(item, tmp, &g_authServerHead) {
        auth = LIST_ENTRY(item, AuthManager, node);
        ListDelete(&auth->node);
        if (auth->encryptDevData != NULL) {
            SoftBusFree(auth->encryptDevData);
            auth->encryptDevData = NULL;
        }
        if (IsWiFiLink(auth)) {
            AuthCloseTcpFd(auth->fd);
        } else {
            ConnDisconnectDevice(auth->connectionId);
        }
        EventRemove(auth->id);
        SoftBusFree(auth);
        auth = NULL;
    }
    ListInit(&g_authClientHead);
    ListInit(&g_authServerHead);
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "clear auth manager finish");
}

static int32_t AuthOpenWifiConn(const AuthConnInfo *info, uint32_t requestId, const AuthConnCallback *callback)
{
    int64_t authId;
    AuthManager *item = NULL;
    AuthManager *next = NULL;
    if (SoftBusMutexLock(&g_authLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "lock mutex failed");
        return SOFTBUS_LOCK_ERR;
    }
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_authClientHead, AuthManager, node) {
        if (!item->isValid) {
            continue;
        }
        if (!IsWiFiLink(item)) {
            continue;
        }
        if (strncmp(item->option.info.ipOption.ip, info->info.ipInfo.ip, strlen(info->info.ipInfo.ip)) == 0 &&
            item->option.info.ipOption.port == info->info.ipInfo.port) {
            authId = item->authId;
            (void)SoftBusMutexUnlock(&g_authLock);
            SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "open wifi conn succ, authId = %lld.", item->authId);
            callback->onConnOpened(requestId, authId);
            return SOFTBUS_OK;
        }
    }
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_authServerHead, AuthManager, node) {
        if (!item->isValid) {
            continue;
        }
        if (!IsWiFiLink(item)) {
            continue;
        }
        if (strncmp(item->option.info.ipOption.ip, info->info.ipInfo.ip, strlen(info->info.ipInfo.ip)) == 0 &&
            item->option.info.ipOption.port == info->info.ipInfo.port) {
            authId = item->authId;
            (void)SoftBusMutexUnlock(&g_authLock);
            SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "open wifi conn succ, authId = %lld.", item->authId);
            callback->onConnOpened(requestId, authId);
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&g_authLock);
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "auth manager not found, requestId = %u.", requestId);
    return SOFTBUS_ERR;
}

static void OnConnectSuccessed(uint32_t requestId, uint32_t connectionId, const ConnectionInfo *info)
{
    (void)info;
    AuthManager *conn = AuthGetManagerByRequestId(requestId);
    if (conn == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "conn request not found, requestId = %u.", requestId);
        return;
    }
    if (conn->connCb.onConnOpened == NULL || conn->connCb.onConnOpenFailed == NULL) {
        MarkDeleteAuth(conn);
        return;
    }
    AuthManager *auth = AuthGetManagerByConnectionId(connectionId);
    if (auth == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "auth not found by connectionId = %u, requestId = %u.",
            connectionId, requestId);
        conn->connCb.onConnOpenFailed(requestId, SOFTBUS_ERR);
    } else {
        conn->connCb.onConnOpened(requestId, auth->authId);
    }
    MarkDeleteAuth(conn);
}

static void OnConnectFailed(uint32_t requestId, int32_t reason)
{
    AuthManager *conn = AuthGetManagerByRequestId(requestId);
    if (conn == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "conn request not found, requestId = %u.", requestId);
        return;
    }
    if (conn->connCb.onConnOpenFailed != NULL) {
        conn->connCb.onConnOpenFailed(requestId, reason);
    }
    MarkDeleteAuth(conn);
}

static int32_t TryCreateConnection(const ConnectOption *option, uint32_t requestId, const AuthConnCallback *callback)
{
    if (option->type != CONNECT_BR && option->type != CONNECT_BLE) {
        return SOFTBUS_INVALID_PARAM;
    }
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "try to create br/ble connection, type = %d.", option->type);
    /* use authManager to record this connect request, delete it while connect successed. */
    char peerUid[MAX_ACCOUNT_HASH_LEN] = {0};
    AuthManager *conn = InitClientAuthManager(LNN, option, requestId, peerUid);
    if (conn == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "init auth manager failed.");
        return SOFTBUS_ERR;
    }
    conn->connCb = *callback;
    ConnectResult result = {
        .OnConnectSuccessed = OnConnectSuccessed,
        .OnConnectFailed = OnConnectFailed,
    };
    int64_t authId = conn->authId;
    if (ConnConnectDevice(option, conn->requestId, &result) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "conn connect device failed.");
        (void)AuthHandleLeaveLNN(authId);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static AuthManager *AuthGetManagerByOption(const ConnectOption *option)
{
    AuthManager *item = NULL;
    AuthManager *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_authClientHead, AuthManager, node) {
        if (!item->isValid) {
            continue;
        }
        if (CompareConnectOption(&item->option, option)) {
            return item;
        }
    }
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_authServerHead, AuthManager, node) {
        if (!item->isValid) {
            continue;
        }
        if (CompareConnectOption(&item->option, option)) {
            return item;
        }
    }
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "auth manager not found by option.");
    return NULL;
}

static bool IsNeedVerifyAgain(ConnectOption *option, uint32_t requestId,
    const AuthConnCallback *callback)
{
    ConnectionInfo info;
    AuthManager *auth = NULL;

    if (SoftBusMutexLock(&g_authLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "lock mutex failed");
        return true;
    }
    auth = AuthGetManagerByOption(option);
    if (auth == NULL) {
        (void)SoftBusMutexUnlock(&g_authLock);
        return true;
    }
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "found existing auth conn, type = %d.", auth->option.type);
    if (IsP2PLink(auth)) {
        callback->onConnOpened(requestId, auth->authId);
        (void)SoftBusMutexUnlock(&g_authLock);
        return false;
    } else if (auth->option.type == CONNECT_BR || auth->option.type == CONNECT_BLE) {
        if (ConnGetConnectionInfo(auth->connectionId, &info) != SOFTBUS_OK ||
            !CheckActiveConnection(&auth->option)) {
            SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "auth br/ble has disconnect, do verify again.");
            (void)SoftBusMutexUnlock(&g_authLock);
            return true;
        }
        (void)SoftBusMutexUnlock(&g_authLock);
        if (auth->option.type == CONNECT_BR) {
            option->info.brOption.sideType = info.isServer ? CONN_SIDE_SERVER : CONN_SIDE_CLIENT;
        }
        if (TryCreateConnection(option, requestId, callback) == SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "auth br/ble connection exist, no neeed verify again.");
            return false;
        }
        return true;
    }
    (void)SoftBusMutexUnlock(&g_authLock);
    return true;
}

static int32_t AuthOpenCommonConn(const AuthConnInfo *info, uint32_t requestId, const AuthConnCallback *callback)
{
    ConnectOption option = {0};
    if (ConvertAuthConnInfoToOption(info, &option) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "convert AuthConnInfo to ConnectOption failed.");
        return SOFTBUS_ERR;
    }

    if (!IsNeedVerifyAgain(&option, requestId, callback)) {
        return SOFTBUS_OK;
    }

    AuthVerifyModule module = (info->type == AUTH_LINK_TYPE_P2P) ? VERIFY_P2P_DEVICE : LNN;
    AuthManager *auth = InitClientAuthManager(module, &option, requestId, info->peerUid);
    if (auth == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "init auth manager failed.");
        return SOFTBUS_ERR;
    }
    auth->connCb = *callback;
    int64_t authId = auth->authId;
    if (ConnConnectDevice(&option, auth->requestId, &g_connResult) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "conn connect device failed.");
        (void)AuthHandleLeaveLNN(authId);
        return SOFTBUS_ERR;
    }

    if (EventInLooper(auth->id) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "start auth timeout failed.");
        MarkDeleteAuth(auth);
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "open common conn started, type = %d, authId = %lld.",
        info->type, auth->authId);
    return SOFTBUS_OK;
}

int32_t AuthStartListening(const AuthListennerInfo *info)
{
    if (info == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    LocalListenerInfo local = {0};
    switch (info->type) {
        case AUTH_LINK_TYPE_P2P:
            local.type = CONNECT_TCP;
            if (strcpy_s(local.info.ipListenerInfo.ip, sizeof(local.info.ipListenerInfo.ip),
                info->info.ipInfo.ip) != EOK) {
                SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "strcpy_s ip failed");
                return SOFTBUS_MEM_ERR;
            }
            local.info.ipListenerInfo.port = info->info.ipInfo.port;
            local.info.ipListenerInfo.moduleId = AUTH_P2P;
            return ConnStartLocalListening(&local);
        default:
            SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "unsupport auth link type, type = %d.", info->type);
            break;
    }
    return SOFTBUS_ERR;
}

int32_t AuthStopListening(const AuthListennerInfo *info)
{
    if (info == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    LocalListenerInfo local = {0};
    switch (info->type) {
        case AUTH_LINK_TYPE_P2P:
            local.type = CONNECT_TCP;
            local.info.ipListenerInfo.moduleId = AUTH_P2P;
            return ConnStopLocalListening(&local);
        default:
            SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "unsupport auth link type, type = %d.", info->type);
            break;
    }
    return SOFTBUS_ERR;
}

uint32_t AuthGenRequestId(void)
{
    return ConnGetNewRequestId(MODULE_DEVICE_AUTH);
}

int32_t AuthOpenConn(const AuthConnInfo *info, uint32_t requestId, const AuthConnCallback *callback)
{
    if (info == NULL || callback == NULL ||
        callback->onConnOpened == NULL || callback->onConnOpenFailed == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    switch (info->type) {
        case AUTH_LINK_TYPE_WIFI:
            return AuthOpenWifiConn(info, requestId, callback);
        case AUTH_LINK_TYPE_BR:
        case AUTH_LINK_TYPE_BLE:
        case AUTH_LINK_TYPE_P2P:
            return AuthOpenCommonConn(info, requestId, callback);
        default:
            SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "unsupport auth link type, type = %d.", info->type);
            break;
    }
    return SOFTBUS_ERR;
}

void AuthCloseConn(int64_t authId)
{
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "auth close conn, authId = %lld.", authId);
    AuthManager *auth = AuthGetManagerByAuthId(authId);
    if (auth == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "auth manager not exist.");
        return;
    }
    if (auth->option.type == CONNECT_TCP) {
        /* for WIFI_WLAN/WIFI_P2P, do nothing. */
        return;
    }
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "close br/ble auth conn, type = %d, connectionId = %u.",
        auth->option.type, auth->connectionId);
    if (PostDisconnectDeviceEvent(auth->connectionId) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "conn disconnect br/ble device fail.");
    }
}

void AuthDeinit(void)
{
    if (g_isAuthInit == false) {
        return;
    }
    if (g_verifyCallback != NULL) {
        SoftBusFree(g_verifyCallback);
        g_verifyCallback = NULL;
    }
    DestroyDeviceAuthService();
    ClearAuthManager();
    AuthClearAllSessionKey();
    AuthTransDataUnRegCallback(TRANS_MODULE_NUM);
    SoftBusMutexDestroy(&g_authLock);
    g_isAuthInit = false;
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "auth deinit succ!");
}

int32_t AuthInit(void)
{
    if (g_isAuthInit == true) {
        return SOFTBUS_OK;
    }
    AuthGetAbility();
    AuthListInit();
    if (RegisterConnCallback(&g_connCallback, &g_connResult) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "RegisterConnCallback failed");
        AuthDeinit();
        return SOFTBUS_ERR;
    }
    if (AuthP2pInit() != SOFTBUS_OK) {
        (void)AuthDeinit();
        return SOFTBUS_ERR;
    }

    AuthLooperInit();

    UniqueIdInit();

    if (HichainServiceInit() != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "auth hichain init failed");
        AuthDeinit();
        return SOFTBUS_ERR;
    }

    if (SoftBusMutexInit(&g_authLock, NULL) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "mutex init fail!");
        AuthDeinit();
        return SOFTBUS_ERR;
    }

    g_isAuthInit = true;
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "auth init succ!");
    return SOFTBUS_OK;
}

static AuthManager *GetAuthManagerInner(int64_t authId)
{
    AuthManager *item = NULL;
    AuthManager *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_authClientHead, AuthManager, node) {
        if (!item->isValid) {
            continue;
        }
        if (item->authId == authId) {
            return item;
        }
    }
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_authServerHead, AuthManager, node) {
        if (!item->isValid) {
            continue;
        }
        if (item->authId == authId) {
            return item;
        }
    }
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "auth manager not found inner, authId = %lld.", authId);
    return NULL;
}

int32_t AuthGetConnInfo(int64_t authId, AuthConnInfo *info)
{
    if (info == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_authLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "lock fail.");
        return SOFTBUS_LOCK_ERR;
    }
    AuthManager *auth = GetAuthManagerInner(authId);
    if (auth == NULL) {
        (void)SoftBusMutexUnlock(&g_authLock);
        return SOFTBUS_ERR;
    }
    (void)ConvertOptionToAuthConnInfo(&auth->option, auth->isAuthP2p, info);
    (void)SoftBusMutexUnlock(&g_authLock);
    return SOFTBUS_OK;
}

int32_t AuthSetP2pMac(int64_t authId, const char *mac)
{
    if (mac == NULL || strlen(mac) == 0) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "invalid p2p mac.");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_authLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "lock fail.");
        return SOFTBUS_LOCK_ERR;
    }
    AuthManager *auth = GetAuthManagerInner(authId);
    if (auth == NULL) {
        (void)SoftBusMutexUnlock(&g_authLock);
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "auth not found, authId = %lld.", authId);
        return SOFTBUS_ERR;
    }
    if (strcpy_s(auth->peerP2pMac, sizeof(auth->peerP2pMac), mac) != EOK) {
        (void)SoftBusMutexUnlock(&g_authLock);
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "copy p2p mac fail.");
        return SOFTBUS_ERR;
    }
    (void)SoftBusMutexUnlock(&g_authLock);
    return SOFTBUS_OK;
}

static bool IsAuthLinkTypeMatched(AuthLinkType type, const AuthManager *auth)
{
    switch (type) {
        case AUTH_LINK_TYPE_WIFI:
            return IsWiFiLink(auth);
        case AUTH_LINK_TYPE_BR:
            return (auth->option.type == CONNECT_BR);
        case AUTH_LINK_TYPE_BLE:
            return (auth->option.type == CONNECT_BLE);
        case AUTH_LINK_TYPE_P2P:
            return IsP2PLink(auth);
        default:
            SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "unknown type: %d.", type);
            break;
    }
    return false;
}

int32_t AuthGetConnectOptionByP2pMac(const char *mac, AuthLinkType type, ConnectOption *option)
{
    if (mac == NULL || strlen(mac) == 0 || option == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    AuthManager *item = NULL;
    AuthManager *next = NULL;
    if (SoftBusMutexLock(&g_authLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "lock mutex failed");
        return SOFTBUS_LOCK_ERR;
    }
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_authClientHead, AuthManager, node) {
        if (!item->isValid) {
            continue;
        }
        if (strncmp(mac, item->peerP2pMac, strlen(item->peerP2pMac)) == 0 &&
            IsAuthLinkTypeMatched(type, item)) {
            (void)memcpy_s(option, sizeof(ConnectOption), &item->option, sizeof(ConnectOption));
            (void)SoftBusMutexUnlock(&g_authLock);
            return SOFTBUS_OK;
        }
    }
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_authServerHead, AuthManager, node) {
        if (!item->isValid) {
            continue;
        }
        if (strncmp(mac, item->peerP2pMac, strlen(item->peerP2pMac)) == 0 &&
            IsAuthLinkTypeMatched(type, item)) {
            (void)memcpy_s(option, sizeof(ConnectOption), &item->option, sizeof(ConnectOption));
            (void)SoftBusMutexUnlock(&g_authLock);
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&g_authLock);
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "auth not found by peer p2p mac: %d.", type);
    return SOFTBUS_ERR;
}

int32_t GetActiveAuthConnInfo(const char *uuid, ConnectType type, AuthConnInfo *connInfo)
{
    ConnectOption option = {0};
    if (uuid == NULL || strlen(uuid) == 0 || connInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    if (AuthGetActiveConnectOption(uuid, type, &option) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "get active auth fail, type = %d.", type);
        return SOFTBUS_ERR;
    }
    (void)ConvertOptionToAuthConnInfo(&option, false, connInfo);
    return SOFTBUS_OK;
}

int32_t AuthGetActiveConnectOption(const char *uuid, ConnectType type, ConnectOption *option)
{
    if (uuid == NULL || strlen(uuid) == 0 || option == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    AuthManager *item = NULL;
    AuthManager *next = NULL;
    if (SoftBusMutexLock(&g_authLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "lock mutex failed");
        return SOFTBUS_LOCK_ERR;
    }
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_authClientHead, AuthManager, node) {
        if (!item->isValid) {
            continue;
        }
        if (IsP2PLink(item) || item->option.type != type || item->status != AUTH_PASSED) {
            continue;
        }
        if (strncmp(item->peerUuid, uuid, strlen(uuid)) == 0) {
            (void)memcpy_s(option, sizeof(ConnectOption), &item->option, sizeof(ConnectOption));
            (void)SoftBusMutexUnlock(&g_authLock);
            return SOFTBUS_OK;
        }
    }
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_authServerHead, AuthManager, node) {
        if (!item->isValid) {
            continue;
        }
        if (IsP2PLink(item) || item->option.type != type || item->status != AUTH_PASSED) {
            continue;
        }
        if (strncmp(item->peerUuid, uuid, strlen(uuid)) == 0) {
            (void)memcpy_s(option, sizeof(ConnectOption), &item->option, sizeof(ConnectOption));
            (void)SoftBusMutexUnlock(&g_authLock);
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&g_authLock);
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "active auth not found, type = %d.", type);
    return SOFTBUS_ERR;
}

int32_t AuthGetActiveBleConnectOption(const char *uuid, bool isServerSide, ConnectOption *option)
{
    if (uuid == NULL || uuid[0] == '\0' || option == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    AuthManager *item = NULL;
    ListNode *targetList = isServerSide ? &g_authServerHead : &g_authClientHead;
    if (SoftBusMutexLock(&g_authLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "lock mutex failed");
        return SOFTBUS_LOCK_ERR;
    }
    LIST_FOR_EACH_ENTRY(item, targetList, AuthManager, node) {
        if (!item->isValid) {
            continue;
        }
        if (item->status == AUTH_PASSED && item->option.type == CONNECT_BLE &&
            strcmp(item->peerUuid, uuid) == 0) {
            (void)memcpy_s(option, sizeof(ConnectOption), &item->option, sizeof(ConnectOption));
            (void)SoftBusMutexUnlock(&g_authLock);
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&g_authLock);
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "active ble auth not exist.");
    return SOFTBUS_ERR;
}
