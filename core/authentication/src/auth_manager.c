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
#include "auth_sessionkey.h"
#include "auth_socket.h"
#include "lnn_connection_addr_utils.h"
#include "message_handler.h"
#include "softbus_adapter_mem.h"
#include "softbus_base_listener.h"
#include "softbus_errcode.h"
#include "softbus_json_utils.h"
#include "softbus_log.h"

#ifdef __cplusplus
extern "C" {
#endif

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

static pthread_mutex_t g_authLock;
static bool g_isAuthInit = false;

#define INITIAL_STATE 0
#define RECV_ENCRYPT_DATA_STATE 1
#define KEY_GENERATEG_STATE 2

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

static int32_t EventInLooper(int64_t authId)
{
    SoftBusMessage *msgDelay = (SoftBusMessage *)SoftBusMalloc(sizeof(SoftBusMessage));
    if (msgDelay == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "SoftBusMalloc failed");
        return SOFTBUS_ERR;
    }
    (void)memset_s(msgDelay, sizeof(SoftBusMessage), 0, sizeof(SoftBusMessage));
    msgDelay->arg1 = (uint64_t)authId;
    msgDelay->handler = &g_authHandler;
    if (g_authHandler.looper == NULL || g_authHandler.looper->PostMessageDelay == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "softbus handler is null");
        SoftBusFree(msgDelay);
        return SOFTBUS_ERR;
    }
    g_authHandler.looper->PostMessageDelay(g_authHandler.looper, msgDelay, AUTH_DELAY_MS);
    return SOFTBUS_OK;
}

static int32_t CustomFunc(const SoftBusMessage *msg, void *authId)
{
    if (msg == NULL || authId == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "invalid parameter");
        return 0;
    }
    int64_t id = *(int64_t *)authId;
    if ((int64_t)(msg->arg1) == id) {
        SoftBusFree(authId);
        return SOFTBUS_OK;
    }
    return SOFTBUS_ERR;
}

static void EventRemove(int64_t authId)
{
    int64_t *id = (int64_t *)SoftBusMalloc(sizeof(int64_t));
    if (id == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "SoftBusMalloc failed");
        return;
    }
    *id = authId;
    g_authHandler.looper->RemoveMessageCustom(g_authHandler.looper, &g_authHandler, CustomFunc, (void *)id);
}

AuthManager *AuthGetManagerByAuthId(int64_t authId, AuthSideFlag side)
{
    if (pthread_mutex_lock(&g_authLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "lock mutex failed");
        return NULL;
    }
    ListNode *item = NULL;
    ListNode *head = NULL;
    if (side == CLIENT_SIDE_FLAG) {
        head = &g_authClientHead;
    } else {
        head = &g_authServerHead;
    }
    LIST_FOR_EACH(item, head) {
        AuthManager *auth = LIST_ENTRY(item, AuthManager, node);
        if (auth->authId == authId) {
            (void)pthread_mutex_unlock(&g_authLock);
            return auth;
        }
    }
    (void)pthread_mutex_unlock(&g_authLock);
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_WARN,
        "cannot find auth by authId, authId is %lld, side is %d", authId, side);
    return NULL;
}

AuthManager *AuthGetManagerByFd(int32_t fd)
{
    if (pthread_mutex_lock(&g_authLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "lock mutex failed");
        return NULL;
    }
    AuthManager *auth = NULL;
    ListNode *item = NULL;
    ListNode *head = NULL;
    head = &g_authClientHead;
    LIST_FOR_EACH(item, head) {
        auth = LIST_ENTRY(item, AuthManager, node);
        if (auth->fd == fd) {
            (void)pthread_mutex_unlock(&g_authLock);
            return auth;
        }
    }
    head = &g_authServerHead;
    LIST_FOR_EACH(item, head) {
        auth = LIST_ENTRY(item, AuthManager, node);
        if (auth->fd == fd) {
            (void)pthread_mutex_unlock(&g_authLock);
            return auth;
        }
    }
    (void)pthread_mutex_unlock(&g_authLock);
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "cannot find auth by fd, fd is %d", fd);
    return NULL;
}

static AuthManager *GetAuthByPeerUdid(const char *peerUdid)
{
    if (pthread_mutex_lock(&g_authLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "lock mutex failed");
        return NULL;
    }
    AuthManager *auth = NULL;
    ListNode *item = NULL;
    LIST_FOR_EACH(item, &g_authClientHead) {
        auth = LIST_ENTRY(item, AuthManager, node);
        if (strncmp(auth->peerUdid, peerUdid, strlen(peerUdid)) == 0) {
            (void)pthread_mutex_unlock(&g_authLock);
            return auth;
        }
    }
    LIST_FOR_EACH(item, &g_authServerHead) {
        auth = LIST_ENTRY(item, AuthManager, node);
        if (strncmp(auth->peerUdid, peerUdid, strlen(peerUdid)) == 0) {
            (void)pthread_mutex_unlock(&g_authLock);
            return auth;
        }
    }
    (void)pthread_mutex_unlock(&g_authLock);
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "cannot find auth by peerUdid!");
    return NULL;
}

static VerifyCallback *GetAuthCallback(uint32_t moduleId)
{
    if (moduleId >= MODULE_NUM) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "invalid parameter");
        return NULL;
    }
    if (g_verifyCallback == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "verify callback is null");
        return NULL;
    }
    return &g_verifyCallback[moduleId];
}

static VerifyCallback *GetDefaultAuthCallback(void)
{
    if (g_verifyCallback == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "verify callback is null");
        return NULL;
    }
    return &g_verifyCallback[LNN];
}

AuthManager *AuthGetManagerByRequestId(uint32_t requestId)
{
    if (pthread_mutex_lock(&g_authLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "lock mutex failed");
        return NULL;
    }
    ListNode *item = NULL;
    LIST_FOR_EACH(item, &g_authClientHead) {
        AuthManager *auth = LIST_ENTRY(item, AuthManager, node);
        if (auth->requestId == requestId) {
            (void)pthread_mutex_unlock(&g_authLock);
            return auth;
        }
    }
    (void)pthread_mutex_unlock(&g_authLock);
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "cannot find auth by requestId, requestId is %u", requestId);
    return NULL;
}

static void DeleteAuth(AuthManager *auth)
{
    if (pthread_mutex_lock(&g_authLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "lock mutex failed");
        return;
    }
    ListDelete(&auth->node);
    if (auth->encryptDevData != NULL) {
        SoftBusFree(auth->encryptDevData);
        auth->encryptDevData = NULL;
    }
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "delete auth manager, authId is %lld", auth->authId);
    SoftBusFree(auth);
    (void)pthread_mutex_unlock(&g_authLock);
}

static void HandleAuthFail(AuthManager *auth)
{
    if (auth == NULL) {
        return;
    }
    EventRemove(auth->authId);
    auth->cb->onDeviceVerifyFail(auth->authId);
}

int32_t AuthHandleLeaveLNN(int64_t authId)
{
    AuthManager *auth = NULL;
    auth = AuthGetManagerByAuthId(authId, CLIENT_SIDE_FLAG);
    if (auth == NULL) {
        auth = AuthGetManagerByAuthId(authId, SERVER_SIDE_FLAG);
        if (auth == NULL) {
            SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "no match auth found, AuthHandleLeaveLNN failed");
            return SOFTBUS_ERR;
        }
    }
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "auth handle leave LNN, authId is %lld", authId);
    if (pthread_mutex_lock(&g_authLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "lock mutex failed");
        return SOFTBUS_ERR;
    }
    AuthClearSessionKeyBySeq((int32_t)authId);
    (void)pthread_mutex_unlock(&g_authLock);
    if (auth->option.type == CONNECT_TCP) {
        AuthCloseTcpFd(auth->fd);
    }
    DeleteAuth(auth);
    return SOFTBUS_OK;
}

static int32_t InitNewAuthManager(AuthManager *auth, uint32_t moduleId, const ConnectOption *option,
    const ConnectionAddr *addr)
{
    auth->cb = GetAuthCallback(moduleId);
    if (auth->cb == NULL) {
        return SOFTBUS_ERR;
    }
    auth->status = WAIT_CONNECTION_ESTABLISHED;
    auth->side = CLIENT_SIDE_FLAG;
    auth->authId = GetSeq(CLIENT_SIDE_FLAG);
    auth->requestId = ConnGetNewRequestId(MODULE_DEVICE_AUTH);
    auth->softbusVersion = SOFT_BUS_NEW_V1;
    auth->option = *option;
    auth->hichain = g_hichainGaInstance;
    if (memcpy_s(auth->peerUid, MAX_ACCOUNT_HASH_LEN, addr->peerUid, MAX_ACCOUNT_HASH_LEN) != 0) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "memcpy_s faield");
        return SOFTBUS_ERR;
    }
    ListNodeInsert(&g_authClientHead, &auth->node);
    return SOFTBUS_OK;
}

static AuthManager *InitClientAuthManager(AuthModuleId moduleId, const ConnectOption *option,
    const ConnectionAddr *addr)
{
    if (pthread_mutex_lock(&g_authLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "lock mutex failed");
        return NULL;
    }
    AuthManager *auth = (AuthManager *)SoftBusMalloc(sizeof(AuthManager));
    if (auth == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "SoftBusMalloc failed");
        (void)pthread_mutex_unlock(&g_authLock);
        return NULL;
    }
    (void)memset_s(auth, sizeof(AuthManager), 0, sizeof(AuthManager));
    if (InitNewAuthManager(auth, moduleId, option, addr) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "auth InitNewAuthManager failed");
        (void)pthread_mutex_unlock(&g_authLock);
        SoftBusFree(auth);
        return NULL;
    }
    (void)pthread_mutex_unlock(&g_authLock);
    return auth;
}

static int64_t HandleVerifyDevice(AuthModuleId moduleId, const ConnectionAddr *addr)
{
    ConnectOption option = {0};
    if (!LnnConvertAddrToOption(addr, &option)) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "auth LnnConverAddrToOption failed");
        return SOFTBUS_ERR;
    }
    AuthManager *auth = NULL;
    auth = InitClientAuthManager(moduleId, &option, addr);
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
    } else if (option.type == CONNECT_BR) {
        if (ConnConnectDevice(&option, auth->requestId, &g_connResult) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "auth ConnConnectDevice failed");
            (void)AuthHandleLeaveLNN(auth->authId);
            return SOFTBUS_ERR;
        }
    } else {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "auth conn type %d is not support", option.type);
        (void)AuthHandleLeaveLNN(auth->authId);
        return SOFTBUS_ERR;
    }
    if (EventInLooper(auth->authId) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "auth EventInLooper failed");
        (void)AuthHandleLeaveLNN(auth->authId);
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "start authentication process, authId is %lld", auth->authId);
    return auth->authId;
}

int64_t AuthVerifyDevice(AuthModuleId moduleId, const ConnectionAddr *addr)
{
    int64_t authId;

    if (addr == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "invalid parameter");
        return SOFTBUS_INVALID_PARAM;
    }
    if (g_hichainGaInstance == NULL || g_hichainGmInstance == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "need to call HichainServiceInit!");
        return SOFTBUS_ERR;
    }
    authId = HandleVerifyDevice(moduleId, addr);
    if (authId <= 0) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "auth HandleVerifyDevice failed");
        return SOFTBUS_ERR;
    }
    return authId;
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
        HandleAuthFail(auth);
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
    HandleAuthFail(auth);
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
            HandleAuthFail(auth);
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
    if (auth->hichain->authDevice(auth->authId, authParams, &g_hichainCallback) != 0) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "authDevice failed");
        cJSON_free(authParams);
        HandleAuthFail(auth);
        return;
    }
    cJSON_free(authParams);
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
    auth = AuthGetManagerByAuthId(authId, CLIENT_SIDE_FLAG);
    if (auth == NULL) {
        auth = AuthGetManagerByAuthId(authId, SERVER_SIDE_FLAG);
        if (auth == NULL) {
            SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "no match auth found");
            return;
        }
    }
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "auth get session key succ, authId is %lld", authId);
    NecessaryDevInfo devInfo = {0};
    if (AuthGetDeviceKey(devInfo.deviceKey, MAX_DEVICE_KEY_LEN, &devInfo.deviceKeyLen, &auth->option) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "auth get device key failed");
        return;
    }
    if (pthread_mutex_lock(&g_authLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "lock mutex failed");
        return;
    }
    devInfo.type = auth->option.type;
    devInfo.side = auth->side;
    devInfo.seq = (int32_t)((uint64_t)authId & LOW_32_BIT);
    AuthSetLocalSessionKey(&devInfo, auth->peerUdid, sessionKey, sessionKeyLen);
    auth->status = IN_SYNC_PROGRESS;
    (void)pthread_mutex_unlock(&g_authLock);
    if (auth->option.type == CONNECT_TCP && auth->side == SERVER_SIDE_FLAG) {
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
        HandleAuthFail(auth);
        return;
    }
    if (auth->side == SERVER_SIDE_FLAG) {
        if (EventInLooper(auth->authId) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "auth EventInLooper failed");
            HandleAuthFail(auth);
            return;
        }
        if (AuthSyncDeviceUuid(auth) != SOFTBUS_OK) {
            HandleAuthFail(auth);
        }
        return;
    }
    VerifyDeviceDevLvl(auth);
}

static void ReceiveCloseAck(uint32_t connectionId)
{
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "auth receive close connection ack");
    AuthSendCloseAck(connectionId);
    ListNode *item = NULL;
    ListNode *tmp = NULL;
    LIST_FOR_EACH_SAFE(item, tmp, &g_authClientHead) {
        AuthManager *auth = LIST_ENTRY(item, AuthManager, node);
        if (auth->connectionId == connectionId && auth->option.type != CONNECT_TCP) {
            EventRemove(auth->authId);
            auth->cb->onDeviceVerifyPass(auth->authId);
            return;
        }
    }
}

void AuthHandlePeerSyncDeviceInfo(AuthManager *auth, uint8_t *data, uint32_t len)
{
    if (auth == NULL || data == NULL || len == 0 || len > AUTH_MAX_DATA_LEN) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "invalid parameter");
        return;
    }

    if (auth->option.type == CONNECT_TCP && auth->side == SERVER_SIDE_FLAG &&
        auth->encryptInfoStatus == KEY_GENERATEG_STATE) {
        auth->cb->onKeyGenerated(auth->authId, &auth->option, auth->peerVersion);
    }
    auth->encryptInfoStatus = RECV_ENCRYPT_DATA_STATE;

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
            HandleAuthFail(auth);
            return;
        }
        (void)memset_s(auth->encryptDevData, len, 0, len);
        if (memcpy_s(auth->encryptDevData, len, data, len) != EOK) {
            SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "memcpy_s failed");
            HandleAuthFail(auth);
            return;
        }
        auth->encryptLen = len;
        return;
    }
    auth->cb->onRecvSyncDeviceInfo(auth->authId, auth->side, auth->peerUuid, data, len);
    auth->status = AUTH_PASSED;
    if (auth->option.type == CONNECT_TCP) {
        auth->cb->onDeviceVerifyPass(auth->authId);
        EventRemove(auth->authId);
    }
}

static int32_t ServerAuthInit(AuthManager *auth, int64_t authId, uint64_t connectionId)
{
    auth->cb = GetDefaultAuthCallback();
    if (auth->cb == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "GetDefaultAuthCallback failed");
        return SOFTBUS_ERR;
    }

    auth->side = SERVER_SIDE_FLAG;
    auth->status = WAIT_CONNECTION_ESTABLISHED;
    auth->authId = authId;
    auth->connectionId = connectionId;
    auth->softbusVersion = SOFT_BUS_NEW_V1;
    if (g_hichainGaInstance == NULL || g_hichainGmInstance == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "need to HichainServiceInit!");
        return SOFTBUS_ERR;
    }
    auth->hichain = g_hichainGaInstance;
    ConnectionInfo connInfo;
    if (memset_s(&connInfo, sizeof(ConnectOption), 0, sizeof(ConnectOption)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "memset_s connInfo fail!");
    }
    if (ConnGetConnectionInfo(connectionId, &connInfo) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "auth ConnGetConnectionInfo failed");
        return SOFTBUS_ERR;
    }
    ConnectOption option;
    (void)memset_s(&option, sizeof(ConnectOption), 0, sizeof(ConnectOption));
    if (AuthConvertConnInfo(&option, &connInfo) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "AuthConvertConnInfo failed");
        return SOFTBUS_ERR;
    }
    auth->option = option;
    ListNodeInsert(&g_authServerHead, &auth->node);
    return SOFTBUS_OK;
}

static int32_t AnalysisData(char *data, int len, AuthDataInfo *info)
{
    if (len < (int32_t)sizeof(AuthDataInfo)) {
        return SOFTBUS_ERR;
    }
    info->type = *(uint32_t *)data;
    data += sizeof(uint32_t);
    info->module = *(int32_t *)data;
    data += sizeof(int32_t);
    info->authId = *(int64_t *)data;
    data += sizeof(int64_t);
    info->flag = *(int32_t *)data;
    data += sizeof(int32_t);
    info->dataLen = *(uint32_t *)data;
    return SOFTBUS_OK;
}

static AuthManager *CreateServerAuth(uint32_t connectionId, AuthDataInfo *authDataInfo)
{
    AuthManager *auth = NULL;
    if (pthread_mutex_lock(&g_authLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "lock mutex failed");
        return NULL;
    }
    auth = (AuthManager *)SoftBusMalloc(sizeof(AuthManager));
    if (auth == NULL) {
        (void)pthread_mutex_unlock(&g_authLock);
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "SoftBusMalloc failed");
        return NULL;
    }
    (void)memset_s(auth, sizeof(AuthManager), 0, sizeof(AuthManager));
    if (ServerAuthInit(auth, authDataInfo->authId, connectionId) != SOFTBUS_OK) {
        (void)pthread_mutex_unlock(&g_authLock);
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "ServerAuthInit failed");
        SoftBusFree(auth);
        return NULL;
    }
    (void)pthread_mutex_unlock(&g_authLock);
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "create auth as server side, authId is %lld", auth->authId);
    return auth;
}

static void HandleReceiveData(uint32_t connectionId, AuthDataInfo *authDataInfo, AuthSideFlag side, uint8_t *recvData)
{
    AuthManager *auth = NULL;
    auth = AuthGetManagerByAuthId(authDataInfo->authId, side);
    if (auth == NULL && authDataInfo->type != DATA_TYPE_CLOSE_ACK) {
        if (authDataInfo->type == DATA_TYPE_DEVICE_ID && side == SERVER_SIDE_FLAG && AuthIsSupportServerSide()) {
            auth = CreateServerAuth(connectionId, authDataInfo);
            if (auth == NULL) {
                SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "CreateServerAuth failed");
                return;
            }
        } else {
            SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "cannot find auth");
            return;
        }
    }
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "auth data type is %u", authDataInfo->type);
    switch (authDataInfo->type) {
        case DATA_TYPE_DEVICE_ID: {
            HandleReceiveDeviceId(auth, recvData);
            break;
        }
        case DATA_TYPE_AUTH: {
            HandleReceiveAuthData(auth, authDataInfo->module, recvData, authDataInfo->dataLen);
            break;
        }
        case DATA_TYPE_SYNC: {
            AuthHandlePeerSyncDeviceInfo(auth, recvData, authDataInfo->dataLen);
            break;
        }
        case DATA_TYPE_CLOSE_ACK: {
            ReceiveCloseAck(connectionId);
            break;
        }
        default: {
            SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "unknown data type");
            break;
        }
    }
}

void AuthOnDataReceived(uint32_t connectionId, ConnModule moduleId, int64_t seq, char *data, int len)
{
    if (data == NULL || moduleId != MODULE_DEVICE_AUTH) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "invalid parameter");
        return;
    }
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO,
        "auth receive data, connectionId is %u, moduleId is %d, seq is %lld", connectionId, moduleId, seq);
    AuthDataInfo authDataInfo = {0};
    uint8_t *recvData = NULL;
    AuthSideFlag side;
    side = AuthGetSideByRemoteSeq(seq);
    if (AnalysisData(data, len, &authDataInfo) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "AnalysisData failed");
        return;
    }
    recvData = (uint8_t *)data + sizeof(AuthDataInfo);
    HandleReceiveData(connectionId, &authDataInfo, side, recvData);
}

static void AuthOnError(int64_t authId, int operationCode, int errorCode, const char *errorReturn)
{
    (void)operationCode;
    (void)errorReturn;
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "HiChain auth failed, errorCode is %d", errorCode);
    AuthManager *auth = NULL;
    auth = AuthGetManagerByAuthId(authId, CLIENT_SIDE_FLAG);
    if (auth == NULL) {
        auth = AuthGetManagerByAuthId(authId, SERVER_SIDE_FLAG);
        if (auth == NULL) {
            SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "no match auth found, AuthPostData failed");
            return;
        }
    }
    HandleAuthFail(auth);
}

static char *AuthOnRequest(int64_t authReqId, int authForm, const char *reqParams)
{
    AuthManager *auth = NULL;
    auth = AuthGetManagerByAuthId(authReqId, SERVER_SIDE_FLAG);
    if (auth == NULL) {
        auth = AuthGetManagerByAuthId(authReqId, CLIENT_SIDE_FLAG);
        if (auth == NULL) {
            SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "no match auth found, AuthPostData failed");
            return NULL;
        }
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
    (void)connectionId;
    (void)info;
}

static void AuthOnDeviceNotTrusted(const char *peerUdid)
{
    AuthManager *auth = NULL;
    auth = GetAuthByPeerUdid(peerUdid);
    if (auth == NULL) {
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
    g_hichainListener.onDeviceNotTrusted = AuthOnDeviceNotTrusted;
    if (g_hichainGmInstance->regDataChangeListener(AUTH_APPID, &g_hichainListener) != 0) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "auth RegDataChangeListener failed");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static void AuthTimeout(SoftBusMessage *msg)
{
    if (msg == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "invalid parameter");
        return;
    }
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "auth process timeout, authId = %lld", (int64_t)(msg->arg1));
    AuthManager *auth = NULL;
    auth = AuthGetManagerByAuthId((int64_t)(msg->arg1), CLIENT_SIDE_FLAG);
    if (auth == NULL) {
        auth = AuthGetManagerByAuthId((int64_t)(msg->arg1), SERVER_SIDE_FLAG);
        if (auth == NULL) {
            SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "no match auth found");
            return;
        }
    }
    auth->cb->onDeviceVerifyFail(auth->authId);
}

void AuthHandleTransInfo(AuthManager *auth, const ConnPktHead *head, char *data, int len)
{
    int32_t i;
    if (g_transCallback == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "auth trans callback is null");
        return;
    }
    for (i = 0; i < MODULE_NUM; i++) {
        if (g_transCallback[i].onTransUdpDataRecv != NULL) {
            AuthTransDataInfo info = {0};
            info.module = head->module;
            info.flags = head->flag;
            info.seq = head->seq;
            info.data = data;
            info.len = len;
            g_transCallback[i].onTransUdpDataRecv(auth->authId, &(auth->option), &info);
        }
    }
}

int32_t AuthTransDataRegCallback(AuthModuleId moduleId, AuthTransCallback *cb)
{
    if (cb == NULL || moduleId >= MODULE_NUM) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "invalid parameter");
        return SOFTBUS_INVALID_PARAM;
    }
    if (g_transCallback == NULL) {
        g_transCallback = (AuthTransCallback *)SoftBusMalloc(sizeof(AuthTransCallback) * MODULE_NUM);
        if (g_transCallback == NULL) {
            SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "SoftBusMalloc failed");
            return SOFTBUS_ERR;
        }
        (void)memset_s(g_transCallback, sizeof(AuthTransCallback) * MODULE_NUM, 0,
            sizeof(AuthTransCallback) * MODULE_NUM);
    }
    if (cb->onTransUdpDataRecv != NULL) {
        g_transCallback[moduleId].onTransUdpDataRecv = cb->onTransUdpDataRecv;
    }
    if (cb->onAuthChannelClose != NULL) {
        g_transCallback[moduleId].onAuthChannelClose = cb->onAuthChannelClose;
    }
    return SOFTBUS_OK;
}

static int32_t AuthCallbackInit(uint32_t moduleNum)
{
    if (g_verifyCallback != NULL) {
        SoftBusFree(g_verifyCallback);
        g_verifyCallback = NULL;
    }
    g_verifyCallback = (VerifyCallback *)SoftBusMalloc(sizeof(VerifyCallback) * moduleNum);
    if (g_verifyCallback == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "SoftBusMalloc failed");
        return SOFTBUS_ERR;
    }
    (void)memset_s(g_verifyCallback, sizeof(VerifyCallback) * moduleNum, 0, sizeof(VerifyCallback) * moduleNum);
    return SOFTBUS_OK;
}

int32_t AuthRegCallback(AuthModuleId moduleId, VerifyCallback *cb)
{
    if (cb == NULL || cb->onKeyGenerated == NULL || cb->onDeviceVerifyFail == NULL ||
        cb->onRecvSyncDeviceInfo == NULL || cb->onDeviceNotTrusted == NULL ||
        cb->onDeviceVerifyPass == NULL || cb->onDisconnect == NULL || moduleId >= MODULE_NUM) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "invalid parameter");
        return SOFTBUS_INVALID_PARAM;
    }
    if (g_verifyCallback == NULL) {
        int32_t ret = AuthCallbackInit(MODULE_NUM);
        if (ret != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "AuthCallbackInit failed");
            return ret;
        }
    }
    g_verifyCallback[moduleId].onKeyGenerated = cb->onKeyGenerated;
    g_verifyCallback[moduleId].onDeviceVerifyFail = cb->onDeviceVerifyFail;
    g_verifyCallback[moduleId].onRecvSyncDeviceInfo = cb->onRecvSyncDeviceInfo;
    g_verifyCallback[moduleId].onDeviceVerifyPass = cb->onDeviceVerifyPass;
    g_verifyCallback[moduleId].onDeviceNotTrusted = cb->onDeviceNotTrusted;
    g_verifyCallback[moduleId].onDisconnect = cb->onDisconnect;
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

static void AuthLooperInit(void)
{
    g_authHandler.name = "auth_handler";
    g_authHandler.HandleMessage = AuthTimeout;
    g_authHandler.looper = GetLooper(LOOP_TYPE_DEFAULT);
}

static int32_t ServerIpAuthInit(AuthManager *auth, int32_t cfd, const char *peerIp, int32_t port)
{
    auth->cb = GetDefaultAuthCallback();
    if (auth->cb == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "GetDefaultAuthCallback failed");
        return SOFTBUS_ERR;
    }
    auth->side = SERVER_SIDE_FLAG;
    auth->status = WAIT_CONNECTION_ESTABLISHED;
    auth->softbusVersion = SOFT_BUS_NEW_V1;
    if (g_hichainGaInstance == NULL || g_hichainGmInstance == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "need to HichainServiceInit!");
        return SOFTBUS_ERR;
    }
    auth->hichain = g_hichainGaInstance;
    auth->fd = cfd;
    auth->authId = 0;
    auth->encryptInfoStatus = INITIAL_STATE;
    ConnectOption option;
    (void)memset_s(&option, sizeof(ConnectOption), 0, sizeof(ConnectOption));
    option.type = CONNECT_TCP;
    if (strncpy_s(option.info.ipOption.ip, IP_LEN, peerIp, strlen(peerIp))) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "strncpy_s failed");
        return SOFTBUS_ERR;
    }
    option.info.ipOption.port = port;
    auth->option = option;
    ListNodeInsert(&g_authServerHead, &auth->node);
    return SOFTBUS_OK;
}

int32_t CreateServerIpAuth(int32_t cfd, const char *ip, int32_t port)
{
    AuthManager *auth = NULL;

    if (pthread_mutex_lock(&g_authLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "lock mutex failed");
        return SOFTBUS_ERR;
    }
    auth = (AuthManager *)SoftBusMalloc(sizeof(AuthManager));
    if (auth == NULL) {
        (void)pthread_mutex_unlock(&g_authLock);
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "SoftBusMalloc failed");
        return SOFTBUS_ERR;
    }
    (void)memset_s(auth, sizeof(AuthManager), 0, sizeof(AuthManager));
    if (ServerIpAuthInit(auth, cfd, ip, port) != SOFTBUS_OK) {
        (void)pthread_mutex_unlock(&g_authLock);
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "ServerIpAuthInit failed");
        SoftBusFree(auth);
        return SOFTBUS_ERR;
    }
    (void)pthread_mutex_unlock(&g_authLock);
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
    fd = OpenTcpChannel(option);
    if (fd < 0) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "auth OpenTcpChannel failed");
        return SOFTBUS_ERR;
    }
    AuthManager *auth = (AuthManager *)SoftBusCalloc(sizeof(AuthManager));
    if (auth == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "SoftBusCalloc failed");
        return SOFTBUS_ERR;
    }
    (void)pthread_mutex_lock(&g_authLock);
    auth->side = CLIENT_SIDE_FLAG;
    auth->authId = GetSeq(CLIENT_SIDE_FLAG);
    auth->softbusVersion = SOFT_BUS_NEW_V1;
    auth->option = *option;
    auth->fd = fd;
    auth->hichain = g_hichainGaInstance;
    ListNodeInsert(&g_authClientHead, &auth->node);
    (void)pthread_mutex_unlock(&g_authLock);
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
    EventRemove(auth->authId);
    if (auth->side == SERVER_SIDE_FLAG && auth->status < IN_SYNC_PROGRESS) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "auth no need to notify lnn disconn");
        (void)AuthHandleLeaveLNN(auth->authId);
    } else {
        if (auth->cb != NULL) {
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
    for (i = 0; i < MODULE_NUM; i++) {
        if (g_transCallback[i].onAuthChannelClose != NULL) {
            g_transCallback[i].onAuthChannelClose(authId);
        }
    }
}

void AuthIpChanged(ConnectType type)
{
    AuthManager *auth = NULL;
    ListNode *item = NULL;
    ListNode *tmp = NULL;
    if (pthread_mutex_lock(&g_authLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "lock mutex failed");
        return;
    }
    LIST_FOR_EACH_SAFE(item, tmp, &g_authClientHead) {
        auth = LIST_ENTRY(item, AuthManager, node);
        if (auth->option.type == CONNECT_TCP) {
            EventRemove(auth->authId);
            auth->cb->onDisconnect(auth->authId);
        }
    }
    LIST_FOR_EACH_SAFE(item, tmp, &g_authServerHead) {
        auth = LIST_ENTRY(item, AuthManager, node);
        if (auth->option.type == CONNECT_TCP) {
            EventRemove(auth->authId);
            if (auth->status < IN_SYNC_PROGRESS) {
                SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "auth no need to notify lnn");
                (void)pthread_mutex_unlock(&g_authLock);
                (void)AuthHandleLeaveLNN(auth->authId);
                (void)pthread_mutex_lock(&g_authLock);
            } else {
                auth->cb->onDisconnect(auth->authId);
            }
        }
    }
    (void)pthread_mutex_unlock(&g_authLock);
}

int32_t AuthGetIdByOption(const ConnectOption *option, int64_t *authId)
{
    AuthManager *auth = NULL;
    ListNode *item = NULL;
    ListNode *tmp = NULL;
    if (pthread_mutex_lock(&g_authLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "lock mutex failed");
        return SOFTBUS_ERR;
    }
    LIST_FOR_EACH_SAFE(item, tmp, &g_authClientHead) {
        auth = LIST_ENTRY(item, AuthManager, node);
        if ((option->type == CONNECT_TCP && strncmp(auth->option.info.ipOption.ip, option->info.ipOption.ip,
            strlen(auth->option.info.ipOption.ip)) == 0) || (option->type == CONNECT_BR &&
            strncmp(auth->option.info.brOption.brMac, option->info.brOption.brMac, BT_MAC_LEN) == 0)) {
            *authId = auth->authId;
            (void)pthread_mutex_unlock(&g_authLock);
            return SOFTBUS_OK;
        }
    }
    LIST_FOR_EACH_SAFE(item, tmp, &g_authServerHead) {
        auth = LIST_ENTRY(item, AuthManager, node);
        if ((option->type == CONNECT_TCP && strncmp(auth->option.info.ipOption.ip, option->info.ipOption.ip,
            strlen(auth->option.info.ipOption.ip)) == 0) || (option->type == CONNECT_BR &&
            strncmp(auth->option.info.brOption.brMac, option->info.brOption.brMac, BT_MAC_LEN) == 0)) {
            *authId = auth->authId;
            (void)pthread_mutex_unlock(&g_authLock);
            return SOFTBUS_OK;
        }
    }
    (void)pthread_mutex_unlock(&g_authLock);
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "auth get id by option failed");
    return SOFTBUS_ERR;
}

int32_t AuthGetUuidByOption(const ConnectOption *option, char *buf, uint32_t bufLen)
{
    AuthManager *auth = NULL;
    ListNode *item = NULL;
    ListNode *tmp = NULL;
    if (pthread_mutex_lock(&g_authLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "lock mutex failed");
        return SOFTBUS_ERR;
    }
    LIST_FOR_EACH_SAFE(item, tmp, &g_authClientHead) {
        auth = LIST_ENTRY(item, AuthManager, node);
        if ((option->type == CONNECT_TCP && strncmp(auth->option.info.ipOption.ip, option->info.ipOption.ip,
            strlen(auth->option.info.ipOption.ip)) == 0) || (option->type == CONNECT_BR &&
            strncmp(auth->option.info.brOption.brMac, option->info.brOption.brMac, BT_MAC_LEN) == 0)) {
            if (strncpy_s(buf, bufLen, auth->peerUuid, strlen(auth->peerUuid)) != EOK) {
                (void)pthread_mutex_unlock(&g_authLock);
                SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "memcpy_s failed");
                return SOFTBUS_ERR;
            }
            (void)pthread_mutex_unlock(&g_authLock);
            return SOFTBUS_OK;
        }
    }
    LIST_FOR_EACH_SAFE(item, tmp, &g_authServerHead) {
        auth = LIST_ENTRY(item, AuthManager, node);
        if ((option->type == CONNECT_TCP && strncmp(auth->option.info.ipOption.ip, option->info.ipOption.ip,
            strlen(auth->option.info.ipOption.ip)) == 0) || (option->type == CONNECT_BR &&
            strncmp(auth->option.info.brOption.brMac, option->info.brOption.brMac, BT_MAC_LEN) == 0)) {
            if (strncpy_s(buf, bufLen, auth->peerUuid, strlen(auth->peerUuid)) != EOK) {
                (void)pthread_mutex_unlock(&g_authLock);
                SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "memcpy_s failed");
                return SOFTBUS_ERR;
            }
            (void)pthread_mutex_unlock(&g_authLock);
            return SOFTBUS_OK;
        }
    }
    (void)pthread_mutex_unlock(&g_authLock);
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "auth get uuid by option failed");
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
        if (auth->option.type == CONNECT_TCP) {
            AuthCloseTcpFd(auth->fd);
        }
        EventRemove(auth->authId);
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
        if (auth->option.type == CONNECT_TCP) {
            AuthCloseTcpFd(auth->fd);
        }
        EventRemove(auth->authId);
        SoftBusFree(auth);
        auth = NULL;
    }
    ListInit(&g_authClientHead);
    ListInit(&g_authServerHead);
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "clear auth manager finish");
}

int32_t AuthDeinit(void)
{
    if (g_isAuthInit == false) {
        return SOFTBUS_OK;
    }
    if (g_verifyCallback != NULL) {
        SoftBusFree(g_verifyCallback);
        g_verifyCallback = NULL;
    }
    DestroyDeviceAuthService();
    ClearAuthManager();
    AuthClearAllSessionKey();
    pthread_mutex_destroy(&g_authLock);
    g_isAuthInit = false;
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "auth deinit succ!");
    return SOFTBUS_OK;
}

int32_t AuthInit(void)
{
    if (g_isAuthInit == true) {
        return SOFTBUS_OK;
    }
    if (AuthCallbackInit(MODULE_NUM) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "AuthCallbackInit failed");
        return SOFTBUS_ERR;
    }
    AuthGetAbility();
    AuthListInit();
    if (RegisterConnCallback(&g_connCallback, &g_connResult) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "RegisterConnCallback failed");
        (void)AuthDeinit();
        return SOFTBUS_ERR;
    }
    AuthLooperInit();
    UniqueIdInit();
    if (HichainServiceInit() != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "auth hichain init failed");
        (void)AuthDeinit();
        return SOFTBUS_ERR;
    }
    if (pthread_mutex_init(&g_authLock, NULL) != 0) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "mutex init fail!");
        (void)AuthDeinit();
        return SOFTBUS_ERR;
    }
    g_isAuthInit = true;
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "auth init succ!");
    return SOFTBUS_OK;
}

#ifdef __cplusplus
}
#endif
