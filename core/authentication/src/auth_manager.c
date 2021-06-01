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
#include "message_handler.h"
#include "softbus_base_listener.h"
#include "softbus_errcode.h"
#include "softbus_json_utils.h"
#include "softbus_log.h"
#include "softbus_mem_interface.h"

#ifdef __cplusplus
extern "C" {
#endif

static ListNode g_authClientHead;
static ListNode g_authServerHead;
static VerifyCallback *g_verifyCallback = NULL;
static ConnectCallback g_connCallback = {0};
static ConnectResult g_connResult = {0};
static const GroupAuthManager *g_hichainGaInstance = NULL;
static const DeviceGroupManager *g_hichainGmInstance = NULL;
static DeviceAuthCallback g_hichainCallback = {0};
static DataChangeListener g_hichainListener = {0};
static SoftBusHandler g_authHandler = {0};

static pthread_mutex_t g_authLock;
static bool g_isAuthInit = false;
static int32_t HichainServiceInit(void);

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
        LOG_ERR("SoftBusMalloc failed");
        return SOFTBUS_ERR;
    }
    (void)memset_s(msgDelay, sizeof(SoftBusMessage), 0, sizeof(SoftBusMessage));
    msgDelay->arg1 = (uint64_t)authId;
    msgDelay->handler = &g_authHandler;
    if (g_authHandler.looper == NULL || g_authHandler.looper->PostMessageDelay == NULL) {
        LOG_ERR("softbus handler is null");
        return SOFTBUS_ERR;
    }
    g_authHandler.looper->PostMessageDelay(g_authHandler.looper, msgDelay, AUTH_DELAY_MS);
    return SOFTBUS_OK;
}

static int32_t CustomFunc(const SoftBusMessage *msg, void *authId)
{
    if (msg == NULL || authId == NULL) {
        LOG_ERR("invalid parameter");
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
        LOG_ERR("SoftBusMalloc failed");
        return;
    }
    *id = authId;
    g_authHandler.looper->RemoveMessageCustom(g_authHandler.looper, &g_authHandler, CustomFunc, (void *)id);
}

AuthManager *AuthGetManagerByAuthId(int64_t authId, AuthSideFlag side)
{
    if (pthread_mutex_lock(&g_authLock) != 0) {
        LOG_ERR("lock mutex failed");
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
    LOG_ERR("cannot find auth by authId, authId is %lld", authId);
    return NULL;
}

AuthManager *AuthGetManagerByFd(int32_t fd)
{
    if (pthread_mutex_lock(&g_authLock) != 0) {
        LOG_ERR("lock mutex failed");
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
    LOG_ERR("cannot find auth by fd, fd is %d", fd);
    return NULL;
}

static AuthManager *GetAuthByPeerUdid(const char *peerUdid)
{
    if (pthread_mutex_lock(&g_authLock) != 0) {
        LOG_ERR("lock mutex failed");
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
    LOG_ERR("cannot find auth by peerUdid!");
    return NULL;
}

static VerifyCallback *GetAuthCallback(uint32_t moduleId)
{
    if (moduleId >= MODULE_NUM) {
        LOG_ERR("invalid parameter");
        return NULL;
    }
    if (g_verifyCallback == NULL) {
        LOG_ERR("verify callback is null");
        return NULL;
    }
    return &g_verifyCallback[moduleId];
}

static VerifyCallback *GetDefaultAuthCallback(void)
{
    if (g_verifyCallback == NULL) {
        LOG_ERR("verify callback is null");
        return NULL;
    }
    return &g_verifyCallback[LNN];
}

AuthManager *AuthGetManagerByRequestId(uint32_t requestId)
{
    if (pthread_mutex_lock(&g_authLock) != 0) {
        LOG_ERR("lock mutex failed");
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
    LOG_ERR("cannot find auth by requestId, requestId is %u", requestId);
    return NULL;
}

static bool IsDeviceAuthingNow(const ConnectOption *option)
{
    ListNode *item = NULL;
    LIST_FOR_EACH(item, &g_authClientHead) {
        AuthManager *auth = LIST_ENTRY(item, AuthManager, node);
        if (memcmp(&auth->option, option, sizeof(ConnectOption)) == 0 &&
            auth->status != AUTH_PASSED && auth->status != AUTH_FAIL) {
            return true;
        }
    }
    LIST_FOR_EACH(item, &g_authServerHead) {
        AuthManager *auth = LIST_ENTRY(item, AuthManager, node);
        if (memcmp(&auth->option, option, sizeof(ConnectOption)) == 0 &&
            auth->status != AUTH_PASSED && auth->status != AUTH_FAIL) {
            return true;
        }
    }
    return false;
}

static bool IsNeedVerify(const ConnectOption *option)
{
    char deviceKey[MAX_DEVICE_KEY_LEN] = {0};
    uint32_t deviceKeyLen = 0;
    if (AuthGetDeviceKey(deviceKey, MAX_DEVICE_KEY_LEN, &deviceKeyLen, option) != SOFTBUS_OK) {
        LOG_ERR("auth get device key failed");
        return true;
    }
    return !AuthIsDeviceVerified(option->type, deviceKey, deviceKeyLen);
}

static void DeleteAuth(AuthManager *auth)
{
    if (pthread_mutex_lock(&g_authLock) != 0) {
        LOG_ERR("lock mutex failed");
        return;
    }
    ListDelete(&auth->node);
    if (auth->encryptDevData != NULL) {
        SoftBusFree(auth->encryptDevData);
        auth->encryptDevData = NULL;
    }
    LOG_INFO("delete auth manager, authId is %lld", auth->authId);
    SoftBusFree(auth);
    (void)pthread_mutex_unlock(&g_authLock);
}

static void HandleAuthFail(AuthManager *auth)
{
    if (auth == NULL) {
        return;
    }
    if (auth->status != AUTH_PASSED) {
        auth->cb->onDeviceVerifyFail(auth->authId, &auth->option);
    }
    EventRemove(auth->authId);
    DeleteAuth(auth);
}

static int32_t InitNewAuthManager(AuthManager *auth, uint32_t moduleId, const ConnectOption *option)
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
    ListNodeInsert(&g_authClientHead, &auth->node);
    return SOFTBUS_OK;
}

static int32_t HandleVerifyDevice(AuthModuleId moduleId, const ConnectOption *option)
{
    if (pthread_mutex_lock(&g_authLock) != 0) {
        LOG_ERR("lock mutex failed");
        return SOFTBUS_ERR;
    }
    AuthManager *auth = (AuthManager *)SoftBusMalloc(sizeof(AuthManager));
    if (auth == NULL) {
        LOG_ERR("SoftBusMalloc failed");
        (void)pthread_mutex_unlock(&g_authLock);
        return SOFTBUS_ERR;
    }
    (void)memset_s(auth, sizeof(AuthManager), 0, sizeof(AuthManager));
    if (InitNewAuthManager(auth, moduleId, option) != SOFTBUS_OK) {
        LOG_ERR("auth InitNewAuthManager failed");
        (void)pthread_mutex_unlock(&g_authLock);
        SoftBusFree(auth);
        return SOFTBUS_ERR;
    }
    (void)pthread_mutex_unlock(&g_authLock);

    if (option->type == CONNECT_TCP) {
        if (HandleIpVerifyDevice(auth, option) != SOFTBUS_OK) {
            LOG_ERR("HandleIpVerifyDevice failed");
            DeleteAuth(auth);
            return SOFTBUS_ERR;
        }
    } else if (option->type == CONNECT_BR) {
        if (ConnConnectDevice(option, auth->requestId, &g_connResult) != SOFTBUS_OK) {
            LOG_ERR("auth ConnConnectDevice failed");
            DeleteAuth(auth);
            return SOFTBUS_ERR;
        }
    } else {
        LOG_ERR("auth conn type %d is not support", option->type);
        DeleteAuth(auth);
        return SOFTBUS_ERR;
    }
    if (EventInLooper(auth->authId) != SOFTBUS_OK) {
        LOG_ERR("auth EventInLooper failed");
        DeleteAuth(auth);
        return SOFTBUS_ERR;
    }
    LOG_INFO("start authentication process, authId is %lld", auth->authId);
    return SOFTBUS_OK;
}

int32_t AuthVerifyDevice(AuthModuleId moduleId, const ConnectOption *option)
{
    if (option == NULL) {
        LOG_ERR("invalid parameter");
        return SOFTBUS_INVALID_PARAM;
    }
    if (pthread_mutex_lock(&g_authLock) != 0) {
        LOG_ERR("lock mutex failed");
        return SOFTBUS_ERR;
    }
    if (IsNeedVerify(option) == false) {
        (void)pthread_mutex_unlock(&g_authLock);
        LOG_INFO("there is no need to verify!");
        return SOFTBUS_AUTH_VERIFIED;
    }
    if (IsDeviceAuthingNow(option) == true) {
        (void)pthread_mutex_unlock(&g_authLock);
        LOG_ERR("authentication between two devices is in progress, please verify later");
        return SOFTBUS_AUTH_VERIFYING;
    }
    (void)pthread_mutex_unlock(&g_authLock);
    if (g_hichainGaInstance == NULL || g_hichainGmInstance == NULL) {
        LOG_ERR("need to call AuthVerifyInit!");
        return SOFTBUS_ERR;
    }
    if (HandleVerifyDevice(moduleId, option) != SOFTBUS_OK) {
        LOG_ERR("auth HandleVerifyDevice failed");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
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
    LOG_ERR("auth create connection failed, fail reason is %d", reason);
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
        LOG_ERR("invalid parameter");
        return;
    }
    if (module == MODULE_AUTH_SDK) {
        if (auth->hichain->processData(auth->authId, data, dataLen, &g_hichainCallback) != 0) {
            LOG_ERR("Hichain process data failed");
            HandleAuthFail(auth);
        }
    } else {
        LOG_ERR("unknown auth data module");
    }
}

static void StartAuth(AuthManager *auth, char *groupId, bool isDeviceLevel, bool isClient)
{
    (void)groupId;
    char *authParams = NULL;
    if (isDeviceLevel) {
        authParams = AuthGenDeviceLevelParam(auth, isClient);
    } else {
        LOG_ERR("not supported session level");
        return;
    }
    if (authParams == NULL) {
        LOG_ERR("generate auth param failed");
        return;
    }
    if (auth->hichain->authDevice(auth->authId, authParams, &g_hichainCallback) != 0) {
        LOG_ERR("authDevice failed");
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

void HandleReceiveDeviceId(AuthManager *auth, uint8_t *data)
{
    if (auth == NULL || data == NULL) {
        LOG_ERR("invalid parameter");
        return;
    }
    if (AuthUnpackDeviceInfo(auth, data) != SOFTBUS_OK) {
        LOG_ERR("AuthUnpackDeviceInfo failed");
        HandleAuthFail(auth);
        return;
    }
    if (auth->side == SERVER_SIDE_FLAG) {
        if (AuthSyncDeviceUuid(auth) != SOFTBUS_OK) {
            HandleAuthFail(auth);
        }
        return;
    }
    if (auth->status == AUTH_PASSED) {
        LOG_INFO("auth pass, no need to call verify again");
        return;
    }
    VerifyDeviceDevLvl(auth);
}

static void ReceiveCloseAck(uint32_t connectionId)
{
    LOG_INFO("auth receive close connection ack");
    AuthSendCloseAck(connectionId);
    ListNode *item = NULL;
    ListNode *tmp = NULL;
    LIST_FOR_EACH_SAFE(item, tmp, &g_authClientHead) {
        AuthManager *auth = LIST_ENTRY(item, AuthManager, node);
        if (auth->connectionId == connectionId) {
            EventRemove(auth->authId);
            return;
        }
    }
}

void AuthHandlePeerSyncDeviceInfo(AuthManager *auth, uint8_t *data, uint32_t len)
{
    if (auth == NULL || data == NULL || len == 0 || len > AUTH_MAX_DATA_LEN) {
        LOG_ERR("invalid parameter");
        return;
    }
    if (AuthIsSeqInKeyList((int32_t)(auth->authId)) == false ||
        auth->status == IN_SYNC_PROGRESS) {
        LOG_INFO("auth saved encrypted data first");
        if (auth->encryptDevData != NULL) {
            LOG_WARN("encrypted data is not null");
            SoftBusFree(auth->encryptDevData);
            auth->encryptDevData = NULL;
        }
        auth->encryptDevData = (uint8_t *)SoftBusMalloc(len);
        if (auth->encryptDevData == NULL) {
            LOG_ERR("SoftBusMalloc failed");
            HandleAuthFail(auth);
            return;
        }
        (void)memset_s(auth->encryptDevData, len, 0, len);
        if (memcpy_s(auth->encryptDevData, len, data, len) != EOK) {
            LOG_ERR("memcpy_s failed");
            HandleAuthFail(auth);
            return;
        }
        auth->encryptLen = len;
        return;
    }
    auth->cb->onRecvSyncDeviceInfo(auth->authId, auth->side, auth->peerUuid, data, len);
    auth->status = AUTH_PASSED;
    if (auth->option.type == CONNECT_TCP) {
        ListNode *item = NULL;
        ListNode *tmp = NULL;
        LIST_FOR_EACH_SAFE(item, tmp, &g_authClientHead) {
            AuthManager *authList = LIST_ENTRY(item, AuthManager, node);
            if (authList == auth) {
                EventRemove(auth->authId);
                return;
            }
        }
    }
}

static int32_t ServerAuthInit(AuthManager *auth, int64_t authId, uint64_t connectionId)
{
    auth->cb = GetDefaultAuthCallback();
    if (auth->cb == NULL) {
        LOG_ERR("GetDefaultAuthCallback failed");
        return SOFTBUS_ERR;
    }
    if (AuthVerifyInit() != SOFTBUS_OK) {
        LOG_ERR("AuthVerifyInit failed");
        return SOFTBUS_ERR;
    }

    auth->side = SERVER_SIDE_FLAG;
    auth->status = WAIT_CONNECTION_ESTABLISHED;
    auth->authId = authId;
    auth->connectionId = connectionId;
    auth->softbusVersion = SOFT_BUS_NEW_V1;
    if (g_hichainGaInstance == NULL || g_hichainGmInstance == NULL) {
        LOG_ERR("need to AuthVerifyInit!");
        return SOFTBUS_ERR;
    }
    auth->hichain = g_hichainGaInstance;
    ConnectionInfo connInfo;
    if (memset_s(&connInfo, sizeof(ConnectOption), 0, sizeof(ConnectOption)) != EOK) {
        LOG_ERR("memset_s connInfo fail!");
    }
    if (ConnGetConnectionInfo(connectionId, &connInfo) != SOFTBUS_OK) {
        LOG_ERR("auth ConnGetConnectionInfo failed");
        return SOFTBUS_ERR;
    }
    ConnectOption option;
    (void)memset_s(&option, sizeof(ConnectOption), 0, sizeof(ConnectOption));
    if (AuthConvertConnInfo(&option, &connInfo) != SOFTBUS_OK) {
        LOG_ERR("AuthConvertConnInfo failed");
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
        LOG_ERR("lock mutex failed");
        return NULL;
    }
    auth = (AuthManager *)SoftBusMalloc(sizeof(AuthManager));
    if (auth == NULL) {
        (void)pthread_mutex_unlock(&g_authLock);
        LOG_ERR("SoftBusMalloc failed");
        return NULL;
    }
    (void)memset_s(auth, sizeof(AuthManager), 0, sizeof(AuthManager));
    if (ServerAuthInit(auth, authDataInfo->authId, connectionId) != SOFTBUS_OK) {
        (void)pthread_mutex_unlock(&g_authLock);
        LOG_ERR("ServerAuthInit failed");
        SoftBusFree(auth);
        return NULL;
    }
    if (EventInLooper(auth->authId) != SOFTBUS_OK) {
        (void)pthread_mutex_unlock(&g_authLock);
        LOG_ERR("auth EventInLooper failed");
        DeleteAuth(auth);
        return NULL;
    }
    (void)pthread_mutex_unlock(&g_authLock);
    LOG_INFO("auth as server side");
    return auth;
}

static void HandleReceiveData(uint32_t connectionId, AuthDataInfo *authDataInfo, AuthSideFlag side, uint8_t *recvData)
{
    AuthManager *auth = NULL;
    auth = AuthGetManagerByAuthId(authDataInfo->authId, side);
    if (auth == NULL && authDataInfo->type != DATA_TYPE_CLOSE_ACK) {
        if (authDataInfo->type == DATA_TYPE_DEVICE_ID && side == SERVER_SIDE_FLAG) {
            auth = CreateServerAuth(connectionId, authDataInfo);
            if (auth == NULL) {
                LOG_ERR("CreateServerAuth failed");
                return;
            }
        } else {
            LOG_ERR("cannot find auth");
            return;
        }
    }
    LOG_INFO("auth data type is %u", authDataInfo->type);
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
            LOG_ERR("unknown data type");
            break;
        }
    }
}

void AuthOnDataReceived(uint32_t connectionId, ConnModule moduleId, int64_t seq, char *data, int len)
{
    if (data == NULL || moduleId != MODULE_DEVICE_AUTH) {
        LOG_ERR("invalid parameter");
        return;
    }
    LOG_INFO("auth receive data, connectionId is %u, moduleId is %d, seq is %lld", connectionId, moduleId, seq);
    AuthDataInfo authDataInfo = {0};
    uint8_t *recvData = NULL;
    AuthSideFlag side;
    side = AuthGetSideByRemoteSeq(seq);
    if (AnalysisData(data, len, &authDataInfo) != SOFTBUS_OK) {
        LOG_ERR("AnalysisData failed");
        return;
    }
    recvData = (uint8_t *)data + sizeof(AuthDataInfo);
    HandleReceiveData(connectionId, &authDataInfo, side, recvData);
}

static void AuthOnSessionKeyReturned(int64_t authId, const uint8_t *sessionKey, uint32_t sessionKeyLen)
{
    if (sessionKey == NULL) {
        LOG_ERR("invalid parameter");
        return;
    }
    AuthManager *auth = NULL;
    auth = AuthGetManagerByAuthId(authId, false);
    if (auth == NULL) {
        auth = AuthGetManagerByAuthId(authId, true);
        if (auth == NULL) {
            LOG_ERR("no match auth found");
            return;
        }
    }
    LOG_INFO("auth get session key succ, authId is %lld", authId);
    NecessaryDevInfo devInfo = {0};
    if (AuthGetDeviceKey(devInfo.deviceKey, MAX_DEVICE_KEY_LEN, &devInfo.deviceKeyLen, &auth->option) != SOFTBUS_OK) {
        LOG_ERR("auth get device key failed");
        return;
    }
    if (pthread_mutex_lock(&g_authLock) != 0) {
        LOG_ERR("lock mutex failed");
        return;
    }
    devInfo.type = auth->option.type;
    devInfo.side = auth->side;
    devInfo.seq = (int32_t)((uint64_t)authId & LOW_32_BIT);
    AuthSetLocalSessionKey(&devInfo, auth->peerUdid, sessionKey, sessionKeyLen);
    auth->status = IN_SYNC_PROGRESS;
    (void)pthread_mutex_unlock(&g_authLock);
    auth->cb->onDeviceVerifyPass(authId, &auth->option, auth->peerVersion);
}

static void AuthOnError(int64_t authId, int operationCode, int errorCode, const char *errorReturn)
{
    (void)operationCode;
    if (errorReturn == NULL) {
        LOG_ERR("invalid parameter");
        return;
    }
    LOG_ERR("HiChain auth failed, errorCode is %d, errorReturn is %s", errorCode, errorReturn);
    AuthManager *auth = NULL;
    auth = AuthGetManagerByAuthId(authId, false);
    if (auth == NULL) {
        auth = AuthGetManagerByAuthId(authId, true);
        if (auth == NULL) {
            LOG_ERR("no match auth found, AuthPostData failed");
            return;
        }
    }
    HandleAuthFail(auth);
}

static char *AuthOnRequest(int64_t authReqId, int authForm, const char *reqParams)
{
    (void)authReqId;
    (void)authForm;
    (void)reqParams;
    return NULL;
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
        LOG_ERR("GetAuthByPeerUdid failed");
        return;
    }
    auth->cb->onDeviceNotTrusted(peerUdid);
}

static int32_t HichainServiceInit(void)
{
    if (InitDeviceAuthService() != 0) {
        LOG_ERR("auth InitDeviceAuthService failed");
        return SOFTBUS_ERR;
    }
    g_hichainGaInstance = GetGaInstance();
    if (g_hichainGaInstance == NULL) {
        LOG_ERR("auth GetGaInstance failed");
        return SOFTBUS_ERR;
    }
    g_hichainGmInstance = GetGmInstance();
    if (g_hichainGmInstance == NULL) {
        LOG_ERR("auth GetGmInstance failed");
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
        LOG_ERR("auth RegDataChangeListener failed");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static void AuthTimeout(SoftBusMessage *msg)
{
    if (msg == NULL) {
        LOG_ERR("invalid parameter");
        return;
    }
    LOG_ERR("auth process timeout, authId = %lld", (int64_t)(msg->arg1));
    AuthManager *auth = NULL;
    auth = AuthGetManagerByAuthId((int64_t)(msg->arg1), false);
    if (auth == NULL) {
        auth = AuthGetManagerByAuthId((int64_t)(msg->arg1), true);
        if (auth == NULL) {
            LOG_ERR("no match auth found");
            return;
        }
    }
    HandleAuthFail(auth);
}

int32_t AuthVerifyInit(void)
{
    if (HichainServiceInit() != SOFTBUS_OK) {
        LOG_ERR("HichainServiceInit failed");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t AuthVerifyDeinit(void)
{
    DestroyDeviceAuthService();
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
        LOG_ERR("SoftBusMalloc failed");
        return SOFTBUS_ERR;
    }
    (void)memset_s(g_verifyCallback, sizeof(VerifyCallback) * moduleNum, 0, sizeof(VerifyCallback) * moduleNum);
    return SOFTBUS_OK;
}

int32_t AuthRegCallback(AuthModuleId moduleId, VerifyCallback *cb)
{
    if (cb == NULL || cb->onDeviceVerifyPass == NULL || cb->onDeviceVerifyFail == NULL ||
        cb->onRecvSyncDeviceInfo == NULL || cb->onDeviceNotTrusted == NULL || moduleId >= MODULE_NUM) {
        LOG_ERR("invalid parameter");
        return SOFTBUS_INVALID_PARAM;
    }
    if (g_verifyCallback == NULL) {
        int32_t ret = AuthCallbackInit(MODULE_NUM);
        if (ret != SOFTBUS_OK) {
            LOG_ERR("AuthCallbackInit failed");
            return ret;
        }
    }
    g_verifyCallback[moduleId].onDeviceVerifyPass = cb->onDeviceVerifyPass;
    g_verifyCallback[moduleId].onDeviceVerifyFail = cb->onDeviceVerifyFail;
    g_verifyCallback[moduleId].onRecvSyncDeviceInfo = cb->onRecvSyncDeviceInfo;
    g_verifyCallback[moduleId].onDeviceNotTrusted = cb->onDeviceNotTrusted;
    return SOFTBUS_OK;
}

static int32_t RegisterConnCallback(ConnectCallback *connCb, ConnectResult *connResult)
{
    connCb->OnConnected = AuthOnConnected;
    connCb->OnDisconnected = AuthOnDisConnect;
    connCb->OnDataReceived = AuthOnDataReceived;
    if (ConnSetConnectCallback(MODULE_DEVICE_AUTH, connCb) != SOFTBUS_OK) {
        LOG_ERR("auth ConnSetConnectCallback failed");
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

int32_t AuthHandleLeaveLNN(int64_t authId)
{
    AuthManager *auth = NULL;
    auth = AuthGetManagerByAuthId(authId, false);
    if (auth == NULL) {
        auth = AuthGetManagerByAuthId(authId, true);
        if (auth == NULL) {
            LOG_ERR("no match auth found, AuthHandleLeaveLNN failed");
            return SOFTBUS_ERR;
        }
    }
    LOG_INFO("auth handle leave LNN, authId is %lld", authId);
    char deviceKey[MAX_DEVICE_KEY_LEN] = {0};
    uint32_t deviceKeyLen = 0;
    if (AuthGetDeviceKey(deviceKey, MAX_DEVICE_KEY_LEN, &deviceKeyLen, &auth->option) != SOFTBUS_OK) {
        LOG_ERR("get device key failed");
        return SOFTBUS_ERR;
    }
    if (pthread_mutex_lock(&g_authLock) != 0) {
        LOG_ERR("lock mutex failed");
        return SOFTBUS_ERR;
    }
    AuthClearSessionKeyByDeviceInfo(auth->option.type, deviceKey, deviceKeyLen);
    (void)pthread_mutex_unlock(&g_authLock);
    if (auth->option.type == CONNECT_TCP) {
        AuthCloseTcpFd(auth->fd);
    }
    DeleteAuth(auth);
    return SOFTBUS_OK;
}

int32_t AuthGetUuidByOption(const ConnectOption *option, char *buf, uint32_t bufLen)
{
    AuthManager *auth = NULL;
    ListNode *item = NULL;
    ListNode *tmp = NULL;
    LIST_FOR_EACH_SAFE(item, tmp, &g_authClientHead) {
        auth = LIST_ENTRY(item, AuthManager, node);
        if ((option->type == CONNECT_TCP && strncmp(auth->option.info.ipOption.ip, option->info.ipOption.ip,
            strlen(auth->option.info.ipOption.ip)) == 0) || (option->type == CONNECT_BR &&
            strncmp(auth->option.info.brOption.brMac, option->info.brOption.brMac, BT_MAC_LEN) == 0)) {
            if (memcpy_s(buf, bufLen, auth->peerUuid, strlen(auth->peerUuid)) != EOK) {
                LOG_ERR("memcpy_s failed");
                return SOFTBUS_ERR;
            }
            return SOFTBUS_OK;
        }
    }
    LIST_FOR_EACH_SAFE(item, tmp, &g_authServerHead) {
        auth = LIST_ENTRY(item, AuthManager, node);
        if ((option->type == CONNECT_TCP && strncmp(auth->option.info.ipOption.ip, option->info.ipOption.ip,
            strlen(auth->option.info.ipOption.ip)) == 0) || (option->type == CONNECT_BR &&
            strncmp(auth->option.info.brOption.brMac, option->info.brOption.brMac, BT_MAC_LEN) == 0)) {
            if (memcpy_s(buf, bufLen, auth->peerUuid, strlen(auth->peerUuid)) != EOK) {
                LOG_ERR("memcpy_s failed");
                return SOFTBUS_ERR;
            }
            return SOFTBUS_OK;
        }
    }
    LOG_ERR("auth get uuid by option failed");
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
    LOG_INFO("clear auth manager finish");
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
    ClearAuthManager();
    AuthClearAllSessionKey();
    pthread_mutex_destroy(&g_authLock);
    g_isAuthInit = false;
    LOG_INFO("auth deinit succ!");
    return SOFTBUS_OK;
}

int32_t AuthInit(void)
{
    if (g_isAuthInit == true) {
        return SOFTBUS_OK;
    }
    if (AuthCallbackInit(MODULE_NUM) != SOFTBUS_OK) {
        LOG_ERR("AuthCallbackInit failed");
        return SOFTBUS_ERR;
    }
    AuthListInit();
    if (RegisterConnCallback(&g_connCallback, &g_connResult) != SOFTBUS_OK) {
        LOG_ERR("RegisterConnCallback failed");
        (void)AuthDeinit();
        return SOFTBUS_ERR;
    }
    AuthLooperInit();
    UniqueIdInit();
    if (pthread_mutex_init(&g_authLock, NULL) != 0) {
        LOG_ERR("mutex init fail!");
        (void)AuthDeinit();
        return SOFTBUS_ERR;
    }
    g_isAuthInit = true;
    LOG_INFO("auth init succ!");
    return SOFTBUS_OK;
}

#ifdef __cplusplus
}
#endif
