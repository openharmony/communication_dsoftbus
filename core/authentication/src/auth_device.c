/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "auth_device.h"

#include <securec.h>
#include "anonymizer.h"
#include "auth_connection.h"
#include "auth_deviceprofile.h"
#include "auth_hichain.h"
#include "auth_log.h"
#include "auth_request.h"
#include "auth_session_message.h"
#include "bus_center_manager.h"
#include "device_profile_listener.h"
#include "lnn_app_bind_interface.h"
#include "lnn_decision_db.h"
#include "lnn_heartbeat_ctrl.h"
#include "lnn_local_net_ledger.h"
#include "lnn_ohos_account_adapter.h"
#include "lnn_map.h"
#include "lnn_net_builder.h"
#include "legacy/softbus_adapter_hitrace.h"
#include "softbus_adapter_mem.h"

#define DELAY_AUTH_TIME                    (8 * 1000L)

static AuthVerifyListener g_verifyListener = { 0 };
static GroupChangeListener g_groupChangeListener = { 0 };
static Map g_authLimitMap;
static SoftBusMutex g_authLimitMutex;
static bool g_isInit = false;
static bool g_regDataChangeListener = false;

static bool AuthMapInit(void)
{
    if (SoftBusMutexInit(&g_authLimitMutex, NULL) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "g_authLimit mutex init fail");
        return false;
    }
    LnnMapInit(&g_authLimitMap);
    g_isInit = true;
    AUTH_LOGI(AUTH_FSM, "authLimit map init success");
    return true;
}

static void InsertToAuthLimitMap(const char *udidHash, uint64_t currentTime)
{
    if (SoftBusMutexLock(&g_authLimitMutex) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "SoftBusMutexLock fail");
        return;
    }
    if (LnnMapSet(&g_authLimitMap, udidHash, (const void *)&currentTime, sizeof(uint64_t)) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "LnnMapSet fail");
        (void)SoftBusMutexUnlock(&g_authLimitMutex);
        return;
    }
    (void)SoftBusMutexUnlock(&g_authLimitMutex);
}

static int32_t GetNodeFromAuthLimitMap(const char *udidHash, uint64_t *time)
{
    if (!g_isInit) {
        return SOFTBUS_OK;
    }
    if (SoftBusMutexLock(&g_authLimitMutex) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "SoftBusMutexLock fail");
        return SOFTBUS_LOCK_ERR;
    }
    uint64_t *ptr = (uint64_t *)LnnMapGet(&g_authLimitMap, udidHash);
    if (ptr == NULL) {
        AUTH_LOGE(AUTH_FSM, "LnnMapGet fail");
        (void)SoftBusMutexUnlock(&g_authLimitMutex);
        return SOFTBUS_INVALID_PARAM;
    }
    *time = *ptr;
    (void)SoftBusMutexUnlock(&g_authLimitMutex);
    return SOFTBUS_OK;
}

bool IsNeedAuthLimit(const char *udidHash)
{
    if (udidHash == NULL) {
        AUTH_LOGE(AUTH_FSM, "invalid param");
        return false;
    }
    uint64_t time = 0;
    uint64_t currentTime = 0;
    if (GetNodeFromAuthLimitMap(udidHash, &time) != SOFTBUS_OK) {
        return false;
    }
    if (time == 0) {
        AUTH_LOGI(AUTH_FSM, "no need delay authentication");
        return false;
    }
    currentTime = GetCurrentTimeMs();
    AUTH_LOGI(AUTH_FSM, "currentTime=%{public}" PRIu64 ", time=%{public}" PRIu64 "", currentTime, time);
    if (currentTime - time < DELAY_AUTH_TIME) {
        AUTH_LOGI(AUTH_FSM, "lastest retcode authentication time less than 8s");
        return true;
    }
    return false;
}

void AuthDeleteLimitMap(const char *udidHash)
{
    if (!g_isInit || udidHash == NULL) {
        return;
    }
    if (SoftBusMutexLock(&g_authLimitMutex) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "SoftBusMutexLock fail");
        return;
    }
    int32_t ret = LnnMapErase(&g_authLimitMap, udidHash);
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "delete item fail, ret=%{public}d", ret);
        (void)SoftBusMutexUnlock(&g_authLimitMutex);
        return;
    }
    (void)SoftBusMutexUnlock(&g_authLimitMutex);
}

void ClearAuthLimitMap(void)
{
    if (!g_isInit) {
        return;
    }
    if (SoftBusMutexLock(&g_authLimitMutex) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "SoftBusMutexLock fail");
        return;
    }
    LnnMapDelete(&g_authLimitMap);
    AUTH_LOGI(AUTH_FSM, "ClearAuthLimitMap success");
    (void)SoftBusMutexUnlock(&g_authLimitMutex);
}

void AuthAddNodeToLimitMap(const char *udid, int32_t reason)
{
    AUTH_CHECK_AND_RETURN_LOGE(udid != NULL, AUTH_FSM, "udid is null");

    if (reason == SOFTBUS_AUTH_HICHAIN_LOCAL_IDENTITY_NOT_EXIST || reason == SOFTBUS_AUTH_HICHAIN_GROUP_NOT_EXIST ||
        reason == SOFTBUS_AUTH_HICHAIN_NO_CANDIDATE_GROUP) {
        uint64_t currentTime = GetCurrentTimeMs();
        AUTH_LOGI(AUTH_FSM, "reason=%{public}d, currentTime=%{public}" PRIu64 "", reason, currentTime);

        uint8_t hash[SHA_256_HASH_LEN] = { 0 };
        char udidHash[SHORT_UDID_HASH_HEX_LEN + 1] = { 0 };
        if (SoftBusGenerateStrHash((uint8_t *)udid, strlen(udid), hash) != SOFTBUS_OK) {
            AUTH_LOGE(AUTH_FSM, "GenerateUdidShortHash fail.");
            return;
        }
        if (ConvertBytesToUpperCaseHexString(udidHash, SHORT_UDID_HASH_HEX_LEN + 1, hash, UDID_SHORT_HASH_LEN_TEMP) !=
            SOFTBUS_OK) {
            AUTH_LOGE(AUTH_FSM, "convert bytes to string fail");
            return;
        }
        if (!g_isInit && !AuthMapInit()) {
            return;
        }
        InsertToAuthLimitMap(udidHash, currentTime);
    }
}

int32_t AuthDevicePostTransData(AuthHandle authHandle, const AuthTransData *dataInfo)
{
    if (dataInfo == NULL) {
        AUTH_LOGE(AUTH_CONN, "dataInfo is null");
        return SOFTBUS_INVALID_PARAM;
    }
    if (authHandle.type < AUTH_LINK_TYPE_WIFI || authHandle.type >= AUTH_LINK_TYPE_MAX) {
        AUTH_LOGE(AUTH_CONN, "authHandle type error");
        return SOFTBUS_INVALID_PARAM;
    }
    AuthManager *auth = GetAuthManagerByAuthId(authHandle.authId);
    if (auth == NULL) {
        return SOFTBUS_AUTH_NOT_FOUND;
    }
    AuthDataHead head;
    head.dataType = DATA_TYPE_CONNECTION;
    head.module = dataInfo->module;
    head.seq = dataInfo->seq;
    head.flag = dataInfo->flag;
    head.len = 0;
    uint8_t *encData = NULL;
    InDataInfo inDataInfo = { .inData = dataInfo->data, .inLen = dataInfo->len };
    if (EncryptInner(&auth->sessionKeyList, (AuthLinkType)authHandle.type, &inDataInfo, &encData,
        &head.len) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_KEY, "encrypt trans data fail");
        DelDupAuthManager(auth);
        return SOFTBUS_ENCRYPT_ERR;
    }
    if (PostAuthData(auth->connId[authHandle.type], !auth->isServer, &head, encData) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "post trans data fail");
        SoftBusFree(encData);
        DelDupAuthManager(auth);
        return SOFTBUS_AUTH_SEND_FAIL;
    }
    SoftBusFree(encData);
    DelDupAuthManager(auth);
    return SOFTBUS_OK;
}

int32_t AuthDeviceEncrypt(AuthHandle *authHandle, const uint8_t *inData, uint32_t inLen, uint8_t *outData,
    uint32_t *outLen)
{
    if (authHandle == NULL || inData == NULL || inLen == 0 || outData == NULL || outLen == NULL ||
        *outLen < (inLen + ENCRYPT_OVER_HEAD_LEN)) {
        AUTH_LOGE(AUTH_KEY, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    AuthManager *auth = GetAuthManagerByAuthId(authHandle->authId);
    if (auth == NULL) {
        return SOFTBUS_AUTH_NOT_FOUND;
    }
    InDataInfo inDataInfo = { .inData = inData, .inLen = inLen };
    if (EncryptData(&auth->sessionKeyList, (AuthLinkType)authHandle->type, &inDataInfo, outData,
        outLen) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_KEY, "auth encrypt fail");
        DelDupAuthManager(auth);
        return SOFTBUS_ENCRYPT_ERR;
    }
    DelDupAuthManager(auth);
    return SOFTBUS_OK;
}

int32_t AuthDeviceDecrypt(AuthHandle *authHandle, const uint8_t *inData, uint32_t inLen, uint8_t *outData,
    uint32_t *outLen)
{
    if (authHandle == NULL || inData == NULL || inLen == 0 || outData == NULL || outLen == NULL ||
        *outLen < AuthGetDecryptSize(inLen)) {
        AUTH_LOGE(AUTH_KEY, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    AuthManager *auth = GetAuthManagerByAuthId(authHandle->authId);
    if (auth == NULL) {
        return SOFTBUS_AUTH_NOT_FOUND;
    }
    InDataInfo inDataInfo = { .inData = inData, .inLen = inLen };
    if (DecryptData(&auth->sessionKeyList, (AuthLinkType)authHandle->type, &inDataInfo, outData,
        outLen) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_KEY, "auth decrypt fail, authId=%{public}" PRId64, authHandle->authId);
        DelDupAuthManager(auth);
        return SOFTBUS_ENCRYPT_ERR;
    }
    DelDupAuthManager(auth);
    return SOFTBUS_OK;
}

int32_t AuthDeviceGetConnInfo(AuthHandle authHandle, AuthConnInfo *connInfo)
{
    if (connInfo == NULL) {
        AUTH_LOGE(AUTH_CONN, "connInfo is null");
        return SOFTBUS_INVALID_PARAM;
    }
    if (authHandle.type < AUTH_LINK_TYPE_WIFI || authHandle.type >= AUTH_LINK_TYPE_MAX) {
        AUTH_LOGE(AUTH_CONN, "authHandle type error");
        return SOFTBUS_INVALID_PARAM;
    }
    AuthManager *auth = GetAuthManagerByAuthId(authHandle.authId);
    if (auth == NULL) {
        return SOFTBUS_AUTH_NOT_FOUND;
    }
    *connInfo = auth->connInfo[authHandle.type];
    DelDupAuthManager(auth);
    return SOFTBUS_OK;
}

int32_t AuthDeviceGetServerSide(int64_t authId, bool *isServer)
{
    if (isServer == NULL) {
        AUTH_LOGE(AUTH_CONN, "isServer is null");
        return SOFTBUS_INVALID_PARAM;
    }
    AuthManager *auth = GetAuthManagerByAuthId(authId);
    if (auth == NULL) {
        return SOFTBUS_AUTH_NOT_FOUND;
    }
    *isServer = auth->isServer;
    DelDupAuthManager(auth);
    return SOFTBUS_OK;
}

int32_t AuthDeviceGetDeviceUuid(int64_t authId, char *uuid, uint16_t size)
{
    if (uuid == NULL) {
        AUTH_LOGE(AUTH_CONN, "uuid is empty");
        return SOFTBUS_INVALID_PARAM;
    }
    AuthManager *auth = GetAuthManagerByAuthId(authId);
    if (auth == NULL) {
        return SOFTBUS_AUTH_NOT_FOUND;
    }
    if (strcpy_s(uuid, size, auth->uuid) != EOK) {
        AUTH_LOGI(AUTH_CONN, "copy uuid fail, size=%{public}u", size);
        DelDupAuthManager(auth);
        return SOFTBUS_STRCPY_ERR;
    }
    DelDupAuthManager(auth);
    return SOFTBUS_OK;
}

int32_t AuthDeviceGetVersion(int64_t authId, SoftBusVersion *version)
{
    if (version == NULL) {
        AUTH_LOGE(AUTH_CONN, "version is null");
        return SOFTBUS_INVALID_PARAM;
    }
    AuthManager *auth = GetAuthManagerByAuthId(authId);
    if (auth == NULL) {
        return SOFTBUS_AUTH_NOT_FOUND;
    }
    *version = auth->version;
    DelDupAuthManager(auth);
    return SOFTBUS_OK;
}

void AuthDeviceNotTrust(const char *peerUdid)
{
    if (peerUdid == NULL || strlen(peerUdid) == 0) {
        AUTH_LOGE(AUTH_HICHAIN, "invalid param");
        return;
    }
    char networkId[NETWORK_ID_BUF_LEN] = {0};
    if (LnnGetNetworkIdByUdid(peerUdid, networkId, sizeof(networkId)) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_HICHAIN, "get networkId by udid fail");
        return;
    }
    RemoveNotPassedAuthManagerByUdid(peerUdid);
    AuthSessionHandleDeviceNotTrusted(peerUdid);
    LnnDeleteSpecificTrustedDevInfo(peerUdid, GetActiveOsAccountIds());
    LnnHbOnTrustedRelationReduced();
    AuthRemoveDeviceKeyByUdid(peerUdid);
    if (LnnRequestLeaveSpecific(networkId, CONNECTION_ADDR_MAX) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_HICHAIN, "request leave specific fail");
    } else {
        AUTH_LOGI(AUTH_HICHAIN, "request leave specific successful");
    }
}

void AuthNotifyDeviceVerifyPassed(AuthHandle authHandle, const NodeInfo *nodeInfo)
{
    CHECK_NULL_PTR_RETURN_VOID(nodeInfo);
    AuthManager *auth = GetAuthManagerByAuthId(authHandle.authId);
    if (auth == NULL) {
        AUTH_LOGE(AUTH_FSM, "get auth manager failed");
        return;
    }
    if (auth->connInfo[authHandle.type].type == AUTH_LINK_TYPE_P2P) {
        /* P2P auth no need notify to LNN. */
        DelDupAuthManager(auth);
        return;
    }
    DelDupAuthManager(auth);

    /* notify LNN device verify pass. */
    if (g_verifyListener.onDeviceVerifyPass == NULL) {
        AUTH_LOGW(AUTH_FSM, "onDeviceVerifyPass not set");
        return;
    }
    g_verifyListener.onDeviceVerifyPass(authHandle, nodeInfo);
}

void AuthNotifyDeviceDisconnect(AuthHandle authHandle)
{
    if (g_verifyListener.onDeviceDisconnect == NULL) {
        AUTH_LOGW(AUTH_FSM, "onDeviceDisconnect not set");
        return;
    }
    g_verifyListener.onDeviceDisconnect(authHandle);
}

static void OnDeviceNotTrusted(const char *peerUdid, int32_t localUserId)
{
    RemoveNotPassedAuthManagerByUdid(peerUdid);
    AuthSessionHandleDeviceNotTrusted(peerUdid);
    if (!DpHasAccessControlProfile(peerUdid, false, localUserId)) {
        LnnDeleteLinkFinderInfo(peerUdid);
    }
    if (!DpHasAccessControlProfile(peerUdid, true, localUserId)) {
        LnnDeleteSpecificTrustedDevInfo(peerUdid, localUserId);
    }
    if (g_verifyListener.onDeviceNotTrusted == NULL) {
        AUTH_LOGW(AUTH_HICHAIN, "onDeviceNotTrusted not set");
        return;
    }
    g_verifyListener.onDeviceNotTrusted(peerUdid);
    LnnHbOnTrustedRelationReduced();
    AuthRemoveDeviceKeyByUdid(peerUdid);
}

int32_t RegAuthVerifyListener(const AuthVerifyListener *listener)
{
    if (listener == NULL) {
        AUTH_LOGE(AUTH_CONN, "invalid listener");
        return SOFTBUS_INVALID_PARAM;
    }
    g_verifyListener = *listener;
    return SOFTBUS_OK;
}

void UnregAuthVerifyListener(void)
{
    (void)memset_s(&g_verifyListener, sizeof(AuthVerifyListener), 0, sizeof(AuthVerifyListener));
}

static void OnGroupCreated(const char *groupId, int32_t groupType)
{
    if (g_groupChangeListener.onGroupCreated != NULL) {
        g_groupChangeListener.onGroupCreated(groupId, groupType);
    }
}

static void OnGroupDeleted(const char *groupId, int32_t groupType)
{
    if (g_groupChangeListener.onGroupDeleted != NULL) {
        g_groupChangeListener.onGroupDeleted(groupId, groupType);
    }
}

static void OnDeviceBound(const char *udid, const char *groupInfo)
{
    LnnInsertSpecificTrustedDevInfo(udid);
    if (g_groupChangeListener.onDeviceBound != NULL) {
        g_groupChangeListener.onDeviceBound(udid, groupInfo);
    }
}

static int32_t RetryRegTrustDataChangeListener()
{
    TrustDataChangeListener trustListener = {
        .onGroupCreated = OnGroupCreated,
        .onGroupDeleted = OnGroupDeleted,
        .onDeviceNotTrusted = OnDeviceNotTrusted,
        .onDeviceBound = OnDeviceBound,
    };
    for (int32_t i = 1; i <= RETRY_REGDATA_TIMES; i++) {
        int32_t ret = RegTrustDataChangeListener(&trustListener);
        if (ret == SOFTBUS_OK) {
            AUTH_LOGI(AUTH_HICHAIN, "regDataChangeListener success, times=%{public}d", i);
            return SOFTBUS_OK;
        }
        AUTH_LOGW(AUTH_HICHAIN, "retry regDataChangeListener, current retry times=%{public}d, err=%{public}d", i, ret);
        (void)SoftBusSleepMs(RETRY_REGDATA_MILLSECONDS);
    }
    return SOFTBUS_AUTH_REG_DATA_FAIL;
}

int32_t RegTrustListenerOnHichainSaStart(void)
{
    TrustDataChangeListener trustListener = {
        .onGroupCreated = OnGroupCreated,
        .onGroupDeleted = OnGroupDeleted,
        .onDeviceNotTrusted = OnDeviceNotTrusted,
        .onDeviceBound = OnDeviceBound,
    };
    if (RegTrustDataChangeListener(&trustListener) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_INIT, "RegTrustDataChangeListener fail");
        g_regDataChangeListener = false;
        return SOFTBUS_AUTH_INIT_FAIL;
    }
    g_regDataChangeListener = true;
    AUTH_LOGE(AUTH_INIT, "OnHichainSaStart add listener succ");
    return SOFTBUS_OK;
}

int32_t RegGroupChangeListener(const GroupChangeListener *listener)
{
    if (listener == NULL) {
        AUTH_LOGE(AUTH_CONN, "listener is null");
        return SOFTBUS_INVALID_PARAM;
    }
    g_groupChangeListener.onGroupCreated = listener->onGroupCreated;
    g_groupChangeListener.onGroupDeleted = listener->onGroupDeleted;
    g_groupChangeListener.onDeviceBound = listener->onDeviceBound;
    return SOFTBUS_OK;
}

void UnregGroupChangeListener(void)
{
    g_groupChangeListener.onGroupCreated = NULL;
    g_groupChangeListener.onGroupDeleted = NULL;
    g_groupChangeListener.onDeviceBound = NULL;
}

void AuthRegisterToDpDelay(void *para)
{
    DeviceProfileChangeListener deviceProfileChangeListener = {
        .onDeviceProfileAdd = OnDeviceBound,
        .onDeviceProfileDeleted = OnDeviceNotTrusted,
    };
    RegisterToDp(&deviceProfileChangeListener);
}

int32_t AuthDirectOnlineCreateAuthManager(int64_t authSeq, const AuthSessionInfo *info)
{
    AUTH_CHECK_AND_RETURN_RET_LOGE(info, SOFTBUS_INVALID_PARAM, AUTH_FSM, "info is null");
    AUTH_CHECK_AND_RETURN_RET_LOGE(CheckAuthConnInfoType(&info->connInfo), SOFTBUS_INVALID_PARAM,
        AUTH_FSM, "connInfo type error");
    AUTH_LOGI(AUTH_FSM, "direct online authSeq=%{public}" PRId64 ", side=%{public}s, requestId=%{public}u",
        authSeq, GetAuthSideStr(info->isServer), info->requestId);
    if (!RequireAuthLock()) {
        return SOFTBUS_LOCK_ERR;
    }
    if (info->connInfo.type != AUTH_LINK_TYPE_BLE) {
        AUTH_LOGE(AUTH_FSM, "sessionkey online only support ble");
        ReleaseAuthLock();
        return SOFTBUS_AUTH_UNEXPECTED_CONN_TYPE;
    }

    bool isNewCreated = false;
    AuthManager *auth = GetDeviceAuthManager(authSeq, info, &isNewCreated, authSeq);
    if (auth == NULL) {
        AUTH_LOGE(AUTH_FSM, "auth manager does not exist.");
        ReleaseAuthLock();
        return SOFTBUS_AUTH_NOT_FOUND;
    }
    auth->hasAuthPassed[info->connInfo.type] = true;
    AUTH_LOGI(AUTH_FSM,
        "auth manager without sessionkey. isNewCreated=%{public}d, authId=%{public}" PRId64 ", authSeq=%{public}" PRId64
        ", lastVerifyTime=%{public}" PRId64,
        isNewCreated, auth->authId, authSeq, auth->lastVerifyTime);
    ReleaseAuthLock();
    return SOFTBUS_OK;
}

static int32_t VerifyDevice(AuthRequest *request)
{
    int64_t traceId = GenSeq(false);
    request->traceId = traceId;
    SoftbusHitraceStart(SOFTBUS_HITRACE_ID_VALID, (uint64_t)traceId);
    AUTH_LOGI(AUTH_CONN, "start verify device: requestId=%{public}u", request->requestId);
    if (!g_regDataChangeListener) {
        if (RetryRegTrustDataChangeListener() != SOFTBUS_OK) {
            AUTH_LOGE(AUTH_HICHAIN, "hichain regDataChangeListener failed");
            SoftbusHitraceStop();
            return SOFTBUS_AUTH_INIT_FAIL;
        }
        g_regDataChangeListener = true;
    }
    uint32_t waitNum = AddAuthRequest(request);
    if (waitNum == 0) {
        AUTH_LOGE(AUTH_CONN, "add verify request to list fail, requestId=%{public}u", request->requestId);
        SoftbusHitraceStop();
        return SOFTBUS_AUTH_INNER_ERR;
    }
    if (waitNum > 1) {
        AUTH_LOGI(
            AUTH_CONN, "wait last verify request complete, waitNum=%{public}u, requestId=%{public}u",
            waitNum, request->requestId);
        SoftbusHitraceStop();
        return SOFTBUS_OK;
    }
    if (ConnectAuthDevice(request->requestId, &request->connInfo, CONN_SIDE_ANY) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "connect auth device failed: requestId=%{public}u", request->requestId);
        FindAndDelAuthRequestByConnInfo(request->requestId, &request->connInfo);
        SoftbusHitraceStop();
        return SOFTBUS_AUTH_CONN_FAIL;
    }
    SoftbusHitraceStop();
    AUTH_LOGI(AUTH_CONN, "verify device succ. requestId=%{public}u", request->requestId);
    return SOFTBUS_OK;
}

static int32_t StartConnVerifyDevice(uint32_t requestId, const AuthConnInfo *connInfo, const AuthConnCallback *connCb,
    AuthVerifyModule module, bool isFastAuth)
{
    if (connInfo == NULL || connCb == NULL) {
        AUTH_LOGE(AUTH_CONN, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    AuthRequest request;
    (void)memset_s(&request, sizeof(AuthRequest), 0, sizeof(AuthRequest));
    request.connCb = *connCb;
    request.module = module;
    request.requestId = requestId;
    request.connInfo = *connInfo;
    request.authId = AUTH_INVALID_ID;
    request.type = REQUEST_TYPE_VERIFY;
    request.isFastAuth = isFastAuth;
    return VerifyDevice(&request);
}

static int32_t StartVerifyDevice(uint32_t requestId, const AuthConnInfo *connInfo, const AuthVerifyCallback *verifyCb,
    AuthVerifyModule module, bool isFastAuth)
{
    if (connInfo == NULL || verifyCb == NULL) {
        AUTH_LOGE(AUTH_CONN, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    AuthRequest request;
    (void)memset_s(&request, sizeof(AuthRequest), 0, sizeof(AuthRequest));
    request.verifyCb = *verifyCb;
    request.module = module;
    request.requestId = requestId;
    request.connInfo = *connInfo;
    request.authId = AUTH_INVALID_ID;
    request.type = REQUEST_TYPE_VERIFY;
    request.isFastAuth = isFastAuth;
    return VerifyDevice(&request);
}

int32_t AuthStartReconnectDevice(
    AuthHandle authHandle, const AuthConnInfo *connInfo, uint32_t requestId, const AuthConnCallback *connCb)
{
    AUTH_CHECK_AND_RETURN_RET_LOGE(connInfo != NULL, SOFTBUS_INVALID_PARAM, AUTH_CONN, "connInfo is NULL");
    AUTH_CHECK_AND_RETURN_RET_LOGE(connCb != NULL, SOFTBUS_INVALID_PARAM, AUTH_CONN, "connCb is NULL");
    AUTH_LOGI(AUTH_CONN, "start reconnect device. requestId=%{public}u, authId=%{public}" PRId64,
        requestId, authHandle.authId);
    AuthManager *auth = GetAuthManagerByAuthId(authHandle.authId);
    if (auth == NULL) {
        return SOFTBUS_AUTH_NOT_FOUND;
    }
    ConnSideType sideType = GetConnSideType(auth->connId[connInfo->type]);
    uint64_t connId = auth->connId[AUTH_LINK_TYPE_BR];
    DelDupAuthManager(auth);

    AuthRequest request;
    (void)memset_s(&request, sizeof(AuthRequest), 0, sizeof(AuthRequest));
    request.authId = authHandle.authId;
    request.connCb = *connCb;
    request.connInfo = *connInfo;
    request.requestId = requestId;
    request.type = REQUEST_TYPE_RECONNECT;
    request.isFastAuth = true;
    if (connInfo->type == AUTH_LINK_TYPE_BR) {
        request.connInfo.info.brInfo.connectionId = GetConnId(connId);
    }
    if (AddAuthRequest(&request) == 0) {
        AUTH_LOGE(AUTH_CONN, "add reconnect request fail, requestId=%{public}u", requestId);
        return SOFTBUS_AUTH_ADD_REQUEST_FAIL;
    }
    if (ConnectAuthDevice(requestId, &request.connInfo, sideType) != SOFTBUS_OK) {
        DelAuthRequest(requestId);
        return SOFTBUS_AUTH_CONN_FAIL;
    }
    return SOFTBUS_OK;
}

static bool AuthCheckSessionKey(AuthHandle *authHandle)
{
    AuthManager *auth = GetAuthManagerByAuthId(authHandle->authId);
    if (auth == NULL) {
        AUTH_LOGE(AUTH_CONN, "not found auth manager, authId=%{public}" PRId64, authHandle->authId);
        return false;
    }
    bool res = CheckSessionKeyListExistType(&auth->sessionKeyList, (AuthLinkType)authHandle->type);
    DelDupAuthManager(auth);
    return res;
}

int32_t AuthDeviceOpenConn(const AuthConnInfo *info, uint32_t requestId, const AuthConnCallback *callback)
{
    if (info == NULL || !CheckAuthConnCallback(callback)) {
        AUTH_LOGE(AUTH_CONN, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    AUTH_CHECK_AND_RETURN_RET_LOGE(CheckAuthConnInfoType(info), SOFTBUS_INVALID_PARAM,
        AUTH_FSM, "connInfo type error");
    AUTH_LOGI(AUTH_CONN, "open auth conn: connType=%{public}d, requestId=%{public}u", info->type, requestId);
    AuthHandle authHandle = { .authId = AUTH_INVALID_ID, .type = info->type };
    bool judgeTimeOut = false;
    switch (info->type) {
        case AUTH_LINK_TYPE_WIFI:
            authHandle.authId = GetLatestIdByConnInfo(info);
            if (authHandle.authId == AUTH_INVALID_ID) {
                return SOFTBUS_AUTH_NOT_FOUND;
            }
            callback->onConnOpened(requestId, authHandle);
            break;
        case AUTH_LINK_TYPE_BR:
            /* fall-through */
        case AUTH_LINK_TYPE_BLE:
            judgeTimeOut = true;
            authHandle.authId = GetActiveAuthIdByConnInfo(info, judgeTimeOut);
            if (authHandle.authId != AUTH_INVALID_ID && AuthCheckSessionKey(&authHandle)) {
                return AuthStartReconnectDevice(authHandle, info, requestId, callback);
            }
            return StartConnVerifyDevice(requestId, info, callback, AUTH_MODULE_LNN, true);
        case AUTH_LINK_TYPE_P2P:
        case AUTH_LINK_TYPE_ENHANCED_P2P:
            authHandle.authId = GetActiveAuthIdByConnInfo(info, judgeTimeOut);
            if (authHandle.authId != AUTH_INVALID_ID) {
                AUTH_LOGI(AUTH_CONN, "reuse type=%{public}d, authId=%{public}" PRId64, info->type, authHandle.authId);
                callback->onConnOpened(requestId, authHandle);
                break;
            }
            return StartConnVerifyDevice(requestId, info, callback, AUTH_MODULE_LNN, true);
        default:
            AUTH_LOGE(AUTH_CONN, "unknown connType. type=%{public}d", info->type);
            return SOFTBUS_INVALID_PARAM;
    }
    return SOFTBUS_OK;
}

void AuthDeviceCloseConn(AuthHandle authHandle)
{
    AUTH_LOGI(AUTH_CONN, "close auth conn: authId=%{public}" PRId64, authHandle.authId);
    if (authHandle.type < AUTH_LINK_TYPE_WIFI || authHandle.type >= AUTH_LINK_TYPE_MAX) {
        AUTH_LOGE(AUTH_CONN, "authHandle type error");
        return;
    }
    AuthManager *auth = GetAuthManagerByAuthId(authHandle.authId);
    if (auth == NULL) {
        return;
    }
    switch (auth->connInfo[authHandle.type].type) {
        case AUTH_LINK_TYPE_WIFI:
        case AUTH_LINK_TYPE_P2P:
        case AUTH_LINK_TYPE_ENHANCED_P2P:
            /* Do nothing. */
            break;
        case AUTH_LINK_TYPE_BR:
        case AUTH_LINK_TYPE_BLE:
            DisconnectAuthDevice(&auth->connId[authHandle.type]);
            break;
        default:
            break;
    }
    DelDupAuthManager(auth);
    return;
}

int32_t AuthStartVerify(const AuthConnInfo *connInfo, uint32_t requestId, const AuthVerifyCallback *callback,
    AuthVerifyModule module, bool isFastAuth)
{
    if (connInfo == NULL || !CheckVerifyCallback(callback)) {
        AUTH_LOGE(AUTH_CONN, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    AUTH_CHECK_AND_RETURN_RET_LOGE(CheckAuthConnInfoType(connInfo), SOFTBUS_INVALID_PARAM,
        AUTH_FSM, "connInfo type error");
    return StartVerifyDevice(requestId, connInfo, callback, module, isFastAuth);
}

int32_t AuthStartConnVerify(const AuthConnInfo *connInfo, uint32_t requestId, const AuthConnCallback *connCallback,
    AuthVerifyModule module, bool isFastAuth)
{
    if (connInfo == NULL || !CheckAuthConnCallback(connCallback)) {
        AUTH_LOGE(AUTH_CONN, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    AUTH_CHECK_AND_RETURN_RET_LOGE(CheckAuthConnInfoType(connInfo), SOFTBUS_INVALID_PARAM,
        AUTH_FSM, "connInfo type error");
    return StartConnVerifyDevice(requestId, connInfo, connCallback, module, isFastAuth);
}
