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

#include "auth_manager.h"

#include <securec.h>

#include "auth_common.h"
#include "auth_connection.h"
#include "auth_hichain.h"
#include "auth_request.h"
#include "auth_session_fsm.h"
#include "auth_session_message.h"
#include "bus_center_manager.h"
#include "lnn_decision_db.h"
#include "softbus_adapter_mem.h"

#define MAX_AUTH_VALID_PERIOD (30 * 60 * 1000L) /* 30 mins */
#define SCHEDULE_UPDATE_SESSION_KEY_PERIOD ((5 * 60 + 30) * 60 * 1000L) /* 5 hour 30 mins */

static ListNode g_authClientList = { &g_authClientList, &g_authClientList };
static ListNode g_authServerList = { &g_authServerList, &g_authServerList };

static AuthVerifyListener g_verifyListener = {0};
static GroupChangeListener g_groupChangeListener = {0};
static AuthTransCallback g_transCallback = {0};
/* Auth Manager */
static AuthManager *NewAuthManager(int64_t authSeq, const AuthSessionInfo *info)
{
    AuthManager *auth = (AuthManager *)SoftBusMalloc(sizeof(AuthManager));
    if (auth == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_WARN, "malloc AuthManager fail.");
        return NULL;
    }
    auth->authId = authSeq;
    auth->isServer = info->isServer;
    auth->connId = info->connId;
    auth->connInfo = info->connInfo;
    if (strcpy_s(auth->udid, sizeof(auth->udid), info->udid) != EOK ||
        strcpy_s(auth->uuid, sizeof(auth->uuid), info->uuid) != EOK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_WARN, "copy uuid/udid fail.");
        SoftBusFree(auth);
        return NULL;
    }
    auth->version = info->version;
    auth->hasAuthPassed = false;
    InitSessionKeyList(&auth->sessionKeyList);
    if (auth->isServer) {
        ListTailInsert(&g_authServerList, &auth->node);
    } else {
        ListTailInsert(&g_authClientList, &auth->node);
    }
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO,
        "create auth manager, side=%s, authId=%" PRId64 ".", GetAuthSideStr(auth->isServer), auth->authId);
    return auth;
}

static AuthManager *DupAuthManager(const AuthManager *auth)
{
    AuthManager *newAuth = (AuthManager *)DupMemBuffer((const uint8_t *)auth, sizeof(AuthManager));
    if (newAuth == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR,
            "auth manager[%"PRId64"] dup fail", auth->authId);
        return NULL;
    }
    ListInit(&newAuth->node);
    ListInit(&newAuth->sessionKeyList);
    if (DupSessionKeyList(&auth->sessionKeyList, &newAuth->sessionKeyList)) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR,
            "auth manager[%"PRId64"] dup session key fail", auth->authId);
        SoftBusFree(newAuth);
        return NULL;
    }
    return newAuth;
}

void DelAuthManager(AuthManager *auth, bool removeAuthFromList)
{
    CHECK_NULL_PTR_RETURN_VOID(auth);
    if (removeAuthFromList) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO,
            "delete auth manager, side=%s, authId=%" PRId64 ".", GetAuthSideStr(auth->isServer), auth->authId);
        ListDelete(&auth->node);
    }
    DestroySessionKeyList(&auth->sessionKeyList);
    SoftBusFree(auth);
}

static AuthManager *FindAuthManagerByConnInfo(const AuthConnInfo *connInfo, bool isServer)
{
    AuthManager *item = NULL;
    ListNode *list = isServer ? &g_authServerList : &g_authClientList;
    LIST_FOR_EACH_ENTRY(item, list, AuthManager, node) {
        if (CompareConnInfo(&item->connInfo, connInfo)) {
            return item;
        }
    }
    return NULL;
}

static AuthManager *FindAuthManagerByUuid(const char *uuid, AuthLinkType type, bool isServer)
{
    AuthManager *item = NULL;
    ListNode *list = isServer ? &g_authServerList : &g_authClientList;
    LIST_FOR_EACH_ENTRY(item, list, AuthManager, node) {
        if (item->connInfo.type == type && (strcmp(item->uuid, uuid) == 0)) {
            return item;
        }
    }
    return NULL;
}

static AuthManager *FindAuthManagerByP2pMac(const char *p2pMac, AuthLinkType type, bool isServer)
{
    AuthManager *item = NULL;
    ListNode *list = isServer ? &g_authServerList : &g_authClientList;
    LIST_FOR_EACH_ENTRY(item, list, AuthManager, node) {
        if (item->connInfo.type == type &&
            (StrCmpIgnoreCase(item->p2pMac, p2pMac) == 0)) {
            return item;
        }
    }
    return NULL;
}

static AuthManager *FindAuthManagerByAuthId(int64_t authId)
{
    AuthManager *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_authClientList, AuthManager, node) {
        if (item->authId == authId) {
            return item;
        }
    }
    LIST_FOR_EACH_ENTRY(item, &g_authServerList, AuthManager, node) {
        if (item->authId == authId) {
            return item;
        }
    }
    return NULL;
}

static AuthManager *FindAuthManagerByConnId(uint64_t connId, bool isServer)
{
    AuthManager *item = NULL;
    ListNode *list = isServer ? &g_authServerList : &g_authClientList;
    LIST_FOR_EACH_ENTRY(item, list, AuthManager, node) {
        if (item->connId == connId) {
            return item;
        }
    }
    return NULL;
}

static void DestroyAuthManagerList(void)
{
    if (!RequireAuthLock()) {
        return;
    }
    AuthManager *item = NULL;
    AuthManager *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_authClientList, AuthManager, node) {
        DelAuthManager(item, true);
    }
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_authServerList, AuthManager, node) {
        DelAuthManager(item, true);
    }
    ReleaseAuthLock();
}

static int32_t SetAuthConnId(AuthManager *auth, const AuthManager *inAuth)
{
    auth->connId = inAuth->connId;
    return SOFTBUS_OK;
}

static int32_t SetAuthP2pMac(AuthManager *auth, const AuthManager *inAuth)
{
    if (strcpy_s(auth->p2pMac, sizeof(auth->p2pMac), inAuth->p2pMac) != EOK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR,
            "copy auth p2p mac fail, authId=%" PRId64, auth->authId);
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t UpdateAuthManagerByAuthId(int64_t authId,
    int32_t (*updateFunc)(AuthManager *, const AuthManager *), const AuthManager *inAuth)
{
    if (!RequireAuthLock()) {
        return SOFTBUS_LOCK_ERR;
    }
    AuthManager *auth = FindAuthManagerByAuthId(authId);
    if (auth == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR,
            "auth manager not found, authId=%" PRId64, authId);
        ReleaseAuthLock();
        return SOFTBUS_AUTH_NOT_FOUND;
    }
    if (updateFunc(auth, inAuth) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR,
            "update auth manager fail, authId=%" PRId64, authId);
        ReleaseAuthLock();
        return SOFTBUS_ERR;
    }
    ReleaseAuthLock();
    return SOFTBUS_OK;
}

static void RemoveAuthManagerByAuthId(int64_t authId)
{
    if (!RequireAuthLock()) {
        return;
    }
    AuthManager *auth = FindAuthManagerByAuthId(authId);
    if (auth == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO,
            "auth manager already removed, authId=%" PRId64, authId);
        ReleaseAuthLock();
        return;
    }
    DelAuthManager(auth, true);
    ReleaseAuthLock();
}

static void RemoveAuthManagerByConnInfo(const AuthConnInfo *connInfo, bool isServer)
{
    if (!RequireAuthLock()) {
        return;
    }
    AuthManager *auth = FindAuthManagerByConnInfo(connInfo, isServer);
    if (auth == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO,
            "auth manager already removed, connType=%d, side=%s", connInfo->type, GetAuthSideStr(isServer));
        ReleaseAuthLock();
        return;
    }
    DelAuthManager(auth, true);
    ReleaseAuthLock();
}

static void RemoveNotPassedAuthManagerByUdid(const char *udid)
{
    if (!RequireAuthLock()) {
        return;
    }
    AuthManager *item = NULL;
    AuthManager *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_authClientList, AuthManager, node) {
        if (item->hasAuthPassed || strcmp(item->udid, udid) != 0) {
            continue;
        }
        DelAuthManager(item, true);
    }
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_authServerList, AuthManager, node) {
        if (item->hasAuthPassed || strcmp(item->udid, udid) != 0) {
            continue;
        }
        DelAuthManager(item, true);
    }
    ReleaseAuthLock();
}

static int32_t GetAuthConnInfoByUuid(const char *uuid, AuthLinkType type, AuthConnInfo *connInfo)
{
    if (!RequireAuthLock()) {
        return SOFTBUS_LOCK_ERR;
    }
    AuthManager *auth = FindAuthManagerByUuid(uuid, type, false);
    if (auth == NULL) {
        auth = FindAuthManagerByUuid(uuid, type, true);
    }
    if (auth == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "auth not found by uuid, connType=%d.", type);
        ReleaseAuthLock();
        return SOFTBUS_ERR;
    }
    *connInfo = auth->connInfo;
    ReleaseAuthLock();
    return SOFTBUS_OK;
}

/* Note: must call DelAuthManager(auth, false) to free. */
AuthManager *GetAuthManagerByAuthId(int64_t authId)
{
    if (!RequireAuthLock()) {
        return NULL;
    }
    AuthManager *item = FindAuthManagerByAuthId(authId);
    if (item == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO,
            "auth manager[%"PRId64"] not found", authId);
        ReleaseAuthLock();
        return NULL;
    }
    AuthManager *newAuth = DupAuthManager(item);
    ReleaseAuthLock();
    return newAuth;
}

static AuthManager *GetAuthManagerByConnInfo(const AuthConnInfo *connInfo, bool isServer)
{
    if (!RequireAuthLock()) {
        return NULL;
    }
    AuthManager *item = FindAuthManagerByConnInfo(connInfo, isServer);
    if (item == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO,
            "auth manager not found, connType=%d, side=%s", connInfo->type, GetAuthSideStr(isServer));
        ReleaseAuthLock();
        return NULL;
    }
    AuthManager *newAuth = DupAuthManager(item);
    ReleaseAuthLock();
    return newAuth;
}

static int64_t GetAuthIdByConnId(uint64_t connId, bool isServer)
{
    int64_t authId;
    if (!RequireAuthLock()) {
        return AUTH_INVALID_ID;
    }
    AuthManager *auth = FindAuthManagerByConnId(connId, isServer);
    if (auth == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_WARN,
            "auth manager[%s] not found, " CONN_INFO, GetAuthSideStr(isServer), CONN_DATA(connId));
        ReleaseAuthLock();
        return AUTH_INVALID_ID;
    }
    authId = auth->authId;
    ReleaseAuthLock();
    return authId;
}

static int64_t GetAuthIdByConnInfo(const AuthConnInfo *connInfo, bool isServer)
{
    int64_t authId;
    if (!RequireAuthLock()) {
        return AUTH_INVALID_ID;
    }
    AuthManager *auth = FindAuthManagerByConnInfo(connInfo, isServer);
    if (auth == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR,
            "auth manager not found, connType=%d, side=%s", connInfo->type, GetAuthSideStr(isServer));
        ReleaseAuthLock();
        return AUTH_INVALID_ID;
    }
    authId = auth->authId;
    ReleaseAuthLock();
    return authId;
}

static int64_t GetActiveAuthIdByConnInfo(const AuthConnInfo *connInfo)
{
    if (!RequireAuthLock()) {
        return AUTH_INVALID_ID;
    }
    uint32_t num = 0;
    AuthManager *auth[2] = {NULL, NULL}; /* 2: client + server */
    auth[num++] = FindAuthManagerByConnInfo(connInfo, false);
    auth[num++] = FindAuthManagerByConnInfo(connInfo, true);
    /* Check auth valid period */
    uint64_t currentTime = GetCurrentTimeMs();
    for (uint32_t i = 0; i < num; i++) {
        if (auth[i] != NULL && (currentTime - auth[i]->lastActiveTime >= MAX_AUTH_VALID_PERIOD)) {
            auth[i] = NULL;
        }
    }
    /* Get lastest authId */
    int64_t authId = AUTH_INVALID_ID;
    uint64_t maxVerifyTime = 0;
    for (uint32_t i = 0; i < sizeof(auth) / sizeof(auth[0]); i++) {
        if (auth[i] == NULL) {
            continue;
        }
        if (auth[i] != NULL && auth[i]->lastVerifyTime > maxVerifyTime) {
            authId = auth[i]->authId;
        }
    }
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO,
        "get active auth manager[%"PRId64"]", authId);
    ReleaseAuthLock();
    return authId;
}

int32_t AuthManagerSetSessionKey(int64_t authSeq, const AuthSessionInfo *info, const SessionKey *sessionKey)
{
    CHECK_NULL_PTR_RETURN_VALUE(info, SOFTBUS_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(sessionKey, SOFTBUS_INVALID_PARAM);
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "SetSessionKey: authSeq=%" PRId64 ", side=%s, requestId=%u.",
        authSeq, GetAuthSideStr(info->isServer), info->requestId);
    if (!RequireAuthLock()) {
        return SOFTBUS_LOCK_ERR;
    }
    bool isNewCreated = false;
    AuthManager *auth = FindAuthManagerByConnInfo(&info->connInfo, info->isServer);
    if (auth == NULL) {
        auth = NewAuthManager(authSeq, info);
        if (auth == NULL) {
            SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "NewAuthManager fail.");
            ReleaseAuthLock();
            return SOFTBUS_MALLOC_ERR;
        }
        isNewCreated = true;
    }
    auth->connId = info->connId;
    auth->lastVerifyTime = GetCurrentTimeMs();
    auth->lastActiveTime = GetCurrentTimeMs();
    if (AddSessionKey(&auth->sessionKeyList, TO_INT32(authSeq), sessionKey) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "AddSessionKey fail.");
        if (isNewCreated) {
            DelAuthManager(auth, true);
        }
        ReleaseAuthLock();
        return SOFTBUS_ERR;
    }
    if (auth->connInfo.type == AUTH_LINK_TYPE_WIFI && !auth->isServer) {
        ScheduleUpdateSessionKey(auth->authId, SCHEDULE_UPDATE_SESSION_KEY_PERIOD);
    }
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_DBG,
        "auth manager[%"PRId64"] add session key succ, index=%d.", auth->authId, TO_INT32(authSeq));
    ReleaseAuthLock();
    return SOFTBUS_OK;
}

int32_t AuthManagerGetSessionKey(int64_t authSeq, const AuthSessionInfo *info, SessionKey *sessionKey)
{
    CHECK_NULL_PTR_RETURN_VALUE(info, SOFTBUS_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(sessionKey, SOFTBUS_INVALID_PARAM);
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "GetSessionKey: authSeq=%" PRId64 ", side=%s, requestId=%u.",
        authSeq, GetAuthSideStr(info->isServer), info->requestId);
    if (!RequireAuthLock()) {
        return SOFTBUS_LOCK_ERR;
    }
    AuthManager *auth = FindAuthManagerByConnInfo(&info->connInfo, info->isServer);
    if (auth == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "auth manager not found.");
        ReleaseAuthLock();
        return SOFTBUS_ERR;
    }
    if (GetSessionKeyByIndex(&auth->sessionKeyList, TO_INT32(authSeq), sessionKey) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "GetSessionKeyByIndex fail.");
        ReleaseAuthLock();
        return SOFTBUS_ERR;
    }
    ReleaseAuthLock();
    return SOFTBUS_OK;
}

static void NotifyDeviceVerifyPassed(int64_t authId, const NodeInfo *nodeInfo)
{
    AuthManager *auth = GetAuthManagerByAuthId(authId);
    if (auth == NULL) {
        return;
    }
    if (auth->connInfo.type == AUTH_LINK_TYPE_P2P) {
        /* P2P auth no need notify to LNN. */
        DelAuthManager(auth, false);
        return;
    }
    DelAuthManager(auth, false);

    /* notify LNN device verify pass. */
    if (g_verifyListener.onDeviceVerifyPass == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_WARN, "onDeviceVerifyPass not set.");
        return;
    }
    g_verifyListener.onDeviceVerifyPass(authId, nodeInfo);
}

static void NotifyDeviceDisconnect(int64_t authId)
{
    if (g_verifyListener.onDeviceDisconnect == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_WARN, "onDeviceDisconnect not set.");
        return;
    }
    g_verifyListener.onDeviceDisconnect(authId);
}

static void OnDeviceNotTrusted(const char *peerUdid)
{
    RemoveNotPassedAuthManagerByUdid(peerUdid);
    AuthSessionHandleDeviceNotTrusted(peerUdid);
    LnnDeleteSpecificTrustedDevInfo(peerUdid);
    if (g_verifyListener.onDeviceNotTrusted == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_WARN, "onDeviceNotTrusted not set.");
        return;
    }
    g_verifyListener.onDeviceNotTrusted(peerUdid);
}

static void OnGroupCreated(const char *groupId)
{
    if (g_groupChangeListener.onGroupCreated != NULL) {
        g_groupChangeListener.onGroupCreated(groupId);
    }
}

static void OnGroupDeleted(const char *groupId)
{
    if (g_groupChangeListener.onGroupDeleted != NULL) {
        g_groupChangeListener.onGroupDeleted(groupId);
    }
}

static int32_t StartVerifyDevice(uint32_t requestId, const AuthConnInfo *connInfo,
    const AuthVerifyCallback *verifyCb, const AuthConnCallback *connCb)
{
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO,
        "start verify device: requestId=%u.", requestId);
    AuthRequest request;
    (void)memset_s(&request, sizeof(AuthRequest), 0, sizeof(AuthRequest));
    if (connCb != NULL) {
        request.connCb = *connCb;
    }
    if (verifyCb != NULL) {
        request.verifyCb = *verifyCb;
    }
    request.requestId = requestId;
    request.connInfo = *connInfo;
    request.authId = AUTH_INVALID_ID;
    request.type = REQUEST_TYPE_VERIFY;
    uint32_t waitNum = AddAuthRequest(&request);
    if (waitNum == 0) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR,
            "add verify request to list fail, requestId=%u.", requestId);
        return SOFTBUS_AUTH_INNER_ERR;
    }
    if (waitNum > 1) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO,
            "wait last verify request complete, waitNum=%u, requestId=%u.", waitNum, requestId);
        return SOFTBUS_OK;
    }
    if (ConnectAuthDevice(requestId, connInfo, CONN_SIDE_ANY) != SOFTBUS_OK) {
        DelAuthRequest(requestId);
        return SOFTBUS_AUTH_CONN_FAIL;
    }
    return SOFTBUS_OK;
}

static int32_t StartReconnectDevice(int64_t authId, const AuthConnInfo *connInfo,
    uint32_t requestId, const AuthConnCallback *connCb)
{
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO,
        "start reconnect device: requestId=%u, authId=%" PRId64, requestId, authId);
    AuthManager *auth = GetAuthManagerByAuthId(authId);
    if (auth == NULL) {
        return SOFTBUS_AUTH_NOT_FOUND;
    }
    ConnSideType sideType = GetConnSideType(auth->connId);
    DelAuthManager(auth, false);

    AuthRequest request;
    (void)memset_s(&request, sizeof(AuthRequest), 0, sizeof(AuthRequest));
    request.authId = authId;
    request.connCb = *connCb;
    request.connInfo = *connInfo;
    request.requestId = requestId;
    request.type = REQUEST_TYPE_RECONNECT;
    if (AddAuthRequest(&request) == 0) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR,
            "add reconnect request fail, requestId=%u.", requestId);
        return SOFTBUS_ERR;
    }
    if (ConnectAuthDevice(requestId, connInfo, sideType) != SOFTBUS_OK) {
        DelAuthRequest(requestId);
        return SOFTBUS_AUTH_CONN_FAIL;
    }
    return SOFTBUS_OK;
}

static void ReportAuthRequestPassed(uint32_t requestId, int64_t authId, const NodeInfo *nodeInfo)
{
    AuthRequest request;
    if (GetAuthRequest(requestId, &request) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO,
            "auth request not found, only notify LNN to update nodeInfo.");
        NotifyDeviceVerifyPassed(authId, nodeInfo);
        return;
    }
    do {
        if (CheckAuthConnCallback(&request.connCb)) {
            NotifyDeviceVerifyPassed(authId, nodeInfo);
            if (request.connInfo.type == AUTH_LINK_TYPE_WIFI ||
                request.connInfo.type == AUTH_LINK_TYPE_P2P) {
                PerformAuthConnCallback(request.requestId, SOFTBUS_OK, authId);
                DelAuthRequest(request.requestId);
                continue;
            }
            /* For open auth br/ble connection, reconnect to keep long-connection. */
            DelAuthRequest(request.requestId);
            if (StartReconnectDevice(authId, &request.connInfo,
                request.requestId, &request.connCb) != SOFTBUS_OK) {
                SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "open auth reconnect fail.");
                request.connCb.onConnOpenFailed(request.requestId, SOFTBUS_AUTH_CONN_FAIL);
            }
            continue;
        }
        PerformVerifyCallback(request.requestId, SOFTBUS_OK, authId, nodeInfo);
        DelAuthRequest(request.requestId);
    } while (FindAuthRequestByConnInfo(&request.connInfo, &request) == SOFTBUS_OK);
}

static void ReportAuthRequestFailed(uint32_t requestId, int32_t reason)
{
    AuthRequest request;
    if (GetAuthRequest(requestId, &request) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "auth request not found.");
        return;
    }
    if (CheckAuthConnCallback(&request.connCb)) {
        PerformAuthConnCallback(request.requestId, reason, AUTH_INVALID_ID);
    } else {
        PerformVerifyCallback(request.requestId, reason, AUTH_INVALID_ID, NULL);
    }
    DelAuthRequest(request.requestId);
    if (FindAuthRequestByConnInfo(&request.connInfo, &request) != SOFTBUS_OK) {
        /* verify request wait list is empty, return. */
        return;
    }
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO,
        "find another verify request in wait list, do verify again.");
    if (ConnectAuthDevice(request.requestId, &request.connInfo, CONN_SIDE_ANY) != SOFTBUS_OK) {
        ReportAuthRequestFailed(request.requestId, SOFTBUS_AUTH_CONN_FAIL);
    }
}

void AuthManagerSetAuthPassed(int64_t authSeq, const AuthSessionInfo *info)
{
    int64_t authId;
    CHECK_NULL_PTR_RETURN_VOID(info);
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "SetAuthPassed: authSeq=%" PRId64 ", side=%s, requestId=%u.",
        authSeq, GetAuthSideStr(info->isServer), info->requestId);

    if (!RequireAuthLock()) {
        return;
    }
    AuthManager *auth = FindAuthManagerByConnInfo(&info->connInfo, info->isServer);
    if (auth == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR,
            "auth manager not found, connType=%d, side=%s", info->connInfo.type, GetAuthSideStr(info->isServer));
        ReleaseAuthLock();
        return;
    }
    auth->hasAuthPassed = true;
    if (info->nodeInfo.p2pInfo.p2pMac[0] != '\0') {
        if (strcpy_s(auth->p2pMac, sizeof(auth->p2pMac), info->nodeInfo.p2pInfo.p2pMac)) {
            SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR,
                "copy p2pMac fail, authSeq=%" PRId64, authSeq);
        }
    }
    authId = auth->authId;
    ReleaseAuthLock();

    if (info->isServer) {
        NotifyDeviceVerifyPassed(authId, &info->nodeInfo);
    } else {
        ReportAuthRequestPassed(info->requestId, authId, &info->nodeInfo);
        UpdateAuthDevicePriority(info->connId);
        /* br and ble NOT long-connection, close connection after auth pass. */
        if (info->connInfo.type == AUTH_LINK_TYPE_BR || info->connInfo.type == AUTH_LINK_TYPE_BLE) {
            DisconnectAuthDevice(info->connId);
        }
    }
}

void AuthManagerSetAuthFailed(int64_t authSeq, const AuthSessionInfo *info, int32_t reason)
{
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "SetAuthFailed: authSeq=%" PRId64 ", requestId=%u, reason=%d.",
        authSeq, info->requestId, reason);
    AuthManager *auth = GetAuthManagerByConnInfo(&info->connInfo, info->isServer);
    if (auth != NULL && auth->hasAuthPassed) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR,
            "update session key fail, authId=%" PRId64, auth->authId);
        NotifyDeviceDisconnect(auth->authId);
    }
    DelAuthManager(auth, false);

    RemoveAuthManagerByConnInfo(&info->connInfo, info->isServer);
    ReportAuthRequestFailed(info->requestId, reason);
    if (!info->isServer) {
        /* only client close connection. */
        DisconnectAuthDevice(info->connId);
    }
}

static void HandleReconnectResult(const AuthRequest *request, uint64_t connId, int32_t result)
{
    if (result != SOFTBUS_OK) {
        PerformAuthConnCallback(request->requestId, result, AUTH_INVALID_ID);
        DelAuthRequest(request->requestId);
        return;
    }
    AuthManager inAuth = {.connId = connId};
    if (UpdateAuthManagerByAuthId(request->authId, SetAuthConnId, &inAuth) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR,
            "set auth connId fail, requestId=%u.", request->requestId);
        PerformAuthConnCallback(request->requestId, SOFTBUS_AUTH_NOT_FOUND, AUTH_INVALID_ID);
        DelAuthRequest(request->requestId);
        return;
    }
    PerformAuthConnCallback(request->requestId, SOFTBUS_OK, request->authId);
    DelAuthRequest(request->requestId);
}

static void OnConnectResult(uint32_t requestId, uint64_t connId, int32_t result, const AuthConnInfo *connInfo)
{
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO,
        "OnConnectResult: requestId=%u, result=%d.", requestId, result);
    AuthRequest request;
    if (GetAuthRequest(requestId, &request) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "request not found, requestId=%u.", requestId);
        return;
    }
    if (request.type == REQUEST_TYPE_RECONNECT) {
        HandleReconnectResult(&request, connId, result);
        return;
    }

    if (result != SOFTBUS_OK) {
        ReportAuthRequestFailed(requestId, result);
        return;
    }
    /* connect success */
    (void)UpdateAuthRequestConnInfo(requestId, connInfo);
    int32_t ret = AuthSessionStartAuth(GenSeq(false), requestId, connId, connInfo, false);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR,
            "start auth session fail(=%d), requestId=%u.", ret, requestId);
        DisconnectAuthDevice(connId);
        ReportAuthRequestFailed(requestId, ret);
        return;
    }
}

static void HandleDeviceIdData(uint64_t connId, const AuthConnInfo *connInfo,
    const AuthDataHead *head, const uint8_t *data)
{
    int32_t ret;
    if (head->flag == CLIENT_SIDE_FLAG) {
        if (!GetConfigSupportAsServer()) {
            SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR,
                "local device NOT support as server, ignore auth seq=%" PRId64, head->seq);
            return;
        }
        ret = AuthSessionStartAuth(head->seq, AuthGenRequestId(), connId, connInfo, true);
        if (ret != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR,
                "perform auth(=%"PRId64") session start auth fail(=%d)", head->seq, ret);
            return;
        }
    }
    ret = AuthSessionProcessDevIdData(head->seq, data, head->len);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR,
            "perform auth(=%"PRId64") session recv devId fail(=%d)", head->seq, ret);
        return;
    }
}

static void HandleAuthData(const AuthConnInfo *connInfo,
    const AuthDataHead *head, const uint8_t *data)
{
    int32_t ret = AuthSessionProcessAuthData(head->seq, data, head->len);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR,
            "perform auth(=%"PRId64") session recv authData fail(=%d)", head->seq, ret);
        return;
    }
}

static void HandleDeviceInfoData(uint64_t connId, const AuthConnInfo *connInfo, bool fromServer,
    const AuthDataHead *head, const uint8_t *data)
{
    int32_t ret;
    if (head->seq != 0) {
        ret = AuthSessionProcessDevInfoData(head->seq, data, head->len);
    } else {
        /* To be compatible with ohos-3.1 and early. */
        ret = AuthSessionProcessDevInfoDataByConnId(connId, !fromServer, data, head->len);
    }
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR,
            "perform auth(=%"PRId64") session recv devInfo fail(=%d)", head->seq, ret);
        return;
    }
}

static void HandleCloseAckData(uint64_t connId, const AuthConnInfo *connInfo, bool fromServer,
    const AuthDataHead *head, const uint8_t *data)
{
    int32_t ret;
    if (head->seq != 0) {
        ret = AuthSessionProcessCloseAck(head->seq, data, head->len);
    } else {
        /* To be compatible with nearby. */
        ret = AuthSessionProcessCloseAckByConnId(connId, !fromServer, data, head->len);
    }
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR,
            "perform auth(=%"PRId64") session recv closeAck fail(=%d)", head->seq, ret);
        return;
    }
}

static void HandleConnectionData(uint64_t connId, const AuthConnInfo *connInfo, bool fromServer,
    const AuthDataHead *head, const uint8_t *data)
{
    if (!RequireAuthLock()) {
        return;
    }
    AuthManager *auth = FindAuthManagerByConnInfo(connInfo, !fromServer);
    if (auth == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "AuthManager not found.");
        ReleaseAuthLock();
        return;
    }
    int64_t authId = auth->authId;
    uint8_t *decData = NULL;
    uint32_t decDataLen = 0;
    if (DecryptInner(&auth->sessionKeyList, data, head->len, &decData, &decDataLen) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "decrypt trans data fail.");
        ReleaseAuthLock();
        return;
    }
    auth->lastActiveTime = GetCurrentTimeMs();
    auth->connId = connId;
    ReleaseAuthLock();
    if (g_transCallback.OnDataReceived != NULL) {
        g_transCallback.OnDataReceived(authId, head, decData, decDataLen);
    }
    SoftBusFree(decData);
}

static void OnDataReceived(uint64_t connId, const AuthConnInfo *connInfo, bool fromServer,
    const AuthDataHead *head, const uint8_t *data)
{
    if (connInfo == NULL || head == NULL || data == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "invalid param.");
        return;
    }
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO,
        "auth recv data{type=0x%x, module=%d, seq=%"PRId64", flag=%d, len=%u} " CONN_INFO " from[%s]",
        head->dataType, head->module, head->seq, head->flag, head->len, CONN_DATA(connId), GetAuthSideStr(fromServer));
    switch (head->dataType) {
        case DATA_TYPE_DEVICE_ID:
            HandleDeviceIdData(connId, connInfo, head, data);
            break;
        case DATA_TYPE_AUTH:
            HandleAuthData(connInfo, head, data);
            break;
        case DATA_TYPE_DEVICE_INFO:
            HandleDeviceInfoData(connId, connInfo, fromServer, head, data);
            break;
        case DATA_TYPE_CLOSE_ACK:
            HandleCloseAckData(connId, connInfo, fromServer, head, data);
            break;
        case DATA_TYPE_CONNECTION:
            HandleConnectionData(connId, connInfo, fromServer, head, data);
            break;
        default:
            break;
    }
}

static void HandleDisconnectedEvent(const void *para)
{
    CHECK_NULL_PTR_RETURN_VOID(para);
    uint64_t connId = *((uint64_t *)para);
    uint32_t num = 0;
    int64_t authIds[2]; /* 2: client and server may use same connection. */
    authIds[num++]= GetAuthIdByConnId(connId, false);
    authIds[num++]= GetAuthIdByConnId(connId, true);
    for (uint32_t i = 0; i < num; i++) {
        if (authIds[i] == AUTH_INVALID_ID) {
            continue;
        }
        if (g_transCallback.OnDisconnected != NULL) {
            g_transCallback.OnDisconnected(authIds[i]);
        }
        if (GetConnType(connId) == AUTH_LINK_TYPE_WIFI || GetConnType(connId) == AUTH_LINK_TYPE_P2P) {
            RemoveAuthManagerByAuthId(authIds[i]);
            NotifyDeviceDisconnect(authIds[i]);
        }
    }
    /* Try to terminate authing session. */
    (void)AuthSessionHandleDeviceDisconnected(connId);
}

static void OnDisconnected(uint64_t connId, const AuthConnInfo *connInfo)
{
    (void)connInfo;
    (void)PostAuthEvent(EVENT_AUTH_DISCONNECT, HandleDisconnectedEvent, &connId, sizeof(connId), 0);
}

int32_t RegAuthVerifyListener(const AuthVerifyListener *listener)
{
    if (listener == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "invalid listener.");
        return SOFTBUS_INVALID_PARAM;
    }
    g_verifyListener = *listener;
    return SOFTBUS_OK;
}

void UnregAuthVerifyListener(void)
{
    (void)memset_s(&g_verifyListener, sizeof(AuthVerifyListener), 0, sizeof(AuthVerifyListener));
}

uint32_t AuthGenRequestId(void)
{
    return ConnGetNewRequestId(MODULE_DEVICE_AUTH);
}

int32_t AuthStartVerify(const AuthConnInfo *connInfo, uint32_t requestId, const AuthVerifyCallback *callback)
{
    if (connInfo == NULL || !CheckVerifyCallback(callback)) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "%s: invalid param.", __func__);
        return SOFTBUS_INVALID_PARAM;
    }
    return StartVerifyDevice(requestId, connInfo, callback, NULL);
}

void AuthHandleLeaveLNN(int64_t authId)
{
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO,
        "auth handle leave LNN, authId=%" PRId64, authId);
    if (!RequireAuthLock()) {
        return;
    }
    AuthManager *auth = FindAuthManagerByAuthId(authId);
    if (auth == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO,
            "auth manager not found, authId=%" PRId64, authId);
        ReleaseAuthLock();
        return;
    }
    if (auth->connInfo.type == AUTH_LINK_TYPE_WIFI) {
        DisconnectAuthDevice(auth->connId);
    }
    DelAuthManager(auth, true);
    ReleaseAuthLock();
}

int32_t AuthFlushDevice(const char *uuid)
{
    if (uuid == NULL || uuid[0] == '\0') {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "uuid is empty.");
        return SOFTBUS_INVALID_PARAM;
    }
    if (!RequireAuthLock()) {
        return SOFTBUS_LOCK_ERR;
    }
    uint32_t num = 0;
    AuthManager *auth[2] = {NULL, NULL}; /* 2: WiFi * (Client + Server) */
    auth[num++] = FindAuthManagerByUuid(uuid, AUTH_LINK_TYPE_WIFI, false);
    auth[num++] = FindAuthManagerByUuid(uuid, AUTH_LINK_TYPE_WIFI, true);
    for (uint32_t i = 0; i < num; i++) {
        if (auth[i] == NULL) {
            continue;
        }
        (void)PostVerifyDeviceMessage(auth[i]);
    }
    ReleaseAuthLock();
    return SOFTBUS_OK;
}

static int32_t TryGetBrConnInfo(const char *uuid, AuthConnInfo *connInfo)
{
    char networkId[NETWORK_ID_BUF_LEN] = {0};
    if (LnnGetNetworkIdByUuid(uuid, networkId, sizeof(networkId)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "get networkdId by uuid fail.");
        return SOFTBUS_ERR;
    }

    uint32_t local, remote;
    if (LnnGetLocalNumInfo(NUM_KEY_NET_CAP, (int32_t *)&local) != SOFTBUS_OK ||
        LnnGetRemoteNumInfo(networkId, NUM_KEY_NET_CAP, (int32_t *)&remote) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "get NET_CAP fail.");
        return SOFTBUS_ERR;
    }
    if (((local & (1 << BIT_BR)) == 0) || ((remote & (1 << BIT_BR)) == 0)) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "can't support BR.");
        return SOFTBUS_ERR;
    }
    if (LnnGetRemoteStrInfo(networkId, STRING_KEY_BT_MAC, connInfo->info.brInfo.brMac, BT_MAC_LEN) != SOFTBUS_OK ||
        connInfo->info.brInfo.brMac[0] == '\0') {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "get bt mac fail.");
        return SOFTBUS_ERR;
    }
    connInfo->type = AUTH_LINK_TYPE_BR;
    return SOFTBUS_OK;
}

int32_t AuthDeviceGetPreferConnInfo(const char *uuid, AuthConnInfo *connInfo)
{
    if (uuid == NULL || uuid[0] == '\0' || connInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "invalid uuid or connInfo.");
        return SOFTBUS_INVALID_PARAM;
    }
    AuthLinkType linkList[] = { AUTH_LINK_TYPE_WIFI, AUTH_LINK_TYPE_BR }; /* Not support BLE for transport yet */
    for (uint32_t i = 0; i < sizeof(linkList) / sizeof(linkList[0]); i++) {
        if (GetAuthConnInfoByUuid(uuid, linkList[i], connInfo) != SOFTBUS_OK) {
            continue;
        }
        if (linkList[i] == AUTH_LINK_TYPE_BLE) {
            if (!CheckActiveAuthConnection(connInfo)) {
                SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "auth ble connection not active.");
                continue;
            }
        }
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "select auth type: %d.", linkList[i]);
        return SOFTBUS_OK;
    }
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "no active auth, try br connection.");
    return TryGetBrConnInfo(uuid, connInfo);
}

int32_t AuthDeviceOpenConn(const AuthConnInfo *info, uint32_t requestId, const AuthConnCallback *callback)
{
    if (info == NULL || !CheckAuthConnCallback(callback)) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "%s: invalid param.", __func__);
        return SOFTBUS_INVALID_PARAM;
    }
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO,
        "open auth conn: connType=%d, requestId=%u.", info->type, requestId);
    int64_t authId;
    switch (info->type) {
        case AUTH_LINK_TYPE_WIFI:
            authId = GetAuthIdByConnInfo(info, false);
            if (authId == AUTH_INVALID_ID) {
                authId = GetAuthIdByConnInfo(info, true);
            }
            if (authId == AUTH_INVALID_ID) {
                return SOFTBUS_AUTH_NOT_FOUND;
            }
            callback->onConnOpened(requestId, authId);
            break;
        case AUTH_LINK_TYPE_BR:
        case AUTH_LINK_TYPE_BLE:
        case AUTH_LINK_TYPE_P2P:
            authId = GetActiveAuthIdByConnInfo(info);
            if (authId != AUTH_INVALID_ID) {
                return StartReconnectDevice(authId, info, requestId, callback);
            }
            return StartVerifyDevice(requestId, info, NULL, callback);
        default:
            SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "unknown connType: %d", info->type);
            return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

void AuthDeviceCloseConn(int64_t authId)
{
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "close auth conn: authId=%" PRId64, authId);
    AuthManager *auth = GetAuthManagerByAuthId(authId);
    if (auth == NULL) {
        return;
    }
    switch (auth->connInfo.type) {
        case AUTH_LINK_TYPE_WIFI:
        case AUTH_LINK_TYPE_P2P:
            /* Do nothing. */
            break;
        case AUTH_LINK_TYPE_BR:
        case AUTH_LINK_TYPE_BLE:
            DisconnectAuthDevice(auth->connId);
            break;
        default:
            break;
    }
    DelAuthManager(auth, false);
    return;
}

int32_t AuthDevicePostTransData(int64_t authId, const AuthTransData *dataInfo)
{
    if (dataInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "dataInfo is null.");
        return SOFTBUS_INVALID_PARAM;
    }
    AuthManager *auth = GetAuthManagerByAuthId(authId);
    if (auth == NULL) {
        return SOFTBUS_AUTH_NOT_FOUND;
    }
    AuthDataHead head;
    head.dataType = DATA_TYPE_CONNECTION;
    head.module = dataInfo->module;
    head.seq = dataInfo->seq;
    head.flag = dataInfo->flag;
    uint8_t *encData = NULL;
    if (EncryptInner(&auth->sessionKeyList, dataInfo->data, dataInfo->len, &encData, &head.len) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "encrypt trans data fail.");
        DelAuthManager(auth, false);
        return SOFTBUS_ENCRYPT_ERR;
    }
    if (PostAuthData(auth->connId, !auth->isServer, &head, encData) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "post trans data fail.");
        SoftBusFree(encData);
        DelAuthManager(auth, false);
        return SOFTBUS_ERR;
    }
    SoftBusFree(encData);
    DelAuthManager(auth, false);
    return SOFTBUS_OK;
}

int32_t RegGroupChangeListener(const GroupChangeListener *listener)
{
    if (listener == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    g_groupChangeListener.onGroupCreated = listener->onGroupCreated;
    g_groupChangeListener.onGroupDeleted = listener->onGroupDeleted;
    return SOFTBUS_OK;
}

void UnregGroupChangeListener(void)
{
    g_groupChangeListener.onGroupCreated = NULL;
    g_groupChangeListener.onGroupDeleted = NULL;
}

int64_t AuthDeviceGetLatestIdByUuid(const char *uuid, bool isIpConnection)
{
    if (uuid == NULL || uuid[0] == '\0') {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "uuid is empty.");
        return AUTH_INVALID_ID;
    }
    if (!RequireAuthLock()) {
        return SOFTBUS_LOCK_ERR;
    }
    uint32_t num = 0;
    AuthManager *auth[4] = {NULL, NULL, NULL, NULL}; /* 4: max size for (BR + BLE) * (CLIENT+ SERVER) */
    if (isIpConnection) {
        auth[num++] = FindAuthManagerByUuid(uuid, AUTH_LINK_TYPE_WIFI, false);
        auth[num++] = FindAuthManagerByUuid(uuid, AUTH_LINK_TYPE_WIFI, true);
    } else {
        auth[num++] = FindAuthManagerByUuid(uuid, AUTH_LINK_TYPE_BR, false);
        auth[num++] = FindAuthManagerByUuid(uuid, AUTH_LINK_TYPE_BR, true);
        auth[num++] = FindAuthManagerByUuid(uuid, AUTH_LINK_TYPE_BLE, false);
        auth[num++] = FindAuthManagerByUuid(uuid, AUTH_LINK_TYPE_BLE, true);
    }
    int64_t latestAuthId = AUTH_INVALID_ID;
    uint64_t latestVerifyTime = 0;
    for (uint32_t i = 0; i < num; i++) {
        if (auth[i] != NULL && auth[i]->lastVerifyTime > latestVerifyTime) {
            latestAuthId = auth[i]->authId;
            latestVerifyTime = auth[i]->lastVerifyTime;
        }
    }
    ReleaseAuthLock();
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO,
        "latest auth manager[%"PRId64"] found, lastVerifyTime=%" PRIu64, latestAuthId, latestVerifyTime);
    return latestAuthId;
}

int64_t AuthDeviceGetIdByConnInfo(const AuthConnInfo *connInfo, bool isServer)
{
    if (connInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "connInfo is null.");
        return AUTH_INVALID_ID;
    }
    return GetAuthIdByConnInfo(connInfo, isServer);
}

int64_t AuthDeviceGetIdByP2pMac(const char *p2pMac, AuthLinkType type, bool isServer)
{
    if (p2pMac == NULL || p2pMac[0] == '\0') {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "p2pMac is empty.");
        return AUTH_INVALID_ID;
    }
    if (!RequireAuthLock()) {
        return AUTH_INVALID_ID;
    }
    AuthManager *auth = FindAuthManagerByP2pMac(p2pMac, type, isServer);
    if (auth == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR,
            "auth manager not found by p2pMac, connType=%d, side=%s", type, GetAuthSideStr(isServer));
        ReleaseAuthLock();
        return AUTH_INVALID_ID;
    }
    int64_t authId = auth->authId;
    ReleaseAuthLock();
    return authId;
}

uint32_t AuthGetEncryptSize(uint32_t inLen)
{
    return inLen + ENCRYPT_OVER_HEAD_LEN;
}

uint32_t AuthGetDecryptSize(uint32_t inLen)
{
    if (inLen <= OVERHEAD_LEN) {
        return inLen;
    }
    return inLen - OVERHEAD_LEN;
}

int32_t AuthDeviceEncrypt(int64_t authId, const uint8_t *inData, uint32_t inLen, uint8_t *outData, uint32_t *outLen)
{
    if (inData == NULL || inLen == 0 || outData == NULL || outLen == NULL || *outLen < AuthGetEncryptSize(inLen)) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "%s: invalid param.", __func__);
        return SOFTBUS_INVALID_PARAM;
    }
    AuthManager *auth = GetAuthManagerByAuthId(authId);
    if (auth == NULL) {
        return SOFTBUS_AUTH_NOT_FOUND;
    }
    if (EncryptData(&auth->sessionKeyList, inData, inLen, outData, outLen) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "auth encrypt fail.");
        DelAuthManager(auth, false);
        return SOFTBUS_ENCRYPT_ERR;
    }
    DelAuthManager(auth, false);
    return SOFTBUS_OK;
}

int32_t AuthDeviceDecrypt(int64_t authId, const uint8_t *inData, uint32_t inLen, uint8_t *outData, uint32_t *outLen)
{
    if (inData == NULL || inLen == 0 || outData == NULL || outLen == NULL || *outLen < AuthGetDecryptSize(inLen)) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "%s: invalid param.", __func__);
        return SOFTBUS_INVALID_PARAM;
    }
    AuthManager *auth = GetAuthManagerByAuthId(authId);
    if (auth == NULL) {
        return SOFTBUS_AUTH_NOT_FOUND;
    }
    if (DecryptData(&auth->sessionKeyList, inData, inLen, outData, outLen) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "auth decrypt fail.");
        DelAuthManager(auth, false);
        return SOFTBUS_ENCRYPT_ERR;
    }
    DelAuthManager(auth, false);
    return SOFTBUS_OK;
}

int32_t AuthDeviceSetP2pMac(int64_t authId, const char *p2pMac)
{
    if (p2pMac == NULL || p2pMac[0] == '\0') {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "p2pMac is empty.");
        return SOFTBUS_INVALID_PARAM;
    }
    AuthManager inAuth = {0};
    if (strcpy_s(inAuth.p2pMac, sizeof(inAuth.p2pMac), p2pMac) != EOK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR,
            "copy p2pMac fail, authId=%" PRId64, authId);
        return SOFTBUS_MEM_ERR;
    }
    return UpdateAuthManagerByAuthId(authId, SetAuthP2pMac, &inAuth);
}

int32_t AuthDeviceGetConnInfo(int64_t authId, AuthConnInfo *connInfo)
{
    if (connInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "connInfo is null.");
        return SOFTBUS_INVALID_PARAM;
    }
    AuthManager *auth = GetAuthManagerByAuthId(authId);
    if (auth == NULL) {
        return SOFTBUS_AUTH_NOT_FOUND;
    }
    *connInfo = auth->connInfo;
    DelAuthManager(auth, false);
    return SOFTBUS_OK;
}

int32_t AuthDeviceGetServerSide(int64_t authId, bool *isServer)
{
    if (isServer == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "isServer is null.");
        return SOFTBUS_INVALID_PARAM;
    }
    AuthManager *auth = GetAuthManagerByAuthId(authId);
    if (auth == NULL) {
        return SOFTBUS_AUTH_NOT_FOUND;
    }
    *isServer = auth->isServer;
    DelAuthManager(auth, false);
    return SOFTBUS_OK;
}

int32_t AuthDeviceGetDeviceUuid(int64_t authId, char *uuid, uint16_t size)
{
    if (uuid == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "uuid is empty.");
        return SOFTBUS_INVALID_PARAM;
    }
    AuthManager *auth = GetAuthManagerByAuthId(authId);
    if (auth == NULL) {
        return SOFTBUS_AUTH_NOT_FOUND;
    }
    if (strcpy_s(uuid, size, auth->uuid) != EOK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "copy uuid fail, size=%u.", size);
        DelAuthManager(auth, false);
        return SOFTBUS_ERR;
    }
    DelAuthManager(auth, false);
    return SOFTBUS_OK;
}

int32_t AuthDeviceGetVersion(int64_t authId, SoftBusVersion *version)
{
    if (version == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "version is null.");
        return SOFTBUS_INVALID_PARAM;
    }
    AuthManager *auth = GetAuthManagerByAuthId(authId);
    if (auth == NULL) {
        return SOFTBUS_AUTH_NOT_FOUND;
    }
    *version = auth->version;
    DelAuthManager(auth, false);
    return SOFTBUS_OK;
}

int32_t AuthDeviceInit(const AuthTransCallback *callback)
{
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "auth init enter.");
    if (callback == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "Auth notify trans callback is null.");
        return SOFTBUS_INVALID_PARAM;
    }
    g_transCallback = *callback;
    ListInit(&g_authClientList);
    ListInit(&g_authServerList);
    if (AuthCommonInit() != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "AuthCommonInit fail.");
        return SOFTBUS_AUTH_INIT_FAIL;
    }

    AuthConnListener connListener = {
        .onConnectResult = OnConnectResult,
        .onDataReceived = OnDataReceived,
        .onDisconnected = OnDisconnected,
    };
    if (AuthConnInit(&connListener) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "AuthConnInit fail.");
        AuthCommonDeinit();
        return SOFTBUS_AUTH_INIT_FAIL;
    }

    TrustDataChangeListener trustListener = {
        .onGroupCreated = OnGroupCreated,
        .onGroupDeleted = OnGroupDeleted,
        .onDeviceNotTrusted = OnDeviceNotTrusted,
    };
    if (RegTrustDataChangeListener(&trustListener) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "RegTrustDataChangeListener fail.");
        AuthConnDeinit();
        AuthCommonDeinit();
        return SOFTBUS_AUTH_INIT_FAIL;
    }
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "auth init succ.");
    return SOFTBUS_OK;
}

void AuthDeviceDeinit(void)
{
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "auth deinit enter.");
    UnregTrustDataChangeListener();
    DestroyAuthManagerList();
    ClearAuthRequest();
    AuthConnDeinit();
    AuthSessionFsmExit();
    AuthCommonDeinit();
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "auth deinit succ.");
}
