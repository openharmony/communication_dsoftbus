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

#include "auth_manager.h"

#include <securec.h>

#include "anonymizer.h"
#include "auth_common.h"
#include "auth_connection.h"
#include "auth_hichain.h"
#include "auth_log.h"
#include "auth_request.h"
#include "auth_session_fsm.h"
#include "auth_session_message.h"
#include "bus_center_manager.h"
#include "device_profile_listener.h"
#include "lnn_async_callback_utils.h"
#include "lnn_app_bind_interface.h"
#include "lnn_decision_db.h"
#include "lnn_event.h"
#include "lnn_feature_capability.h"
#include "lnn_heartbeat_ctrl.h"
#include "lnn_net_builder.h"
#include "softbus_adapter_hitrace.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"

#define MAX_AUTH_VALID_PERIOD              (30 * 60 * 1000L)            /* 30 mins */
#define SCHEDULE_UPDATE_SESSION_KEY_PERIOD ((5 * 60 + 30) * 60 * 1000L) /* 5 hour 30 mins */
#define FLAG_REPLY                         1
#define FLAG_ACTIVE                        0
#define RETRY_REGDATA_TIMES                3
#define RETRY_REGDATA_MILLSECONDS          300
#define DELAY_REG_DP_TIME                  10000

static ListNode g_authClientList = { &g_authClientList, &g_authClientList };
static ListNode g_authServerList = { &g_authServerList, &g_authServerList };

static AuthVerifyListener g_verifyListener = { 0 };
static GroupChangeListener g_groupChangeListener = { 0 };
static AuthTransCallback g_transCallback = { 0 };
static bool g_regDataChangeListener = false;

/* Auth Manager */
AuthManager *NewAuthManager(int64_t authSeq, const AuthSessionInfo *info)
{
    AuthManager *auth = (AuthManager *)SoftBusCalloc(sizeof(AuthManager));
    if (auth == NULL) {
        AUTH_LOGW(AUTH_FSM, "malloc AuthManager fail");
        return NULL;
    }
    auth->authId = authSeq;
    auth->isServer = info->isServer;
    auth->connId = info->connId;
    auth->connInfo = info->connInfo;
    if (strcpy_s(auth->udid, sizeof(auth->udid), info->udid) != EOK ||
        strcpy_s(auth->uuid, sizeof(auth->uuid), info->uuid) != EOK) {
        AUTH_LOGW(AUTH_FSM, "copy uuid/udid fail");
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
    AUTH_LOGI(AUTH_FSM, "create auth manager, side=%{public}s, authId=%{public}" PRId64, GetAuthSideStr(auth->isServer),
        auth->authId);
    return auth;
}

static AuthManager *DupAuthManager(const AuthManager *auth)
{
    AuthManager *newAuth = (AuthManager *)DupMemBuffer((const uint8_t *)auth, sizeof(AuthManager));
    if (newAuth == NULL) {
        AUTH_LOGE(AUTH_FSM, "auth manager dup fail. authId=%{public}" PRId64 "", auth->authId);
        return NULL;
    }
    ListInit(&newAuth->node);
    ListInit(&newAuth->sessionKeyList);
    if (DupSessionKeyList(&auth->sessionKeyList, &newAuth->sessionKeyList)) {
        AUTH_LOGE(AUTH_FSM, "auth manager dup session key fail. authId=%{public}" PRId64 "", auth->authId);
        SoftBusFree(newAuth);
        return NULL;
    }
    return newAuth;
}

void DelAuthManager(AuthManager *auth, bool removeAuthFromList)
{
    AUTH_CHECK_AND_RETURN_LOGE(auth != NULL, AUTH_FSM, "auth is null");
    if (removeAuthFromList) {
        char *anonyUdid = NULL;
        Anonymize(auth->udid, &anonyUdid);
        AUTH_LOGI(AUTH_FSM, "delete auth manager, udid=%{public}s, side=%{public}s, authId=%{public}" PRId64, anonyUdid,
            GetAuthSideStr(auth->isServer), auth->authId);
        AnonymizeFree(anonyUdid);
        ListDelete(&auth->node);
        CancelUpdateSessionKey(auth->authId);
    }
    DestroySessionKeyList(&auth->sessionKeyList);
    SoftBusFree(auth);
}

static AuthManager *FindAuthManagerByConnInfo(const AuthConnInfo *connInfo, bool isServer)
{
    AuthManager *item = NULL;
    ListNode *list = isServer ? &g_authServerList : &g_authClientList;
    LIST_FOR_EACH_ENTRY(item, list, AuthManager, node) {
        if (CompareConnInfo(&item->connInfo, connInfo, true)) {
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
        if (item->connInfo.type == type && (strcmp(item->uuid, uuid) == 0) && item->hasAuthPassed) {
            return item;
        }
    }
    return NULL;
}

static AuthManager *FindAuthManagerByUdid(const char *udid, AuthLinkType type, bool isServer)
{
    AuthManager *item = NULL;
    ListNode *list = isServer ? &g_authServerList : &g_authClientList;
    LIST_FOR_EACH_ENTRY(item, list, AuthManager, node) {
        if (item->connInfo.type == type && (strcmp(item->udid, udid) == 0) && item->hasAuthPassed) {
            return item;
        }
    }
    return NULL;
}

static void PrintAuthConnInfo(const AuthConnInfo *connInfo)
{
    if (connInfo == NULL) {
        return;
    }
    char *anonyUdidHash = NULL;
    char *anonyMac = NULL;
    char *anonyIp = NULL;
    char udidHash[UDID_BUF_LEN] = { 0 };
    switch (connInfo->type) {
        case AUTH_LINK_TYPE_WIFI:
            Anonymize(connInfo->info.ipInfo.ip, &anonyIp);
            AUTH_LOGD(AUTH_CONN, "print AuthConninfo ip=*.*.*%{public}s", anonyIp);
            AnonymizeFree(anonyIp);
            break;
        case AUTH_LINK_TYPE_BR:
            Anonymize(connInfo->info.brInfo.brMac, &anonyMac);
            AUTH_LOGD(AUTH_CONN, "print AuthConninfo brMac=**:**:**:**:%{public}s", anonyMac);
            AnonymizeFree(anonyMac);
            break;
        case AUTH_LINK_TYPE_BLE:
            if (ConvertBytesToHexString(udidHash, UDID_BUF_LEN,
                (const unsigned char *)connInfo->info.bleInfo.deviceIdHash, UDID_HASH_LEN) != SOFTBUS_OK) {
                AUTH_LOGE(AUTH_CONN, "gen udid hash hex str err");
                return;
            }
            Anonymize(udidHash, &anonyUdidHash);
            Anonymize(connInfo->info.bleInfo.bleMac, &anonyMac);
            AUTH_LOGD(AUTH_CONN, "print AuthConninfo bleMac=**:**:**:**:%{public}s, udidhash=%{public}s", anonyMac,
                anonyUdidHash);
            AnonymizeFree(anonyMac);
            AnonymizeFree(anonyUdidHash);
            break;
        default:
            break;
    }
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

    AUTH_LOGE(AUTH_FSM, "auth manager not found. authId=%{public}" PRId64 "", authId);
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
        AUTH_LOGE(AUTH_CONN, "copy auth p2p mac fail, authId=%{public}" PRId64, auth->authId);
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t UpdateAuthManagerByAuthId(
    int64_t authId, int32_t (*updateFunc)(AuthManager *, const AuthManager *), const AuthManager *inAuth)
{
    if (!RequireAuthLock()) {
        return SOFTBUS_LOCK_ERR;
    }
    AuthManager *auth = FindAuthManagerByAuthId(authId);
    if (auth == NULL) {
        AUTH_LOGE(AUTH_FSM, "auth manager not found, authId=%{public}" PRId64, authId);
        ReleaseAuthLock();
        return SOFTBUS_AUTH_NOT_FOUND;
    }
    if (updateFunc(auth, inAuth) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "update auth manager fail, authId=%{public}" PRId64, authId);
        ReleaseAuthLock();
        return SOFTBUS_ERR;
    }
    ReleaseAuthLock();
    return SOFTBUS_OK;
}

static ConnectionAddrType ConvertAuthLinkTypeToConnect(AuthLinkType type)
{
    switch (type) {
        case AUTH_LINK_TYPE_WIFI:
            return CONNECTION_ADDR_WLAN;
        case AUTH_LINK_TYPE_BLE:
            return CONNECTION_ADDR_BLE;
        case AUTH_LINK_TYPE_BR:
            return CONNECTION_ADDR_BR;
        default:
            return CONNECTION_ADDR_MAX;
    }
}

void RemoveAuthSessionKeyByIndex(int64_t authId, int32_t index)
{
    if (!RequireAuthLock()) {
        return;
    }
    AuthManager *auth = FindAuthManagerByAuthId(authId);
    if (auth == NULL) {
        ReleaseAuthLock();
        AUTH_LOGI(AUTH_CONN, "auth manager already removed, authId=%{public}" PRId64, authId);
        return;
    }
    RemoveSessionkeyByIndex(&auth->sessionKeyList, index);
    bool keyClear = IsListEmpty(&auth->sessionKeyList);
    ConnectionAddrType connType = CONNECTION_ADDR_MAX;
    char networkId[NETWORK_ID_BUF_LEN] = { 0 };
    int32_t ret = SOFTBUS_ERR;
    if (keyClear) {
        connType = ConvertAuthLinkTypeToConnect(auth->connInfo.type);
        ret = LnnGetNetworkIdByUdid(auth->udid, networkId, sizeof(networkId));
    }
    char udid[UDID_BUF_LEN] = { 0 };
    AuthLinkType type = auth->connInfo.type;
    (void)memcpy_s(udid, UDID_BUF_LEN, auth->udid, UDID_BUF_LEN);
    ReleaseAuthLock();
    AuthRemoveDeviceKey(udid, type);
    if ((ret == SOFTBUS_OK) && (connType != CONNECTION_ADDR_MAX) && (keyClear)) {
        AUTH_LOGI(AUTH_CONN, "auth key clear empty, Lnn offline. authId=%{public}" PRId64, authId);
        LnnRequestLeaveSpecific(networkId, connType);
    }
}

void RemoveAuthManagerByAuthId(int64_t authId)
{
    if (!RequireAuthLock()) {
        return;
    }
    AuthManager *auth = FindAuthManagerByAuthId(authId);
    if (auth == NULL) {
        AUTH_LOGI(AUTH_CONN, "auth manager already removed, authId=%{public}" PRId64, authId);
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
        PrintAuthConnInfo(connInfo);
        ReleaseAuthLock();
        AUTH_LOGI(AUTH_CONN, "auth manager already removed, connType=%{public}d, side=%{public}s", connInfo->type,
            GetAuthSideStr(isServer));
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
        AUTH_LOGI(AUTH_CONN, "auth not found by uuid, connType=%{public}d", type);
        ReleaseAuthLock();
        return SOFTBUS_AUTH_NOT_FOUND;
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
        AUTH_LOGI(AUTH_FSM, "auth manager not found. authId=%{public}" PRId64 "", authId);
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
        PrintAuthConnInfo(connInfo);
        ReleaseAuthLock();
        AUTH_LOGI(AUTH_FSM, "auth manager not found, connType=%{public}d, side=%{public}s", connInfo->type,
            GetAuthSideStr(isServer));
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
        ReleaseAuthLock();
        AUTH_LOGI(AUTH_CONN, "auth manager not found, isServer=%{public}s, " CONN_INFO,
            GetAuthSideStr(isServer), CONN_DATA(connId));
        return AUTH_INVALID_ID;
    }
    authId = auth->authId;
    ReleaseAuthLock();
    return authId;
}

static int64_t GetLatestIdByConnInfo(const AuthConnInfo *connInfo, AuthLinkType type)
{
    if (connInfo == NULL) {
        AUTH_LOGE(AUTH_CONN, "connInfo is empty");
        return AUTH_INVALID_ID;
    }
    if (!RequireAuthLock()) {
        return SOFTBUS_LOCK_ERR;
    }
    uint32_t num = 0;
    const AuthManager *auth[2] = { NULL, NULL }; /* 2: client + server */
    auth[num++] = FindAuthManagerByConnInfo(connInfo, false);
    auth[num++] = FindAuthManagerByConnInfo(connInfo, true);
    int64_t latestAuthId = AUTH_INVALID_ID;
    uint64_t latestVerifyTime = 0;
    for (uint32_t i = 0; i < num; i++) {
        if (auth[i] != NULL && auth[i]->lastVerifyTime > latestVerifyTime && auth[i]->hasAuthPassed) {
            latestAuthId = auth[i]->authId;
            latestVerifyTime = auth[i]->lastVerifyTime;
        }
    }
    ReleaseAuthLock();
    AUTH_LOGD(AUTH_CONN,
        "latest auth manager found. num=%{public}d, latestAuthId=%{public}" PRId64 ", lastVerifyTime=%{public}" PRIu64
        ", type=%{public}d",
        num, latestAuthId, latestVerifyTime, type);
    return latestAuthId;
}

static int64_t GetAuthIdByConnInfo(const AuthConnInfo *connInfo, bool isServer)
{
    int64_t authId;
    if (!RequireAuthLock()) {
        return AUTH_INVALID_ID;
    }
    AuthManager *auth = FindAuthManagerByConnInfo(connInfo, isServer);
    if (auth == NULL) {
        AUTH_LOGE(AUTH_CONN, "auth manager not found, connType=%{public}d, side=%{public}s", connInfo->type,
            GetAuthSideStr(isServer));
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
    AuthManager *auth[2] = { NULL, NULL }; /* 2: client + server */
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
    uint32_t authMgrNum = sizeof(auth) / sizeof(auth[0]);
    for (uint32_t i = 0; i < authMgrNum; i++) {
        if (auth[i] == NULL) {
            continue;
        }
        if (auth[i] != NULL && auth[i]->lastVerifyTime > maxVerifyTime) {
            authId = auth[i]->authId;
        }
    }
    AUTH_LOGI(AUTH_CONN, "get active auth manager. authId=%{public}" PRId64 "", authId);
    ReleaseAuthLock();
    return authId;
}

static AuthManager *AuthManagerIsExist(int64_t authSeq, const AuthSessionInfo *info, bool *isNewCreated)
{
    AuthManager *auth = FindAuthManagerByConnInfo(&info->connInfo, info->isServer);
    if (auth == NULL) {
        auth = NewAuthManager(authSeq, info);
        if (auth == NULL) {
            AUTH_LOGE(AUTH_FSM, "new authManager create fail.");
            return NULL;
        }
        *isNewCreated = true;
    } else {
        if (auth->connId != info->connId && auth->connInfo.type == AUTH_LINK_TYPE_WIFI) {
            DisconnectAuthDevice(&auth->connId);
            auth->hasAuthPassed = false;
            AUTH_LOGI(AUTH_FSM, "auth manager may single device on line");
        }
    }
    auth->connId = info->connId;
    auth->lastAuthSeq = authSeq;
    auth->lastVerifyTime = GetCurrentTimeMs();
    auth->lastActiveTime = GetCurrentTimeMs();

    AUTH_LOGI(AUTH_FSM, "auth manager exist.");
    return auth;
}

int32_t AuthManagerSetSessionKey(int64_t authSeq, const AuthSessionInfo *info,
    const SessionKey *sessionKey, bool isConnect)
{
    AUTH_CHECK_AND_RETURN_RET_LOGE(info != NULL, SOFTBUS_INVALID_PARAM, AUTH_FSM, "info is NULL");
    AUTH_CHECK_AND_RETURN_RET_LOGE(sessionKey != NULL, SOFTBUS_INVALID_PARAM, AUTH_FSM, "sessionKey is NULL");
    AUTH_LOGI(AUTH_FSM, "SetSessionKey: authSeq=%{public}" PRId64 ", side=%{public}s, requestId=%{public}u", authSeq,
        GetAuthSideStr(info->isServer), info->requestId);
    if (!RequireAuthLock()) {
        return SOFTBUS_LOCK_ERR;
    }
    if (!isConnect && info->connInfo.type != AUTH_LINK_TYPE_BLE) {
        AUTH_LOGI(AUTH_FSM, "only support ble direct on line");
        ReleaseAuthLock();
        return SOFTBUS_OK;
    }

    bool isNewCreated = false;
    AuthManager *auth = AuthManagerIsExist(authSeq, info, &isNewCreated);
    if (auth == NULL) {
        AUTH_LOGE(AUTH_FSM, "auth manager does not exist.");
        ReleaseAuthLock();
        return SOFTBUS_ERR;
    }
    int32_t sessionKeyIndex = TO_INT32(authSeq);
    if ((info->isSupportFastAuth) && (info->version <= SOFTBUS_OLD_V2)) {
        sessionKeyIndex = TO_INT32(info->oldIndex);
    }
    if (AddSessionKey(&auth->sessionKeyList, sessionKeyIndex, sessionKey) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "failed to add a sessionkey");
        if (isNewCreated) {
            DelAuthManager(auth, true);
        }
        ReleaseAuthLock();
        return SOFTBUS_ERR;
    }
    if (auth->connInfo.type == AUTH_LINK_TYPE_WIFI && !auth->isServer) {
        ScheduleUpdateSessionKey(auth->authId, SCHEDULE_UPDATE_SESSION_KEY_PERIOD);
    }
    if (!isConnect) {
        auth->hasAuthPassed = true;
    }
    AUTH_LOGI(AUTH_FSM,
        "auth manager. authId=%{public}" PRId64 ", authSeq=%{public}" PRId64
        ", index=%{public}d, lastVerifyTime=%{public}" PRId64,
        auth->authId, authSeq, sessionKeyIndex, auth->lastVerifyTime);
    ReleaseAuthLock();
    return SOFTBUS_OK;
}

int32_t AuthManagerGetSessionKey(int64_t authSeq, const AuthSessionInfo *info, SessionKey *sessionKey)
{
    AUTH_CHECK_AND_RETURN_RET_LOGE(info != NULL, SOFTBUS_INVALID_PARAM, AUTH_FSM, "info is NULL");
    AUTH_CHECK_AND_RETURN_RET_LOGE(sessionKey != NULL, SOFTBUS_INVALID_PARAM, AUTH_FSM, "sessionKey is NULL");
    AUTH_LOGI(AUTH_FSM, "GetSessionKey: authSeq=%{public}" PRId64 ", side=%{public}s, requestId=%{public}u", authSeq,
        GetAuthSideStr(info->isServer), info->requestId);
    if (!RequireAuthLock()) {
        return SOFTBUS_LOCK_ERR;
    }
    AuthManager *auth = FindAuthManagerByConnInfo(&info->connInfo, info->isServer);
    if (auth == NULL) {
        PrintAuthConnInfo(&info->connInfo);
        AUTH_LOGI(AUTH_FSM, "auth manager not found, connType=%{public}d", info->connInfo.type);
        ReleaseAuthLock();
        return SOFTBUS_AUTH_NOT_FOUND;
    }
    if (GetSessionKeyByIndex(&auth->sessionKeyList, TO_INT32(authSeq), sessionKey) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "GetSessionKeyByIndex fail");
        ReleaseAuthLock();
        return SOFTBUS_AUTH_GET_SESSION_KEY_FAIL;
    }
    ReleaseAuthLock();
    return SOFTBUS_OK;
}

static void NotifyDeviceVerifyPassed(int64_t authId, const NodeInfo *nodeInfo)
{
    AuthManager *auth = GetAuthManagerByAuthId(authId);
    if (auth == NULL) {
        AUTH_LOGE(AUTH_FSM, "get auth manager failed");
        return;
    }
    if (auth->connInfo.type == AUTH_LINK_TYPE_P2P || auth->connInfo.type == AUTH_LINK_TYPE_ENHANCED_P2P) {
        /* P2P auth no need notify to LNN. */
        DelAuthManager(auth, false);
        return;
    }
    DelAuthManager(auth, false);

    /* notify LNN device verify pass. */
    if (g_verifyListener.onDeviceVerifyPass == NULL) {
        AUTH_LOGW(AUTH_FSM, "onDeviceVerifyPass not set");
        return;
    }
    g_verifyListener.onDeviceVerifyPass(authId, nodeInfo);
}

static void NotifyDeviceDisconnect(int64_t authId)
{
    if (g_verifyListener.onDeviceDisconnect == NULL) {
        AUTH_LOGW(AUTH_FSM, "onDeviceDisconnect not set");
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
        AUTH_LOGW(AUTH_HICHAIN, "onDeviceNotTrusted not set");
        return;
    }
    g_verifyListener.onDeviceNotTrusted(peerUdid);
    LnnHbOnTrustedRelationReduced();
    AuthRemoveDeviceKeyByUdid(peerUdid);
}

static void OnGroupCreated(const char *groupId, int32_t groupType)
{
    if (g_groupChangeListener.onGroupCreated != NULL) {
        g_groupChangeListener.onGroupCreated(groupId, groupType);
    }
}

static void OnGroupDeleted(const char *groupId)
{
    if (g_groupChangeListener.onGroupDeleted != NULL) {
        g_groupChangeListener.onGroupDeleted(groupId);
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
    return SOFTBUS_ERR;
}

static void DfxRecordLnnAuthStart(const AuthConnInfo *connInfo)
{
    LnnEventExtra extra = { 0 };
    LnnEventExtraInit(&extra);
    if (connInfo != NULL) {
        extra.authLinkType = connInfo->type;
    }
    LNN_EVENT(EVENT_SCENE_JOIN_LNN, EVENT_STAGE_AUTH, extra);
}

static int32_t StartVerifyDevice(uint32_t requestId, const AuthConnInfo *connInfo, const AuthVerifyCallback *verifyCb,
    const AuthConnCallback *connCb, bool isFastAuth)
{
    int64_t traceId = GenSeq(false);
    SoftbusHitraceStart(SOFTBUS_HITRACE_ID_VALID, (uint64_t)traceId);
    AUTH_LOGI(AUTH_CONN, "start verify device: requestId=%{public}u", requestId);
    if (!g_regDataChangeListener) {
        if (RetryRegTrustDataChangeListener() != SOFTBUS_OK) {
            AUTH_LOGE(AUTH_HICHAIN, "hichain regDataChangeListener failed");
            SoftbusHitraceStop();
            return SOFTBUS_AUTH_INIT_FAIL;
        }
        g_regDataChangeListener = true;
    }
    AuthRequest request;
    (void)memset_s(&request, sizeof(AuthRequest), 0, sizeof(AuthRequest));
    if (connCb != NULL) {
        request.connCb = *connCb;
    }
    if (verifyCb != NULL) {
        request.verifyCb = *verifyCb;
    }
    request.traceId = traceId;
    request.requestId = requestId;
    request.connInfo = *connInfo;
    request.authId = AUTH_INVALID_ID;
    request.type =
        (verifyCb == NULL && connInfo->type == AUTH_LINK_TYPE_BLE) ? REQUEST_TYPE_CONNECT : REQUEST_TYPE_VERIFY;
    request.addTime = GetCurrentTimeMs();
    request.isFastAuth = isFastAuth;
    uint32_t waitNum = AddAuthRequest(&request);
    if (waitNum == 0) {
        AUTH_LOGE(AUTH_CONN, "add verify request to list fail, requestId=%{public}u", requestId);
        SoftbusHitraceStop();
        return SOFTBUS_AUTH_INNER_ERR;
    }
    if (waitNum > 1) {
        AUTH_LOGI(
            AUTH_CONN, "wait last verify request complete, waitNum=%{public}u, requestId=%{public}u",
            waitNum, requestId);
        SoftbusHitraceStop();
        return SOFTBUS_OK;
    }
    if (ConnectAuthDevice(requestId, connInfo, CONN_SIDE_ANY) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "connect auth device failed: requestId=%{public}u", requestId);
        FindAndDelAuthRequestByConnInfo(requestId, connInfo);
        SoftbusHitraceStop();
        return SOFTBUS_AUTH_CONN_FAIL;
    }
    SoftbusHitraceStop();
    AUTH_LOGI(AUTH_CONN, "verify device succ. requestId=%{public}u", requestId);
    return SOFTBUS_OK;
}

static int32_t StartReconnectDevice(
    int64_t authId, const AuthConnInfo *connInfo, uint32_t requestId, const AuthConnCallback *connCb)
{
    AUTH_LOGI(AUTH_CONN, "start reconnect device. requestId=%{public}u, authId=%{public}" PRId64, requestId, authId);
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
    request.addTime = GetCurrentTimeMs();
    request.isFastAuth = true;
    if (AddAuthRequest(&request) == 0) {
        AUTH_LOGE(AUTH_CONN, "add reconnect request fail, requestId=%{public}u", requestId);
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
        AUTH_LOGI(AUTH_FSM, "auth request not found, only notify LNN to update nodeInfo");
        NotifyDeviceVerifyPassed(authId, nodeInfo);
        return;
    }
    do {
        if (CheckAuthConnCallback(&request.connCb)) {
            NotifyDeviceVerifyPassed(authId, nodeInfo);
            if (request.connInfo.type == AUTH_LINK_TYPE_WIFI || request.connInfo.type == AUTH_LINK_TYPE_P2P ||
                request.connInfo.type == AUTH_LINK_TYPE_ENHANCED_P2P) {
                PerformAuthConnCallback(request.requestId, SOFTBUS_OK, authId);
                DelAuthRequest(request.requestId);
                continue;
            }
            /* For open auth br/ble connection, reconnect to keep long-connection. */
            DelAuthRequest(request.requestId);
            if (StartReconnectDevice(authId, &request.connInfo, request.requestId, &request.connCb) != SOFTBUS_OK) {
                AUTH_LOGE(AUTH_CONN, "open auth reconnect fail");
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
        AUTH_LOGE(AUTH_FSM, "auth request not found");
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
    AUTH_LOGI(AUTH_CONN, "find another verify request in wait list, do verify again");
    if (ConnectAuthDevice(request.requestId, &request.connInfo, CONN_SIDE_ANY) != SOFTBUS_OK) {
        ReportAuthRequestFailed(request.requestId, SOFTBUS_AUTH_CONN_FAIL);
    }
}

static int32_t ComplementConnectionInfoIfNeed(AuthManager *auth, const char *udid)
{
    if (auth->connInfo.type != AUTH_LINK_TYPE_BLE) {
        return SOFTBUS_OK;
    }
    if (udid == NULL || strlen(udid) == 0) {
        AUTH_LOGE(AUTH_FSM, "invalid udid");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = SoftBusGenerateStrHash((unsigned char *)udid, strlen(udid),
        (unsigned char *)auth->connInfo.info.bleInfo.deviceIdHash);
    return ret;
}

void AuthManagerSetAuthPassed(int64_t authSeq, const AuthSessionInfo *info)
{
    int64_t authId;
    AUTH_CHECK_AND_RETURN_LOGE(info != NULL, AUTH_FSM, "info is null");
    AUTH_LOGI(AUTH_FSM, "SetAuthPassed: authSeq=%{public}" PRId64 ", side=%{public}s, requestId=%{public}u", authSeq,
        GetAuthSideStr(info->isServer), info->requestId);

    if (!RequireAuthLock()) {
        return;
    }
    AuthManager *auth = FindAuthManagerByConnInfo(&info->connInfo, info->isServer);
    if (auth == NULL) {
        PrintAuthConnInfo(&info->connInfo);
        ReleaseAuthLock();
        AUTH_LOGE(AUTH_FSM, "auth manager not found, connType=%{public}d, side=%{public}s", info->connInfo.type,
            GetAuthSideStr(info->isServer));
        return;
    }

    int32_t ret = ComplementConnectionInfoIfNeed(auth, info->nodeInfo.deviceInfo.deviceUdid);
    if (ret != SOFTBUS_OK) {
        ReleaseAuthLock();
        AUTH_LOGE(AUTH_FSM, "complement auth connection info failed, authSeq=%{public}" PRId64 ", ret=%{public}d",
            authSeq, ret);
        return;
    }

    auth->hasAuthPassed = true;
    if (info->nodeInfo.p2pInfo.p2pMac[0] != '\0') {
        if (strcpy_s(auth->p2pMac, sizeof(auth->p2pMac), info->nodeInfo.p2pInfo.p2pMac)) {
            AUTH_LOGE(AUTH_FSM, "copy p2pMac fail, authSeq=%{public}" PRId64, authSeq);
        }
    }
    authId = auth->authId;
    ReleaseAuthLock();

    if (info->isServer) {
        NotifyDeviceVerifyPassed(authId, &info->nodeInfo);
    } else {
        ReportAuthRequestPassed(info->requestId, authId, &info->nodeInfo);
        UpdateAuthDevicePriority(info->connId);
    }
}

void AuthManagerSetAuthFailed(int64_t authSeq, const AuthSessionInfo *info, int32_t reason)
{
    AUTH_CHECK_AND_RETURN_LOGE(info != NULL, AUTH_FSM, "auth session info is null");
    AUTH_LOGE(AUTH_FSM, "SetAuthFailed: authSeq=%{public}" PRId64 ", requestId=%{public}u, reason=%{public}d", authSeq,
        info->requestId, reason);
    AuthManager *auth = GetAuthManagerByConnInfo(&info->connInfo, info->isServer);
    bool needDisconnect = true;
    if (auth != NULL && reason == SOFTBUS_AUTH_TIMEOUT && info->connInfo.type == AUTH_LINK_TYPE_WIFI
        && info->connInfo.info.ipInfo.port != auth->connInfo.info.ipInfo.port) {
        AUTH_LOGE(AUTH_FSM, "auth manager port change, connType=%{public}d, side=%{public}s",
            info->connInfo.type, GetAuthSideStr(info->isServer));
        needDisconnect = false;
    }
    if (auth != NULL && auth->hasAuthPassed && needDisconnect) {
        AUTH_LOGE(AUTH_FSM, "update session key fail, authId=%{public}" PRId64, auth->authId);
        NotifyDeviceDisconnect(auth->authId);
    }
    DelAuthManager(auth, false);

    if (needDisconnect) {
        RemoveAuthManagerByConnInfo(&info->connInfo, info->isServer);
    }
    ReportAuthRequestFailed(info->requestId, reason);
    if (GetConnType(info->connId) == AUTH_LINK_TYPE_WIFI) {
        DisconnectAuthDevice((uint64_t *)&info->connId);
    } else if (!info->isServer) {
        /* Bluetooth networking only the client to close the connection. */
        UpdateAuthDevicePriority(info->connId);
        DisconnectAuthDevice((uint64_t *)&info->connId);
    }
}

static void HandleBleDisconnectDelay(const void *para)
{
    AUTH_CHECK_AND_RETURN_LOGE(para != NULL, AUTH_FSM, "para is null");
    uint64_t connId = *((uint64_t *)para);
    DisconnectAuthDevice(&connId);
}

static void BleDisconnectDelay(uint64_t connId, uint64_t delayMs)
{
    (void)PostAuthEvent(EVENT_BLE_DISCONNECT_DELAY, HandleBleDisconnectDelay, &connId, sizeof(connId), delayMs);
}

void AuthManagerSetAuthFinished(int64_t authSeq, const AuthSessionInfo *info)
{
    AUTH_CHECK_AND_RETURN_LOGE(info != NULL, AUTH_FSM, "auth session info is null");
    AUTH_LOGI(AUTH_FSM, "SetAuthFinished: authSeq=%{public}" PRId64 ", requestId=%{public}u", authSeq, info->requestId);
    if (info->isServer) {
        AUTH_LOGI(AUTH_FSM, "SERVER: wait client close connection");
        return;
    }
    /* br and ble NOT long-connection, close connection after auth pass. */
    if (info->connInfo.type == AUTH_LINK_TYPE_BLE) {
        uint64_t localFeature;
        int32_t ret = LnnGetLocalNumU64Info(NUM_KEY_FEATURE_CAPA, &localFeature);
        if (ret != SOFTBUS_OK) {
            AUTH_LOGE(AUTH_FSM, "ret=%{public}d, local=%{public}" PRIu64, ret, localFeature);
            return;
        }
        if (info->connInfo.info.bleInfo.protocol == BLE_GATT &&
            IsFeatureSupport(localFeature, BIT_BLE_ONLINE_REUSE_CAPABILITY) &&
            IsFeatureSupport(info->nodeInfo.feature, BIT_BLE_ONLINE_REUSE_CAPABILITY)) {
            AUTH_LOGI(
                AUTH_FSM, "support ble reuse, bleConnCloseDelayTime=%{public}ds", info->nodeInfo.bleConnCloseDelayTime);
            BleDisconnectDelay(info->connId, info->nodeInfo.bleConnCloseDelayTime);
        } else {
            AUTH_LOGI(AUTH_FSM, "ble disconn now");
            DisconnectAuthDevice((uint64_t *)&info->connId);
        }
    }
    if (info->connInfo.type == AUTH_LINK_TYPE_BR) {
        AUTH_LOGI(AUTH_FSM, "br disconn now");
        DisconnectAuthDevice((uint64_t *)&info->connId);
    }
}

static void HandleReconnectResult(const AuthRequest *request, uint64_t connId, int32_t result)
{
    if (result != SOFTBUS_OK) {
        PerformAuthConnCallback(request->requestId, result, AUTH_INVALID_ID);
        DelAuthRequest(request->requestId);
        return;
    }
    AuthManager inAuth = { .connId = connId };
    if (UpdateAuthManagerByAuthId(request->authId, SetAuthConnId, &inAuth) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "set auth connId fail, requestId=%{public}u", request->requestId);
        PerformAuthConnCallback(request->requestId, SOFTBUS_AUTH_NOT_FOUND, AUTH_INVALID_ID);
        DelAuthRequest(request->requestId);
        return;
    }
    PerformAuthConnCallback(request->requestId, SOFTBUS_OK, request->authId);
    DelAuthRequest(request->requestId);
}

static void HandleBleConnectResult(uint32_t requestId, int64_t authId, uint64_t connId, int32_t result)
{
    AuthRequest request;
    if (GetAuthRequest(requestId, &request) != SOFTBUS_OK) {
        AUTH_LOGI(AUTH_CONN, "get request info failed, requestId=%{public}u", requestId);
        return;
    }
    AuthManager inAuth = { .connId = connId };
    if (UpdateAuthManagerByAuthId(authId, SetAuthConnId, &inAuth) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "set auth connId fail, requestId=%{public}u", requestId);
        return;
    }
    do {
        if (result != SOFTBUS_OK) {
            PerformAuthConnCallback(request.requestId, result, AUTH_INVALID_ID);
        } else {
            PerformAuthConnCallback(request.requestId, SOFTBUS_OK, authId);
        }
        DelAuthRequest(request.requestId);
    } while (FindAuthRequestByConnInfo(&request.connInfo, &request) == SOFTBUS_OK);
}

static void DfxRecordLnnConnectEnd(uint64_t connId, const AuthConnInfo *connInfo, int32_t reason)
{
    LnnEventExtra extra = { 0 };
    LnnEventExtraInit(&extra);
    extra.connectionId = (int32_t)connId;
    extra.errcode = reason;
    extra.result = (reason == SOFTBUS_OK) ? EVENT_STAGE_RESULT_OK : EVENT_STAGE_RESULT_FAILED;

    if (connInfo != NULL) {
        extra.authLinkType = connInfo->type;
    }
    LNN_EVENT(EVENT_SCENE_JOIN_LNN, EVENT_STAGE_AUTH_CONNECTION, extra);
}

static void OnConnectResult(uint32_t requestId, uint64_t connId, int32_t result, const AuthConnInfo *connInfo)
{
    DfxRecordLnnConnectEnd(connId, connInfo, result);
    AUTH_LOGI(AUTH_CONN, "OnConnectResult: requestId=%{public}u, result=%{public}d", requestId, result);
    AuthRequest request;
    if (GetAuthRequest(requestId, &request) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "request not found, requestId=%{public}u", requestId);
        return;
    }
    SoftbusHitraceStart(SOFTBUS_HITRACE_ID_VALID, (uint64_t)request.traceId);
    if (request.type == REQUEST_TYPE_RECONNECT) {
        HandleReconnectResult(&request, connId, result);
        SoftbusHitraceStop();
        return;
    }

    if (result != SOFTBUS_OK) {
        ReportAuthRequestFailed(requestId, result);
        SoftbusHitraceStop();
        return;
    }
    if ((connInfo != NULL) && (connInfo->type == AUTH_LINK_TYPE_BLE) && (request.type == REQUEST_TYPE_CONNECT)) {
        int64_t authId = GetLatestIdByConnInfo(connInfo, connInfo->type);
        if (authId != AUTH_INVALID_ID) {
            HandleBleConnectResult(requestId, authId, connId, result);
            SoftbusHitraceStop();
            return;
        }
    }
    int32_t ret = AuthSessionStartAuth(request.traceId, requestId, connId, connInfo, false, request.isFastAuth);
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "start auth session fail=%{public}d, requestId=%{public}u", ret, requestId);
        DisconnectAuthDevice(&connId);
        ReportAuthRequestFailed(requestId, ret);
        SoftbusHitraceStop();
        return;
    }
    SoftbusHitraceStop();
}

static void HandleDeviceIdData(
    uint64_t connId, const AuthConnInfo *connInfo, bool fromServer, const AuthDataHead *head, const uint8_t *data)
{
    int32_t ret;
    if (head->flag == CLIENT_SIDE_FLAG) {
        if (!GetConfigSupportAsServer()) {
            AUTH_LOGE(AUTH_FSM, "local device NOT support as server, ignore auth seq=%{public}" PRId64, head->seq);
            return;
        }
        AuthFsm *fsm = GetAuthFsmByConnId(connId, true);
        if ((fsm != NULL && fsm->info.idType == EXCHANGE_NETWORKID) ||
            (fsm != NULL && fsm->info.idType == EXCHANGE_FAIL)) {
            ret = AuthSessionProcessDevIdData(head->seq, data, head->len);
            if (ret != SOFTBUS_OK) {
                AUTH_LOGE(AUTH_FSM,
                    "perform auth session recv devId fail. seq=%{public}" PRId64 ", ret=%{public}d", head->seq, ret);
            }
            return;
        }
        if (fsm != NULL && fsm->info.idType == EXCHANHE_UDID) {
            AUTH_LOGE(AUTH_FSM, "the same connId fsm not support, ignore auth seq=%{public}" PRId64, head->seq);
            HandleRepeatDeviceIdDataDelay(connId, connInfo, fromServer, head, data);
            return;
        }
        ret = AuthSessionStartAuth(head->seq, AuthGenRequestId(), connId, connInfo, true, true);
        if (ret != SOFTBUS_OK) {
            AUTH_LOGE(AUTH_FSM,
                "perform auth session start auth fail. seq=%{public}" PRId64 ", ret=%{public}d", head->seq, ret);
            return;
        }
    }
    ret = AuthSessionProcessDevIdData(head->seq, data, head->len);
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM,
            "perform auth session recv devId fail. seq=%{public}" PRId64 ", ret=%{public}d", head->seq, ret);
        return;
    }
}

static void HandleAuthData(const AuthConnInfo *connInfo, const AuthDataHead *head, const uint8_t *data)
{
    int32_t ret = AuthSessionProcessAuthData(head->seq, data, head->len);
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM,
            "perform auth session recv authData fail. seq=%{public}" PRId64 ", ret=%{public}d", head->seq, ret);
        return;
    }
}

static void FlushDeviceProcess(const AuthConnInfo *connInfo, bool isServer)
{
    if (!RequireAuthLock()) {
        return;
    }
    AuthManager *auth = FindAuthManagerByConnInfo(connInfo, isServer);
    if (auth == NULL) {
        PrintAuthConnInfo(connInfo);
        ReleaseAuthLock();
        AUTH_LOGE(AUTH_FSM, "auth manager not found");
        return;
    }
    if (PostVerifyDeviceMessage(auth, FLAG_REPLY) == SOFTBUS_OK) {
        AUTH_LOGI(AUTH_FSM, "post flush device ok");
    }
    ReleaseAuthLock();
    return;
}

static void HandleDeviceInfoData(
    uint64_t connId, const AuthConnInfo *connInfo, bool fromServer, const AuthDataHead *head, const uint8_t *data)
{
    int32_t ret = SOFTBUS_OK;
    if (IsFlushDevicePacket(connInfo, head, data, !fromServer)) {
        if (head->flag == 0) {
            AUTH_LOGE(AUTH_FSM, "flush device need relay");
            FlushDeviceProcess(connInfo, !fromServer);
        } else {
            AUTH_LOGE(AUTH_FSM, "flush device not need relay");
        }
        return;
    }

    if (AuthSessionProcessDevInfoData(head->seq, data, head->len) != SOFTBUS_OK) {
        /* To be compatible with ohos-3.1 and early. */
        AUTH_LOGI(AUTH_FSM,
            "auth processDeviceInfo. type=0x%{public}x, module=%{public}d, seq=%{public}" PRId64 ", "
            "flag=%{public}d, len=%{public}u, " CONN_INFO ", fromServer=%{public}s",
            head->dataType, head->module, head->seq, head->flag, head->len, CONN_DATA(connId),
            GetAuthSideStr(fromServer));
        ret = AuthSessionProcessDevInfoDataByConnId(connId, !fromServer, data, head->len);
    }
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "perform auth session recv devInfo fail. seq=%{public}" PRId64 ", ret=%{public}d",
            head->seq, ret);
        return;
    }
}

static void HandleCloseAckData(
    uint64_t connId, const AuthConnInfo *connInfo, bool fromServer, const AuthDataHead *head, const uint8_t *data)
{
    int32_t ret;
    if (head->seq != 0) {
        ret = AuthSessionProcessCloseAck(head->seq, data, head->len);
    } else {
        /* To be compatible with nearby. */
        ret = AuthSessionProcessCloseAckByConnId(connId, !fromServer, data, head->len);
    }
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "perform auth session recv closeAck fail. seq=%{public}" PRId64 ", ret=%{public}d",
            head->seq, ret);
        return;
    }
}

static void HandleConnectionData(
    uint64_t connId, const AuthConnInfo *connInfo, bool fromServer, const AuthDataHead *head, const uint8_t *data)
{
    if (!RequireAuthLock()) {
        return;
    }
    AuthManager *auth = FindAuthManagerByConnInfo(connInfo, !fromServer);
    if (auth == NULL) {
        PrintAuthConnInfo(connInfo);
        AUTH_LOGE(AUTH_CONN, "AuthManager not found, connType=%{public}d", connInfo->type);
        ReleaseAuthLock();
        return;
    }
    int64_t authId = auth->authId;
    uint8_t *decData = NULL;
    uint32_t decDataLen = 0;
    if (DecryptInner(&auth->sessionKeyList, data, head->len, &decData, &decDataLen) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "decrypt trans data fail");
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

static void OnDataReceived(
    uint64_t connId, const AuthConnInfo *connInfo, bool fromServer, const AuthDataHead *head, const uint8_t *data)
{
    if (connInfo == NULL || head == NULL || data == NULL) {
        AUTH_LOGE(AUTH_CONN, "invalid param");
        return;
    }
    SoftbusHitraceStart(SOFTBUS_HITRACE_ID_VALID, (uint64_t)head->seq);
    AUTH_LOGI(AUTH_CONN,
        "auth recv data. type=0x%{public}x, module=%{public}d, seq=%{public}" PRId64 ", "
        "flag=%{public}d, len=%{public}u, " CONN_INFO ", fromServer=%{public}s",
        head->dataType, head->module, head->seq, head->flag, head->len, CONN_DATA(connId), GetAuthSideStr(fromServer));
    switch (head->dataType) {
        case DATA_TYPE_DEVICE_ID:
            HandleDeviceIdData(connId, connInfo, fromServer, head, data);
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
    SoftbusHitraceStop();
}

static void HandleDisconnectedEvent(const void *para)
{
    AUTH_CHECK_AND_RETURN_LOGE(para != NULL, AUTH_FSM, "para is null");
    uint64_t connId = *((uint64_t *)para);
    uint32_t num = 0;
    uint64_t dupConnId = connId;
    int64_t authIds[2]; /* 2: client and server may use same connection. */
    authIds[num++] = GetAuthIdByConnId(connId, false);
    authIds[num++] = GetAuthIdByConnId(connId, true);
    for (uint32_t i = 0; i < num; i++) {
        if (authIds[i] == AUTH_INVALID_ID) {
            continue;
        }
        if (g_transCallback.OnDisconnected != NULL) {
            g_transCallback.OnDisconnected(authIds[i]);
        }
        if (GetConnType(connId) == AUTH_LINK_TYPE_WIFI || GetConnType(connId) == AUTH_LINK_TYPE_P2P ||
            GetConnType(connId) == AUTH_LINK_TYPE_ENHANCED_P2P) {
            NotifyDeviceDisconnect(authIds[i]);
            DisconnectAuthDevice(&dupConnId);
            AuthManager inAuth = { .connId = dupConnId };
            (void)UpdateAuthManagerByAuthId(authIds[i], SetAuthConnId, &inAuth);
            RemoveAuthManagerByAuthId(authIds[i]);
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

uint32_t AuthGenRequestId(void)
{
    return ConnGetNewRequestId(MODULE_DEVICE_AUTH);
}

int32_t AuthStartVerify(const AuthConnInfo *connInfo, uint32_t requestId,
    const AuthVerifyCallback *callback, bool isFastAuth)
{
    DfxRecordLnnAuthStart(connInfo);
    if (connInfo == NULL || !CheckVerifyCallback(callback)) {
        AUTH_LOGE(AUTH_CONN, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    return StartVerifyDevice(requestId, connInfo, callback, NULL, isFastAuth);
}

void AuthHandleLeaveLNN(int64_t authId)
{
    AUTH_LOGI(AUTH_FSM, "auth handle leave LNN, authId=%{public}" PRId64, authId);
    if (!RequireAuthLock()) {
        return;
    }
    AuthManager *auth = FindAuthManagerByAuthId(authId);
    if (auth == NULL) {
        ReleaseAuthLock();
        AUTH_LOGE(AUTH_FSM, "auth manager not found, authId=%{public}" PRId64, authId);
        return;
    }
    if (!auth->hasAuthPassed) {
        ReleaseAuthLock();
        AUTH_LOGI(AUTH_FSM, "auth pass = false, don't need to leave");
        return;
    }
    if (auth->connInfo.type == AUTH_LINK_TYPE_WIFI) {
        DisconnectAuthDevice(&auth->connId);
    }
    DelAuthManager(auth, true);
    ReleaseAuthLock();
}

int32_t AuthFlushDevice(const char *uuid)
{
    if (uuid == NULL || uuid[0] == '\0') {
        AUTH_LOGE(AUTH_CONN, "uuid is empty");
        return SOFTBUS_INVALID_PARAM;
    }
    if (!RequireAuthLock()) {
        return SOFTBUS_LOCK_ERR;
    }
    uint32_t num = 0;
    int32_t ret = SOFTBUS_ERR;
    AuthManager *auth[2] = { NULL, NULL }; /* 2: WiFi * (Client + Server) */
    auth[num++] = FindAuthManagerByUuid(uuid, AUTH_LINK_TYPE_WIFI, false);
    auth[num++] = FindAuthManagerByUuid(uuid, AUTH_LINK_TYPE_WIFI, true);
    for (uint32_t i = 0; i < num; i++) {
        if (auth[i] == NULL) {
            continue;
        }
        if (PostVerifyDeviceMessage(auth[i], FLAG_ACTIVE) == SOFTBUS_OK) {
            ret = SOFTBUS_OK;
        }
    }
    ReleaseAuthLock();
    return ret;
}

static int32_t TryGetBrConnInfo(const char *uuid, AuthConnInfo *connInfo)
{
    char networkId[NETWORK_ID_BUF_LEN] = { 0 };
    if (LnnGetNetworkIdByUuid(uuid, networkId, sizeof(networkId)) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "get networkdId by uuid fail");
        return SOFTBUS_AUTH_GET_BR_CONN_INFO_FAIL;
    }

    uint32_t local, remote;
    if (LnnGetLocalNumInfo(NUM_KEY_NET_CAP, (int32_t *)&local) != SOFTBUS_OK ||
        LnnGetRemoteNumInfo(networkId, NUM_KEY_NET_CAP, (int32_t *)&remote) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "get NET_CAP fail");
        return SOFTBUS_AUTH_GET_BR_CONN_INFO_FAIL;
    }
    if (((local & (1 << BIT_BR)) == 0) || ((remote & (1 << BIT_BR)) == 0)) {
        AUTH_LOGW(AUTH_CONN, "can't support BR");
        return SOFTBUS_AUTH_GET_BR_CONN_INFO_FAIL;
    }
    if (LnnGetRemoteStrInfo(networkId, STRING_KEY_BT_MAC, connInfo->info.brInfo.brMac, BT_MAC_LEN) != SOFTBUS_OK ||
        connInfo->info.brInfo.brMac[0] == '\0') {
        AUTH_LOGE(AUTH_CONN, "get bt mac fail");
        return SOFTBUS_AUTH_GET_BR_CONN_INFO_FAIL;
    }
    connInfo->type = AUTH_LINK_TYPE_BR;
    return SOFTBUS_OK;
}

int32_t AuthDeviceGetPreferConnInfo(const char *uuid, AuthConnInfo *connInfo)
{
    if (uuid == NULL || uuid[0] == '\0' || connInfo == NULL) {
        AUTH_LOGE(AUTH_CONN, "invalid uuid or connInfo");
        return SOFTBUS_INVALID_PARAM;
    }
    AuthLinkType linkList[] = { AUTH_LINK_TYPE_WIFI, AUTH_LINK_TYPE_BR, AUTH_LINK_TYPE_BLE };
    uint32_t linkTypeNum = sizeof(linkList) / sizeof(linkList[0]);
    for (uint32_t i = 0; i < linkTypeNum; i++) {
        if (GetAuthConnInfoByUuid(uuid, linkList[i], connInfo) != SOFTBUS_OK) {
            continue;
        }
        if (linkList[i] == AUTH_LINK_TYPE_BLE) {
            if (!CheckActiveAuthConnection(connInfo)) {
                AUTH_LOGI(AUTH_CONN, "auth ble connection not active");
                continue;
            }
        }
        AUTH_LOGI(AUTH_CONN, "select auth type. i=%{public}d, linkList[i]=%{public}d", i, linkList[i]);
        return SOFTBUS_OK;
    }
    AUTH_LOGI(AUTH_CONN, "no active auth, try br connection");
    return TryGetBrConnInfo(uuid, connInfo);
}

int32_t AuthDeviceGetP2pConnInfo(const char *uuid, AuthConnInfo *connInfo)
{
    if (uuid == NULL || uuid[0] == '\0' || connInfo == NULL) {
        AUTH_LOGE(AUTH_CONN, "invalid uuid or connInfo");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = GetAuthConnInfoByUuid(uuid, AUTH_LINK_TYPE_ENHANCED_P2P, connInfo);
    if (ret == SOFTBUS_OK) {
        AUTH_LOGI(AUTH_CONN, "select auth type=%{public}d", AUTH_LINK_TYPE_ENHANCED_P2P);
    }
    return ret;
}

bool AuthDeviceCheckConnInfo(const char *uuid, AuthLinkType type, bool checkConnection)
{
    AUTH_CHECK_AND_RETURN_RET_LOGE(uuid, false, AUTH_CONN, "invalid null uuid");
    AUTH_CHECK_AND_RETURN_RET_LOGE(uuid[0] != '\0', false, AUTH_CONN, "invalid empty uuid");

    AuthConnInfo connInfo;
    (void)memset_s(&connInfo, sizeof(connInfo), 0, sizeof(connInfo));
    if (GetAuthConnInfoByUuid(uuid, type, &connInfo) != SOFTBUS_OK) {
        return false;
    }
    return checkConnection ? CheckActiveAuthConnection(&connInfo) : true;
}

int32_t AuthDeviceOpenConn(const AuthConnInfo *info, uint32_t requestId, const AuthConnCallback *callback)
{
    if (info == NULL || !CheckAuthConnCallback(callback)) {
        AUTH_LOGE(AUTH_CONN, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    AUTH_LOGI(AUTH_CONN, "open auth conn: connType=%{public}d, requestId=%{public}u", info->type, requestId);
    int64_t authId;
    switch (info->type) {
        case AUTH_LINK_TYPE_WIFI:
            authId = GetLatestIdByConnInfo(info, AUTH_LINK_TYPE_WIFI);
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
            return StartVerifyDevice(requestId, info, NULL, callback, true);
        case AUTH_LINK_TYPE_ENHANCED_P2P:
            authId = GetActiveAuthIdByConnInfo(info);
            if (authId != AUTH_INVALID_ID) {
                AUTH_LOGI(AUTH_CONN, "reuse enhanced p2p authId=%{public}" PRId64, authId);
                callback->onConnOpened(requestId, authId);
                break;
            }
            return StartVerifyDevice(requestId, info, NULL, callback, true);
        default:
            AUTH_LOGE(AUTH_CONN, "unknown connType. type=%{public}d", info->type);
            return SOFTBUS_INVALID_PARAM;
    }
    return SOFTBUS_OK;
}

void AuthDeviceCloseConn(int64_t authId)
{
    AUTH_LOGI(AUTH_CONN, "close auth conn: authId=%{public}" PRId64, authId);
    AuthManager *auth = GetAuthManagerByAuthId(authId);
    if (auth == NULL) {
        return;
    }
    switch (auth->connInfo.type) {
        case AUTH_LINK_TYPE_WIFI:
        case AUTH_LINK_TYPE_P2P:
        case AUTH_LINK_TYPE_ENHANCED_P2P:
            /* Do nothing. */
            break;
        case AUTH_LINK_TYPE_BR:
        case AUTH_LINK_TYPE_BLE:
            DisconnectAuthDevice(&auth->connId);
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
        AUTH_LOGE(AUTH_CONN, "dataInfo is null");
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
    head.len = 0;
    uint8_t *encData = NULL;
    if (EncryptInner(&auth->sessionKeyList, dataInfo->data, dataInfo->len, &encData, &head.len) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_KEY, "encrypt trans data fail");
        DelAuthManager(auth, false);
        return SOFTBUS_ENCRYPT_ERR;
    }
    if (PostAuthData(auth->connId, !auth->isServer, &head, encData) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "post trans data fail");
        SoftBusFree(encData);
        DelAuthManager(auth, false);
        return SOFTBUS_AUTH_SEND_FAIL;
    }
    SoftBusFree(encData);
    DelAuthManager(auth, false);
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

int32_t AuthGetLatestAuthSeqList(const char *udid, int64_t *seqList, uint32_t num)
{
    if (udid == NULL || udid[0] == '\0' || seqList == NULL || num != DISCOVERY_TYPE_COUNT) {
        AUTH_LOGE(AUTH_CONN, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (!RequireAuthLock()) {
        return SOFTBUS_LOCK_ERR;
    }
    bool notFound = true;
    AuthManager *authClient = NULL;
    AuthManager *authServer = NULL;
    AuthLinkType linkList[] = { AUTH_LINK_TYPE_WIFI, AUTH_LINK_TYPE_BLE, AUTH_LINK_TYPE_BR };
    for (size_t i = 0; i < sizeof(linkList) / sizeof(AuthLinkType); i++) {
        authClient = FindAuthManagerByUdid(udid, linkList[i], false);
        authServer = FindAuthManagerByUdid(udid, linkList[i], true);
        if (authClient == NULL && authServer == NULL) {
            seqList[ConvertToDiscoveryType(linkList[i])] = 0;
            continue;
        }
        notFound = false;
        if (authClient != NULL && authServer == NULL) {
            seqList[ConvertToDiscoveryType(linkList[i])] = authClient->lastAuthSeq;
        } else if (authClient == NULL && authServer != NULL) {
            seqList[ConvertToDiscoveryType(linkList[i])] = authServer->lastAuthSeq;
        } else if (authClient->lastVerifyTime >= authServer->lastVerifyTime) {
            seqList[ConvertToDiscoveryType(linkList[i])] = authClient->lastAuthSeq;
        } else {
            seqList[ConvertToDiscoveryType(linkList[i])] = authServer->lastAuthSeq;
        }
    }
    if (notFound) {
        ReleaseAuthLock();
        char *anonyUdid = NULL;
        Anonymize(udid, &anonyUdid);
        AUTH_LOGE(AUTH_CONN, "not found active authManager, udid=%{public}s", anonyUdid);
        AnonymizeFree(anonyUdid);
        return SOFTBUS_AUTH_NOT_FOUND;
    }
    ReleaseAuthLock();
    return SOFTBUS_OK;
}

int64_t AuthDeviceGetLatestIdByUuid(const char *uuid, AuthLinkType type)
{
    if (uuid == NULL || uuid[0] == '\0') {
        AUTH_LOGE(AUTH_CONN, "uuid is empty");
        return AUTH_INVALID_ID;
    }
    if (!RequireAuthLock()) {
        return SOFTBUS_LOCK_ERR;
    }
    uint32_t num = 0;
    AuthManager *auth[4] = { NULL, NULL, NULL, NULL }; /* 4: max size for (BR + BLE) * (CLIENT+ SERVER) */
    if ((type == AUTH_LINK_TYPE_WIFI) || (type == AUTH_LINK_TYPE_BLE)) {
        auth[num++] = FindAuthManagerByUuid(uuid, type, false);
        auth[num++] = FindAuthManagerByUuid(uuid, type, true);
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
    char *anonyUuid = NULL;
    Anonymize(uuid, &anonyUuid);
    AUTH_LOGI(AUTH_CONN,
        "latest auth manager found, latestAuthId=%{public}" PRId64 ", lastVerifyTime=%{public}" PRIu64
        ", uuid=%{public}s, type=%{public}d",
        latestAuthId, latestVerifyTime, anonyUuid, type);
    AnonymizeFree(anonyUuid);
    return latestAuthId;
}

int64_t AuthDeviceGetIdByConnInfo(const AuthConnInfo *connInfo, bool isServer)
{
    if (connInfo == NULL) {
        AUTH_LOGE(AUTH_CONN, "connInfo is null");
        return AUTH_INVALID_ID;
    }
    return GetAuthIdByConnInfo(connInfo, isServer);
}

int64_t AuthDeviceGetIdByUuid(const char *uuid, AuthLinkType type, bool isServer)
{
    if (uuid == NULL || uuid[0] == '\0') {
        AUTH_LOGE(AUTH_FSM, "uuid is empty");
        return AUTH_INVALID_ID;
    }
    if (!RequireAuthLock()) {
        return AUTH_INVALID_ID;
    }
    AuthManager *auth = FindAuthManagerByUuid(uuid, type, isServer);
    if (auth == NULL) {
        AUTH_LOGE(
            AUTH_CONN, "not found auth manager, connType=%{public}d, side=%{public}s", type, GetAuthSideStr(isServer));
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
        AUTH_LOGE(AUTH_KEY, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    AuthManager *auth = GetAuthManagerByAuthId(authId);
    if (auth == NULL) {
        return SOFTBUS_AUTH_NOT_FOUND;
    }
    if (EncryptData(&auth->sessionKeyList, inData, inLen, outData, outLen) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_KEY, "auth encrypt fail");
        DelAuthManager(auth, false);
        return SOFTBUS_ENCRYPT_ERR;
    }
    DelAuthManager(auth, false);
    return SOFTBUS_OK;
}

int32_t AuthDeviceDecrypt(int64_t authId, const uint8_t *inData, uint32_t inLen, uint8_t *outData, uint32_t *outLen)
{
    if (inData == NULL || inLen == 0 || outData == NULL || outLen == NULL || *outLen < AuthGetDecryptSize(inLen)) {
        AUTH_LOGE(AUTH_KEY, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    AuthManager *auth = GetAuthManagerByAuthId(authId);
    if (auth == NULL) {
        return SOFTBUS_AUTH_NOT_FOUND;
    }
    if (DecryptData(&auth->sessionKeyList, inData, inLen, outData, outLen) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_KEY, "auth decrypt fail");
        DelAuthManager(auth, false);
        return SOFTBUS_ENCRYPT_ERR;
    }
    DelAuthManager(auth, false);
    return SOFTBUS_OK;
}

int32_t AuthDeviceSetP2pMac(int64_t authId, const char *p2pMac)
{
    if (p2pMac == NULL || p2pMac[0] == '\0') {
        AUTH_LOGE(AUTH_CONN, "p2pMac is empty");
        return SOFTBUS_INVALID_PARAM;
    }
    AuthManager inAuth = { 0 };
    if (strcpy_s(inAuth.p2pMac, sizeof(inAuth.p2pMac), p2pMac) != EOK) {
        AUTH_LOGE(AUTH_CONN, "copy p2pMac fail, authId=%{public}" PRId64, authId);
        return SOFTBUS_MEM_ERR;
    }
    return UpdateAuthManagerByAuthId(authId, SetAuthP2pMac, &inAuth);
}

int32_t AuthDeviceGetConnInfo(int64_t authId, AuthConnInfo *connInfo)
{
    if (connInfo == NULL) {
        AUTH_LOGE(AUTH_CONN, "connInfo is null");
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
        AUTH_LOGE(AUTH_CONN, "isServer is null");
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
        AUTH_LOGE(AUTH_CONN, "uuid is empty");
        return SOFTBUS_INVALID_PARAM;
    }
    AuthManager *auth = GetAuthManagerByAuthId(authId);
    if (auth == NULL) {
        return SOFTBUS_AUTH_NOT_FOUND;
    }
    if (strcpy_s(uuid, size, auth->uuid) != EOK) {
        AUTH_LOGI(AUTH_CONN, "copy uuid fail, size=%{public}u", size);
        DelAuthManager(auth, false);
        return SOFTBUS_ERR;
    }
    DelAuthManager(auth, false);
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
    DelAuthManager(auth, false);
    return SOFTBUS_OK;
}

static void RegisterToDpDelay(void *para)
{
    DeviceProfileChangeListener deviceProfileChangeListener = {
        .onDeviceProfileAdd = OnDeviceBound,
        .onDeviceProfileDeleted = OnDeviceNotTrusted,
    };
    RegisterToDp(&deviceProfileChangeListener);
}

int32_t AuthDeviceInit(const AuthTransCallback *callback)
{
    AUTH_LOGI(AUTH_INIT, "auth init enter");
    if (callback == NULL) {
        AUTH_LOGE(AUTH_INIT, "Auth notify trans callback is null");
        return SOFTBUS_INVALID_PARAM;
    }
    g_transCallback = *callback;
    ListInit(&g_authClientList);
    ListInit(&g_authServerList);
    if (AuthCommonInit() != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_INIT, "AuthCommonInit fail");
        return SOFTBUS_ERR;
    }

    AuthConnListener connListener = {
        .onConnectResult = OnConnectResult,
        .onDisconnected = OnDisconnected,
        .onDataReceived = OnDataReceived,
    };
    if (AuthConnInit(&connListener) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_INIT, "AuthConnInit fail");
        AuthCommonDeinit();
        return SOFTBUS_ERR;
    }
    if (LnnAsyncCallbackDelayHelper(GetLooper(LOOP_TYPE_DEFAULT), RegisterToDpDelay, NULL, DELAY_REG_DP_TIME) !=
        SOFTBUS_OK) {
        AUTH_LOGE(AUTH_INIT, "delay registertoDp failed");
        return SOFTBUS_AUTH_INIT_FAIL;
    }
    AUTH_LOGI(AUTH_INIT, "auth init succ");
    return SOFTBUS_OK;
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

void AuthDeviceDeinit(void)
{
    AUTH_LOGI(AUTH_INIT, "auth deinit enter");
    UnregTrustDataChangeListener();
    UnRegHichainSaStatusListener();
    DestroyAuthManagerList();
    ClearAuthRequest();
    AuthConnDeinit();
    AuthSessionFsmExit();
    AuthCommonDeinit();
    AUTH_LOGI(AUTH_INIT, "auth deinit succ");
}