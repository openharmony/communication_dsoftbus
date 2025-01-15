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
#include "auth_device_common_key.h"
#include "auth_hichain.h"
#include "auth_interface.h"
#include "auth_log.h"
#include "auth_normalize_request.h"
#include "auth_request.h"
#include "auth_session_fsm.h"
#include "auth_session_message.h"
#include "auth_tcp_connection.h"
#include "bus_center_manager.h"
#include "device_profile_listener.h"
#include "lnn_app_bind_interface.h"
#include "lnn_async_callback_utils.h"
#include "lnn_decision_db.h"
#include "lnn_device_info.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_event.h"
#include "lnn_feature_capability.h"
#include "lnn_net_builder.h"
#include "legacy/softbus_adapter_hitrace.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_socket.h"
#include "softbus_def.h"
#include "lnn_connection_fsm.h"

#define MAX_AUTH_VALID_PERIOD              (30 * 60 * 1000L)            /* 30 mins */
#define SCHEDULE_UPDATE_SESSION_KEY_PERIOD ((5 * 60 + 30) * 60 * 1000L) /* 5 hour 30 mins */
#define FLAG_REPLY                         1
#define FLAG_ACTIVE                        0
#define AUTH_COUNT                         2
#define DELAY_REG_DP_TIME                  10000
#define RECV_DATA_WAIT_TIME                100

static ListNode g_authClientList = { &g_authClientList, &g_authClientList };
static ListNode g_authServerList = { &g_authServerList, &g_authServerList };
static AuthTransCallback g_transCallback = { 0 };

/* Auth Manager */
AuthManager *NewAuthManager(int64_t authSeq, const AuthSessionInfo *info)
{
    AUTH_CHECK_AND_RETURN_RET_LOGE(info != NULL, NULL, AUTH_FSM, "info is null");
    AUTH_CHECK_AND_RETURN_RET_LOGE(CheckAuthConnInfoType(&info->connInfo), NULL, AUTH_FSM, "connInfo type error");
    AuthManager *auth = (AuthManager *)SoftBusCalloc(sizeof(AuthManager));
    if (auth == NULL) {
        AUTH_LOGW(AUTH_FSM, "malloc AuthManager fail");
        return NULL;
    }
    auth->authId = authSeq;
    auth->isServer = info->isServer;
    auth->connId[info->connInfo.type] = info->connId;
    auth->connInfo[info->connInfo.type] = info->connInfo;
    if (strcpy_s(auth->udid, sizeof(auth->udid), info->udid) != EOK ||
        strcpy_s(auth->uuid, sizeof(auth->uuid), info->uuid) != EOK) {
        AUTH_LOGW(AUTH_FSM, "copy uuid/udid fail");
        SoftBusFree(auth);
        return NULL;
    }
    auth->version = info->version;
    auth->hasAuthPassed[info->connInfo.type] = false;
    InitSessionKeyList(&auth->sessionKeyList);
    if (auth->isServer) {
        ListTailInsert(&g_authServerList, &auth->node);
    } else {
        ListTailInsert(&g_authClientList, &auth->node);
    }
    char *anonyUuid = NULL;
    Anonymize(auth->uuid, &anonyUuid);
    AUTH_LOGI(AUTH_FSM, "create auth manager, uuid=%{public}s, side=%{public}s, authId=%{public}" PRId64,
        AnonymizeWrapper(anonyUuid), GetAuthSideStr(auth->isServer), auth->authId);
    AnonymizeFree(anonyUuid);
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

void DelDupAuthManager(AuthManager *auth)
{
    AUTH_CHECK_AND_RETURN_LOGE(auth != NULL, AUTH_FSM, "auth is null");
    DestroySessionKeyList(&auth->sessionKeyList);
    SoftBusFree(auth);
}

void DelAuthManager(AuthManager *auth, int32_t type)
{
    AUTH_CHECK_AND_RETURN_LOGE(auth != NULL, AUTH_FSM, "auth is null");
    if (type < AUTH_LINK_TYPE_WIFI || type > AUTH_LINK_TYPE_MAX) {
        AUTH_LOGE(AUTH_FSM, "type error.");
        return;
    }
    char *anonyUdid = NULL;
    Anonymize(auth->udid, &anonyUdid);
    if (type != AUTH_LINK_TYPE_MAX) {
        if (auth->connId[type] == 0) {
            AUTH_LOGE(AUTH_FSM, "authManager has been deleted, authId=%{public}" PRId64, auth->authId);
            AnonymizeFree(anonyUdid);
            return;
        }
        auth->hasAuthPassed[type] = false;
        auth->connId[type] = 0;
        (void)memset_s(&auth->connInfo[type], sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
        for (int32_t i = AUTH_LINK_TYPE_WIFI; i < AUTH_LINK_TYPE_MAX; i++) {
            if (auth->connId[i] == 0) {
                continue;
            }
            ClearSessionkeyByAuthLinkType(auth->authId, &auth->sessionKeyList, (AuthLinkType)type);
            AUTH_LOGI(AUTH_FSM, "only clear connInfo, udid=%{public}s, side=%{public}s, type=%{public}d,"
                " authId=%{public}" PRId64, AnonymizeWrapper(anonyUdid),
                GetAuthSideStr(auth->isServer), type, auth->authId);
            AnonymizeFree(anonyUdid);
            return;
        }
    }
    AUTH_LOGI(AUTH_FSM, "delete auth manager, udid=%{public}s, side=%{public}s, authId=%{public}" PRId64,
        AnonymizeWrapper(anonyUdid), GetAuthSideStr(auth->isServer), auth->authId);
    AnonymizeFree(anonyUdid);
    ListDelete(&auth->node);
    CancelUpdateSessionKey(auth->authId);
    DestroySessionKeyList(&auth->sessionKeyList);
    SoftBusFree(auth);
}

static AuthManager *FindAuthManagerByConnInfo(const AuthConnInfo *connInfo, bool isServer)
{
    AuthManager *item = NULL;
    ListNode *list = isServer ? &g_authServerList : &g_authClientList;
    LIST_FOR_EACH_ENTRY(item, list, AuthManager, node) {
        if (CompareConnInfo(&item->connInfo[connInfo->type], connInfo, true)) {
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
        if (item->connInfo[type].type == type && (strcmp(item->uuid, uuid) == 0) && item->hasAuthPassed[type]) {
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
        if (item->connInfo[type].type == type && (strcmp(item->udid, udid) == 0) && item->hasAuthPassed[type]) {
            return item;
        }
    }
    return NULL;
}

static AuthManager *FindNormalizedKeyAuthManagerByUdid(const char *udid, bool isServer)
{
    AuthManager *item = NULL;
    ListNode *list = isServer ? &g_authServerList : &g_authClientList;
    LIST_FOR_EACH_ENTRY(item, list, AuthManager, node) {
        if ((strcmp(item->udid, udid) == 0)) {
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

    AUTH_LOGE(AUTH_FSM, "auth manager not found. authId=%{public}" PRId64 "", authId);
    return NULL;
}

static AuthManager *FindAuthManagerByConnId(uint64_t connId, bool isServer)
{
    AuthManager *item = NULL;
    int32_t type = GetConnType(connId);
    ListNode *list = isServer ? &g_authServerList : &g_authClientList;
    LIST_FOR_EACH_ENTRY(item, list, AuthManager, node) {
        if (item->connId[type] == connId) {
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
        DelAuthManager(item, AUTH_LINK_TYPE_MAX);
    }
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_authServerList, AuthManager, node) {
        DelAuthManager(item, AUTH_LINK_TYPE_MAX);
    }
    ReleaseAuthLock();
}

static int32_t SetAuthConnId(AuthManager *auth, const AuthManager *inAuth, AuthLinkType type)
{
    auth->connId[type] = inAuth->connId[type];
    return SOFTBUS_OK;
}

static int32_t SetAuthP2pMac(AuthManager *auth, const AuthManager *inAuth, AuthLinkType type)
{
    (void)type;
    if (strcpy_s(auth->p2pMac, sizeof(auth->p2pMac), inAuth->p2pMac) != EOK) {
        AUTH_LOGE(AUTH_CONN, "copy auth p2p mac fail, authId=%{public}" PRId64, auth->authId);
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t UpdateAuthManagerByAuthId(
    int64_t authId, int32_t (*updateFunc)(AuthManager *, const AuthManager *, AuthLinkType),
    const AuthManager *inAuth, AuthLinkType type)
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
    if (updateFunc(auth, inAuth, type) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "update auth manager fail, authId=%{public}" PRId64, authId);
        ReleaseAuthLock();
        return SOFTBUS_AUTH_UPDATE_PROCESS_FAIL;
    }
    ReleaseAuthLock();
    return SOFTBUS_OK;
}

void RemoveAuthSessionKeyByIndex(int64_t authId, int32_t index, AuthLinkType type)
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
    RemoveSessionkeyByIndex(&auth->sessionKeyList, index, type);
    char udid[UDID_BUF_LEN] = { 0 };
    (void)memcpy_s(udid, UDID_BUF_LEN, auth->udid, UDID_BUF_LEN);
    ReleaseAuthLock();
    AuthRemoveDeviceKeyByUdid(udid);
    if (IsListEmpty(&auth->sessionKeyList)) {
        AUTH_LOGI(AUTH_CONN, "auth key clear empty, Lnn offline. authId=%{public}" PRId64, authId);
        LnnNotifyEmptySessionKey(authId);
    } else if (!CheckSessionKeyListExistType(&auth->sessionKeyList, type)) {
        AUTH_LOGI(AUTH_CONN, "auth key type=%{public}d clear, Lnn offline. authId=%{public}" PRId64, type, authId);
        AuthHandle authHandle = { .authId = authId, .type = type };
        LnnNotifyLeaveLnnByAuthHandle(&authHandle);
    }
}

void RemoveAuthManagerByAuthId(AuthHandle authHandle)
{
    if (!RequireAuthLock()) {
        return;
    }
    AuthManager *auth = FindAuthManagerByAuthId(authHandle.authId);
    if (auth == NULL) {
        AUTH_LOGI(AUTH_CONN, "auth manager already removed, authId=%{public}" PRId64, authHandle.authId);
        ReleaseAuthLock();
        return;
    }
    DelAuthManager(auth, authHandle.type);
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
    DelAuthManager(auth, connInfo->type);
    ReleaseAuthLock();
}

static bool HasAuthPassed(AuthManager *auth)
{
    for (uint32_t i = AUTH_LINK_TYPE_WIFI; i < AUTH_LINK_TYPE_MAX; i++) {
        if (auth->hasAuthPassed[i]) {
            return true;
        }
    }
    return false;
}

void RemoveNotPassedAuthManagerByUdid(const char *udid)
{
    if (udid == NULL) {
        AUTH_LOGE(AUTH_CONN, "udid is empty");
        return;
    }
    if (!RequireAuthLock()) {
        return;
    }
    AuthManager *item = NULL;
    AuthManager *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_authClientList, AuthManager, node) {
        if (HasAuthPassed(item) || strcmp(item->udid, udid) != 0) {
            continue;
        }
        DelAuthManager(item, AUTH_LINK_TYPE_MAX);
    }
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_authServerList, AuthManager, node) {
        if (HasAuthPassed(item) || strcmp(item->udid, udid) != 0) {
            continue;
        }
        DelAuthManager(item, AUTH_LINK_TYPE_MAX);
    }
    ReleaseAuthLock();
}

int32_t GetAuthConnInfoByUuid(const char *uuid, AuthLinkType type, AuthConnInfo *connInfo)
{
    AUTH_CHECK_AND_RETURN_RET_LOGE(uuid != NULL, SOFTBUS_INVALID_PARAM, AUTH_CONN, "uuid is NULL");
    AUTH_CHECK_AND_RETURN_RET_LOGE(connInfo != NULL, SOFTBUS_INVALID_PARAM, AUTH_CONN, "connInfo is NULL");
    if (type < AUTH_LINK_TYPE_WIFI || type > AUTH_LINK_TYPE_MAX) {
        AUTH_LOGE(AUTH_CONN, "connInfo type error");
        return SOFTBUS_INVALID_PARAM;
    }
    if (!RequireAuthLock()) {
        return SOFTBUS_LOCK_ERR;
    }
    AuthManager *auth = FindAuthManagerByUuid(uuid, type, false);
    if (auth == NULL) {
        auth = FindAuthManagerByUuid(uuid, type, true);
    }
    char *anonyUuid = NULL;
    Anonymize(uuid, &anonyUuid);
    if (auth == NULL) {
        AUTH_LOGI(AUTH_CONN, "auth not found by uuid, connType=%{public}d, uuid=%{public}s",
            type, AnonymizeWrapper(anonyUuid));
        AnonymizeFree(anonyUuid);
        ReleaseAuthLock();
        return SOFTBUS_AUTH_NOT_FOUND;
    }
    AnonymizeFree(anonyUuid);
    *connInfo = auth->connInfo[type];
    ReleaseAuthLock();
    return SOFTBUS_OK;
}

static int32_t GetAvailableAuthConnInfoByUuid(const char *uuid, AuthLinkType type, AuthConnInfo *connInfo)
{
    if (!RequireAuthLock()) {
        return SOFTBUS_LOCK_ERR;
    }
    AuthManager *auth = FindAuthManagerByUuid(uuid, type, false);
    if (auth == NULL) {
        auth = FindAuthManagerByUuid(uuid, type, true);
    }
    char *anonyUuid = NULL;
    Anonymize(uuid, &anonyUuid);
    if (auth == NULL) {
        AUTH_LOGI(AUTH_CONN, "auth not found by uuid, connType=%{public}d, uuid=%{public}s",
            type, AnonymizeWrapper(anonyUuid));
        AnonymizeFree(anonyUuid);
        ReleaseAuthLock();
        return SOFTBUS_AUTH_NOT_FOUND;
    }
    if (GetLatestAvailableSessionKeyTime(&auth->sessionKeyList, type) == 0) {
        AUTH_LOGI(AUTH_FSM, "not available session key, connType=%{public}d, uuid=%{public}s",
            type, AnonymizeWrapper(anonyUuid));
        AnonymizeFree(anonyUuid);
        ReleaseAuthLock();
        return SOFTBUS_AUTH_SESSION_KEY_INVALID;
    }
    AnonymizeFree(anonyUuid);
    *connInfo = auth->connInfo[type];
    ReleaseAuthLock();
    return SOFTBUS_OK;
}

/* Note: must call DelDupAuthManager(auth) to free. */
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

AuthManager *GetAuthManagerByConnInfo(const AuthConnInfo *connInfo, bool isServer)
{
    AUTH_CHECK_AND_RETURN_RET_LOGE(connInfo != NULL, NULL, AUTH_FSM, "info is null");
    AUTH_CHECK_AND_RETURN_RET_LOGE(CheckAuthConnInfoType(connInfo), NULL, AUTH_FSM, "connInfo type error");
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

int64_t GetLatestIdByConnInfo(const AuthConnInfo *connInfo)
{
    if (connInfo == NULL) {
        AUTH_LOGE(AUTH_CONN, "connInfo is empty");
        return AUTH_INVALID_ID;
    }
    if (!RequireAuthLock()) {
        return AUTH_INVALID_ID;
    }
    uint32_t num = 0;
    const AuthManager *auth[2] = { NULL, NULL }; /* 2: client + server */
    auth[num++] = FindAuthManagerByConnInfo(connInfo, false);
    auth[num++] = FindAuthManagerByConnInfo(connInfo, true);
    int64_t latestAuthId = AUTH_INVALID_ID;
    uint64_t latestVerifyTime = 0;
    for (uint32_t i = 0; i < num; i++) {
        if (auth[i] != NULL && auth[i]->lastVerifyTime > latestVerifyTime && auth[i]->hasAuthPassed[connInfo->type]) {
            latestAuthId = auth[i]->authId;
            latestVerifyTime = auth[i]->lastVerifyTime;
        }
    }
    ReleaseAuthLock();
    AUTH_LOGD(AUTH_CONN,
        "latest auth manager found. num=%{public}d, latestAuthId=%{public}" PRId64 ", lastVerifyTime=%{public}" PRIu64,
        num, latestAuthId, latestVerifyTime);
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

int64_t GetActiveAuthIdByConnInfo(const AuthConnInfo *connInfo, bool judgeTimeOut)
{
    AUTH_CHECK_AND_RETURN_RET_LOGE(connInfo != NULL, AUTH_INVALID_ID, AUTH_CONN, "info is null");
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
        if (auth[i] == NULL) {
            continue;
        }
        if (!auth[i]->hasAuthPassed[connInfo->type]) {
            AUTH_LOGI(AUTH_CONN, "auth manager has not auth pass. authId=%{public}" PRId64, auth[i]->authId);
            auth[i] = NULL;
            continue;
        }
        if (CheckSessionKeyListExistType(&auth[i]->sessionKeyList, connInfo->type) &&
            GetLatestAvailableSessionKeyTime(&auth[i]->sessionKeyList, connInfo->type) == 0) {
            AUTH_LOGI(AUTH_CONN, "auth manager has not available key. authId=%{public}" PRId64, auth[i]->authId);
            auth[i] = NULL;
            continue;
        }
        if (judgeTimeOut && (currentTime > auth[i]->lastActiveTime)
            && (currentTime - auth[i]->lastActiveTime >= MAX_AUTH_VALID_PERIOD)) {
            AUTH_LOGI(AUTH_CONN, "auth manager timeout. authId=%{public}" PRId64, auth[i]->authId);
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
        if (auth[i]->lastVerifyTime > maxVerifyTime) {
            authId = auth[i]->authId;
        }
    }
    AUTH_LOGI(AUTH_CONN, "get active auth manager. authId=%{public}" PRId64 "", authId);
    ReleaseAuthLock();
    return authId;
}

static int32_t ProcessSessionKey(SessionKeyList *list, const SessionKey *key, AuthSessionInfo *info,
    bool isOldKey, int64_t *peerAuthSeq)
{
    if (info->normalizedType == NORMALIZED_SUPPORT) {
        if (SetSessionKeyAuthLinkType(list, info->normalizedIndex, info->connInfo.type) == SOFTBUS_OK) {
            AUTH_LOGI(AUTH_FSM, "index is alread exist");
            return SOFTBUS_OK;
        }
        *peerAuthSeq = info->normalizedIndex;
    }
    if (AddSessionKey(list, TO_INT32(*peerAuthSeq), key, info->connInfo.type, isOldKey) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "failed to add a sessionKey");
        return SOFTBUS_AUTH_SESSION_KEY_PROC_ERR;
    }
    AUTH_LOGI(AUTH_FSM, "add key index=%{public}d, new type=%{public}d", TO_INT32(*peerAuthSeq), info->connInfo.type);
    return SOFTBUS_OK;
}

static AuthManager *GetExistAuthManager(int64_t authSeq, const AuthSessionInfo *info)
{
    if (info->normalizedType == NORMALIZED_NOT_SUPPORT) {
        AUTH_LOGI(AUTH_FSM, "peer not support normalized");
        return NewAuthManager(authSeq, info);
    }
    AuthManager *auth = FindNormalizedKeyAuthManagerByUdid(info->udid, info->isServer);
    if (auth == NULL) {
        return NewAuthManager(authSeq, info);
    }
    auth->connId[info->connInfo.type] = info->connId;
    if (strcpy_s(auth->uuid, UUID_BUF_LEN, info->uuid) != EOK) {
        char *anonyUuid = NULL;
        Anonymize(info->uuid, &anonyUuid);
        AUTH_LOGE(AUTH_FSM, "str copy uuid fail, uuid=%{public}s", AnonymizeWrapper(anonyUuid));
        AnonymizeFree(anonyUuid);
    }
    if (memcpy_s(&auth->connInfo[info->connInfo.type], sizeof(AuthConnInfo),
        &info->connInfo, sizeof(AuthConnInfo)) != EOK) {
        AUTH_LOGE(AUTH_FSM, "connInfo cpy fail");
        return NULL;
    }
    return auth;
}

AuthManager *GetDeviceAuthManager(int64_t authSeq, const AuthSessionInfo *info, bool *isNewCreated,
    int64_t lastAuthSeq)
{
    AUTH_CHECK_AND_RETURN_RET_LOGE(info != NULL, NULL, AUTH_FSM, "info is NULL");
    AUTH_CHECK_AND_RETURN_RET_LOGE(isNewCreated != NULL, NULL, AUTH_FSM, "isNewCreated is NULL");
    AUTH_CHECK_AND_RETURN_RET_LOGE(CheckAuthConnInfoType(&info->connInfo), NULL, AUTH_FSM, "connInfo type error");
    AuthManager *auth = FindAuthManagerByConnInfo(&info->connInfo, info->isServer);
    if (auth != NULL && auth->connInfo[info->connInfo.type].type != 0) {
        if (strcpy_s(auth->uuid, UUID_BUF_LEN, info->uuid) != EOK) {
            AUTH_LOGE(AUTH_FSM, "str copy uuid fail");
        }
        if (auth->connId[info->connInfo.type] != info->connId &&
            auth->connInfo[info->connInfo.type].type == AUTH_LINK_TYPE_WIFI) {
            AuthFsm *fsm = GetAuthFsmByConnId(auth->connId[info->connInfo.type], info->isServer, false);
            DisconnectAuthDevice(&auth->connId[info->connInfo.type]);
            if (fsm != NULL) {
                UpdateFd(&fsm->info.connId, AUTH_INVALID_FD);
            }
            auth->hasAuthPassed[info->connInfo.type] = false;
            AUTH_LOGI(AUTH_FSM, "auth manager may single device on line");
        }
        char *anonyUuid = NULL;
        Anonymize(auth->uuid, &anonyUuid);
        AUTH_LOGI(AUTH_FSM, "uuid=%{public}s, authId=%{public}" PRId64,
            AnonymizeWrapper(anonyUuid), auth->authId);
        AnonymizeFree(anonyUuid);
    } else {
        auth = GetExistAuthManager(authSeq, info);
        if (auth != NULL) {
            *isNewCreated = true;
        } else {
            AUTH_LOGE(AUTH_FSM, "auth manager is null.");
            return NULL;
        }
    }
    auth->connId[info->connInfo.type] = info->connId;
    auth->lastAuthSeq[info->connInfo.type] = lastAuthSeq;
    auth->lastVerifyTime = GetCurrentTimeMs();
    auth->lastActiveTime = GetCurrentTimeMs();
    return auth;
}

static int32_t ProcessEmptySessionKey(const AuthSessionInfo *info, int32_t index, bool isServer,
    const SessionKey *sessionKey)
{
    AuthManager *auth = FindAuthManagerByUdid(info->udid, AUTH_LINK_TYPE_BLE, isServer);
    if (auth == NULL || auth->connInfo[AUTH_LINK_TYPE_BLE].type != AUTH_LINK_TYPE_BLE) {
        AUTH_LOGI(AUTH_FSM, "should not process empty session key.");
        return SOFTBUS_OK;
    }
    (void)ClearOldKey(&auth->sessionKeyList, AUTH_LINK_TYPE_BLE);
    if (SetSessionKeyAuthLinkType(&auth->sessionKeyList, index, AUTH_LINK_TYPE_BLE) == SOFTBUS_OK) {
        AUTH_LOGI(AUTH_FSM, "add keyType, index=%{public}d, type=%{public}d, authId=%{public}" PRId64,
            index, AUTH_LINK_TYPE_BLE, auth->authId);
        return SOFTBUS_OK;
    }
    if (AddSessionKey(&auth->sessionKeyList, index, sessionKey, AUTH_LINK_TYPE_BLE, false) != SOFTBUS_OK ||
        SetSessionKeyAvailable(&auth->sessionKeyList, index) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "add sessionkey fail, index=%{public}d, newType=%{public}d",
            index, AUTH_LINK_TYPE_BLE);
        return SOFTBUS_AUTH_SESSION_KEY_INVALID;
    }
    AUTH_LOGI(AUTH_FSM, "add sessionkey, index=%{public}d, type=%{public}d, authId=%{public}" PRId64,
        index, AUTH_LINK_TYPE_BLE, auth->authId);
    return SOFTBUS_OK;
}

static int32_t AuthProcessEmptySessionKey(const AuthSessionInfo *info, int32_t index)
{
    if (info->module != AUTH_MODULE_TRANS) {
        AUTH_LOGI(AUTH_FSM, "no need AuthProcessEmptySessionKey");
        return SOFTBUS_OK;
    }
    AuthManager *auth = FindAuthManagerByUdid(info->udid, info->connInfo.type, info->isServer);
    if (auth == NULL) {
        return SOFTBUS_AUTH_NOT_FOUND;
    }
    SessionKey sessionKey;
    (void)memset_s(&sessionKey, sizeof(SessionKey), 0, sizeof(SessionKey));
    if (GetSessionKeyByIndex(&auth->sessionKeyList, index, info->connInfo.type, &sessionKey) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "GetSessionKeyByIndex fail index=%{public}d", index);
        return SOFTBUS_AUTH_GET_SESSION_KEY_FAIL;
    }
    if (ProcessEmptySessionKey(info, index, !info->isServer, &sessionKey) != SOFTBUS_OK ||
        ProcessEmptySessionKey(info, index, info->isServer, &sessionKey) != SOFTBUS_OK) {
        (void)memset_s(&sessionKey, sizeof(SessionKey), 0, sizeof(SessionKey));
        return SOFTBUS_AUTH_SESSION_KEY_INVALID;
    }
    (void)memset_s(&sessionKey, sizeof(SessionKey), 0, sizeof(SessionKey));
    return SOFTBUS_OK;
}

int32_t AuthManagerSetSessionKey(int64_t authSeq, AuthSessionInfo *info, const SessionKey *sessionKey,
    bool isConnect, bool isOldKey)
{
    AUTH_CHECK_AND_RETURN_RET_LOGE(info != NULL, SOFTBUS_INVALID_PARAM, AUTH_FSM, "info is NULL");
    AUTH_CHECK_AND_RETURN_RET_LOGE(sessionKey != NULL, SOFTBUS_INVALID_PARAM, AUTH_FSM, "sessionKey is NULL");
    AUTH_CHECK_AND_RETURN_RET_LOGE(CheckAuthConnInfoType(&info->connInfo), SOFTBUS_INVALID_PARAM,
        AUTH_FSM, "connInfo type error");
    int64_t sessionKeyIndex = authSeq;
    if ((info->isSupportFastAuth) && (info->version <= SOFTBUS_OLD_V2)) {
        sessionKeyIndex = info->oldIndex;
    }
    authSeq = isConnect ? authSeq : GenSeq(info->isServer);
    AUTH_LOGI(AUTH_FSM, "SetSessionKey: authSeq=%{public}" PRId64 ", side=%{public}s, requestId=%{public}u", authSeq,
        GetAuthSideStr(info->isServer), info->requestId);
    if (!RequireAuthLock()) {
        return SOFTBUS_LOCK_ERR;
    }
    if (!isConnect && info->connInfo.type != AUTH_LINK_TYPE_BLE) {
        AUTH_LOGE(AUTH_FSM, "only support ble direct on line");
        ReleaseAuthLock();
        return SOFTBUS_OK;
    }
    bool isNewCreated = false;
    AuthManager *auth = GetDeviceAuthManager(authSeq, info, &isNewCreated, sessionKeyIndex);
    if (auth == NULL) {
        AUTH_LOGE(AUTH_FSM, "auth manager does not exist.");
        ReleaseAuthLock();
        return SOFTBUS_AUTH_NOT_FOUND;
    }
    if (ProcessSessionKey(&auth->sessionKeyList, sessionKey, info, isOldKey, &sessionKeyIndex) != SOFTBUS_OK) {
        if (isNewCreated) {
            DelAuthManager(auth, info->connInfo.type);
        }
        ReleaseAuthLock();
        return SOFTBUS_AUTH_SESSION_KEY_PROC_ERR;
    }
    AuthHandle authHandle = { .authId = auth->authId, .type = info->connInfo.type };
    if (auth->connInfo[info->connInfo.type].type == AUTH_LINK_TYPE_WIFI && !auth->isServer) {
        ScheduleUpdateSessionKey(authHandle, SCHEDULE_UPDATE_SESSION_KEY_PERIOD);
    }
    int32_t ret = SOFTBUS_OK;
    if (!isConnect) {
        ret = SetSessionKeyAvailable(&auth->sessionKeyList, TO_INT32(sessionKeyIndex));
        auth->hasAuthPassed[info->connInfo.type] = true;
    }
    info->isSavedSessionKey = true;
    AUTH_LOGI(AUTH_FSM,
        "authId=%{public}" PRId64 ", authSeq=%{public}" PRId64 ", index=%{public}d, lastVerifyTime=%{public}" PRId64,
        auth->authId, authSeq, TO_INT32(sessionKeyIndex), auth->lastVerifyTime);
    ReleaseAuthLock();
    return ret;
}

int32_t AuthManagerGetSessionKey(int64_t authSeq, const AuthSessionInfo *info, SessionKey *sessionKey)
{
    AUTH_CHECK_AND_RETURN_RET_LOGE(info != NULL, SOFTBUS_INVALID_PARAM, AUTH_FSM, "info is NULL");
    AUTH_CHECK_AND_RETURN_RET_LOGE(sessionKey != NULL, SOFTBUS_INVALID_PARAM, AUTH_FSM, "sessionKey is NULL");
    AUTH_CHECK_AND_RETURN_RET_LOGE(CheckAuthConnInfoType(&info->connInfo), SOFTBUS_INVALID_PARAM,
        AUTH_FSM, "connInfo type error");
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
    if (GetSessionKeyByIndex(&auth->sessionKeyList, TO_INT32(authSeq), info->connInfo.type,
        sessionKey) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "GetSessionKeyByIndex fail");
        ReleaseAuthLock();
        return SOFTBUS_AUTH_GET_SESSION_KEY_FAIL;
    }
    ReleaseAuthLock();
    return SOFTBUS_OK;
}

static void ReportAuthRequestPassed(uint32_t requestId, AuthHandle authHandle, const NodeInfo *nodeInfo)
{
    AuthRequest request;
    if (GetAuthRequest(requestId, &request) != SOFTBUS_OK) {
        AUTH_LOGI(AUTH_FSM, "auth request not found, only notify LNN to update nodeInfo");
        AuthNotifyDeviceVerifyPassed(authHandle, nodeInfo);
        return;
    }
    do {
        if (CheckAuthConnCallback(&request.connCb)) {
            AuthNotifyDeviceVerifyPassed(authHandle, nodeInfo);
            if (request.connInfo.type == AUTH_LINK_TYPE_WIFI || request.connInfo.type == AUTH_LINK_TYPE_P2P ||
                request.connInfo.type == AUTH_LINK_TYPE_ENHANCED_P2P) {
                PerformAuthConnCallback(request.requestId, SOFTBUS_OK, authHandle.authId);
                DelAuthRequest(request.requestId);
                continue;
            }
            if (request.module != AUTH_MODULE_LNN) {
                PerformAuthConnCallback(request.requestId, SOFTBUS_OK, authHandle.authId);
                DelAuthRequest(request.requestId);
                continue;
            }
            DelAuthRequest(request.requestId);
            /* For open auth br/ble connection, reconnect to keep long-connection. */
            if (AuthStartReconnectDevice(authHandle, &request.connInfo, request.requestId,
                &request.connCb) != SOFTBUS_OK) {
                AUTH_LOGE(AUTH_CONN, "open auth reconnect fail");
                request.connCb.onConnOpenFailed(request.requestId, SOFTBUS_AUTH_CONN_FAIL);
            }
            continue;
        }
        PerformVerifyCallback(request.requestId, SOFTBUS_OK, authHandle, nodeInfo);
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
        AuthHandle authHandle = { .authId = AUTH_INVALID_ID, .type = request.connInfo.type };
        PerformVerifyCallback(request.requestId, reason, authHandle, NULL);
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

static void PostCancelAuthMessage(int64_t authSeq, const AuthSessionInfo *info)
{
    AUTH_LOGI(AUTH_FSM, "post cancel auth msg, authSeq=%{public}" PRId64, authSeq);
    const char *msg = "";
    AuthDataHead head = {
        .dataType = DATA_TYPE_CANCEL_AUTH,
        .module = MODULE_AUTH_CANCEL,
        .seq = authSeq,
        .flag = 0,
        .len = strlen(msg) + 1,
    };
    if (PostAuthData(info->connId, !info->isConnectServer, &head, (uint8_t *)msg) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "post cancel auth fail");
    }
}

void AuthNotifyAuthPassed(int64_t authSeq, const AuthSessionInfo *info)
{
    AUTH_CHECK_AND_RETURN_LOGE(info != NULL, AUTH_FSM, "info is null");
    AUTH_CHECK_AND_RETURN_LOGE(CheckAuthConnInfoType(&info->connInfo), AUTH_FSM, "connInfo type error");
    AUTH_LOGI(AUTH_FSM, "AuthNotifyAuthPassed, authSeq=%{public}" PRId64, authSeq);
    DelAuthNormalizeRequest(authSeq);
    if (!RequireAuthLock()) {
        return;
    }
    AuthManager *auth = FindAuthManagerByConnInfo(&info->connInfo, info->isServer);
    if (auth == NULL) {
        PrintAuthConnInfo(&info->connInfo);
        AUTH_LOGE(AUTH_FSM, "auth manager not found, continue find, connType=%{public}d, side=%{public}s",
            info->connInfo.type, GetAuthSideStr(info->isServer));
        auth = FindAuthManagerByConnInfo(&info->connInfo, !info->isServer);
    }
    if (auth == NULL) {
        PrintAuthConnInfo(&info->connInfo);
        AUTH_LOGE(AUTH_FSM, "auth manager not found, connType=%{public}d, side=%{public}s",
            info->connInfo.type, GetAuthSideStr(!info->isServer));
        ReleaseAuthLock();
        return;
    }
    AuthHandle authHandle = { .authId = auth->authId, .type = info->connInfo.type };
    ReleaseAuthLock();
    if (info->connInfo.type != AUTH_LINK_TYPE_WIFI && info->connInfo.type != AUTH_LINK_TYPE_SESSION) {
        PostCancelAuthMessage(authSeq, info);
    }
    if (!info->isConnectServer) {
        ReportAuthRequestPassed(info->requestId, authHandle, NULL);
        AUTH_LOGI(AUTH_FSM, "notify auth passed, disconnect connId=%{public}" PRIu64, info->connId);
        DisconnectAuthDevice((uint64_t *)&info->connId);
    }
}

static void NotifyAuthResult(AuthHandle authHandle, const AuthSessionInfo *info)
{
    if (info->isConnectServer) {
        AuthNotifyDeviceVerifyPassed(authHandle, &info->nodeInfo);
    } else {
        ReportAuthRequestPassed(info->requestId, authHandle, &info->nodeInfo);
        UpdateAuthDevicePriority(info->connId);
    }
}

void AuthManagerSetAuthPassed(int64_t authSeq, const AuthSessionInfo *info)
{
    AUTH_CHECK_AND_RETURN_LOGE(info != NULL, AUTH_FSM, "info is null");
    AUTH_CHECK_AND_RETURN_LOGE(CheckAuthConnInfoType(&info->connInfo), AUTH_FSM, "connInfo type error");
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
    int64_t index = authSeq;
    if (info->normalizedType == NORMALIZED_SUPPORT) {
        index = info->normalizedIndex;
    }
    if (SetSessionKeyAvailable(&auth->sessionKeyList, TO_INT32(index)) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "set sessionKey available fail, index=%{public}d", TO_INT32(index));
        ReleaseAuthLock();
        return;
    }
    auth->hasAuthPassed[info->connInfo.type] = true;
    if (AuthProcessEmptySessionKey(info, TO_INT32(index)) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "process empty session key error, index=%{public}d", TO_INT32(index));
        ReleaseAuthLock();
        return;
    }
    if (info->nodeInfo.p2pInfo.p2pMac[0] != '\0') {
        if (strcpy_s(auth->p2pMac, sizeof(auth->p2pMac), info->nodeInfo.p2pInfo.p2pMac)) {
            AUTH_LOGE(AUTH_FSM, "copy p2pMac fail, authSeq=%{public}" PRId64, authSeq);
        }
    }
    AuthHandle authHandle = { .authId = auth->authId, .type = info->connInfo.type };
    ReleaseAuthLock();
    if (!LnnSetDlPtk(info->nodeInfo.networkId, info->nodeInfo.remotePtk)) {
        AUTH_LOGE(AUTH_FSM, "set remote ptk error, index=%{public}d", TO_INT32(index));
    }
    bool isExchangeUdid = true;
    if (GetIsExchangeUdidByNetworkId(info->nodeInfo.networkId, &isExchangeUdid) == SOFTBUS_OK && isExchangeUdid) {
        AUTH_LOGI(AUTH_FSM, "clear isExchangeUdid");
        LnnClearAuthExchangeUdid(info->nodeInfo.networkId);
    }
    NotifyAuthResult(authHandle, info);
}

static void UpdateAuthConnIdSyncWithInfo(const AuthConnInfo *connInfo, uint64_t connId, bool isServer)
{
    if (!RequireAuthLock()) {
        AUTH_LOGE(AUTH_FSM, "get auth lock fail");
        return;
    }

    AuthManager *auth = FindAuthManagerByConnInfo(connInfo, isServer);
    if (auth == NULL) {
        PrintAuthConnInfo(connInfo);
        ReleaseAuthLock();
        AUTH_LOGE(AUTH_FSM, "auth manager not found, connType=%{public}d, side=%{public}s",
            connInfo->type, GetAuthSideStr(isServer));
        return;
    }
    if (auth->connId[connInfo->type] == connId &&  GetConnType(connId) == AUTH_LINK_TYPE_WIFI) {
        AUTH_LOGI(AUTH_FSM,
            "When conntype is wifi, auth connId sync with connInfo, connId=%{public}" PRIu64, connId);
        UpdateFd(&auth->connId[connInfo->type], AUTH_INVALID_FD);
    }
    ReleaseAuthLock();
}

void AuthManagerSetAuthFailed(int64_t authSeq, const AuthSessionInfo *info, int32_t reason)
{
    AUTH_CHECK_AND_RETURN_LOGE(info != NULL, AUTH_FSM, "auth session info is null");
    AUTH_CHECK_AND_RETURN_LOGE(CheckAuthConnInfoType(&info->connInfo), AUTH_FSM, "connInfo type error");
    AUTH_LOGE(AUTH_FSM, "SetAuthFailed: authSeq=%{public}" PRId64 ", requestId=%{public}u, reason=%{public}d", authSeq,
        info->requestId, reason);
    AuthManager *auth = NULL;
    if (info->isSavedSessionKey) {
        int64_t authId = GetAuthIdByConnId(info->connId, info->isServer);
        auth = GetAuthManagerByAuthId(authId);
        AUTH_LOGE(AUTH_FSM, "already save sessionkey, get auth mgr. authSeq=%{public}" PRId64, authSeq);
    }
    bool needDisconnect = true;
    if (auth != NULL && reason == SOFTBUS_AUTH_TIMEOUT && info->connInfo.type == AUTH_LINK_TYPE_WIFI
        && info->connInfo.info.ipInfo.port != auth->connInfo[AUTH_LINK_TYPE_WIFI].info.ipInfo.port) {
        AUTH_LOGE(AUTH_FSM, "auth manager port change, connType=%{public}d, side=%{public}s",
            info->connInfo.type, GetAuthSideStr(info->isServer));
        needDisconnect = false;
    }
    if (auth != NULL && auth->hasAuthPassed[info->connInfo.type] && needDisconnect) {
        AUTH_LOGE(AUTH_FSM, "update session key fail, authId=%{public}" PRId64, auth->authId);
        AuthHandle authHandle = { .authId = auth->authId, .type = info->connInfo.type };
        AuthNotifyDeviceDisconnect(authHandle);
    }
    DelDupAuthManager(auth);

    if (needDisconnect && auth != NULL) {
        RemoveAuthManagerByConnInfo(&info->connInfo, info->isServer);
    }
    ReportAuthRequestFailed(info->requestId, reason);
    if (GetConnType(info->connId) == AUTH_LINK_TYPE_WIFI) {
        UpdateAuthConnIdSyncWithInfo(&info->connInfo, info->connId, info->isServer);
        DisconnectAuthDevice((uint64_t *)&info->connId);
    } else if (!info->isConnectServer) {
        /* Bluetooth networking only the client to close the connection. */
        UpdateAuthDevicePriority(info->connId);
        DisconnectAuthDevice((uint64_t *)&info->connId);
    }
    AuthAddNodeToLimitMap(info->udid, reason);
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

static int32_t GenerateUdidHash(const char *udid, uint8_t *hash)
{
    if (SoftBusGenerateStrHash((uint8_t *)udid, strlen(udid), hash) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "generate udidHash fail");
        return SOFTBUS_NETWORK_GENERATE_STR_HASH_ERR;
    }
    return SOFTBUS_OK;
}

void AuthManagerSetAuthFinished(int64_t authSeq, const AuthSessionInfo *info)
{
    AUTH_CHECK_AND_RETURN_LOGE(info != NULL, AUTH_FSM, "auth session info is null");
    AUTH_LOGI(AUTH_FSM, "SetAuthFinished: authSeq=%{public}" PRId64 ", requestId=%{public}u", authSeq, info->requestId);
    if (info->isConnectServer) {
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
        AUTH_CHECK_AND_RETURN_LOGE(info->udid != NULL, AUTH_FSM, "udid is null");
        uint8_t hash[SHA_256_HASH_LEN] = { 0 };
        char udidHash[SHORT_UDID_HASH_HEX_LEN + 1] = { 0 };
        if (GenerateUdidHash(info->udid, hash) != SOFTBUS_OK) {
            AUTH_LOGE(AUTH_FSM, "GenerateUdidShortHash fail.");
            return;
        }
        if (ConvertBytesToUpperCaseHexString(udidHash, SHORT_UDID_HASH_HEX_LEN + 1, hash, UDID_SHORT_HASH_LEN_TEMP) !=
            SOFTBUS_OK) {
            AUTH_LOGE(AUTH_FSM, "convert bytes to string fail");
            return;
        }
        AuthDeleteLimitMap(udidHash);
    }
    if (info->connInfo.type == AUTH_LINK_TYPE_BR) {
        AUTH_LOGI(AUTH_FSM, "br disconn now");
        DisconnectAuthDevice((uint64_t *)&info->connId);
    }
}

static void HandleReconnectResult(const AuthRequest *request, uint64_t connId, int32_t result, int32_t type)
{
    if (result != SOFTBUS_OK) {
        PerformAuthConnCallback(request->requestId, result, AUTH_INVALID_ID);
        DelAuthRequest(request->requestId);
        return;
    }
    AuthManager inAuth = {0};
    inAuth.connId[type] = connId;
    if (UpdateAuthManagerByAuthId(request->authId, SetAuthConnId, &inAuth, (AuthLinkType)type) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "set auth connId fail, requestId=%{public}u", request->requestId);
        PerformAuthConnCallback(request->requestId, SOFTBUS_AUTH_NOT_FOUND, AUTH_INVALID_ID);
        DelAuthRequest(request->requestId);
        return;
    }
    PerformAuthConnCallback(request->requestId, SOFTBUS_OK, request->authId);
    DelAuthRequest(request->requestId);
}

static void DfxRecordLnnConnectEnd(uint32_t requestId, uint64_t connId, const AuthConnInfo *connInfo, int32_t reason)
{
    LnnEventExtra extra = { 0 };
    LnnEventExtraInit(&extra);
    extra.authRequestId = (int32_t)requestId;
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
    DfxRecordLnnConnectEnd(requestId, connId, connInfo, result);
    AUTH_LOGI(AUTH_CONN, "OnConnectResult: requestId=%{public}u, result=%{public}d", requestId, result);
    AuthRequest request;
    if (GetAuthRequest(requestId, &request) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "request not found, requestId=%{public}u", requestId);
        return;
    }
    SoftbusHitraceStart(SOFTBUS_HITRACE_ID_VALID, (uint64_t)request.traceId);
    if (request.type == REQUEST_TYPE_RECONNECT && connInfo != NULL) {
        HandleReconnectResult(&request, connId, result, connInfo->type);
        SoftbusHitraceStop();
        return;
    }
    if (result != SOFTBUS_OK) {
        ReportAuthRequestFailed(requestId, result);
        SoftbusHitraceStop();
        return;
    }
    AuthParam authInfo = {
        .authSeq = request.traceId,
        .requestId = requestId,
        .connId = connId,
        .isServer = false,
        .isFastAuth = request.isFastAuth,
    };
    int32_t ret = AuthSessionStartAuth(&authInfo, connInfo);
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "start auth session fail=%{public}d, requestId=%{public}u", ret, requestId);
        DisconnectAuthDevice(&connId);
        ReportAuthRequestFailed(requestId, ret);
        SoftbusHitraceStop();
        return;
    }
    SoftbusHitraceStop();
}

static void DfxRecordServerRecvPassiveConnTime(const AuthConnInfo *connInfo, const AuthDataHead *head)
{
    uint64_t timeStamp = 0;
    int32_t ret = SOFTBUS_OK;
    LnnEventExtra extra = { 0 };
    (void)LnnEventExtraInit(&extra);
    LnnTriggerInfo triggerInfo = { 0 };
    GetLnnTriggerInfo(&triggerInfo);
    timeStamp = SoftBusGetSysTimeMs();
    extra.timeLatency = timeStamp - triggerInfo.triggerTime;
    extra.authSeq = head->seq;
    char *udidHash = (char *)SoftBusCalloc(SHORT_UDID_HASH_HEX_LEN + 1);
    if (udidHash == NULL) {
        AUTH_LOGE(AUTH_FSM, "udidHash calloc fail");
        return;
    }
    if (connInfo->type == AUTH_LINK_TYPE_BLE) {
        ret = ConvertBytesToHexString(udidHash, SHORT_UDID_HASH_HEX_LEN + 1,
                                      connInfo->info.bleInfo.deviceIdHash, SHORT_UDID_HASH_LEN);
        if (ret != SOFTBUS_OK) {
            AUTH_LOGE(AUTH_FSM, "convert bytes to string fail. ret=%{public}d", ret);
            SoftBusFree(udidHash);
            return;
        }
        extra.peerUdidHash = udidHash;
    } else if (connInfo->type == AUTH_LINK_TYPE_WIFI) {
        ret = ConvertBytesToHexString(udidHash, SHORT_UDID_HASH_HEX_LEN + 1,
                                      connInfo->info.ipInfo.deviceIdHash, SHORT_UDID_HASH_LEN);
        if (ret != SOFTBUS_OK) {
            AUTH_LOGE(AUTH_FSM, "convert bytes to string fail. ret=%{public}d", ret);
            SoftBusFree(udidHash);
            return;
        }
        extra.peerUdidHash = udidHash;
    }
    LNN_EVENT(EVENT_SCENE_JOIN_LNN, EVENT_STAGE_AUTH_CONNECTION, extra);
    SoftBusFree(udidHash);
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
        if (!RequireAuthLock()) {
            AUTH_LOGE(AUTH_FSM, "lock fail");
            return;
        }
        AuthFsm *fsm = GetAuthFsmByConnId(connId, true, true);
        if (fsm != NULL && (fsm->info.idType == EXCHANGE_NETWORKID || fsm->info.idType == EXCHANGE_FAIL ||
            fsm->info.localState != AUTH_STATE_COMPATIBLE)) {
            ReleaseAuthLock();
            ret = AuthSessionProcessDevIdData(head->seq, data, head->len);
            if (ret != SOFTBUS_OK) {
                AUTH_LOGE(AUTH_FSM,
                    "perform auth session recv devId fail. seq=%{public}" PRId64 ", ret=%{public}d", head->seq, ret);
            }
            return;
        }
        if (fsm != NULL && fsm->info.idType == EXCHANGE_UDID && fsm->info.localState == AUTH_STATE_COMPATIBLE) {
            AUTH_LOGE(AUTH_FSM, "the same connId fsm not support, ignore auth seq=%{public}" PRId64, head->seq);
            ReleaseAuthLock();
            HandleRepeatDeviceIdDataDelay(connId, connInfo, fromServer, head, data);
            return;
        }
        ReleaseAuthLock();
        AuthParam authInfo = {
            .authSeq = head->seq, .requestId = AuthGenRequestId(), .connId = connId,
            .isServer = true, .isFastAuth = true,
        };
        ret = AuthSessionStartAuth(&authInfo, connInfo);
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
    DfxRecordServerRecvPassiveConnTime(connInfo, head);
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

static void FlushDeviceProcess(const AuthConnInfo *connInfo, bool isServer, DeviceMessageParse *messageParse)
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
    if (PostDeviceMessage(auth, FLAG_REPLY, connInfo->type, messageParse) == SOFTBUS_OK) {
        AUTH_LOGI(AUTH_FSM, "post flush device ok");
    }
    ReleaseAuthLock();
    return;
}

static int32_t AuthSetTcpKeepaliveByConnInfo(const AuthConnInfo *connInfo, ModeCycle cycle)
{
    if (connInfo == NULL) {
        AUTH_LOGE(AUTH_CONN, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t ret = SOFTBUS_NETWORK_SET_KEEPALIVE_OPTION_FAIL;
    AuthManager *auth[AUTH_COUNT] = { NULL, NULL }; /* 2: WiFi * (Client + Server) */
    auth[0] = GetAuthManagerByConnInfo(connInfo, false);
    auth[1] = GetAuthManagerByConnInfo(connInfo, true);
    for (uint32_t i = 0; i < AUTH_COUNT; i++) {
        if (auth[i] == NULL) {
            continue;
        }
        ret = AuthSetTcpKeepaliveOption(GetFd(auth[i]->connId[AUTH_LINK_TYPE_WIFI]), cycle);
        if (ret != SOFTBUS_OK) {
            AUTH_LOGE(AUTH_CONN, "auth set tcp keepalive option fail");
            break;
        }
    }
    DelDupAuthManager(auth[0]);
    DelDupAuthManager(auth[1]);
    return ret;
}

static void HandleDeviceInfoData(
    uint64_t connId, const AuthConnInfo *connInfo, bool fromServer, const AuthDataHead *head, const uint8_t *data)
{
    int32_t ret = SOFTBUS_OK;
    DeviceMessageParse messageParse = { 0 };
    if (IsDeviceMessagePacket(connInfo, head, data, !fromServer, &messageParse)) {
        if (head->flag == 0 && messageParse.messageType == CODE_VERIFY_DEVICE) {
            AUTH_LOGE(AUTH_FSM, "flush device need relay");
            FlushDeviceProcess(connInfo, !fromServer, &messageParse);
        } else if (head->flag == 0 && messageParse.messageType == CODE_TCP_KEEPALIVE) {
            if (AuthSetTcpKeepaliveByConnInfo(connInfo, messageParse.cycle) != SOFTBUS_OK) {
                AUTH_LOGE(AUTH_FSM, "set tcp keepalive by connInfo fail");
            }
        } else {
            AUTH_LOGE(AUTH_FSM, "device message not need relay");
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

static int32_t PostDecryptFailAuthData(
    uint64_t connId, bool fromServer, const AuthDataHead *inputHead, const uint8_t *data)
{
    AuthDataHead head = {
        .dataType = DATA_TYPE_DECRYPT_FAIL,
        .module = 0,
        .seq = inputHead->seq,
        .flag = 0,
        .len = inputHead->len,
    };
    AUTH_LOGI(AUTH_CONN, "post decrypt fail data");
    int32_t ret = PostAuthData(connId, fromServer, &head, data);
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "post data fail");
        return ret;
    }
    return SOFTBUS_OK;
}

static void HandleConnectionData(
    uint64_t connId, const AuthConnInfo *connInfo, bool fromServer, const AuthDataHead *head, const uint8_t *data)
{
    if (!RequireAuthLock()) {
        return;
    }
    char udid[UDID_BUF_LEN] = { 0 };
    AuthManager *auth = FindAuthManagerByConnInfo(connInfo, !fromServer);
    if (auth == NULL) {
        PrintAuthConnInfo(connInfo);
        AUTH_LOGE(AUTH_CONN, "AuthManager not found, connType=%{public}d", connInfo->type);
        ReleaseAuthLock();
        if (connInfo->type == AUTH_LINK_TYPE_P2P || connInfo->type == AUTH_LINK_TYPE_WIFI) {
            return;
        }
        (void)PostDecryptFailAuthData(connId, fromServer, head, data);
        return;
    }
    int64_t authId = auth->authId;
    AuthLinkType type = connInfo->type;
    uint8_t *decData = NULL;
    uint32_t decDataLen = 0;
    InDataInfo inDataInfo = { .inData = data, .inLen = head->len };
    if (DecryptInner(&auth->sessionKeyList, type, &inDataInfo, &decData, &decDataLen) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "decrypt trans data fail");
        ReleaseAuthLock();
        return;
    }
    int32_t index = (int32_t)SoftBusLtoHl(*(uint32_t *)data);
    (void)SetSessionKeyAvailable(&auth->sessionKeyList, index);
    auth->hasAuthPassed[connInfo->type] = true;
    auth->lastActiveTime = GetCurrentTimeMs();
    auth->connId[type] = connId;
    AuthHandle authHandle = { .authId = authId, .type = GetConnType(connId) };
    int32_t ret = SOFTBUS_OK;
    if (strcpy_s(udid, UDID_BUF_LEN, auth->udid) != EOK) {
        AUTH_LOGE(AUTH_CONN, "copy udid fail");
        ret = SOFTBUS_MEM_ERR;
    }
    ReleaseAuthLock();
    if (ret == SOFTBUS_OK && !LnnGetOnlineStateById(udid, CATEGORY_UDID)) {
        AUTH_LOGE(AUTH_CONN, "device is offline, need wait");
        (void)SoftBusSleepMs(RECV_DATA_WAIT_TIME);
    }
    if (g_transCallback.onDataReceived != NULL) {
        g_transCallback.onDataReceived(authHandle, head, decData, decDataLen);
    }
    SoftBusFree(decData);
}

static void HandleDecryptFailData(
    uint64_t connId, const AuthConnInfo *connInfo, bool fromServer, const AuthDataHead *head, const uint8_t *data)
{
    if (!RequireAuthLock()) {
        return;
    }
    int32_t num = 0;
    const AuthManager *auth[2] = { NULL, NULL }; /* 2: client + server */
    auth[num++] = FindAuthManagerByConnInfo(connInfo, false);
    auth[num++] = FindAuthManagerByConnInfo(connInfo, true);
    if (auth[0] == NULL && auth[1] == NULL) {
        PrintAuthConnInfo(connInfo);
        AUTH_LOGE(AUTH_CONN, "AuthManager not found, conntype=%{public}d", connInfo->type);
        ReleaseAuthLock();
        return;
    }
    uint8_t *decData = NULL;
    uint32_t decDataLen = 0;
    int32_t index = (int32_t)SoftBusLtoHl(*(uint32_t *)data);
    InDataInfo inDataInfo = { .inData = data, .inLen = head->len };
    AuthHandle authHandle = { .type = connInfo->type };
    if (auth[0] != NULL && DecryptInner(&auth[0]->sessionKeyList, connInfo->type, &inDataInfo,
        &decData, &decDataLen) == SOFTBUS_OK) {
        ReleaseAuthLock();
        SoftBusFree(decData);
        RemoveAuthSessionKeyByIndex(auth[0]->authId, index, connInfo->type);
        authHandle.authId = auth[0]->authId;
    } else if (auth[1] != NULL && DecryptInner(&auth[1]->sessionKeyList, connInfo->type, &inDataInfo,
        &decData, &decDataLen) == SOFTBUS_OK) {
        ReleaseAuthLock();
        SoftBusFree(decData);
        RemoveAuthSessionKeyByIndex(auth[1]->authId, index, connInfo->type);
        authHandle.authId = auth[1]->authId;
    } else {
        ReleaseAuthLock();
        AUTH_LOGE(AUTH_CONN, "decrypt trans data fail.");
    }
    if (g_transCallback.onException != NULL) {
        AUTH_LOGE(AUTH_CONN, "notify exception");
        g_transCallback.onException(authHandle, SOFTBUS_AUTH_DECRYPT_ERR);
    }
}

static void HandleCancelAuthData(
    uint64_t connId, const AuthConnInfo *connInfo, bool fromServer, const AuthDataHead *head, const uint8_t *data)
{
    int32_t ret = AuthSessionProcessCancelAuthByConnId(connId, !fromServer, data, head->len);
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "perform auth session cancel auth fail. seq=%{public}" PRId64 ", ret=%{public}d",
            head->seq, ret);
    }
}

static void CorrectFromServer(uint64_t connId, const AuthConnInfo *connInfo, bool *fromServer)
{
    if (connInfo->type != AUTH_LINK_TYPE_WIFI) {
        return;
    }
    uint32_t num = 0;
    int64_t authIds[2];
    bool tmp = *fromServer;
    authIds[num++] = GetAuthIdByConnId(connId, false);
    authIds[num++] = GetAuthIdByConnId(connId, true);
    if (authIds[0] != AUTH_INVALID_ID) {
        *fromServer = true;
    }
    if (authIds[1] != AUTH_INVALID_ID) {
        *fromServer = false;
    }
    if (tmp != *fromServer) {
        AUTH_LOGE(AUTH_CONN, "CorrectFromServer succ.");
    }
}

static void OnDataReceived(
    uint64_t connId, const AuthConnInfo *connInfo, bool fromServer, const AuthDataHead *head, const uint8_t *data)
{
    if (connInfo == NULL || head == NULL || data == NULL) {
        AUTH_LOGE(AUTH_CONN, "invalid param");
        return;
    }
    SoftbusHitraceStart(SOFTBUS_HITRACE_ID_VALID, (uint64_t)head->seq);
    CorrectFromServer(connId, connInfo, &fromServer);
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
        case DATA_TYPE_DECRYPT_FAIL:
            HandleDecryptFailData(connId, connInfo, fromServer, head, data);
            break;
        case DATA_TYPE_CANCEL_AUTH:
            HandleCancelAuthData(connId, connInfo, fromServer, head, data);
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
        AuthHandle authHandle = { .authId = authIds[i], .type = GetConnType(connId) };
        if (g_transCallback.onDisconnected != NULL) {
            g_transCallback.onDisconnected(authHandle);
        }
        if (GetConnType(connId) == AUTH_LINK_TYPE_WIFI || GetConnType(connId) == AUTH_LINK_TYPE_P2P ||
            GetConnType(connId) == AUTH_LINK_TYPE_ENHANCED_P2P) {
            AuthNotifyDeviceDisconnect(authHandle);
            DisconnectAuthDevice(&dupConnId);
            AuthManager inAuth = {0};
            inAuth.connId[GetConnType(connId)] = dupConnId;
            (void)UpdateAuthManagerByAuthId(authIds[i], SetAuthConnId, &inAuth, (AuthLinkType)GetConnType(connId));
            RemoveAuthManagerByAuthId(authHandle);
        }
    }
    /* Try to terminate authing session. */
    (void)AuthSessionHandleDeviceDisconnected(connId, GetFd(dupConnId) != AUTH_INVALID_FD);
}

static void OnDisconnected(uint64_t connId, const AuthConnInfo *connInfo)
{
    (void)connInfo;
    (void)PostAuthEvent(EVENT_AUTH_DISCONNECT, HandleDisconnectedEvent, &connId, sizeof(connId), 0);
}

uint32_t AuthGenRequestId(void)
{
    return ConnGetNewRequestId(MODULE_DEVICE_AUTH);
}

void AuthHandleLeaveLNN(AuthHandle authHandle)
{
    if (authHandle.type < AUTH_LINK_TYPE_WIFI || authHandle.type >= AUTH_LINK_TYPE_MAX) {
        AUTH_LOGE(AUTH_FSM, "authHandle type error");
        return;
    }
    if (!RequireAuthLock()) {
        return;
    }
    AuthManager *auth = FindAuthManagerByAuthId(authHandle.authId);
    if (auth == NULL) {
        AUTH_LOGE(AUTH_FSM, "auth manager not found, authId=%{public}" PRId64, authHandle.authId);
        ReleaseAuthLock();
        return;
    }
    if (!auth->hasAuthPassed[authHandle.type]) {
        ReleaseAuthLock();
        AUTH_LOGI(AUTH_FSM, "auth pass = false, don't need to leave");
        return;
    }
    AuthFsm *authFsm = GetAuthFsmByConnId(auth->connId[authHandle.type], auth->isServer, false);
    if (authFsm == NULL) {
        authFsm = GetAuthFsmByConnId(auth->connId[authHandle.type], !auth->isServer, false);
    }
    if (authFsm != NULL && authFsm->curState >= STATE_SYNC_DEVICE_INFO) {
        AUTH_LOGI(AUTH_FSM, "another fsm use this auth manager");
        ReleaseAuthLock();
        return;
    }
    if (auth->connInfo[authHandle.type].type == AUTH_LINK_TYPE_WIFI) {
        AUTH_LOGI(AUTH_FSM, "AuthHandleLeaveLNN disconnect");
        DisconnectAuthDevice(&auth->connId[authHandle.type]);
    }
    DelAuthManager(auth, authHandle.type);
    ReleaseAuthLock();
}

static int32_t PostDeviceMessageByUuid(const char *uuid, int32_t messageType, ModeCycle cycle)
{
    if (!RequireAuthLock()) {
        return SOFTBUS_LOCK_ERR;
    }
    uint32_t num = 0;
    int32_t ret = SOFTBUS_AUTH_POST_MSG_FAIL;
    DeviceMessageParse messageParse = { messageType, cycle };
    AuthManager *auth[2] = { NULL, NULL }; /* 2: WiFi * (Client + Server) */
    auth[num++] = FindAuthManagerByUuid(uuid, AUTH_LINK_TYPE_WIFI, false);
    auth[num++] = FindAuthManagerByUuid(uuid, AUTH_LINK_TYPE_WIFI, true);
    for (uint32_t i = 0; i < num; i++) {
        if (auth[i] == NULL) {
            continue;
        }
        ret = PostDeviceMessage(auth[i], FLAG_ACTIVE, AUTH_LINK_TYPE_WIFI, &messageParse);
        if (ret != SOFTBUS_OK) {
            AUTH_LOGE(AUTH_CONN, "%{public}d:messageType=%{public}d, post device message fail", i, messageType);
            ReleaseAuthLock();
            return ret;
        }
    }
    ReleaseAuthLock();
    return ret;
}

static int32_t SetLocalTcpKeepalive(const char *uuid, ModeCycle cycle)
{
    int32_t ret = SOFTBUS_NETWORK_SET_KEEPALIVE_OPTION_FAIL;
    AuthConnInfo connInfo;
    (void)memset_s(&connInfo, sizeof(connInfo), 0, sizeof(connInfo));
    ret = GetAuthConnInfoByUuid(uuid, AUTH_LINK_TYPE_WIFI, &connInfo);
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "get AuthConnInfo by uuid fail, ret=%{public}d", ret);
        return ret;
    }
    ret = AuthSetTcpKeepaliveByConnInfo(&connInfo, cycle);
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "set tcp keepalive fail, ret=%{public}d", ret);
    }
    return ret;
}

int32_t AuthFlushDevice(const char *uuid)
{
    if (uuid == NULL || uuid[0] == '\0') {
        AUTH_LOGE(AUTH_CONN, "uuid is empty");
        return SOFTBUS_INVALID_PARAM;
    }
    if (PostDeviceMessageByUuid(uuid, CODE_VERIFY_DEVICE, DEFAULT_FREQ_CYCLE) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "post flush device message by uuid fail");
        return SOFTBUS_AUTH_POST_MSG_FAIL;
    }
    return SOFTBUS_OK;
}

int32_t AuthSendKeepaliveOption(const char *uuid, ModeCycle cycle)
{
    if (uuid == NULL || uuid[0] == '\0' || cycle < HIGH_FREQ_CYCLE || cycle > DEFAULT_FREQ_CYCLE) {
        AUTH_LOGE(AUTH_CONN, "uuid is empty or invalid cycle");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SetLocalTcpKeepalive(uuid, cycle) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "set local tcp keepalive fail");
        return SOFTBUS_NETWORK_SET_KEEPALIVE_OPTION_FAIL;
    }
    if (PostDeviceMessageByUuid(uuid, CODE_TCP_KEEPALIVE, cycle) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "post device keepalive message by uuid fail");
        return SOFTBUS_AUTH_POST_MSG_FAIL;
    }
    return SOFTBUS_OK;
}

int32_t TryGetBrConnInfo(const char *uuid, AuthConnInfo *connInfo)
{
    AUTH_CHECK_AND_RETURN_RET_LOGE(uuid != NULL, AUTH_INVALID_ID, AUTH_CONN, "uuid is null");
    AUTH_CHECK_AND_RETURN_RET_LOGE(connInfo != NULL, AUTH_INVALID_ID, AUTH_CONN, "connInfo is null");
    char networkId[NETWORK_ID_BUF_LEN] = { 0 };
    if (LnnGetNetworkIdByUuid(uuid, networkId, sizeof(networkId)) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "get networkId by uuid fail");
        return SOFTBUS_AUTH_GET_BR_CONN_INFO_FAIL;
    }

    uint32_t local, remote;
    if (LnnGetLocalNumU32Info(NUM_KEY_NET_CAP, &local) != SOFTBUS_OK ||
        LnnGetRemoteNumU32Info(networkId, NUM_KEY_NET_CAP, &remote) != SOFTBUS_OK) {
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
            if (!IsRemoteDeviceSupportBleGuide(uuid, CATEGORY_UUID)) {
                AUTH_LOGI(AUTH_CONN, "peer device is not support ble");
                continue;
            }
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

int32_t AuthDeviceGetConnInfoByType(const char *uuid, AuthLinkType type, AuthConnInfo *connInfo)
{
    if (uuid == NULL || uuid[0] == '\0' || connInfo == NULL) {
        AUTH_LOGE(AUTH_CONN, "invalid uuid or connInfo");
        return SOFTBUS_INVALID_PARAM;
    }
    if (GetAuthConnInfoByUuid(uuid, type, connInfo) != SOFTBUS_OK) {
        if (type == AUTH_LINK_TYPE_BR) {
            return TryGetBrConnInfo(uuid, connInfo);
        }
        return SOFTBUS_AUTH_NOT_FOUND;
    }
    if (type == AUTH_LINK_TYPE_BLE) {
        if (!CheckActiveAuthConnection(connInfo)) {
            AUTH_LOGI(AUTH_CONN, "auth ble connection not active");
            return SOFTBUS_AUTH_CONN_NOT_ACTIVE;
        }
    }
    return SOFTBUS_OK;
}

int32_t AuthDeviceGetP2pConnInfo(const char *uuid, AuthConnInfo *connInfo)
{
    if (uuid == NULL || uuid[0] == '\0' || connInfo == NULL) {
        AUTH_LOGE(AUTH_CONN, "invalid uuid or connInfo");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = GetAvailableAuthConnInfoByUuid(uuid, AUTH_LINK_TYPE_P2P, connInfo);
    if (ret == SOFTBUS_OK) {
        AUTH_LOGI(AUTH_CONN, "select auth type=%{public}d", AUTH_LINK_TYPE_P2P);
    }
    return ret;
}

int32_t AuthDeviceGetHmlConnInfo(const char *uuid, AuthConnInfo *connInfo)
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

int32_t AuthGetLatestAuthSeqListByType(const char *udid, int64_t *seqList, uint64_t *authVerifyTime, DiscoveryType type)
{
    if (udid == NULL || udid[0] == '\0' || seqList == NULL || authVerifyTime == NULL) {
        AUTH_LOGE(AUTH_CONN, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (!RequireAuthLock()) {
        AUTH_LOGE(AUTH_CONN, "lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    const AuthManager *authClient = NULL;
    const AuthManager *authServer = NULL;
    authClient = FindAuthManagerByUdid(udid, ConvertToAuthLinkType(type), false);
    authServer = FindAuthManagerByUdid(udid, ConvertToAuthLinkType(type), true);
    if (authClient == NULL && authServer == NULL) {
        AUTH_LOGE(AUTH_CONN, "authManager not found");
        ReleaseAuthLock();
        return SOFTBUS_AUTH_NOT_FOUND;
    }
    AuthLinkType seqType = ConvertToAuthLinkType(type);
    if (seqType == AUTH_LINK_TYPE_MAX) {
        AUTH_LOGE(AUTH_CONN, "seqType is invalid");
        ReleaseAuthLock();
        return SOFTBUS_AUTH_CONN_TYPE_INVALID;
    }
    if (authClient != NULL) {
        seqList[0] = authClient->lastAuthSeq[seqType];
        authVerifyTime[0] = authClient->lastVerifyTime;
    }
    if (authServer != NULL) {
        seqList[1] = authServer->lastAuthSeq[seqType];
        authVerifyTime[1] = authServer->lastVerifyTime;
    }
    ReleaseAuthLock();
    return SOFTBUS_OK;
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
            seqList[ConvertToDiscoveryType(linkList[i])] = authClient->lastAuthSeq[linkList[i]];
        } else if (authClient == NULL && authServer != NULL) {
            seqList[ConvertToDiscoveryType(linkList[i])] = authServer->lastAuthSeq[linkList[i]];
        } else if (authClient->lastVerifyTime >= authServer->lastVerifyTime) {
            seqList[ConvertToDiscoveryType(linkList[i])] = authClient->lastAuthSeq[linkList[i]];
        } else {
            seqList[ConvertToDiscoveryType(linkList[i])] = authServer->lastAuthSeq[linkList[i]];
        }
    }
    if (notFound) {
        ReleaseAuthLock();
        char *anonyUdid = NULL;
        Anonymize(udid, &anonyUdid);
        AUTH_LOGE(AUTH_CONN, "not found active authManager, udid=%{public}s", AnonymizeWrapper(anonyUdid));
        AnonymizeFree(anonyUdid);
        return SOFTBUS_AUTH_NOT_FOUND;
    }
    ReleaseAuthLock();
    return SOFTBUS_OK;
}

static void FillAuthHandleList(ListNode *list, AuthHandle *handle, int32_t *num, int32_t count)
{
    AuthManager *item = NULL;
    LIST_FOR_EACH_ENTRY(item, list, AuthManager, node) {
        if (item->connInfo[AUTH_LINK_TYPE_ENHANCED_P2P].type == AUTH_LINK_TYPE_ENHANCED_P2P &&
            item->hasAuthPassed[AUTH_LINK_TYPE_ENHANCED_P2P]) {
            handle[*num].authId = item->authId;
            handle[*num].type = AUTH_LINK_TYPE_ENHANCED_P2P;
            (*num)++;
        } else if (item->connInfo[AUTH_LINK_TYPE_P2P].type == AUTH_LINK_TYPE_P2P &&
            item->hasAuthPassed[AUTH_LINK_TYPE_P2P]) {
            handle[*num].authId = item->authId;
            handle[*num].type = AUTH_LINK_TYPE_P2P;
            (*num)++;
        }
        if (*num == count) {
            break;
        }
    }
}

static uint32_t GetAllHmlOrP2pAuthHandleNum(void)
{
    uint32_t count = 0;
    AuthManager *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_authServerList, AuthManager, node) {
        if ((item->connInfo[AUTH_LINK_TYPE_ENHANCED_P2P].type == AUTH_LINK_TYPE_ENHANCED_P2P &&
            item->hasAuthPassed[AUTH_LINK_TYPE_ENHANCED_P2P]) ||
            (item->connInfo[AUTH_LINK_TYPE_P2P].type == AUTH_LINK_TYPE_P2P &&
            item->hasAuthPassed[AUTH_LINK_TYPE_P2P])) {
            count++;
        }
    }
    LIST_FOR_EACH_ENTRY(item, &g_authClientList, AuthManager, node) {
        if ((item->connInfo[AUTH_LINK_TYPE_ENHANCED_P2P].type == AUTH_LINK_TYPE_ENHANCED_P2P &&
            item->hasAuthPassed[AUTH_LINK_TYPE_ENHANCED_P2P]) ||
            (item->connInfo[AUTH_LINK_TYPE_P2P].type == AUTH_LINK_TYPE_P2P &&
            item->hasAuthPassed[AUTH_LINK_TYPE_P2P])) {
            count++;
        }
    }
    return count;
}

int32_t GetHmlOrP2pAuthHandle(AuthHandle **authHandle, int32_t *num)
{
    if (authHandle == NULL || num == NULL) {
        AUTH_LOGE(AUTH_CONN, "authHandle is empty");
        return SOFTBUS_INVALID_PARAM;
    }
    if (!RequireAuthLock()) {
        AUTH_LOGE(AUTH_CONN, "get auth lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    uint32_t count = GetAllHmlOrP2pAuthHandleNum();
    if (count == 0) {
        AUTH_LOGE(AUTH_CONN, "not found hml or p2p authHandle");
        ReleaseAuthLock();
        return SOFTBUS_AUTH_NOT_FOUND;
    }
    AuthHandle *handle = (AuthHandle *)SoftBusCalloc(sizeof(AuthHandle) * count);
    if (handle == NULL) {
        AUTH_LOGE(AUTH_CONN, "authHandle calloc fail");
        ReleaseAuthLock();
        return SOFTBUS_MALLOC_ERR;
    }
    *num = 0;
    FillAuthHandleList(&g_authServerList, handle, num, count);
    FillAuthHandleList(&g_authClientList, handle, num, count);

    *authHandle = handle;
    ReleaseAuthLock();
    return SOFTBUS_OK;
}

void AuthDeviceGetLatestIdByUuid(const char *uuid, AuthLinkType type, AuthHandle *authHandle)
{
    if (uuid == NULL || uuid[0] == '\0' || authHandle == NULL) {
        AUTH_LOGE(AUTH_CONN, "uuid is empty");
        return;
    }
    if (!RequireAuthLock()) {
        return;
    }
    authHandle->type = type;
    uint32_t num = 0;
    AuthManager *auth[2] = { NULL, NULL }; /* 2: max size for (CLIENT+ SERVER) */
    auth[num++] = FindAuthManagerByUuid(uuid, type, false);
    auth[num++] = FindAuthManagerByUuid(uuid, type, true);
    if (type == AUTH_LINK_TYPE_BR && auth[0] == NULL && auth[1] == NULL) {
        num = 0;
        auth[num++] = FindAuthManagerByUuid(uuid, AUTH_LINK_TYPE_BLE, false);
        auth[num++] = FindAuthManagerByUuid(uuid, AUTH_LINK_TYPE_BLE, true);
        authHandle->type = AUTH_LINK_TYPE_BLE;
    }
    authHandle->authId = AUTH_INVALID_ID;
    uint64_t latestVerifyTime = 0;
    for (uint32_t i = 0; i < num; i++) {
        uint64_t tmpTime = 0;
        if (auth[i] != NULL) {
            tmpTime = GetLatestAvailableSessionKeyTime(&auth[i]->sessionKeyList, (AuthLinkType)authHandle->type);
        }
        if (tmpTime > latestVerifyTime) {
            authHandle->authId = auth[i]->authId;
            latestVerifyTime = tmpTime;
        }
    }
    ReleaseAuthLock();
    char *anonyUuid = NULL;
    Anonymize(uuid, &anonyUuid);
    AUTH_LOGI(AUTH_CONN,
        "latest auth manager found, latestAuthId=%{public}" PRId64 ", lastVerifyTime=%{public}" PRIu64
        ", uuid=%{public}s, type=%{public}d",
        authHandle->authId, latestVerifyTime, AnonymizeWrapper(anonyUuid), authHandle->type);
    AnonymizeFree(anonyUuid);
}

int64_t AuthDeviceGetIdByConnInfo(const AuthConnInfo *connInfo, bool isServer)
{
    if (connInfo == NULL) {
        AUTH_LOGE(AUTH_CONN, "connInfo is null");
        return AUTH_INVALID_ID;
    }
    AUTH_CHECK_AND_RETURN_RET_LOGE(CheckAuthConnInfoType(connInfo), AUTH_INVALID_ID,
        AUTH_FSM, "connInfo type error");
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
        ReleaseAuthLock();
        char *anoyUuid = NULL;
        Anonymize(uuid, &anoyUuid);
        AUTH_LOGE(AUTH_CONN, "not found auth manager, uuid=%{public}s, connType=%{public}d, side=%{public}s",
            AnonymizeWrapper(anoyUuid), type, GetAuthSideStr(isServer));
        AnonymizeFree(anoyUuid);
        return AUTH_INVALID_ID;
    }
    int64_t authId = auth->authId;
    ReleaseAuthLock();
    return authId;
}

int32_t AuthDeviceGetAuthHandleByIndex(const char *udid, bool isServer, int32_t index, AuthHandle *authHandle)
{
    if (udid == NULL || authHandle == NULL) {
        AUTH_LOGE(AUTH_FSM, "param error");
        return SOFTBUS_INVALID_PARAM;
    }
    if (!RequireAuthLock()) {
        AUTH_LOGE(AUTH_CONN, "RequireAuthLock fail");
        return SOFTBUS_LOCK_ERR;
    }
    AuthManager *auth = FindNormalizedKeyAuthManagerByUdid(udid, isServer);
    if (auth == NULL) {
        AUTH_LOGE(AUTH_CONN, "not found auth manager, side=%{public}s", GetAuthSideStr(isServer));
        ReleaseAuthLock();
        return SOFTBUS_AUTH_NOT_FOUND;
    }
    AuthLinkType type = GetSessionKeyTypeByIndex(&auth->sessionKeyList, index);
    ReleaseAuthLock();
    if (type == AUTH_LINK_TYPE_MAX || type < AUTH_LINK_TYPE_WIFI) {
        AUTH_LOGE(AUTH_CONN, "auth type error");
        return SOFTBUS_AUTH_NOT_FOUND;
    }
    authHandle->authId = auth->authId;
    authHandle->type = type;
    AUTH_LOGI(AUTH_CONN, "found auth manager, side=%{public}s, type=%{public}d, authId=%{public}" PRId64,
        GetAuthSideStr(isServer), type, auth->authId);
    return SOFTBUS_OK;
}

uint32_t AuthGetEncryptSize(int64_t authId, uint32_t inLen)
{
    AuthManager *auth = GetAuthManagerByAuthId(authId);
    if (auth != NULL) {
        DelDupAuthManager(auth);
        return inLen + ENCRYPT_OVER_HEAD_LEN;
    }
    return inLen + OVERHEAD_LEN;
}

uint32_t AuthGetDecryptSize(uint32_t inLen)
{
    if (inLen <= OVERHEAD_LEN) {
        return inLen;
    }
    return inLen - OVERHEAD_LEN;
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
    return UpdateAuthManagerByAuthId(authId, SetAuthP2pMac, &inAuth, AUTH_LINK_TYPE_P2P);
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
        return SOFTBUS_AUTH_COMM_INIT_FAIL;
    }
    InitAuthReqInfo();

    AuthConnListener connListener = {
        .onConnectResult = OnConnectResult,
        .onDisconnected = OnDisconnected,
        .onDataReceived = OnDataReceived,
    };
    if (AuthConnInit(&connListener) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_INIT, "AuthConnInit fail");
        AuthCommonDeinit();
        return SOFTBUS_AUTH_CONN_INIT_FAIL;
    }
    if (LnnAsyncCallbackDelayHelper(GetLooper(LOOP_TYPE_DEFAULT), AuthRegisterToDpDelay, NULL, DELAY_REG_DP_TIME) !=
        SOFTBUS_OK) {
        AUTH_LOGE(AUTH_INIT, "delay registertoDp failed");
        return SOFTBUS_AUTH_INIT_FAIL;
    }
    AUTH_LOGI(AUTH_INIT, "auth init succ");
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
    DeInitAuthReqInfo();
    AuthCommonDeinit();
    AUTH_LOGI(AUTH_INIT, "auth deinit succ");
}
