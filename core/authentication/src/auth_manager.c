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
#include "auth_interface.h"
#include "auth_log.h"
#include "auth_request.h"
#include "auth_normalize_request.h"
#include "auth_session_fsm.h"
#include "auth_session_message.h"
#include "bus_center_manager.h"
#include "device_profile_listener.h"
#include "lnn_ctrl_lane.h"
#include "lnn_async_callback_utils.h"
#include "lnn_app_bind_interface.h"
#include "lnn_decision_db.h"
#include "lnn_device_info.h"
#include "lnn_event.h"
#include "lnn_lane_interface.h"
#include "lnn_lane_link.h"
#include "lnn_local_net_ledger.h"
#include "lnn_feature_capability.h"
#include "lnn_heartbeat_ctrl.h"
#include "lnn_net_builder.h"
#include "softbus_adapter_hitrace.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_socket.h"
#include "softbus_def.h"

#define MAX_AUTH_VALID_PERIOD              (30 * 60 * 1000L)            /* 30 mins */
#define SCHEDULE_UPDATE_SESSION_KEY_PERIOD ((5 * 60 + 30) * 60 * 1000L) /* 5 hour 30 mins */
#define FLAG_REPLY                         1
#define FLAG_ACTIVE                        0
#define UDID_SHORT_HASH_LEN_TEMP           8
#define RETRY_REGDATA_TIMES                3
#define RETRY_REGDATA_MILLSECONDS          300
#define DELAY_REG_DP_TIME                  10000
#define CODE_VERIFY_DEVICE                 2
#define CODE_KEEP_ALIVE                    3

static ListNode g_authClientList = { &g_authClientList, &g_authClientList };
static ListNode g_authServerList = { &g_authServerList, &g_authServerList };

static AuthVerifyListener g_verifyListener = { 0 };
static GroupChangeListener g_groupChangeListener = { 0 };
static AuthTransCallback g_transCallback = { 0 };
static bool g_regDataChangeListener = false;
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

static bool CheckAuthConnInfoType(const AuthConnInfo *connInfo)
{
    AUTH_CHECK_AND_RETURN_RET_LOGE(connInfo != NULL, false, AUTH_FSM, "connInfo is null");
    if (connInfo->type >= AUTH_LINK_TYPE_WIFI && connInfo->type < AUTH_LINK_TYPE_MAX) {
        return true;
    }
    return false;
}

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
        auth->connId[type] = 0;
        (void)memset_s(&auth->connInfo[type], sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
        for (int32_t i = AUTH_LINK_TYPE_WIFI; i < AUTH_LINK_TYPE_MAX; i++) {
            if (auth->connId[i] == 0) {
                continue;
            }
            ClearSessionkeyByAuthLinkType(auth->authId, &auth->sessionKeyList, (AuthLinkType)type);
            AUTH_LOGI(AUTH_FSM, "only clear connInfo, udid=%{public}s, side=%{public}s, type=%{public}d,"
                " authId=%{public}" PRId64, anonyUdid, GetAuthSideStr(auth->isServer), type, auth->authId);
            AnonymizeFree(anonyUdid);
            return;
        }
    }
    AUTH_LOGI(AUTH_FSM, "delete auth manager, udid=%{public}s, side=%{public}s, authId=%{public}" PRId64, anonyUdid,
        GetAuthSideStr(auth->isServer), auth->authId);
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
        if (item->connInfo[type].type == type && (strcmp(item->uuid, uuid) == 0) && item->hasAuthPassed) {
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
        if (item->connInfo[type].type == type && (strcmp(item->udid, udid) == 0) && item->hasAuthPassed) {
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
        return SOFTBUS_ERR;
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
        DelAuthManager(item, AUTH_LINK_TYPE_MAX);
    }
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_authServerList, AuthManager, node) {
        if (item->hasAuthPassed || strcmp(item->udid, udid) != 0) {
            continue;
        }
        DelAuthManager(item, AUTH_LINK_TYPE_MAX);
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
    char *anonyUuid = NULL;
    Anonymize(uuid, &anonyUuid);
    if (auth == NULL) {
        AUTH_LOGI(AUTH_CONN, "auth not found by uuid, connType=%{public}d, uuid=%{public}s", type, anonyUuid);
        AnonymizeFree(anonyUuid);
        ReleaseAuthLock();
        return SOFTBUS_AUTH_NOT_FOUND;
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

static int64_t GetLatestIdByConnInfo(const AuthConnInfo *connInfo)
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
        if (auth[i] != NULL && auth[i]->lastVerifyTime > latestVerifyTime && auth[i]->hasAuthPassed) {
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

static int64_t GetActiveAuthIdByConnInfo(const AuthConnInfo *connInfo, bool judgeTimeOut)
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
    for (uint32_t i = 0; i < num && judgeTimeOut; i++) {
        if (auth[i] != NULL && (currentTime - auth[i]->lastActiveTime >= MAX_AUTH_VALID_PERIOD)) {
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
        if (auth[i] != NULL && auth[i]->lastVerifyTime > maxVerifyTime) {
            authId = auth[i]->authId;
        }
    }
    AUTH_LOGI(AUTH_CONN, "get active auth manager. authId=%{public}" PRId64 "", authId);
    ReleaseAuthLock();
    return authId;
}

static int32_t ProcessSessionKey(SessionKeyList *list, int32_t *index, int64_t authSeq, const SessionKey *key,
    AuthSessionInfo *info)
{
    if (info->normalizedType == NORMALIZED_SUPPORT) {
        if (SetSessionKeyAuthLinkType(list, info->normalizedIndex, info->connInfo.type) == SOFTBUS_OK) {
            AUTH_LOGI(AUTH_FSM, "index is alread exist");
            return SOFTBUS_OK;
        }
        *index = info->normalizedIndex;
    }
    if (AddSessionKey(list, *index, key, info->connInfo.type) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "failed to add a sessionKey");
        return SOFTBUS_ERR;
    }
    AUTH_LOGI(AUTH_FSM, "authSeq=%{public}" PRId64 ",add session key index=%{public}d, new type=%{public}d",
        authSeq, *index, info->connInfo.type);
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
        AUTH_LOGE(AUTH_FSM, "str copy uuid fail, uuid=%{public}s", anonyUuid);
        AnonymizeFree(anonyUuid);
    }
    if (memcpy_s(&auth->connInfo[info->connInfo.type], sizeof(AuthConnInfo),
        &info->connInfo, sizeof(AuthConnInfo)) != EOK) {
        AUTH_LOGE(AUTH_FSM, "connInfo cpy fail");
        return NULL;
    }
    return auth;
}

static AuthManager *AuthManagerIsExist(int64_t authSeq, const AuthSessionInfo *info, bool *isNewCreated)
{
    AuthManager *auth = FindAuthManagerByConnInfo(&info->connInfo, info->isServer);
    if (auth != NULL && auth->connInfo[info->connInfo.type].type != 0) {
        if (strcpy_s(auth->uuid, UUID_BUF_LEN, info->uuid) != EOK) {
            char *anonyUuid = NULL;
            Anonymize(info->uuid, &anonyUuid);
            AUTH_LOGE(AUTH_FSM, "str copy uuid fail, uuid=%{public}s", anonyUuid);
            AnonymizeFree(anonyUuid);
        }
        if (auth->connId[info->connInfo.type] != info->connId &&
            auth->connInfo[info->connInfo.type].type == AUTH_LINK_TYPE_WIFI) {
            DisconnectAuthDevice(&auth->connId[info->connInfo.type]);
            auth->hasAuthPassed = false;
            AUTH_LOGI(AUTH_FSM, "auth manager may single device on line");
        }
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
    auth->lastAuthSeq[info->connInfo.type] = authSeq;
    auth->lastVerifyTime = GetCurrentTimeMs();
    auth->lastActiveTime = GetCurrentTimeMs();
    return auth;
}

int32_t AuthManagerSetSessionKey(int64_t authSeq, AuthSessionInfo *info, const SessionKey *sessionKey,
    bool isConnect)
{
    AUTH_CHECK_AND_RETURN_RET_LOGE(info != NULL, SOFTBUS_INVALID_PARAM, AUTH_FSM, "info is NULL");
    AUTH_CHECK_AND_RETURN_RET_LOGE(sessionKey != NULL, SOFTBUS_INVALID_PARAM, AUTH_FSM, "sessionKey is NULL");
    AUTH_CHECK_AND_RETURN_RET_LOGE(CheckAuthConnInfoType(&info->connInfo), SOFTBUS_INVALID_PARAM,
        AUTH_FSM, "connInfo type error");
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
    if (ProcessSessionKey(&auth->sessionKeyList, &sessionKeyIndex, authSeq, sessionKey, info) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "failed to add a sessionkey");
        if (isNewCreated) {
            DelAuthManager(auth, info->connInfo.type);
        }
        ReleaseAuthLock();
        return SOFTBUS_ERR;
    }
    AuthHandle authHandle = { .authId = auth->authId, .type = info->connInfo.type };
    if (auth->connInfo[info->connInfo.type].type == AUTH_LINK_TYPE_WIFI && !auth->isServer) {
        ScheduleUpdateSessionKey(authHandle, SCHEDULE_UPDATE_SESSION_KEY_PERIOD);
    }
    int32_t ret = SOFTBUS_OK;
    if (!isConnect) {
        ret = SetSessionKeyAvailable(&auth->sessionKeyList, sessionKeyIndex);
        auth->hasAuthPassed = true;
    }
    AUTH_LOGI(AUTH_FSM,
        "auth manager. authId=%{public}" PRId64 ", authSeq=%{public}" PRId64
        ", index=%{public}d, lastVerifyTime=%{public}" PRId64 ", ret=%{public}d",
        auth->authId, authSeq, sessionKeyIndex, auth->lastVerifyTime, ret);
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

static void NotifyDeviceVerifyPassed(AuthHandle authHandle, const NodeInfo *nodeInfo)
{
    AuthManager *auth = GetAuthManagerByAuthId(authHandle.authId);
    if (auth == NULL) {
        AUTH_LOGE(AUTH_FSM, "get auth manager failed");
        return;
    }
    if (auth->connInfo[authHandle.type].type == AUTH_LINK_TYPE_P2P ||
        auth->connInfo[authHandle.type].type == AUTH_LINK_TYPE_ENHANCED_P2P) {
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

static void NotifyDeviceDisconnect(AuthHandle authHandle)
{
    if (g_verifyListener.onDeviceDisconnect == NULL) {
        AUTH_LOGW(AUTH_FSM, "onDeviceDisconnect not set");
        return;
    }
    g_verifyListener.onDeviceDisconnect(authHandle);
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
    return SOFTBUS_ERR;
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
    AuthHandle authHandle, const AuthConnInfo *connInfo, uint32_t requestId, const AuthConnCallback *connCb)
{
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
    request.addTime = GetCurrentTimeMs();
    request.isFastAuth = true;
    if (connInfo->type == AUTH_LINK_TYPE_BR) {
        request.connInfo.info.brInfo.connectionId = GetConnId(connId);
    }
    if (AddAuthRequest(&request) == 0) {
        AUTH_LOGE(AUTH_CONN, "add reconnect request fail, requestId=%{public}u", requestId);
        return SOFTBUS_ERR;
    }
    if (ConnectAuthDevice(requestId, &request.connInfo, sideType) != SOFTBUS_OK) {
        DelAuthRequest(requestId);
        return SOFTBUS_AUTH_CONN_FAIL;
    }
    return SOFTBUS_OK;
}

static void ReportAuthRequestPassed(uint32_t requestId, AuthHandle authHandle, const NodeInfo *nodeInfo)
{
    AuthRequest request;
    if (GetAuthRequest(requestId, &request) != SOFTBUS_OK) {
        AUTH_LOGI(AUTH_FSM, "auth request not found, only notify LNN to update nodeInfo");
        NotifyDeviceVerifyPassed(authHandle, nodeInfo);
        return;
    }
    do {
        if (CheckAuthConnCallback(&request.connCb)) {
            NotifyDeviceVerifyPassed(authHandle, nodeInfo);
            if (request.connInfo.type == AUTH_LINK_TYPE_WIFI || request.connInfo.type == AUTH_LINK_TYPE_P2P ||
                request.connInfo.type == AUTH_LINK_TYPE_ENHANCED_P2P) {
                PerformAuthConnCallback(request.requestId, SOFTBUS_OK, authHandle.authId);
                DelAuthRequest(request.requestId);
                continue;
            }
            /* For open auth br/ble connection, reconnect to keep long-connection. */
            DelAuthRequest(request.requestId);
            if (StartReconnectDevice(authHandle, &request.connInfo, request.requestId, &request.connCb) != SOFTBUS_OK) {
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
    auth->hasAuthPassed = true;
    if (info->nodeInfo.p2pInfo.p2pMac[0] != '\0') {
        if (strcpy_s(auth->p2pMac, sizeof(auth->p2pMac), info->nodeInfo.p2pInfo.p2pMac)) {
            AUTH_LOGE(AUTH_FSM, "copy p2pMac fail, authSeq=%{public}" PRId64, authSeq);
        }
    }
    ReleaseAuthLock();
    AuthHandle authHandle = { .authId = auth->authId, .type = info->connInfo.type };
    if (info->isServer) {
        NotifyDeviceVerifyPassed(authHandle, &info->nodeInfo);
    } else {
        ReportAuthRequestPassed(info->requestId, authHandle, &info->nodeInfo);
        UpdateAuthDevicePriority(info->connId);
    }
}

void AuthManagerSetAuthFailed(int64_t authSeq, const AuthSessionInfo *info, int32_t reason)
{
    AUTH_CHECK_AND_RETURN_LOGE(info != NULL, AUTH_FSM, "auth session info is null");
    AUTH_CHECK_AND_RETURN_LOGE(CheckAuthConnInfoType(&info->connInfo), AUTH_FSM, "connInfo type error");
    AUTH_LOGE(AUTH_FSM, "SetAuthFailed: authSeq=%{public}" PRId64 ", requestId=%{public}u, reason=%{public}d", authSeq,
        info->requestId, reason);
    AuthManager *auth = GetAuthManagerByConnInfo(&info->connInfo, info->isServer);
    bool needDisconnect = true;
    if (auth != NULL && reason == SOFTBUS_AUTH_TIMEOUT && info->connInfo.type == AUTH_LINK_TYPE_WIFI
        && info->connInfo.info.ipInfo.port != auth->connInfo[AUTH_LINK_TYPE_WIFI].info.ipInfo.port) {
        AUTH_LOGE(AUTH_FSM, "auth manager port change, connType=%{public}d, side=%{public}s",
            info->connInfo.type, GetAuthSideStr(info->isServer));
        needDisconnect = false;
    }
    if (auth != NULL && auth->hasAuthPassed && needDisconnect) {
        AUTH_LOGE(AUTH_FSM, "update session key fail, authId=%{public}" PRId64, auth->authId);
        AuthHandle authHandle = { .authId = auth->authId, .type = info->connInfo.type };
        NotifyDeviceDisconnect(authHandle);
    }
    DelDupAuthManager(auth);

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

static void HandleBleConnectResult(uint32_t requestId, int64_t authId, uint64_t connId, int32_t result, int32_t type)
{
    AuthRequest request;
    if (GetAuthRequest(requestId, &request) != SOFTBUS_OK) {
        AUTH_LOGI(AUTH_CONN, "get request info failed, requestId=%{public}u", requestId);
        return;
    }
    AuthManager inAuth = {0};
    inAuth.connId[type] = connId;
    if (UpdateAuthManagerByAuthId(authId, SetAuthConnId, &inAuth, (AuthLinkType)type) != SOFTBUS_OK) {
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

static int32_t GenerateUdidHash(const char *udid, uint8_t *hash)
{
    if (SoftBusGenerateStrHash((uint8_t *)udid, strlen(udid), hash) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "generate udidHash fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t GetUdidShortHash(const AuthConnInfo *connInfo, char *udidBuf, uint32_t bufLen)
{
    char udid[UDID_BUF_LEN] = {0};
    uint8_t emptyHash[SHA_256_HASH_LEN] = {0};
    uint8_t hash[SHA_256_HASH_LEN] = {0};
    switch (connInfo->type) {
        case AUTH_LINK_TYPE_BR:
            if (LnnGetUdidByBrMac(connInfo->info.brInfo.brMac, udid, UDID_BUF_LEN) != SOFTBUS_OK) {
                AUTH_LOGE(AUTH_FSM, "get udid by brMac fail.");
                return SOFTBUS_ERR;
            }
            if (GenerateUdidHash(udid, hash) != SOFTBUS_OK) {
                AUTH_LOGE(AUTH_FSM, "GenerateUdidHash fail.");
                return SOFTBUS_ERR;
            }
            break;
        case AUTH_LINK_TYPE_WIFI:
            if (ConvertHexStringToBytes(hash, SHA_256_HASH_LEN, (const char *)connInfo->info.ipInfo.deviceIdHash,
                strlen((const char *)connInfo->info.ipInfo.deviceIdHash)) != SOFTBUS_OK) {
                return SOFTBUS_ERR;
            }
            break;
        case AUTH_LINK_TYPE_BLE:
            if (memcpy_s(hash, SHA_256_HASH_LEN, connInfo->info.bleInfo.deviceIdHash, UDID_HASH_LEN) != EOK) {
                return SOFTBUS_MEM_ERR;
            }
            break;
        case AUTH_LINK_TYPE_P2P:
        case AUTH_LINK_TYPE_ENHANCED_P2P:
            if (GenerateUdidHash(connInfo->info.ipInfo.udid, hash) != SOFTBUS_OK) {
                AUTH_LOGE(AUTH_FSM, "GenerateUdidHash fail.");
                return SOFTBUS_ERR;
            }
            break;
        default:
            AUTH_LOGE(AUTH_CONN, "unknown connType. type=%{public}d", connInfo->type);
            return SOFTBUS_ERR;
    }
    if (memcmp(emptyHash, hash, SHA_256_HASH_LEN) == 0) {
        AUTH_LOGI(AUTH_CONN, "udidHash is empty");
        return SOFTBUS_ERR;
    }
    if (ConvertBytesToHexString(udidBuf, bufLen, hash, UDID_SHORT_HASH_LEN_TEMP) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "convert bytes to string fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
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

int32_t AuthVerifyAfterNotifyNormalize(NormalizeRequest *request)
{
    if (request == NULL) {
        AUTH_LOGE(AUTH_CONN, "normalize request is null");
        return SOFTBUS_INVALID_PARAM;
    }
    AuthParam authInfo = {
        .authSeq = request->authSeq,
        .requestId = request->requestId,
        .connId = request->connId,
        .isServer = false,
        .isFastAuth = request->isFastAuth,
    };
    int32_t ret = AuthSessionStartAuth(&authInfo, &request->connInfo);
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "start auth session fail=%{public}d, requestId=%{public}u", ret, request->requestId);
        DisconnectAuthDevice(&request->connId);
        ReportAuthRequestFailed(request->requestId, ret);
    }
    return ret;
}

static uint32_t AddConcurrentAuthRequest(const AuthConnInfo *connInfo, AuthRequest *request, uint64_t connId)
{
    char udidHashHexStr[SHA_256_HEX_HASH_LEN] = {0};
    uint32_t num = 0;
    if (GetUdidShortHash(connInfo, udidHashHexStr, SHA_256_HEX_HASH_LEN) == SOFTBUS_OK) {
        NormalizeRequest normalizeRequest = {.authSeq = request->traceId, .requestId = request->requestId,
            .connId = connId, .isFastAuth = request->isFastAuth, .connInfo = *connInfo};
        if (strcpy_s(normalizeRequest.udidHash, sizeof(normalizeRequest.udidHash), udidHashHexStr) != EOK) {
            return num;
        }
        num = AddNormalizeRequest(&normalizeRequest);
        char *anonyUdidHash = NULL;
        Anonymize(udidHashHexStr, &anonyUdidHash);
        AUTH_LOGI(AUTH_CONN, "add normalize queue, num=%{public}d, udidHash=%{public}s", num, anonyUdidHash);
        AnonymizeFree(anonyUdidHash);
    }
    return num;
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
    if ((connInfo != NULL) && (connInfo->type == AUTH_LINK_TYPE_BLE) && (request.type == REQUEST_TYPE_CONNECT)) {
        int64_t authId = GetLatestIdByConnInfo(connInfo);
        if (authId != AUTH_INVALID_ID) {
            HandleBleConnectResult(requestId, authId, connId, result, connInfo->type);
            SoftbusHitraceStop();
            return;
        }
    }
    uint32_t num = AddConcurrentAuthRequest(&request.connInfo, &request, connId);
    if (num > 1) {
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
        AuthFsm *fsm = GetAuthFsmByConnId(connId, true);
        if ((fsm != NULL && fsm->info.idType == EXCHANGE_NETWORKID) ||
            (fsm != NULL && fsm->info.idType == EXCHANGE_FAIL)) {
            ReleaseAuthLock();
            ret = AuthSessionProcessDevIdData(head->seq, data, head->len);
            if (ret != SOFTBUS_OK) {
                AUTH_LOGE(AUTH_FSM,
                    "perform auth session recv devId fail. seq=%{public}" PRId64 ", ret=%{public}d", head->seq, ret);
            }
            return;
        }
        if (fsm != NULL && fsm->info.idType == EXCHANHE_UDID) {
            AUTH_LOGE(AUTH_FSM, "the same connId fsm not support, ignore auth seq=%{public}" PRId64, head->seq);
            ReleaseAuthLock();
            HandleRepeatDeviceIdDataDelay(connId, connInfo, fromServer, head, data);
            return;
        }
        ReleaseAuthLock();
        AuthParam authInfo = {
            .authSeq = head->seq,
            .requestId = AuthGenRequestId(),
            .connId = connId,
            .isServer = true,
            .isFastAuth = true,
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

static void HandleDeviceInfoData(
    uint64_t connId, const AuthConnInfo *connInfo, bool fromServer, const AuthDataHead *head, const uint8_t *data)
{
    int32_t ret = SOFTBUS_OK;
    DeviceMessageParse messageParse = { 0 };
    if (IsDeviceMessagePacket(connInfo, head, data, !fromServer, &messageParse)) {
        if (head->flag == 0 && messageParse.messageType == CODE_VERIFY_DEVICE) {
            AUTH_LOGE(AUTH_FSM, "flush device need relay");
            FlushDeviceProcess(connInfo, !fromServer, &messageParse);
        } else if (head->flag == 0 && messageParse.messageType == CODE_KEEP_ALIVE) {
            if (AuthSetTcpKeepAlive(connInfo, messageParse.cycle) != SOFTBUS_OK) {
                AUTH_LOGE(AUTH_FSM, "set tcp keepalive fail");
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
    if (PostAuthData(connId, fromServer, &head, data) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "post data fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
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
    auth->lastActiveTime = GetCurrentTimeMs();
    auth->connId[type] = connId;
    AuthHandle authHandle = { .authId = authId, .type = GetConnType(connId) };
    ReleaseAuthLock();
    if (g_transCallback.OnDataReceived != NULL) {
        g_transCallback.OnDataReceived(authHandle, head, decData, decDataLen);
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
    if (auth[0] != NULL && DecryptInner(&auth[0]->sessionKeyList, connInfo->type, &inDataInfo,
        &decData, &decDataLen) == SOFTBUS_OK) {
        ReleaseAuthLock();
        SoftBusFree(decData);
        RemoveAuthSessionKeyByIndex(auth[0]->authId, index, connInfo->type);
    } else if (auth[1] != NULL && DecryptInner(&auth[1]->sessionKeyList, connInfo->type, &inDataInfo,
        &decData, &decDataLen) == SOFTBUS_OK) {
        ReleaseAuthLock();
        SoftBusFree(decData);
        RemoveAuthSessionKeyByIndex(auth[1]->authId, index, connInfo->type);
    } else {
        ReleaseAuthLock();
        AUTH_LOGE(AUTH_CONN, "decrypt trans data fail.");
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
        if (g_transCallback.OnDisconnected != NULL) {
            g_transCallback.OnDisconnected(authHandle);
        }
        if (GetConnType(connId) == AUTH_LINK_TYPE_WIFI || GetConnType(connId) == AUTH_LINK_TYPE_P2P ||
            GetConnType(connId) == AUTH_LINK_TYPE_ENHANCED_P2P) {
            NotifyDeviceDisconnect(authHandle);
            DisconnectAuthDevice(&dupConnId);
            AuthManager inAuth = {0};
            inAuth.connId[GetConnType(connId)] = dupConnId;
            (void)UpdateAuthManagerByAuthId(authIds[i], SetAuthConnId, &inAuth, (AuthLinkType)GetConnType(connId));
            RemoveAuthManagerByAuthId(authHandle);
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
    if (connInfo == NULL || !CheckVerifyCallback(callback)) {
        AUTH_LOGE(AUTH_CONN, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    AUTH_CHECK_AND_RETURN_RET_LOGE(CheckAuthConnInfoType(connInfo), SOFTBUS_INVALID_PARAM,
        AUTH_FSM, "connInfo type error");
    return StartVerifyDevice(requestId, connInfo, callback, NULL, isFastAuth);
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
    if (!auth->hasAuthPassed) {
        ReleaseAuthLock();
        AUTH_LOGI(AUTH_FSM, "auth pass = false, don't need to leave");
        return;
    }
    if (auth->connInfo[authHandle.type].type == AUTH_LINK_TYPE_WIFI) {
        DisconnectAuthDevice(&auth->connId[authHandle.type]);
    }
    DelAuthManager(auth, authHandle.type);
    AuthFreeConn(&authHandle);
    ReleaseAuthLock();
}

static int32_t PostDeviceMessageByUuid(const char *uuid, int32_t messageType, ModeCycle cycle)
{
    if (!RequireAuthLock()) {
        return SOFTBUS_LOCK_ERR;
    }
    uint32_t num = 0;
    int32_t ret = SOFTBUS_ERR;
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

static int32_t SetLocalDeviceTcpKeepAlive(const char *uuid, ModeCycle cycle)
{
    int32_t ret = SOFTBUS_ERR;
    AuthConnInfo connInfo;
    (void)memset_s(&connInfo, sizeof(connInfo), 0, sizeof(connInfo));
    ret = GetAuthConnInfoByUuid(uuid, AUTH_LINK_TYPE_WIFI, &connInfo);
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "get AuthConnInfo by uuid fail");
        return ret;
    }
    ret = AuthSetTcpKeepAlive(&connInfo, cycle);
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "set tcp keepalive fail");
    }
    return ret;
}

int32_t AuthFlushDevice(const char *uuid)
{
    if (uuid == NULL || uuid[0] == '\0') {
        AUTH_LOGE(AUTH_CONN, "uuid is empty");
        return SOFTBUS_INVALID_PARAM;
    }
    if (PostDeviceMessageByUuid(uuid, CODE_VERIFY_DEVICE, DEFT_FREQ_CYCLE) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "post flush device message by uuid fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t AuthSendKeepAlive(const char *uuid, ModeCycle cycle)
{
    if (uuid == NULL || uuid[0] == '\0' || cycle < HIGH_FREQ_CYCLE || cycle > DEFT_FREQ_CYCLE) {
        AUTH_LOGE(AUTH_CONN, "uuid is empty or invalid cycle");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SetLocalDeviceTcpKeepAlive(uuid, cycle) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "set local device tcp keepalive fail");
        return SOFTBUS_ERR;
    }
    if (PostDeviceMessageByUuid(uuid, CODE_KEEP_ALIVE, cycle) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "post device keepalive message by uuid fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t TryGetBrConnInfo(const char *uuid, AuthConnInfo *connInfo)
{
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
            return SOFTBUS_ERR;
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
        return SOFTBUS_ERR;
    }
    char udid[UDID_BUF_LEN] = {0};
    if (LnnGetRemoteStrInfo(networkId, STRING_KEY_DEV_UDID, udid, UDID_BUF_LEN) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "get peer udid fail");
        return SOFTBUS_ERR;
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
        if (linkList[i] == AUTH_LINK_TYPE_ENHANCED_P2P || linkList[i] == AUTH_LINK_TYPE_P2P) {
            if (!IsAuthReuseP2p(networkId, udid, linkList[i])) {
                continue;
            }
        }
        if (linkList[i] == AUTH_LINK_TYPE_BLE && !CheckActiveAuthConnection(&connInfo)) {
            AUTH_LOGI(AUTH_CONN, "auth ble connection not active");
            continue;
        }
        AUTH_LOGI(AUTH_CONN, "select auth type. i=%{public}d, authLinkType=%{public}d", i, linkList[i]);
        linkTypeList->linkType[linkTypeList->linkTypeNum] = linkList[i];
        linkTypeList->linkTypeNum++;
    }
    if (linkTypeList->linkTypeNum == 0) {
        AUTH_LOGE(AUTH_CONN, "no available auth link");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
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
        case AUTH_LINK_TYPE_P2P:
            authHandle.authId = GetActiveAuthIdByConnInfo(info, judgeTimeOut);
            if (authHandle.authId != AUTH_INVALID_ID) {
                return StartReconnectDevice(authHandle, info, requestId, callback);
            }
            return StartVerifyDevice(requestId, info, NULL, callback, true);
        case AUTH_LINK_TYPE_ENHANCED_P2P:
            authHandle.authId = GetActiveAuthIdByConnInfo(info, judgeTimeOut);
            if (authHandle.authId != AUTH_INVALID_ID) {
                AUTH_LOGI(AUTH_CONN, "reuse enhanced p2p authId=%{public}" PRId64, authHandle.authId);
                callback->onConnOpened(requestId, authHandle);
                break;
            }
            return StartVerifyDevice(requestId, info, NULL, callback, true);
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
        return SOFTBUS_ERR;
    }
    AuthLinkType seqType = ConvertToAuthLinkType(type);
    if (seqType == AUTH_LINK_TYPE_MAX) {
        AUTH_LOGE(AUTH_CONN, "seqType is invalid");
        ReleaseAuthLock();
        return SOFTBUS_ERR;
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
        AUTH_LOGE(AUTH_CONN, "not found active authManager, udid=%{public}s", anonyUdid);
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
            item->hasAuthPassed) {
            handle[*num].authId = item->authId;
            handle[*num].type = AUTH_LINK_TYPE_ENHANCED_P2P;
            (*num)++;
        } else if (item->connInfo[AUTH_LINK_TYPE_P2P].type == AUTH_LINK_TYPE_P2P && item->hasAuthPassed) {
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
        if ((item->connInfo[AUTH_LINK_TYPE_ENHANCED_P2P].type == AUTH_LINK_TYPE_ENHANCED_P2P ||
            item->connInfo[AUTH_LINK_TYPE_P2P].type == AUTH_LINK_TYPE_P2P) && item->hasAuthPassed) {
            count++;
        }
    }
    LIST_FOR_EACH_ENTRY(item, &g_authClientList, AuthManager, node) {
        if ((item->connInfo[AUTH_LINK_TYPE_ENHANCED_P2P].type == AUTH_LINK_TYPE_ENHANCED_P2P ||
            item->connInfo[AUTH_LINK_TYPE_P2P].type == AUTH_LINK_TYPE_P2P) && item->hasAuthPassed) {
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
    if (count <= 0) {
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
        authHandle->authId, latestVerifyTime, anonyUuid, authHandle->type);
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
        AUTH_LOGE(
            AUTH_CONN, "not found auth manager, connType=%{public}d, side=%{public}s", type, GetAuthSideStr(isServer));
        ReleaseAuthLock();
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

int32_t AuthDeviceEncrypt(AuthHandle *authHandle, const uint8_t *inData, uint32_t inLen, uint8_t *outData,
    uint32_t *outLen)
{
    if (authHandle == NULL || inData == NULL || inLen == 0 || outData == NULL || outLen == NULL ||
        *outLen < AuthGetEncryptSize(inLen)) {
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
        return SOFTBUS_ERR;
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

static void RegisterToDpDelay(void *para)
{
    DeviceProfileChangeListener deviceProfileChangeListener = {
        .onDeviceProfileAdd = OnDeviceBound,
        .onDeviceProfileDeleted = OnDeviceNotTrusted,
    };
    RegisterToDp(&deviceProfileChangeListener);
}

static void InitAuthReqInfo(void)
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

static void DeInitAuthReqInfo(void)
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
    InitAuthReqInfo();

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
    DeInitAuthReqInfo();
    AuthCommonDeinit();
    AUTH_LOGI(AUTH_INIT, "auth deinit succ");
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
    if (GetAuthConn(uuid, laneConnInfo->type, &authConnInfo) != SOFTBUS_OK) {
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

static int32_t AuthGetRequestOption(const char *networkId, LaneAllocInfo *allocInfo)
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
        return SOFTBUS_ERR;
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
        return SOFTBUS_ERR;
    }

    LaneAllocInfo allocInfo;
    if (memset_s(&allocInfo, sizeof(LaneAllocInfo), 0, sizeof(LaneAllocInfo) != EOK)) {
        AUTH_LOGE(AUTH_CONN, "LaneRequestOption memset_s fail");
        GetLaneManager()->lnnFreeLane(laneHandle);
        return SOFTBUS_MEM_ERR;
    }

    if (AuthGetRequestOption(networkId, &allocInfo) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "auth get requestOption fail");
        GetLaneManager()->lnnFreeLane(laneHandle);
        return SOFTBUS_ERR;
    }

    LaneAllocListener listener;
    listener.onLaneAllocSuccess = AuthOnLaneAllocSuccess;
    listener.onLaneAllocFail = AuthOnLaneAllocFail;
    AUTH_LOGI(AUTH_CONN, "auth alloc lane, laneHandle=%{public}u, authRequestId=%{public}u", laneHandle, authRequestId);
    if (GetLaneManager()->lnnAllocLane(laneHandle, &allocInfo, &listener) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "auth alloc lane fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}
