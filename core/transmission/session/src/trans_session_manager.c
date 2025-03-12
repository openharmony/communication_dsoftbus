/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "trans_session_manager.h"

#include "anonymizer.h"
#include "lnn_lane_link.h"
#include "permission_entry.h"
#include "securec.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_utils.h"
#include "legacy/softbus_hidumper_trans.h"
#include "trans_channel_callback.h"
#include "trans_client_proxy.h"
#include "trans_log.h"

#define MAX_SESSION_SERVER_NUM 100
#define CMD_REGISTED_SESSION_LIST "registed_sessionlist"
#define GET_ROUTE_TYPE(type) ((uint32_t)(type) & 0xff)
#define GET_CONN_TYPE(type) (((uint32_t)(type) >> 8) & 0xff)

static SoftBusList *g_sessionServerList = NULL;

static int32_t TransSessionForEachShowInfo(int32_t fd)
{
    if (g_sessionServerList == NULL) {
        TRANS_LOGE(TRANS_CTRL, "session server list is empty");
        return SOFTBUS_NO_INIT;
    }
    if (SoftBusMutexLock(&g_sessionServerList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "lock mutex failed");
        return SOFTBUS_LOCK_ERR;
    }

    SessionServer *pos = NULL;
    LIST_FOR_EACH_ENTRY(pos, &g_sessionServerList->list, SessionServer, node) {
        SoftBusTransDumpRegisterSession(fd, pos->pkgName, pos->sessionName, pos->uid, pos->pid);
    }

    (void)SoftBusMutexUnlock(&g_sessionServerList->lock);
    return SOFTBUS_OK;
}

int32_t TransSessionMgrInit(void)
{
    if (g_sessionServerList != NULL) {
        return SOFTBUS_OK;
    }
    g_sessionServerList = CreateSoftBusList();
    if (g_sessionServerList == NULL) {
        TRANS_LOGE(TRANS_CTRL, "session manager init fail");
        return SOFTBUS_MALLOC_ERR;
    }

    return SoftBusRegTransVarDump(CMD_REGISTED_SESSION_LIST, TransSessionForEachShowInfo);
}

void TransSessionMgrDeinit(void)
{
    if (g_sessionServerList != NULL) {
        DestroySoftBusList(g_sessionServerList);
        g_sessionServerList = NULL;
    }
}

bool TransSessionServerIsExist(const char *sessionName)
{
    if (sessionName == NULL) {
        return false;
    }
    if (g_sessionServerList == NULL) {
        TRANS_LOGE(TRANS_CTRL, "sessionServerList not init");
        return false;
    }

    SessionServer *pos = NULL;
    SessionServer *tmp = NULL;
    if (SoftBusMutexLock(&g_sessionServerList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "lock mutex failed");
        return false;
    }

    LIST_FOR_EACH_ENTRY_SAFE(pos, tmp, &g_sessionServerList->list, SessionServer, node) {
        if (strcmp(pos->sessionName, sessionName) == 0) {
            (void)SoftBusMutexUnlock(&g_sessionServerList->lock);
            return true;
        }
    }
    (void)SoftBusMutexUnlock(&g_sessionServerList->lock);
    char *tmpSessionName = NULL;
    Anonymize(sessionName, &tmpSessionName);
    TRANS_LOGE(TRANS_CTRL, "session server not exist, sessionName=%{public}s", AnonymizeWrapper(tmpSessionName));
    AnonymizeFree(tmpSessionName);
    return false;
}

static void ShowSessionServer(void)
{
    SessionServer *pos = NULL;
    SessionServer *tmp = NULL;
    int32_t count = 0;
    char *tmpName = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(pos, tmp, &g_sessionServerList->list, SessionServer, node) {
        Anonymize(pos->sessionName, &tmpName);
        TRANS_LOGI(TRANS_CTRL,
            "session server is exist. count=%{public}d, sessionName=%{public}s", count, AnonymizeWrapper(tmpName));
        AnonymizeFree(tmpName);
        count++;
    }
}

int32_t TransSessionServerAddItem(SessionServer *newNode)
{
    TRANS_CHECK_AND_RETURN_RET_LOGE(newNode != NULL, SOFTBUS_INVALID_PARAM, TRANS_CTRL, "param invalid");
    TRANS_CHECK_AND_RETURN_RET_LOGE(g_sessionServerList != NULL, SOFTBUS_NO_INIT, TRANS_CTRL, "not init");
    if (SoftBusMutexLock(&g_sessionServerList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "lock mutex failed");
        return SOFTBUS_LOCK_ERR;
    }
    if (g_sessionServerList->cnt >= MAX_SESSION_SERVER_NUM) {
        (void)ShowSessionServer();
        (void)SoftBusMutexUnlock(&g_sessionServerList->lock);
        TRANS_LOGE(TRANS_CTRL, "session server num reach max");
        return SOFTBUS_INVALID_NUM;
    }

    SessionServer *pos = NULL;
    SessionServer *tmp = NULL;
    char *tmpName = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(pos, tmp, &g_sessionServerList->list, SessionServer, node) {
        if (strcmp(pos->sessionName, newNode->sessionName) == 0) {
            Anonymize(newNode->sessionName, &tmpName);
            if ((pos->uid == newNode->uid) && (pos->pid == newNode->pid)) {
                TRANS_LOGI(TRANS_CTRL, "session server is exist, sessionName=%{public}s", AnonymizeWrapper(tmpName));
                (void)SoftBusMutexUnlock(&g_sessionServerList->lock);
                AnonymizeFree(tmpName);
                return SOFTBUS_SERVER_NAME_REPEATED;
            }
            if (CheckServiceIsRegistered(pos->pkgName, pos->pid) == SOFTBUS_OK) {
                TRANS_LOGI(TRANS_CTRL,
                    "sessionName=%{public}s has been used by other processes, old Pid=%{public}d, new pid=%{public}d",
                    AnonymizeWrapper(tmpName), pos->pid, newNode->pid);
                (void)SoftBusMutexUnlock(&g_sessionServerList->lock);
                AnonymizeFree(tmpName);
                return SOFTBUS_SERVER_NAME_USED;
            }
            pos->pid = newNode->pid;
            TRANS_LOGI(TRANS_CTRL, "sessionName=%{public}s is exist. old pid=%{public}d, new pid=%{public}d",
                AnonymizeWrapper(tmpName), pos->pid, newNode->pid);
            (void)SoftBusMutexUnlock(&g_sessionServerList->lock);
            AnonymizeFree(tmpName);
            SoftBusFree(newNode);
            return SOFTBUS_OK;
        }
    }

    Anonymize(newNode->sessionName, &tmpName);
    ListAdd(&(g_sessionServerList->list), &(newNode->node));
    TRANS_LOGI(TRANS_CTRL, "add sessionName=%{public}s", AnonymizeWrapper(tmpName));
    g_sessionServerList->cnt++;
    (void)SoftBusMutexUnlock(&g_sessionServerList->lock);
    AnonymizeFree(tmpName);
    return SOFTBUS_OK;
}

int32_t TransSessionServerDelItem(const char *sessionName)
{
    if (sessionName == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (g_sessionServerList == NULL) {
        return SOFTBUS_NO_INIT;
    }

    bool isFind = false;
    SessionServer *pos = NULL;
    SessionServer *tmp = NULL;
    if (SoftBusMutexLock(&g_sessionServerList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "lock mutex failed");
        return SOFTBUS_LOCK_ERR;
    }
    LIST_FOR_EACH_ENTRY_SAFE(pos, tmp, &g_sessionServerList->list, SessionServer, node) {
        if (strcmp(pos->sessionName, sessionName) == 0) {
            isFind = true;
            break;
        }
    }
    if (isFind) {
        ListDelete(&pos->node);
        SoftBusFree(pos);
        g_sessionServerList->cnt--;
        char *tmpName = NULL;
        Anonymize(sessionName, &tmpName);
        TRANS_LOGI(TRANS_CTRL, "destroy session server sessionName=%{public}s", AnonymizeWrapper(tmpName));
        AnonymizeFree(tmpName);
    }
    (void)SoftBusMutexUnlock(&g_sessionServerList->lock);
    return SOFTBUS_OK;
}

bool CheckUidAndPid(const char *sessionName, pid_t callingUid, pid_t callingPid)
{
    if (sessionName == NULL) {
        TRANS_LOGE(TRANS_CTRL, "Parameter sessionName is empty");
        return false;
    }
    if (g_sessionServerList == NULL) {
        TRANS_LOGE(TRANS_CTRL, "sessionServer is empty");
        return false;
    }
    if (SoftBusMutexLock(&g_sessionServerList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "Lock failure");
        return false;
    }

    SessionServer *pos = NULL;
    LIST_FOR_EACH_ENTRY(pos, &g_sessionServerList->list, SessionServer, node) {
        if (strcmp(pos->sessionName, sessionName) == 0 &&
            pos->uid == callingUid && pos->pid == callingPid) {
            (void)SoftBusMutexUnlock(&g_sessionServerList->lock);
            return true;
        }
    }

    (void)SoftBusMutexUnlock(&g_sessionServerList->lock);
    return false;
}

void TransDelItemByPackageName(const char *pkgName, int32_t pid)
{
    if (pkgName == NULL || g_sessionServerList == NULL) {
        return;
    }

    SessionServer *pos = NULL;
    SessionServer *tmp = NULL;
    if (SoftBusMutexLock(&g_sessionServerList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "lock mutex failed");
        return;
    }
    LIST_FOR_EACH_ENTRY_SAFE(pos, tmp, &g_sessionServerList->list, SessionServer, node) {
        if ((strcmp(pos->pkgName, pkgName) == 0) && (pos->pid == pid)) {
            if (CheckDBinder(pos->sessionName)) {
                // Remove RPC Permission when Client Process Exit
                (void)DeleteDynamicPermission(pos->sessionName);
            }
            ListDelete(&pos->node);
            g_sessionServerList->cnt--;
            SoftBusFree(pos);
            pos = NULL;
        }
    }
    (void)SoftBusMutexUnlock(&g_sessionServerList->lock);
    TRANS_LOGI(TRANS_CTRL, "del pkgName=%{public}s", pkgName);
}

int32_t TransGetPkgNameBySessionName(const char *sessionName, char *pkgName, uint16_t len)
{
    if (sessionName == NULL || pkgName == NULL || len == 0) {
        TRANS_LOGE(TRANS_CTRL, "param error");
        return SOFTBUS_INVALID_PARAM;
    }
    if (g_sessionServerList == NULL) {
        TRANS_LOGE(TRANS_CTRL, "session server list not init");
        return SOFTBUS_NO_INIT;
    }

    SessionServer *pos = NULL;
    SessionServer *tmp = NULL;
    if (SoftBusMutexLock(&g_sessionServerList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "lock mutex failed");
        return SOFTBUS_LOCK_ERR;
    }
    LIST_FOR_EACH_ENTRY_SAFE(pos, tmp, &g_sessionServerList->list, SessionServer, node) {
        if (strcmp(pos->sessionName, sessionName) == 0) {
            int32_t ret = strcpy_s(pkgName, len, pos->pkgName);
            (void)SoftBusMutexUnlock(&g_sessionServerList->lock);
            if (ret != EOK) {
                TRANS_LOGE(TRANS_CTRL, "strcpy_s error ret, ret=%{public}d", ret);
                return SOFTBUS_STRCPY_ERR;
            }
            return SOFTBUS_OK;
        }
    }

    (void)SoftBusMutexUnlock(&g_sessionServerList->lock);
    char *tmpName = NULL;
    Anonymize(sessionName, &tmpName);
    TRANS_LOGE(TRANS_CTRL, "not found sessionName=%{public}s.", AnonymizeWrapper(tmpName));
    AnonymizeFree(tmpName);
    return SOFTBUS_TRANS_SESSION_NAME_NO_EXIST;
}

int32_t TransGetUidAndPid(const char *sessionName, int32_t *uid, int32_t *pid)
{
    if (sessionName == NULL || uid == NULL || pid == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (g_sessionServerList == NULL) {
        TRANS_LOGE(TRANS_CTRL, "not init");
        return SOFTBUS_NO_INIT;
    }

    if (SoftBusMutexLock(&g_sessionServerList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "lock mutex failed");
        return SOFTBUS_LOCK_ERR;
    }

    SessionServer *pos = NULL;
    SessionServer *tmp = NULL;
    char *tmpName = NULL;
    Anonymize(sessionName, &tmpName);
    LIST_FOR_EACH_ENTRY_SAFE(pos, tmp, &g_sessionServerList->list, SessionServer, node) {
        if (strcmp(pos->sessionName, sessionName) == 0) {
            *uid = pos->uid;
            *pid = pos->pid;
            TRANS_LOGD(TRANS_CTRL, "sessionName=%{public}s, uid=%{public}d, pid=%{public}d",
                AnonymizeWrapper(tmpName), pos->uid, pos->pid);
            (void)SoftBusMutexUnlock(&g_sessionServerList->lock);
            AnonymizeFree(tmpName);
            return SOFTBUS_OK;
        }
    }

    (void)SoftBusMutexUnlock(&g_sessionServerList->lock);
    TRANS_LOGE(TRANS_CTRL, "err: sessionName=%{public}s", AnonymizeWrapper(tmpName));
    AnonymizeFree(tmpName);
    return SOFTBUS_TRANS_GET_PID_FAILED;
}

static void TransListDelete(ListNode *sessionServerList)
{
    SessionServer *pos = NULL;
    SessionServer *tmp = NULL;

    LIST_FOR_EACH_ENTRY_SAFE(pos, tmp, sessionServerList, SessionServer, node) {
        ListDelete(&pos->node);
        SoftBusFree(pos);
    }
}

static int32_t TransListCopy(ListNode *sessionServerList)
{
    TRANS_LOGD(TRANS_CTRL, "enter.");
    if (sessionServerList == NULL) {
        return SOFTBUS_NO_INIT;
    }

    SessionServer *pos = NULL;
    SessionServer *tmp = NULL;
    if (SoftBusMutexLock(&g_sessionServerList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "lock mutex failed");
        return SOFTBUS_LOCK_ERR;
    }
    LIST_FOR_EACH_ENTRY_SAFE(pos, tmp, &g_sessionServerList->list, SessionServer, node) {
        SessionServer *newPos = (SessionServer *)SoftBusMalloc(sizeof(SessionServer));
        if (newPos == NULL) {
            TransListDelete(sessionServerList);
            TRANS_LOGE(TRANS_CTRL, "SoftBusMalloc failed");
            (void)SoftBusMutexUnlock(&g_sessionServerList->lock);
            return SOFTBUS_MALLOC_ERR;
        }
        *newPos = *pos;
        ListAdd(sessionServerList, &newPos->node);
    }
    (void)SoftBusMutexUnlock(&g_sessionServerList->lock);
    return SOFTBUS_OK;
}

void TransOnLinkDown(const char *networkId, const char *uuid, const char *udid, const char *peerIp, int32_t type)
{
#define USER_SWITCH_OFFSET 10
    if (networkId == NULL || g_sessionServerList == NULL) {
        return;
    }
    int32_t routeType = (int32_t)GET_ROUTE_TYPE(type);
    int32_t connType = (int32_t)GET_CONN_TYPE(type);
    bool isUserSwitchEvent = (bool)(((uint32_t)(type) >> USER_SWITCH_OFFSET) & 0xff);
    char *anonyNetworkId = NULL;
    Anonymize(networkId, &anonyNetworkId);
    TRANS_LOGI(TRANS_CTRL,
        "routeType=%{public}d, networkId=%{public}s connType=%{public}d", routeType,
            AnonymizeWrapper(anonyNetworkId), connType);
    AnonymizeFree(anonyNetworkId);

    ListNode sessionServerList = {0};
    ListInit(&sessionServerList);
    int32_t ret = TransListCopy(&sessionServerList);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "copy list failed");
        return;
    }

    SessionServer *pos = NULL;
    SessionServer *tmp = NULL;
    LinkDownInfo info = {
        .uuid = uuid,
        .udid = udid,
        .peerIp = peerIp,
        .networkId = networkId,
        .routeType = type
    };

    LIST_FOR_EACH_ENTRY_SAFE(pos, tmp, &sessionServerList, SessionServer, node) {
        if (isUserSwitchEvent && pos->callerType != CALLER_TYPE_FEATURE_ABILITY) {
            continue;
        }
        (void)TransServerOnChannelLinkDown(pos->pkgName, pos->pid, &info);
    }

    if (routeType == WIFI_P2P) {
        LaneDeleteP2pAddress(networkId, true);
    }
    TransListDelete(&sessionServerList);
}

int32_t TransGetPidAndPkgName(const char *sessionName, int32_t uid, int32_t *pid, char *pkgName, uint32_t len)
{
    if (sessionName == NULL || pid == NULL || pkgName == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }

    if (len == 0 || len > PKG_NAME_SIZE_MAX) {
        TRANS_LOGE(TRANS_CTRL, "pkgName len is invalid.");
        return SOFTBUS_INVALID_PARAM;
    }

    if (g_sessionServerList == NULL) {
        TRANS_LOGE(TRANS_CTRL, "g_sessionServerList has not been initialized.");
        return SOFTBUS_NO_INIT;
    }

    if (SoftBusMutexLock(&g_sessionServerList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "lock mutex failed.");
        return SOFTBUS_LOCK_ERR;
    }

    SessionServer *pos = NULL;
    LIST_FOR_EACH_ENTRY(pos, &g_sessionServerList->list, SessionServer, node) {
        if (strcmp(pos->sessionName, sessionName) == 0 && pos->uid == uid) {
            *pid = pos->pid;
            int32_t ret = strcpy_s(pkgName, len, pos->pkgName);
            (void)SoftBusMutexUnlock(&g_sessionServerList->lock);
            if (ret != EOK) {
                TRANS_LOGE(TRANS_CTRL, "strcpy_s error ret, ret=%{public}d.", ret);
                return SOFTBUS_STRCPY_ERR;
            }
            return SOFTBUS_OK;
        }
    }

    (void)SoftBusMutexUnlock(&g_sessionServerList->lock);
    char *tmpName = NULL;
    Anonymize(sessionName, &tmpName);
    TRANS_LOGE(TRANS_CTRL, "sessionName=%{public}s uid=%{public}d not found.", AnonymizeWrapper(tmpName), uid);
    AnonymizeFree(tmpName);
    return SOFTBUS_TRANS_GET_PID_FAILED;
}

int32_t TransGetTokenIdBySessionName(const char *sessionName, uint64_t *tokenId)
{
    if (sessionName == NULL || tokenId == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (g_sessionServerList == NULL) {
        TRANS_LOGE(TRANS_CTRL, "g_sessionServerList has not been initialized.");
        return SOFTBUS_NO_INIT;
    }

    if (SoftBusMutexLock(&g_sessionServerList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "lock mutex failed.");
        return SOFTBUS_LOCK_ERR;
    }
    SessionServer *pos = NULL;
    LIST_FOR_EACH_ENTRY(pos, &g_sessionServerList->list, SessionServer, node) {
        if (strcmp(pos->sessionName, sessionName) == 0) {
            *tokenId = pos->tokenId;
            (void)SoftBusMutexUnlock(&g_sessionServerList->lock);
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&g_sessionServerList->lock);
    char *tmpName = NULL;
    Anonymize(sessionName, &tmpName);
    TRANS_LOGE(TRANS_CTRL, "sessionName=%{public}s not found.", AnonymizeWrapper(tmpName));
    AnonymizeFree(tmpName);
    return SOFTBUS_TRANS_SESSION_NAME_NO_EXIST;
}
