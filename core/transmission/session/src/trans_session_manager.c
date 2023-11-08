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

#include "lnn_lane_link.h"
#include "securec.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_log_old.h"
#include "softbus_utils.h"
#include "softbus_hidumper_trans.h"
#include "trans_channel_callback.h"

#define MAX_SESSION_SERVER_NUM 100
#define CMD_REGISTED_SESSION_LIST "registed_sessionlist"

static SoftBusList *g_sessionServerList = NULL;

static int32_t TransSessionForEachShowInfo(int32_t fd)
{
    if (g_sessionServerList == NULL) {
        return SOFTBUS_ERR;
    }

    if (SoftBusMutexLock(&g_sessionServerList->lock) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock mutex failed");
        return SOFTBUS_ERR;
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
        return SOFTBUS_ERR;
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
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "sessionServerList not init");
        return false;
    }

    SessionServer *pos = NULL;
    SessionServer *tmp = NULL;
    if (SoftBusMutexLock(&g_sessionServerList->lock) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock mutex failed");
        return false;
    }
    LIST_FOR_EACH_ENTRY_SAFE(pos, tmp, &g_sessionServerList->list, SessionServer, node) {
        if (strcmp(pos->sessionName, sessionName) == 0) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "session server [%s] is exist", sessionName);
            (void)SoftBusMutexUnlock(&g_sessionServerList->lock);
            return true;
        }
    }

    (void)SoftBusMutexUnlock(&g_sessionServerList->lock);
    return false;
}

static void ShowSessionServer(void)
{
    SessionServer *pos = NULL;
    SessionServer *tmp = NULL;
    int32_t count = 0;
    LIST_FOR_EACH_ENTRY_SAFE(pos, tmp, &g_sessionServerList->list, SessionServer, node) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR,
            "ShowSessionServer: [%d] session server [%s] is exist", count, pos->sessionName);
        count++;
    }
}

int32_t TransSessionServerAddItem(SessionServer *newNode)
{
    if (newNode == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (g_sessionServerList == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "not init");
        return SOFTBUS_NO_INIT;
    }

    if (SoftBusMutexLock(&g_sessionServerList->lock) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock mutex failed");
        return SOFTBUS_ERR;
    }
    if (g_sessionServerList->cnt >= MAX_SESSION_SERVER_NUM) {
        (void)ShowSessionServer();
        (void)SoftBusMutexUnlock(&g_sessionServerList->lock);
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "session server num reach max");
        return SOFTBUS_INVALID_NUM;
    }

    SessionServer *pos = NULL;
    SessionServer *tmp = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(pos, tmp, &g_sessionServerList->list, SessionServer, node) {
        if (strcmp(pos->sessionName, newNode->sessionName) == 0) {
            if ((pos->uid == newNode->uid) && (pos->pid == newNode->pid)) {
                SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "session server [%s] is exist", newNode->sessionName);
                (void)SoftBusMutexUnlock(&g_sessionServerList->lock);
                return SOFTBUS_SERVER_NAME_REPEATED;
            } else {
                SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO,
                    "sessionname [%s] has been used by other processes", newNode->sessionName);
                (void)SoftBusMutexUnlock(&g_sessionServerList->lock);
                return SOFTBUS_SERVER_NAME_USED;
            }
        }
    }

    ListAdd(&(g_sessionServerList->list), &(newNode->node));
    g_sessionServerList->cnt++;
    (void)SoftBusMutexUnlock(&g_sessionServerList->lock);

    return SOFTBUS_OK;
}

int32_t TransSessionServerDelItem(const char *sessionName)
{
    if (sessionName == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (g_sessionServerList == NULL) {
        return SOFTBUS_ERR;
    }

    bool isFind = false;
    SessionServer *pos = NULL;
    SessionServer *tmp = NULL;
    if (SoftBusMutexLock(&g_sessionServerList->lock) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    LIST_FOR_EACH_ENTRY_SAFE(pos, tmp, &g_sessionServerList->list, SessionServer, node) {
        if (strcmp(pos->sessionName, sessionName) == 0) {
            isFind = true;
            break;
        }
    }
    if (isFind) {
        ListDelete(&pos->node);
        g_sessionServerList->cnt--;
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "destroy session server [%s]", sessionName);
        SoftBusFree(pos);
    }
    (void)SoftBusMutexUnlock(&g_sessionServerList->lock);
    return SOFTBUS_OK;
}

void TransDelItemByPackageName(const char *pkgName, int32_t pid)
{
    if (pkgName == NULL || g_sessionServerList == NULL) {
        return;
    }

    SessionServer *pos = NULL;
    SessionServer *tmp = NULL;
    if (SoftBusMutexLock(&g_sessionServerList->lock) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock mutex failed");
        return;
    }
    LIST_FOR_EACH_ENTRY_SAFE(pos, tmp, &g_sessionServerList->list, SessionServer, node) {
        if ((strcmp(pos->pkgName, pkgName) == 0) && (pos->pid == pid)) {
            ListDelete(&pos->node);
            g_sessionServerList->cnt--;
            SoftBusFree(pos);
            pos = NULL;
        }
    }
    (void)SoftBusMutexUnlock(&g_sessionServerList->lock);
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "del package name [%s]", pkgName);
}

int32_t TransGetPkgNameBySessionName(const char *sessionName, char *pkgName, uint16_t len)
{
    if (sessionName == NULL || pkgName == NULL || len == 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "TransGetPkgNameBySessionName param error");
        return SOFTBUS_ERR;
    }
    if (g_sessionServerList == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "session server list not init");
        return SOFTBUS_ERR;
    }

    SessionServer *pos = NULL;
    SessionServer *tmp = NULL;
    if (SoftBusMutexLock(&g_sessionServerList->lock) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock mutex failed");
        return SOFTBUS_ERR;
    }
    LIST_FOR_EACH_ENTRY_SAFE(pos, tmp, &g_sessionServerList->list, SessionServer, node) {
        if (strcmp(pos->sessionName, sessionName) == 0) {
            int32_t ret = strcpy_s(pkgName, len, pos->pkgName);
            (void)SoftBusMutexUnlock(&g_sessionServerList->lock);
            if (ret != EOK) {
                SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "strcpy_s error ret, [%d]", ret);
                return SOFTBUS_ERR;
            }
            return SOFTBUS_OK;
        }
    }

    (void)SoftBusMutexUnlock(&g_sessionServerList->lock);
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "not found session name [%s].", sessionName);
    return SOFTBUS_ERR;
}

int32_t TransGetUidAndPid(const char *sessionName, int32_t *uid, int32_t *pid)
{
    if (sessionName == NULL || uid == NULL || pid == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (g_sessionServerList == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "not init");
        return SOFTBUS_ERR;
    }

    if (SoftBusMutexLock(&g_sessionServerList->lock) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock mutex failed");
        return SOFTBUS_LOCK_ERR;
    }

    SessionServer *pos = NULL;
    SessionServer *tmp = NULL;
    char *anonyOut = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(pos, tmp, &g_sessionServerList->list, SessionServer, node) {
        if (strcmp(pos->sessionName, sessionName) == 0) {
            *uid = pos->uid;
            *pid = pos->pid;
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "sessionName=%s, uid=%d, pid=%d",
                AnonyDevId(&anonyOut, sessionName), pos->uid, pos->pid);
            SoftBusFree(anonyOut);
            (void)SoftBusMutexUnlock(&g_sessionServerList->lock);
            return SOFTBUS_OK;
        }
    }

    (void)SoftBusMutexUnlock(&g_sessionServerList->lock);
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "err: sessionName=%s", AnonyDevId(&anonyOut, sessionName));
    SoftBusFree(anonyOut);
    return SOFTBUS_ERR;
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
    if (sessionServerList == NULL) {
        return SOFTBUS_ERR;
    }

    SessionServer *pos = NULL;
    SessionServer *tmp = NULL;
    if (SoftBusMutexLock(&g_sessionServerList->lock) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock mutex failed");
        return SOFTBUS_ERR;
    }
    LIST_FOR_EACH_ENTRY_SAFE(pos, tmp, &g_sessionServerList->list, SessionServer, node) {
        SessionServer *newPos = (SessionServer *)SoftBusMalloc(sizeof(SessionServer));
        if (newPos == NULL) {
            TransListDelete(sessionServerList);
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "SoftBusMalloc failed");
            (void)SoftBusMutexUnlock(&g_sessionServerList->lock);
            return SOFTBUS_MALLOC_ERR;
        }
        *newPos = *pos;
        ListAdd(sessionServerList, &newPos->node);
    }
    (void)SoftBusMutexUnlock(&g_sessionServerList->lock);
    return SOFTBUS_OK;
}

void TransOnLinkDown(const char *networkId, const char *uuid, const char *udid, const char *peerIp, int32_t routeType)
{
    if (networkId == NULL || g_sessionServerList == NULL) {
        return;
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "TransOnLinkDown: routeType=%d", routeType);

    ListNode sessionServerList = {0};
    ListInit(&sessionServerList);
    int32_t ret = TransListCopy(&sessionServerList);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "TransOnLinkDown copy list failed");
        return;
    }

    SessionServer *pos = NULL;
    SessionServer *tmp = NULL;

    LIST_FOR_EACH_ENTRY_SAFE(pos, tmp, &sessionServerList, SessionServer, node) {
        (void)TransServerOnChannelLinkDown(pos->pkgName, pos->pid, uuid, udid, peerIp, networkId, routeType);
    }

    if (routeType == WIFI_P2P) {
        LaneDeleteP2pAddress(networkId, true);
    }
    TransListDelete(&sessionServerList);
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "TransOnLinkDown end");
}
