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

#include "trans_session_manager.h"

#include "securec.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_utils.h"
#include "trans_channel_callback.h"
#include "softbus_hidumper_trans.h"

#define MAX_SESSION_SERVER_NUM 32

static SoftBusList *g_sessionServerList = NULL;

static void TransSessionForEachShowInfo(int fd)
{
    if (g_sessionServerList == NULL) {
        return;
    }

    if (SoftBusMutexLock(&g_sessionServerList->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock mutex fail!");
        return;
    }

    SessionServer *pos = NULL;
    LIST_FOR_EACH_ENTRY(pos, &g_sessionServerList->list, SessionServer, node) {
        SoftBusTransDumpRegisterSession(fd, pos->pkgName, pos->sessionName, pos->uid, pos->pid);
    }
    
    (void)SoftBusMutexUnlock(&g_sessionServerList->lock);
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

    SetShowRegisterSessionInfosFunc(TransSessionForEachShowInfo);
    return SOFTBUS_OK;
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
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "not init");
        return false;
    }

    SessionServer *pos = NULL;
    SessionServer *tmp = NULL;
    if (SoftBusMutexLock(&g_sessionServerList->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock mutex fail!");
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

int32_t TransSessionServerAddItem(SessionServer *newNode)
{
    if (newNode == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (g_sessionServerList == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "not init");
        return SOFTBUS_NO_INIT;
    }

    if (SoftBusMutexLock(&g_sessionServerList->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock mutex fail!");
        return SOFTBUS_ERR;
    }
    if (g_sessionServerList->cnt >= MAX_SESSION_SERVER_NUM) {
        (void)SoftBusMutexUnlock(&g_sessionServerList->lock);
        return SOFTBUS_INVALID_NUM;
    }
    SessionServer  *pos = NULL;
    SessionServer  *tmp = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(pos, tmp, &g_sessionServerList->list, SessionServer, node) {
        if (strcmp(pos->sessionName, newNode->sessionName) == 0) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "session server [%s] is exist", newNode->sessionName);
            (void)SoftBusMutexUnlock(&g_sessionServerList->lock);
            return SOFTBUS_SERVER_NAME_REPEATED;
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
    if (SoftBusMutexLock(&g_sessionServerList->lock) != 0) {
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

void TransDelItemByPackageName(const char *pkgName)
{
    if (pkgName == NULL || g_sessionServerList == NULL) {
        return;
    }

    SessionServer *pos = NULL;
    SessionServer *tmp = NULL;
    if (SoftBusMutexLock(&g_sessionServerList->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock mutex fail!");
        return;
    }
    LIST_FOR_EACH_ENTRY_SAFE(pos, tmp, &g_sessionServerList->list, SessionServer, node) {
        if (strcmp(pos->pkgName, pkgName) == 0) {
            ListDelete(&pos->node);
            g_sessionServerList->cnt--;
            SoftBusFree(pos);
            pos = NULL;
        }
    }
    (void)SoftBusMutexUnlock(&g_sessionServerList->lock);
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "del package name [%s].", pkgName);
}

int32_t TransGetPkgNameBySessionName(const char *sessionName, char *pkgName, uint16_t len)
{
    if ((sessionName == NULL) || (pkgName == NULL) || (len == 0)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "TransGetPkgNameBySessionName param error.");
        return SOFTBUS_ERR;
    }
    if (g_sessionServerList == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "session server list not init");
        return SOFTBUS_ERR;
    }

    SessionServer *pos = NULL;
    SessionServer *tmp = NULL;
    if (SoftBusMutexLock(&g_sessionServerList->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock mutex fail!");
        return SOFTBUS_ERR;
    }
    LIST_FOR_EACH_ENTRY_SAFE(pos, tmp, &g_sessionServerList->list, SessionServer, node) {
        if (strcmp(pos->sessionName, sessionName) == 0) {
            int32_t ret = strcpy_s(pkgName, len, pos->pkgName);
            (void)SoftBusMutexUnlock(&g_sessionServerList->lock);
            if (ret != 0) {
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

    SessionServer *pos = NULL;
    SessionServer *tmp = NULL;
    if (SoftBusMutexLock(&g_sessionServerList->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock mutex fail!");
        return SOFTBUS_LOCK_ERR;
    }
    char *anonyOut = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(pos, tmp, &g_sessionServerList->list, SessionServer, node) {
        if (strcmp(pos->sessionName, sessionName) == 0) {
            *uid = pos->uid;
            *pid = pos->pid;
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "TransGetUidAndPid: sessionName=%s, uid=%d, pid=%d",
                AnonyDevId(&anonyOut, sessionName), pos->uid, pos->pid);
            SoftBusFree(anonyOut);
            (void)SoftBusMutexUnlock(&g_sessionServerList->lock);
            return SOFTBUS_OK;
        }
    }

    (void)SoftBusMutexUnlock(&g_sessionServerList->lock);
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "TransGetUidAndPid err: sessionName=%s",
        AnonyDevId(&anonyOut, sessionName));
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
    return;
}

static int32_t TransListCopy(ListNode *sessionServerList)
{
    if (sessionServerList == NULL) {
        return SOFTBUS_ERR;
    }

    SessionServer *pos = NULL;
    SessionServer *tmp = NULL;

    if (SoftBusMutexLock(&g_sessionServerList->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock mutex fail!");
        return SOFTBUS_ERR;
    }
    LIST_FOR_EACH_ENTRY_SAFE(pos, tmp, &g_sessionServerList->list, SessionServer, node) {
        SessionServer *newpos = (SessionServer *)SoftBusMalloc(sizeof(SessionServer));
        if (newpos == NULL) {
            TransListDelete(sessionServerList);
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "SoftBusMalloc fail!");
            (void)SoftBusMutexUnlock(&g_sessionServerList->lock);
            return SOFTBUS_MALLOC_ERR;
        }
        *newpos = *pos;
        ListAdd(sessionServerList, &newpos->node);
    }
    (void)SoftBusMutexUnlock(&g_sessionServerList->lock);
    return SOFTBUS_OK;
}

void TransOnLinkDown(const char *networkId, int32_t routeType)
{
    if (networkId == NULL || g_sessionServerList == NULL) {
        return;
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "TransOnLinkDown: routeType=%d", routeType);

    ListNode sessionServerList = {0};
    ListInit(&sessionServerList);
    int32_t ret = TransListCopy(&sessionServerList);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "TransOnLinkDown copy list fail!");
        return;
    }

    SessionServer *pos = NULL;
    SessionServer *tmp = NULL;

    LIST_FOR_EACH_ENTRY_SAFE(pos, tmp, &sessionServerList, SessionServer, node) {
        (void)TransServerOnChannelLinkDown(pos->pkgName, networkId, routeType);
    }

    TransListDelete(&sessionServerList);
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "TransOnLinkDown end");
    return;
}
