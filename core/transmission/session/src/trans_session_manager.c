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
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_utils.h"

#define MAX_SESSION_SERVER_NUM 32

static SoftBusList *g_sessionServerList = NULL;

int TransSessionMgrInit(void)
{
    if (g_sessionServerList != NULL) {
        return SOFTBUS_OK;
    }
    g_sessionServerList = CreateSoftBusList();
    if (g_sessionServerList == NULL) {
        return SOFTBUS_ERR;
    }
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
    if (pthread_mutex_lock(&g_sessionServerList->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock mutex fail!");
        return false;
    }
    LIST_FOR_EACH_ENTRY_SAFE(pos, tmp, &g_sessionServerList->list, SessionServer, node) {
        if (strcmp(pos->sessionName, sessionName) == 0) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "session server [%s] is exist", sessionName);
            (void)pthread_mutex_unlock(&g_sessionServerList->lock);
            return true;
        }
    }

    (void)pthread_mutex_unlock(&g_sessionServerList->lock);
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

    if (pthread_mutex_lock(&g_sessionServerList->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock mutex fail!");
        return SOFTBUS_ERR;
    }
    if (g_sessionServerList->cnt >= MAX_SESSION_SERVER_NUM) {
        (void)pthread_mutex_unlock(&g_sessionServerList->lock);
        return SOFTBUS_INVALID_NUM;
    }
    SessionServer  *pos = NULL;
    SessionServer  *tmp = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(pos, tmp, &g_sessionServerList->list, SessionServer, node) {
        if (strcmp(pos->sessionName, newNode->sessionName) == 0) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "session server [%s] is exist", newNode->sessionName);
            (void)pthread_mutex_unlock(&g_sessionServerList->lock);
            return SOFTBUS_SERVER_NAME_REPEATED;
        }
    }

    ListAdd(&(g_sessionServerList->list), &(newNode->node));
    g_sessionServerList->cnt++;
    (void)pthread_mutex_unlock(&g_sessionServerList->lock);

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
    if (pthread_mutex_lock(&g_sessionServerList->lock) != 0) {
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
    (void)pthread_mutex_unlock(&g_sessionServerList->lock);
    return SOFTBUS_OK;
}

void TransDelItemByPackageName(const char *pkgName)
{
    if (pkgName == NULL || g_sessionServerList == NULL) {
        return;
    }

    SessionServer *pos = NULL;
    SessionServer *tmp = NULL;
    if (pthread_mutex_lock(&g_sessionServerList->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock mutex fail!");
        return;
    }
    LIST_FOR_EACH_ENTRY_SAFE(pos, tmp, &g_sessionServerList->list, SessionServer, node) {
        if (strcmp(pos->pkgName, pkgName) == 0) {
            ListDelete(&pos->node);
            g_sessionServerList->cnt--;
            SoftBusFree(pos);
            pos = NULL;
            break;
        }
    }
    (void)pthread_mutex_unlock(&g_sessionServerList->lock);
}

int32_t TransGetPkgNameBySessionName(const char *sessionName, char *pkgName, uint16_t len)
{
    if ((sessionName == NULL) || (pkgName == NULL) || (len == 0)) {
        return SOFTBUS_ERR;
    }
    if (g_sessionServerList == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "not init");
        return SOFTBUS_ERR;
    }

    SessionServer *pos = NULL;
    SessionServer *tmp = NULL;
    if (pthread_mutex_lock(&g_sessionServerList->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock mutex fail!");
        return SOFTBUS_ERR;
    }
    LIST_FOR_EACH_ENTRY_SAFE(pos, tmp, &g_sessionServerList->list, SessionServer, node) {
        if (strcmp(pos->sessionName, sessionName) == 0) {
            int32_t ret = strcpy_s(pkgName, len, pos->pkgName);
            (void)pthread_mutex_unlock(&g_sessionServerList->lock);
            if (ret != 0) {
                SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "strcpy_s error ret, [%d]", ret);
                return SOFTBUS_ERR;
            }
            return SOFTBUS_OK;
        }
    }

    (void)pthread_mutex_unlock(&g_sessionServerList->lock);
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
    if (pthread_mutex_lock(&g_sessionServerList->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock mutex fail!");
        return SOFTBUS_LOCK_ERR;
    }
    LIST_FOR_EACH_ENTRY_SAFE(pos, tmp, &g_sessionServerList->list, SessionServer, node) {
        if (strcmp(pos->sessionName, sessionName) == 0) {
            *uid = pos->uid;
            *pid = pos->pid;
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "TransGetUidAndPid: sessionName=%s, uid=%d, pid=%d",
                sessionName, pos->uid, pos->pid);
            (void)pthread_mutex_unlock(&g_sessionServerList->lock);
            return SOFTBUS_OK;
        }
    }

    (void)pthread_mutex_unlock(&g_sessionServerList->lock);
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "TransGetUidAndPid err: sessionName=%s", sessionName);
    return SOFTBUS_ERR;
}