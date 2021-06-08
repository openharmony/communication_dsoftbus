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
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_mem_interface.h"
#include "softbus_permission.h"
#include "softbus_utils.h"
#include "trans_channel_manager.h"

#define MAX_SESSION_SERVER_NUM 32

typedef struct {
    ListNode node;
    SoftBusSecType type;
    char pkgName[PKG_NAME_SIZE_MAX];
    char sessionName[SESSION_NAME_SIZE_MAX];
} SessionServer;

static SoftBusList *g_sessionServerList = NULL;
static bool g_transSessionInitFlag = false;

int32_t TransServerInit(void)
{
    if (g_transSessionInitFlag) {
        return SOFTBUS_OK;
    }
    g_sessionServerList = CreateSoftBusList();
    if (g_sessionServerList == NULL) {
        return SOFTBUS_ERR;
    }
    g_transSessionInitFlag = true;

    if (TransPermissionInit(PERMISSION_JSON_FILE) != SOFTBUS_OK) {
        LOG_ERR("Init trans permission failed");
        return SOFTBUS_ERR;
    }
    if (TransChannelInit() != SOFTBUS_OK) {
        LOG_ERR("TransChannelInit failed");
        return SOFTBUS_ERR;
    }
    LOG_INFO("trans session server list init succ");
    return SOFTBUS_OK;
}

void TransServerDeinit(void)
{
    if (g_transSessionInitFlag == false) {
        return;
    }
    if (g_sessionServerList != NULL) {
        DestroySoftBusList(g_sessionServerList);
        g_sessionServerList = NULL;
    }
    g_transSessionInitFlag = false;
    TransChannelDeinit();
    TransPermissionDeinit();
}

void TransServerDeathCallback(const char *pkgName)
{
    if (pkgName == NULL || g_sessionServerList == NULL) {
        return;
    }
    SessionServer *pos = NULL;
    SessionServer *tmp = NULL;
    if (pthread_mutex_lock(&g_sessionServerList->lock) != 0) {
        LOG_ERR("lock mutex fail!");
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

    TransChannelDeathCallback(pkgName);
}

static bool TransSessionServerIsExist(const char *sessionName)
{
    if (sessionName == NULL) {
        return false;
    }
    if (g_sessionServerList == NULL) {
        LOG_INFO("not init");
        return false;
    }

    SessionServer *pos = NULL;
    SessionServer *tmp = NULL;
    if (pthread_mutex_lock(&g_sessionServerList->lock) != 0) {
        LOG_ERR("lock mutex fail!");
        return false;
    }
    LIST_FOR_EACH_ENTRY_SAFE(pos, tmp, &g_sessionServerList->list, SessionServer, node) {
        if (strcmp(pos->sessionName, sessionName) == 0) {
            LOG_INFO("session server [%s] is exist", sessionName);
            (void)pthread_mutex_unlock(&g_sessionServerList->lock);
            return true;
        }
    }

    (void)pthread_mutex_unlock(&g_sessionServerList->lock);
    return false;
}

static int32_t TransSessionServerAddItem(SessionServer *newNode)
{
    if (newNode == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (g_sessionServerList == NULL) {
        LOG_ERR("not init");
        return SOFTBUS_NO_INIT;
    }

    if (pthread_mutex_lock(&g_sessionServerList->lock) != 0) {
        LOG_ERR("lock mutex fail!");
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
            LOG_INFO("session server [%s] is exist", newNode->sessionName);
            (void)pthread_mutex_unlock(&g_sessionServerList->lock);
            return SOFTBUS_SERVER_NAME_REPEATED;
        }
    }

    ListAdd(&(g_sessionServerList->list), &(newNode->node));
    g_sessionServerList->cnt++;
    (void)pthread_mutex_unlock(&g_sessionServerList->lock);

    return SOFTBUS_OK;
}

static int32_t TransSessionServerDelItem(const char *sessionName)
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
        LOG_INFO("destroy session server [%s]", sessionName);
        SoftBusFree(pos);
    }
    (void)pthread_mutex_unlock(&g_sessionServerList->lock);
    return SOFTBUS_OK;
}

int32_t TransCreateSessionServer(const char *pkgName, const char *sessionName)
{
    if (!IsValidString(pkgName, PKG_NAME_SIZE_MAX) ||
        !IsValidString(sessionName, SESSION_NAME_SIZE_MAX)) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (CheckTransPermission(sessionName, pkgName, ACTION_CREATE) < SOFTBUS_OK) {
        LOG_ERR("TransCreateSessionServer no permission!\n");
        return SOFTBUS_PERMISSION_DENIED;
    }
    SessionServer *newNode = (SessionServer *)SoftBusCalloc(sizeof(SessionServer));
    if (newNode == NULL) {
        return SOFTBUS_ERR;
    }
    if (strcpy_s(newNode->pkgName, sizeof(newNode->pkgName), pkgName) != EOK) {
        SoftBusFree(newNode);
        return SOFTBUS_ERR;
    }
    if (strcpy_s(newNode->sessionName, sizeof(newNode->sessionName), sessionName) != EOK) {
        SoftBusFree(newNode);
        return SOFTBUS_ERR;
    }
    newNode->type = SEC_TYPE_CIPHERTEXT;

    int ret = TransSessionServerAddItem(newNode);
    if (ret != SOFTBUS_OK) {
        SoftBusFree(newNode);
        if (ret == SOFTBUS_SERVER_NAME_REPEATED) {
            LOG_INFO("SessionServer is already created [%s]", sessionName);
            return SOFTBUS_SERVER_NAME_REPEATED;
        }
        return ret;
    }
    LOG_INFO("CreateSessionServer OK, pkg name: [%s], session name: [%s]", pkgName, sessionName);
    return SOFTBUS_OK;
}

int32_t TransRemoveSessionServer(const char *pkgName, const char *sessionName)
{
    if (!IsValidString(pkgName, PKG_NAME_SIZE_MAX) ||
        !IsValidString(sessionName, SESSION_NAME_SIZE_MAX)) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (CheckTransPermission(sessionName, pkgName, ACTION_CREATE) < SOFTBUS_OK) {
        LOG_ERR("TransOpenSession no permission!");
        return SOFTBUS_PERMISSION_DENIED;
    }
    return TransSessionServerDelItem(sessionName);
}

int32_t TransOpenSession(const char *mySessionName, const char *peerSessionName,
    const char *peerDeviceId, const char *groupId, int32_t flags)
{
    LOG_INFO("trans server opensession.");
    if (!IsValidString(mySessionName, SESSION_NAME_SIZE_MAX) ||
        !IsValidString(peerSessionName, SESSION_NAME_SIZE_MAX) ||
        !IsValidString(peerDeviceId, DEVICE_ID_SIZE_MAX) ||
        !IsValidString(groupId, GROUP_ID_SIZE_MAX)) {
        return INVALID_CHANNEL_ID;
    }

    char pkgName[PKG_NAME_SIZE_MAX];
    if (TransGetPkgNameBySessionName(mySessionName, pkgName, PKG_NAME_SIZE_MAX) != SOFTBUS_OK) {
        LOG_ERR("TransGetPkgNameBySessionName failed");
        return SOFTBUS_ERR;
    }
    if (CheckTransPermission(mySessionName, pkgName, ACTION_OPEN) < SOFTBUS_OK) {
        LOG_ERR("TransOpenSession no permission!");
        return SOFTBUS_PERMISSION_DENIED;
    }

    if (!TransSessionServerIsExist(mySessionName)) {
        LOG_ERR("session server invalid");
        return INVALID_CHANNEL_ID;
    }

    return TransOpenChannel(mySessionName, peerSessionName, peerDeviceId, groupId, flags);
}

int32_t TransGetPkgNameBySessionName(const char *sessionName, char *pkgName, uint16_t len)
{
    if ((sessionName == NULL) || (pkgName == NULL) || (len == 0)) {
        return SOFTBUS_ERR;
    }
    if (g_sessionServerList == NULL) {
        LOG_INFO("not init");
        return SOFTBUS_ERR;
    }

    SessionServer *pos = NULL;
    SessionServer *tmp = NULL;
    if (pthread_mutex_lock(&g_sessionServerList->lock) != 0) {
        LOG_ERR("lock mutex fail!");
        return SOFTBUS_ERR;
    }
    LIST_FOR_EACH_ENTRY_SAFE(pos, tmp, &g_sessionServerList->list, SessionServer, node) {
        if (strcmp(pos->sessionName, sessionName) == 0) {
            int32_t ret = strcpy_s(pkgName, len, pos->pkgName);
            (void)pthread_mutex_unlock(&g_sessionServerList->lock);
            if (ret != 0) {
                LOG_ERR("strcpy_s error ret, [%d]", ret);
                return SOFTBUS_ERR;
            }
            return SOFTBUS_OK;
        }
    }

    (void)pthread_mutex_unlock(&g_sessionServerList->lock);
    return SOFTBUS_ERR;
}