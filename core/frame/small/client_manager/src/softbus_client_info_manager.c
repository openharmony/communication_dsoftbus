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

#include "softbus_client_info_manager.h"

#include "securec.h"
#include "softbus_adapter_mem.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_utils.h"

typedef struct {
    ListNode node;
    char name[PKG_NAME_SIZE_MAX]; /* softbus client name */
    unsigned int handle; /* use for small system device */
    unsigned int token; /* use for small system device */
    unsigned int cookie; /* use for small system device */
} SoftBusClientInfoNode;

static SoftBusList *g_clientInfoList = NULL;

int SERVER_InitClient(void)
{
    if (g_clientInfoList != NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "has inited");
        return SOFTBUS_ERR;
    }

    g_clientInfoList = CreateSoftBusList();
    if (g_clientInfoList == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "init service info list failed");
        return SOFTBUS_MALLOC_ERR;
    }

    return SOFTBUS_OK;
}

int SERVER_RegisterService(const char *name, const struct CommonScvId *svcId)
{
    if (name == NULL || svcId == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "invalid param");
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "new client register:%s", name);

    if (g_clientInfoList == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "not init");
        return SOFTBUS_ERR;
    }

    SoftBusClientInfoNode *clientInfo = SoftBusMalloc(sizeof(SoftBusClientInfoNode));
    if (clientInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "malloc failed");
        return SOFTBUS_ERR;
    }
    (void)memset_s(clientInfo, sizeof(SoftBusClientInfoNode), 0, sizeof(SoftBusClientInfoNode));

    if (strcpy_s(clientInfo->name, sizeof(clientInfo->name), name) != EOK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "strcpy failed");
        SoftBusFree(clientInfo);
        return SOFTBUS_ERR;
    }

    clientInfo->handle = svcId->handle;
    clientInfo->token = svcId->token;
    clientInfo->cookie = svcId->cookie;
    ListInit(&clientInfo->node);

    if (SoftBusMutexLock(&g_clientInfoList->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "lock failed");
        SoftBusFree(clientInfo);
        return SOFTBUS_ERR;
    }

    ListAdd(&(g_clientInfoList->list), &(clientInfo->node));
    g_clientInfoList->cnt++;

    (void)SoftBusMutexUnlock(&g_clientInfoList->lock);
    return SOFTBUS_OK;
}

int SERVER_GetIdentityByPkgName(const char *name, struct CommonScvId *svcId)
{
    if (name == NULL || svcId == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "invalid param");
        return SOFTBUS_ERR;
    }

    if (g_clientInfoList == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "not init");
        return SOFTBUS_ERR;
    }

    if (SoftBusMutexLock(&g_clientInfoList->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "lock failed");
        return SOFTBUS_ERR;
    }

    SoftBusClientInfoNode *clientInfo = NULL;
    LIST_FOR_EACH_ENTRY(clientInfo, &g_clientInfoList->list, SoftBusClientInfoNode, node) {
        if (strcmp(clientInfo->name, name) == 0) {
            svcId->handle = clientInfo->handle;
            svcId->token = clientInfo->token;
            svcId->cookie = clientInfo->cookie;
            (void)SoftBusMutexUnlock(&g_clientInfoList->lock);
            return SOFTBUS_OK;
        }
    }

    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "not found");
    (void)SoftBusMutexUnlock(&g_clientInfoList->lock);
    return SOFTBUS_ERR;
}

int SERVER_GetClientInfoNodeNum(int *num)
{
    *num = 0;
    if (g_clientInfoList == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "not init");
        return SOFTBUS_ERR;
    }
    if (SoftBusMutexLock(&g_clientInfoList->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "lock failed");
        return SOFTBUS_ERR;
    }
    *num = g_clientInfoList->cnt;
    (void)SoftBusMutexUnlock(&g_clientInfoList->lock);
    return SOFTBUS_OK;
}

int SERVER_GetAllClientIdentity(struct CommonScvId *svcId, int num)
{
    if (svcId == NULL || num == 0) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "invalid parameters");
        return SOFTBUS_ERR;
    }
    int32_t i = 0;
    if (g_clientInfoList == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "not init");
        return SOFTBUS_ERR;
    }
    if (SoftBusMutexLock(&g_clientInfoList->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "lock failed");
        return SOFTBUS_ERR;
    }
    SoftBusClientInfoNode *clientInfo = NULL;
    LIST_FOR_EACH_ENTRY(clientInfo, &g_clientInfoList->list, SoftBusClientInfoNode, node) {
        if (i < num) {
            svcId[i].handle = clientInfo->handle;
            svcId[i].token = clientInfo->token;
            svcId[i].cookie = clientInfo->cookie;
            i++;
        }
    }
    (void)SoftBusMutexUnlock(&g_clientInfoList->lock);
    return SOFTBUS_OK;
}

void SERVER_UnregisterService(const char *name)
{
    if (g_clientInfoList == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "server info list not init");
        return;
    }
    if (SoftBusMutexLock(&g_clientInfoList->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "lock failed");
        return;
    }
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "client service %s died, remove it from softbus server", name);
    SoftBusClientInfoNode *clientInfo = NULL;
    LIST_FOR_EACH_ENTRY(clientInfo, &g_clientInfoList->list, SoftBusClientInfoNode, node) {
        if (strcmp(clientInfo->name, name) == 0) {
            ListDelete(&(clientInfo->node));
            SoftBusFree(clientInfo);
            g_clientInfoList->cnt--;
            break;
        }
    }
    (void)SoftBusMutexUnlock(&g_clientInfoList->lock);
}