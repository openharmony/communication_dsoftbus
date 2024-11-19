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

#include "softbus_client_info_manager.h"

#include "comm_log.h"
#include "securec.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"
#include "softbus_utils.h"

typedef struct {
    ListNode node;
    char name[PKG_NAME_SIZE_MAX]; /* softbus client name */
    unsigned int handle;          /* use for small system device */
    uintptr_t token;        /* use for small system device */
    uintptr_t cookie;       /* use for small system device */
} SoftBusClientInfoNode;

static SoftBusList *g_clientInfoList = NULL;

int SERVER_InitClient(void)
{
    if (g_clientInfoList != NULL) {
        COMM_LOGI(COMM_SVC, "has inited");
        return SOFTBUS_ERR;
    }

    g_clientInfoList = CreateSoftBusList();
    if (g_clientInfoList == NULL) {
        COMM_LOGE(COMM_SVC, "init client info list failed");
        return SOFTBUS_MALLOC_ERR;
    }

    return SOFTBUS_OK;
}

int SERVER_RegisterService(const char *name, const struct CommonScvId *svcId)
{
    if (name == NULL || svcId == NULL) {
        COMM_LOGE(COMM_SVC, "invalid param");
        return SOFTBUS_ERR;
    }
    COMM_LOGI(COMM_SVC, "new client register=%{public}s", name);

    if (g_clientInfoList == NULL) {
        COMM_LOGE(COMM_SVC, "not init");
        return SOFTBUS_ERR;
    }

    SoftBusClientInfoNode *clientInfo = SoftBusCalloc(sizeof(SoftBusClientInfoNode));
    if (clientInfo == NULL) {
        COMM_LOGE(COMM_SVC, "malloc failed");
        return SOFTBUS_ERR;
    }

    if (strcpy_s(clientInfo->name, sizeof(clientInfo->name), name) != EOK) {
        COMM_LOGE(COMM_SVC, "strcpy failed");
        SoftBusFree(clientInfo);
        return SOFTBUS_ERR;
    }

    clientInfo->handle = svcId->handle;
    clientInfo->token = svcId->token;
    clientInfo->cookie = svcId->cookie;
    ListInit(&clientInfo->node);

    if (SoftBusMutexLock(&g_clientInfoList->lock) != 0) {
        COMM_LOGE(COMM_SVC, "lock failed");
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
        COMM_LOGE(COMM_SVC, "invalid param");
        return SOFTBUS_ERR;
    }

    if (g_clientInfoList == NULL) {
        COMM_LOGE(COMM_SVC, "not init");
        return SOFTBUS_ERR;
    }

    if (SoftBusMutexLock(&g_clientInfoList->lock) != 0) {
        COMM_LOGE(COMM_SVC, "lock failed");
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

    COMM_LOGE(COMM_SVC, "not found");
    (void)SoftBusMutexUnlock(&g_clientInfoList->lock);
    return SOFTBUS_ERR;
}

int SERVER_GetClientInfoNodeNum(int *num)
{
    if (num == NULL) {
        COMM_LOGE(COMM_SVC, "num is null");
        return SOFTBUS_INVALID_PARAM;
    }
    *num = 0;
    if (g_clientInfoList == NULL) {
        COMM_LOGE(COMM_SVC, "not init");
        return SOFTBUS_ERR;
    }
    if (SoftBusMutexLock(&g_clientInfoList->lock) != 0) {
        COMM_LOGE(COMM_SVC, "lock failed");
        return SOFTBUS_ERR;
    }
    *num = g_clientInfoList->cnt;
    (void)SoftBusMutexUnlock(&g_clientInfoList->lock);
    return SOFTBUS_OK;
}

int SERVER_GetAllClientIdentity(struct CommonScvId *svcId, int num)
{
    if (svcId == NULL || num == 0) {
        COMM_LOGE(COMM_SVC, "invalid parameters");
        return SOFTBUS_ERR;
    }
    int32_t i = 0;
    if (g_clientInfoList == NULL) {
        COMM_LOGE(COMM_SVC, "not init");
        return SOFTBUS_ERR;
    }
    if (SoftBusMutexLock(&g_clientInfoList->lock) != 0) {
        COMM_LOGE(COMM_SVC, "lock failed");
        return SOFTBUS_ERR;
    }
    SoftBusClientInfoNode *clientInfo = NULL;
    LIST_FOR_EACH_ENTRY(clientInfo, &g_clientInfoList->list, SoftBusClientInfoNode, node) {
        if (i < num) {
            svcId[i].handle = clientInfo->handle;
            svcId[i].token = clientInfo->token;
            svcId[i].cookie = clientInfo->cookie;
            i++;
        } else {
            break;
        }
    }
    (void)SoftBusMutexUnlock(&g_clientInfoList->lock);
    return SOFTBUS_OK;
}

void SERVER_UnregisterService(const char *name)
{
    if (name == NULL) {
        COMM_LOGE(COMM_SVC, "invalid parameters");
        return;
    }
    if (g_clientInfoList == NULL) {
        COMM_LOGE(COMM_SVC, "server info list not init");
        return;
    }
    if (SoftBusMutexLock(&g_clientInfoList->lock) != SOFTBUS_OK) {
        COMM_LOGE(COMM_SVC, "lock failed");
        return;
    }
    COMM_LOGE(COMM_SVC, "client service died, remove it from softbus server. name=%{public}s", name);
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