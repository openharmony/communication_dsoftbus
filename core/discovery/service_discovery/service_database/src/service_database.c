/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include <stddef.h>
#include <securec.h>

#include "disc_log.h"
#include "service_database.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_utils.h"

static bool g_isDBInited = false;
static SoftBusList *g_serviceInfoList = NULL;

typedef struct {
    ListNode node;
    ServiceInfo *serviceInfo;
} ServiceInfoItem;

static void ReleaseServiceInfo(ServiceInfo *info)
{
    if (info == NULL) {
        return;
    }

    (void)memset_s(info, sizeof(ServiceInfo), 0x0, sizeof(ServiceInfo));
    SoftBusFree((void *)info);
    info = NULL;
}

static void ReleaseServiceInfoItem(ServiceInfoItem *itemNode)
{
    if (itemNode == NULL) {
        return;
    }

    ReleaseServiceInfo(itemNode->serviceInfo);

    SoftBusFree((void *)itemNode);
    itemNode = NULL;
}

static void RemoveAllServiceInfo(SoftBusList *list)
{
    DISC_CHECK_AND_RETURN_LOGE(list != NULL, DISC_ABILITY, "invalid list");
    DISC_CHECK_AND_RETURN_LOGE(SoftBusMutexLock(&(list->lock)) == SOFTBUS_OK, DISC_ABILITY, "lock list fail");
    if (list->cnt == 0) {
        DISC_LOGI(DISC_ABILITY, "no serviceInfo in list, no need remove");
        (void)SoftBusMutexUnlock(&(list->lock));
        return;
    }

    list->cnt = 0;
    ServiceInfoItem *itemNode = NULL;
    ServiceInfoItem *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(itemNode, next, &(list->list), ServiceInfoItem, node) {
        ListDelete(&(itemNode->node));
        ReleaseServiceInfoItem(itemNode);
    }
    DISC_LOGI(DISC_ABILITY, "remove all serviceInfo success");
    (void)SoftBusMutexUnlock(&(list->lock));
}

int32_t GetAllServiceInfos(ServiceInfo *infos, uint32_t *cnt)
{
    DISC_CHECK_AND_RETURN_RET_LOGE(infos != NULL, SOFTBUS_INVALID_PARAM, DISC_ABILITY, "invalid param infos");
    DISC_CHECK_AND_RETURN_RET_LOGE(cnt != NULL, SOFTBUS_INVALID_PARAM, DISC_ABILITY, "invalid param cnt");

    SoftBusList *list = g_serviceInfoList;
    DISC_CHECK_AND_RETURN_RET_LOGE(list != NULL, SOFTBUS_INVALID_PARAM, DISC_ABILITY, "invalid list");
    DISC_CHECK_AND_RETURN_RET_LOGE(SoftBusMutexLock(&(list->lock)) == SOFTBUS_OK, SOFTBUS_LOCK_ERR,
        DISC_ABILITY, "lock list fail");

    if (list->cnt == 0) {
        *cnt = list->cnt;
        DISC_LOGI(DISC_ABILITY, "no service info in database");
        (void)SoftBusMutexUnlock(&(list->lock));
        return SOFTBUS_OK;
    }
    if (*cnt < list->cnt) {
        DISC_LOGE(DISC_ABILITY, "input cnt is too small, cnt=%{public}u, list->cnt=%{public}u", *cnt, list->cnt);
        (void)SoftBusMutexUnlock(&(list->lock));
        return SOFTBUS_DISCOVER_SD_SPACE_NOT_MATCH;
    }

    *cnt = list->cnt;
    DISC_LOGD(DISC_ABILITY, "list->cnt:%{public}u, cnt: %{public}u", list->cnt, *cnt);

    ServiceInfoItem *itemNode = NULL;
    int32_t idx = 0;
    LIST_FOR_EACH_ENTRY(itemNode, &(list->list), ServiceInfoItem, node) {
        if (idx >= list->cnt) {
            break;
        }
        if (memcpy_s(&infos[idx], sizeof(ServiceInfo), itemNode->serviceInfo, sizeof(ServiceInfo)) != EOK) {
            DISC_LOGE(DISC_ABILITY, "memcpy service info fail");
            (void)SoftBusMutexUnlock(&(list->lock));
            return SOFTBUS_MEM_ERR;
        }
        idx++;
    }

    (void)SoftBusMutexUnlock(&(list->lock));
    return SOFTBUS_OK;
}

int32_t GetServiceInfo(int64_t serviceId, ServiceInfo *info)
{
    DISC_CHECK_AND_RETURN_RET_LOGE(info != NULL, SOFTBUS_INVALID_PARAM, DISC_ABILITY, "invalid param info");

    SoftBusList *list = g_serviceInfoList;
    DISC_CHECK_AND_RETURN_RET_LOGE(list != NULL, SOFTBUS_INVALID_PARAM, DISC_ABILITY, "invalid list");
    DISC_CHECK_AND_RETURN_RET_LOGE(SoftBusMutexLock(&(list->lock)) == SOFTBUS_OK, SOFTBUS_LOCK_ERR,
        DISC_ABILITY, "lock list fail");

    ServiceInfoItem *itemNode = NULL;
    LIST_FOR_EACH_ENTRY(itemNode, &(list->list), ServiceInfoItem, node) {
        if (itemNode->serviceInfo->serviceId != serviceId) {
            continue;
        }
        if (memcpy_s(info, sizeof(ServiceInfo), itemNode->serviceInfo, sizeof(ServiceInfo)) != EOK) {
            DISC_LOGE(DISC_ABILITY, "memcpy service info fail");
            (void)SoftBusMutexUnlock(&(list->lock));
            return SOFTBUS_MEM_ERR;
        }
        (void)SoftBusMutexUnlock(&(list->lock));
        return SOFTBUS_OK;
    }
    DISC_LOGE(DISC_ABILITY, "service id not existed");
    (void)SoftBusMutexUnlock(&(list->lock));
    return SOFTBUS_DISCOVER_SD_SERVICE_ID_NOT_EXISTED;
}

static int32_t CheckServiceInfo(const ServiceInfo *info)
{
    DISC_CHECK_AND_RETURN_RET_LOGE(info != NULL, SOFTBUS_INVALID_PARAM, DISC_ABILITY, "invalid param info");

    DISC_CHECK_AND_RETURN_RET_LOGE(info->dataLen < DISC_SERVICE_CUSTOMDATA_MAX_LEN, SOFTBUS_INVALID_PARAM,
        DISC_ABILITY, "invalid dataLen=%{public}u", info->dataLen);

    uint32_t len = strnlen((const char *)info->customData, DISC_SERVICE_CUSTOMDATA_MAX_LEN);
    DISC_CHECK_AND_RETURN_RET_LOGE(len == info->dataLen, SOFTBUS_INVALID_PARAM,
        DISC_ABILITY, "customData len != dataLen. len=%{public}u, dataLen=%{public}u", len, info->dataLen);
    DISC_CHECK_AND_RETURN_RET_LOGE(info->customData[info->dataLen] == '\0', SOFTBUS_DISCOVER_INVALID_CSTRING,
        DISC_ABILITY, "customData is not c-string format: dataLen=%{public}u", info->dataLen);
    return SOFTBUS_OK;
}

int32_t AddServiceInfo(const ServiceInfo *info)
{
    int32_t ret = CheckServiceInfo(info);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, DISC_ABILITY, "check info fail");

    SoftBusList *list = g_serviceInfoList;
    DISC_CHECK_AND_RETURN_RET_LOGE(list != NULL, SOFTBUS_INVALID_PARAM, DISC_ABILITY, "invalid list");
    DISC_CHECK_AND_RETURN_RET_LOGE(SoftBusMutexLock(&(list->lock)) == SOFTBUS_OK, SOFTBUS_LOCK_ERR,
        DISC_ABILITY, "lock list fail");
    if (list->cnt > DISC_SERVICE_MAX_NUM) {
        DISC_LOGE(DISC_ABILITY, "reach the max num of service, add fail");
        (void)SoftBusMutexUnlock(&(list->lock));
        return SOFTBUS_DISCOVER_SD_ADD_SERVICE_FAILED;
    }

    ServiceInfoItem *itemNode = NULL;
    LIST_FOR_EACH_ENTRY(itemNode, &(list->list), ServiceInfoItem, node) {
        if (itemNode->serviceInfo->serviceId != info->serviceId) {
            continue;
        }
        DISC_LOGE(DISC_ABILITY, "service id already existed, call UpdateServiceInfo instead");
        (void)SoftBusMutexUnlock(&(list->lock));
        return SOFTBUS_DISCOVER_SD_SERVICE_ID_EXISTED;
    }

    itemNode = (ServiceInfoItem *)SoftBusCalloc(sizeof(ServiceInfoItem));
    if (itemNode == NULL) {
        DISC_LOGE(DISC_ABILITY, "calloc item node fail");
        (void)SoftBusMutexUnlock(&(list->lock));
        return SOFTBUS_MEM_ERR;
    }

    itemNode->serviceInfo = (ServiceInfo *)SoftBusCalloc(sizeof(ServiceInfo));
    if (itemNode->serviceInfo == NULL) {
        DISC_LOGE(DISC_ABILITY, "calloc service info fail");
        ReleaseServiceInfoItem(itemNode);
        (void)SoftBusMutexUnlock(&(list->lock));
        return SOFTBUS_MEM_ERR;
    }

    ListInit(&itemNode->node);
    if (memcpy_s(itemNode->serviceInfo, sizeof(ServiceInfo), info, sizeof(ServiceInfo)) != EOK) {
        DISC_LOGE(DISC_ABILITY, "memcpy service info fail");
        ReleaseServiceInfoItem(itemNode);
        (void)SoftBusMutexUnlock(&(list->lock));
        return SOFTBUS_MEM_ERR;
    }

    ListTailInsert(&(list->list), &(itemNode->node));
    list->cnt++;
    (void)SoftBusMutexUnlock(&(list->lock));
    return SOFTBUS_OK;
}

int32_t UpdateServiceInfo(const ServiceInfo *info)
{
    int32_t ret = CheckServiceInfo(info);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, DISC_ABILITY, "check info fail");

    ret = RemoveServiceInfo(info->serviceId);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, DISC_ABILITY, "remove ServiceInfo fail");

    ret = AddServiceInfo(info);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, DISC_ABILITY, "add ServiceInfo fail");

    return ret;
}

int32_t RemoveServiceInfo(int64_t serviceId)
{
    SoftBusList *list = g_serviceInfoList;
    DISC_CHECK_AND_RETURN_RET_LOGE(list != NULL, SOFTBUS_INVALID_PARAM, DISC_ABILITY, "invalid list");
    DISC_CHECK_AND_RETURN_RET_LOGE(SoftBusMutexLock(&(list->lock)) == SOFTBUS_OK, SOFTBUS_LOCK_ERR,
        DISC_ABILITY, "lock list fail");

    ServiceInfoItem *itemNode = NULL;
    ServiceInfoItem *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(itemNode, next, &(list->list), ServiceInfoItem, node) {
        if (itemNode->serviceInfo->serviceId != serviceId) {
            continue;
        }

        list->cnt--;
        ListDelete(&(itemNode->node));
        ReleaseServiceInfoItem(itemNode);
        DISC_LOGI(DISC_ABILITY, "remove success");

        break;
    }
    (void)SoftBusMutexUnlock(&(list->lock));
    return SOFTBUS_OK;
}

// Only called once at softbus process startup
int32_t ServiceDatabaseInit(void)
{
    DISC_CHECK_AND_RETURN_RET_LOGW(g_isDBInited == false, SOFTBUS_OK, DISC_INIT, "service database already inited");

    g_serviceInfoList = CreateSoftBusList();
    DISC_CHECK_AND_RETURN_RET_LOGE(g_serviceInfoList != NULL, SOFTBUS_DISCOVER_SD_INIT_FAIL, DISC_INIT,
        "init service info list fail");

    g_isDBInited = true;
    DISC_LOGI(DISC_INIT, "service database init success");
    return SOFTBUS_OK;
}

// Only called at softbus process exits
void ServiceDatabaseDeinit(void)
{
    DISC_CHECK_AND_RETURN_LOGW(g_isDBInited == true, DISC_INIT, "disc manager is not inited");

    RemoveAllServiceInfo(g_serviceInfoList);
    DestroySoftBusList(g_serviceInfoList);
    g_serviceInfoList = NULL;

    g_isDBInited = false;
    DISC_LOGI(DISC_INIT, "service database deinit success");
}
