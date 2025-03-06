/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "lnn_lane_link_ledger.h"

#include <securec.h>

#include "anonymizer.h"
#include "lnn_log.h"
#include "lnn_map.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_error_code.h"

#define MAX_LINK_BUILD_INFO_NODE_SIZE 20
static Map g_linkLedgerMap;
static SoftBusMutex g_linkLedgerMutex;

static int32_t Lock(void)
{
    return SoftBusMutexLock(&g_linkLedgerMutex);
}

static void Unlock(void)
{
    (void)SoftBusMutexUnlock(&g_linkLedgerMutex);
}

static int32_t DeleteOldestNode(Map *map)
{
    MapIterator *it = LnnMapInitIterator(map);
    if (it == NULL) {
        LNN_LOGE(LNN_LANE, "init iterator fail");
        return SOFTBUS_NETWORK_MAP_INIT_FAILED;
    }
    uint64_t oldTime = 0;
    char *oldUdid = NULL;
    while (LnnMapHasNext(it)) {
        it = LnnMapNext(it);
        if (it == NULL || it->node->value == NULL) {
            LNN_LOGE(LNN_LANE, "node is NULL");
            break;
        }
        LinkLedgerInfo *info = (LinkLedgerInfo *)it->node->value;
        if (oldTime == 0 || info->lastTryBuildTime < oldTime) {
            oldTime = info->lastTryBuildTime;
            oldUdid = it->node->key;
        }
    }
    int32_t ret = LnnMapErase(map, (const char *)oldUdid);
    char *anonyUdid = NULL;
    Anonymize(oldUdid, &anonyUdid);
    LNN_LOGI(LNN_LANE, "delete link info, ret=%{public}d, udid=%{public}s", ret, AnonymizeWrapper(anonyUdid));
    AnonymizeFree(anonyUdid);
    LnnMapDeinitIterator(it);
    return SOFTBUS_OK;
}

int32_t LnnAddLinkLedgerInfo(const char *udid, const LinkLedgerInfo *info)
{
    if (udid == NULL || info == NULL) {
        LNN_LOGE(LNN_LANE, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    char *anonyUdid = NULL;
    Anonymize(udid, &anonyUdid);
    LNN_LOGI(LNN_LANE, "add link info, udid=%{public}s", AnonymizeWrapper(anonyUdid));
    AnonymizeFree(anonyUdid);

    if (Lock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    if (LnnMapGet(&g_linkLedgerMap, udid) == NULL && // check max size when record not exist
        MapGetSize(&g_linkLedgerMap) >= MAX_LINK_BUILD_INFO_NODE_SIZE &&
        DeleteOldestNode(&g_linkLedgerMap) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "exceeds max size and delete fail");
        Unlock();
        return SOFTBUS_INVALID_NUM;
    }
    int32_t ret = LnnMapSet(&g_linkLedgerMap, udid, (const void *)info, sizeof(LinkLedgerInfo));
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "save data fail, ret=%{public}d", ret);
    }
    Unlock();
    return ret;
}

int32_t LnnGetLinkLedgerInfo(const char *udid, LinkLedgerInfo *info)
{
    if (udid == NULL || info == NULL) {
        LNN_LOGE(LNN_LANE, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (Lock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lock fail");
        return SOFTBUS_LOCK_ERR;
    }

    char *anonyUdid = NULL;
    Anonymize(udid, &anonyUdid);
    LinkLedgerInfo *data = LnnMapGet(&g_linkLedgerMap, udid);
    if (data == NULL) {
        LNN_LOGI(LNN_LANE, "not find, udid=%{public}s", AnonymizeWrapper(anonyUdid));
        Unlock();
        AnonymizeFree(anonyUdid);
        return SOFTBUS_NOT_FIND;
    }
    if (memcpy_s(info, sizeof(LinkLedgerInfo), data, sizeof(LinkLedgerInfo)) != EOK) {
        LNN_LOGE(LNN_LANE, "memcpy fail, udid=%{public}s", AnonymizeWrapper(anonyUdid));
        Unlock();
        AnonymizeFree(anonyUdid);
        return SOFTBUS_MEM_ERR;
    }
    Unlock();
    AnonymizeFree(anonyUdid);
    return SOFTBUS_OK;
}

void LnnDeleteLinkLedgerInfo(const char *udid)
{
    if (udid == NULL) {
        LNN_LOGE(LNN_LANE, "invalid param");
        return;
    }
    if (Lock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lock fail");
        return;
    }
    int32_t ret = LnnMapErase(&g_linkLedgerMap, udid);
    Unlock();
    char *anonyUdid = NULL;
    Anonymize(udid, &anonyUdid);
    LNN_LOGI(LNN_LANE, "delete link info, ret=%{public}d, udid=%{public}s", ret, AnonymizeWrapper(anonyUdid));
    AnonymizeFree(anonyUdid);
}

int32_t InitLinkLedger(void)
{
    LnnMapInit(&g_linkLedgerMap);
    if (SoftBusMutexInit(&g_linkLedgerMutex, NULL) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "mutex init fail");
        return SOFTBUS_NO_INIT;
    }
    return SOFTBUS_OK;
}

void DeinitLinkLedger(void)
{
    if (Lock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lock fail");
        return;
    }
    LnnMapDelete(&g_linkLedgerMap);
    Unlock();
    (void)SoftBusMutexDestroy(&g_linkLedgerMutex);
}