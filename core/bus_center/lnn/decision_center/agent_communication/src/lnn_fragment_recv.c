/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "lnn_fragment_recv.h"

#include <arpa/inet.h>
#include <securec.h>
#include <string.h>

#include "common_list.h"
#include "lnn_device_cloud_convergence_struct.h"
#include "lnn_log.h"
#include "lnn_cloud_query_fragment.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_common.h"
#include "softbus_error_code.h"

#define FRAGMENT_CONTEXT_TIMEOUT_MS (5 * 60 * 1000)

typedef struct {
    ListNode node;
    uint32_t msgId;
    FarFieldBusiness moduleType;
    uint64_t createTime;
} FragmentRecvContext;

typedef struct {
    const char *udid;
    const uint8_t *data;
    uint32_t dataLen;
    uint32_t *offset;
} SingleFragmentData;

static ListNode g_fragmentList;
static SoftBusMutex g_fragmentMutex = {0};
static bool g_isInit = false;

void FragmentRecvInit(void)
{
    if (g_isInit) {
        return;
    }
    ListInit(&g_fragmentList);
    SoftBusMutexAttr mutexAttr;
    (void)SoftBusMutexAttrInit(&mutexAttr);
    if (SoftBusMutexInit(&g_fragmentMutex, &mutexAttr) != SOFTBUS_OK) {
        LNN_LOGE(LNN_EVENT, "init fragment mutex failed");
        return;
    }
    SoftBusMutexLock(&g_fragmentMutex);
    if (g_isInit) {
        SoftBusMutexUnlock(&g_fragmentMutex);
        return;
    }
    g_isInit = true;
    SoftBusMutexUnlock(&g_fragmentMutex);
    LNN_LOGI(LNN_EVENT, "fragment recv init success");
}

void FragmentRecvDeinit(void)
{
    if (!g_isInit) {
        return;
    }
    SoftBusMutexLock(&g_fragmentMutex);
    FragmentRecvContext *item = NULL;
    FragmentRecvContext *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_fragmentList, FragmentRecvContext, node) {
        ListDelete(&item->node);
        SoftBusFree(item);
    }
    SoftBusMutexUnlock(&g_fragmentMutex);
    (void)SoftBusMutexDestroy(&g_fragmentMutex);
    g_isInit = false;
    LNN_LOGI(LNN_EVENT, "fragment recv deinit success");
}

static FragmentRecvContext *FindFragmentContext(uint32_t msgId)
{
    FragmentRecvContext *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_fragmentList, FragmentRecvContext, node) {
        if (item->msgId == msgId) {
            return item;
        }
    }
    return NULL;
}

static FragmentRecvContext *CreateFragmentContext(uint32_t msgId, FarFieldBusiness moduleType)
{
    FragmentRecvContext *ctx = (FragmentRecvContext *)SoftBusCalloc(sizeof(FragmentRecvContext));
    if (ctx == NULL) {
        LNN_LOGE(LNN_EVENT, "alloc fragment context failed");
        return NULL;
    }
    ctx->msgId = msgId;
    ctx->moduleType = moduleType;
    ctx->createTime = SoftBusGetTimeMs();
    ListInit(&ctx->node);
    ListAdd(&g_fragmentList, &(ctx->node));
    LNN_LOGI(LNN_EVENT, "create fragment context, msgId=%{public}u, moduleType=%{public}d", msgId, moduleType);
    return ctx;
}

static void DestroyFragmentContext(FragmentRecvContext *ctx)
{
    if (ctx == NULL) {
        return;
    }
    LNN_LOGI(LNN_EVENT, "destroy fragment context, msgId=%{public}u", ctx->msgId);
    ListDelete(&ctx->node);
    SoftBusFree(ctx);
}

void FragmentRecvClear(uint32_t msgId)
{
    SoftBusMutexLock(&g_fragmentMutex);
    FragmentRecvContext *ctx = FindFragmentContext(msgId);
    if (ctx != NULL) {
        DestroyFragmentContext(ctx);
    }
    SoftBusMutexUnlock(&g_fragmentMutex);
    LNN_LOGI(LNN_EVENT, "clear fragment recv context, msgId=%{public}u", msgId);
}

void FragmentRecvClearAll(void)
{
    SoftBusMutexLock(&g_fragmentMutex);
    FragmentRecvContext *item = NULL;
    FragmentRecvContext *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_fragmentList, FragmentRecvContext, node) {
        DestroyFragmentContext(item);
    }
    SoftBusMutexUnlock(&g_fragmentMutex);
    LNN_LOGI(LNN_EVENT, "clear all fragment recv context");
}

static bool ParseModuleType(const uint8_t *data, uint32_t dataLen, FarFieldBusiness *moduleType)
{
    if (dataLen < FAR_FIELD_PKT_HEAD_SIZE) {
        LNN_LOGE(LNN_EVENT, "data too short for pkt head, dataLen=%{public}u", dataLen);
        return false;
    }
    FarFiledPktHead header;
    uint32_t magic = 0;
    uint32_t type = 0;
    uint32_t len = 0;
    if (memcpy_s(&magic, sizeof(uint32_t), data, sizeof(uint32_t)) != EOK ||
        memcpy_s(&type, sizeof(uint32_t), data + sizeof(uint32_t), sizeof(uint32_t)) != EOK ||
        memcpy_s(&len, sizeof(uint32_t), data + sizeof(uint32_t) + sizeof(uint32_t), sizeof(uint32_t)) != EOK) {
        LNN_LOGE(LNN_EVENT, "memcpy_s failed");
        return false;
    }
    header.magic = ntohl(magic);
    header.type = ntohl(type);
    header.len = ntohl(len);

    if (header.magic != 0xBABEFACE) {
        LNN_LOGE(LNN_EVENT, "invalid magic=%{public}x", header.magic);
        return false;
    }
    if (header.len > dataLen) {
        LNN_LOGE(LNN_EVENT, "header.len=%{public}u exceeds dataLen=%{public}u", header.len, dataLen);
        return false;
    }

    *moduleType = (FarFieldBusiness)header.type;
    if (*moduleType >= FAR_FIELD_BUSINESS_MAX) {
        LNN_LOGE(LNN_EVENT, "invalid moduleType=%{public}d", *moduleType);
        return false;
    }
    return true;
}

static void CleanupTimeoutContexts(void)
{
    uint64_t currentTime = SoftBusGetTimeMs();
    FragmentRecvContext *item = NULL;
    FragmentRecvContext *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_fragmentList, FragmentRecvContext, node) {
        if (currentTime - item->createTime > FRAGMENT_CONTEXT_TIMEOUT_MS) {
            LNN_LOGW(LNN_EVENT, "fragment context timeout, msgId=%{public}u", item->msgId);
            DestroyFragmentContext(item);
        }
    }
}

static int32_t GetOrCreateFragmentContext(uint32_t msgId, FarFieldBusiness moduleType)
{
    SoftBusMutexLock(&g_fragmentMutex);
    FragmentRecvContext *ctx = FindFragmentContext(msgId);
    if (ctx == NULL) {
        ctx = CreateFragmentContext(msgId, moduleType);
        if (ctx == NULL) {
            SoftBusMutexUnlock(&g_fragmentMutex);
            return SOFTBUS_MALLOC_ERR;
        }
    }
    SoftBusMutexUnlock(&g_fragmentMutex);
    return SOFTBUS_OK;
}

static int32_t ExtractFragmentData(const uint8_t *data, uint32_t offset, uint32_t fragmentTotalSize,
    uint8_t **buffer, uint32_t *fragmentDataSize)
{
    *fragmentDataSize = fragmentTotalSize - FAR_FIELD_PKT_HEAD_SIZE;
    *buffer = (uint8_t *)SoftBusCalloc(*fragmentDataSize);
    if (*buffer == NULL) {
        LNN_LOGE(LNN_EVENT, "alloc buffer failed, size=%{public}u", *fragmentDataSize);
        return SOFTBUS_MALLOC_ERR;
    }

    if (memcpy_s(*buffer, *fragmentDataSize,
        data + offset + FAR_FIELD_PKT_HEAD_SIZE, *fragmentDataSize) != EOK) {
        LNN_LOGE(LNN_EVENT, "memcpy_s fragment data failed");
        SoftBusFree(*buffer);
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t ProcessSingleFragment(SingleFragmentData *singleData, ConversationChannelType channelType,
    FragmentRecvCallback callback)
{
    uint32_t totalHeaderSize = FAR_FIELD_PKT_HEAD_SIZE + FRAGMENT_HEADER_LEN;
    if (singleData->dataLen - *(singleData->offset) < totalHeaderSize) {
        LNN_LOGE(LNN_EVENT, "data too short for header");
        return SOFTBUS_INVALID_PARAM;
    }

    FarFieldBusiness moduleType = FAR_FIELD_BUSINESS_MAX;
    if (!ParseModuleType(singleData->data + *(singleData->offset),
        singleData->dataLen - *(singleData->offset), &moduleType)) {
        LNN_LOGE(LNN_EVENT, "parse module type failed");
        return SOFTBUS_INVALID_PARAM;
    }

    DataFragmentInfo header = { 0 };
    if (ParseFragmentHeader(singleData->data + *(singleData->offset) + FAR_FIELD_PKT_HEAD_SIZE,
        FRAGMENT_HEADER_LEN, &header) != SOFTBUS_OK) {
        LNN_LOGE(LNN_EVENT, "parse fragment header failed");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = GetOrCreateFragmentContext(header.msgId, moduleType);
    if (ret != SOFTBUS_OK) {
        return ret;
    }

    uint32_t fragmentTotalSize = totalHeaderSize + header.size;
    if (singleData->dataLen - *(singleData->offset) < fragmentTotalSize) {
        LNN_LOGE(LNN_EVENT, "data too short for fragment");
        return SOFTBUS_INVALID_PARAM;
    }

    uint8_t *buffer = NULL;
    uint32_t fragmentDataSize = 0;
    ret = ExtractFragmentData(singleData->data, *(singleData->offset), fragmentTotalSize, &buffer, &fragmentDataSize);
    if (ret != SOFTBUS_OK) {
        return ret;
    }

    LNN_LOGI(LNN_EVENT, "fragment received, msgId=%{public}u, size=%{public}u, offset=%{public}u, total=%{public}u",
        header.msgId, header.size, header.offset, header.total);

    callback(singleData->udid, (const char *)buffer, fragmentDataSize, channelType, moduleType);
    SoftBusFree(buffer);

    *(singleData->offset) += fragmentTotalSize;
    return SOFTBUS_OK;
}

int32_t FragmentRecvProcess(const char *udid, const uint8_t *data, uint32_t dataLen,
    ConversationChannelType channelType, FragmentRecvCallback callback)
{
    if (udid == NULL || data == NULL || callback == NULL) {
        LNN_LOGE(LNN_EVENT, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (dataLen == 0 || dataLen > MAX_MSG_LEN) {
        LNN_LOGE(LNN_EVENT, "invalid len=%{public}u", dataLen);
        return SOFTBUS_INVALID_PARAM;
    }

    FragmentRecvInit();

    SoftBusMutexLock(&g_fragmentMutex);
    CleanupTimeoutContexts();
    SoftBusMutexUnlock(&g_fragmentMutex);

    // 解析模块类型，判断是否需要分片处理
    FarFieldBusiness moduleType = FAR_FIELD_BUSINESS_MAX;
    if (!ParseModuleType(data, dataLen, &moduleType)) {
        LNN_LOGE(LNN_EVENT, "parse module type failed");
        return SOFTBUS_INVALID_PARAM;
    }

    // TYPE_LNN_FAST_OFFLINE 不需要分片处理，直接传递给回调
    if (moduleType == TYPE_LNN_FAST_OFFLINE) {
        LNN_LOGI(LNN_EVENT, "TYPE_LNN_FAST_OFFLINE, no fragment needed");
        // 跳过 FarFiledPktHead 包头（12字节）
        if (dataLen <= FAR_FIELD_PKT_HEAD_SIZE) {
            LNN_LOGE(LNN_EVENT, "data too short for TYPE_LNN_FAST_OFFLINE");
            return SOFTBUS_INVALID_PARAM;
        }
        callback(udid, (const char *)(data + FAR_FIELD_PKT_HEAD_SIZE), dataLen - FAR_FIELD_PKT_HEAD_SIZE,
            channelType, moduleType);
        return SOFTBUS_OK;
    }

    // TYPE_AGENT_COMMUNICATION 需要分片处理
    uint32_t offset = 0;
    while (offset < dataLen) {
        SingleFragmentData singleData = { udid, data, dataLen, &offset };
        int32_t ret = ProcessSingleFragment(&singleData, channelType, callback);
        if (ret != SOFTBUS_OK) {
            return ret;
        }
    }

    return SOFTBUS_OK;
}