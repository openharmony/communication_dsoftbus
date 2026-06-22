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

#include "lnn_cloud_query_fragment.h"

#include <securec.h>
#include <stdbool.h>

#include <arpa/inet.h>

#include "common_list.h"
#include "lnn_device_cloud_convergence_struct.h"
#include "lnn_log.h"
#include "softbus_adapter_crypto.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_common.h"
#include "softbus_error_code.h"
#include "g_enhance_lnn_func_pack.h"

#define MAX_FRAGMENT_NUM 1024
#define MAX_ASSEMBLED_LEN (10 * 1024 * 1024) // 10MB
#define BASE_RANDOM_ID 10000
#define BASE_RANDOM_BIT_LEN 14
#define BIT_14_MASK 0x3FFF

typedef struct {
    ListNode node;
    uint32_t msgId;
    uint32_t total;
    uint32_t sliceTotal;
    uint32_t receivedBytes;
    uint8_t *buffer;
} FragmentContext;

typedef struct {
    const DataFragmentInfo *header;
    uint8_t *fragmentData;
    uint8_t **assembledData;
    uint32_t *assembledLen;
} ProcessFragmentInput;

static ListNode g_fragmentList;
static uint32_t g_currentMsgId = 1;
static SoftBusMutex g_msgIdMutex = {0};
static SoftBusMutex g_fragmentMutex = {0};
static bool g_isInit = false;

void DataFragmentInit(void)
{
    if (g_isInit) {
        return;
    }

    ListInit(&g_fragmentList);

    if (SoftBusMutexInit(&g_msgIdMutex, NULL) != SOFTBUS_OK) {
        LNN_LOGE(LNN_EVENT, "init msgId mutex failed");
        return;
    }

    if (SoftBusMutexLock(&g_msgIdMutex) != SOFTBUS_OK) {
        LNN_LOGE(LNN_EVENT, "lock msgId mutex failed");
        (void)SoftBusMutexDestroy(&g_msgIdMutex);
        return;
    }

    uint64_t now = SoftBusGetSysTimeMs();
    uint32_t randVal = SoftBusCryptoRand();
    uint32_t timePart = now & BIT_14_MASK;
    uint32_t randPart = randVal % BASE_RANDOM_ID;
    g_currentMsgId = (timePart << BASE_RANDOM_BIT_LEN) | randPart;
    (void)SoftBusMutexUnlock(&g_msgIdMutex);

    if (SoftBusMutexInit(&g_fragmentMutex, NULL) != SOFTBUS_OK) {
        LNN_LOGE(LNN_EVENT, "init fragment mutex failed");
        (void)SoftBusMutexDestroy(&g_msgIdMutex);
        return;
    }

    if (SoftBusMutexLock(&g_fragmentMutex) != SOFTBUS_OK) {
        LNN_LOGE(LNN_EVENT, "lock fragment mutex failed");
        (void)SoftBusMutexDestroy(&g_msgIdMutex);
        (void)SoftBusMutexDestroy(&g_fragmentMutex);
        return;
    }

    g_isInit = true;
    (void)SoftBusMutexUnlock(&g_fragmentMutex);
    LNN_LOGI(LNN_EVENT, "init data fragment success");
}

void WriteFragmentHeader(uint8_t *buffer, uint32_t bufferLen, const DataFragmentInfo *header)
{
    if (bufferLen < FRAGMENT_HEADER_LEN) {
        LNN_LOGE(LNN_EVENT, "buffer too small, bufferLen=%{public}u, required=%{public}u",
            bufferLen, FRAGMENT_HEADER_LEN);
        return;
    }
    uint32_t offset = 0;
    *((uint32_t *)(buffer + offset)) = htonl(header->msgId);
    offset += sizeof(uint32_t);
    *((uint32_t *)(buffer + offset)) = htonl(header->size);
    offset += sizeof(uint32_t);
    *((uint32_t *)(buffer + offset)) = htonl(header->offset);
    offset += sizeof(uint32_t);
    *((uint32_t *)(buffer + offset)) = htonl(header->total);
}

static int32_t CreateFragmentBuffer(const DataFragmentInfo *header, const uint8_t *data,
    uint8_t **buffer, uint32_t *bufferLen)
{
    uint32_t totalLen = FRAGMENT_HEADER_LEN + header->size;
    uint8_t *buf = (uint8_t *)SoftBusCalloc(totalLen);
    if (buf == NULL) {
        LNN_LOGE(LNN_EVENT, "alloc fragment buffer failed");
        return SOFTBUS_MALLOC_ERR;
    }

    WriteFragmentHeader(buf, totalLen, header);

    if (header->size > 0 && data != NULL) {
        int32_t ret = memcpy_s(buf + FRAGMENT_HEADER_LEN, totalLen - FRAGMENT_HEADER_LEN,
            data, header->size);
        if (ret != EOK) {
            LNN_LOGE(LNN_EVENT, "memcpy_s failed, ret=%{public}d", ret);
            SoftBusFree(buf);
            return SOFTBUS_MEM_ERR;
        }
    }

    *buffer = buf;
    *bufferLen = totalLen;
    LNN_LOGI(LNN_EVENT, "msgId=%{public}u, size=%{public}u, offset=%{public}u, "
        "total=%{public}u, totalLen=%{public}u", header->msgId, header->size,
        header->offset, header->total, totalLen);
    return SOFTBUS_OK;
}

uint32_t GenerateMsgId(void)
{
    uint32_t msgId = 0;
    if (SoftBusMutexLock(&g_msgIdMutex) != SOFTBUS_OK) {
        LNN_LOGE(LNN_EVENT, "lock msgId mutex failed");
        return 0;
    }

    msgId = g_currentMsgId++;
    if (msgId == 0) {
        msgId = g_currentMsgId++;
    }

    (void)SoftBusMutexUnlock(&g_msgIdMutex);
    return msgId;
}

static int32_t SendSingleSlice(const DataFragmentInfo *header, const uint8_t *data, const char *udid)
{
    uint8_t *buffer = NULL;
    uint32_t bufferLen = 0;
    int32_t ret = CreateFragmentBuffer(header, data, &buffer, &bufferLen);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_EVENT, "create fragment buffer failed, offset=%{public}u",
            header->offset);
        return ret;
    }

    ret = LnnSendAgentDataPacked(udid, (const char *)buffer, bufferLen);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_EVENT, "send slice by cloud failed, offset=%{public}u, ret=%{public}d",
            header->offset, ret);
        SoftBusFree(buffer);
        return ret;
    }

    SoftBusFree(buffer);
    return SOFTBUS_OK;
}

int32_t DataSlice(const uint8_t *data, uint32_t dataLen, uint32_t sliceLen,
    const char *udid, uint32_t msgId)
{
    if (data == NULL || udid == NULL) {
        LNN_LOGI(LNN_EVENT, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (dataLen == 0 || sliceLen == 0 || sliceLen > MAX_SLICE_LEN || dataLen > MAX_ASSEMBLED_LEN) {
        LNN_LOGE(LNN_EVENT, "invalid param, dataLen=%{public}u, sliceLen=%{public}u", dataLen, sliceLen);
        return SOFTBUS_INVALID_PARAM;
    }

    uint32_t sliceTotal = (dataLen + sliceLen - 1) / sliceLen;
    if (sliceTotal > MAX_FRAGMENT_NUM) {
        LNN_LOGE(LNN_EVENT, "sliceTotal too large, sliceTotal=%{public}u", sliceTotal);
        return SOFTBUS_INVALID_PARAM;
    }
    LNN_LOGI(LNN_EVENT, "dataLen=%{public}u, sliceLen=%{public}u, sliceTotal=%{public}u",
        dataLen, sliceLen, sliceTotal);

    for (uint32_t i = 0; i < sliceTotal; i++) {
        uint32_t offset = i * sliceLen;
        if (dataLen < offset) {
            LNN_LOGE(LNN_EVENT, "invalid param, dataLen=%{public}u", dataLen);
            return SOFTBUS_INVALID_PARAM;
        }
        uint32_t size = (offset + sliceLen > dataLen) ? (dataLen - offset) : sliceLen;

        DataFragmentInfo header = {msgId, size, offset, dataLen};
        int32_t ret = SendSingleSlice(&header, data + offset, udid);
        if (ret != SOFTBUS_OK) {
            return ret;
        }
    }

    return SOFTBUS_OK;
}

static int32_t FindFragmentContext(uint32_t msgId, FragmentContext **ctx)
{
    FragmentContext *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_fragmentList, FragmentContext, node) {
        if (item->msgId == msgId) {
            *ctx = item;
            return SOFTBUS_OK;
        }
    }
    return SOFTBUS_NOT_FIND;
}

static FragmentContext *CreateFragmentContext(uint32_t msgId, uint32_t total, uint32_t sliceTotal)
{
    FragmentContext *ctx = (FragmentContext *)SoftBusCalloc(sizeof(FragmentContext));
    if (ctx == NULL) {
        LNN_LOGE(LNN_EVENT, "alloc fragment context failed");
        return NULL;
    }

    ctx->msgId = msgId;
    ctx->total = total;
    ctx->sliceTotal = sliceTotal;
    ctx->receivedBytes = 0;
    ctx->buffer = (uint8_t *)SoftBusCalloc(total);
    if (ctx->buffer == NULL) {
        LNN_LOGE(LNN_EVENT, "alloc buffer failed");
        SoftBusFree(ctx);
        return NULL;
    }

    ListTailInsert(&g_fragmentList, &ctx->node);
    LNN_LOGI(LNN_EVENT, "create fragment context, msgId=%{public}u, total=%{public}u, sliceTotal=%{public}u",
        msgId, total, sliceTotal);
    return ctx;
}

static void ClearFragmentContext(FragmentContext *ctx)
{
    if (ctx == NULL) {
        return;
    }

    if (ctx->buffer != NULL) {
        SoftBusFree(ctx->buffer);
        ctx->buffer = NULL;
    }

    ListDelete(&ctx->node);
    SoftBusFree(ctx);
}

static int32_t AssembleData(FragmentContext *ctx, uint8_t **assembledData, uint32_t *assembledLen)
{
    *assembledData = ctx->buffer;
    *assembledLen = ctx->total;
    ctx->buffer = NULL; // ownership transferred
    LNN_LOGI(LNN_EVENT, "assemble data done, totalLen=%{public}u", *assembledLen);
    return SOFTBUS_OK;
}

int32_t ParseFragmentHeader(const uint8_t *data, uint32_t dataLen, DataFragmentInfo *header)
{
    if (data == NULL || header == NULL) {
        LNN_LOGE(LNN_EVENT, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (dataLen < FRAGMENT_HEADER_LEN) {
        LNN_LOGE(LNN_EVENT, "dataLen too small, dataLen=%{public}u, required=%{public}u",
            dataLen, FRAGMENT_HEADER_LEN);
        return SOFTBUS_INVALID_PARAM;
    }

    uint32_t offset = 0;
    header->msgId = ntohl(*((uint32_t *)(data + offset)));
    offset += sizeof(uint32_t);
    header->size = ntohl(*((uint32_t *)(data + offset)));
    offset += sizeof(uint32_t);
    header->offset = ntohl(*((uint32_t *)(data + offset)));
    offset += sizeof(uint32_t);
    header->total = ntohl(*((uint32_t *)(data + offset)));
    return SOFTBUS_OK;
}

static int32_t ValidateFragmentHeader(const DataFragmentInfo *header, uint32_t dataLen)
{
    if (header->total > MAX_ASSEMBLED_LEN || header->size > MAX_SLICE_LEN ||
        header->offset >= header->total || dataLen < FRAGMENT_HEADER_LEN) {
        LNN_LOGE(LNN_EVENT, "invalid value, total=%{public}u, size=%{public}u, offset=%{public}u",
            header->total, header->size, header->offset);
        return SOFTBUS_INVALID_PARAM;
    }

    uint32_t actualDataLen = dataLen - FRAGMENT_HEADER_LEN;
    if (header->size != actualDataLen) {
        LNN_LOGE(LNN_EVENT, "fragment data length mismatch, header size=%{public}u, actual=%{public}u",
            header->size, actualDataLen);
        return SOFTBUS_INVALID_PARAM;
    }

    if (header->offset + header->size > header->total) {
        LNN_LOGE(LNN_EVENT, "fragment overflow, offset=%{public}u, size=%{public}u, total=%{public}u",
            header->offset, header->size, header->total);
        return SOFTBUS_INVALID_PARAM;
    }
    return SOFTBUS_OK;
}

static uint8_t *CreateFragmentDataCopy(const uint8_t *data, uint32_t fragmentSize)
{
    uint8_t *fragmentData = (uint8_t *)SoftBusCalloc(fragmentSize);
    if (fragmentData == NULL) {
        LNN_LOGE(LNN_EVENT, "alloc fragment data failed");
        return NULL;
    }

    if (fragmentSize > 0 &&
        memcpy_s(fragmentData, fragmentSize, data + FRAGMENT_HEADER_LEN, fragmentSize) != EOK) {
        LNN_LOGE(LNN_EVENT, "memcpy_s failed, fragmentSize=%{public}u", fragmentSize);
        SoftBusFree(fragmentData);
        return NULL;
    }
    return fragmentData;
}

static int32_t ValidateAndParseFragment(const uint8_t *data, uint32_t dataLen,
    DataFragmentInfo *header)
{
    if (data == NULL || dataLen < FRAGMENT_HEADER_LEN || header == NULL) {
        LNN_LOGE(LNN_EVENT, "invalid param, dataLen=%{public}u", dataLen);
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t ret = ParseFragmentHeader(data, dataLen, header);
    if (ret != SOFTBUS_OK) {
        return ret;
    }

    ret = ValidateFragmentHeader(header, dataLen);
    if (ret != SOFTBUS_OK) {
        return ret;
    }

    return SOFTBUS_OK;
}

static int32_t FindOrCreateFragmentContext(const DataFragmentInfo *header, FragmentContext **ctx)
{
    int32_t ret = FindFragmentContext(header->msgId, ctx);
    if (ret == SOFTBUS_OK) {
        return SOFTBUS_OK;
    }

    uint32_t sliceTotal = (header->total + MAX_SLICE_LEN - 1) / MAX_SLICE_LEN;
    *ctx = CreateFragmentContext(header->msgId, header->total, sliceTotal);
    if (*ctx == NULL) {
        LNN_LOGE(LNN_EVENT, "create fragment context failed");
        return SOFTBUS_MALLOC_ERR;
    }

    return SOFTBUS_OK;
}

static int32_t ProcessFragmentWithLock(const ProcessFragmentInput *input)
{
    if (SoftBusMutexLock(&g_fragmentMutex) != SOFTBUS_OK) {
        LNN_LOGE(LNN_EVENT, "lock fragment mutex failed");
        return SOFTBUS_LOCK_ERR;
    }

    FragmentContext *ctx = NULL;
    int32_t ret = FindOrCreateFragmentContext(input->header, &ctx);
    if (ret != SOFTBUS_OK || ctx == NULL) {
        (void)SoftBusMutexUnlock(&g_fragmentMutex);
        return ret;
    }

    if (memcpy_s(ctx->buffer + input->header->offset, input->header->size,
        input->fragmentData, input->header->size) != EOK) {
        LNN_LOGE(LNN_EVENT, "memcpy_s failed");
        ClearFragmentContext(ctx);
        (void)SoftBusMutexUnlock(&g_fragmentMutex);
        return SOFTBUS_MEM_ERR;
    }

    ctx->receivedBytes += input->header->size;

    if (ctx->receivedBytes == ctx->total) {
        ret = AssembleData(ctx, input->assembledData, input->assembledLen);
        ClearFragmentContext(ctx);
        LNN_LOGI(LNN_EVENT, "assemble data done, ret=%{public}d", ret);
        (void)SoftBusMutexUnlock(&g_fragmentMutex);
        return ret;
    }

    (void)SoftBusMutexUnlock(&g_fragmentMutex);
    return SOFTBUS_OK;
}

int32_t DataAggregate(const uint8_t *data, uint32_t dataLen, uint8_t **assembledData, uint32_t *assembledLen,
    uint32_t *msgId)
{
    if (assembledData == NULL || assembledLen == NULL || msgId == NULL) {
        LNN_LOGE(LNN_EVENT, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    *assembledData = NULL;
    *assembledLen = 0;

    DataFragmentInfo header = { 0 };

    int32_t ret = ValidateAndParseFragment(data, dataLen, &header);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    uint8_t *fragmentData = CreateFragmentDataCopy(data, header.size);
    if (fragmentData == NULL) {
        return SOFTBUS_MALLOC_ERR;
    }
    *msgId = header.msgId;
    ProcessFragmentInput input = {&header, fragmentData, assembledData, assembledLen};
    ret = ProcessFragmentWithLock(&input);
    SoftBusFree(fragmentData);
    return ret;
}