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

#include "softbus_tlv_utils.h"

#include "securec.h"

#include "comm_log.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_socket.h"
#include "softbus_error_code.h"

#define TLV_SIZE(obj, length) ((obj)->tSize + (obj)->lSize + (length))

static TlvMember *NewTlvMember(uint32_t type, uint32_t length, const uint8_t *value)
{
    TlvMember *tlv = (TlvMember *)SoftBusMalloc(sizeof(TlvMember) + length);
    COMM_CHECK_AND_RETURN_RET_LOGW(tlv != NULL, NULL, COMM_UTILS, "malloc fail");
    tlv->type = type;
    tlv->length = length;
    if (length > 0 && value != NULL) {
        (void)memcpy_s(tlv->value, length, value, length);
    }
    return tlv;
}

static void DelTlvMember(TlvMember *tlv)
{
    SoftBusFree(tlv);
}

TlvObject *CreateTlvObject(uint8_t tSize, uint8_t lSize)
{
    COMM_CHECK_AND_RETURN_RET_LOGW(tSize >= UINT8_T && tSize <= UINT32_T,
        NULL, COMM_UTILS, "invalid tSize=%{public}u", tSize);
    COMM_CHECK_AND_RETURN_RET_LOGW(lSize >= UINT8_T && lSize <= UINT32_T,
        NULL, COMM_UTILS, "invalid lSize=%{public}u", lSize);
    TlvObject *obj = (TlvObject *)SoftBusMalloc(sizeof(TlvObject));
    COMM_CHECK_AND_RETURN_RET_LOGW(obj != NULL, NULL, COMM_UTILS, "malloc fail");
    obj->tSize = tSize;
    obj->lSize = lSize;
    obj->size = 0;
    ListInit(&obj->mList);
    return obj;
}

void DestroyTlvObject(TlvObject *obj)
{
    COMM_CHECK_AND_RETURN_LOGW(obj != NULL, COMM_UTILS, "obj nullptr");
    TlvMember *item = NULL;
    TlvMember *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &obj->mList, TlvMember, node) {
        ListDelete(&item->node);
        DelTlvMember(item);
    }
    SoftBusFree(obj);
}

int32_t AddTlvMember(TlvObject *obj, uint32_t type, uint32_t length, const uint8_t *value)
{
    COMM_CHECK_AND_RETURN_RET_LOGW(obj != NULL, SOFTBUS_INVALID_PARAM, COMM_UTILS, "obj nullptr");
    COMM_CHECK_AND_RETURN_RET_LOGW(((length > 0 && length < MAX_VALUE_LENGTH && value != NULL) || (length == 0)),
        SOFTBUS_INVALID_PARAM, COMM_UTILS, "invalid param, length=%{public}u", length);
    TlvMember *tlv = NewTlvMember(type, length, value);
    COMM_CHECK_AND_RETURN_RET_LOGW(tlv != NULL, SOFTBUS_MALLOC_ERR, COMM_UTILS, "new tlv fail");
    ListTailInsert(&obj->mList, &tlv->node);
    obj->size += TLV_SIZE(obj, tlv->length);
    return SOFTBUS_OK;
}

int32_t GetTlvMember(TlvObject *obj, uint32_t type, uint32_t *length, uint8_t **value)
{
    COMM_CHECK_AND_RETURN_RET_LOGW(obj != NULL, SOFTBUS_INVALID_PARAM, COMM_UTILS, "obj nullptr");
    COMM_CHECK_AND_RETURN_RET_LOGW(length != NULL, SOFTBUS_INVALID_PARAM, COMM_UTILS, "length nullptr");
    COMM_CHECK_AND_RETURN_RET_LOGW(value != NULL, SOFTBUS_INVALID_PARAM, COMM_UTILS, "value nullptr");
    TlvMember *tlv = NULL;
    LIST_FOR_EACH_ENTRY(tlv, &obj->mList, TlvMember, node) {
        if (tlv->type == type) {
            *length = tlv->length;
            *value = tlv->value;
            return SOFTBUS_OK;
        }
    }
    COMM_LOGE(COMM_UTILS, "tlv not found by type(=%{public}u)", type);
    return SOFTBUS_NOT_FIND;
}

static int32_t PackTypeOrLength(uint8_t *buf, uint32_t size, uint32_t content, uint8_t contentSize)
{
    errno_t err;
    switch (contentSize) {
        case UINT8_T: {
            uint8_t type = (uint8_t)content;
            err = memcpy_s(buf, size, &type, sizeof(type));
            break;
        }
        case UINT16_T: {
            uint16_t type = SoftBusHtoLs((uint16_t)content);
            err = memcpy_s(buf, size, &type, sizeof(type));
            break;
        }
        case UINT32_T: {
            uint32_t type = SoftBusHtoLl(content);
            err = memcpy_s(buf, size, &type, sizeof(type));
            break;
        }
        default:
            COMM_LOGW(COMM_UTILS, "unsupport type/length size(=%{public}u)", contentSize);
            return SOFTBUS_NOT_IMPLEMENT;
    }
    return (err != EOK ? SOFTBUS_MEM_ERR : SOFTBUS_OK);
}

static int32_t PackValue(uint8_t *buf, uint32_t size, const uint8_t *value, uint32_t vSize)
{
    COMM_CHECK_AND_RETURN_RET_LOGW(vSize != 0, SOFTBUS_OK, COMM_UTILS, "tlv len=0! warning!");
    errno_t err = memcpy_s(buf, size, value, vSize);
    return (err != EOK ? SOFTBUS_MEM_ERR : SOFTBUS_OK);
}

static int32_t PackTlvMember(const TlvObject *obj, const TlvMember *tlv, uint8_t *buffer, uint32_t size)
{
    COMM_CHECK_AND_RETURN_RET_LOGE(size >= TLV_SIZE(obj, tlv->length),
        SOFTBUS_NO_ENOUGH_DATA, COMM_UTILS, "buffer not enough(size=%{public}u, len=%{public}u)", size, tlv->length);
    uint32_t offset = 0;
    int32_t ret = PackTypeOrLength(buffer, obj->size, tlv->type, obj->tSize);
    COMM_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, COMM_UTILS, "pack type fail(=%{public}d)", ret);
    offset += obj->tSize;
    ret = PackTypeOrLength(buffer + offset, obj->size - offset, tlv->length, obj->lSize);
    COMM_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, COMM_UTILS, "pack length fail(=%{public}d)", ret);
    offset += obj->lSize;
    ret = PackValue(buffer + offset, obj->size - offset, tlv->value, tlv->length);
    COMM_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, COMM_UTILS, "pack value fail(=%{public}d)", ret);
    return SOFTBUS_OK;
}

int32_t GetTlvBinary(TlvObject *obj, uint8_t **output, uint32_t *outputSize)
{
    COMM_CHECK_AND_RETURN_RET_LOGW(obj != NULL, SOFTBUS_INVALID_PARAM, COMM_UTILS, "obj nullptr");
    COMM_CHECK_AND_RETURN_RET_LOGW(output != NULL, SOFTBUS_INVALID_PARAM, COMM_UTILS, "output nullptr");
    COMM_CHECK_AND_RETURN_RET_LOGW(outputSize != NULL, SOFTBUS_INVALID_PARAM, COMM_UTILS, "outputSize nullptr");
    COMM_CHECK_AND_RETURN_RET_LOGW(obj->size > 0, SOFTBUS_NOT_FIND, COMM_UTILS, "no tlv member");

    uint8_t *buffer = (uint8_t *)SoftBusCalloc(obj->size);
    COMM_CHECK_AND_RETURN_RET_LOGE(buffer != NULL, SOFTBUS_MALLOC_ERR, COMM_UTILS, "malloc buf fail");

    int32_t ret;
    uint32_t offset = 0;
    TlvMember *tlv = NULL;
    LIST_FOR_EACH_ENTRY(tlv, &obj->mList, TlvMember, node) {
        ret = PackTlvMember(obj, tlv, buffer + offset, obj->size - offset);
        if (ret != SOFTBUS_OK) {
            SoftBusFree(buffer);
            return ret;
        }
        offset += TLV_SIZE(obj, tlv->length);
    }
    *output = buffer;
    *outputSize = offset;
    return SOFTBUS_OK;
}

static uint32_t UnpackTypeOrLength(const uint8_t *buf, uint32_t size)
{
    switch (size) {
        case UINT8_T: {
            uint8_t type = *((uint8_t *)buf);
            return (uint32_t)type;
        }
        case UINT16_T: {
            uint16_t type = *((uint16_t *)buf);
            return (uint32_t)SoftBusLtoHs(type);
        }
        case UINT32_T: {
            uint32_t type = *((uint32_t *)buf);
            return SoftBusLtoHl(type);
        }
        default:
            COMM_LOGW(COMM_UTILS, "unsupport type/length size(=%{public}u)", size);
            break;
    }
    return UINT32_MAX;
}

int32_t SetTlvBinary(TlvObject *obj, const uint8_t *input, uint32_t inputSize)
{
    COMM_CHECK_AND_RETURN_RET_LOGW(obj != NULL, SOFTBUS_INVALID_PARAM, COMM_UTILS, "obj nullptr");
    COMM_CHECK_AND_RETURN_RET_LOGW(input != NULL, SOFTBUS_INVALID_PARAM, COMM_UTILS, "input nullptr");
    COMM_CHECK_AND_RETURN_RET_LOGW(inputSize > 0 && inputSize < MAX_TLV_BINARY_LENGTH,
        SOFTBUS_INVALID_DATA_HEAD, COMM_UTILS, "invalid inputSize(=%{public}u)", inputSize);
    uint32_t offset = 0;
    while (offset + TLV_SIZE(obj, 0) <= inputSize) {
        uint32_t type = UnpackTypeOrLength(input + offset, obj->tSize);
        uint32_t length = UnpackTypeOrLength(input + offset + obj->tSize, obj->lSize);
        COMM_CHECK_AND_RETURN_RET_LOGE((type != UINT32_MAX && length != UINT32_MAX), SOFTBUS_NOT_IMPLEMENT,
            COMM_UTILS, "invalid tSize(=%{public}u)/lSize(=%{public}u)", obj->tSize, obj->lSize);
        COMM_CHECK_AND_RETURN_RET_LOGE(length < MAX_VALUE_LENGTH, SOFTBUS_INVALID_DATA_HEAD,
            COMM_UTILS, "invalid length=%{public}u", length);
        if (TLV_SIZE(obj, length) > inputSize - offset) {
            COMM_LOGW(COMM_UTILS, "incomplete tlv, type=%{public}u, length=%{public}u", type, length);
            return SOFTBUS_NO_ENOUGH_DATA;
        }
        int32_t ret = AddTlvMember(obj, type, length, input + offset + TLV_SIZE(obj, 0));
        COMM_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, COMM_UTILS, "add tlv member fail(=%{public}d)", ret);
        offset += TLV_SIZE(obj, length);
    }
    COMM_CHECK_AND_RETURN_RET_LOGW(offset > 0, SOFTBUS_NO_ENOUGH_DATA,
        COMM_UTILS, "no tlv member, offset=%{public}u, length=%{public}u", offset, inputSize);
    COMM_CHECK_AND_RETURN_RET_LOGW(offset == inputSize, SOFTBUS_OK,
        COMM_UTILS, "TLV binary not be parsed completely, offset=%{public}u, length=%{public}u", offset, inputSize);
    return SOFTBUS_OK;
}

int32_t GetTlvMemberWithSpecifiedBuffer(TlvObject *obj, uint32_t type, uint8_t *buffer, uint32_t size)
{
    COMM_CHECK_AND_RETURN_RET_LOGW(obj != NULL, SOFTBUS_INVALID_PARAM, COMM_UTILS, "obj nullptr");
    uint32_t length = 0;
    uint8_t *value = NULL;
    int32_t ret = GetTlvMember(obj, type, &length, &value);
    COMM_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, COMM_UTILS, "get tlv fail(=%{public}d)", ret);
    COMM_CHECK_AND_RETURN_RET_LOGE(length == size, SOFTBUS_INVALID_PARAM,
        COMM_UTILS, "size(=%{public}u) not match length(=%{public}u)", size, length);
    COMM_CHECK_AND_RETURN_RET_LOGW(length > 0, SOFTBUS_OK, COMM_UTILS, "tlv len==0! warning!");
    COMM_CHECK_AND_RETURN_RET_LOGW(buffer != NULL, SOFTBUS_INVALID_PARAM, COMM_UTILS, "buffer nullptr");
    errno_t err = memcpy_s(buffer, size, value, length);
    return (err != EOK ? SOFTBUS_MEM_ERR : SOFTBUS_OK);
}

int32_t GetTlvMemberWithEstimatedBuffer(TlvObject *obj, uint32_t type, uint8_t *buffer, uint32_t *size)
{
    COMM_CHECK_AND_RETURN_RET_LOGW(obj != NULL, SOFTBUS_INVALID_PARAM, COMM_UTILS, "obj nullptr");
    COMM_CHECK_AND_RETURN_RET_LOGW(size != NULL, SOFTBUS_INVALID_PARAM, COMM_UTILS, "size nullptr");
    COMM_CHECK_AND_RETURN_RET_LOGW(buffer != NULL, SOFTBUS_INVALID_PARAM, COMM_UTILS, "buffer nullptr");
    uint32_t length = 0;
    uint8_t *value = NULL;
    int32_t ret = GetTlvMember(obj, type, &length, &value);
    COMM_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, COMM_UTILS, "get tlv fail(=%{public}d)", ret);
    if (length == 0) {
        COMM_LOGW(COMM_UTILS, "tlv len==0! warning!");
        *size = 0;
        return SOFTBUS_OK;
    }
    errno_t err = memcpy_s(buffer, *size, value, length);
    COMM_CHECK_AND_RETURN_RET_LOGE(err == EOK, SOFTBUS_MEM_ERR, COMM_UTILS, "copy value fail(=%{public}d)", ret);
    *size = length;
    return SOFTBUS_OK;
}

int32_t AddTlvMemberU8(TlvObject *obj, uint32_t type, uint8_t value)
{
    return AddTlvMember(obj, type, sizeof(uint8_t), &value);
}

int32_t GetTlvMemberU8(TlvObject *obj, uint32_t type, uint8_t *value)
{
    return GetTlvMemberWithSpecifiedBuffer(obj, type, value, sizeof(uint8_t));
}

int32_t AddTlvMemberU16(TlvObject *obj, uint32_t type, uint16_t value)
{
    value = SoftBusHtoLs(value);
    return AddTlvMember(obj, type, sizeof(uint16_t), (const uint8_t *)&value);
}

int32_t GetTlvMemberU16(TlvObject *obj, uint32_t type, uint16_t *value)
{
    int32_t ret = GetTlvMemberWithSpecifiedBuffer(obj, type, (uint8_t *)value, sizeof(uint16_t));
    COMM_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, COMM_UTILS, "get tlv fail(=%{public}d)", ret);
    *value = SoftBusLtoHs(*value);
    return SOFTBUS_OK;
}

int32_t AddTlvMemberU32(TlvObject *obj, uint32_t type, uint32_t value)
{
    value = SoftBusHtoLl(value);
    return AddTlvMember(obj, type, sizeof(uint32_t), (const uint8_t *)&value);
}

int32_t GetTlvMemberU32(TlvObject *obj, uint32_t type, uint32_t *value)
{
    int32_t ret = GetTlvMemberWithSpecifiedBuffer(obj, type, (uint8_t *)value, sizeof(uint32_t));
    COMM_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, COMM_UTILS, "get tlv fail(=%{public}d)", ret);
    *value = SoftBusLtoHl(*value);
    return SOFTBUS_OK;
}

int32_t AddTlvMemberU64(TlvObject *obj, uint32_t type, uint64_t value)
{
    value = SoftBusHtoLll(value);
    return AddTlvMember(obj, type, sizeof(uint64_t), (const uint8_t *)&value);
}

int32_t GetTlvMemberU64(TlvObject *obj, uint32_t type, uint64_t *value)
{
    int32_t ret = GetTlvMemberWithSpecifiedBuffer(obj, type, (uint8_t *)value, sizeof(uint64_t));
    COMM_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, COMM_UTILS, "get tlv fail(=%{public}d)", ret);
    *value = SoftBusLtoHll(*value);
    return SOFTBUS_OK;
}
