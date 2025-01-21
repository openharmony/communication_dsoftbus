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

#include "client_trans_assemble_tlv.h"

#include <securec.h>

#include "softbus_adapter_mem.h"
#include "softbus_adapter_socket.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "trans_log.h"

#define TLV_TYPE_AND_LENTH 2

int32_t TransAssembleTlvData(DataHead *pktHead, uint8_t type, uint8_t *buffer, uint8_t bufferLen, int32_t *bufferSize)
{
    if (pktHead == NULL || buffer == NULL || bufferSize == NULL) {
        TRANS_LOGE(TRANS_SDK, "param invalid.");
        return SOFTBUS_INVALID_PARAM;
    }
    TlvElement *element = (TlvElement *)pktHead->tlvElement;
    element->type = type;
    element->value = (uint8_t *)SoftBusCalloc(bufferLen);
    if (element->value == NULL) {
        TRANS_LOGE(TRANS_SDK, "malloc bufferLen failed.");
        return SOFTBUS_MALLOC_ERR;
    }
    if (memcpy_s(element->value, bufferLen, buffer, bufferLen) != EOK) {
        SoftBusFree(element->value);
        TRANS_LOGE(TRANS_SDK, "memcpy buffer failed.");
        return SOFTBUS_MEM_ERR;
    }
    element->length = bufferLen;
    pktHead->tlvElement += sizeof(TlvElement);
    *bufferSize += (TLV_TYPE_AND_LENTH * sizeof(uint8_t) + bufferLen);
    pktHead->tlvCount++;
    return SOFTBUS_OK;
}

void ReleaseTlvValueBuffer(DataHead *pktHead)
{
    pktHead->tlvElement -= ((pktHead->tlvCount) * sizeof(TlvElement));
    for (int index = 0; index < pktHead->tlvCount; index++) {
        TlvElement *temp = (TlvElement *)pktHead->tlvElement;
        SoftBusFree(temp->value);
        temp->value = NULL;
        pktHead->tlvElement += sizeof(TlvElement);
    }
    pktHead->tlvElement -= ((pktHead->tlvCount) * sizeof(TlvElement));
}