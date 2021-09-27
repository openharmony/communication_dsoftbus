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

#include "softbus_ble_trans_manager.h"
#include <arpa/inet.h>
#include "securec.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_log.h"

typedef struct {
    int32_t seq;
    int32_t size;
    int32_t offset;
    int32_t total;
} BleTransHeader;

static const int MTU_HEADER_SIZE = 3;

static int32_t GetTransHeader(char *value, int32_t len, BleTransHeader *header)
{
    BleTransHeader *tmpHeader = (BleTransHeader *)value;
    header->seq = ntohl(tmpHeader->seq);
    header->size = ntohl(tmpHeader->size);
    header->offset = ntohl(tmpHeader->offset);
    header->total = ntohl(tmpHeader->total);
    if ((header->size != len - (int32_t)sizeof(BleTransHeader)) ||
        (header->total < header->size + header->offset) ||
        (header->offset < 0) || (header->total > MAX_DATA_LEN)) {
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

char *BleTransRecv(int32_t halConnId, char *value, uint32_t len, uint32_t *outLen, int32_t *index)
{
    if (value == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BleTransRecv invalid data");
        return NULL;
    }
    BleConnectionInfo *targetNode = GetBleConnInfoByHalConnId(halConnId);
    if (targetNode == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BleTransRecv unknown device");
        return NULL;
    }
    BleTransHeader header;
    if (GetTransHeader(value, len, &header) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BleTransRecv GetTransHeader failed");
        return NULL;
    }
    if (header.size == header.total) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "BleTransRecv a full pack");
        *outLen = (uint32_t)header.total;
        *index = -1;
        return value + sizeof(BleTransHeader);
    }
    int availableIndex = -1;
    int i;
    for (i = 0; i < MAX_CACHE_NUM_PER_CONN; i++) {
        if (targetNode->recvCache[i].isUsed == 0) {
            availableIndex = (availableIndex > -1) ? availableIndex : i;
            continue;
        }
        if (targetNode->recvCache[i].seq == header.seq) {
            break;
        }
    }
    if ((i == MAX_CACHE_NUM_PER_CONN) && (availableIndex == -1)) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BleTransRecv no availed cache");
        return NULL;
    }
    if (i == MAX_CACHE_NUM_PER_CONN) {
        targetNode->recvCache[availableIndex].isUsed = 1;
        targetNode->recvCache[availableIndex].currentSize = 0;
        targetNode->recvCache[availableIndex].seq = header.seq;
        if (targetNode->recvCache[availableIndex].cache == NULL) {
            targetNode->recvCache[availableIndex].cache = (char *)SoftBusCalloc(MAX_DATA_LEN);
            if (targetNode->recvCache[availableIndex].cache == NULL) {
                targetNode->recvCache[availableIndex].isUsed = 0;
                return NULL;
            }
        }
        i = availableIndex;
    }
    if (memcpy_s(targetNode->recvCache[i].cache + header.offset, MAX_DATA_LEN - header.offset,
        value + sizeof(BleTransHeader), header.size) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BleTransRecv memcpy_s failed");
        targetNode->recvCache[i].isUsed = 0;
        return NULL;
    }
    targetNode->recvCache[i].currentSize += header.size;
    if (targetNode->recvCache[i].currentSize == header.total) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "BleTransRecv a part pack, build complete");
        *outLen = header.total;
        *index = i;
        return targetNode->recvCache[i].cache;
    }
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "BleTransRecv a part pack, wait next one, total:%d, current:%d",
        header.total, targetNode->recvCache[i].currentSize);
    return NULL;
}

void BleTransCacheFree(int32_t halConnId, int32_t index)
{
    BleConnectionInfo *targetNode = GetBleConnInfoByHalConnId(halConnId);
    if (targetNode == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BleTransCacheFree unknown device");
        return;
    }
    if (targetNode->recvCache[index].cache != NULL) {
        SoftBusFree(targetNode->recvCache[index].cache);
        targetNode->recvCache[index].cache = NULL;
    }
    targetNode->recvCache[index].isUsed = 0;
}

static int32_t BleHalSend(const BleConnectionInfo *connInfo, const char *data, int32_t len, int32_t module)
{
    if (connInfo->info.isServer == 1) {
        SoftBusGattsNotify notify = {
            .connectId = connInfo->halConnId,
            .attrHandle =  GetBleAttrHandle(module),
            .confirm = 0,
            .valueLen = len,
            .value = (char *)data
        };
        return SoftBusGattsSendNotify(&notify);
    } else {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "SendBleData ble gatt client not support");
        return SOFTBUS_ERR;
    }
}

int32_t BleTransSend(BleConnectionInfo *connInfo, const char *data, int32_t len, int32_t seq, int32_t module)
{
    int32_t templen = len;
    char *sendData = (char *)data;
    int32_t dataLenMax = connInfo->mtu - MTU_HEADER_SIZE - sizeof(BleTransHeader);
    int32_t offset = 0;
    while (templen > 0) {
        int32_t sendlenth = templen;
        if (sendlenth > dataLenMax) {
            sendlenth = dataLenMax;
        }
        char *buff = (char *)SoftBusCalloc(sendlenth + sizeof(BleTransHeader));
        int ret = memcpy_s(buff + sizeof(BleTransHeader), sendlenth, sendData, sendlenth);
        if (ret != SOFTBUS_OK) {
            LOG_INFO("BleTransSend big msg, len:%{public}d\n", templen);
            SoftBusFree(buff);
            return ret;
        }
        BleTransHeader *transHeader = (BleTransHeader *)buff;
        transHeader->total = htonl(len);
        transHeader->size = htonl(sendlenth);
        transHeader->offset = htonl(offset);
        transHeader->seq = htonl(seq);
        ret = BleHalSend((const BleConnectionInfo *)connInfo, buff, sendlenth + sizeof(BleTransHeader), module);
        if (ret != SOFTBUS_OK) {
            LOG_INFO("BleTransSend BleHalSend failed");
            SoftBusFree(buff);
            return ret;
        }
        SoftBusFree(buff);
        sendData += sendlenth;
        templen -= sendlenth;
        offset += sendlenth;
    }
    return SOFTBUS_OK;
}