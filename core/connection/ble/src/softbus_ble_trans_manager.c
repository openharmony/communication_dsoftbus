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
#include "softbus_adapter_timer.h"
#include "softbus_ble_gatt_client.h"
#include "softbus_ble_gatt_server.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_hisysevt_connreporter.h"

typedef struct {
    uint32_t seq;
    uint32_t size;
    uint32_t offset;
    uint32_t total;
} BleTransHeader;

static const int MTU_HEADER_SIZE = 3;
static SoftBusBleTransCalback *g_softBusBleTransCb = NULL;

static int32_t GetTransHeader(char *value, uint32_t len, BleTransHeader *header)
{
    BleTransHeader *tmpHeader = (BleTransHeader *)value;
    header->seq = ntohl(tmpHeader->seq);
    header->size = ntohl(tmpHeader->size);
    header->offset = ntohl(tmpHeader->offset);
    header->total = ntohl(tmpHeader->total);
    if ((header->size != len - sizeof(BleTransHeader)) || (header->total > MAX_DATA_LEN) ||
        (header->size > header->total) || (header->total - header->size < header->offset)) {
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t FindAvailableCacheIndex(BleConnectionInfo *targetNode, const BleTransHeader *header, int *canIndex)
{
    int32_t availableIndex = -1;
    int32_t i;
    for (i = 0; i < MAX_CACHE_NUM_PER_CONN; i++) {
        if (targetNode->recvCache[i].isUsed == 0) {
            availableIndex = (availableIndex > -1) ? availableIndex : i;
            continue;
        }
        if (targetNode->recvCache[i].seq == header->seq) {
            break;
        }
    }
    if ((i == MAX_CACHE_NUM_PER_CONN) && (availableIndex == -1)) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BleTransRecv no availed cache");
        return SOFTBUS_ERR;
    }
    if (i == MAX_CACHE_NUM_PER_CONN) {
        targetNode->recvCache[availableIndex].isUsed = 1;
        targetNode->recvCache[availableIndex].currentSize = 0;
        targetNode->recvCache[availableIndex].seq = header->seq;
        if (targetNode->recvCache[availableIndex].cache == NULL) {
            targetNode->recvCache[availableIndex].cache = (char *)SoftBusCalloc(MAX_DATA_LEN);
            if (targetNode->recvCache[availableIndex].cache == NULL) {
                targetNode->recvCache[availableIndex].isUsed = 0;
                return SOFTBUS_ERR;
            }
        }
        i = availableIndex;
    }
    *canIndex = i;
    return SOFTBUS_OK;
}

char *BleTransRecv(BleHalConnInfo halConnInfo, char *value, uint32_t len, uint32_t *outLen, int32_t *index)
{
    if (value == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BleTransRecv invalid data");
        SoftBusReportConnFaultEvt(SOFTBUS_HISYSEVT_CONN_MEDIUM_BLE, SOFTBUS_HISYSEVT_BLE_RECV_INVALID_DATA);
        return NULL;
    }
    BleConnectionInfo *targetNode = g_softBusBleTransCb->GetBleConnInfoByHalConnId(halConnInfo);
    if (targetNode == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BleTransRecv unknown device");
        SoftBusReportConnFaultEvt(SOFTBUS_HISYSEVT_CONN_MEDIUM_BLE, SOFTBUS_HISYSEVT_BLE_RECV_INVALID_DEVICE);
        return NULL;
    }
    BleTransHeader header;
    if (GetTransHeader(value, len, &header) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BleTransRecv GetTransHeader failed");
        return NULL;
    }
    if (header.size == header.total) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "BleTransRecv a full pack");
        *outLen = header.total;
        *index = -1;
        return value + sizeof(BleTransHeader);
    }

    int32_t canIndex;
    if (FindAvailableCacheIndex(targetNode, &header, &canIndex) != SOFTBUS_OK) {
        return NULL;
    }

    if (memcpy_s(targetNode->recvCache[canIndex].cache + header.offset, MAX_DATA_LEN - header.offset,
        value + sizeof(BleTransHeader), header.size) != EOK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BleTransRecv memcpy_s failed");
        targetNode->recvCache[canIndex].isUsed = 0;
        return NULL;
    }
    targetNode->recvCache[canIndex].currentSize += header.size;
    if (targetNode->recvCache[canIndex].currentSize == header.total) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "BleTransRecv a part pack, build complete");
        *outLen = header.total;
        *index = canIndex;
        return targetNode->recvCache[canIndex].cache;
    }
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "BleTransRecv a part pack, wait next one, total:%d, current:%d",
        header.total, targetNode->recvCache[canIndex].currentSize);
    return NULL;
}

void BleTransCacheFree(BleHalConnInfo halConnInfo, int32_t index)
{
    BleConnectionInfo *targetNode = g_softBusBleTransCb->GetBleConnInfoByHalConnId(halConnInfo);
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
        return SoftBusGattServerSend(connInfo->halConnId, data, len, module);
    } else {
        return SoftBusGattClientSend(connInfo->halConnId, data, len, module);
    }
}

int32_t BleTransSend(BleConnectionInfo *connInfo, const char *data, uint32_t len, int32_t seq, int32_t module)
{
#define BLE_SEND_PACKET_DELAY_LEN 10 // ms
    CLOGI("enter connId:%d, datalen:%d, module:%d", connInfo->connId, len, module);
    uint32_t tempLen = len;
    char *sendData = (char *)data;
    uint32_t dataLenMax = (uint32_t)(connInfo->mtu - MTU_HEADER_SIZE - sizeof(BleTransHeader));
    uint32_t offset = 0;
    while (tempLen > 0) {
        uint32_t sendLength = tempLen;
        if (sendLength > dataLenMax) {
            sendLength = dataLenMax;
        }
        char *buff = (char *)SoftBusCalloc(sendLength + sizeof(BleTransHeader));
        if (buff == NULL) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "malloc failed");
            return SOFTBUS_MALLOC_ERR;
        }
        int ret = memcpy_s(buff + sizeof(BleTransHeader), sendLength, sendData, sendLength);
        if (ret != EOK) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "BleTransSend big msg, len:%u\n", tempLen);
            SoftBusFree(buff);
            return ret;
        }
        BleTransHeader *transHeader = (BleTransHeader *)buff;
        transHeader->total = htonl(len);
        transHeader->size = htonl(sendLength);
        transHeader->offset = htonl(offset);
        transHeader->seq = htonl(seq);
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "BleTransSend  module:%d", module);
        ret = BleHalSend((const BleConnectionInfo *)connInfo, buff, sendLength + sizeof(BleTransHeader), module);
        if (ret != SOFTBUS_OK) {
            SoftBusReportConnFaultEvt(SOFTBUS_HISYSEVT_CONN_MEDIUM_BLE, SOFTBUS_HISYSEVT_BLE_SEND_FAIL);
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "BleTransSend BleHalSend failed");
            SoftBusFree(buff);
            return ret;
        }
        SoftBusFree(buff);
        sendData += sendLength;
        tempLen -= sendLength;
        if (tempLen > 0) {
            // Temporarily add delay to avoid packet loss
            SoftBusSleepMs(BLE_SEND_PACKET_DELAY_LEN);
        }
        offset += sendLength;
    }
    return SOFTBUS_OK;
}

int32_t BleTransInit(SoftBusBleTransCalback *cb)
{
    if (cb == NULL) {
        return SOFTBUS_ERR;
    }
    g_softBusBleTransCb = cb;
    return SOFTBUS_OK;
}