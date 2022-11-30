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

#include "br_trans_manager.h"

#include <arpa/inet.h>

#include "securec.h"
#include "softbus_adapter_mem.h"
#include "softbus_datahead_transform.h"
#include "softbus_conn_interface.h"
#include "softbus_conn_manager.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_json_utils.h"
#include "softbus_log.h"

static int32_t ReceivedHeadCheck(BrConnectionInfo *conn)
{
    int32_t pktHeadLen = sizeof(ConnPktHead);
    if (conn->recvPos < pktHeadLen) {
        return SOFTBUS_ERR;
    }
    ConnPktHead *head = (ConnPktHead *)(conn->recvBuf);
    UnpackConnPktHead(head);
    if ((uint32_t)(head->magic) != MAGIC_NUMBER) {
        conn->recvPos = 0;
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "[ReceivedHeadCheck] magic error 0x%x", head->magic);
        return SOFTBUS_ERR;
    }

    if ((int32_t)(head->len) < 0 ||
        conn->recvSize - pktHeadLen < (int32_t)(head->len)) {
        conn->recvPos = 0;
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR,
            "[ReceivedHeadCheck]data size is illegal. module=%d, seq=%" PRId64 ", datalen=%d",
            head->module, head->seq, head->len);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static char *BrRecvDataParse(BrConnectionInfo *conn, int32_t *outLen)
{
    if (ReceivedHeadCheck(conn) != SOFTBUS_OK) {
        return NULL;
    }
    int32_t bufLen = conn->recvPos;
    ConnPktHead *head = (ConnPktHead *)(conn->recvBuf);
    int32_t packLen = (int32_t)(head->len) + sizeof(ConnPktHead);
    if (bufLen < packLen) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "not a complete package, continue");
        return NULL;
    }
    if (bufLen < 0 || packLen < 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "bufLen or packLen invalid");
        return NULL;
    }
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "[BrTransRead] a complete package packLen: %d", packLen);
    char *dataCopy = SoftBusMalloc(packLen);
    if (dataCopy == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "[BrTransRead] SoftBusMalloc failed");
        return NULL;
    }
    if (memcpy_s(dataCopy, packLen, conn->recvBuf, packLen) != EOK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "[BrTransRead] memcpy_s failed");
        SoftBusFree(dataCopy);
        return NULL;
    }

    if (bufLen > packLen &&
        memmove_s(conn->recvBuf, conn->recvSize, conn->recvBuf + packLen, bufLen - packLen) != EOK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "[BrTransRead] memmove_s failed");
        SoftBusFree(dataCopy);
        return NULL;
    }
    conn->recvPos = bufLen - packLen;
    *outLen = packLen;
    return dataCopy;
}

int32_t BrTransReadOneFrame(uint32_t connectionId, const SppSocketDriver *sppDriver, int32_t clientId, char **outBuf)
{
    BrConnectionInfo *conn = GetConnectionRef(connectionId);
    if (conn == NULL) {
        return BR_READ_FAILED;
    }
    int32_t recvLen;
    while (1) {
        int32_t packLen;
        char *dataBuf = BrRecvDataParse(conn, &packLen);
        if (dataBuf != NULL) {
            *outBuf = dataBuf;
            ReleaseConnectionRef(conn);
            return packLen;
        }
        if (conn->recvSize - conn->recvPos > 0) {
            recvLen = sppDriver->Read(clientId, conn->recvBuf + conn->recvPos, conn->recvSize - conn->recvPos);
            if (recvLen == BR_READ_SOCKET_CLOSED) {
                ReleaseConnectionRef(conn);
                return BR_READ_SOCKET_CLOSED;
            }
            if (recvLen == BR_READ_FAILED) {
                SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "sppDriver Read BR_READ_FAILED");
                ReleaseConnectionRef(conn);
                return BR_READ_SOCKET_CLOSED;
            }
            conn->recvPos += recvLen;
        }
        dataBuf = BrRecvDataParse(conn, &packLen);
        if (dataBuf != NULL) {
            *outBuf = dataBuf;
            ReleaseConnectionRef(conn);
            return packLen;
        }
    }
}

int32_t BrTransSend(BrConnectionInfo *brConnInfo, const SppSocketDriver *sppDriver,
    int32_t brSendPeerLen, const char *data, uint32_t len)
{
    if (brConnInfo == NULL) {
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "BrTransSend, %d", brConnInfo->connectionId);
    int32_t socketFd = brConnInfo->socketFd;
    if (socketFd == -1) {
        return SOFTBUS_ERR;
    }
    const char *tempData = data;
    int32_t ret = SOFTBUS_OK;
    int32_t writeRet;
    int32_t tempLen = (int32_t)len;
    while (tempLen > 0) {
        (void)pthread_mutex_lock(&brConnInfo->lock);
        if (brConnInfo->conGestState == BT_RFCOM_CONGEST_ON &&
            (brConnInfo->state == BR_CONNECTION_STATE_CONNECTED || brConnInfo->state == BR_CONNECTION_STATE_CLOSING)) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "wait congest condition, %d", brConnInfo->connectionId);
            pthread_cond_wait(&brConnInfo->congestCond, &brConnInfo->lock);
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "free congest condition, %d", brConnInfo->connectionId);
        }
        (void)pthread_mutex_unlock(&brConnInfo->lock);

        int32_t sendLength = tempLen;
        if (sendLength > brSendPeerLen) {
            sendLength = brSendPeerLen;
        }
        writeRet = sppDriver->Write(socketFd, tempData, sendLength);
        if (writeRet == -1) {
            ret = SOFTBUS_ERR;
            break;
        }
        tempData += sendLength;
        tempLen -= sendLength;
    }
    return ret;
}

static char *BrAddNumToJson(int32_t method, int32_t delta, uint64_t count)
{
    cJSON *json = cJSON_CreateObject();
    if (json == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "Cannot create cJSON object");
        return NULL;
    }
    if (method == METHOD_NOTIFY_REQUEST) {
        if (!AddNumberToJsonObject(json, KEY_METHOD, METHOD_NOTIFY_REQUEST) ||
            !AddNumberToJsonObject(json, KEY_DELTA, delta) ||
            !AddNumberToJsonObject(json, KEY_REFERENCE_NUM, (int32_t)count)) {
            cJSON_Delete(json);
            return NULL;
        }
    } else if (method == METHOD_NOTIFY_ACK) {
        if (!AddNumberToJsonObject(json, KEY_METHOD, METHOD_NOTIFY_ACK) ||
            !AddNumberToJsonObject(json, KEY_WINDOWS, delta) ||
            !AddNumber64ToJsonObject(json, KEY_ACK_SEQ_NUM, (int64_t)count)) {
            cJSON_Delete(json);
            return NULL;
        }
    } else if (method == METHOD_ACK_RESPONSE) {
        if (!AddNumberToJsonObject(json, KEY_METHOD, METHOD_ACK_RESPONSE) ||
            !AddNumberToJsonObject(json, KEY_WINDOWS, delta) ||
            !AddNumber64ToJsonObject(json, KEY_ACK_SEQ_NUM, (int64_t)count)) {
            cJSON_Delete(json);
            return NULL;
        }
    } else {
        if (!AddNumberToJsonObject(json, KEY_METHOD, METHOD_NOTIFY_RESPONSE) ||
            !AddNumberToJsonObject(json, KEY_REFERENCE_NUM, (int32_t)count)) {
            cJSON_Delete(json);
            return NULL;
        }
    }
    char *data = cJSON_PrintUnformatted(json);
    cJSON_Delete(json);
    return data;
}

char *BrPackRequestOrResponse(int32_t requestOrResponse, int32_t delta, uint64_t count, int32_t *outLen)
{
    char *data = BrAddNumToJson(requestOrResponse, delta, count);
    if (data == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BrAddNumToJson failed");
        return NULL;
    }

    uint32_t headSize = sizeof(ConnPktHead);
    uint32_t dataLen = strlen(data) + 1 + headSize;
    char *buf = (char *)SoftBusCalloc(dataLen);
    if (buf == NULL) {
        cJSON_free(data);
        return NULL;
    }
    ConnPktHead head;
    head.magic = MAGIC_NUMBER;
    head.module = MODULE_CONNECTION;
    head.seq = 1;
    head.flag = 0;
    head.len = strlen(data) + 1;
    PackConnPktHead(&head);
    if (memcpy_s(buf, dataLen, (void *)&head, headSize) != EOK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "memcpy_s head error");
        cJSON_free(data);
        SoftBusFree(buf);
        return NULL;
    }
    if (memcpy_s(buf + headSize, dataLen - headSize, data, strlen(data) + 1) != EOK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "memcpy_s data error");
        cJSON_free(data);
        SoftBusFree(buf);
        return NULL;
    }
    *outLen = (int32_t)dataLen;
    cJSON_free(data);
    return buf;
}
