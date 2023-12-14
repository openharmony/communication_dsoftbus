/*
 * Copyright (C) 2021-2023 Huawei Device Co., Ltd.
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

#include "coap_adapter.h"
#include "nstackx_dfinder_log.h"
#include "securec.h"
#include "nstackx_statistics.h"

#define COAP_MAX_ENDPOINTS_NUM 64
#define COAP_LOW_DELTA_NUM 13
#define COAP_MID_DELTA_NUM 256
#define COAP_EXTEND_DELTA_VALUE_UINT8 13
#define COAP_EXTEND_DELTA_VALUE_UINT16 14
#define COAP_EXTEND_DELTA_VALUE_INVALID 15
#define COAP_OPTION_MAX_LEN 64
#define COAP_OPTION_EXTENSION_LEN   2
#define COAP_SHIFT_BIT8 8
#define COAP_SHIFT_BIT6 6
#define COAP_SHIFT_BIT4 4
#define BUF_OFFSET_BYTE2 2
#define BUF_OFFSET_BYTE3 3
#define BUF_OFFSET_BYTE4 4
#define MSGID_HIGHT_BYTE 2
#define RAND_DIVISOR 0

#define TAG "nStackXCoAP"

typedef struct {
    CoapPacket *pkt;
    CoapPacketParam *param;
    const uint8_t *payload;
    unsigned long payloadLen;
} CoapResponseInfo;

static uint16_t g_msgId = 0;

static int32_t CoapParseOptionExtension(uint16_t *value, const uint8_t **dataPos, uint8_t *headerLen, uint32_t bufLen)
{
    if (*value == COAP_EXTEND_DELTA_VALUE_UINT8) {
        (*headerLen)++;
        if (bufLen < *headerLen) {
            DFINDER_LOGE(TAG, "opt invalid cause short for header");
            return DISCOVERY_ERR_OPT_INVALID_SHORT_FOR_HEADER;
        }

        *value = (uint16_t)((*dataPos)[1] + COAP_LOW_DELTA_NUM);
        (*dataPos)++;
        return DISCOVERY_ERR_SUCCESS;
    }

    if (*value == COAP_EXTEND_DELTA_VALUE_UINT16) {
        *headerLen = (uint8_t)(*headerLen + COAP_OPTION_EXTENSION_LEN);
        if (bufLen < *headerLen) {
            DFINDER_LOGE(TAG, "opt invalid cause short for header");
            return DISCOVERY_ERR_OPT_INVALID_SHORT_FOR_HEADER;
        }

        uint16_t optionDeltaValue = (uint16_t)((*dataPos)[1] << COAP_SHIFT_BIT8) |
            (*dataPos)[COAP_OPTION_EXTENSION_LEN];
        if (optionDeltaValue > (0xFFFF - COAP_LOW_DELTA_NUM - COAP_MID_DELTA_NUM)) {
            DFINDER_LOGE(TAG, "CoapParseOptionExtension bad req");
            return DISCOVERY_ERR_BAD_REQ;
        }

        *value = (uint16_t)(optionDeltaValue + COAP_LOW_DELTA_NUM + COAP_MID_DELTA_NUM);
        (*dataPos) += COAP_OPTION_EXTENSION_LEN;
        return DISCOVERY_ERR_SUCCESS;
    }

    if (*value == COAP_EXTEND_DELTA_VALUE_INVALID) {
        DFINDER_LOGE(TAG, "CoapParseOptionExtension opt invalid delta");
        return DISCOVERY_ERR_OPT_INVALID_DELTA;
    }

    return DISCOVERY_ERR_SUCCESS;
}

static int32_t CoapParseOption(CoapOption *option, uint16_t *runningDelta, const uint8_t **buf, uint32_t bufLen)
{
    const uint8_t *dataPos = NULL;
    uint8_t headLen;
    uint16_t len;
    uint16_t delta;
    int32_t ret;

    if (bufLen < 1)  {
        DFINDER_LOGE(TAG, "CoapParseOption buf too short");
        return DISCOVERY_ERR_OPT_INVALID_SHORT_FOR_HEADER;
    }
    dataPos = *buf;
    delta = (dataPos[0] & 0xF0) >> COAP_SHIFT_BIT4;
    len = dataPos[0] & 0x0F;
    headLen = 1;
    ret = CoapParseOptionExtension(&delta, &dataPos, &headLen, bufLen);
    if (ret != DISCOVERY_ERR_SUCCESS) {
        return ret;
    }

    ret = CoapParseOptionExtension(&len, &dataPos, &headLen, bufLen);
    if (ret != DISCOVERY_ERR_SUCCESS) {
        return ret;
    }

    if ((dataPos + 1 + len) > (*buf + bufLen)) {
        DFINDER_LOGE(TAG, "CoapParseOption dataPos too big");
        return DISCOVERY_ERR_OPT_INVALID_BIG;
    }

    option->num = (uint16_t)(delta + *runningDelta);
    option->optionBuf = dataPos + 1;
    option->len = len;

    *buf = dataPos + 1 + len;
    *runningDelta = (uint16_t)(*runningDelta + delta);
    return DISCOVERY_ERR_SUCCESS;
}

static int32_t CoapParseOptionsAndPayloadEx(CoapPacket *pkt, const uint8_t *buf, uint32_t buflen)
{
    uint8_t optionIndex = 0;
    uint16_t delta = 0;
    const uint8_t *dataPos = buf + HEADER_LEN + pkt->header.tokenLen;
    const uint8_t *end = buf + buflen;

    if (dataPos > end) {
        DFINDER_LOGE(TAG, "CoapParseOptionsAndPayload overruns pkt");
        return DISCOVERY_ERR_OPT_OVERRUNS_PKT;
    }

    while ((dataPos < end) && (*dataPos != 0xFF) && (optionIndex < COAP_MAX_OPTION)) {
        int32_t ret = CoapParseOption(&((pkt->options)[optionIndex]), &delta, &dataPos, end - dataPos);
        if (ret != DISCOVERY_ERR_SUCCESS) {
            return ret;
        }
        optionIndex++;
    }

    if ((dataPos < end) && (*dataPos != 0xFF) && (optionIndex >= COAP_MAX_OPTION)) {
        DFINDER_LOGE(TAG, "CoapParseOptionsAndPayload server error");
        return DISCOVERY_ERR_SERVER_ERR;
    }
    pkt->optionsNum = optionIndex;
    if ((dataPos < end) && (*dataPos != 0xFF)) {
        pkt->payload.buffer = NULL;
        pkt->payload.len = 0;
        return DISCOVERY_ERR_SUCCESS;
    }

    if (dataPos + 1 >= end) {
        DFINDER_LOGE(TAG, "CoapParseOptionsAndPayload invalid pkt");
        return DISCOVERY_ERR_INVALID_PKT;
    }

    pkt->payload.buffer = dataPos + 1;
    pkt->payload.len = (uint32_t)(end - (dataPos + 1));
    return DISCOVERY_ERR_SUCCESS;
}

static int32_t CoapParseOptionsAndPayload(CoapPacket *pkt, const uint8_t *buf, uint32_t buflen)
{
    int32_t ret = CoapParseOptionsAndPayloadEx(pkt, buf, buflen);
    if (ret != DISCOVERY_ERR_SUCCESS) {
        IncStatistics(STATS_INVALID_OPT_AND_PAYLOAD);
    }
    return ret;
}

static int32_t CoapParseHeader(CoapPacket *pkt, const uint8_t *buf, uint32_t bufLen)
{
    if (bufLen < HEADER_LEN) {
        DFINDER_LOGE(TAG, "CoapParseHeader header invalid short");
        return DISCOVERY_ERR_HEADER_INVALID_SHORT;
    }

    pkt->header.ver = (((uint32_t)buf[0] >> COAP_SHIFT_BIT6) & 0x03);
    pkt->header.type = ((((uint32_t)buf[0] & 0x30) >> COAP_SHIFT_BIT4) & 0x03);
    pkt->header.tokenLen = (((uint32_t)buf[0] & 0x0F));
    pkt->header.code = buf[1];
    pkt->header.varSection.msgId = (uint16_t)((uint16_t)(buf[MSGID_HIGHT_BYTE] << COAP_SHIFT_BIT8)
       | buf[BUF_OFFSET_BYTE3]);
    return DISCOVERY_ERR_SUCCESS;
}

static int32_t CoapSoftBusDecodeEx(CoapPacket *pkt, const uint8_t *buf, uint32_t bufLen)
{
    int32_t ret;
    if (pkt == NULL || buf == NULL) {
        DFINDER_LOGE(TAG, "CoapSoftBusDecode pkt or buf invalid");
        return -1;
    }

    if (bufLen == 0) {
        DFINDER_LOGE(TAG, "CoapSoftBusDecode buflen invalid");
        return -1;
    }

    if (pkt->protocol != COAP_UDP) {
        DFINDER_LOGE(TAG, "CoapSoftBusDecode protocol not coap_udp");
        return -1;
    }

    ret = CoapParseHeader(pkt, buf, bufLen);
    if (ret != DISCOVERY_ERR_SUCCESS) {
        return ret;
    }

    if (pkt->header.ver != COAP_VERSION) {
        DFINDER_LOGE(TAG, "CoapSoftBusDecode protocol header version invalid");
        return DISCOVERY_ERR_VER_INVALID;
    }

    if (pkt->header.tokenLen > MAX_TOK_LEN) {
        DFINDER_LOGE(TAG, "CoapSoftBusDecode protocol header tokenlen invalid");
        return DISCOVERY_ERR_INVALID_TOKEN_LEN;
    }

    if ((bufLen > HEADER_LEN) && (pkt->header.code == 0)) {
        DFINDER_LOGE(TAG, "CoapSoftBusDecode empty msg");
        return DISCOVERY_ERR_INVALID_EMPTY_MSG;
    }

    if (pkt->header.tokenLen == 0) {
        pkt->token.buffer = NULL;
        pkt->token.len = 0;
    } else if ((uint32_t)(pkt->header.tokenLen + HEADER_LEN) > bufLen) {
        DFINDER_LOGE(TAG, "CoapSoftBusDecode token too short");
        return DISCOVERY_ERR_TOKEN_INVALID_SHORT;
    } else {
        pkt->token.buffer = &buf[BUF_OFFSET_BYTE4];
        pkt->token.len = pkt->header.tokenLen;
    }

    ret = CoapParseOptionsAndPayload(pkt, buf, bufLen);
    if (ret != DISCOVERY_ERR_SUCCESS) {
        return ret;
    }

    pkt->len = bufLen;
    return DISCOVERY_ERR_SUCCESS;
}

int32_t CoapSoftBusDecode(CoapPacket *pkt, const uint8_t *buf, uint32_t bufLen)
{
    int32_t ret = CoapSoftBusDecodeEx(pkt, buf, bufLen);
    if (ret != DISCOVERY_ERR_SUCCESS) {
        IncStatistics(STATS_DECODE_FAILED);
    }
    return ret;
}

static int32_t CoapCreateHeaderEx(CoapPacket *pkt, const CoapPacketParam *pktParam, CoapReadWriteBuffer *buf)
{
    if (buf->len != 0) {
        DFINDER_LOGE(TAG, "CoapCreateHeader invalid argument");
        return DISCOVERY_ERR_INVALID_ARGUMENT;
    }

    if ((pktParam->protocol != COAP_UDP) && (pktParam->protocol != COAP_TCP)) {
        DFINDER_LOGE(TAG, "CoapCreateHeader protocol not udp or tcp");
        return DISCOVERY_ERR_TRANSPORT_NOT_UDP_OR_TCP;
    }
    pkt->protocol = pktParam->protocol;

    if (pktParam->type > COAP_TYPE_RESET) {
        DFINDER_LOGE(TAG, "CoapCreateHeader unknown msg type");
        return DISCOVERY_ERR_UNKNOWN_MSG_TYPE;
    }

    if (buf->size < HEADER_LEN) {
        DFINDER_LOGE(TAG, "CoapCreateHeader exceed max pdu");
        return DISCOVERY_ERR_PKT_EXCEED_MAX_PDU;
    }

    pkt->header.type = (uint32_t)pktParam->type & 0x03;
    pkt->header.ver = COAP_VERSION;
    pkt->header.code = COAP_RESPONSE_CODE(pktParam->code);

    if (pkt->protocol == COAP_UDP) {
        pkt->header.varSection.msgId = pktParam->msgId;
        buf->readWriteBuf[0] = (char)(pkt->header.ver << COAP_SHIFT_BIT6);
        buf->readWriteBuf[0] = (char)((uint8_t)buf->readWriteBuf[0] |
            (uint8_t)(pkt->header.type << COAP_SHIFT_BIT4));
        buf->readWriteBuf[1] = (char)pkt->header.code;
        buf->readWriteBuf[BUF_OFFSET_BYTE2] = (char)((pkt->header.varSection.msgId & 0xFF00) >> COAP_SHIFT_BIT8);
        buf->readWriteBuf[BUF_OFFSET_BYTE3] = (char)(pkt->header.varSection.msgId & 0x00FF);
    } else {
        DFINDER_LOGE(TAG, "CoapCreateHeader not supported");
        return DISCOVERY_ERR_NOT_SUPPORTED;
    }
    pkt->len = buf->len = HEADER_LEN;
    return DISCOVERY_ERR_SUCCESS;
}

static int32_t CoapCreateHeader(CoapPacket *pkt, const CoapPacketParam *pktParam, CoapReadWriteBuffer *buf)
{
    int32_t ret = CoapCreateHeaderEx(pkt, pktParam, buf);
    if (ret != DISCOVERY_ERR_SUCCESS) {
        IncStatistics(STATS_CREATE_HEADER_FAILED);
    }
    return ret;
}

static int32_t CoapAddData(CoapPacket *pkt, const CoapBuffer *payload, CoapReadWriteBuffer *buf)
{
    if ((payload->len == 0) && (payload->buffer == NULL)) {
        DFINDER_LOGE(TAG, "CoapAddData invalid argument");
        return DISCOVERY_ERR_INVALID_ARGUMENT;
    }

    if (buf->len < HEADER_LEN) {
        DFINDER_LOGE(TAG, "CoapAddData buf invalid argument");
        return DISCOVERY_ERR_INVALID_ARGUMENT;
    }

    if ((payload->len > 0xFFFF) || (buf->len + payload->len + 1) > buf->size) {
        DFINDER_LOGE(TAG, "CoapAddData exceed max pdu");
        return DISCOVERY_ERR_PKT_EXCEED_MAX_PDU;
    }

    pkt->payload.len = payload->len;
    if (payload->len != 0) {
        pkt->payload.len = payload->len;
        buf->readWriteBuf[buf->len] = 0xFF;
        (buf->len)++;
        pkt->payload.buffer = (const uint8_t *)&buf->readWriteBuf[buf->len];
        if (memcpy_s(&buf->readWriteBuf[buf->len], buf->size - buf->len, payload->buffer, payload->len) != EOK) {
            DFINDER_LOGE(TAG, "CoapAddData memcpy fail");
            return DISCOVERY_ERR_INVALID_ARGUMENT;
        }
    }

    buf->len += payload->len;
    pkt->len = buf->len;

    return DISCOVERY_ERR_SUCCESS;
}

static void CoapGetOptionParam(uint16_t value, uint8_t *param)
{
    if (value < COAP_LOW_DELTA_NUM) {
        *param = (uint8_t)(value & 0xFF);
        return;
    }

    if (value < (COAP_LOW_DELTA_NUM + COAP_MID_DELTA_NUM)) {
        *param = COAP_EXTEND_DELTA_VALUE_UINT8;
        return;
    }

    *param = COAP_EXTEND_DELTA_VALUE_UINT16;
    return;
}

static uint16_t CoapGetOptionLength(const CoapOption *opt, uint16_t runningDelta)
{
    uint16_t optionLen = 1;
    uint8_t delta = 0;
    uint8_t len = 0;

    CoapGetOptionParam((uint16_t)(opt->num - runningDelta), &delta);
    if (delta == COAP_EXTEND_DELTA_VALUE_UINT8) {
        optionLen += 1;
    } else if (delta == COAP_EXTEND_DELTA_VALUE_UINT16) {
        optionLen += BUF_OFFSET_BYTE2;
    }

    CoapGetOptionParam((uint16_t)opt->len, &len);
    if (len == COAP_EXTEND_DELTA_VALUE_UINT8) {
        optionLen += 1;
    } else if (len == COAP_EXTEND_DELTA_VALUE_UINT16) {
        optionLen += BUF_OFFSET_BYTE2;
    }

    return optionLen + opt->len;
}

static int32_t CoapCheckOption(const CoapPacket *pkt, const CoapOption *option, const CoapReadWriteBuffer *buf)
{
    uint16_t optionLen;
    uint16_t runningDelta = 0;

    if (buf->len < HEADER_LEN) {
        DFINDER_LOGE(TAG, "CoapCheckOption buf invalid argument");
        return DISCOVERY_ERR_INVALID_ARGUMENT;
    }

    if ((option->optionBuf == NULL) && (option->len != 0)) {
        DFINDER_LOGE(TAG, "CoapCheckOption invalid argument");
        return DISCOVERY_ERR_INVALID_ARGUMENT;
    }

    if ((option->len > 0xFFFF) || (pkt->optionsNum >= COAP_MAX_OPTION)) {
        DFINDER_LOGE(TAG, "CoapCheckOption bad req");
        return DISCOVERY_ERR_BAD_REQ;
    }

    if (pkt->optionsNum != 0) {
        runningDelta = pkt->options[pkt->optionsNum - 1].num;
    }

    optionLen = CoapGetOptionLength(option, runningDelta);
    if ((buf->len + optionLen) > buf->size) {
        DFINDER_LOGE(TAG, "CoapCheckOption exceed max pdu");
        return DISCOVERY_ERR_PKT_EXCEED_MAX_PDU;
    }

    return DISCOVERY_ERR_SUCCESS;
}

static int32_t CoapAddOption(CoapPacket *pkt, const CoapOption *option, CoapReadWriteBuffer *buf)
{
    uint8_t delta;
    uint8_t len;
    uint16_t optionDelta;
    uint16_t prevOptionNum;

    if (CoapCheckOption(pkt, option, buf) != DISCOVERY_ERR_SUCCESS) {
        DFINDER_LOGE(TAG, "CoapAddOption invalid argument");
        return DISCOVERY_ERR_INVALID_ARGUMENT;
    }

    prevOptionNum = 0;
    if (pkt->optionsNum != 0) {
        prevOptionNum = pkt->options[pkt->optionsNum - 1].num;
    }
    optionDelta = option->num - prevOptionNum;
    CoapGetOptionParam(optionDelta, &delta);
    CoapGetOptionParam(option->len, &len);

    buf->readWriteBuf[buf->len++] = (char)(((delta << COAP_SHIFT_BIT4) | len) & 0xFF);
    if (delta == COAP_EXTEND_DELTA_VALUE_UINT8) {
        buf->readWriteBuf[buf->len++] = (char)(optionDelta - COAP_LOW_DELTA_NUM);
    } else if (delta == COAP_EXTEND_DELTA_VALUE_UINT16) {
        buf->readWriteBuf[buf->len++] = (char)((optionDelta - (COAP_LOW_DELTA_NUM + COAP_MID_DELTA_NUM))
                                                >> COAP_SHIFT_BIT8);
        buf->readWriteBuf[buf->len++] = (char)((optionDelta - (COAP_LOW_DELTA_NUM + COAP_MID_DELTA_NUM)) & 0xFF);
    }

    if (len == COAP_EXTEND_DELTA_VALUE_UINT8) {
        buf->readWriteBuf[buf->len++] = (char)(option->len - COAP_LOW_DELTA_NUM);
    } else if (len == COAP_EXTEND_DELTA_VALUE_UINT16) {
        buf->readWriteBuf[buf->len++] = (char)((option->len - (COAP_LOW_DELTA_NUM + COAP_MID_DELTA_NUM))
                                                >> COAP_SHIFT_BIT8);
        buf->readWriteBuf[buf->len++] = (char)((option->len - (COAP_LOW_DELTA_NUM + COAP_MID_DELTA_NUM)) & 0xFF);
    }

    if (option->len != 0) {
        if (memcpy_s(&buf->readWriteBuf[buf->len], buf->size - buf->len, option->optionBuf, option->len) != EOK) {
            DFINDER_LOGE(TAG, "CoapAddOption memcpy fail");
            return DISCOVERY_ERR_OPT_INVALID_BIG;
        }
    }

    pkt->options[pkt->optionsNum].optionBuf = (const uint8_t *)&buf->readWriteBuf[buf->len];
    pkt->options[pkt->optionsNum].num = option->num;
    pkt->options[pkt->optionsNum].len = option->len;

    buf->len += option->len;
    pkt->len = buf->len;
    pkt->optionsNum++;

    return DISCOVERY_ERR_SUCCESS;
}

static int32_t CoapAddToken(CoapPacket *pkt, const CoapBuffer *token, CoapReadWriteBuffer *buf)
{
    if ((token->len != 0) && (token->buffer == NULL)) {
        DFINDER_LOGE(TAG, "CoapAddToken token invalid argument");
        return DISCOVERY_ERR_INVALID_ARGUMENT;
    }

    if (buf->len != HEADER_LEN) {
        DFINDER_LOGE(TAG, "CoapAddToken buf invalid argument");
        return DISCOVERY_ERR_INVALID_ARGUMENT;
    }

    if (token->len > MAX_TOK_LEN)  {
        DFINDER_LOGE(TAG, "CoapAddToken token too long");
        return DISCOVERY_ERR_INVALID_TOKEN_LEN;
    }

    if ((buf->len + token->len) > buf->size) {
        DFINDER_LOGE(TAG, "CoapAddToken exceed max pdu");
        return DISCOVERY_ERR_PKT_EXCEED_MAX_PDU;
    }

    pkt->token.len = token->len;
    pkt->header.tokenLen = pkt->token.len & 0x0F;
    pkt->token.buffer = (const uint8_t *)&buf->readWriteBuf[buf->len];
    if (token->len != 0)  {
        if (pkt->protocol == COAP_UDP) {
            buf->readWriteBuf[0] = (char)((uint8_t)buf->readWriteBuf[0] | token->len);
        } else {
            buf->readWriteBuf[BUF_OFFSET_BYTE2] = (char)((uint8_t)buf->readWriteBuf[BUF_OFFSET_BYTE2] | token->len);
        }

        if (memcpy_s(&buf->readWriteBuf[buf->len], buf->size - buf->len, token->buffer, pkt->header.tokenLen) != EOK) {
            DFINDER_LOGE(TAG, "CoapAddToken memcpy fail");
            return DISCOVERY_ERR_INVALID_ARGUMENT;
        }
    }
    buf->len += token->len;
    pkt->len = buf->len;

    return DISCOVERY_ERR_SUCCESS;
}

static int32_t CoapCreateBody(CoapPacket *pkt, const CoapPacketParam *param, const CoapBuffer *token,
    const CoapBuffer *payload, CoapReadWriteBuffer *buf)
{
    int32_t i;
    int32_t ret;

    if (token != NULL) {
        ret = CoapAddToken(pkt, token, buf);
        if (ret != DISCOVERY_ERR_SUCCESS) {
            return ret;
        }
    }

    if (param->options != 0) {
        if (param->optionsNum > COAP_MAX_OPTION) {
            DFINDER_LOGE(TAG, "CoapCreateBody server error");
            return DISCOVERY_ERR_SERVER_ERR;
        }

        for (i = 0; i < param->optionsNum; i++) {
            ret = CoapAddOption(pkt, &param->options[i], buf);
            if (ret != DISCOVERY_ERR_SUCCESS) {
                return ret;
            }
        }
    }

    if (payload != NULL) {
        ret = CoapAddData(pkt, payload, buf);
        if (ret != DISCOVERY_ERR_SUCCESS) {
            return ret;
        }
    }

    return DISCOVERY_ERR_SUCCESS;
}

static int32_t CoapSoftBusEncodeEx(CoapPacket *pkt, const CoapPacketParam *param, const CoapBuffer *payload,
    CoapReadWriteBuffer *buf)
{
    int32_t ret;

    if (pkt == NULL || param == NULL || buf == NULL || buf->readWriteBuf == NULL) {
        DFINDER_LOGE(TAG, "CoapSoftBusEncode invalid");
        return DISCOVERY_ERR_INVALID_EMPTY_MSG;
    }

    ret = CoapCreateHeader(pkt, param, buf);
    if (ret != DISCOVERY_ERR_SUCCESS) {
        return ret;
    }

    if ((param->code == 0) && ((param->options != NULL) || (payload != NULL))) {
        DFINDER_LOGE(TAG, "CoapSoftBusEncode empty msg");
        return DISCOVERY_ERR_INVALID_EMPTY_MSG;
    }

    ret = CoapCreateBody(pkt, param, NULL, payload, buf);
    if (ret != DISCOVERY_ERR_SUCCESS) {
        return ret;
    }

    return DISCOVERY_ERR_SUCCESS;
}

static int32_t CoapSoftBusEncode(CoapPacket *pkt, const CoapPacketParam *param, const CoapBuffer *payload,
    CoapReadWriteBuffer *buf)
{
    int32_t ret = CoapSoftBusEncodeEx(pkt, param, payload, buf);
    if (ret != DISCOVERY_ERR_SUCCESS) {
        IncStatistics(STATS_ENCODE_FAILED);
    }
    return ret;
}

void CoapSoftBusInitMsgId(void)
{
    g_msgId = (uint16_t)(RAND_DIVISOR);
}

uint16_t CoapSoftBusMsgId(void)
{
    if (++g_msgId == 0) {
        g_msgId++;
    }
    return g_msgId;
}

static int32_t CoapSoftBusBuildMessage(const CoapResponseInfo *resqInfo, CoapReadWriteBuffer *sndPktBuff)
{
    if (resqInfo == NULL || resqInfo->pkt == NULL || resqInfo->param == NULL || sndPktBuff->readWriteBuf == NULL ||
        resqInfo->payloadLen >= sndPktBuff->size) {
        return DISCOVERY_ERR_BAD_REQ;
    }

    int32_t ret;
    CoapReadWriteBuffer outBuf;
    CoapBuffer inPayload;
    (void)memset_s(&outBuf, sizeof(CoapReadWriteBuffer), 0, sizeof(CoapReadWriteBuffer));
    (void)memset_s(&inPayload, sizeof(CoapBuffer), 0, sizeof(CoapBuffer));
    outBuf.readWriteBuf = sndPktBuff->readWriteBuf;
    outBuf.size = sndPktBuff->size;
    inPayload.buffer = resqInfo->payload;
    inPayload.len = resqInfo->payloadLen;

    if ((resqInfo->payload == NULL) || (resqInfo->payloadLen == 0)) {
        ret = CoapSoftBusEncode(resqInfo->pkt, resqInfo->param, NULL, &outBuf);
    } else {
        ret = CoapSoftBusEncode(resqInfo->pkt, resqInfo->param, &inPayload, &outBuf);
    }

    if (ret != DISCOVERY_ERR_SUCCESS) {
        return DISCOVERY_ERR_BAD_REQ;
    }

    sndPktBuff->len = outBuf.len;
    return ret;
}

static void BuildCoapPktParam(const CoapBuildParam *buildParam, CoapPacketParam *outParam)
{
    outParam->protocol = COAP_UDP;
    outParam->options[outParam->optionsNum].num = DISCOVERY_MSG_URI_HOST;
    outParam->options[outParam->optionsNum].optionBuf = (uint8_t *)(buildParam->remoteIp);
    outParam->options[outParam->optionsNum].len = strlen(buildParam->remoteIp);
    outParam->optionsNum++;

    outParam->options[outParam->optionsNum].num = DISCOVERY_MSG_URI_PATH;
    outParam->options[outParam->optionsNum].optionBuf = (uint8_t *)(buildParam->uriPath);
    outParam->options[outParam->optionsNum].len = strlen(buildParam->uriPath);
    outParam->optionsNum++;

    outParam->type = buildParam->msgType;
    outParam->code = buildParam->methodType;
    outParam->msgId = buildParam->msgId;
}

static int32_t BuildCoapPktEx(const CoapBuildParam *param, const char *pktPayload,
    CoapReadWriteBuffer *sndPktBuff, bool isAck)
{
    if (param == NULL || sndPktBuff == NULL || sndPktBuff->readWriteBuf == NULL) {
        DFINDER_LOGE(TAG, "BuildCoapPkt invalid");
        return DISCOVERY_ERR_BAD_REQ;
    }

    if (!isAck && (pktPayload == NULL)) {
        DFINDER_LOGE(TAG, "BuildCoapPkt bad req");
        return DISCOVERY_ERR_BAD_REQ;
    }

    CoapOption options[COAP_MAX_OPTION] = {0};
    CoapPacketParam outParam = {0};
    outParam.options = options;
    BuildCoapPktParam(param, &outParam);

    CoapPacket respPkt = {0};
    if (isAck) {
        if (CoapCreateHeader(&respPkt, &outParam, sndPktBuff) != DISCOVERY_ERR_SUCCESS) {
            return DISCOVERY_ERR_BAD_REQ;
        }
    } else {
        CoapResponseInfo respInfo = {0};
        respInfo.pkt = &respPkt;
        respInfo.param = &outParam;
        respInfo.payload = (uint8_t *)pktPayload;
        respInfo.payloadLen = strlen(pktPayload) + 1;

        if (CoapSoftBusBuildMessage(&respInfo, sndPktBuff) != DISCOVERY_ERR_SUCCESS) {
            return DISCOVERY_ERR_BAD_REQ;
        }
    }

    if (sndPktBuff->len >= sndPktBuff->size) {
        DFINDER_LOGE(TAG, "BuildCoapPkt snd pkt buff too long");
        return DISCOVERY_ERR_BAD_REQ;
    }

    return DISCOVERY_ERR_SUCCESS;
}

int32_t BuildCoapPkt(const CoapBuildParam *param, const char *pktPayload, CoapReadWriteBuffer *sndPktBuff, bool isAck)
{
    int32_t ret = BuildCoapPktEx(param, pktPayload, sndPktBuff, isAck);
    if (ret != DISCOVERY_ERR_SUCCESS) {
        IncStatistics(STATS_BUILD_PKT_FAILED);
    }
    return ret;
}
