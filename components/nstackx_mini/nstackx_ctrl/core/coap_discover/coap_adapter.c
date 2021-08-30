/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "coap_adapter.h"
#include "securec.h"

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

typedef struct {
    CoapPacket *pkt;
    CoapPacketParam *param;
    const uint8_t *payload;
    unsigned long payloadLen;
} CoapResponseInfo;

static uint16_t g_msgId = 0;

static int CoapParseOptionExtension(uint16_t *value, const uint8_t **dataPos, uint8_t *headerLen,
    uint32_t bufLen)
{
    if (*value == COAP_EXTEND_DELTA_VALUE_UINT8) {
        (*headerLen)++;
        if (bufLen < *headerLen) {
            return DISCOVERY_ERR_OPT_INVALID_SHORT_FOR_HEADER;
        }

        *value = (uint16_t)((*dataPos)[1] + COAP_LOW_DELTA_NUM);
        (*dataPos)++;
        return DISCOVERY_ERR_SUCCESS;
    }

    if (*value == COAP_EXTEND_DELTA_VALUE_UINT16) {
        *headerLen = (uint8_t)(*headerLen + COAP_OPTION_EXTENSION_LEN);
        if (bufLen < *headerLen) {
            return DISCOVERY_ERR_OPT_INVALID_SHORT_FOR_HEADER;
        }

        uint16_t optionDeltaValue = (uint16_t)((*dataPos)[1] << COAP_SHIFT_BIT8) |
            (*dataPos)[COAP_OPTION_EXTENSION_LEN];
        if (optionDeltaValue > (0xFFFF - COAP_LOW_DELTA_NUM - COAP_MID_DELTA_NUM)) {
            return DISCOVERY_ERR_BAD_REQ;
        }

        *value = (uint16_t)(optionDeltaValue + COAP_LOW_DELTA_NUM + COAP_MID_DELTA_NUM);
        (*dataPos) += COAP_OPTION_EXTENSION_LEN;
        return DISCOVERY_ERR_SUCCESS;
    }

    if (*value == COAP_EXTEND_DELTA_VALUE_INVALID) {
        return DISCOVERY_ERR_OPT_INVALID_DELTA;
    }

    return DISCOVERY_ERR_SUCCESS;
}

static int CoapParseOption(CoapOption *option, uint16_t *runningDelta, const uint8_t **buf,
    uint32_t bufLen)
{
    const uint8_t *dataPos = NULL;
    uint8_t headLen;
    uint16_t len;
    uint16_t delta;
    int ret;

    if (bufLen < 1)  {
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
        return DISCOVERY_ERR_OPT_INVALID_BIG;
    }

    option->num = (uint16_t)(delta + *runningDelta);
    option->optionBuf = dataPos + 1;
    option->len = len;

    *buf = dataPos + 1 + len;
    *runningDelta = (uint16_t)(*runningDelta + delta);
    return DISCOVERY_ERR_SUCCESS;
}

static int CoapParseOptionsAndPayload(CoapPacket *pkt, const uint8_t *buf,
    uint32_t buflen)
{
    uint8_t optionIndex = 0;
    uint16_t delta = 0;
    const uint8_t *dataPos = buf + HEADER_LEN + pkt->header.tokenLen;
    const uint8_t *end = buf + buflen;

    if (dataPos > end) {
        return DISCOVERY_ERR_OPT_OVERRUNS_PKT;
    }

    while ((dataPos < end) && (*dataPos != 0xFF) && (optionIndex < COAP_MAX_OPTION)) {
        int ret = CoapParseOption(&((pkt->options)[optionIndex]), &delta, &dataPos, end - dataPos);
        if (ret != DISCOVERY_ERR_SUCCESS) {
            return ret;
        }
        optionIndex++;
    }

    if ((dataPos < end) && (*dataPos != 0xFF) && (optionIndex >= COAP_MAX_OPTION)) {
        return DISCOVERY_ERR_SERVER_ERR;
    }
    pkt->optionsNum = optionIndex;
    if ((dataPos < end) && (*dataPos != 0xFF)) {
        pkt->payload.buffer = NULL;
        pkt->payload.len = 0;
        return DISCOVERY_ERR_SUCCESS;
    }

    if (dataPos + 1 >= end) {
        return DISCOVERY_ERR_INVALID_PKT;
    }

    pkt->payload.buffer = dataPos + 1;
    pkt->payload.len = (uint32_t)(long)(end - (dataPos + 1));
    return DISCOVERY_ERR_SUCCESS;
}

static int CoapParseHeader(CoapPacket *pkt, const uint8_t *buf, uint32_t bufLen)
{
    if (bufLen < HEADER_LEN) {
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

int CoapSoftBusDecode(CoapPacket *pkt, const uint8_t *buf, uint32_t bufLen)
{
    int ret;
    if (pkt == NULL || buf == NULL) {
        return -1;
    }

    if (bufLen == 0) {
        return -1;
    }

    if (pkt->protocol != COAP_UDP) {
        return -1;
    }

    ret = CoapParseHeader(pkt, buf, bufLen);
    if (ret != DISCOVERY_ERR_SUCCESS) {
        return ret;
    }

    if (pkt->header.ver != COAP_VERSION) {
        return DISCOVERY_ERR_VER_INVALID;
    }

    if (pkt->header.tokenLen > MAX_TOK_LEN) {
        return DISCOVERY_ERR_INVALID_TOKEN_LEN;
    }

    if ((bufLen > HEADER_LEN) && (pkt->header.code == 0)) {
        return DISCOVERY_ERR_INVALID_EMPTY_MSG;
    }

    if (pkt->header.tokenLen == 0) {
        pkt->token.buffer = NULL;
        pkt->token.len = 0;
    } else if ((uint32_t)(pkt->header.tokenLen + HEADER_LEN) > bufLen) {
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

static int CoapCreateHeader(CoapPacket *pkt, const CoapPacketParam *pktParam, CoapReadWriteBuffer *buf)
{
    if (buf->len != 0) {
        return DISCOVERY_ERR_INVALID_ARGUMENT;
    }

    if ((pktParam->protocol != COAP_UDP) && (pktParam->protocol != COAP_TCP)) {
        return DISCOVERY_ERR_TRANSPORT_NOT_UDP_OR_TCP;
    }
    pkt->protocol = pktParam->protocol;

    if (pktParam->type > COAP_TYPE_RESET) {
        return DISCOVERY_ERR_UNKNOWN_MSG_TYPE;
    }

    if (buf->size < HEADER_LEN) {
        return DISCOVERY_ERR_PKT_EXCEED_MAX_PDU;
    }

    pkt->header.type = (uint32_t)pktParam->type & 0x03;
    pkt->header.ver = COAP_VERSION;
    pkt->header.code = pktParam->code;

    if (pkt->protocol == COAP_UDP) {
        pkt->header.varSection.msgId = pktParam->msgId;
        buf->readWriteBuf[0] = (char)(pkt->header.ver << COAP_SHIFT_BIT6);
        buf->readWriteBuf[0] = (char)((uint8_t)buf->readWriteBuf[0] |
            (uint8_t)(pkt->header.type << COAP_SHIFT_BIT4));
        buf->readWriteBuf[1] = (char)pkt->header.code;
        buf->readWriteBuf[BUF_OFFSET_BYTE2] = (char)((pkt->header.varSection.msgId & 0xFF00) >> COAP_SHIFT_BIT8);
        buf->readWriteBuf[BUF_OFFSET_BYTE3] = (char)(pkt->header.varSection.msgId & 0x00FF);
    } else {
        return DISCOVERY_ERR_NOT_SUPPORTED;
    }
    pkt->len = buf->len = HEADER_LEN;
    return DISCOVERY_ERR_SUCCESS;
}

static int CoapAddData(CoapPacket *pkt, const CoapBuffer *payload, CoapReadWriteBuffer *buf)
{
    if ((payload->len == 0) && (payload->buffer == NULL)) {
        return DISCOVERY_ERR_INVALID_ARGUMENT;
    }

    if (buf->len < HEADER_LEN) {
        return DISCOVERY_ERR_INVALID_ARGUMENT;
    }

    if ((payload->len > 0xFFFF) || (buf->len + payload->len + 1) > buf->size) {
        return DISCOVERY_ERR_PKT_EXCEED_MAX_PDU;
    }

    pkt->payload.len = payload->len;
    if (payload->len != 0) {
        pkt->payload.len = payload->len;
        buf->readWriteBuf[buf->len] = 0xFF;
        (buf->len)++;
        pkt->payload.buffer = (const uint8_t *)&buf->readWriteBuf[buf->len];
        if (memcpy_s(&buf->readWriteBuf[buf->len], buf->size - buf->len, payload->buffer, payload->len) != EOK) {
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

static int CoapCheckOption(const CoapPacket *pkt, const CoapOption *option, const CoapReadWriteBuffer *buf)
{
    uint16_t optionLen;
    uint16_t runningDelta = 0;

    if (buf->len < HEADER_LEN) {
        return DISCOVERY_ERR_INVALID_ARGUMENT;
    }

    if ((option->optionBuf == NULL) && (option->len != 0)) {
        return DISCOVERY_ERR_INVALID_ARGUMENT;
    }

    if ((option->len > 0xFFFF) || (pkt->optionsNum >= COAP_MAX_OPTION)) {
        return DISCOVERY_ERR_BAD_REQ;
    }

    if (pkt->optionsNum != 0) {
        runningDelta = pkt->options[pkt->optionsNum - 1].num;
    }

    optionLen = CoapGetOptionLength(option, runningDelta);
    if ((buf->len + optionLen) > buf->size) {
        return DISCOVERY_ERR_PKT_EXCEED_MAX_PDU;
    }

    return DISCOVERY_ERR_SUCCESS;
}

static int CoapAddOption(CoapPacket *pkt, const CoapOption *option, CoapReadWriteBuffer *buf)
{
    uint8_t delta;
    uint8_t len;
    uint16_t optionDelta;
    uint16_t prevOptionNum;

    if (CoapCheckOption(pkt, option, buf) != DISCOVERY_ERR_SUCCESS) {
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

static int CoapAddToken(CoapPacket *pkt, const CoapBuffer *token, CoapReadWriteBuffer *buf)
{
    if ((token->len != 0) && (token->buffer == NULL)) {
        return DISCOVERY_ERR_INVALID_ARGUMENT;
    }

    if (buf->len != HEADER_LEN) {
        return DISCOVERY_ERR_INVALID_ARGUMENT;
    }

    if (token->len > MAX_TOK_LEN)  {
        return DISCOVERY_ERR_INVALID_TOKEN_LEN;
    }

    if ((buf->len + token->len) > buf->size) {
        return DISCOVERY_ERR_PKT_EXCEED_MAX_PDU;
    }

    pkt->token.len = token->len;
    pkt->header.tokenLen = pkt->token.len & 0x0F;
    pkt->token.buffer = (const uint8_t *)&buf->readWriteBuf[buf->len];
    if (token->len != 0)  {
        if (pkt->protocol == COAP_UDP) {
            buf->readWriteBuf[0] = (char)((uint8_t)buf->readWriteBuf[0] | token->len);
        } else {
            buf->readWriteBuf[BUF_OFFSET_BYTE2] = (char)((uint8_t)buf->readWriteBuf[BUF_OFFSET_BYTE2]
                                                  | token->len);
        }

        if (memcpy_s(&buf->readWriteBuf[buf->len], pkt->header.tokenLen, token->buffer, token->len) != EOK) {
            return DISCOVERY_ERR_INVALID_ARGUMENT;
        }
    }
    buf->len += token->len;
    pkt->len = buf->len;

    return DISCOVERY_ERR_SUCCESS;
}

static int CoapCreateBody(CoapPacket *pkt, const CoapPacketParam *param, const CoapBuffer *token,
    const CoapBuffer *payload, CoapReadWriteBuffer *buf)
{
    int i;
    int ret;

    if (token != NULL) {
        ret = CoapAddToken(pkt, token, buf);
        if (ret != DISCOVERY_ERR_SUCCESS) {
            return ret;
        }
    }

    if (param->options != 0) {
        if (param->optionsNum > COAP_MAX_OPTION) {
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

int CoapSoftBusEncode(CoapPacket *pkt, const CoapPacketParam *param, const CoapBuffer *token,
    const CoapBuffer *payload, CoapReadWriteBuffer *buf)
{
    int ret;

    if (pkt == NULL || param == NULL || buf == NULL || buf->readWriteBuf == NULL) {
        return DISCOVERY_ERR_INVALID_EMPTY_MSG;
    }

    ret = CoapCreateHeader(pkt, param, buf);
    if (ret != DISCOVERY_ERR_SUCCESS) {
        return ret;
    }

    if ((param->code == 0) && ((token != NULL) || (param->options != NULL) || (payload != NULL))) {
        return DISCOVERY_ERR_INVALID_EMPTY_MSG;
    }

    ret = CoapCreateBody(pkt, param, NULL, payload, buf);
    if (ret != DISCOVERY_ERR_SUCCESS) {
        return ret;
    }

    return DISCOVERY_ERR_SUCCESS;
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

static int CoapBuildResponseParam(const CoapPacket *req, const CoapResponseInfo *resqInfo, CoapBuffer *inToken)
{
    if (req == NULL || resqInfo == NULL) {
        return DISCOVERY_ERR_NOT_SUPPORTED;
    }
    inToken->buffer = req->token.buffer;
    inToken->len = req->token.len;
    resqInfo->param->protocol = req->protocol;
    resqInfo->param->type = COAP_TYPE_NONCON;
    resqInfo->param->code = (uint8_t)COAP_METHOD_POST;
    resqInfo->param->msgId = CoapSoftBusMsgId();
    return DISCOVERY_ERR_SUCCESS;
}

static int CoapSoftBusBuildMessage(const CoapPacket *req, const CoapResponseInfo *resqInfo,
    char *buf, uint32_t *len)
{
    int ret;
    CoapReadWriteBuffer outBuf;
    CoapBuffer inPayload;
    CoapBuffer inToken;

    if (resqInfo == NULL || resqInfo->pkt == NULL
        || resqInfo->param == NULL || buf == NULL
        || len == NULL) {
        return DISCOVERY_ERR_BAD_REQ;
    }

    if (*len == 0) {
        return DISCOVERY_ERR_BAD_REQ;
    }

    (void)memset_s(&outBuf, sizeof(CoapReadWriteBuffer), 0, sizeof(CoapReadWriteBuffer));
    (void)memset_s(&inPayload, sizeof(CoapBuffer), 0, sizeof(CoapBuffer));
    (void)memset_s(&inToken, sizeof(CoapBuffer), 0, sizeof(CoapBuffer));

    outBuf.readWriteBuf = buf;
    outBuf.size = *len;
    inPayload.buffer = resqInfo->payload;
    inPayload.len = resqInfo->payloadLen;
    if (resqInfo->payloadLen >= *len) {
        return DISCOVERY_ERR_BAD_REQ;
    }

    ret = CoapBuildResponseParam(req, resqInfo, &inToken);
    if (ret != DISCOVERY_ERR_SUCCESS) {
        return ret;
    }

    if ((resqInfo->payload == NULL) || (resqInfo->payloadLen == 0)) {
        ret = CoapSoftBusEncode(resqInfo->pkt, resqInfo->param, &inToken, NULL, &outBuf);
    } else {
        ret = CoapSoftBusEncode(resqInfo->pkt, resqInfo->param, &inToken, &inPayload, &outBuf);
    }

    if (ret != DISCOVERY_ERR_SUCCESS) {
        return DISCOVERY_ERR_BAD_REQ;
    }

    *len = outBuf.len;
    return ret;
}

int BuildSendPkt(const CoapPacket *pkt, const char *remoteIp, const char *pktPayload, CoapReadWriteBuffer *sndPktBuff)
{
    CoapPacket respPkt;
    CoapPacketParam respPktPara;
    CoapOption options[COAP_MAX_OPTION] = {0};

    if (pkt == NULL || remoteIp == NULL || pktPayload == NULL || sndPktBuff == NULL) {
        return DISCOVERY_ERR_BAD_REQ;
    }

    char *buf = sndPktBuff->readWriteBuf;
    uint32_t len = sndPktBuff->size;

    if (buf == NULL) {
        return DISCOVERY_ERR_BAD_REQ;
    }

    (void)memset_s(&respPkt, sizeof(CoapPacket), 0, sizeof(CoapPacket));
    (void)memset_s(&respPktPara, sizeof(CoapPacketParam), 0, sizeof(CoapPacketParam));
    respPktPara.options = options;
    respPktPara.options[respPktPara.optionsNum].num = DISCOVERY_MSG_URI_HOST;
    respPktPara.options[respPktPara.optionsNum].optionBuf = (uint8_t *)remoteIp;
    respPktPara.options[respPktPara.optionsNum].len = strlen(remoteIp);
    respPktPara.optionsNum++;

    respPktPara.options[respPktPara.optionsNum].num = DISCOVERY_MSG_URI_PATH;
    respPktPara.options[respPktPara.optionsNum].optionBuf = (uint8_t *)"device_discover";
    respPktPara.options[respPktPara.optionsNum].len = strlen("device_discover");
    respPktPara.optionsNum++;

    (void)memset_s(buf, COAP_MAX_PDU_SIZE, 0, COAP_MAX_PDU_SIZE);
    CoapResponseInfo respInfo = {&respPkt, &respPktPara, NULL, 0};
    respInfo.payload = (uint8_t *)pktPayload;
    respInfo.payloadLen = strlen(pktPayload) + 1;
    int ret = CoapSoftBusBuildMessage(pkt, &respInfo, buf, &len);
    if (ret != DISCOVERY_ERR_SUCCESS) {
        return DISCOVERY_ERR_BAD_REQ;
    }

    if (len >= sndPktBuff->size) {
        return DISCOVERY_ERR_BAD_REQ;
    }
    sndPktBuff->len = len;
    return DISCOVERY_ERR_SUCCESS;
}
