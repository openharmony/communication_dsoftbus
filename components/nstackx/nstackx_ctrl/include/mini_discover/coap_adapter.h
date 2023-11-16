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

#ifndef COAP_ADAPTER_H
#define COAP_ADAPTER_H

#include <stdbool.h>

#include "coap_def.h"

#ifdef __cplusplus
extern "C" {
#endif

#define COAP_VERSION 1
#define DEFAULT_TOK_LEN 0
#define MAX_TOK_LEN 8
#define HEADER_LEN 4
#define COAP_MAX_PDU_SIZE 1024

typedef struct {
    enum CoapProtocolTypeEnum protocol;
    enum CoapMsgTypeEnum type;
    uint8_t code;
    uint8_t optionsNum;
    uint16_t msgId;
    CoapOption *options;
} CoapPacketParam;

typedef struct {
    char *readWriteBuf;
    uint32_t len;
    uint32_t size;
} CoapReadWriteBuffer;

typedef struct {
    char *remoteIp;
    char *uriPath;
    CoapMsgTypeEnum msgType;
    CoapMethodTypeEnum methodType;
    uint16_t msgId;
} CoapBuildParam;

enum ErrorTypeEnum {
    DISCOVERY_ERR_SUCCESS                      = 0,
    DISCOVERY_ERR_HEADER_INVALID_SHORT         = 1,
    DISCOVERY_ERR_VER_INVALID                  = 2,
    DISCOVERY_ERR_TOKEN_INVALID_SHORT          = 3,
    DISCOVERY_ERR_OPT_INVALID_SHORT_FOR_HEADER = 4,
    DISCOVERY_ERR_OPT_INVALID_SHORT            = 5,
    DISCOVERY_ERR_OPT_OVERRUNS_PKT             = 6,
    DISCOVERY_ERR_OPT_INVALID_BIG              = 7,
    DISCOVERY_ERR_OPT_INVALID_LEN              = 8,
    DISCOVERY_ERR_BUF_INVALID_SMALL            = 9,
    DISCOVERY_ERR_NOT_SUPPORTED                = 10,
    DISCOVERY_ERR_OPT_INVALID_DELTA            = 11,
    DISCOVERY_ERR_PKT_EXCEED_MAX_PDU           = 12,
    DISCOVERY_ERR_TCP_TYPE_INVALID             = 13,
    DISCOVERY_ERR_UNKNOWN_MSG_TYPE             = 14,
    DISCOVERY_ERR_INVALID_PKT                  = 15,
    DISCOVERY_ERR_INVALID_TOKEN_LEN            = 16,
    DISCOVERY_ERR_INVALID_ARGUMENT             = 17,
    DISCOVERY_ERR_TRANSPORT_NOT_UDP_OR_TCP     = 18,
    DISCOVERY_ERR_INVALID_EMPTY_MSG            = 19,
    DISCOVERY_ERR_SERVER_ERR                   = 20,
    DISCOVERY_ERR_BAD_REQ                      = 21,
    DISCOVERY_ERR_UNKNOWN_METHOD               = 22,
    DISCOVERY_ERR_BLOCK_NO_PAYLOAD             = 23
};

int32_t CoapSoftBusDecode(CoapPacket *pkt, const uint8_t *buf, uint32_t bufLen);
int32_t BuildCoapPkt(const CoapBuildParam *param, const char *pktPayload, CoapReadWriteBuffer *sndPktBuff, bool isAck);
void CoapSoftBusInitMsgId(void);
uint16_t CoapSoftBusMsgId(void);

#ifdef __cplusplus
}
#endif

#endif /* COAP_ADAPTER_H */
