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

#ifndef COAP_DEF_H
#define COAP_DEF_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define COAP_MAX_OPTION 16
#define DISCOVERY_MSG_URI_HOST 3
#define DISCOVERY_MSG_URI_PATH 11

#define COAP_RESPONSE_CODE(N) ((((N) / 100) << 5) | ((N) % 100))

enum CoapProtocolTypeEnum {
    COAP_UDP = 0,
    COAP_TCP
};

typedef enum CoapMethodTypeEnum {
    COAP_METHOD_GET = 1,
    COAP_METHOD_POST = 2,
    COAP_METHOD_PUT = 3,
    COAP_METHOD_DELETE = 4,
    COAP_RESPONSE_201 = 201
} CoapMethodTypeEnum;

typedef enum CoapMsgTypeEnum {
    COAP_TYPE_CON = 0,
    COAP_TYPE_NONCON = 1,
    COAP_TYPE_ACK = 2,
    COAP_TYPE_RESET = 3
} CoapMsgTypeEnum;

typedef struct {
    uint32_t ver : 2;
    uint32_t type : 2;
    uint32_t tokenLen : 4;
    uint32_t code : 8;
    union {
        uint16_t msgLen;
        uint16_t msgId;
    } varSection;
} CoapHeader;

typedef struct {
    const uint8_t *buffer;
    uint32_t len;
} CoapBuffer;

typedef struct {
    const uint8_t *optionBuf;
    uint32_t len;
    uint16_t num;
} CoapOption;

typedef struct {
    enum CoapProtocolTypeEnum protocol;
    uint32_t len;
    CoapHeader header;
    CoapBuffer token;
    uint8_t optionsNum;
    CoapOption options[COAP_MAX_OPTION];
    CoapBuffer payload;
} CoapPacket;

#ifdef __cplusplus
}
#endif

#endif /* COAP_DEF_H */
