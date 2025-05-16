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
#ifndef SOFTBUS_CONN_GENERAL_NEGOATION_H
#define SOFTBUS_CONN_GENERAL_NEGOATION_H

#include "softbus_common.h"
#include "softbus_conn_common.h"
#include "softbus_conn_interface.h"
#include "softbus_utils.h"

#include "stdint.h"
#ifdef __cplusplus
extern "C" {
#endif

#define GENERAL_NAME_LEN (30)
#define BUNDLE_NAME_MAX (256)

typedef enum {
    GENERAL_CONNECTION_MSG_TYPE_HANDSHAKE = 0,
    GENERAL_CONNECTION_MSG_TYPE_HANDSHAKE_ACK,
    GENERAL_CONNECTION_MSG_TYPE_RESET,
    GENERAL_CONNECTION_MSG_TYPE_MERGE,
    GENERAL_CONNECTION_MSG_TYPE_NORMAL = 12,
    GENERAL_CONNECTION_MSG_TYPE_MAX = 22,
} GeneralConnectionMsgType;
typedef struct {
    int32_t msgType;
    int32_t localId;
    int32_t peerId;
    int32_t headLen;
} GeneralConnectionHead;

typedef uint32_t GeneralConnAbilityBitSet;
static const size_t GENERAL_CONNECTION_HEADER_SIZE = sizeof(GeneralConnectionHead);

typedef struct {
    char name[GENERAL_NAME_LEN];
    char bundleName[BUNDLE_NAME_MAX];
    GeneralConnAbilityBitSet abilityBitSet;
    uint32_t peerId;
    uint32_t localId;
    int32_t  ackStatus;
    uint32_t updateHandle;
} GeneralConnectionInfo;

typedef struct {
    uint8_t *data;
    uint32_t dataLen;
} OutData;

OutData *GeneralConnectionPackMsg(GeneralConnectionInfo *info, GeneralConnectionMsgType msgType);
int32_t GeneralConnectionUnpackMsg(const uint8_t *data, uint32_t dataLen, GeneralConnectionInfo *info,
    GeneralConnectionMsgType parseMsgType);
void FreeOutData(OutData *outData);
#ifdef __cplusplus
}
#endif /* _cplusplus */
#endif /* SOFTBUS_CONN_GENERAL_NEGOATION_H */