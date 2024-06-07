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

#ifndef SOFTBUS_CONN_BLE_TRANS_H
#define SOFTBUS_CONN_BLE_TRANS_H

#include <stdint.h>

#include "common_list.h"
#include "softbus_error_code.h"
#include "softbus_conn_common.h"
#include "softbus_conn_manager.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CTRL_MSG_KEY_METHOD            "KEY_METHOD"
#define CTRL_MSG_KEY_DELTA             "KEY_DELTA"
#define CTRL_MSG_KEY_REF_NUM           "KEY_REF_NUM"
#define CTRL_MSG_KEY_CHALLENGE         "KEY_CHALLENGE"
#define CTRL_MSG_METHOD_NOTIFY_REQUEST 1

typedef struct {
    SoftBusMutex lock;
    bool messagePosted;
    bool sendTaskRunning;
} StartBleSendLPInfo;

typedef struct {
    uint32_t seq;
    uint32_t size;
    uint32_t offset;
    uint32_t total;
} BleTransHeader;

typedef struct {
    ListNode node;
    BleTransHeader header;
    uint8_t *data;
} ConnBlePacket;

typedef struct {
    uint32_t seq;
    uint32_t received;
    uint32_t total;
    ListNode packets;
} ConnBleReadBuffer;

enum BleCtlMessageMethod {
    METHOD_NOTIFY_REQUEST = 1,
};

typedef struct {
    uint32_t connectionId;
    int32_t flag;
    enum BleCtlMessageMethod method;
    union {
        struct {
            int32_t delta;
            int32_t referenceNumber;
        } referenceRequest;
    };
    uint16_t challengeCode;
} BleCtlMessageSerializationContext;

typedef struct {
    void (*onPostBytesFinished)(
        uint32_t connectionId, uint32_t len, int32_t pid, int32_t flag, int32_t module, int64_t seq, int32_t error);
} ConnBleTransEventListener;

typedef void (*PostBytesFinishAction)(uint32_t connectionId, int32_t error);
int32_t ConnBlePostBytesInner(
    uint32_t connectionId, uint8_t *data, uint32_t len, int32_t pid, int32_t flag, int32_t module, int64_t seq,
    PostBytesFinishAction postBytesFinishAction);
uint8_t *ConnGattTransRecv(
    uint32_t connectionId, uint8_t *data, uint32_t dataLen, ConnBleReadBuffer *buffer, uint32_t *outLen);
uint8_t *ConnCocTransRecv(
    uint32_t connectionId, LimitedBuffer *buffer, int32_t *outLen);
int64_t ConnBlePackCtlMessage(BleCtlMessageSerializationContext ctx, uint8_t **outData, uint32_t *outLen);
int32_t ConnBleTransConfigPostLimit(const LimitConfiguration *configuration);

int32_t ConnBleInitTransModule(ConnBleTransEventListener *listener);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* SOFTBUS_CONN_BLE_TRANS_H */