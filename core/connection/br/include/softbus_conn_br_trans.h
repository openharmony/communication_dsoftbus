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

#ifndef CONN_BR_TRANS_H
#define CONN_BR_TRANS_H

#include "cJSON.h"

#include "softbus_conn_br_manager.h"
#include "softbus_conn_common.h"
#include "wrapper_br_interface.h"

#ifdef __cplusplus
extern "C" {
#endif

#define KEY_METHOD        "KEY_METHOD"
#define KEY_DELTA         "KEY_DELTA"
#define KEY_REFERENCE_NUM "KEY_REFERENCE_NUM"
#define KEY_WINDOWS       "KEY_WINDOWS"
#define KEY_ACK_SEQ_NUM   "KEY_ACK_SEQ_NUM"

#define MIN_WINDOW             10
#define MAX_WINDOW             80
#define DEFAULT_WINDOW         20
#define ACK_FAILED_TIMES       3
#define WAIT_ACK_TIMEOUT_MILLS 100
#define TIMEOUT_TIMES          2

enum BrCtlMessageMethod {
    BR_METHOD_NOTIFY_REQUEST = 1,
    BR_METHOD_NOTIFY_RESPONSE = 2,
    BR_METHOD_NOTIFY_ACK = 4,
    BR_METHOD_ACK_RESPONSE = 5,
};

typedef struct {
    SoftBusMutex lock;
    bool messagePosted;
    bool sendTaskRunning;
} StartBrSendLPInfo;


typedef struct {
    uint32_t connectionId;
    int32_t flag;
    enum BrCtlMessageMethod method;
    union {
        struct {
            int32_t delta;
            int32_t referenceNumber;
        } referenceRequest;
        struct {
            int32_t referenceNumber;
        } referenceResponse;
        struct {
            int32_t window;
            int64_t seq;
        } ackRequestResponse;
    };
} BrCtlMessageSerializationContext;

typedef struct {
    void (*onPostByteFinshed)(
        uint32_t connectionId, uint32_t len, int32_t pid, int32_t flag, int32_t module, int64_t seq, int32_t error);
} ConnBrTransEventListener;

int32_t ConnBrTransReadOneFrame(uint32_t connectionId, int32_t socketHandle, LimitedBuffer *buffer, uint8_t **outData);
int32_t BrTransSend(uint32_t connectionId, int32_t socketHandle, uint32_t mtu, const uint8_t *data, uint32_t dataLen);
int64_t ConnBrPackCtlMessage(BrCtlMessageSerializationContext ctx, uint8_t **outData, uint32_t *outLen);
int32_t ConnBrPostBytes(
    uint32_t connectionId, uint8_t *data, uint32_t len, int32_t pid, int32_t flag, int32_t module, int64_t seq);
int32_t ConnBrTransConfigPostLimit(const LimitConfiguration *configuration);

int32_t ConnBrTransMuduleInit(SppSocketDriver *sppDriver, ConnBrTransEventListener *listener);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* CONN_BR_TRANS_H */