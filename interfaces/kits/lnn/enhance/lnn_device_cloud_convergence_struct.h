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

#ifndef LNN_DEVICE_CLOUD_CONVERGENCE_STRUCT_H
#define LNN_DEVICE_CLOUD_CONVERGENCE_STRUCT_H

#define MAX_UDID_NUM 50

#define MAX_MSG_LEN 1300
#define FRAGMENT_HEADER_LEN 16
#define FAR_FIELD_PKT_HEAD_SIZE 12
#define MAX_SLICE_LEN  (MAX_MSG_LEN - FRAGMENT_HEADER_LEN - FAR_FIELD_PKT_HEAD_SIZE)
#define PRIMARY_USER_ID  100

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    CONVERSATION_FAR_FIELD_PUSH = 0,
    CONVERSATION_FAR_FIELD_P2P,
    CONVERSATION_NEAR_FIELD_WIFI_DIRECT,
    CONVERSATION_MAX,
} ConversationChannelType;

typedef void (*FragmentRecvCallback)(const char *udid, const char *data,
    uint32_t dataLen, ConversationChannelType channelType, uint32_t businessType);

typedef struct {
    uint8_t *buffer;
    uint32_t bufferLen;
} BufferInfo;

typedef struct {
    const char *msg;
    uint32_t msgLen;
    uint32_t businessType;
} InputMsg;

typedef struct {
    uint8_t *data;
    uint32_t len;
} OutputData;

typedef void(*LnnCloudHandler)(const void *obj);
typedef int32_t(*LnnCloudRemoveCompareFunc)(const void *obj, void *param);

typedef enum {
    MSG_TYPE_SOCKET_TIMEOUT,
    MSG_TYPE_HML_TIMEOUT,
    MSG_TYPE_DELAY_DISCONNECT,
    MSG_TYPE_DELAY_CLOSE_NETWORK,
} LnnCloudMsgType;

typedef struct {
    LnnCloudMsgType msgType;
    LnnCloudRemoveCompareFunc cmpFunc;
    void *param;
} LnnCloudRemoveInfo;

#ifdef __cplusplus
}
#endif
#endif /* LNN_DEVICE_CLOUD_CONVERGENCE_STRUCT_H */