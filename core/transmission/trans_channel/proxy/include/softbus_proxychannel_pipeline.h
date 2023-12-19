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

#ifndef SOFTBUS_PROXYCHANNEL_PIPELINE_H
#define SOFTBUS_PROXYCHANNEL_PIPELINE_H

#include "stdbool.h"
#include "stdint.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    void (*onDataReceived)(int32_t channelId, const char *data, uint32_t len);
    void (*onDisconnected)(int32_t channelId);
} ITransProxyPipelineListener;

typedef struct {
    void (*onChannelOpened)(int32_t requestId, int32_t channelId);
    void (*onChannelOpenFailed)(int32_t requestId, int32_t reason);
} ITransProxyPipelineCallback;

typedef enum {
    MSG_TYPE_INVALID = 0,

    MSG_TYPE_P2P_NEGO = 0xABADBEEF,
    MSG_TYPE_IP_PORT_EXCHANGE,

    MSG_TYPE_CNT = 2,
} TransProxyPipelineMsgType;

typedef struct {
    bool bleDirect;
} TransProxyPipelineChannelOption;
int32_t TransProxyPipelineGenRequestId(void);
int32_t TransProxyPipelineRegisterListener(TransProxyPipelineMsgType type, const ITransProxyPipelineListener *listener);
int32_t TransProxyPipelineOpenChannel(int32_t requestId, const char *networkId,
    const TransProxyPipelineChannelOption *option, const ITransProxyPipelineCallback *callback);
int32_t TransProxyPipelineSendMessage(
    int32_t channelId, const uint8_t *data, uint32_t dataLen, TransProxyPipelineMsgType type);
int32_t TransProxyPipelineGetChannelIdByNetworkId(const char *networkId);
int32_t TransProxyPipelineGetUuidByChannelId(int32_t channelId, char *uuid, uint32_t uuidLen);
int32_t TransProxyPipelineCloseChannel(int32_t channelId);
int32_t TransProxyPipelineCloseChannelDelay(int32_t channelId);
int32_t TransProxyPipelineInit(void);
int32_t TransProxyReuseByChannelId(int32_t channelId);

#ifdef __cplusplus
}
#endif

#endif
