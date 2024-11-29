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

#ifndef CLIENT_TRANS_SESSION_CALLBACK_H
#define CLIENT_TRANS_SESSION_CALLBACK_H

#include "session.h"
#include "socket.h"
#include "softbus_def.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    int32_t (*OnSessionOpened)(const char *sessionName, const ChannelInfo *channel, SessionType flag);
    int32_t (*OnSessionClosed)(int32_t channelId, int32_t channelType, ShutdownReason reason);
    int32_t (*OnSessionOpenFailed)(int32_t channelId, int32_t channelType, int32_t errCode);
    int32_t (*OnDataReceived)(int32_t channelId, int32_t channelType,
        const void *data, uint32_t len, SessionPktType type);
    int32_t (*OnStreamReceived)(int32_t channelId, int32_t channelType,
        const StreamData *data, const StreamData *ext, const StreamFrameInfo *param);
    int32_t (*OnGetSessionId)(int32_t channelId, int32_t channelType, int32_t *sessionId, bool isClosing);
    int32_t (*OnQosEvent)(int32_t channelId, int32_t channelType, int32_t eventId,
        int32_t tvCount, const QosTv *tvList);
    int32_t (*OnIdleTimeoutReset)(int32_t sessionId);
    int32_t (*OnRawStreamEncryptDefOptGet)(const char *sessionName, bool *isEncrypt);
    int32_t (*OnRawStreamEncryptOptGet)(int32_t channelId, int32_t channelType, bool *isEncrypt);
    int32_t (*OnChannelBind)(int32_t channelId, int32_t channelType);
    int32_t (*IfChannelForSocket)(const char *sessionName, bool *isSocket);
    int32_t (*OnQos)(int32_t channelId, int32_t channelType, QoSEvent event, const QosTV *qos, uint32_t count);
} IClientSessionCallBack;

IClientSessionCallBack *GetClientSessionCb(void);

#ifdef __cplusplus
}
#endif
#endif