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

#ifndef CLIENT_TRANS_UDP_MANAGER_H
#define CLIENT_TRANS_UDP_MANAGER_H

#include <stdint.h>

#include "client_trans_session_callback.h"
#include "session.h"
#include "softbus_def.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    void (*OnStreamReceived)(int32_t channelId, const StreamData *data, const StreamData *ext, const FrameInfo *param);
    void (*OnFileReceived)(void);
    void (*OnMessageReceived)(void);
    void (*OnUdpChannelOpened)(int32_t channelId);
    void (*OnUdpChannelClosed)(int32_t channelId);
} UdpChannelMgrCb;

int32_t ClientTransUdpMgrInit(IClientSessionCallBack *callback);
void ClientTransUdpMgrDeinit(void);

int32_t TransOnUdpChannelOpened(const char *sessionName, const ChannelInfo *channel, int32_t *udpPort);
int32_t TransOnUdpChannelOpenFailed(int32_t channelId);
int32_t TransOnUdpChannelClosed(int32_t channelId);

int32_t TransCloseUdpChannel(int32_t channelId);

int32_t TransUdpChannelSendStream(int32_t channelId, const StreamData *data, const StreamData *ext,
    const FrameInfo *param);
#ifdef __cplusplus
}
#endif
#endif // CLIENT_TRANS_UDP_MANAGER_H