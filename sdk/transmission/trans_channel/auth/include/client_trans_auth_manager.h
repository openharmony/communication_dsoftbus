/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#ifndef CLIENT_TRANS_AUTH_MANAGER_H
#define CLIENT_TRANS_AUTH_MANAGER_H

#include "client_trans_session_callback.h"
#include "softbus_def.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t ClientTransAuthInit(const IClientSessionCallBack *cb);

int32_t ClientTransAuthOnChannelOpened(const char *sessionName, const ChannelInfo *channel);

int32_t ClientTransAuthOnChannelClosed(int32_t channelId, ShutdownReason reason);

int32_t ClientTransAuthOnChannelOpenFailed(int32_t channelId, int32_t errCode);

int32_t ClientTransAuthOnDataReceived(int32_t channelId, const void *data, uint32_t len, SessionPktType type);

void ClientTransAuthCloseChannel(int32_t channelId, ShutdownReason reason);

int32_t TransAuthChannelSendBytes(int32_t channelId, const void *data, uint32_t len);

int32_t TransAuthChannelSendMessage(int32_t channelId, const void *data, uint32_t len);

#ifdef __cplusplus
}
#endif
#endif // CLIENT_TRANS_AUTH_MANAGER_H
