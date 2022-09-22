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

#ifndef CLIENT_TRANS_PROXY_CHANNEL_H
#define CLIENT_TRANS_PROXY_CHANNEL_H

#include "client_trans_file_listener.h"
#include "client_trans_session_callback.h"
#include "softbus_def.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t ClinetTransProxyInit(const IClientSessionCallBack *cb);

void ClientTransProxyDeinit(void);

int32_t ClientTransProxyOnChannelOpened(const char *sessionName, const ChannelInfo *channel);

int32_t ClientTransProxyOnChannelClosed(int32_t channelId);

int32_t ClientTransProxyOnChannelOpenFailed(int32_t channelId, int32_t errCode);

int32_t ClientTransProxyOnDataReceived(int32_t channelId,
    const void *data, uint32_t len, SessionPktType type);

void ClientTransProxyCloseChannel(int32_t channelId);

int32_t TransProxyChannelSendBytes(int32_t channelId, const void *data, uint32_t len);

int32_t TransProxyChannelSendMessage(int32_t channelId, const void *data, uint32_t len);

int32_t TransProxyChannelSendFile(int32_t channelId, const char *sFileList[], const char *dFileList[],
    uint32_t fileCnt);

int32_t ProcessFileFrameData(int32_t sessionId, int32_t channelId, const char *data, uint32_t len, int32_t type);

#ifdef __cplusplus
}
#endif
#endif