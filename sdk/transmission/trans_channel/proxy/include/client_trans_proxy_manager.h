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

#include "softbus_def.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t TransCloseProxyChannel(int32_t channelId);

int32_t TransOnProxyChannelOpened(const ChannelInfo *channel);

int32_t TransProxyChannelSendBytes(int32_t channelId, const void *data, uint32_t len);

int32_t TransProxyChannelSendMessage(int32_t channelId, const void *data, uint32_t len);

#ifdef __cplusplus
}
#endif
#endif // CLIENT_TRANS_PROXY_CHANNEL_H