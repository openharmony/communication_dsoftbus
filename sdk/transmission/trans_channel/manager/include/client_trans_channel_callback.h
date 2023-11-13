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

#ifndef CLIENT_TRANS_CHANNEL_CALLBACK_H
#define CLIENT_TRANS_CHANNEL_CALLBACK_H

#include "session.h"
#include "softbus_def.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t TransOnChannelOpened(const char* sessionName, const ChannelInfo *channel);

int32_t TransOnChannelOpenFailed(int32_t channelId, int32_t channelType, int32_t errCode);

int32_t TransOnChannelLinkDown(const char *networkId, int32_t routeType);

int32_t TransOnChannelClosed(int32_t channelId, int32_t channelType, ShutdownReason reason);

int32_t TransOnChannelMsgReceived(int32_t channelId, int32_t channelType,
    const void *data, unsigned int len, SessionPktType type);

int32_t TransOnChannelQosEvent(int32_t channelId, int32_t channelType, int32_t eventId,
    int32_t tvCount, const QosTv *tvList);

#ifdef __cplusplus
}
#endif
#endif // CLIENT_TRANS_CHANNEL_CALLBACK_H