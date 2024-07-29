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

#ifndef CLIENT_TRANS_STREAM_H
#define CLIENT_TRANS_STREAM_H

#include <stdint.h>
#include "client_trans_udp_manager.h"
#include "softbus_def.h"
#include "softbus_trans_def.h"

#ifdef __cplusplus
extern "C" {
#endif

void RegisterStreamCb(const UdpChannelMgrCb *streamCb);

void UnregisterStreamCb(void);

int32_t TransOnstreamChannelOpened(const ChannelInfo *channel, int32_t *streamPort);

int32_t TransCloseStreamChannel(int32_t channelId);

int32_t TransSendStream(int32_t channelId, const StreamData *data, const StreamData *ext, const StreamFrameInfo *param);

int32_t TransSetStreamMultiLayer(int32_t channelId, const void *optValue);
#ifdef __cplusplus
}
#endif
#endif // CLIENT_TRANS_STREAM_H