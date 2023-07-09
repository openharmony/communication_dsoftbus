/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#ifndef WIFI_DIRECT_FAST_CONNECT_H
#define WIFI_DIRECT_FAST_CONNECT_H

#include "wifi_direct_types.h"

#ifdef __cplusplus
extern "C" {
#endif

struct NegotiateMessage;
struct WifiDirectProcessor;

int32_t FastConnectInit(void);
void FastConnectReset(bool releaseChannel);

void FastConnectBcastDataReceived(const char *networkId, uint8_t *data, size_t dataLen);
void FastConnectSessionDataReceived(int sessionId, const uint8_t *data, size_t dataLen);

void FastConnectCloseChannel(struct WifiDirectNegotiateChannel *channel);

int FastConnectOpenLink(struct WifiDirectConnectInfo *connectInfo, struct WifiDirectProcessor *processor);
int FastConnectReuseLink(struct WifiDirectConnectInfo *connectInfo, struct WifiDirectProcessor *processor);
void FastConnectHandleFailure(int result);
void FastConnectClientConnected(const char *remoteMac);
int32_t FastConnectProcessNegotiateMessage(enum WifiDirectNegotiateCmdType cmd, struct NegotiateMessage *msg);

void FastConnectSyncLnnInfo(void);

#ifdef __cplusplus
}
#endif
#endif