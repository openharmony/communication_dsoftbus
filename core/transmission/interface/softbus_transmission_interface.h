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

#ifndef SOFTBUS_TRANSMISSION_H
#define SOFTBUS_TRANSMISSION_H

#include <stdint.h>
#include "softbus_def.h"

typedef struct {
    int (*onChannelOpened)(int32_t channelId, const char *uuid, unsigned char isServer); // compatible nearby
    void (*onChannelOpenFailed)(int32_t channelId, const char *uuid);
    void (*onChannelClosed)(int32_t channelId);
    void (*onMessageReceived)(int32_t channelId, const char *data, unsigned int len);
} INetworkingListener;

int TransOpenNetWorkingChannel(const char *sessionName, const char *peerNetworkId);

int TransCloseNetWorkingChannel(int32_t channelId);

int TransSendNetworkingMessage(int32_t channelId, const char *data, int dataLen, int priority);

int TransRegisterNetworkingChannelListener(const INetworkingListener *listener);


#endif
