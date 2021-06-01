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

#ifndef SOFTBUS_PROXYCHANNEL_SESSION_H
#define SOFTBUS_PROXYCHANNEL_SESSION_H
#include "stdint.h"
#include "softbus_def.h"

typedef enum {
    PROXY_FLAG_BYTES = 0,
    PROXY_FLAG_ACK = 1,
    PROXY_FLAG_MESSAGE = 2,
    PROXY_FILE_FIRST_FRAME = 3,
    PROXY_FILE_ONGOINE_FRAME = 4,
    PROXY_FILE_LAST_FRAME = 5,
    PROXY_FILE_ONLYONE_FRAME = 6,
    PROXY_FILE_ALLFILE_SENT = 7,
    PROXY_FLAG_ASYNC_MESSAGE = 8,
} ProxyPacketType;

typedef enum {
    PROXY_CHANNEL_PRORITY_MESSAGE = 0,
    PROXY_CHANNEL_PRORITY_BYTES = 1,
    PROXY_CHANNEL_PRORITY_FILE = 2,
    PROXY_CHANNEL_PRORITY_BUTT = 3,
} ProxyChannelPriority;

int32_t TransProxyPostSessionData(int32_t channelId, const uint8_t* data, uint32_t len, SessionPktType flags);
void TransOnNormalMsgReceived(const char *pkgName, int32_t channelId, const char *data, uint32_t len);

#endif
