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
#include "softbus_trans_def.h"
#include "softbus_proxychannel_message.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    PROXY_FLAG_BYTES = 0,
    PROXY_FLAG_ACK = 1,
    PROXY_FLAG_MESSAGE = 2,
    PROXY_FILE_FIRST_FRAME = 3,
    PROXY_FILE_ONGOINE_FRAME = 4,
    PROXY_FILE_LAST_FRAME = 5,
    PROXY_FILE_ONLYONE_FRAME = 6,
    PROXY_FILE_ALLFILE_SENT = 7,
    PROXY_FILE_CRC_CHECK_FRAME = 8,
    PROXY_FILE_RESULT_FRAME = 9,
    PROXY_FILE_ACK_REQUEST_SENT = 10,
    PROXY_FILE_ACK_RESPONSE_SENT = 11,
    PROXY_FLAG_ASYNC_MESSAGE = 12,
} ProxyPacketType;

int32_t TransProxyPostSessionData(int32_t channelId, const unsigned char *data, uint32_t len, SessionPktType flags);
int32_t TransOnNormalMsgReceived(const char *pkgName, int32_t pid, int32_t channelId, const char *data, uint32_t len);
int32_t TransProxyDelSliceProcessorByChannelId(int32_t channelId);
int32_t NotifyClientMsgReceived(const char *pkgName, int32_t pid, int32_t channelId, TransReceiveData *receiveData);

#ifdef __cplusplus
}
#endif

#endif
