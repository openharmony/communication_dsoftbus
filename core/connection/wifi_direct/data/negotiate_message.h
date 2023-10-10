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

#ifndef WIFI_DIRECT_NEGOTIATE_MESSAGE_H
#define WIFI_DIRECT_NEGOTIATE_MESSAGE_H

#include "info_container.h"

#ifdef __cplusplus
extern "C" {
#endif

enum NegotiateMessageKey {
    NM_KEY_MSG_TYPE = 0,
    NM_KEY_SESSION_ID = 1,
    NM_KEY_WIFI_CFG_TYPE = 2,
    NM_KEY_WIFI_CFG_INFO = 3,
    NM_KEY_IPV4_LIST = 4,
    NM_KEY_PREFER_LINK_MODE = 5,
    NM_KEY_IS_MODE_STRICT = 6,
    NM_KEY_PREFER_LINK_BANDWIDTH = 7,
    NM_KEY_IS_BRIDGE_SUPPORTED = 8,
    NM_KEY_LINK_INFO = 9,
    NM_KEY_RESULT_CODE = 10,
    NM_KEY_INTERFACE_INFO_ARRAY = 11,
    NM_KEY_REMOTE_DEVICE_ID = 12,
    NM_KEY_NEGO_CHANNEL = 13,
    NM_KEY_EXTRA_DATA_ARRAY = 14,
    NM_KEY_INNER_LINK = 15,
    NM_KEY_IS_PROXY_ENABLE = 16,
    NM_KEY_CHANNEL_5G_LIST = 17,
    NM_KEY_CHANNEL_5G_SCORE = 18,

    /* old p2p */
    NM_KEY_GC_CHANNEL_LIST = 19,
    NM_KEY_STATION_FREQUENCY = 20,
    NM_KEY_ROLE = 21,
    NM_KEY_EXPECTED_ROLE = 22,
    NM_KEY_VERSION = 23,
    NM_KEY_GC_IP = 24,
    NM_KEY_WIDE_BAND_SUPPORTED = 25,
    NM_KEY_GROUP_CONFIG = 26,
    NM_KEY_MAC = 27,
    NM_KEY_BRIDGE_SUPPORTED = 28,
    NM_KEY_GO_IP = 29,
    NM_KEY_GO_MAC = 30,
    NM_KEY_GO_PORT = 31,
    NM_KEY_IP = 32,
    NM_KEY_RESULT = 33,
    NM_KEY_CONTENT_TYPE = 34,
    NM_KEY_GC_MAC = 35,
    NM_KEY_SELF_WIFI_CONFIG = 36,
    NM_KEY_GC_CHANNEL_SCORE = 37,
    NM_KEY_COMMAND_TYPE = 38,
    NM_KEY_INTERFACE_NAME = 39,

    NM_KEY_MAX
};

struct NegotiateMessage {
    INFO_CONTAINER_BASE(NegotiateMessage, NM_KEY_MAX);
};

void NegotiateMessageConstructor(struct NegotiateMessage* self);
void NegotiateMessageDestructor(struct NegotiateMessage* self);

struct NegotiateMessage* NegotiateMessageNew(void);
void NegotiateMessageDelete(struct NegotiateMessage* self);
struct NegotiateMessage* NegotiateMessageNewArray(size_t size);
void NegotiateMessageDeleteArray(struct NegotiateMessage* self, size_t size);

#ifdef __cplusplus
}
#endif
#endif