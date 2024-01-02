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

#ifndef WIFI_DIRECT_INNER_LINK_H
#define WIFI_DIRECT_INNER_LINK_H

#include "common_list.h"
#include "info_container.h"
#include "wifi_direct_types.h"
#include "processor/wifi_direct_processor.h"

#ifdef __cplusplus
extern "C" {
#endif

enum InnerLinkKey {
    IL_KEY_LINK_TYPE = 1,
    IL_KEY_STATE = 2,
    IL_KEY_LOCAL_INTERFACE = 3,
    IL_KEY_LOCAL_BASE_MAC = 4,
    IL_KEY_LOCAL_DYNAMIC_MAC = 5,
    IL_KEY_LOCAL_IPV4 = 6,
    IL_KEY_REMOTE_INTERFACE = 7,
    IL_KEY_REMOTE_BASE_MAC = 8,
    IL_KEY_REMOTE_DYNAMIC_MAC = 9,
    IL_KEY_REMOTE_IPV4 = 10,
    IL_KEY_IS_BEING_USED_BY_LOCAL = 11,
    IL_KEY_IS_BEING_USED_BY_REMOTE = 12,
    IL_KEY_FREQUENCY = 13,
    IL_KEY_STATE_CHANGE_TIME = 14,
    IL_KEY_DEVICE_ID = 15,
    IL_KEY_NEGO_CHANNEL = 16,
    IL_KEY_LOCAL_PORT = 17,
    IL_KEY_LISTENER_MODULE_ID = 18,

    IL_KEY_MAX
};

enum InnerLinkState {
    INNER_LINK_STATE_INVALID = -1,
    INNER_LINK_STATE_DISCONNECTED = 0,
    INNER_LINK_STATE_CONNECTED = 1,
    INNER_LINK_STATE_CONNECTING = 2,
    INNER_LINK_STATE_DISCONNECTING = 3,
};

struct InnerLink {
    INFO_CONTAINER_BASE(InnerLink, IL_KEY_MAX);

    int32_t (*getLink)(struct InnerLink *self, int32_t requestId, int32_t pid, struct WifiDirectLink *link);
    int32_t (*getLocalIpString)(struct InnerLink *self, char *ipString, int32_t ipStringSize);
    int32_t (*getRemoteIpString)(struct InnerLink *self, char *ipString, int32_t ipStringSize);
    void (*putLocalIpString)(struct InnerLink *self, const char *ipString);
    void (*putRemoteIpString)(struct InnerLink *self, const char *ipString);
    void (*increaseReference)(struct InnerLink *self);
    void (*decreaseReference)(struct InnerLink *self);
    int32_t (*getReference)(struct InnerLink *self);
    void (*addId)(struct InnerLink *self, int32_t linkId, int32_t requestId, int32_t pid);
    void (*removeId)(struct InnerLink *self, int32_t linkId);
    bool (*containId)(struct InnerLink *self, int32_t linkId);
    void (*setState)(struct InnerLink *self, enum InnerLinkState state);
    bool (*isProtected)(struct InnerLink *self);
    void (*dumpLinkId)(struct InnerLink *self, int32_t fd);

    /* for link manager */
    ListNode node;
    int32_t reference;
    ListNode idList;
};

void InnerLinkConstructor(struct InnerLink *self);
void InnerLinkConstructorWithArgs(struct InnerLink *self, enum WifiDirectLinkType type,
                                  const char *localInterface, const char *remoteMac);
void InnerLinkDestructor(struct InnerLink *self);
struct InnerLink* InnerLinkNew(void);
void InnerLinkDelete(struct InnerLink *self);
struct InnerLink* InnerLinkNewArray(size_t size);
void InnerLinkDeleteArray(struct InnerLink *self, size_t size);

#ifdef __cplusplus
}
#endif
#endif