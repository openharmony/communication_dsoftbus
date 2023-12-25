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

#ifndef WIFI_DIRECT_LINK_INFO_H
#define WIFI_DIRECT_LINK_INFO_H

#include "info_container.h"
#include <cJSON.h>
#include "common_list.h"

#ifdef __cplusplus
extern "C" {
#endif

enum LinkInfoKey {
    LI_KEY_LOCAL_INTERFACE = 0,
    LI_KEY_REMOTE_INTERFACE = 1,
    LI_KEY_LOCAL_LINK_MODE = 2,
    LI_KEY_REMOTE_LINK_MODE = 3,
    LI_KEY_CENTER_20M = 4,
    LI_KEY_CENTER_FREQUENCY1 = 5,
    LI_KEY_CENTER_FREQUENCY2 = 6,
    LI_KEY_BANDWIDTH = 7,
    LI_KEY_SSID = 8,
    LI_KEY_BSSID = 9,
    LI_KEY_PSK = 10,
    LI_KEY_IS_DHCP = 11,
    LI_KEY_LOCAL_IPV4 = 12,
    LI_KEY_REMOTE_IPV4 = 13,
    LI_KEY_AUTH_PORT = 14,
    LI_KEY_MAX_PHYSICAL_RATE = 15,
    LI_KEY_REMOTE_DEVICE = 16,
    LI_KEY_STATUS = 17,
    LI_KEY_LOCAL_BASE_MAC = 18,
    LI_KEY_REMOTE_BASE_MAC = 19,
    LI_KEY_IS_CLIENT = 20,
    LI_KEY_MAX,
};

struct LinkInfo {
    INFO_CONTAINER_BASE(LinkInfo, LI_KEY_MAX);

    cJSON* (*toJsonObject)(struct LinkInfo *self);
    int32_t (*getLocalIpString)(struct LinkInfo *self, char *ipString, int32_t ipStringSize);
    int32_t (*getRemoteIpString)(struct LinkInfo *self, char *ipString, int32_t ipStringSize);
    void (*putLocalIpString)(struct LinkInfo *self, const char *ipString);
    void (*putRemoteIpString)(struct LinkInfo *self, const char *ipString);

    ListNode node;
};

void LinkInfoConstructor(struct LinkInfo* self);
void LinkInfoConstructorWithNameAndMode(struct LinkInfo* self, const char *localName, const char *remoteName,
                                        uint32_t localMode, uint32_t remoteMode);
void LinkInfoDestructor(struct LinkInfo* self);

struct LinkInfo* LinkInfoNew(void);
struct LinkInfo* LinkInfoNewWithNameAndMode(const char *localName, const char *remoteName,
                                            uint32_t localMode, uint32_t remoteMode);
void LinkInfoDelete(struct LinkInfo* self);

#ifdef __cplusplus
}
#endif
#endif