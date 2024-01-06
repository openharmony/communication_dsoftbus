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
#ifndef WIFI_DIRECT_INTERFACE_INFO_H
#define WIFI_DIRECT_INTERFACE_INFO_H

#include "info_container.h"
#include "common_list.h"

#ifdef __cplusplus
extern "C" {
#endif

enum InterfaceInfoKey {
    II_KEY_DYNAMIC_MAC = 0,
    II_KEY_INTERFACE_NAME = 1,
    II_KEY_CONNECT_CAPABILITY = 2,
    II_KEY_WIFI_DIRECT_ROLE = 3,
    II_KEY_BASE_MAC = 4,
    II_KEY_PHYSICAL_RATE = 5,
    II_KEY_SUPPORT_BAND = 6,
    II_KEY_CHANNEL_AND_BANDWIDTH = 7,
    II_KEY_COEXIST_CHANNEL_LIST = 8,
    II_KEY_HML_LINK_COUNT = 9,
    II_KEY_ISLAND_DEVICE_COUNT = 10,
    II_KEY_COEXIST_VAP_COUNT = 11,
    II_KEY_IPV4 = 12,
    II_KEY_CHANNEL_5G_LIST = 13,
    II_KEY_SSID = 14,
    II_KEY_PORT = 15,
    II_KEY_IS_WIDE_BAND_SUPPORT = 16,
    II_KEY_CENTER_20M = 17,
    II_KEY_CENTER_FREQUENCY1 = 18,
    II_KEY_CENTER_FREQUENCY2 = 19,
    II_KEY_BANDWIDTH = 20,
    II_KEY_WIFI_CFG_INFO = 21,
    II_KEY_IS_ENABLE = 22,
    II_KEY_CONNECTED_DEVICE_COUNT = 23,
    II_KEY_PSK = 24,
    II_KEY_REUSE_COUNT = 25,
    II_KEY_IS_AVAILABLE = 26,
    II_KEY_COEXIST_RULE = 27,
    II_KEY_MAX,
};

struct InterfaceInfo {
    INFO_CONTAINER_BASE(InterfaceInfo, II_KEY_MAX);

    char* (*getName)(struct InterfaceInfo *self);
    void (*putName)(struct InterfaceInfo *self, const char *name);
    int32_t (*getIpString)(struct InterfaceInfo *self, char *ipString, int32_t ipStringSize);
    void (*putIpString)(struct InterfaceInfo *self, const char *ipString);
    bool (*isEnable);
    int32_t (*getP2pGroupConfig)(struct InterfaceInfo *self, char *buffer, size_t bufferSize);
    int32_t (*setP2pGroupConfig)(struct InterfaceInfo *self, char *groupConfig);
    void (*increaseRefCount)(struct InterfaceInfo *self);
    void (*decreaseRefCount)(struct InterfaceInfo *self);

    struct ListNode node;
};

void InterfaceInfoConstructor(struct InterfaceInfo *self);
void InterfaceInfoConstructorWithName(struct InterfaceInfo *self, const char *name);
void InterfaceInfoDestructor(struct InterfaceInfo *self);

struct InterfaceInfo *InterfaceInfoNew(void);
void InterfaceInfoDelete(struct InterfaceInfo *self);
struct InterfaceInfo *InterfaceInfoNewArray(size_t size);
void InterfaceInfoDeleteArray(struct InterfaceInfo *self, size_t size);

#ifdef __cplusplus
}
#endif
#endif