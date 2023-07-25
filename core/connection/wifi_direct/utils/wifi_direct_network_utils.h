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
#ifndef WIFI_DIRECT_NETWORK_UTILS_H
#define WIFI_DIRECT_NETWORK_UTILS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "wifi_direct_types.h"

#ifdef __cplusplus
extern "C" {
#endif

struct WifiDirectIpv4Info;
struct WifiDirectNetWorkUtils {
    int32_t (*splitString)(char *input, char *splitter, char **outputArray, size_t *outputArraySize);

    int32_t (*channelToFrequency)(int32_t channel);
    int32_t (*frequencyToChannel)(int32_t frequency);

    int32_t (*channelListToString)(int32_t *channelArray, size_t channelNum, char *outBuffer, size_t inSize);
    int32_t (*stringToChannelList)(char *channelListString, int32_t *channelArray, size_t *channelArraySize);

    bool (*is2GBand)(int32_t frequency);
    bool (*is5GBand)(int32_t frequency);
    bool (*isInChannelList)(int32_t channel, const int32_t *channelArray, size_t channelNum);

    int32_t (*getInterfaceIpString)(const char *interface, char *ipString, int32_t ipStringSize);
    int32_t (*ipAddrToString)(uint32_t addrArray, char *addrString, size_t addrStringSize);
    int32_t (*ipStringToAddr)(const char *addrString, uint32_t *addr);
    int32_t (*ipStringToIntArray)(const char *addrString, uint32_t *addrArray, size_t addrArraySize);

    int32_t (*getInterfaceMacAddr)(const char *ifName, uint8_t *macAddrArray, size_t *macAddrArraySize);
    int32_t (*macStringToArray)(const char *macString, uint8_t *array, size_t *arraySize);
    int32_t (*macArrayToString)(const uint8_t *array, size_t arraySize, char *macString, size_t macStringSize);

    int32_t (*getLocalIpv4InfoArray)(struct WifiDirectIpv4Info *info, size_t *size);
};

struct WifiDirectNetWorkUtils* GetWifiDirectNetWorkUtils(void);

#ifdef __cplusplus
}
#endif
#endif