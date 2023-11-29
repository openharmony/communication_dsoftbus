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
#ifndef WIFI_DIRECT_IPV4_H
#define WIFI_DIRECT_IPV4_H

#include <stdint.h>
#include <stddef.h>
#include "wifi_direct_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define IPV4_INFO_BYTES_ARRAY_LEN 5

struct WifiDirectIpv4Info {
    uint32_t address; // network byte order
    uint8_t prefixLength;
};

int32_t WifiDirectIpStringToIpv4(const char *ipString, struct WifiDirectIpv4Info *ipv4);
int32_t WifiDirectIpv4ToString(const struct WifiDirectIpv4Info *ipv4, char *ipString, size_t ipStringSize);

int32_t WifiDirectIpv4InfoToBytes(const struct WifiDirectIpv4Info *ipv4, size_t ipv4Count,
                                  uint8_t *data, size_t *dataLen);
void WifiDirectIpv4BytesToInfo(const uint8_t *ipv4Bytes, size_t ipv4BytesLen,
                               struct WifiDirectIpv4Info *ipv4, size_t *ipv4Count);

#ifdef __cplusplus
}
#endif
#endif