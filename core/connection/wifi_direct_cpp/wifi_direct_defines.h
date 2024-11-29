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
#ifndef WIFI_DIRECT_DEFINES_H
#define WIFI_DIRECT_DEFINES_H

#define MIN(a, b) ((a) < (b) ? (a) : (b))

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

#define MAC_ADDR_STR_LEN 32
#define MAC_ADDR_ARRAY_SIZE 6
#define GROUP_CONFIG_STR_LEN 256
#define WIFI_CFG_INFO_MAX_LEN 512

#define IP_NUM_MAX 32
#define IF_NAME_HML "chba0"
#define IF_NAME_P2P "p2p0"
#define IF_NAME_WLAN "wlan0"
#define IF_NAME_WLAN1 "wlan1"

#define IPV4_ADDR_ARRAY_LEN 4
#define DEFAULT_PREFIX_LEN 24

#define REQUEST_ID_INVALID (-1)

#define HML_IP_NET_PREFIX "172.30."
#define BYPASS_MAC "FF:FF:FF:FF:FF:FF"
#define SSID_PREFIX "Direct-"
#define SSID_PREFIX_LEN 7
#define SSID_SUFFIX_LEN 4
#define WIFI_DIRECT_SSID_LEN (SSID_PREFIX_LEN + SSID_SUFFIX_LEN + 1)
#define WIFI_DIRECT_PSK_LEN 8
#define NETWORK_ID_SHORT_HASH_BIN_LEN 4
#define NETWORK_ID_SHORT_HASH_HEX_LEN 8
#define CHALLENGE_CODE_LEN 2

#endif
