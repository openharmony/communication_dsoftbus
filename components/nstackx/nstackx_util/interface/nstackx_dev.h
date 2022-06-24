/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#ifndef NSTACKX_DEV_H
#define NSTACKX_DEV_H

#include "nstackx_common_header.h"

#ifndef UNUSED
#ifdef __GNUC__
#define UNUSED __attribute__((unused))
#else /* not a GCC */
#define UNUSED
#endif /* GCC */
#endif

/* DFile connect type list. */
typedef enum {
    CONNECT_TYPE_NONE = 0,
    CONNECT_TYPE_P2P,
    CONNECT_TYPE_WLAN,
    CONNECT_TYPE_MAX,
} ConnectType;

typedef enum {
    DEVICE_32_BITS = 32,
    DEVICE_64_BITS = 64,
} DeviceType;

#define P2P_DEV_NAME_PRE "p2p"
#define WLAN_DEV_NAME_PRE "wlan"
#ifndef ETH_DEV_NAME_PRE
#define ETH_DEV_NAME_PRE "eth"
#endif
#define USB_DEV_NAME_PRE "rndis"
#define WIFI_DIRECT_NAME "Wi-Fi Direct"
#define INTERFCAE_NAME_MAX_LENGTH (128 + 4)
#define INTERFACE_GUID_MAX_LENGTH (256 + 4)
#define INTERFACE_NETMASK (0xffffff)
#define INTERFCAE_DES_MAX_LENGTH 128
#define INTERFCAE_ADDR_MAX_LENGTH 16
#define INTERFCAE_TYPE_MAX_LENGTH 20
#define INTERFACE_MAX 16
#define SOFTAP_ADDR_KEY (0xc0a82b01)
#define P2P_ADDR_KEY (0xc0a83101)

NSTACKX_EXPORT int32_t BindToDevice(SocketDesc sockfd, const struct sockaddr_in *localAddr);
NSTACKX_EXPORT int32_t GetIfBroadcastIp(const char *ifName, char *ipString, size_t ipStringLen);
NSTACKX_EXPORT int32_t GetConnectionType(const uint32_t sourceIp, const uint32_t destinationIp, uint16_t *connectType);
NSTACKX_EXPORT int32_t BindToTargetDev(SocketDesc sockfd, const char *targetInterfaceName);
NSTACKX_EXPORT int32_t GetInterfaceNameByIP(uint32_t sourceIp, char *interfaceName, size_t nameLen);
NSTACKX_EXPORT void BindToDevInTheSameLan(SocketDesc sockfd, const struct sockaddr_in *sockAddr);
NSTACKX_EXPORT uint8_t DFileGetDeviceBits(void);

#endif // NSTACKX_DEV_H
