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

#ifndef LNN_IP_UTILS_H
#define LNN_IP_UTILS_H

#include <stdbool.h>

#include "softbus_bus_center.h"

#ifdef __cplusplus
extern "C" {
#endif

#define LNN_LOOPBACK_IP "127.0.0.1"
#define LNN_LOOPBACK_IFNAME "lo"
#define LNN_WLAN_IF_NAME_PREFIX "wlan"
#define LNN_ETH_IF_NAME_PREFIX  "eth"

int32_t LnnGetLocalIp(char *ip, uint32_t len, char *ifName, uint32_t ifNameLen, ConnectionAddrType type);

#ifdef __cplusplus
}
#endif
#endif /* LNN_IP_UTILS_H */
