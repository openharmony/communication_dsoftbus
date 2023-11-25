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
#ifndef WIFI_DIRECT_IP_MANAGER_H
#define WIFI_DIRECT_IP_MANAGER_H

#include "wifi_direct_types.h"
#include "common_list.h"
#include "utils/wifi_direct_ipv4_info.h"

#ifdef __cplusplus
extern "C" {
#endif

struct WifiDirectIpManager {
    int32_t (*applyIp)(struct WifiDirectIpv4Info *remoteArray, size_t remoteArraySize,
                       struct WifiDirectIpv4Info *sink, struct WifiDirectIpv4Info *source);
    int32_t (*configIp)(const char *interface, struct WifiDirectIpv4Info *local, struct WifiDirectIpv4Info *remote,
                        const char *remoteMac);
    void (*releaseIp)(const char *interface, struct WifiDirectIpv4Info *local, struct WifiDirectIpv4Info *remote,
                      const char *remoteMac);
    void (*cleanAllIps)(const char *interface);
};

struct WifiDirectIpManager* GetWifiDirectIpManager(void);

#ifdef __cplusplus
}
#endif
#endif