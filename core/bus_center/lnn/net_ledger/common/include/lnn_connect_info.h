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

#ifndef LNN_CONNECT_INFO_H
#define LNN_CONNECT_INFO_H

#include <stdint.h>

#include "bus_center_info_key.h"

#ifdef __cplusplus
extern "C" {
#endif

#define LOCAL_IP "127.0.0.1"
#define DEFAULT_IP ""
#define DEFAULT_MAC ""
#define DEFAULT_IFNAME ""
#define MAX_ADDR_LEN 46

typedef struct {
    char netIfName[NET_IF_NAME_LEN];
    char deviceIp[MAX_ADDR_LEN];
    char macAddr[MAC_LEN];
    char bleMacAddr[MAC_LEN];
    int authPort;
    int proxyPort;
    int sessionPort;
    uint64_t latestTime;
} ConnectInfo;

#ifdef __cplusplus
}
#endif

#endif // LNN_CONNECT_INFO_H