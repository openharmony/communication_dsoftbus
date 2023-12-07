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
#ifndef WIFI_DIRECT_PERF_RECORDER_H
#define WIFI_DIRECT_PERF_RECORDER_H

#include "wifi_direct_types.h"

#ifdef __cplusplus
extern "C" {
#endif

enum TimePointType {
    TP_P2P_CONNECT_START = 0,
    TP_P2P_CONNECT_END = 1,
    TP_P2P_CREATE_GROUP_START = 2,
    TP_P2P_CREATE_GROUP_END = 3,
    TP_P2P_CONNECT_GROUP_START = 4,
    TP_P2P_CONNECT_GROUP_END = 5,
    TP_P2P_GET_WIFI_CONFIG_START = 6,
    TP_P2P_GET_WIFI_CONFIG_END = 7,
    TP_MAX,
};

enum TimeCostType {
    TC_TOTAL = 0,
    TC_CREATE_GROUP = 1,
    TC_CONNECT_GROUP = 2,
    TC_GET_WIFI_CONFIG = 3,
    TC_NEGOTIATE = 4,
    TC_MAX,
};

struct WifiDirectPerfRecorder {
    void (*setPid)(int32_t pid);
    int32_t (*getPid)(void);
    void (*setConnectType)(enum WifiDirectLinkType type);
    enum WifiDirectLinkType (*getConnectType)(void);
    void (*record)(enum TimePointType type);
    void (*calculate)(void);
    void (*clear)(void);
    uint64_t (*getTime)(enum TimeCostType type);

    bool isInited;
    int32_t pid;
    enum WifiDirectLinkType type;
    uint64_t timePoints[TP_MAX];
    uint64_t timeCosts[TC_MAX];
};

struct WifiDirectPerfRecorder* GetWifiDirectPerfRecorder(void);

#ifdef __cplusplus
}
#endif
#endif