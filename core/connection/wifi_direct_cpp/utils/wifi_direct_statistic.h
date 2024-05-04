/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef WIFI_DIRECET_STATISTIC_H
#define WIFI_DIRECET_STATISTIC_H

#include "stdint.h"
#ifdef __cplusplus
extern "C" {
#endif

enum StatisticLinkType {
    STATISTIC_P2P = 0,
    STATISTIC_HML = 1,
    STATISTIC_TRIGGER_HML = 2,
    STATISTIC_LINK_TYPE_NUM = 3,
};

enum StatisticBootLinkType {
    STATISTIC_NONE = 0,
    STATISTIC_WLAN = 1,
    STATISTIC_BLE = 2,
    STATISTIC_BR = 3,
    STATISTIC_RENEGOTIATE = 4,
    STATISTIC_BOOT_LINK_TYPE_NUM = 5,
};
#ifdef __cplusplus
}
#endif

#endif