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

#ifndef WIFI_STATISTIC_H
#define WIFI_STATISTIC_H

#include <stdint.h>
#include "cJSON.h"

namespace Communication {
namespace Softbus {
class WifiStatistic {
public:
    WifiStatistic() = default;
    ~WifiStatistic() = default;

    static WifiStatistic& GetInstance();
    int32_t GetWifiStatisticInfo(cJSON *json);

private:
    int32_t GetStaInfo(cJSON *json);
    int32_t GetSoftApInfo(cJSON *json);
    int32_t GetP2PInfo(cJSON *json);
};
} // namespace SoftBus
} // namespace Communication

#endif // WIFI_STATISTIC_H