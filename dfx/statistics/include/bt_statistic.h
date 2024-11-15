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

#ifndef BT_STATISTIC_H
#define BT_STATISTIC_H

#include "stdint.h"
#include "cJSON.h"
#include <map>
#include <vector>

namespace Communication {
namespace Softbus {
class BtStatistic {
public:
    BtStatistic();
    ~BtStatistic() = default;

    static BtStatistic& GetInstance();
    int32_t GetBtStatisticInfo(cJSON *json);

private:
    void GetGattClientDeviceInfo(cJSON *json);
    void GetGattServerDeviceInfo(cJSON *json);
    void GetBleAdvertiserDeviceInfo(cJSON *json);
    void GetBleCentralDeviceInfo(cJSON *json);
    void GetBleGattDeviceInfo(cJSON *json);
    void GetA2dpSrcDeviceInfo(cJSON *json);
    void GetA2dpSinkDeviceInfo(cJSON *json);
    void GetAvrCTDeviceInfo(cJSON *json);
    void GetAvrTGDeviceInfo(cJSON *json);
    void GetHfpAGDeviceInfo(cJSON *json);
    void GetHfpHFDeviceInfo(cJSON *json);
    void GetMapMseDeviceInfo(cJSON *json);
    void GetPbapPseDeviceInfo(cJSON *json);
    void GetHidHostDeviceInfo(cJSON *json);
    void GetOppDeviceInfo(cJSON *json);
    void GetPanDeviceInfo(cJSON *json);

    void GetGattDeviceInfo(cJSON *json, uint32_t gattId);

    typedef void (BtStatistic::*GetProfileDeviceInfo)(cJSON *);
    std::map<uint32_t, GetProfileDeviceInfo> getProfileDeviceInfoMap_;
    std::vector<int32_t> connectState_;
};
} // namespace SoftBus
} // namespace Communication

#endif // BT_STATISTIC_H