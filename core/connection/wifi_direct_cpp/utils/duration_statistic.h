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

#ifndef DURATION_STATISTIC_H
#define DURATION_STATISTIC_H

#include <functional>
#include <map>
#include <memory>
#include <string>
#include "wifi_direct_types.h"

namespace OHOS::SoftBus {
using DurationStatisticEvent = std::string;
const DurationStatisticEvent TotalStart("TotalStart");
const DurationStatisticEvent TotalEnd("TotalEnd");
const DurationStatisticEvent TotalDuration("TotalDuration");
const DurationStatisticEvent CreateGroupStart("CreateGroupStart");
const DurationStatisticEvent CreateGroupEnd("CreateGroupEnd");
const DurationStatisticEvent ConnectGroupStart("ConnectGroupStart");
const DurationStatisticEvent ConnectGroupEnd("ConnectGroupEnd");

class DurationStatisticCalculator {
public:
    virtual void CalculateAllEvent(uint32_t requestId, std::map<DurationStatisticEvent, uint64_t> records) = 0;
};

class P2pCalculator : public DurationStatisticCalculator {
public:
    virtual ~P2pCalculator() = default;

    static P2pCalculator &GetInstance()
    {
        static P2pCalculator instance;
        return instance;
    }

    void CalculateAllEvent(uint32_t requestId, std::map<DurationStatisticEvent, uint64_t> records) override;
};

class DurationStatisticCalculatorFactory {
public:
    static DurationStatisticCalculatorFactory &GetInstance()
    {
        static DurationStatisticCalculatorFactory instance;
        return instance;
    }

    std::shared_ptr<DurationStatisticCalculator> NewInstance(enum WifiDirectConnectType type);

    using Creator = std::function<std::shared_ptr<DurationStatisticCalculator>(enum WifiDirectConnectType type)>;
    void Register(const Creator &creator);

private:
    Creator creator_;
};

class DurationStatistic {
public:
    static DurationStatistic &GetInstance()
    {
        static DurationStatistic instance;
        return instance;
    }

    static uint64_t GetTime();
    std::map<uint32_t, std::map<DurationStatisticEvent, uint64_t>> stateTimeMap;
    std::map<uint32_t, std::shared_ptr<DurationStatisticCalculator>> calculators;

    void Start(uint32_t requestId, const std::shared_ptr<DurationStatisticCalculator> &calculator);
    void Record(uint32_t requestId, const DurationStatisticEvent &event);
    void End(uint32_t requestId);
    void Clear(uint32_t requestId);
};

} // namespace OHOS::SoftBus

#endif