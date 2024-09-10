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

#include <mutex>
#include <shared_mutex>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include "wifi_direct_types.h"

namespace OHOS::SoftBus {
static constexpr const char *TOTAL_START = "TotalStart";
static constexpr const char *TOTAL_END = "TotalEnd";
static constexpr const char *TOTAL_DURATION = "TotalDuration";
static constexpr const char *CREATE_GROUP_START = "CreateGroupStart";
static constexpr const char *CREATE_GROUP_END = "CreateGroupEnd";
static constexpr const char *CONNECT_GROUP_START = "ConnectGroupStart";
static constexpr const char *CONNECT_GROUP_END = "ConnectGroupEnd";

class DurationStatisticCalculator {
public:
    virtual void CalculateAllEvent(uint32_t requestId, std::map<std::string, uint64_t> records) = 0;
};

class P2pCalculator : public DurationStatisticCalculator {
public:
    virtual ~P2pCalculator() = default;

    static P2pCalculator &GetInstance()
    {
        static P2pCalculator instance;
        return instance;
    }

    void CalculateAllEvent(uint32_t requestId, std::map<std::string, uint64_t> records) override;
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

    void Start(uint32_t requestId, const std::shared_ptr<DurationStatisticCalculator> &calculator);
    void Record(uint32_t requestId, const std::string &event);
    void RecordReNegotiate(uint32_t requestId, bool flag);
    void End(uint32_t requestId);
    void Clear(uint32_t requestId);
    std::map<std::string, uint64_t> GetStateTimeMapElement(uint32_t requestId);
    bool ReNegotiateFlag(uint32_t requestId);

private:
    static uint64_t GetTime();
    std::map<uint32_t, std::map<std::string, uint64_t>> stateTimeMap_;
    std::map<uint32_t, bool> reNegotiateFlagMap_;
    std::map<uint32_t, std::shared_ptr<DurationStatisticCalculator>> calculators_;

    std::recursive_mutex mutex_;
};

} // namespace OHOS::SoftBus

#endif