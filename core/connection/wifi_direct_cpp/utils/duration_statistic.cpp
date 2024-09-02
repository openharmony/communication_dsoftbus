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

#include "duration_statistic.h"
#include "chrono"
#include "conn_log.h"

namespace OHOS::SoftBus {
uint64_t DurationStatistic::GetTime()
{
    auto now = std::chrono::system_clock::now();
    auto nowTimeMs = std::chrono::time_point_cast<std::chrono::milliseconds>(now);
    auto value = nowTimeMs.time_since_epoch();
    return static_cast<uint64_t>(value.count());
}

void DurationStatistic::Start(uint32_t requestId, const std::shared_ptr<DurationStatisticCalculator> &calculator)
{
    std::lock_guard lock(mutex_);
    calculators_.insert(std::make_pair(requestId, calculator));
}

void DurationStatistic::Record(uint32_t requestId, const std::string &event)
{
    std::lock_guard lock(mutex_);
    if (stateTimeMap_[requestId].find(event) != stateTimeMap_[requestId].end()) {
        stateTimeMap_[requestId][event] = GetTime();
    }
    stateTimeMap_[requestId].insert(std::make_pair(event, GetTime()));
}

void DurationStatistic::RecordReNegotiate(uint32_t requestId, bool flag)
{
    std::lock_guard lock(mutex_);
    reNegotiateFlagMap_.insert(std::make_pair(requestId, flag));
}

void DurationStatistic::End(uint32_t requestId)
{
    std::lock_guard lock(mutex_);
    if (calculators_[requestId] != nullptr) {
        calculators_[requestId]->CalculateAllEvent(requestId, stateTimeMap_[requestId]);
    }
}

void DurationStatistic::Clear(uint32_t requestId)
{
    std::lock_guard lock(mutex_);
    stateTimeMap_.erase(requestId);
    calculators_.erase(requestId);
    reNegotiateFlagMap_.erase(requestId);
}

void P2pCalculator::CalculateAllEvent(uint32_t requestId, std::map<std::string, uint64_t> records)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "p2p calculateEvent");
}

void DurationStatisticCalculatorFactory::Register(
    const OHOS::SoftBus::DurationStatisticCalculatorFactory::Creator &creator)
{
    creator_ = creator;
}

std::shared_ptr<DurationStatisticCalculator> DurationStatisticCalculatorFactory::NewInstance(
    enum WifiDirectConnectType type)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "enter");
    if (creator_ == nullptr) {
        return std::make_shared<P2pCalculator>(P2pCalculator::GetInstance());
    }
    return creator_(type);
}

std::map<std::string, uint64_t> DurationStatistic::GetStateTimeMapElement(uint32_t requestId)
{
    std::lock_guard lock(mutex_);
    return stateTimeMap_[requestId];
}

bool DurationStatistic::ReNegotiateFlag(uint32_t requestId)
{
    std::lock_guard lock(mutex_);
    if (reNegotiateFlagMap_.find(requestId) != reNegotiateFlagMap_.end()) {
        return true;
    }
    return false;
}
} // namespace OHOS::SoftBus