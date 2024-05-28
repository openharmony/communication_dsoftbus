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

#include "wifi_direct_trace.h"

#include "hitrace/trace.h"

namespace OHOS::SoftBus {
static constexpr uint32_t TRACE_ID_OFFSET = 32;

static uint64_t ConvertTraceChainId(const std::string &requestDeviceId, const std::string &receiveDeviceId)
{
    uint32_t request = 0;
    for (auto c : requestDeviceId) {
        request += c;
    }

    uint32_t receiver = 0;
    for (auto c : receiveDeviceId) {
        receiver += c;
    }

    uint64_t chainID = request;
    chainID = chainID << TRACE_ID_OFFSET | receiver;
    return chainID;
}

void WifiDirectTrace::StartTrace(const std::string &requestDeviceId, const std::string &receiverDeviceId)
{
    uint64_t chainId = ConvertTraceChainId(requestDeviceId, receiverDeviceId);
    auto traceId = OHOS::HiviewDFX::HiTraceChain::Begin("", 0);
    traceId.SetChainId(chainId);
    traceId.SetSpanId(0);
    OHOS::HiviewDFX::HiTraceChain::SetId(traceId);
}

void WifiDirectTrace::StopTrace()
{
    auto traceId = OHOS::HiviewDFX::HiTraceChain::GetId();
    OHOS::HiviewDFX::HiTraceChain::End(traceId);
}

void WifiDirectTrace::SetRequestId(uint64_t requestId)
{
    auto traceId = OHOS::HiviewDFX::HiTraceChain::GetId();
    traceId.SetSpanId(requestId);
    OHOS::HiviewDFX::HiTraceChain::SetId(traceId);
}

} // namespace OHOS::SoftBus
