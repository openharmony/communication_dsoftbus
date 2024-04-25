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
#include "wifi_direct_initiator.h"

namespace OHOS::SoftBus {
void WifiDirectInitiator::Init()
{
    for (const auto &function : functions_) {
        function();
    }
}

void WifiDirectInitiator::Add(const InitFuncion &function)
{
    functions_.push_back(function);
}
} // namespace OHOS::SoftBus