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

#include "processor_selector_factory.h"
#include "conn_log.h"
#include "simple_processor_selector.h"

namespace OHOS::SoftBus {
void ProcessorSelectorFactory::Register(const std::shared_ptr<ProcessorSelector> &selector)
{
    selector_ = selector;
}

std::shared_ptr<ProcessorSelector> ProcessorSelectorFactory::NewSelector()
{
    if (!selector_) {
        CONN_LOGI(CONN_WIFI_DIRECT, "simple processor selector");
        return std::make_shared<SimpleProcessorSelector>();
    }
    CONN_LOGI(CONN_WIFI_DIRECT, "complex processor selector");
    return selector_;
}
}
