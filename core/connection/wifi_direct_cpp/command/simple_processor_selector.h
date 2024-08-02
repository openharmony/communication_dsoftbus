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

#ifndef SIMPLE_PROCESSOR_SELECTOR_H
#define SIMPLE_PROCESSOR_SELECTOR_H

#include "processor_selector.h"

namespace OHOS::SoftBus {
class SimpleProcessorSelector : public ProcessorSelector {
public:
    std::shared_ptr<WifiDirectProcessor> operator()(const WifiDirectConnectInfo &info) override;
    std::shared_ptr<WifiDirectProcessor> operator()(const WifiDirectDisconnectInfo &info) override;
    std::shared_ptr<WifiDirectProcessor> operator()(const WifiDirectForceDisconnectInfo &info) override;
    std::shared_ptr<WifiDirectProcessor> operator()(NegotiateMessage &msg) override;
    std::shared_ptr<WifiDirectProcessor> operator()(
        const char *remoteNetworkId, enum WifiDirectLinkType linkType) override;
};
}
#endif
