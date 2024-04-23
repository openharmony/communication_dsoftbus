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
#include "simple_processor_selector.h"

#include <memory>

#include "processor/p2p_v1_processor.h"
#include "data/link_manager.h"
#include "data/inner_link.h"

namespace OHOS::SoftBus {
std::shared_ptr<WifiDirectProcessor> SimpleProcessorSelector::operator()(const WifiDirectConnectInfo &info)
{
    return std::make_shared<P2pV1Processor>(info.remoteNetworkId);
}

std::shared_ptr<WifiDirectProcessor> SimpleProcessorSelector::operator()(const WifiDirectDisconnectInfo &info)
{
    auto innerLink = LinkManager::GetInstance().GetLinkById(info.linkId);
    auto remoteDeviceId = innerLink->GetRemoteDeviceId();
    return std::make_shared<P2pV1Processor>(remoteDeviceId);
}

std::shared_ptr<WifiDirectProcessor> SimpleProcessorSelector::operator()(NegotiateMessage &msg)
{
    return std::make_shared<P2pV1Processor>(msg.GetRemoteDeviceId());
}
}