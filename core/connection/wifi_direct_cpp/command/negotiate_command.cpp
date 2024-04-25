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

#include "negotiate_command.h"
#include "conn_log.h"
#include "softbus_error_code.h"
#include "processor_selector_factory.h"

namespace OHOS::SoftBus {
NegotiateCommand::NegotiateCommand(const NegotiateMessage &msg, const std::shared_ptr<NegotiateChannel> &channel)
    : msg_(msg), channel_(channel)
{
}

std::string NegotiateCommand::GetRemoteDeviceId() const
{
    return channel_->GetRemoteDeviceId();
}

std::shared_ptr<WifiDirectProcessor> NegotiateCommand::GetProcessor()
{
    auto selector = ProcessorSelectorFactory::GetInstance().NewSelector();
    return (*selector)(msg_);
}

NegotiateMessage NegotiateCommand::GetNegotiateMessage()
{
    return msg_;
}

std::shared_ptr<NegotiateChannel> NegotiateCommand::GetNegotiateChannel()
{
    return channel_;
}
}

