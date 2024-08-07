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
#include "command_factory.h"

namespace OHOS::SoftBus {
CommandFactory& CommandFactory::GetInstance()
{
    static CommandFactory instance;
    return instance;
}

std::shared_ptr<ConnectCommand> CommandFactory::CreateConnectCommand(const WifiDirectConnectInfo &info,
                                                                     const WifiDirectConnectCallback &callback)
{
    if (connectCreator_ == nullptr) {
        return std::make_shared<ConnectCommand>(info, callback);
    }
    return connectCreator_(info, callback);
}

std::shared_ptr<DisconnectCommand> CommandFactory::CreateDisconnectCommand(const WifiDirectDisconnectInfo &info,
                                                                           const WifiDirectDisconnectCallback &callback)
{
    if (disconnectCreator_ == nullptr) {
        return std::make_shared<DisconnectCommand>(info, callback);
    }
    return disconnectCreator_(info, callback);
}

std::shared_ptr<ForceDisconnectCommand> CommandFactory::CreateForceDisconnectCommand(
    const WifiDirectForceDisconnectInfo &info, const WifiDirectDisconnectCallback &callback)
{
    return std::make_shared<ForceDisconnectCommand>(info, callback);
}

void CommandFactory::Register(const ConnectCreator &creator)
{
    connectCreator_ = creator;
}

void CommandFactory::Register(const DisconnectCreator &creator)
{
    disconnectCreator_ = creator;
}
}

