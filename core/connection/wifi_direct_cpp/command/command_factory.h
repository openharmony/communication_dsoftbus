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

#ifndef COMMAND_FACTORY_H
#define COMMAND_FACTORY_H

#include <functional>
#include <memory>
#include "connect_command.h"

namespace OHOS::SoftBus {
class CommandFactory {
public:
    static CommandFactory& GetInstance();
    std::shared_ptr<ConnectCommand> CreateConnectCommand(const WifiDirectConnectInfo &info,
                                                         const WifiDirectConnectCallback &callback);
    using Creator = std::function<std::shared_ptr<ConnectCommand>(const WifiDirectConnectInfo&,
                                                                  const WifiDirectConnectCallback&)>;
    void Register(const Creator &creator);

private:
    Creator creator_;
};
}
#endif
