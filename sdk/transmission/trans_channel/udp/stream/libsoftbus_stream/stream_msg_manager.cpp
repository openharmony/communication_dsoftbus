/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "stream_msg_manager.h"

namespace Communication {
namespace SoftBus {
#ifdef SOFTBUS
std::shared_ptr<IStreamMsgManager> IStreamMsgManager::GetInstance(std::shared_ptr<IChannel> channel)
{
    auto tmp = std::make_shared<StreamMsgManager>();
    tmp->SetChannel(channel);
    return tmp;
}
#endif

bool StreamMsgManager::Send(const HistoryStats &stats)
{
    static_cast<void>(stats);
    return false;
}

void StreamMsgManager::Update(const HistoryStats &stats)
{
    historyStatsSet_.push_back(stats);
}

void StreamMsgManager::Recv(const HistoryStats &stats)
{
    static_cast<void>(stats);
}
} // namespace SoftBus
} // namespace Communication
