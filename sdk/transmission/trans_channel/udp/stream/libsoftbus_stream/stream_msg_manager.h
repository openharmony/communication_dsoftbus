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

#ifndef CB_MANAGER_H
#define CB_MANAGER_H

#include <vector>

#include "common_inner.h"
#include "i_stream_msg_manager.h"
#include "stream_common.h"

namespace Communication {
namespace SoftBus {
class StreamMsgManager : public std::enable_shared_from_this<StreamMsgManager>, public IStreamMsgManager {
public:
    StreamMsgManager() = default;
    ~StreamMsgManager() override = default;

    bool Send(const HistoryStats &stats);
    void Recv(const HistoryStats &stats);

    void Update(const HistoryStats &stats);

private:
    std::vector<HistoryStats> historyStatsSet_ = {};
};
} // namespace SoftBus
} // namespace Communication

#endif
