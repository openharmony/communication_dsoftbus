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
#ifndef WIFI_DIRECT_WORK_QUEUE_H
#define WIFI_DIRECT_WORK_QUEUE_H

#include <functional>
#include "message_handler.h"

namespace OHOS::SoftBus {
class WifiDirectWorkQueue {
public:
    using WorkFunction = std::function<void(void *data)>;
    struct Work {
        WorkFunction work;
        void *data;
    };

    WifiDirectWorkQueue();
    ~WifiDirectWorkQueue();

    void ScheduleDelayWork(const Work *work, uint64_t timeMs);
    void RemoveWork(const Work *work);

private:
    SoftBusHandler handler_ {};
};
}
#endif
