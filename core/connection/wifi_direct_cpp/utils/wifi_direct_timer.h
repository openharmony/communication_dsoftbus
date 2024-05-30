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

#ifndef WIFI_DIRECT_TIMER_H
#define WIFI_DIRECT_TIMER_H

#include <functional>
#include <string>
#include <memory>
#include <map>
#include <mutex>
#include "wifi_direct_work_queue.h"

namespace OHOS::SoftBus {
class WifiDirectTimer {
public:
    static constexpr int TIMER_ID_INVALID = -1;
    using TimerCallback = std::function<void()>;
    struct TimerDescriptor {
        int32_t timerId;
        WifiDirectWorkQueue::Work *work;
        TimerCallback callback;
    };

    explicit WifiDirectTimer(const std::string &name);
    ~WifiDirectTimer();

    int32_t Register(const TimerCallback &callback, int32_t timeout);
    void Unregister(int32_t timerId);

private:
    std::string name_;

    static int32_t AllocTimerId();
    static void WorkHandler(void *data);

    static inline int32_t timerId_ = 0;
    static inline int32_t timerCount_ = 0;
    static inline std::mutex timerIdMapLock_;
    static inline std::map<int32_t, TimerDescriptor*> timerIdMap_;
    static inline std::shared_ptr<WifiDirectWorkQueue> workQueue_;
};
}
#endif
