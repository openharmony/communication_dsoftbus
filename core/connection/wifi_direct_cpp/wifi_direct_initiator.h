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

#ifndef WIFI_DIRECT_INITIATOR_H
#define WIFI_DIRECT_INITIATOR_H

#include <list>
#include <functional>

namespace OHOS::SoftBus {
class WifiDirectInitiator {
public:
    static WifiDirectInitiator& GetInstance()
    {
        static WifiDirectInitiator instance;
        return instance;
    }

    using InitFuncion = std::function<void()>;

    void Init();
    void Add(const InitFuncion &function);

private:
    std::list<InitFuncion> functions_;
};
} // namespace OHOS::SoftBus
#endif
