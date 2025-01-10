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
#ifndef INTERFACE_MANAGER_H
#define INTERFACE_MANAGER_H

#include <functional>
#include <shared_mutex>

#include "data/interface_info.h"
#include "dfx/interface_snapshot.h"
#include "wifi_direct_initiator.h"

namespace OHOS::SoftBus {
class InterfaceManager {
public:
    static InterfaceManager& GetInstance()
    {
        static InterfaceManager instance;
        return instance;
    }

    using Updater = std::function<int(InterfaceInfo &)>;
    using Reader = std::function<int(const InterfaceInfo &)>;

    int UpdateInterface(InterfaceInfo::InterfaceType type, const Updater &updater);
    int ReadInterface(InterfaceInfo::InterfaceType type, const Reader &reader);

    bool IsInterfaceAvailable(InterfaceInfo::InterfaceType type, bool forShare) const;

    void LockInterface(InterfaceInfo::InterfaceType type, const std::string &owner);
    void UnlockInterface(InterfaceInfo::InterfaceType type);

    static void Init();
    void InitInterface(InterfaceInfo::InterfaceType type);

    void Dump(std::list<std::shared_ptr<InterfaceSnapshot>> &snapshots);

private:
    class Initiator {
    public:
        Initiator()
        {
            WifiDirectInitiator::GetInstance().Add(InterfaceManager::Init);
        }
    };

    struct ExclusiveHelper {
        std::shared_mutex lock_;
        std::string owner_;
    };

    static inline Initiator initiator_;

    mutable std::shared_mutex lock_;
    InterfaceInfo interfaces_[InterfaceInfo::MAX];
    ExclusiveHelper exclusives_[InterfaceInfo::MAX];
};
} // namespace OHOS::SoftBus
#endif
