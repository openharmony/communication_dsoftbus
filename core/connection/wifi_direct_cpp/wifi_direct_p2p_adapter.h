/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef WIFI_DIRECT_P2P_ADAPTER_H
#define WIFI_DIRECT_P2P_ADAPTER_H

#include <mutex>
#include <string>

#include "p2p_broadcast_receiver.h"
#include "softbus_bus_center.h"
#include "wifi_direct_initiator.h"

namespace OHOS::SoftBus {
class WifiDirectP2pAdapter {
public:
    static WifiDirectP2pAdapter *GetInstance();
    static void Init();
    
    int32_t ConnCreateGoOwner(const char *pkgName, const struct GroupOwnerConfig *config,
        struct GroupOwnerResult *result, GroupOwnerDestroyListener listener);
    void ConnDestroyGoOwner(const char *pkgName);
    static void Listener(BroadcastReceiverAction action, const struct BroadcastParam &param);

private:
    class Initiator {
    public:
        Initiator()
        {
            WifiDirectInitiator::GetInstance().Add(WifiDirectP2pAdapter::Init);
        }
    };

    static inline Initiator initiator_;

    static int SetGroupOwnerResult(std::string groupConfig, struct GroupOwnerResult *result);
    static int CreateGroup(struct GroupOwnerResult *result);
    static int RemoveGroup();
    static int RemoveGroupNotAddReuse();
    static int ReuseP2p();
    static int ReuseGroup(struct GroupOwnerResult *result);

    static inline GroupOwnerDestroyListener groupOwnerDestroyListener_;
    static inline bool isCreateGroup_;
    static inline std::recursive_mutex mutex_;
    static constexpr const char *GROUP_OWNER = "share";
};
} // namespace OHOS::SoftBus
#endif