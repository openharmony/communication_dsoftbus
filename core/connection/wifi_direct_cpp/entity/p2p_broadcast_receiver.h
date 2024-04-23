/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#ifndef P2P_BROADCAST_RECEIVER_H
#define P2P_BROADCAST_RECEIVER_H

#include <map>
#include <memory>
#include <string>

#include "kits/c/wifi_p2p.h"

#include "adapter/p2p_adapter.h"

namespace OHOS::SoftBus {
enum class BroadcastReceiverAction {
    BROADCAST_RECEIVER_ACTION_INVALID = -1,
    WIFI_P2P_STATE_CHANGED_ACTION = 0,
    WIFI_P2P_CONNECTION_CHANGED_ACTION = 1,
    BROADCAST_RECEIVER_ACTION_MAX,
};

enum class ListenerPriority {
    LISTENER_PRIORITY_LOW,
    LISTENER_PRIORITY_MIDDLE,
    LISTENER_PRIORITY_HIGH,
};

struct BroadcastParam {
    P2pState p2pState;

    WifiP2pLinkedInfo p2pLinkInfo;
    std::shared_ptr<P2pAdapter::WifiDirectP2pGroupInfo> groupInfo;
};
typedef void (*BroadcastListener)(enum BroadcastReceiverAction action, const struct BroadcastParam &param);

struct ActionListener {
    BroadcastListener listener;
    std::string name;
    enum ListenerPriority priority;
};

class P2pBroadcast {
public:
    static P2pBroadcast *GetInstance();
    int RegisterBroadcastListener(const BroadcastReceiverAction *actions, size_t size, const std::string &name,
        ListenerPriority priority, BroadcastListener listener);
    void DispatchWorkHandler(BroadcastReceiverAction action, const BroadcastParam &param);

private:
    std::map<BroadcastReceiverAction, std::vector<ActionListener>> listenerMap_;
};
} // namespace OHOS::SoftBus
#endif
