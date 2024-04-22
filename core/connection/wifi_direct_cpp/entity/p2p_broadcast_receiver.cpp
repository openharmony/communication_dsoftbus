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
#include "p2p_broadcast_receiver.h"

#include "conn_log.h"
#include "softbus_error_code.h"

namespace OHOS::SoftBus {
P2pBroadcast *P2pBroadcast::GetInstance()
{
    static P2pBroadcast instance;
    return &instance;
}

int P2pBroadcast::RegisterBroadcastListener(const BroadcastReceiverAction *actions, size_t size,
    const std::string &name, ListenerPriority priority, BroadcastListener listener)
{
    CONN_CHECK_AND_RETURN_RET_LOGE(actions, SOFTBUS_INVALID_PARAM, CONN_WIFI_DIRECT, "action is null");
    CONN_CHECK_AND_RETURN_RET_LOGE(listener, SOFTBUS_INVALID_PARAM, CONN_WIFI_DIRECT, "listener is null");

    for (size_t i = 0; i < size; i++) {
        BroadcastReceiverAction action = actions[i];
        ActionListener actionListener {};
        actionListener.priority = priority;
        actionListener.listener = listener;
        actionListener.name = name;
        listenerMap_[action].push_back(actionListener);
    }
    return SOFTBUS_OK;
}

void P2pBroadcast::DispatchWorkHandler(BroadcastReceiverAction action, const BroadcastParam &param)
{
    auto it = listenerMap_.find(action);
    if (it == listenerMap_.end()) {
        CONN_LOGE(CONN_WIFI_DIRECT, "listener not find, action=%{public}d", static_cast<int>(action));
        return;
    }

    std::vector<ActionListener> listeners = it->second;
    for (auto priority = static_cast<int32_t>(ListenerPriority::LISTENER_PRIORITY_HIGH);
         priority >= static_cast<int32_t>(ListenerPriority::LISTENER_PRIORITY_LOW); priority--) {
        for (auto &listener : listeners) {
            if (static_cast<int32_t>(listener.priority) == priority && listener.listener) {
                listener.listener(action, param);
            }
        }
    }
}

} // namespace OHOS::SoftBus
