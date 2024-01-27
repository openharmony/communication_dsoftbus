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

#include "wifi_direct_initiator.h"
#include "softbus_error_code.h"
#include "wifi_direct_manager.h"
#include "wifi_direct_negotiator.h"
#include "broadcast_receiver.h"
#include "broadcast_handler.h"
#include "conn_log.h"
#include "channel/default_negotiate_channel.h"
#include "channel/fast_connect_negotiate_channel.h"
#include "data/resource_manager.h"
#include "data/link_manager.h"
#include "utils/wifi_direct_timer_list.h"
#include "utils/wifi_direct_work_queue.h"

typedef int32_t (*WifiDirectSubInitFunc)(void);

static WifiDirectSubInitFunc g_subInitFunctions[] = {
    WifiDirectWorkQueueInit,
    WifiDirectTimerListInit,
    DefaultNegotiateChannelInit,
    FastConnectNegotiateChannelInit,
    BroadcastReceiverInit,
    ResourceManagerInit,
    LinkManagerInit,
    BroadcastHandlerInit,
    WifiDirectManagerInit,
    WifiDirectNegotiatorInit,
};

int32_t WifiDirectInit(void)
{
    bool hasFailure = false;
    for (size_t i = 0; i < ARRAY_SIZE(g_subInitFunctions); i++) {
        if (g_subInitFunctions[i]() == SOFTBUS_OK) {
            CONN_LOGI(CONN_INIT, "init success. i=%{public}zu ", i);
            continue;
        }
        CONN_LOGE(CONN_INIT, "init failed. i=%{public}zu", i);
        hasFailure = true;
    }

    if (hasFailure == false) {
        CONN_LOGI(CONN_INIT, "all init success");
    }
    return SOFTBUS_OK;
}