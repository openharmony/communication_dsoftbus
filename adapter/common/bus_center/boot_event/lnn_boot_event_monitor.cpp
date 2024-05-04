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

#include <cstring>

#include "auth_interface.h"
#include "lnn_async_callback_utils.h"
#include "lnn_event_monitor_impl.h"
#include "lnn_fast_offline.h"
#include "lnn_heartbeat_strategy.h"
#include "lnn_log.h"
#include "lnn_ohos_account.h"
#include "softbus_error_code.h"
#include "parameter.h"

#define BOOTEVENT_ACCOUNT_READY "bootevent.account.ready"

static void ProcessBootEvent(void *para)
{
    (void)para;
    LnnUpdateOhosAccount();
    if (LnnIsDefaultOhosAccount() && !IsAuthHasTrustedRelation()) {
        LNN_LOGE(LNN_EVENT, "not trusted releation, heartbeat(HB) process start later");
        return;
    }
    EhLoginEventHandler();
    LnnStartHeartbeat(0);
}

static void AccountBootEventCb(const char *key, const char *value, void *context)
{
    (void)context;
    LNN_LOGI(LNN_EVENT, "start account boot event");
    if (strcmp(key, BOOTEVENT_ACCOUNT_READY) == 0 && strcmp(value, "true") == 0) {
        if (LnnAsyncCallbackDelayHelper(GetLooper(LOOP_TYPE_DEFAULT), ProcessBootEvent, NULL, 0) != SOFTBUS_OK) {
            LNN_LOGE(LNN_EVENT, "async call boot event fail");
        }
    }
}

int32_t LnnInitBootEventMonitorImpl(void)
{
    int32_t ret = WatchParameter("bootevent.account.ready", AccountBootEventCb, NULL);
    if (ret != 0) {
        LNN_LOGE(LNN_EVENT, "watch account server fail");
    }
    return ret;
}
