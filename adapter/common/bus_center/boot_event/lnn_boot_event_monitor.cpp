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
#include "bus_center_manager.h"
#include "g_enhance_lnn_func.h"
#include "g_enhance_lnn_func_pack.h"
#include "lnn_async_callback_utils.h"
#include "lnn_event_monitor_impl.h"
#include "lnn_heartbeat_strategy.h"
#include "lnn_log.h"
#include "lnn_ohos_account.h"
#include "parameter.h"
#include "lnn_init_monitor.h"
#include "softbus_init_common.h"

static int32_t ProcessBootEvent(void)
{
    uint8_t userIdCheckSum[USERID_CHECKSUM_LEN];
    LNN_LOGI(LNN_EVENT, "start process account ready event");
    LnnUpdateOhosAccount(UPDATE_HEARTBEAT);
    int32_t userId = GetActiveOsAccountIds();
    LNN_LOGI(LNN_EVENT, "get userId:%{public}d", userId);
    int32_t ret = LnnSetLocalNumInfo(NUM_KEY_USERID, userId);
    if (ret != SOFTBUS_OK) {
        LNN_LOGW(LNN_EVENT, "set userId failed");
    }
    ret = HbBuildUserIdCheckSumPacked(&userId, 1, userIdCheckSum, USERID_CHECKSUM_LEN);
    if (ret != SOFTBUS_OK) {
        LNN_LOGW(LNN_EVENT, "get userIdCheckSum failed");
    }
    ret = LnnSetLocalByteInfo(BYTE_KEY_USERID_CHECKSUM, userIdCheckSum, USERID_CHECKSUM_LEN);
    if (ret != SOFTBUS_OK) {
        LNN_LOGW(LNN_EVENT, "set userIdChecksum to local failed");
    }
    if (LnnIsDefaultOhosAccount() && !IsAuthHasTrustedRelation()) {
        LNN_LOGE(LNN_EVENT, "not trusted releation, heartbeat(HB) process start later");
        return SOFTBUS_EVENT_MONITER_INIT_FAILED;
    }
    if (!LnnIsDefaultOhosAccount()) {
        LnnNotifyAccountStateChangeEvent(SOFTBUS_ACCOUNT_LOG_IN);
    }
    EhLoginEventHandlerPacked();
    LnnStartHeartbeat(0);
    return SOFTBUS_OK;
}

static void AccountBootEventCb(const char *key, const char *value, void *context)
{
    (void)context;
    LNN_LOGI(LNN_EVENT, "start account boot event, value=%{public}s", value);
    if (strcmp(key, BOOTEVENT_ACCOUNT_READY) == 0 && strcmp(value, "true") == 0) {
        if (LnnInitModuleNotifyWithRetryAsync(INIT_DEPS_PROCESS_BOOT, ProcessBootEvent, 0, 0, true) != SOFTBUS_OK) {
            LNN_LOGE(LNN_EVENT, "async call boot event fail");
        }
    }
}

int32_t LnnInitBootEventMonitorImpl(void)
{
    int32_t ret = WatchParameter(BOOTEVENT_ACCOUNT_READY, AccountBootEventCb, NULL);
    if (ret != 0) {
        LNN_LOGE(LNN_EVENT, "watch account server fail");
    }
    return ret;
}

int32_t LnnSubscribeAccountBootEvent(AccountEventHandle handle)
{
    int32_t ret = WatchParameter(BOOTEVENT_ACCOUNT_READY, handle, NULL);
    if (ret != 0) {
        LNN_LOGE(LNN_EVENT, "watch account server fail");
    }
    return ret;
}
