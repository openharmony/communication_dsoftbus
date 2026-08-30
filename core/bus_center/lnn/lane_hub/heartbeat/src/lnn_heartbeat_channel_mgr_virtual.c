/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "lnn_heartbeat_channel_mgr.h"
#include "softbus_error_code.h"

int32_t LnnHbChannelMgrInit(void)
{
    return SOFTBUS_OK;
}

void LnnHbChannelMgrDeinit(void)
{
}

int32_t LnnHbChannelEnable(LnnHeartbeatChannel channel, bool enable)
{
    (void)channel;
    (void)enable;
    return SOFTBUS_OK;
}

bool LnnHbChannelIsEnabled(LnnHeartbeatChannel channel)
{
    (void)channel;
    return false;
}

int32_t LnnHbChannelSetUserId(LnnHeartbeatChannel channel, int32_t userId)
{
    (void)channel;
    (void)userId;
    return SOFTBUS_OK;
}

int32_t LnnHbChannelGetUserId(LnnHeartbeatChannel channel, int32_t *userId)
{
    (void)channel;
    (void)userId;
    return SOFTBUS_OK;
}