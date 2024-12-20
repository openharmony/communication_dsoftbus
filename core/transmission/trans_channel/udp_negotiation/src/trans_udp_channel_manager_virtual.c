/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "trans_udp_channel_manager.h"

#include "softbus_error_code.h"

int32_t TransGetUdpAppInfoByChannelId(int32_t channelId, AppInfo *appInfo)
{
    (void)channelId;
    (void)appInfo;
    return SOFTBUS_TRANS_UDP_PREPARE_APP_INFO_FAILED;
}