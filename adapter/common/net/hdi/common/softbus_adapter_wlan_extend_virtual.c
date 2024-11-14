/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "softbus_adapter_wlan_extend.h"
#include "softbus_error_code.h"

int32_t SoftBusRegWlanChannelInfoCb(WlanChannelInfoCb *cb)
{
    (void)cb;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t SoftBusRequestWlanChannelInfo(int32_t *channelId, uint32_t num)
{
    (void)channelId;
    (void)num;
    return SOFTBUS_NOT_IMPLEMENT;
}
