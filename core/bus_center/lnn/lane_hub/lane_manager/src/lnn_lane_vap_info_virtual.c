/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "lnn_lane_vap_info.h"
#include "softbus_error_code.h"

int32_t LnnInitVapInfo(void)
{
    return SOFTBUS_NOT_IMPLEMENT;
}

void LnnDeinitVapInfo(void)
{
    return;
}

int32_t LnnAddLocalVapInfo(LnnVapType type, const LnnVapAttr *vapAttr)
{
    (void)type;
    (void)vapAttr;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnDeleteLocalVapInfo(LnnVapType type)
{
    (void)type;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnGetLocalVapInfo(LnnVapType type, LnnVapAttr *vapAttr)
{
    (void)type;
    (void)vapAttr;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnAddRemoteVapInfo(const char *udid, LnnVapType type, const LnnVapAttr *vapAttr)
{
    (void)udid;
    (void)type;
    (void)vapAttr;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnDeleteRemoteVapInfo(const char *udid)
{
    (void)udid;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnGetRemoteVapInfo(const char *udid, LnnVapType type, LnnVapAttr *vapAttr)
{
    (void)udid;
    (void)type;
    (void)vapAttr;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnGetLocalPreferChannel(void)
{
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnGetLocalChannelCode(void)
{
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnAddRemoteChannelCode(const char *udid, int32_t channelCode)
{
    (void)udid;
    (void)channelCode;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnGetRecommendChannel(const char *udid, int32_t *preferChannel)
{
    (void)udid;
    (void)preferChannel;
    return SOFTBUS_NOT_IMPLEMENT;
}