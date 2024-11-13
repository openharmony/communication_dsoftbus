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

#include "disc_ble_dispatcher.h"
#include "disc_manager.h"
#include "disc_share_ble.h"
#include "softbus_error_code.h"

static int32_t Publish(const PublishOption *option)
{
    return SOFTBUS_NOT_IMPLEMENT;
}

static int32_t StartScan(const PublishOption *option)
{
    return SOFTBUS_NOT_IMPLEMENT;
}

static int32_t Unpublish(const PublishOption *option)
{
    return SOFTBUS_NOT_IMPLEMENT;
}

static int32_t StopScan(const PublishOption *option)
{
    return SOFTBUS_NOT_IMPLEMENT;
}

static int32_t StartAdvertise(const SubscribeOption *option)
{
    return SOFTBUS_NOT_IMPLEMENT;
}

static int32_t Subscribe(const SubscribeOption *option)
{
    return SOFTBUS_NOT_IMPLEMENT;
}

static int32_t Unsubscribe(const SubscribeOption *option)
{
    return SOFTBUS_NOT_IMPLEMENT;
}

static int32_t StopAdvertise(const SubscribeOption *option)
{
    return SOFTBUS_NOT_IMPLEMENT;
}

static void LinkStatusChanged(LinkStatus status)
{
    return;
}

static void UpdateLocalDeviceInfo(InfoTypeChanged type)
{
    return;
}

static bool IsConcern(uint32_t capability)
{
    return false;
}

static DiscoveryFuncInterface g_fun = {
    .Publish = Publish,
    .StartScan = StartScan,
    .Unpublish = Unpublish,
    .StopScan = StopScan,
    .StartAdvertise = StartAdvertise,
    .Subscribe = Subscribe,
    .Unsubscribe = Unsubscribe,
    .StopAdvertise = StopAdvertise,
    .LinkStatusChanged = LinkStatusChanged,
    .UpdateLocalDeviceInfo = UpdateLocalDeviceInfo,
};

static DiscoveryBleDispatcherInterface g_sharebleInterface = {
    .IsConcern = IsConcern,
    .mediumInterface = &g_fun,
};

DiscoveryBleDispatcherInterface *DiscShareBleInit(DiscInnerCallback *discInnerCb)
{
    (void)discInnerCb;
    return &g_sharebleInterface;
}

void DiscShareBleDeinit(void)
{
    return;
}
