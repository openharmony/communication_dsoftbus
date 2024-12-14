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

#include "disc_ble.h"

#include "disc_manager.h"
#include "softbus_error_code.h"

static int32_t BleStartActivePublish(const PublishOption *option)
{
    (void)option;
    return SOFTBUS_NOT_IMPLEMENT;
}

static int32_t BleStartPassivePublish(const PublishOption *option)
{
    (void)option;
    return SOFTBUS_NOT_IMPLEMENT;
}

static int32_t BleStopActivePublish(const PublishOption *option)
{
    (void)option;
    return SOFTBUS_NOT_IMPLEMENT;
}

static int32_t BleStopPassivePublish(const PublishOption *option)
{
    (void)option;
    return SOFTBUS_NOT_IMPLEMENT;
}

static int32_t BleStartActiveDiscovery(const SubscribeOption *option)
{
    (void)option;
    return SOFTBUS_NOT_IMPLEMENT;
}

static int32_t BleStartPassiveDiscovery(const SubscribeOption *option)
{
    (void)option;
    return SOFTBUS_NOT_IMPLEMENT;
}

static int32_t BleStopPassiveDiscovery(const SubscribeOption *option)
{
    (void)option;
    return SOFTBUS_NOT_IMPLEMENT;
}

static int32_t BleStopActiveDiscovery(const SubscribeOption *option)
{
    (void)option;
    return SOFTBUS_NOT_IMPLEMENT;
}

static void BleLinkStatusChanged(LinkStatus status)
{
    (void)status;
}

static void BleUpdateLocalDeviceInfo(InfoTypeChanged type)
{
    (void)type;
}

static bool BleIsConcern(uint32_t capability)
{
    (void)capability;
    return false;
}

static DiscoveryFuncInterface g_discBleFuncInterface = {
    .Publish = BleStartActivePublish,
    .StartScan = BleStartPassivePublish,
    .Unpublish = BleStopActivePublish,
    .StopScan = BleStopPassivePublish,
    .StartAdvertise = BleStartActiveDiscovery,
    .Subscribe = BleStartPassiveDiscovery,
    .Unsubscribe = BleStopPassiveDiscovery,
    .StopAdvertise = BleStopActiveDiscovery,
    .LinkStatusChanged = BleLinkStatusChanged,
    .UpdateLocalDeviceInfo = BleUpdateLocalDeviceInfo
};

static DiscoveryBleDispatcherInterface g_discBleDispatcherInterface = {
    .IsConcern = BleIsConcern,
    .mediumInterface = &g_discBleFuncInterface,
};

DiscoveryBleDispatcherInterface *DiscSoftBusBleInit(DiscInnerCallback *callback)
{
    (void)callback;
    return &g_discBleDispatcherInterface;
}

void DiscSoftBusBleDeinit(void)
{
}