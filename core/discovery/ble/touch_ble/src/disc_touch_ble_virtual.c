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

#include "disc_touch_ble.h"

#include "disc_manager.h"
#include "softbus_error_code.h"

static int32_t TouchBleStartActivePublish(const PublishOption *option)
{
    (void)option;
    return SOFTBUS_NOT_IMPLEMENT;
}

static int32_t TouchBleStartPassivePublish(const PublishOption *option)
{
    (void)option;
    return SOFTBUS_NOT_IMPLEMENT;
}

static int32_t TouchBleStopActivePublish(const PublishOption *option)
{
    (void)option;
    return SOFTBUS_NOT_IMPLEMENT;
}

static int32_t TouchBleStopPassivePublish(const PublishOption *option)
{
    (void)option;
    return SOFTBUS_NOT_IMPLEMENT;
}

static int32_t TouchBleStartActiveDiscovery(const SubscribeOption *option)
{
    (void)option;
    return SOFTBUS_NOT_IMPLEMENT;
}

static int32_t TouchBleStartPassiveDiscovery(const SubscribeOption *option)
{
    (void)option;
    return SOFTBUS_NOT_IMPLEMENT;
}

static int32_t TouchBleStopPassiveDiscovery(const SubscribeOption *option)
{
    (void)option;
    return SOFTBUS_NOT_IMPLEMENT;
}

static int32_t TouchBleStopActiveDiscovery(const SubscribeOption *option)
{
    (void)option;
    return SOFTBUS_NOT_IMPLEMENT;
}

static void TouchBleLinkStatusChanged(LinkStatus status)
{
    (void)status;
}

static void TouchBleUpdateLocalDeviceInfo(InfoTypeChanged type)
{
    (void)type;
}

static bool TouchBleIsConcern(uint32_t capability)
{
    (void)capability;
    return false;
}

static DiscoveryFuncInterface g_discTouchFuncInterface = {
    .Publish = TouchBleStartActivePublish,
    .StartScan = TouchBleStartPassivePublish,
    .Unpublish = TouchBleStopActivePublish,
    .StopScan = TouchBleStopPassivePublish,
    .StartAdvertise = TouchBleStartActiveDiscovery,
    .Subscribe = TouchBleStartPassiveDiscovery,
    .Unsubscribe = TouchBleStopPassiveDiscovery,
    .StopAdvertise = TouchBleStopActiveDiscovery,
    .LinkStatusChanged = TouchBleLinkStatusChanged,
    .UpdateLocalDeviceInfo = TouchBleUpdateLocalDeviceInfo
};

static DiscoveryBleDispatcherInterface g_touchBleInterface = {
    .IsConcern = TouchBleIsConcern,
    .mediumInterface = &g_discTouchFuncInterface,
};

DiscoveryBleDispatcherInterface *DiscTouchBleInit(DiscInnerCallback *discInnerCb)
{
    (void)discInnerCb;
    return &g_touchBleInterface;
}

void DiscTouchBleDeinit(void)
{
}

int32_t DiscTouchBleEventInit(void)
{
    return SOFTBUS_OK;
}

void DiscTouchBleEventDeinit(void)
{
}

