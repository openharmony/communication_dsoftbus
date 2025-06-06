/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "disc_oop_ble.h"

#include "disc_manager.h"
#include "softbus_error_code.h"

static int32_t OopBleStartActivePublish(const PublishOption *option)
{
    (void)option;
    return SOFTBUS_NOT_IMPLEMENT;
}

static int32_t OopBleStartPassivePublish(const PublishOption *option)
{
    (void)option;
    return SOFTBUS_NOT_IMPLEMENT;
}

static int32_t OopBleStopActivePublish(const PublishOption *option)
{
    (void)option;
    return SOFTBUS_NOT_IMPLEMENT;
}

static int32_t OopBleStopPassivePublish(const PublishOption *option)
{
    (void)option;
    return SOFTBUS_NOT_IMPLEMENT;
}

static int32_t OopBleStartActiveDiscovery(const SubscribeOption *option)
{
    (void)option;
    return SOFTBUS_NOT_IMPLEMENT;
}

static int32_t OopBleStartPassiveDiscovery(const SubscribeOption *option)
{
    (void)option;
    return SOFTBUS_NOT_IMPLEMENT;
}

static int32_t OopBleStopPassiveDiscovery(const SubscribeOption *option)
{
    (void)option;
    return SOFTBUS_NOT_IMPLEMENT;
}

static int32_t OopBleStopActiveDiscovery(const SubscribeOption *option)
{
    (void)option;
    return SOFTBUS_NOT_IMPLEMENT;
}

static void OopBleLinkStatusChanged(LinkStatus status, int32_t ifnameIdx)
{
    (void)status;
    (void)ifnameIdx;
}

static void OopBleUpdateLocalDeviceInfo(InfoTypeChanged type)
{
    (void)type;
}

static bool OopBleIsConcern(uint32_t capability)
{
    (void)capability;
    return false;
}

static DiscoveryFuncInterface g_discOopFuncInterface = {
    .Publish = OopBleStartActivePublish,
    .StartScan = OopBleStartPassivePublish,
    .Unpublish = OopBleStopActivePublish,
    .StopScan = OopBleStopPassivePublish,
    .StartAdvertise = OopBleStartActiveDiscovery,
    .Subscribe = OopBleStartPassiveDiscovery,
    .Unsubscribe = OopBleStopPassiveDiscovery,
    .StopAdvertise = OopBleStopActiveDiscovery,
    .LinkStatusChanged = OopBleLinkStatusChanged,
    .UpdateLocalDeviceInfo = OopBleUpdateLocalDeviceInfo
};

static DiscoveryBleDispatcherInterface g_touchBleInterface = {
    .IsConcern = OopBleIsConcern,
    .mediumInterface = &g_discOopFuncInterface,
};

DiscoveryBleDispatcherInterface *DiscOopBleInit(DiscInnerCallback *discInnerCb)
{
    (void)discInnerCb;
    return &g_touchBleInterface;
}

void DiscOopBleDeinit(void)
{
}

int32_t DiscOopBleEventInit(void)
{
    return SOFTBUS_OK;
}

void DiscOopBleEventDeinit(void)
{
}

