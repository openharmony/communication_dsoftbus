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

#include "disc_virtual_link_ble.h"

#include "disc_manager.h"
#include "softbus_error_code.h"

static bool IsConcern(uint32_t capability)
{
    (void)capability;
    return false;
}

static int32_t StartSubscribe(const SubscribeOption *option)
{
    (void)option;
    return SOFTBUS_NOT_IMPLEMENT;
}

static int32_t StopSubscribe(const SubscribeOption *option)
{
    (void)option;
    return SOFTBUS_NOT_IMPLEMENT;
}

static int32_t StartPublish(const PublishOption *option)
{
    (void)option;
    return SOFTBUS_NOT_IMPLEMENT;
}

static int32_t StopPublish(const PublishOption *option)
{
    (void)option;
    return SOFTBUS_NOT_IMPLEMENT;
}

static int32_t StartScan(const PublishOption *option)
{
    (void)option;
    return SOFTBUS_NOT_IMPLEMENT;
}

static int32_t StopScan(const PublishOption *option)
{
    (void)option;
    return SOFTBUS_NOT_IMPLEMENT;
}

static int32_t StartAdvertise(const SubscribeOption *option)
{
    (void)option;
    return SOFTBUS_NOT_IMPLEMENT;
}

static int32_t StopAdvertise(const SubscribeOption *option)
{
    (void)option;
    return SOFTBUS_NOT_IMPLEMENT;
}

static void LinkStatusChanged(LinkStatus status)
{
    (void)status;
}

static void UpdateLocalDeviceInfo(InfoTypeChanged type)
{
    (void)type;
}

static DiscoveryFuncInterface g_discVLinkInterface = {
    .Subscribe = StartSubscribe,
    .Unsubscribe = StopSubscribe,
    .Publish = StartPublish,
    .Unpublish = StopPublish,
    .StartScan = StartScan,
    .StopScan = StopScan,
    .StartAdvertise = StartAdvertise,
    .StopAdvertise = StopAdvertise,
    .LinkStatusChanged = LinkStatusChanged,
    .UpdateLocalDeviceInfo = UpdateLocalDeviceInfo
};

static DiscoveryBleDispatcherInterface g_vLinkBleInterface = {
    .IsConcern = IsConcern,
    .mediumInterface = &g_discVLinkInterface,
};

DiscoveryBleDispatcherInterface *DiscVLinkBleInit(DiscInnerCallback *discInnerCb)
{
    (void)discInnerCb;
    return &g_vLinkBleInterface;
}

void DiscVLinkBleDeinit(void)
{
}

int32_t DiscVLinkBleEventInit(void)
{
    return SOFTBUS_OK;
}

void DiscVLinkBleEventDeinit(void)
{
}
