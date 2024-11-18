/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "disc_approach_ble.h"

#include "disc_manager.h"
#include "softbus_error_code.h"

static int32_t ApproachBleStartActivePublish(const PublishOption *option)
{
    (void)option;
    return SOFTBUS_NOT_IMPLEMENT;
}

static int32_t ApproachBleStartPassivePublish(const PublishOption *option)
{
    (void)option;
    return SOFTBUS_NOT_IMPLEMENT;
}

static int32_t ApproachBleStopActivePublish(const PublishOption *option)
{
    (void)option;
    return SOFTBUS_NOT_IMPLEMENT;
}

static int32_t ApproachBleStopPassivePublish(const PublishOption *option)
{
    (void)option;
    return SOFTBUS_NOT_IMPLEMENT;
}

static int32_t ApproachBleStartActiveDiscovery(const SubscribeOption *option)
{
    (void)option;
    return SOFTBUS_NOT_IMPLEMENT;
}

static int32_t ApproachBleStartPassiveDiscovery(const SubscribeOption *option)
{
    (void)option;
    return SOFTBUS_NOT_IMPLEMENT;
}

static int32_t ApproachBleStopPassiveDiscovery(const SubscribeOption *option)
{
    (void)option;
    return SOFTBUS_NOT_IMPLEMENT;
}

static int32_t ApproachBleStopActiveDiscovery(const SubscribeOption *option)
{
    (void)option;
    return SOFTBUS_NOT_IMPLEMENT;
}

static void ApproachBleLinkStatusChanged(LinkStatus status)
{
    (void)status;
}

static void ApproachBleUpdateLocalDeviceInfo(InfoTypeChanged type)
{
    (void)type;
}

static bool ApproachBleIsConcern(uint32_t capability)
{
    (void)capability;
    return false;
}

static DiscoveryFuncInterface g_discApproachFuncInterface = {
    .Publish = ApproachBleStartActivePublish,
    .StartScan = ApproachBleStartPassivePublish,
    .Unpublish = ApproachBleStopActivePublish,
    .StopScan = ApproachBleStopPassivePublish,
    .StartAdvertise = ApproachBleStartActiveDiscovery,
    .Subscribe = ApproachBleStartPassiveDiscovery,
    .Unsubscribe = ApproachBleStopPassiveDiscovery,
    .StopAdvertise = ApproachBleStopActiveDiscovery,
    .LinkStatusChanged = ApproachBleLinkStatusChanged,
    .UpdateLocalDeviceInfo = ApproachBleUpdateLocalDeviceInfo
};

static DiscoveryBleDispatcherInterface g_approachBleInterface = {
    .IsConcern = ApproachBleIsConcern,
    .mediumInterface = &g_discApproachFuncInterface,
};

DiscoveryBleDispatcherInterface *DiscApproachBleInit(DiscInnerCallback *discInnerCb)
{
    (void)discInnerCb;
    return &g_approachBleInterface;
}

void DiscApproachBleDeinit(void)
{
}

int32_t DiscApproachBleEventInit(void)
{
    return SOFTBUS_OK;
}

void DiscApproachBleEventDeinit(void)
{
}

