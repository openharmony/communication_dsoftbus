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

#include "disc_manager.h"
#include "disc_usb.h"
#include "softbus_error_code.h"

static int32_t UsbDiscStartActivePublish(const PublishOption *option)
{
    (void)option;
    return SOFTBUS_NOT_IMPLEMENT;
}

static int32_t UsbDiscStartPassivePublish(const PublishOption *option)
{
    (void)option;
    return SOFTBUS_NOT_IMPLEMENT;
}

static int32_t UsbDiscStopActivePublish(const PublishOption *option)
{
    (void)option;
    return SOFTBUS_NOT_IMPLEMENT;
}

static int32_t UsbDiscStopPassivePublish(const PublishOption *option)
{
    (void)option;
    return SOFTBUS_NOT_IMPLEMENT;
}

static int32_t UsbDiscStartActiveDiscovery(const SubscribeOption *option)
{
    (void)option;
    return SOFTBUS_NOT_IMPLEMENT;
}

static int32_t UsbDiscStartPassiveDiscovery(const SubscribeOption *option)
{
    (void)option;
    return SOFTBUS_OK;
}

static int32_t UsbDiscStopPassiveDiscovery(const SubscribeOption *option)
{
    (void)option;
    return SOFTBUS_OK;
}

static int32_t UsbDiscStopActiveDiscovery(const SubscribeOption *option)
{
    (void)option;
    return SOFTBUS_NOT_IMPLEMENT;
}

static void UsbDiscLinkStatusChanged(LinkStatus status)
{
    (void)status;
}

static void UsbDiscUpdateLocalDeviceInfo(InfoTypeChanged type)
{
    (void)type;
}

static bool UsbDiscIsConcern(uint32_t capability)
{
    (void)capability;
    return false;
}

static DiscoveryFuncInterface g_discUsbFuncInterface = {
    .Publish = UsbDiscStartActivePublish,
    .StartScan = UsbDiscStartPassivePublish,
    .Unpublish = UsbDiscStopActivePublish,
    .StopScan = UsbDiscStopPassivePublish,
    .StartAdvertise = UsbDiscStartActiveDiscovery,
    .Subscribe = UsbDiscStartPassiveDiscovery,
    .Unsubscribe = UsbDiscStopPassiveDiscovery,
    .StopAdvertise = UsbDiscStopActiveDiscovery,
    .LinkStatusChanged = UsbDiscLinkStatusChanged,
    .UpdateLocalDeviceInfo = UsbDiscUpdateLocalDeviceInfo
};

static DiscoveryUsbDispatcherInterface g_usbDiscInterface = {
    .IsConcern = UsbDiscIsConcern,
    .mediumInterface = &g_discUsbFuncInterface,
};

DiscoveryUsbDispatcherInterface *DiscUsbInit(DiscInnerCallback *discInnerCb)
{
    (void)discInnerCb;
    return &g_usbDiscInterface;
}

void DiscUsbDeinit(void)
{
}