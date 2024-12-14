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

#include "disc_usb_dispatcher.h"
#include "disc_event.h"
#include "disc_log.h"
#include "disc_manager.h"
#include "disc_usb.h"
#include "softbus_error_code.h"

#define DISPATCHER_SIZE 1

static DiscoveryUsbDispatcherInterface *g_usbDispatchers[DISPATCHER_SIZE];
static uint32_t g_dispatcherSize = 0;

static DiscoveryFuncInterface *FindDiscoveryFuncInterface(uint32_t capability)
{
    for (uint32_t i = 0; i < g_dispatcherSize; i++) {
        if (g_usbDispatchers[i] == NULL) {
            continue;
        }
        if (g_usbDispatchers[i]->IsConcern != NULL && g_usbDispatchers[i]->IsConcern(capability)) {
            return g_usbDispatchers[i]->mediumInterface;
        }
    }
    return NULL;
}

static int32_t UsbDispatchPublishOption(const PublishOption *option, DiscoverMode mode, InterfaceFuncType type)
{
    DISC_CHECK_AND_RETURN_RET_LOGE(option != NULL, SOFTBUS_INVALID_PARAM, DISC_USB, "option is null");
    DiscoveryFuncInterface *interface = FindDiscoveryFuncInterface(option->capabilityBitmap[0]);
    if (interface == NULL) {
        DISC_LOGE(DISC_USB,
            "dispatch publish action failed: no implement support capability. capabilityBitmap=%{public}u",
            option->capabilityBitmap[0]);
        DiscAuditExtra extra = {
            .result = DISC_AUDIT_DISCONTINUE,
            .errcode = SOFTBUS_DISCOVER_USB_DISPATCHER_FAILED,
            .auditType = AUDIT_EVENT_MSG_ERROR,
            .discMode = mode,
            .broadcastFreq = option->freq,
            .localCapabilityBitmap = option->capabilityBitmap[0],
        };
        DISC_AUDIT(AUDIT_SCENE_USB_PUBLISH, extra);
        return SOFTBUS_DISCOVER_USB_DISPATCHER_FAILED;
    }
    switch (type) {
        case PUBLISH_FUNC:
            return mode == DISCOVER_MODE_ACTIVE ? interface->Publish(option) : interface->StartScan(option);
        case UNPUBLISH_FUNC:
            return mode == DISCOVER_MODE_ACTIVE ? interface->Unpublish(option) : interface->StopScan(option);
        default:
            DISC_LOGE(DISC_USB,
                "dispatch publish action failed: unsupport type. type=%{public}d, capability=%{public}u",
                type, option->capabilityBitmap[0]);
            return SOFTBUS_DISCOVER_USB_DISPATCHER_FAILED;
    }
}

static int32_t UsbDispatchSubscribeOption(const SubscribeOption *option, DiscoverMode mode,
    InterfaceFuncType type)
{
    DISC_CHECK_AND_RETURN_RET_LOGE(option != NULL, SOFTBUS_INVALID_PARAM, DISC_USB, "option is null");
    DiscoveryFuncInterface *interface = FindDiscoveryFuncInterface(option->capabilityBitmap[0]);
    if (interface == NULL) {
        DISC_LOGE(DISC_USB, "dispatch subcribe action failed: no implement support capability. capability=%{public}u",
            option->capabilityBitmap[0]);
        DiscAuditExtra extra = {
            .result = DISC_AUDIT_DISCONTINUE,
            .errcode = SOFTBUS_DISCOVER_USB_DISPATCHER_FAILED,
            .auditType = AUDIT_EVENT_MSG_ERROR,
            .discMode = mode,
            .broadcastFreq = option->freq,
            .localCapabilityBitmap = option->capabilityBitmap[0],
        };
        DISC_AUDIT(AUDIT_SCENE_USB_SUBSCRIBE, extra);
        return SOFTBUS_DISCOVER_USB_DISPATCHER_FAILED;
    }
    switch (type) {
        case STARTDISCOVERTY_FUNC:
            return mode == DISCOVER_MODE_ACTIVE ? interface->StartAdvertise(option) : interface->Subscribe(option);
        case STOPDISCOVERY_FUNC:
            return mode == DISCOVER_MODE_ACTIVE ? interface->StopAdvertise(option) : interface->Unsubscribe(option);
        default:
            DISC_LOGE(DISC_USB, "dispatch subcribe action failed: unsupport. type=%{public}d, capability=%{public}u",
                type, option->capabilityBitmap[0]);
            return SOFTBUS_DISCOVER_USB_DISPATCHER_FAILED;
    }
}

static int32_t UsbDispatchStartActivePublish(const PublishOption *option)
{
    return UsbDispatchPublishOption(option, DISCOVER_MODE_ACTIVE, PUBLISH_FUNC);
}

static int32_t UsbDispatchStartPassivePublish(const PublishOption *option)
{
    return UsbDispatchPublishOption(option, DISCOVER_MODE_PASSIVE, PUBLISH_FUNC);
}

static int32_t UsbDispatchStopActivePublish(const PublishOption *option)
{
    return UsbDispatchPublishOption(option, DISCOVER_MODE_ACTIVE, UNPUBLISH_FUNC);
}

static int32_t UsbDispatchStopPassivePublish(const PublishOption *option)
{
    return UsbDispatchPublishOption(option, DISCOVER_MODE_PASSIVE, UNPUBLISH_FUNC);
}

static int32_t UsbDispatchStartActiveDiscovery(const SubscribeOption *option)
{
    return UsbDispatchSubscribeOption(option, DISCOVER_MODE_ACTIVE, STARTDISCOVERTY_FUNC);
}

static int32_t UsbDispatchStartPassiveDiscovery(const SubscribeOption *option)
{
    return UsbDispatchSubscribeOption(option, DISCOVER_MODE_PASSIVE, STARTDISCOVERTY_FUNC);
}

static int32_t UsbDispatchStopActiveDiscovery(const SubscribeOption *option)
{
    return UsbDispatchSubscribeOption(option, DISCOVER_MODE_ACTIVE, STOPDISCOVERY_FUNC);
}

static int32_t UsbDispatchStopPassiveDiscovery(const SubscribeOption *option)
{
    return UsbDispatchSubscribeOption(option, DISCOVER_MODE_PASSIVE, STOPDISCOVERY_FUNC);
}

static void UsbDispatchLinkStatusChanged(LinkStatus status)
{
    for (uint32_t i = 0; i < g_dispatcherSize; i++) {
        if (g_usbDispatchers[i] != NULL && g_usbDispatchers[i]->mediumInterface != NULL &&
            g_usbDispatchers[i]->mediumInterface->LinkStatusChanged != NULL) {
            g_usbDispatchers[i]->mediumInterface->LinkStatusChanged(status);
        }
    }
}

static void UsbDispatchUpdateLocalDeviceInfo(InfoTypeChanged type)
{
    for (uint32_t i = 0; i < g_dispatcherSize; i++) {
        if (g_usbDispatchers[i] != NULL && g_usbDispatchers[i]->mediumInterface != NULL &&
            g_usbDispatchers[i]->mediumInterface->UpdateLocalDeviceInfo != NULL) {
            g_usbDispatchers[i]->mediumInterface->UpdateLocalDeviceInfo(type);
        }
    }
}

static DiscoveryFuncInterface g_discUsbFrameFuncInterface = {
    .Publish = UsbDispatchStartActivePublish,
    .StartScan = UsbDispatchStartPassivePublish,
    .Unpublish = UsbDispatchStopActivePublish,
    .StopScan = UsbDispatchStopPassivePublish,
    .StartAdvertise = UsbDispatchStartActiveDiscovery,
    .Subscribe = UsbDispatchStartPassiveDiscovery,
    .StopAdvertise = UsbDispatchStopActiveDiscovery,
    .Unsubscribe = UsbDispatchStopPassiveDiscovery,
    .LinkStatusChanged = UsbDispatchLinkStatusChanged,
    .UpdateLocalDeviceInfo = UsbDispatchUpdateLocalDeviceInfo,
};

static void DfxRecordUsbInitEnd(int32_t stage, int32_t reason)
{
    DiscEventExtra extra = { 0 };
    DiscEventExtraInit(&extra);
    extra.initType = USB + 1;
    extra.errcode = reason;
    extra.result = (reason == SOFTBUS_OK) ? EVENT_STAGE_RESULT_OK : EVENT_STAGE_RESULT_FAILED;
    DISC_EVENT(EVENT_SCENE_INIT, stage, extra);

    if (stage != EVENT_STAGE_INIT && reason != SOFTBUS_OK) {
        DISC_EVENT(EVENT_SCENE_INIT, EVENT_STAGE_INIT, extra);
    }
}

DiscoveryFuncInterface *DiscUsbDispatcherInit(DiscInnerCallback *discInnerCb)
{
    if (discInnerCb == NULL) {
        DfxRecordUsbInitEnd(EVENT_STAGE_INIT, SOFTBUS_INVALID_PARAM);
        DISC_LOGE(DISC_INIT, "discInnerCb err");
        return NULL;
    }
    DISC_LOGI(DISC_INIT, "DiscUsbFrameInit");
    g_dispatcherSize = 0;
    DiscoveryUsbDispatcherInterface *usbInterface = DiscUsbInit(discInnerCb);
    if (usbInterface == NULL) {
        DfxRecordUsbInitEnd(EVENT_STAGE_USB_INIT, SOFTBUS_DISCOVER_MANAGER_INIT_FAIL);
        DISC_LOGE(DISC_INIT, "DiscUsbInit err");
        return NULL;
    }
    g_usbDispatchers[g_dispatcherSize++] = usbInterface;
    DfxRecordUsbInitEnd(EVENT_STAGE_USB_INIT, SOFTBUS_OK);

    return &g_discUsbFrameFuncInterface;
}

DiscoveryFuncInterface *DiscUsbInitForTest(DiscoveryUsbDispatcherInterface *interfaceA,
    DiscoveryUsbDispatcherInterface *interfaceB)
{
    g_dispatcherSize = 0;
    g_usbDispatchers[g_dispatcherSize++] = interfaceA;
    g_usbDispatchers[g_dispatcherSize++] = interfaceB;
    return &g_discUsbFrameFuncInterface;
}

void DiscUsbDispatcherDeinit(void)
{
    DISC_LOGI(DISC_INIT, "deinit DiscUsbFrameDeinit");
    for (uint32_t i = 0; i < g_dispatcherSize; i++) {
        g_usbDispatchers[i] = NULL;
    }
    g_dispatcherSize = 0;
    DiscUsbDeinit();
}