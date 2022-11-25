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
#include "disc_ble.h"
#include "disc_share_ble.h"
#include "softbus_log.h"
#include "softbus_errcode.h"

#define DISPATCHER_SIZE 2

static DiscoveryBleDispatcherInterface *g_dispatchers[DISPATCHER_SIZE];
static uint32_t g_dispatcherSize = 0;

static DiscoveryFuncInterface *FindDiscoveryFuncInterface(uint32_t capability)
{
    for (uint32_t i = 0; i < g_dispatcherSize; i++) {
        if (g_dispatchers[i] == NULL) {
            continue;
        }
        if (g_dispatchers[i]->IsConcern != NULL && g_dispatchers[i]->IsConcern(capability)) {
            return g_dispatchers[i]->mediumInterface;
        }
    }
    return NULL;
}

static int32_t BleDispatchPublishOption(const PublishOption *option, DiscoverMode mode, InterfaceFuncType type)
{
    DiscoveryFuncInterface *interface = FindDiscoveryFuncInterface(option->capabilityBitmap[0]);
    if (interface == NULL) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR,
            "dispatch publish action failed: no implement support capability '%u'", option->capabilityBitmap[0]);
        return SOFTBUS_ERR;
    }
    switch (type) {
        case PUBLISH_FUNC:
            return mode == DISCOVER_MODE_ACTIVE ? interface->Publish(option) : interface->StartScan(option);
        case UNPUBLISH_FUNC:
            return mode == DISCOVER_MODE_ACTIVE ? interface->Unpublish(option) : interface->StopScan(option);
        default:
            SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR,
                "dispatch publish action failed: unsupport type '%d', capability '%u'", type,
                option->capabilityBitmap[0]);
            return SOFTBUS_DISCOVER_MANAGER_INNERFUNCTION_FAIL;
    }
}

static int32_t BleDispatchSubscribeOption(const SubscribeOption *option, DiscoverMode mode, InterfaceFuncType type)
{
    DiscoveryFuncInterface *interface = FindDiscoveryFuncInterface(option->capabilityBitmap[0]);
    if (interface == NULL) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR,
            "dispatch subcribe action failed: no implement support capability '%u'", option->capabilityBitmap[0]);
        return SOFTBUS_ERR;
    }
    switch (type) {
        case STARTDISCOVERTY_FUNC:
            return mode == DISCOVER_MODE_ACTIVE ? interface->StartAdvertise(option) : interface->Subscribe(option);
        case STOPDISCOVERY_FUNC:
            return mode == DISCOVER_MODE_ACTIVE ? interface->StopAdvertise(option) : interface->Unsubscribe(option);
        default:
            SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR,
                "dispatch subcribe action failed: unsupport type '%d', capability '%u'", type,
                option->capabilityBitmap[0]);
            return SOFTBUS_DISCOVER_MANAGER_INNERFUNCTION_FAIL;
    }
}

static int32_t BleDispatchStartActivePublish(const PublishOption *option)
{
    return BleDispatchPublishOption(option, DISCOVER_MODE_ACTIVE, PUBLISH_FUNC);
}

static int32_t BleDispatchStartPassivePublish(const PublishOption *option)
{
    return BleDispatchPublishOption(option, DISCOVER_MODE_PASSIVE, PUBLISH_FUNC);
}

static int32_t BleDispatchStopActivePublish(const PublishOption *option)
{
    return BleDispatchPublishOption(option, DISCOVER_MODE_ACTIVE, UNPUBLISH_FUNC);
}

static int32_t BleDispatchStopPassivePublish(const PublishOption *option)
{
    return BleDispatchPublishOption(option, DISCOVER_MODE_PASSIVE, UNPUBLISH_FUNC);
}

static int32_t BleDispatchStartActiveDiscovery(const SubscribeOption *option)
{
    return BleDispatchSubscribeOption(option, DISCOVER_MODE_ACTIVE, STARTDISCOVERTY_FUNC);
}

static int32_t BleDispatchStartPassiveDiscovery(const SubscribeOption *option)
{
    return BleDispatchSubscribeOption(option, DISCOVER_MODE_PASSIVE, STARTDISCOVERTY_FUNC);
}

static int32_t BleDispatchStopActiveDiscovery(const SubscribeOption *option)
{
    return BleDispatchSubscribeOption(option, DISCOVER_MODE_ACTIVE, STOPDISCOVERY_FUNC);
}

static int32_t BleDispatchStopPassiveDiscovery(const SubscribeOption *option)
{
    return BleDispatchSubscribeOption(option, DISCOVER_MODE_PASSIVE, STOPDISCOVERY_FUNC);
}

static void BleDispatchLinkStatusChanged(LinkStatus status)
{
    for (uint32_t i = 0; i < g_dispatcherSize; i++) {
        if (g_dispatchers[i] != NULL && g_dispatchers[i]->mediumInterface != NULL &&
            g_dispatchers[i]->mediumInterface->LinkStatusChanged != NULL) {
            g_dispatchers[i]->mediumInterface->LinkStatusChanged(status);
        }
    }
}

static void BleDispatchUpdateLocalDeviceInfo(InfoTypeChanged type)
{
    for (uint32_t i = 0; i < g_dispatcherSize; i++) {
        if (g_dispatchers[i] != NULL && g_dispatchers[i]->mediumInterface != NULL &&
            g_dispatchers[i]->mediumInterface->UpdateLocalDeviceInfo != NULL) {
            g_dispatchers[i]->mediumInterface->UpdateLocalDeviceInfo(type);
        }
    }
}

static DiscoveryFuncInterface g_discBleFrameFuncInterface = {
    .Publish = BleDispatchStartActivePublish,
    .StartScan = BleDispatchStartPassivePublish,
    .Unpublish = BleDispatchStopActivePublish,
    .StopScan = BleDispatchStopPassivePublish,
    .StartAdvertise = BleDispatchStartActiveDiscovery,
    .Subscribe = BleDispatchStartPassiveDiscovery,
    .StopAdvertise = BleDispatchStopActiveDiscovery,
    .Unsubscribe = BleDispatchStopPassiveDiscovery,
    .LinkStatusChanged = BleDispatchLinkStatusChanged,
    .UpdateLocalDeviceInfo = BleDispatchUpdateLocalDeviceInfo,
};

DiscoveryFuncInterface *DiscBleInit(DiscInnerCallback *discInnerCb)
{
    if (discInnerCb == NULL) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "discInnerCb err");
        return NULL;
    }
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "DiscBleFrameInit");
    g_dispatcherSize = 0;
    DiscoveryBleDispatcherInterface *softbusInterface = DiscSoftBusBleInit(discInnerCb);
    if (softbusInterface == NULL) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "DiscSoftBusBleInit err");
        return NULL;
    }
    g_dispatchers[g_dispatcherSize++] = softbusInterface;

    DiscoveryBleDispatcherInterface *shareInterface = DiscShareBleInit(discInnerCb);
    if (shareInterface == NULL) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "DiscShareBleInit err");
        return NULL;
    }
    g_dispatchers[g_dispatcherSize++] = shareInterface;

    return &g_discBleFrameFuncInterface;
}

DiscoveryFuncInterface *DiscBleInitForTest(DiscoveryBleDispatcherInterface *interfaceA,
    DiscoveryBleDispatcherInterface *interfaceB)
{
    g_dispatcherSize = 0;
    g_dispatchers[g_dispatcherSize++] = interfaceA;
    g_dispatchers[g_dispatcherSize++] = interfaceB;
    return &g_discBleFrameFuncInterface;
}

void DiscBleDeinit(void)
{
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "deinit DiscBleFrameDeinit");
    for (uint32_t i = 0; i < g_dispatcherSize; i++) {
        g_dispatchers[i] = NULL;
    }
    g_dispatcherSize = 0;
    DiscSoftBusBleDeinit();
    DiscShareBleDeinit();
}