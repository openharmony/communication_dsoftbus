/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "lnn_discovery_manager.h"

#include <securec.h>

#include "disc_interface.h"
#include "discovery_service.h"
#include "softbus_errcode.h"
#include "softbus_log.h"

#define LNN_DISC_CAPABILITY "ddmpCapability"
#define LNN_SUBSCRIBE_ID 0

static LnnDiscoveryImplCallback g_callback;

static void DeviceFound(const DeviceInfo *device);

static DiscInnerCallback g_discCb = {
    .OnDeviceFound = DeviceFound,
};

static void DeviceFound(const DeviceInfo *device)
{
    ConnectionAddr addr;

    if (device == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "device para is null\n");
        return;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "DeviceFound enter, type = %d\n", device->addr[0].type);
    if (device->addr[0].type != CONNECTION_ADDR_WLAN && device->addr[0].type != CONNECTION_ADDR_ETH) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "discovery get invalid addrtype: %d\n", device->addr[0].type);
        return;
    }
    if (device->addr[0].info.ip.port == 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "discovery get port is 0 !\n");
        return;
    }
    addr.type = device->addr[0].type;
    if (strncpy_s(addr.info.ip.ip, IP_STR_MAX_LEN, device->addr[0].info.ip.ip,
        strlen(device->addr[0].info.ip.ip)) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "strncpy ip failed\n");
        return;
    }
    addr.info.ip.port = device->addr[0].info.ip.port;
    if (memcpy_s(addr.peerUid, MAX_ACCOUNT_HASH_LEN, device->hwAccountHash, MAX_ACCOUNT_HASH_LEN) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "memcpy_s peer uid failed\n");
        return;
    }
    if (g_callback.OnDeviceFound) {
        g_callback.OnDeviceFound(&addr);
    }
}

int32_t LnnStopCoapDiscovery(void)
{
    if (DiscStopAdvertise(MODULE_LNN, LNN_SUBSCRIBE_ID) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "DiscStopAdvertise fail!\n");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t LnnStartCoapDiscovery(void)
{
    SubscribeInnerInfo subscribeInfo = {
        .subscribeId = LNN_SUBSCRIBE_ID,
        .medium = COAP,
        .freq = HIGH,
        .isSameAccount = false,
        .isWakeRemote = false,
        .capability = LNN_DISC_CAPABILITY,
        .capabilityData = (unsigned char *)LNN_DISC_CAPABILITY,
        .dataLen = strlen(LNN_DISC_CAPABILITY) + 1,
    };
    if (DiscSetDiscoverCallback(MODULE_LNN, &g_discCb) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "DiscSetDiscoverCallback failed\n");
        return SOFTBUS_ERR;
    }
    return DiscStartAdvertise(MODULE_LNN, &subscribeInfo);
}

int32_t LnnInitCoapDiscovery(LnnDiscoveryImplCallback *callback)
{
    if (callback == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "coap discovery callback is null\n");
        return SOFTBUS_INVALID_PARAM;
    }
    g_callback.OnDeviceFound = callback->OnDeviceFound;
    return SOFTBUS_OK;
}
