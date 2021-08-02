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
        LOG_ERR("device para is null");
        return;
    }
    LOG_INFO("DeviceFound enter, type = %d", device->addr[0].type);
    if (device->addr[0].type != CONNECTION_ADDR_WLAN && device->addr[0].type != CONNECTION_ADDR_ETH) {
        LOG_ERR("discovery get invalid addr type: %d", device->addr[0].type);
        return;
    }
    if (device->addr[0].info.ip.port == 0) {
        LOG_ERR("discovery get port is 0 !");
        return;
    }
    addr.type = device->addr[0].type;
    if (memcpy_s(addr.info.ip.ip, IP_STR_MAX_LEN, device->addr[0].info.ip.ip,
        strlen(device->addr[0].info.ip.ip))!= 0) {
        LOG_ERR("strncpy ip failed");
        return;
    }
    addr.info.ip.port = device->addr[0].info.ip.port;
    if (memcpy_s(addr.peerUid, MAX_ACCOUNT_HASH_LEN, device->hwAccountHash, MAX_ACCOUNT_HASH_LEN) != 0) {
        LOG_ERR("memcpy_s peer uid failed");
        return;
    }
    if (g_callback.OnDeviceFound) {
        g_callback.OnDeviceFound(&addr);
    }
}

int32_t LnnStopCoapDiscovery(void)
{
    if (DiscStopAdvertise(MODULE_LNN, LNN_SUBSCRIBE_ID) != SOFTBUS_OK) {
        LOG_ERR("DiscStopAdvertise fail!");
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
        LOG_ERR("DiscSetDiscoverCallback failed");
        return SOFTBUS_ERR;
    }
    return DiscStartAdvertise(MODULE_LNN, &subscribeInfo);
}

int32_t LnnInitCoapDiscovery(LnnDiscoveryImplCallback *callback)
{
    if (callback == NULL) {
        LOG_ERR("coap discovery callback is null");
        return SOFTBUS_INVALID_PARAM;
    }
    g_callback.OnDeviceFound = callback->OnDeviceFound;
    return SOFTBUS_OK;
}
