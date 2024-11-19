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

#include "lnn_coap_discovery_impl.h"

#include <securec.h>

#include "anonymizer.h"
#include "auth_interface.h"
#include "bus_center_manager.h"
#include "lnn_log.h"
#include "softbus_adapter_crypto.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_utils.h"

#define LNN_DISC_CAPABILITY "ddmpCapability"
#define LNN_SUBSCRIBE_ID 0
#define LNN_PUBLISH_ID 0

#define LNN_SHORT_HASH_LEN 8
#define LNN_SHORT_HASH_HEX_LEN 16
#define TYPE_PRINTER 0x09

static LnnDiscoveryImplCallback g_callback;

static void DeviceFound(const DeviceInfo *device, const InnerDeviceInfoAddtions *additions);

static DiscInnerCallback g_discCb = {
    .OnDeviceFound = DeviceFound,
};

static int32_t LnnCheckDiscoveryDeviceInfo(const DeviceInfo *device)
{
    if (device->addr[0].type != CONNECTION_ADDR_WLAN && device->addr[0].type != CONNECTION_ADDR_ETH) {
        LNN_LOGE(LNN_BUILDER, "discovery get invalid addrType=%{public}d", device->addr[0].type);
        return SOFTBUS_INVALID_PARAM;
    }
    if (device->addr[0].info.ip.port == 0) {
        LNN_LOGD(LNN_BUILDER, "discovery get port is 0!");
        LnnCoapConnect(device->addr[0].info.ip.ip);
        return SOFTBUS_INVALID_PARAM;
    }
    return SOFTBUS_OK;
}

static int32_t GetConnectDeviceInfo(const DeviceInfo *device, ConnectionAddr *addr)
{
    addr->type = device->addr[0].type;
    if (strcpy_s(addr->info.ip.ip, IP_STR_MAX_LEN, device->addr[0].info.ip.ip) != EOK) {
        LNN_LOGE(LNN_BUILDER, "strcpy ip failed");
        return SOFTBUS_STRCPY_ERR;
    }
    if (strcpy_s((char *)addr->info.ip.udidHash, UDID_HASH_LEN, device->devId) != EOK) {
        LNN_LOGE(LNN_BUILDER, "strcpy udidHash failed");
        return SOFTBUS_STRCPY_ERR;
    }
    addr->info.ip.port = device->addr[0].info.ip.port;
    if (memcpy_s(addr->peerUid, MAX_ACCOUNT_HASH_LEN, device->accountHash, MAX_ACCOUNT_HASH_LEN) != EOK) {
        LNN_LOGE(LNN_BUILDER, "memcpy_s peer uid failed");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static void DeviceFound(const DeviceInfo *device, const InnerDeviceInfoAddtions *additions)
{
    ConnectionAddr addr;
    (void) additions;

    if (device == NULL) {
        LNN_LOGE(LNN_BUILDER, "device para is null");
        return;
    }
    (void)memset_s(&addr, sizeof(ConnectionAddr), 0, sizeof(ConnectionAddr));
    char *anonyDevId = NULL;
    Anonymize(device->devId, &anonyDevId);
    char *anonyDevName = NULL;
    Anonymize(device->devName, &anonyDevName);
    // devId format is hex hash string here
    LNN_LOGI(LNN_BUILDER, "DeviceFound devName=%{public}s, devId=%{public}s, devType=%{public}03X, port=%{public}u",
        AnonymizeWrapper(anonyDevName), AnonymizeWrapper(anonyDevId), device->devType, device->addr[0].info.ip.port);
    AnonymizeFree(anonyDevName);
    if (!AuthIsPotentialTrusted(device)) {
        LNN_LOGW(LNN_BUILDER, "discovery device is not potential trusted, devId=%{public}s, "
            "accountHash=%{public}02X%{public}02X", AnonymizeWrapper(anonyDevId),
            device->accountHash[0], device->accountHash[1]);
        AnonymizeFree(anonyDevId);
        return;
    }
    AnonymizeFree(anonyDevId);
    if (LnnCheckDiscoveryDeviceInfo(device) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get invalid device para");
        return;
    }
    if (GetConnectDeviceInfo(device, &addr) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get connect device info fail");
        return;
    }
    LnnDfxDeviceInfoReport info;
    (void)memset_s(&info, sizeof(LnnDfxDeviceInfoReport), 0, sizeof(LnnDfxDeviceInfoReport));
    info.type = device->devType;
    if ((uint32_t)info.type == TYPE_PRINTER) {
        LNN_LOGI(LNN_BUILDER, "restrict printer");
        return;
    }
    if (g_callback.onDeviceFound) {
        g_callback.onDeviceFound(&addr, &info);
    }
}

int32_t LnnStartCoapPublish(void)
{
    PublishInfo publishInfo = {
        .publishId = LNN_PUBLISH_ID,
        .mode = DISCOVER_MODE_PASSIVE,
        .medium = COAP,
        .freq = HIGH,
        .capability = LNN_DISC_CAPABILITY,
        .capabilityData = (unsigned char *)LNN_DISC_CAPABILITY,
        .dataLen = strlen(LNN_DISC_CAPABILITY),
    };
    LNN_LOGD(LNN_BUILDER, "lnn start coap publish");
    return LnnPublishService(NULL, &publishInfo, true);
}

int32_t LnnStopCoapPublish(void)
{
    LNN_LOGD(LNN_BUILDER, "lnn stop coap publish");
    return LnnUnPublishService(NULL, LNN_PUBLISH_ID, true);
}

int32_t LnnStopCoapDiscovery(void)
{
    return LnnStopDiscDevice(NULL, LNN_SUBSCRIBE_ID, true);
}

int32_t LnnStartCoapDiscovery(void)
{
    SubscribeInfo subscribeInfo = {
        .subscribeId = LNN_SUBSCRIBE_ID,
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = COAP,
        .freq = HIGH,
        .isSameAccount = false,
        .isWakeRemote = false,
        .capability = LNN_DISC_CAPABILITY,
        .capabilityData = (unsigned char *)LNN_DISC_CAPABILITY,
        .dataLen = strlen(LNN_DISC_CAPABILITY),
    };
    InnerCallback callback = {
        .innerCb = g_discCb,
    };
    LnnDestroyCoapConnectList();
    return LnnStartDiscDevice(NULL, &subscribeInfo, &callback, true);
}

int32_t LnnInitCoapDiscovery(LnnDiscoveryImplCallback *callback)
{
    if (callback == NULL) {
        LNN_LOGE(LNN_BUILDER, "coap discovery callback is null");
        return SOFTBUS_INVALID_PARAM;
    }
    g_callback.onDeviceFound = callback->onDeviceFound;
    return SOFTBUS_OK;
}
