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

#include "auth_interface.h"
#include "bus_center_manager.h"
#include "softbus_adapter_crypto.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_utils.h"

#define LNN_DISC_CAPABILITY "ddmpCapability"
#define LNN_SUBSCRIBE_ID 0
#define LNN_PUBLISH_ID 0

#define LNN_SHORT_HASH_LEN 8
#define LNN_SHORT_HASH_HEX_LEN 16

static LnnDiscoveryImplCallback g_callback;

static void DeviceFound(const DeviceInfo *device, const InnerDeviceInfoAddtions *addtions);

static DiscInnerCallback g_discCb = {
    .OnDeviceFound = DeviceFound,
};

static void ConvertDeviceInfo(const DeviceInfo *fromDevice, DeviceInfo *toDevice)
{
    uint8_t hashResult[SHA_256_HASH_LEN] = {0};

    if (memcpy_s(toDevice, sizeof(DeviceInfo), fromDevice, sizeof(DeviceInfo)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "memcpy_s deviceInfo fail");
        return;
    }
    if (SoftBusGenerateStrHash((const unsigned char *)fromDevice->devId,
        strlen(fromDevice->devId), hashResult) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "generate devId hash fail");
        return;
    }
    (void)memset_s(toDevice->devId, sizeof(toDevice->devId), 0, sizeof(toDevice->devId));
    if (ConvertBytesToHexString(toDevice->devId, LNN_SHORT_HASH_HEX_LEN + 1,
        (const unsigned char *)hashResult, LNN_SHORT_HASH_LEN) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "convert hex devId string fail");
        return;
    }
    (void)memset_s(toDevice->accountHash, sizeof(toDevice->accountHash), 0, sizeof(toDevice->accountHash));
    if (SoftBusGenerateStrHash((const unsigned char *)fromDevice->accountHash,
        strlen(fromDevice->accountHash), (unsigned char *)toDevice->accountHash) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "generate account hash fail");
    }
}

NO_SANITIZE("cfi") static void DeviceFound(const DeviceInfo *device, const InnerDeviceInfoAddtions *addtions)
{
    ConnectionAddr addr;
    DeviceInfo tmpInfo;
    (void) addtions;

    if (device == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "device para is null");
        return;
    }
    (void)memset_s(&tmpInfo, sizeof(DeviceInfo), 0, sizeof(DeviceInfo));
    char *anoyUdid = NULL;
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "DeviceFound devName: %s, devId: %s",
        device->devName, ToSecureStrDeviceID(device->devId, &anoyUdid));
    SoftBusFree(anoyUdid);
    ConvertDeviceInfo(device, &tmpInfo);
    if (!AuthIsPotentialTrusted(&tmpInfo, false)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_WARN, "discovery device is not potential trusted, devId:%s, "
            "accountHash:%02X%02X", AnonymizesUDID(tmpInfo.devId), tmpInfo.accountHash[0], tmpInfo.accountHash[1]);
        return;
    }
    if (device->addr[0].type != CONNECTION_ADDR_WLAN && device->addr[0].type != CONNECTION_ADDR_ETH) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "discovery get invalid addrtype: %d", device->addr[0].type);
        return;
    }
    if (device->addr[0].info.ip.port == 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "discovery get port is 0!");
        return;
    }
    addr.type = device->addr[0].type;
    if (strncpy_s(addr.info.ip.ip, IP_STR_MAX_LEN, device->addr[0].info.ip.ip,
        strlen(device->addr[0].info.ip.ip)) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "strncpy ip failed");
        return;
    }
    addr.info.ip.port = device->addr[0].info.ip.port;
    if (memcpy_s(addr.peerUid, MAX_ACCOUNT_HASH_LEN, device->accountHash, MAX_ACCOUNT_HASH_LEN) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "memcpy_s peer uid failed");
        return;
    }
    if (g_callback.OnDeviceFound) {
        g_callback.OnDeviceFound(&addr);
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
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_DBG, "lnn start coap publish");
    return LnnPublishService(NULL, &publishInfo, true);
}

int32_t LnnStopCoapPublish(void)
{
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_DBG, "lnn stop coap publish");
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
    return LnnStartDiscDevice(NULL, &subscribeInfo, &callback, true);
}

int32_t LnnInitCoapDiscovery(LnnDiscoveryImplCallback *callback)
{
    if (callback == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "coap discovery callback is null");
        return SOFTBUS_INVALID_PARAM;
    }
    g_callback.OnDeviceFound = callback->OnDeviceFound;
    return SOFTBUS_OK;
}
