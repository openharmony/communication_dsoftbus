/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include "nstackx_device.h"

#include <string.h>
#include <stdio.h>
#include <securec.h>
#include <sys/types.h>
#include <unistd.h>

#include "cJSON.h"
#include "nstackx_log.h"
#include "nstackx_event.h"
#include "nstackx_timer.h"
#include "nstackx_error.h"
#include "nstackx_util.h"
#include "nstackx_common.h"
#include "nstackx_database.h"
#include "coap_discover/coap_app.h"
#include "coap_discover/coap_discover.h"

#define TAG "nStackXDFinder"

#define NSTACKX_OFFLINE_DEFERRED_DURATION 5000 /* Defer local device offline event, 5 seconds */

#define NSTACKX_DEFAULT_DEVICE_NAME "nStack Device"

#define NSTACKX_RESERVED_INFO_WIFI_IP "wifiIpAddr"

#define NSTACKX_WLAN_INDEX 0
#define NSTACKX_ETH_INDEX 1
#define NSTACKX_MAX_INTERFACE_NUM 2
#define NETWORKTYPE_LENGTH 20
#define NSTACKX_WLAN_INTERFACE_NAME_PREFIX "wlan"
#define NSTACKX_ETH_INTERFACE_NAME_PREFIX "eth"
#define NSTACKX_DEFAULT_VER "1.0.0.0"

/*
 * Reserved info JSON format:
 *   {"wifiIpAddr":[ip string]}
 */
#define NSTACKX_RESERVED_INFO_JSON_FORMAT \
    "{\"" NSTACKX_RESERVED_INFO_WIFI_IP "\":\"%s\"}"

#define NET_CHANNEL_INFO_STATE_INVALID(info) \
    ((info)->state <= NET_CHANNEL_STATE_START || (info)->state >= NET_CHANNEL_STATE_END)

static void *g_deviceList = NULL;
static void *g_deviceListBackup = NULL;
static Timer *g_offlineDeferredTimer = NULL;
static uint8_t g_deviceInited;
static DeviceInfo g_localDeviceInfo;
static uint32_t g_filterCapabilityBitmapNum = 0;
static uint32_t g_filterCapabilityBitmap[NSTACKX_MAX_CAPABILITY_NUM] = {0};
static NetworkInterfaceInfo g_interfaceList[NSTACKX_MAX_INTERFACE_NUM];
static char g_networkType[NETWORKTYPE_LENGTH] = {0};


static void DeviceListChangeHandle(void);
static void GetLocalIp(struct in_addr *ip);

uint8_t ClearDevices(void *deviceList)
{
    int32_t i;
    int64_t idx = -1;
    DeviceInfo *dev = NULL;
    uint8_t deviceRemoved = NSTACKX_FALSE;

    if (deviceList == NULL) {
        return deviceRemoved;
    }

    for (i = 0; i < NSTACKX_MAX_DEVICE_NUM; i++) {
        dev = DatabaseGetNextRecord(deviceList, &idx);
        if (dev == NULL) {
            break;
        }
        DatabaseFreeRecord(deviceList, (void *)dev);
        deviceRemoved = NSTACKX_TRUE;
    }
    return deviceRemoved;
}

static void LocalDeviceOffline(void *data)
{
    uint8_t deviceRemoved;
    (void)data;

    (void)ClearDevices(g_deviceListBackup);
    LOGW(TAG, "clear device list backup");
    deviceRemoved = ClearDevices(g_deviceList);
    LOGW(TAG, "clear device list");

    CoapServerDestroy();

    if (deviceRemoved) {
        DeviceListChangeHandle();
    }
}

static DeviceInfo *CreateNewDevice(const DeviceInfo *deviceInfo)
{
    DeviceInfo *internalDevice = NULL;

    /* Allocate DB for newly joined device */
    internalDevice = DatabaseAllocRecord(g_deviceList);
    if (internalDevice == NULL) {
        LOGE(TAG, "Failed to allocate device info");
        return NULL;
    }

    (void)memcpy_s(internalDevice, sizeof(DeviceInfo), deviceInfo, sizeof(DeviceInfo));

    return internalDevice;
}

static int32_t UpdateCapabilityBitmap(DeviceInfo *internalDevice, const DeviceInfo *deviceInfo, int8_t *updated)
{
    if (internalDevice == NULL || deviceInfo == NULL || updated == NULL) {
        LOGE(TAG, "UpdateCapabilityBitmap, input parameter error");
        return NSTACKX_EFAILED;
    }

    /* judge capabilityBitmap is or not different with new deviceInfo */
    if ((internalDevice->capabilityBitmapNum != deviceInfo->capabilityBitmapNum) ||
        (deviceInfo->capabilityBitmapNum &&
        memcmp(internalDevice->capabilityBitmap, deviceInfo->capabilityBitmap,
               deviceInfo->capabilityBitmapNum * sizeof(uint32_t)))) {
        *updated = NSTACKX_TRUE;
    }

    internalDevice->capabilityBitmapNum = deviceInfo->capabilityBitmapNum;

    if (memset_s(internalDevice->capabilityBitmap, sizeof(internalDevice->capabilityBitmap),
        0, sizeof(internalDevice->capabilityBitmap)) != EOK) {
        LOGE(TAG, "UpdateCapabilityBitmap, memset_s fails");
        return NSTACKX_EFAILED;
    }
    if (deviceInfo->capabilityBitmapNum) {
        if (memcpy_s(internalDevice->capabilityBitmap, sizeof(internalDevice->capabilityBitmap),
            deviceInfo->capabilityBitmap, deviceInfo->capabilityBitmapNum * sizeof(uint32_t)) != EOK) {
            LOGE(TAG, "UpdateCapabilityBitmap, capabilityBitmap copy error");
            return NSTACKX_EFAILED;
        }
    }
    return NSTACKX_EOK;
}

static int32_t UpdateDeviceInfoInner(DeviceInfo *internalDevice, const DeviceInfo *deviceInfo, int8_t *updated)
{
    if (internalDevice == NULL || deviceInfo == NULL) {
        LOGE(TAG, "UpdateDeviceInfo input error");
        return NSTACKX_EFAILED;
    }
    if (internalDevice->deviceType != deviceInfo->deviceType) {
        LOGE(TAG, "deviceType is different");
        return NSTACKX_EFAILED;
    }

    if (strcmp(internalDevice->deviceName, deviceInfo->deviceName)) {
        if (strcpy_s(internalDevice->deviceName, sizeof(internalDevice->deviceName), deviceInfo->deviceName) != EOK) {
            LOGE(TAG, "deviceName copy error");
            return NSTACKX_EFAILED;
        }
        *updated = NSTACKX_TRUE;
    }

    if (strlen(deviceInfo->version) > 0 && strcmp(internalDevice->version, deviceInfo->version)) {
        if (strcpy_s(internalDevice->version, sizeof(internalDevice->version), deviceInfo->version) != EOK) {
            LOGE(TAG, "hicom version copy error");
            return NSTACKX_EFAILED;
        }
        *updated = NSTACKX_TRUE;
    }

    if (UpdateCapabilityBitmap(internalDevice, deviceInfo, updated) != NSTACKX_EOK) {
        LOGE(TAG, "UpdateCapabilityBitmap fails");
        return NSTACKX_EFAILED;
    }

    return NSTACKX_EOK;
}

static int32_t UpdateDeviceInfo(DeviceInfo *internalDevice, const DeviceInfo *deviceInfo, int8_t *updatedPtr)
{
    int8_t updated = NSTACKX_FALSE;
    if (UpdateDeviceInfoInner(internalDevice, deviceInfo, &updated) != NSTACKX_EOK) {
        LOGE(TAG, "UpdateDeviceInfoInner error");
        return NSTACKX_EFAILED;
    }

    if (strcmp(internalDevice->deviceHash, deviceInfo->deviceHash)) {
        if (strcpy_s(internalDevice->deviceHash, sizeof(internalDevice->deviceHash), deviceInfo->deviceHash) != EOK) {
            LOGE(TAG, "deviceHash copy error");
            return NSTACKX_EFAILED;
        }
        updated = NSTACKX_TRUE;
    }

    if (internalDevice->mode != deviceInfo->mode) {
        internalDevice->mode = deviceInfo->mode;
        updated = NSTACKX_TRUE;
    }

    if (strcmp(internalDevice->serviceData, deviceInfo->serviceData)) {
        if (strcpy_s(internalDevice->serviceData, NSTACKX_MAX_SERVICE_DATA_LEN, deviceInfo->serviceData) != EOK) {
            LOGE(TAG, "serviceData copy error");
            return NSTACKX_EFAILED;
        }
        updated = NSTACKX_TRUE;
    }

    if (memcmp(&internalDevice->netChannelInfo, &deviceInfo->netChannelInfo, sizeof(deviceInfo->netChannelInfo)) ||
        (internalDevice->portNumber != deviceInfo->portNumber)) {
        (void)memcpy_s(&internalDevice->netChannelInfo, sizeof(internalDevice->netChannelInfo),
            &deviceInfo->netChannelInfo, sizeof(deviceInfo->netChannelInfo));
        internalDevice->portNumber = deviceInfo->portNumber;
        updated = NSTACKX_TRUE;
    }

    *updatedPtr = updated;
    return NSTACKX_EOK;
}

int32_t UpdateDeviceDb(const DeviceInfo *deviceInfo, uint8_t forceUpdate)
{
    DeviceInfo *internalDevice = NULL;
    int8_t updated = NSTACKX_FALSE;

    if (deviceInfo == NULL) {
        return NSTACKX_EINVAL;
    }

    internalDevice = GetDeviceInfoById(deviceInfo->deviceId, g_deviceList);
    if (internalDevice == NULL) {
        internalDevice = CreateNewDevice(deviceInfo);
        if (internalDevice == NULL) {
            return NSTACKX_ENOMEM;
        }
        updated = NSTACKX_TRUE;
    } else {
        if (UpdateDeviceInfo(internalDevice, deviceInfo, &updated) != NSTACKX_EOK) {
            return NSTACKX_EFAILED;
        }
    }
    internalDevice->update = updated;

    if (updated || forceUpdate) {
        DeviceListChangeHandle();
    }

    return NSTACKX_EOK;
}

static int32_t GetReservedInfo(DeviceInfo *deviceInfo, NSTACKX_DeviceInfo *deviceList)
{
    char wifiIpAddr[NSTACKX_MAX_IP_STRING_LEN];
    (void)memset_s(wifiIpAddr, sizeof(wifiIpAddr), 0, sizeof(wifiIpAddr));
    (void)inet_ntop(AF_INET, &deviceInfo->netChannelInfo.wifiApInfo.ip, wifiIpAddr, sizeof(wifiIpAddr));
    if (sprintf_s(deviceList[0].reservedInfo, sizeof(deviceList[0].reservedInfo),
        NSTACKX_RESERVED_INFO_JSON_FORMAT, wifiIpAddr) == NSTACKX_EFAILED) {
        return NSTACKX_EFAILED;
    }
    cJSON *item = cJSON_Parse(deviceList[0].reservedInfo);
    if (item == NULL) {
        LOGE(TAG, "pares deviceList fails");
        return NSTACKX_EFAILED;
    }

    if (deviceInfo->mode != DEFAULT_MODE) {
        if (!cJSON_AddNumberToObject(item, "mode", deviceInfo->mode)) {
            LOGE(TAG, "add mode to object failed");
        }
    }
    if (!cJSON_AddStringToObject(item, "hwAccountHashVal", deviceInfo->deviceHash)) {
        LOGE(TAG, "add hwAccountHashVal to object failed");
    }
    const char *ver = (strlen(deviceInfo->version) == 0) ? NSTACKX_DEFAULT_VER : deviceInfo->version;
    if (!cJSON_AddStringToObject(item, "version", ver)) {
        LOGE(TAG, "add hwAccountHashVal to object failed");
    }
    char *newData = cJSON_Print(item);
    if (newData == NULL) {
        cJSON_Delete(item);
        return NSTACKX_EFAILED;
    }
    (void)memset_s(deviceList[0].reservedInfo, sizeof(deviceList[0].reservedInfo), 0,
                   sizeof(deviceList[0].reservedInfo));
    if (strcpy_s(deviceList[0].reservedInfo, sizeof(deviceList[0].reservedInfo), newData) != EOK) {
        cJSON_Delete(item);
        free(newData);
        return NSTACKX_EFAILED;
    }
    cJSON_Delete(item);
    free(newData);
    return NSTACKX_EOK;
}

void PushPublishInfo(DeviceInfo *deviceInfo, NSTACKX_DeviceInfo *deviceList, uint32_t deviceNum)
{
    if (deviceNum != PUBLISH_DEVICE_NUM || deviceInfo == NULL) {
        return;
    }
    if (strcpy_s(deviceList[0].deviceId, sizeof(deviceList[0].deviceId), deviceInfo->deviceId) != EOK ||
        strcpy_s(deviceList[0].deviceName, sizeof(deviceList[0].deviceName), deviceInfo->deviceName) != EOK ||
        strcpy_s(deviceList[0].version, sizeof(deviceList[0].version), deviceInfo->version) != EOK) {
        return;
    }
    deviceList[0].capabilityBitmapNum = deviceInfo->capabilityBitmapNum;
    if (deviceInfo->capabilityBitmapNum) {
        if (memcpy_s(deviceList[0].capabilityBitmap, sizeof(deviceList[0].capabilityBitmap),
            deviceInfo->capabilityBitmap, deviceInfo->capabilityBitmapNum * sizeof(uint32_t)) != EOK) {
            return;
        }
    }

    if (GetReservedInfo(deviceInfo, deviceList) != NSTACKX_EOK) {
        LOGE(TAG, "GetReservedInfo Failed");
        return;
    }
    deviceList[0].deviceType = deviceInfo->deviceType;
}

static bool MatchDeviceFilter(DeviceInfo *deviceInfo)
{
    uint32_t i, ret;

    if (g_filterCapabilityBitmapNum == 0) {
        return true;
    }

    for (i = 0; ((i < g_filterCapabilityBitmapNum) && (i < deviceInfo->capabilityBitmapNum)); i++) {
        ret = (g_filterCapabilityBitmap[i] & (deviceInfo->capabilityBitmap[i]));
        if (ret != 0) {
            return true;
        }
    }
    return false;
}

static int8_t SetReservedInfoFromDeviceInfo(NSTACKX_DeviceInfo *deviceList, uint32_t count, DeviceInfo *deviceInfo)
{
    char wifiIpAddr[NSTACKX_MAX_IP_STRING_LEN];
    int ret  = NSTACKX_EFAILED;
    if (deviceList == NULL) {
        LOGE(TAG, "deviceList or deviceInfo is null");
        return NSTACKX_EINVAL;
    }

    (void)memset_s(wifiIpAddr, sizeof(wifiIpAddr), 0, sizeof(wifiIpAddr));
    (void)inet_ntop(AF_INET, &deviceInfo->netChannelInfo.wifiApInfo.ip, wifiIpAddr, sizeof(wifiIpAddr));
    if (sprintf_s(deviceList[count].reservedInfo, sizeof(deviceList[count].reservedInfo),
        NSTACKX_RESERVED_INFO_JSON_FORMAT, wifiIpAddr) == -1) {
        LOGE(TAG, "sprintf_s reservedInfo with wifiIpAddr fails");
        return NSTACKX_EAGAIN;
    }
    cJSON *item = cJSON_Parse(deviceList[count].reservedInfo);
    if (item == NULL) {
        LOGE(TAG, "pares deviceList fails");
        return NSTACKX_EINVAL;
    }

    if (deviceInfo->mode != 0 && !cJSON_AddNumberToObject(item, "mode", deviceInfo->mode)) {
        goto L_END;
    }
    if (!cJSON_AddStringToObject(item, "hwAccountHashVal", deviceInfo->deviceHash)) {
        goto L_END;
    }
    const char *ver = (strlen(deviceInfo->version) == 0) ? NSTACKX_DEFAULT_VER : deviceInfo->version;
    if (!cJSON_AddStringToObject(item, "version", ver)) {
        goto L_END;
    }
    if (strlen(deviceInfo->serviceData) != 0 && strlen(deviceInfo->serviceData) < NSTACKX_MAX_SERVICE_DATA_LEN) {
        if (!cJSON_AddStringToObject(item, "serviceData", deviceInfo->serviceData)) {
            goto L_END;
        }
    }
    char *newData = cJSON_Print(item);
    if (newData == NULL) {
        goto L_END;
    }
    (void)memset_s(deviceList[count].reservedInfo, sizeof(deviceList[count].reservedInfo),
                   0, sizeof(deviceList[count].reservedInfo));
    if (strcpy_s(deviceList[count].reservedInfo, sizeof(deviceList[count].reservedInfo), newData) != EOK) {
        free(newData);
        LOGE(TAG, "strcpy_s fails");
        goto L_END;
    }
    free(newData);
    ret = NSTACKX_EOK;
L_END:
    cJSON_Delete(item);
    return ret;
}

void GetDeviceList(NSTACKX_DeviceInfo *deviceList, uint32_t *deviceCountPtr, bool doFilter)
{
    DeviceInfo *deviceInfo = NULL;
    int64_t idx = -1;
    uint32_t count = 0;
    int32_t i;

    for (i = 0; i < NSTACKX_MAX_DEVICE_NUM; i++) {
        if (count >= *deviceCountPtr) {
            break;
        }

        deviceInfo = DatabaseGetNextRecord(g_deviceList, &idx);
        if (deviceInfo == NULL) {
            break;
        }

        if (doFilter && !MatchDeviceFilter(deviceInfo)) {
            continue;
        }

        if (strcpy_s(deviceList[count].deviceId, sizeof(deviceList[count].deviceId), deviceInfo->deviceId) != EOK ||
            strcpy_s(deviceList[count].deviceName, sizeof(deviceList[count].deviceName),
                     deviceInfo->deviceName) != EOK ||
            strcpy_s(deviceList[count].version, sizeof(deviceList[count].version), deviceInfo->version) != EOK) {
            break;
        }
        deviceList[count].capabilityBitmapNum = deviceInfo->capabilityBitmapNum;
        if (deviceInfo->capabilityBitmapNum) {
            if (memcpy_s(deviceList[count].capabilityBitmap, sizeof(deviceList[count].capabilityBitmap),
                deviceInfo->capabilityBitmap, deviceInfo->capabilityBitmapNum * sizeof(uint32_t)) != EOK) {
                break;
            }
        }

        int8_t result = SetReservedInfoFromDeviceInfo(deviceList, count, deviceInfo);
        if (result == NSTACKX_EAGAIN) {
            LOGE(TAG, "SetReservedInfoFromDeviceInfo fails, sprintf_s or strcpy_s fails");
            break;
        } else if (result == NSTACKX_EINVAL || result == NSTACKX_EFAILED) {
            LOGE(TAG, "SetReservedInfoFromDeviceInfo fails");
            return;
        }

        deviceList[count].deviceType = deviceInfo->deviceType;
        deviceList[count].mode = deviceInfo->mode;
        deviceList[count].update = deviceInfo->update;
        deviceInfo->update = NSTACKX_FALSE;
        ++count;
    }

    *deviceCountPtr = count;
}

static void DeviceListChangeHandle(void)
{
    size_t deviceListLen = sizeof(NSTACKX_DeviceInfo) * NSTACKX_MAX_DEVICE_NUM;
    NSTACKX_DeviceInfo *deviceList = (NSTACKX_DeviceInfo *)malloc(deviceListLen);
    if (deviceList == NULL) {
        return;
    }
    uint32_t count = NSTACKX_MAX_DEVICE_NUM;
    (void)memset_s(deviceList, deviceListLen, 0, deviceListLen);
    GetDeviceList(deviceList, &count, true);

    NotifyDeviceListChanged(deviceList, count);
    if (CoapDiscoverRequestOngoing()) {
        NotifyDeviceFound(deviceList, count);
    }
}

DeviceInfo *GetDeviceInfoById(const char *deviceId, const void *db)
{
    DeviceInfo dev;
    (void)memset_s(&dev, sizeof(dev), 0, sizeof(dev));
    if (strcpy_s(dev.deviceId, sizeof(dev.deviceId), deviceId) != EOK) {
        return NULL;
    }
    return DatabaseSearchRecord(db, &dev);
}

static uint8_t IsSameDevice(void *recptr, void *myptr)
{
    DeviceInfo *rec = recptr;
    DeviceInfo *my  = myptr;

    if (recptr == NULL || myptr == NULL) {
        LOGE(TAG, "NULL input, can't compare");
        return NSTACKX_FALSE;
    }

    if (strcmp(rec->deviceId, my->deviceId) == 0) {
        return NSTACKX_TRUE;
    }
    return NSTACKX_FALSE;
}

static const NetworkInterfaceInfo *GetLocalInterface(void)
{
    /* Ethernet have higher priority */
    if (g_interfaceList[NSTACKX_ETH_INDEX].ip.s_addr) {
        return &g_interfaceList[NSTACKX_ETH_INDEX];
    }

    if (g_interfaceList[NSTACKX_WLAN_INDEX].ip.s_addr) {
        return &g_interfaceList[NSTACKX_WLAN_INDEX];
    }

    return NULL;
}

static void GetLocalIp(struct in_addr *ip)
{
    const NetworkInterfaceInfo *ifInfo = GetLocalInterface();
    if (ifInfo != NULL) {
        (void)memcpy_s(ip, sizeof(struct in_addr),
                       &ifInfo->ip, sizeof(struct in_addr));
    } else {
        (void)memset_s(ip, sizeof(struct in_addr), 0, sizeof(struct in_addr));
    }
}

/* Return NSTACKX_TRUE if ifName prefix is the same, else return false */
static uint8_t NetworkInterfaceNamePrefixCmp(const char *ifName, const char *prefix)
{
    if (strlen(ifName) < strlen(prefix)) {
        return NSTACKX_FALSE;
    }

    if (memcmp(ifName, prefix, strlen(prefix)) == 0) {
        return NSTACKX_TRUE;
    }
    return NSTACKX_FALSE;
}

static int32_t UpdateLocalNetworkInterface(const NetworkInterfaceInfo *interfaceInfo)
{
    uint32_t i;
    struct in_addr preIp, newIp;

    if (interfaceInfo == NULL) {
        return NSTACKX_EINVAL;
    }

    GetLocalIp(&preIp);
    for (i = 0; i < NSTACKX_MAX_INTERFACE_NUM; i++) {
        if (NetworkInterfaceNamePrefixCmp(interfaceInfo->name, g_interfaceList[i].name) &&
            (i == NSTACKX_ETH_INDEX || i == NSTACKX_WLAN_INDEX)) {
            (void)memcpy_s(&g_interfaceList[i].ip, sizeof(struct in_addr), &interfaceInfo->ip, sizeof(struct in_addr));
            break;
        }
    }

    if (i == NSTACKX_MAX_INTERFACE_NUM) {
        return NSTACKX_EINVAL;
    }

    GetLocalIp(&newIp);
    if (newIp.s_addr == preIp.s_addr) {
        LOGI(TAG, "ip not changed");
        return NSTACKX_EOK;
    }

    /* Cleanup device db when Wifi AP disconnected. */
    if (interfaceInfo->ip.s_addr == 0) {
        /*
         * We don't cleanup DB and transport immediately.
         * Instead, defer the event for a while in case WiFi connected again.
         */
        LOGE(TAG, "g_networkType is %s and interfaceInfo is %s", g_networkType,  interfaceInfo->name);
        if (strcmp(g_networkType, interfaceInfo->name) != 0 && strcmp(g_networkType, "") != 0) {
            LOGE(TAG, "into ignore");
            return NSTACKX_EOK;
        }
        TimerSetTimeout(g_offlineDeferredTimer, NSTACKX_OFFLINE_DEFERRED_DURATION, NSTACKX_FALSE);
    } else {
        TimerSetTimeout(g_offlineDeferredTimer, 0, NSTACKX_FALSE);
        int ret = memcpy_s(g_networkType, sizeof(g_networkType), interfaceInfo->name, sizeof(interfaceInfo->name));
        if (ret != EOK) {
            LOGE(TAG, "memcpy_s error");
            return NSTACKX_EFAILED;
        }
        struct in_addr ip;
        (void)memcpy_s(&ip, sizeof(struct in_addr), &interfaceInfo->ip, sizeof(struct in_addr));
        CoapServerInit(&ip);
    }

    return NSTACKX_EOK;
}


void SetModeInfo(uint8_t mode)
{
    g_localDeviceInfo.mode = mode;
}

uint8_t GetModeInfo(void)
{
    return g_localDeviceInfo.mode;
}

void SetDeviceHash(uint64_t deviceHash)
{
    (void)memset_s(g_localDeviceInfo.deviceHash, sizeof(g_localDeviceInfo.deviceHash),
        0, sizeof(g_localDeviceInfo.deviceHash));
    if (sprintf_s(g_localDeviceInfo.deviceHash, DEVICE_HASH_LEN,
        "%ju", deviceHash) == -1) {
        LOGE(TAG, "set device hash error");
    }
}

int32_t ConfigureLocalDeviceInfo(const NSTACKX_LocalDeviceInfo *localDeviceInfo)
{
    char deviceId[NSTACKX_MAX_DEVICE_ID_LEN];
    struct in_addr ipAddr;
    NetworkInterfaceInfo interfaceInfo;

    (void)memset_s(&interfaceInfo, sizeof(interfaceInfo), 0, sizeof(interfaceInfo));
    /* Backup device id */
    (void)memcpy_s(deviceId, sizeof(deviceId), g_localDeviceInfo.deviceId, sizeof(deviceId));
    if (strcpy_s(g_localDeviceInfo.deviceId, sizeof(g_localDeviceInfo.deviceId), localDeviceInfo->deviceId) != EOK) {
        LOGE(TAG, "Invalid device id!");
        /* Restore device id if some error happens */
        if (memcpy_s(g_localDeviceInfo.deviceId, sizeof(g_localDeviceInfo.deviceId),
            deviceId, sizeof(deviceId)) != EOK) {
            LOGE(TAG, "deviceId copy error and can't restore device id!");
        }
        return NSTACKX_EINVAL;
    }

    if ((inet_pton(AF_INET, localDeviceInfo->networkIpAddr, &ipAddr) == 1) &&
        (strcpy_s(interfaceInfo.name, sizeof(interfaceInfo.name), localDeviceInfo->networkName) == EOK)) {
        interfaceInfo.ip = ipAddr;
        UpdateLocalNetworkInterface(&interfaceInfo);
    } else {
        LOGD(TAG, "Invalid if name or ip address. Ignore");
    }

    if (strlen(localDeviceInfo->name) == 0 || (strncpy_s(g_localDeviceInfo.deviceName,
        sizeof(g_localDeviceInfo.deviceName), localDeviceInfo->name, NSTACKX_MAX_DEVICE_NAME_LEN - 1) != EOK)) {
        LOGW(TAG, "Invalid device name. Will use default name");
        (void)strcpy_s(g_localDeviceInfo.deviceName, sizeof(g_localDeviceInfo.deviceName), NSTACKX_DEFAULT_DEVICE_NAME);
    }

    if (strcpy_s(g_localDeviceInfo.version, sizeof(g_localDeviceInfo.version), localDeviceInfo->version) != EOK) {
        LOGE(TAG, "Invalid version!");
        return NSTACKX_EINVAL;
    }

    g_localDeviceInfo.deviceType = localDeviceInfo->deviceType;

    return NSTACKX_EOK;
}

const DeviceInfo *GetLocalDeviceInfoPtr(void)
{
    return &g_localDeviceInfo;
}

uint8_t IsWifiApConnected(void)
{
    struct in_addr ip;
    GetLocalIp(&ip);
    if (ip.s_addr != 0) {
        return NSTACKX_TRUE;
    }
    return NSTACKX_FALSE;
}

int32_t GetLocalIpString(char *ipString, size_t length)
{
    struct in_addr ip;
    GetLocalIp(&ip);
    if (ip.s_addr == 0) {
        return NSTACKX_EFAILED;
    }
    if (inet_ntop(AF_INET, &ip, ipString, length) == NULL) {
        return NSTACKX_EFAILED;
    }
    return NSTACKX_EOK;
}

int32_t GetLocalInterfaceName(char *ifName, size_t ifNameLength)
{
    const NetworkInterfaceInfo *ifInfo = GetLocalInterface();
    if (ifInfo == NULL) {
        return NSTACKX_EFAILED;
    }

    if (strcpy_s(ifName, ifNameLength, ifInfo->name) != EOK) {
        return NSTACKX_EFAILED;
    }

    return NSTACKX_EOK;
}

int32_t RegisterCapability(uint32_t capabilityBitmapNum, uint32_t capabilityBitmap[])
{
    (void)memset_s(g_localDeviceInfo.capabilityBitmap, sizeof(g_localDeviceInfo.capabilityBitmap),
        0, sizeof(g_localDeviceInfo.capabilityBitmap));
    if (capabilityBitmapNum) {
        if (memcpy_s(g_localDeviceInfo.capabilityBitmap, sizeof(g_localDeviceInfo.capabilityBitmap),
            capabilityBitmap, sizeof(uint32_t) * capabilityBitmapNum) != EOK) {
            LOGE(TAG, "capabilityBitmap copy error");
            return NSTACKX_EFAILED;
        }
    }
    g_localDeviceInfo.capabilityBitmapNum = capabilityBitmapNum;
    return NSTACKX_EOK;
}

int32_t SetFilterCapability(uint32_t capabilityBitmapNum, uint32_t capabilityBitmap[])
{
    (void)memset_s(g_filterCapabilityBitmap, sizeof(g_filterCapabilityBitmap),
        0, sizeof(g_filterCapabilityBitmap));
    if (capabilityBitmapNum) {
        if (memcpy_s(g_filterCapabilityBitmap, sizeof(g_filterCapabilityBitmap),
            capabilityBitmap, sizeof(uint32_t) * capabilityBitmapNum) != EOK) {
            LOGE(TAG, "FilterCapabilityBitmap copy error");
            return NSTACKX_EFAILED;
        }
    }
    g_filterCapabilityBitmapNum = capabilityBitmapNum;
    return NSTACKX_EOK;
}

int32_t RegisterServiceData(const char *serviceData)
{
    if (serviceData == NULL) {
        LOGE(TAG, "device db init failed");
        return NSTACKX_EINVAL;
    }

    if (strcpy_s(g_localDeviceInfo.serviceData, NSTACKX_MAX_SERVICE_DATA_LEN - 1, serviceData) != EOK)  {
        LOGE(TAG, "serviceData copy error");
        return NSTACKX_EFAILED;
    }
    return NSTACKX_EOK;
}

void DeviceModuleClean(void)
{
    if (g_deviceInited == NSTACKX_FALSE) {
        return;
    }

    TimerDelete(g_offlineDeferredTimer);
    g_offlineDeferredTimer = NULL;

    if (g_deviceList != NULL) {
        ClearDevices(g_deviceList);
        LOGW(TAG, "clear device list");
        DatabaseClean(g_deviceList);
        g_deviceList = NULL;
    }
    if (g_deviceListBackup != NULL) {
        ClearDevices(g_deviceListBackup);
        LOGW(TAG, "clear device list backup");
        DatabaseClean(g_deviceListBackup);
        g_deviceListBackup = NULL;
    }

    g_deviceInited = NSTACKX_FALSE;
    return;
}

int32_t DeviceModuleInit(EpollDesc epollfd)
{
    int32_t ret = NSTACKX_EFAILED;

    if (g_deviceInited) {
        return NSTACKX_EOK;
    }
    (void)memset_s(&g_localDeviceInfo, sizeof(g_localDeviceInfo), 0, sizeof(g_localDeviceInfo));
    (void)memset_s(g_networkType, sizeof(g_networkType), 0, sizeof(g_networkType));
    g_deviceList = DatabaseInit(NSTACKX_MAX_DEVICE_NUM, sizeof(DeviceInfo), IsSameDevice);
    if (g_deviceList == NULL) {
        LOGE(TAG, "device db init failed");
        ret = NSTACKX_ENOMEM;
        goto L_ERR_DEVICE_DB_LIST;
    }
    g_deviceListBackup = DatabaseInit(NSTACKX_MAX_DEVICE_NUM, sizeof(DeviceInfo), IsSameDevice);
    if (g_deviceListBackup == NULL) {
        LOGE(TAG, "device db backup init failed");
        ret = NSTACKX_ENOMEM;
        goto L_ERR_DEVICE_DB_BACKUP_LIST;
    }

    g_offlineDeferredTimer = TimerStart(epollfd, 0, NSTACKX_FALSE, LocalDeviceOffline, NULL);
    if (g_offlineDeferredTimer == NULL) {
        LOGE(TAG, "device offline deferred timer start failed");
        goto L_ERR_DEFERRED_TIMER;
    }
    (void)memset_s(g_interfaceList, sizeof(g_interfaceList), 0, sizeof(g_interfaceList));
    (void)strcpy_s(g_interfaceList[NSTACKX_WLAN_INDEX].name,
        sizeof(g_interfaceList[NSTACKX_WLAN_INDEX].name), NSTACKX_WLAN_INTERFACE_NAME_PREFIX);
    (void)strcpy_s(g_interfaceList[NSTACKX_ETH_INDEX].name,
        sizeof(g_interfaceList[NSTACKX_ETH_INDEX].name), NSTACKX_ETH_INTERFACE_NAME_PREFIX);
    g_deviceInited = NSTACKX_TRUE;
    return NSTACKX_EOK;

    /* Call TimerDelete(g_offlineDeferredTimer) when add module. */
L_ERR_DEFERRED_TIMER:
    DatabaseClean(g_deviceListBackup);
    g_deviceListBackup = NULL;
L_ERR_DEVICE_DB_BACKUP_LIST:
    DatabaseClean(g_deviceList);
    g_deviceList = NULL;
L_ERR_DEVICE_DB_LIST:
    return ret;
}

int32_t BackupDeviceDB(void)
{
    void *db = g_deviceList;
    void *backupDB = g_deviceListBackup;
    int64_t idx = -1;
    DeviceInfo *deviceInfo = NULL;

    if (db == NULL || backupDB == NULL) {
        return NSTACKX_EFAILED;
    }
    uint8_t result = ClearDevices(backupDB);
    if (result == NSTACKX_FALSE) {
        LOGE(TAG, "clear backupDB error");
    }

    for (int i = 0; i < NSTACKX_MAX_DEVICE_NUM; i++) {
        deviceInfo = DatabaseGetNextRecord(db, &idx);
        if (deviceInfo == NULL) {
            break;
        }

        DeviceInfo *newDeviceInfo = DatabaseAllocRecord(backupDB);
        if (newDeviceInfo == NULL) {
            LOGE(TAG, "allocate device info failure");
            return NSTACKX_EFAILED;
        }
        if (memcpy_s(newDeviceInfo, sizeof(DeviceInfo), deviceInfo, sizeof(DeviceInfo)) != EOK) {
            LOGE(TAG, "memcpy failure");
            return NSTACKX_EFAILED;
        }
    }
    return NSTACKX_EOK;
}

void *GetDeviceDB(void)
{
    return g_deviceList;
}

void *GetDeviceDBBackup(void)
{
    return g_deviceListBackup;
}

void ResetDeviceTaskCount(uint8_t isBusy)
{
    if (g_offlineDeferredTimer != NULL) {
        if (isBusy) {
            LOGI(TAG, "in this busy interval: g_offlineDeferredTimer task count %llu",
                 g_offlineDeferredTimer->task.count);
        }
        g_offlineDeferredTimer->task.count = 0;
    }
}
