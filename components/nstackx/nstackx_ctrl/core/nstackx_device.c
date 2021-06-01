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
#ifdef SUPPORT_SMARTGENIUS
#include <linux/rtnetlink.h>
#include <arpa/inet.h>
#endif /* SUPPORT_SMARTGENIUS */

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
#define NSTACKX_P2PUSB_SERVERINIT_MAX_RETRY_TIMES 4

#define NSTACKX_DEFAULT_DEVICE_NAME "nStack Device"

#define NSTACKX_RESERVED_INFO_WIFI_IP "wifiIpAddr"

#define NSTACKX_WLAN_INDEX 0
#define NSTACKX_ETH_INDEX 1
#define NSTACKX_P2P_INDEX 2
#define NSTACKX_USB_INDEX 3
#define NSTACKX_MAX_INTERFACE_NUM 4
#define NETWORKTYPE_LENGTH 20
#define NSTACKX_WLAN_INTERFACE_NAME_PREFIX "wlan"
#define NSTACKX_ETH_INTERFACE_NAME_PREFIX "eth"
#define NSTACKX_P2P_INTERFACE_NAME_PREFIX "p2p-p2p0-"
#define NSTACKX_P2P_WLAN_INTERFACE_NAME_PREFIX "p2p-wlan0-"
#define NSTACKX_USB_INTERFACE_NAME_PREFIX "rndis0"
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
static Timer *g_p2pServerInitDeferredTimer = NULL;
static Timer *g_usbServerInitDeferredTimer = NULL;
static uint8_t g_deviceInited;
static DeviceInfo g_localDeviceInfo;
static uint32_t g_filterCapabilityBitmapNum = 0;
static uint32_t g_filterCapabilityBitmap[NSTACKX_MAX_CAPABILITY_NUM] = {0};
static NetworkInterfaceInfo g_interfaceList[NSTACKX_MAX_INTERFACE_NUM];
static char g_networkType[NETWORKTYPE_LENGTH] = {0};
static const uint32_t g_serverInitRetryBackoffList[NSTACKX_P2PUSB_SERVERINIT_MAX_RETRY_TIMES] = { 10, 15, 25, 100 };
static uint32_t g_p2pRetryCount = 0;
static uint32_t g_usbRetryCount = 0;

static struct in_addr g_p2pIp;
static struct in_addr g_usbIp;

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

static void StopP2pServerInitRetryTimer(void)
{
    if (g_p2pRetryCount != 0 && g_p2pServerInitDeferredTimer != NULL) {
        TimerSetTimeout(g_p2pServerInitDeferredTimer, 0, NSTACKX_FALSE); // stop previous timer
        g_p2pRetryCount = 0;
    }
}

static void StopUsbServerInitRetryTimer(void)
{
    if (g_usbRetryCount != 0 && g_usbServerInitDeferredTimer != NULL) {
        TimerSetTimeout(g_usbServerInitDeferredTimer, 0, NSTACKX_FALSE); // stop previous timer
        g_usbRetryCount = 0;
        (void)memset_s(&g_usbIp, sizeof(g_usbIp), 0, sizeof(g_usbIp));
    }
}

void DestroyP2pUsbServerInitRetryTimer(void)
{
    if (g_p2pServerInitDeferredTimer != NULL) {
        StopP2pServerInitRetryTimer();
        TimerDelete(g_p2pServerInitDeferredTimer);
        g_p2pServerInitDeferredTimer = NULL;
    }
    if (g_usbServerInitDeferredTimer != NULL) {
        StopUsbServerInitRetryTimer();
        TimerDelete(g_usbServerInitDeferredTimer);
        g_usbServerInitDeferredTimer = NULL;
    }
}

static void CoapP2pServerInitDelayHandler(void *data)
{
    (void)data;
    LOGD(TAG, "CoapP2pServerInitDelay, retry %u times", g_p2pRetryCount);
    if (CoapP2pServerInit(&g_p2pIp) == NSTACKX_EOK) {
        LOGE(TAG, "CoapP2pServerInitDelay success");
        g_p2pRetryCount = 0;
        return;
    }
    if (g_p2pRetryCount >= NSTACKX_P2PUSB_SERVERINIT_MAX_RETRY_TIMES) {
        LOGE(TAG, "CoapP2pServerInitDelay retry reach max times");
        g_p2pRetryCount = 0;
        (void)memset_s(&g_p2pIp, sizeof(g_p2pIp), 0, sizeof(g_p2pIp));
        return;
    }
    TimerSetTimeout(g_p2pServerInitDeferredTimer, g_serverInitRetryBackoffList[g_p2pRetryCount], NSTACKX_FALSE);
    g_p2pRetryCount++;
}

static void CoapUsbServerInitDelayHandler(void *data)
{
    LOGD(TAG, "CoapUsbServerInitDelay, retry %u times", g_usbRetryCount);
    (void)data;
    if (CoapUsbServerInit(&g_usbIp) == NSTACKX_EOK) {
        LOGE(TAG, "CoapUsbServerInitDelay success");
        g_usbRetryCount = 0;
        (void)memset_s(&g_usbIp, sizeof(g_usbIp), 0, sizeof(g_usbIp));
        return;
    }
    if (g_usbRetryCount >= NSTACKX_P2PUSB_SERVERINIT_MAX_RETRY_TIMES) {
        LOGE(TAG, "CoapUsbServerInitDelay retry reach max times");
        g_usbRetryCount = 0;
        (void)memset_s(&g_usbIp, sizeof(g_usbIp), 0, sizeof(g_usbIp));
        return;
    }

    TimerSetTimeout(g_usbServerInitDeferredTimer, g_serverInitRetryBackoffList[g_usbRetryCount], NSTACKX_FALSE);
    g_usbRetryCount++;
}

int32_t P2pUsbTimerInit(EpollDesc epollfd)
{
    g_p2pRetryCount = 0;
    g_usbRetryCount = 0;
    g_p2pServerInitDeferredTimer = TimerStart(epollfd, 0, NSTACKX_FALSE, CoapP2pServerInitDelayHandler, NULL);
    if (g_p2pServerInitDeferredTimer == NULL) {
        LOGE(TAG, "g_p2pServerInitDeferredTimer start failed");
        return NSTACKX_EFAILED;
    }
    (void)memset_s(&g_p2pIp, sizeof(g_p2pIp), 0, sizeof(g_p2pIp));
    g_usbServerInitDeferredTimer = TimerStart(epollfd, 0, NSTACKX_FALSE, CoapUsbServerInitDelayHandler, NULL);
    if (g_usbServerInitDeferredTimer == NULL) {
        LOGE(TAG, "g_UsbServerInitDeferredTimer start failed");
        return NSTACKX_EFAILED;
    }
    (void)memset_s(&g_usbIp, sizeof(g_usbIp), 0, sizeof(g_usbIp));
    return NSTACKX_EOK;
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

int8_t SetReservedInfoFromDeviceInfo(NSTACKX_DeviceInfo *deviceList, uint32_t count, DeviceInfo *deviceInfo)
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

static void DeviceListChangeHandle(void)
{
    NSTACKX_DeviceInfo deviceList[NSTACKX_MAX_DEVICE_NUM];
    uint32_t count = NSTACKX_MAX_DEVICE_NUM;

    (void)memset_s(deviceList, sizeof(deviceList), 0, sizeof(deviceList));
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

    if (g_interfaceList[NSTACKX_P2P_INDEX].ip.s_addr) {
        return &g_interfaceList[NSTACKX_P2P_INDEX];
    }

    if (g_interfaceList[NSTACKX_USB_INDEX].ip.s_addr) {
        return &g_interfaceList[NSTACKX_USB_INDEX];
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

int32_t UpdateLocalNetworkInterface(const NetworkInterfaceInfo *interfaceInfo)
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

void SetP2pIp(const struct in_addr *ip)
{
    if (ip == NULL) {
        return;
    }
    if (memcpy_s(&g_p2pIp, sizeof(struct in_addr), ip, sizeof(struct in_addr)) != EOK) {
        LOGE(TAG, "memcpy_s failed");
    }
}

static void TryToInitP2pCoapServer(struct in_addr ip)
{
    /* ignore p2p service when new ip is 0. */
    if (ip.s_addr == 0) {
        LOGE(TAG, "p2p newIp is 0");
        return;
    }
    StopP2pServerInitRetryTimer();
    if (CoapP2pServerInit(&ip) != NSTACKX_EOK) { /* If init fail, start retry */
        LOGE(TAG, "start p2p init delayed");
        if (g_p2pServerInitDeferredTimer == NULL) {
            return;
        }
        /* if CoapP2pServerInit failed, update the g_p2pIp */
        SetP2pIp(&ip);
        TimerSetTimeout(g_p2pServerInitDeferredTimer, g_serverInitRetryBackoffList[0], NSTACKX_FALSE);
        g_p2pRetryCount++;
        return;
    }
    LOGD(TAG, "start p2p init success");
}

int32_t UpdateLocalNetworkInterfaceP2pMode(const NetworkInterfaceInfo *interfaceInfo, uint16_t nlmsgType)
{
    struct in_addr newIp;

    if (interfaceInfo == NULL) {
        return NSTACKX_EINVAL;
    }

#ifdef SUPPORT_SMARTGENIUS
    if (nlmsgType == RTM_DELADDR) {
        LOGD(TAG, "p2p delete address, call CoapP2pServerDestroy()");
        CoapP2pServerDestroy();
        StopP2pServerInitRetryTimer();
        (void)memset_s(&g_p2pIp, sizeof(g_p2pIp), 0, sizeof(g_p2pIp));
        return NSTACKX_EOK;
    }
#else
    (void)nlmsgType;
#endif /* SUPPORT_SMARTGENIUS */

    /* p2p new ip does not write to g_interfaceList */
    if (NetworkInterfaceNamePrefixCmp(interfaceInfo->name, g_interfaceList[NSTACKX_P2P_INDEX].name) ||
        NetworkInterfaceNamePrefixCmp(interfaceInfo->name, g_interfaceList[NSTACKX_P2P_INDEX].alias)) {
        if (memcpy_s(&newIp, sizeof(struct in_addr), &interfaceInfo->ip, sizeof(struct in_addr)) != EOK) {
            LOGE(TAG, "newIp memcpy_s failed");
            return NSTACKX_EFAILED;
        }
    } else {
        LOGI(TAG, "NetworkInterfaceNamePrefixCmp p2p fail");
        return NSTACKX_EINVAL;
    }
    TryToInitP2pCoapServer(newIp);
    return NSTACKX_EOK;
}

void SetUsbIp(const struct in_addr *ip)
{
    if (ip == NULL) {
        return;
    }
    if (memcpy_s(&g_usbIp, sizeof(struct in_addr), ip, sizeof(struct in_addr)) != EOK) {
        LOGE(TAG, "memcpy_s failed");
    }
}

static void TryToInitUsbCoapServer(struct in_addr ip)
{
    /* ignore usb service when new ip is 0. */
    if (ip.s_addr == 0) {
        LOGE(TAG, "usb newIp is 0");
        return;
    }

    StopUsbServerInitRetryTimer();
    if (CoapUsbServerInit(&ip) != NSTACKX_EOK) {
        LOGE(TAG, "start usb init delayed");
        if (g_usbServerInitDeferredTimer == NULL) {
            return;
        }

        /* if CoapUsbServerInit failed, update the g_p2pIp */
        SetUsbIp(&ip);

        TimerSetTimeout(g_usbServerInitDeferredTimer, g_serverInitRetryBackoffList[0], NSTACKX_FALSE);
        g_usbRetryCount++;
        return;
    }
    LOGI(TAG, "start usb init success");
}

int32_t UpdateLocalNetworkInterfaceUsbMode(const NetworkInterfaceInfo *interfaceInfo, uint16_t nlmsgType)
{
    struct in_addr newIp;

    if (interfaceInfo == NULL) {
        return NSTACKX_EINVAL;
    }

#ifdef SUPPORT_SMARTGENIUS
    if (nlmsgType == RTM_DELADDR) {
        LOGD(TAG, "usb delete address, call CoapUsbServerDestroy()");
        CoapUsbServerDestroy();
        StopUsbServerInitRetryTimer();
        (void)memset_s(&g_usbIp, sizeof(g_usbIp), 0, sizeof(g_usbIp));
        return NSTACKX_EOK;
    }
#else
    (void)nlmsgType;
#endif /* SUPPORT_SMARTGENIUS */

    /* usb new ip does not write to g_interfaceList */
    if (NetworkInterfaceNamePrefixCmp(interfaceInfo->name, g_interfaceList[NSTACKX_USB_INDEX].name)) {
        if (memcpy_s(&newIp, sizeof(struct in_addr), &interfaceInfo->ip, sizeof(struct in_addr)) != EOK) {
            LOGE(TAG, "newIp memcpy_s failed");
            return NSTACKX_EFAILED;
        }
    } else {
        return NSTACKX_EINVAL;
    }
    TryToInitUsbCoapServer(newIp);
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

int32_t GetP2pIpString(char *ipString, size_t length)
{
    if (ipString == NULL || length == 0) {
        return NSTACKX_EFAILED;
    }
    if (inet_ntop(AF_INET, &g_p2pIp, ipString, length) == NULL) {
        return NSTACKX_EFAILED;
    }
    return NSTACKX_EOK;
}

int32_t GetUsbIpString(char *ipString, size_t length)
{
    if (ipString == NULL || length == 0) {
        return NSTACKX_EFAILED;
    }
    if (inet_ntop(AF_INET, &g_usbIp, ipString, length) == NULL) {
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

uint8_t FilterNetworkInterface(const char *ifName)
{
    uint32_t i;
    if (ifName == NULL) {
        return NSTACKX_FALSE;
    }

    for (i = 0; i < NSTACKX_MAX_INTERFACE_NUM; i++) {
        if (NetworkInterfaceNamePrefixCmp(ifName, g_interfaceList[i].name) ||
            NetworkInterfaceNamePrefixCmp(ifName, g_interfaceList[i].alias)) {
            return NSTACKX_TRUE;
        }
    }
    return NSTACKX_FALSE;
}

uint8_t IsWlanIpAddr(const char *ifName)
{
    if (ifName == NULL) {
        return NSTACKX_FALSE;
    }

    if (NetworkInterfaceNamePrefixCmp(ifName, g_interfaceList[NSTACKX_WLAN_INDEX].name)) {
        LOGE(TAG, "IsWlanIpAddr success");
        return NSTACKX_TRUE;
    }

    return NSTACKX_FALSE;
}

uint8_t IsEthIpAddr(const char *ifName)
{
    if (ifName == NULL) {
        return NSTACKX_FALSE;
    }

    if (NetworkInterfaceNamePrefixCmp(ifName, g_interfaceList[NSTACKX_ETH_INDEX].name)) {
        LOGE(TAG, "IsEthIpAddr success");
        return NSTACKX_TRUE;
    }

    return NSTACKX_FALSE;
}

uint8_t IsP2pIpAddr(const char *ifName)
{
    if (ifName == NULL) {
        return NSTACKX_FALSE;
    }

    if (NetworkInterfaceNamePrefixCmp(ifName, g_interfaceList[NSTACKX_P2P_INDEX].name) ||
        NetworkInterfaceNamePrefixCmp(ifName, g_interfaceList[NSTACKX_P2P_INDEX].alias)) {
        LOGE(TAG, "IsP2pIpAddr success");
        return NSTACKX_TRUE;
    }

    return NSTACKX_FALSE;
}

uint8_t IsUsbIpAddr(const char *ifName)
{
    if (ifName == NULL) {
        return NSTACKX_FALSE;
    }

    if (NetworkInterfaceNamePrefixCmp(ifName, g_interfaceList[NSTACKX_USB_INDEX].name)) {
        LOGE(TAG, "IsUsbIpAddr success");
        return NSTACKX_TRUE;
    }

    return NSTACKX_FALSE;
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
    (void)strcpy_s(g_interfaceList[NSTACKX_P2P_INDEX].name,
        sizeof(g_interfaceList[NSTACKX_P2P_INDEX].name), NSTACKX_P2P_INTERFACE_NAME_PREFIX);
    (void)strcpy_s(g_interfaceList[NSTACKX_P2P_INDEX].alias,
        sizeof(g_interfaceList[NSTACKX_P2P_INDEX].alias), NSTACKX_P2P_WLAN_INTERFACE_NAME_PREFIX);
    (void)strcpy_s(g_interfaceList[NSTACKX_USB_INDEX].name,
        sizeof(g_interfaceList[NSTACKX_USB_INDEX].name), NSTACKX_USB_INTERFACE_NAME_PREFIX);
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

static void PadNetworkInterfaceInfo(NetworkInterfaceInfo *intInfo, const struct in_addr *addr, const char *name)
{
    if (intInfo == NULL || addr == NULL || name == NULL) {
        return;
    }
    (void)memset_s(intInfo, sizeof(NetworkInterfaceInfo), 0, sizeof(NetworkInterfaceInfo));
    (void)memcpy_s(&intInfo->ip, sizeof(struct in_addr), addr, sizeof(struct in_addr));
    if (strcpy_s(intInfo->name, sizeof(intInfo->name), name) != EOK) {
        LOGE(TAG, "interface name copy failed");
    }
}

void GetLocalNetworkInterface(void *arg)
{
    struct ifreq buf[INTERFACE_MAX];
    struct ifconf ifc;
    uint8_t isUpdated[NSTACKX_MAX_INTERFACE_NUM] = {0};
    NetworkInterfaceInfo wlanIntInfo, ethIntInfo;
    (void)arg;
    int fd = GetInterfaceList(&ifc, buf, sizeof(buf));
    if (fd < 0) {
        return;
    }

    int interfaceNum = ifc.ifc_len / sizeof(struct ifreq);
    for (int i = 0; i < interfaceNum && i < INTERFACE_MAX; i++) {
        /* get IP of this interface */
        int state = GetInterfaceIP(fd, &buf[i]);
        if (state == NSTACKX_EFAILED) {
            close(fd);
            return;
        } else if (state == NSTACKX_EINVAL) {
            continue;
        }
        struct sockaddr_in *sa = (struct sockaddr_in *)&(buf[i].ifr_addr);
        if (IsEthIpAddr(buf[i].ifr_name) && !isUpdated[NSTACKX_ETH_INDEX]) {
            PadNetworkInterfaceInfo(&ethIntInfo, &sa->sin_addr, buf[i].ifr_name);
            isUpdated[NSTACKX_ETH_INDEX] = NSTACKX_TRUE;
            continue;
        }
        if (IsWlanIpAddr(buf[i].ifr_name) && !isUpdated[NSTACKX_WLAN_INDEX]) {
            PadNetworkInterfaceInfo(&wlanIntInfo, &sa->sin_addr, buf[i].ifr_name);
            isUpdated[NSTACKX_WLAN_INDEX] = NSTACKX_TRUE;
            continue;
        }

        /* p2p or usb new ip does not write to g_interfaceList */
        if (IsP2pIpAddr(buf[i].ifr_name) && !isUpdated[NSTACKX_P2P_INDEX]) {
            TryToInitP2pCoapServer(sa->sin_addr);
            isUpdated[NSTACKX_P2P_INDEX] = NSTACKX_TRUE;
            continue;
        }
        if (IsUsbIpAddr(buf[i].ifr_name) && !isUpdated[NSTACKX_USB_INDEX]) {
            TryToInitUsbCoapServer(sa->sin_addr);
            isUpdated[NSTACKX_USB_INDEX] = NSTACKX_TRUE;
            continue;
        }
    }
    close(fd);
    if (isUpdated[NSTACKX_ETH_INDEX] && UpdateLocalNetworkInterface(&ethIntInfo) != NSTACKX_EOK) {
        LOGE(TAG, "Update eth interface failed");
    }
    if (!isUpdated[NSTACKX_ETH_INDEX] && isUpdated[NSTACKX_WLAN_INDEX] &&
        UpdateLocalNetworkInterface(&wlanIntInfo) != NSTACKX_EOK) {
        LOGE(TAG, "Update wlan interface failed");
    }
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

    if (g_p2pServerInitDeferredTimer != NULL) {
        if (isBusy) {
            LOGI(TAG, "in this busy interval: g_p2pServerInitDeferredTimer task count %llu",
                 g_p2pServerInitDeferredTimer->task.count);
        }
        g_p2pServerInitDeferredTimer->task.count = 0;
    }

    if (g_usbServerInitDeferredTimer != NULL) {
        if (isBusy) {
            LOGI(TAG, "in this busy interval: g_usbServerInitDeferredTimer task count %llu",
                 g_usbServerInitDeferredTimer->task.count);
        }
        g_usbServerInitDeferredTimer->task.count = 0;
    }
}

