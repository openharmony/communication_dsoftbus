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
#ifndef _WIN32
#include <unistd.h>
#endif
#ifdef SUPPORT_SMARTGENIUS
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <arpa/inet.h>
#endif /* SUPPORT_SMARTGENIUS */

#include "cJSON.h"
#include "nstackx_dfinder_log.h"
#include "nstackx_event.h"
#include "nstackx_timer.h"
#include "nstackx_error.h"
#include "nstackx_util.h"
#include "nstackx_common.h"
#ifdef DFINDER_SAVE_DEVICE_LIST
#include "nstackx_database.h"
#endif
#include "coap_app.h"
#include "coap_discover.h"
#include "json_payload.h"
#include "nstackx_statistics.h"

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

#ifdef DFINDER_SUPPORT_MULTI_NIF
#define IF_STATE_INIT 0
#define IF_STATE_UPDATED 1
#define IF_STATE_REMAIN_UP 2
#endif

#ifdef DFINDER_SAVE_DEVICE_LIST
static void *g_deviceList = NULL;
static void *g_deviceListBackup = NULL;
#endif

static Timer *g_offlineDeferredTimer = NULL;
#ifndef DFINDER_SUPPORT_MULTI_NIF
static Timer *g_p2pServerInitDeferredTimer = NULL;
static Timer *g_usbServerInitDeferredTimer = NULL;
#endif

static uint32_t g_maxDeviceNum;
static uint8_t g_deviceInited;
static DeviceInfo g_localDeviceInfo;
static uint32_t g_filterCapabilityBitmapNum = 0;
static uint32_t g_filterCapabilityBitmap[NSTACKX_MAX_CAPABILITY_NUM] = {0};
/* g_interfaceList store the actual interface name prefix for one platform */
static NetworkInterfaceInfo g_interfaceList[NSTACKX_MAX_INTERFACE_NUM];

#if !defined(DFINDER_SUPPORT_MULTI_NIF)
static char g_networkType[NETWORKTYPE_LENGTH] = {0};
#endif
#if !defined(DFINDER_SUPPORT_MULTI_NIF) && !defined(DFINDER_USE_MINI_NSTACKX)
/*
 * g_interfacePrefixList store all interface name prefix to adapt different platform
 * when platform interface name prefix update, just update g_interfacePrefixList
 */
static const NetworkInterfacePrefiexPossible g_interfacePrefixList[NSTACKX_MAX_INTERFACE_NUM] = {
    {{"wlan", "ap", ""}},
    {{"eth", "", ""}},
    {{"p2p-p2p0-", "p2p-wlan0-", "p2p0"}},
    {{"rndis0", "", ""}}
};
static const uint32_t g_serverInitRetryBackoffList[NSTACKX_P2PUSB_SERVERINIT_MAX_RETRY_TIMES] = { 10, 15, 25, 100 };
static uint32_t g_p2pRetryCount = 0;
static uint32_t g_usbRetryCount = 0;

static struct in_addr g_p2pIp;
static struct in_addr g_usbIp;
#endif /* END OF (!DFINDER_USE_MINI_NSTACKX) && (!DFINDER_SUPPORT_MULTI_NIF) */

#ifdef DFINDER_SAVE_DEVICE_LIST
static void DeviceListChangeHandle(void);
static void GetDeviceList(void *dbList, NSTACKX_DeviceInfo *deviceList, uint32_t *deviceCountPtr, bool doFilter);
#endif

static bool MatchDeviceFilter(const DeviceInfo *deviceInfo);

#ifndef DFINDER_SAVE_DEVICE_LIST
static int32_t GetNotifyDeviceInfo(NSTACKX_DeviceInfo *notifyDevice, const DeviceInfo *deviceInfo);
#endif

#ifdef DFINDER_SAVE_DEVICE_LIST
static uint8_t IsSameDevice(void *recptr, void *myptr);
#ifdef DFINDER_SUPPORT_MULTI_NIF
static void GetDeviceListWithReportIdx(void *dbList, NSTACKX_DeviceInfo *deviceList,
    uint32_t *deviceCountPtr, bool doFilter);
static uint32_t CheckAndUpdateBusinessAll(BusinessDataAll *a, const BusinessDataAll *b, uint8_t *updated);
#endif
#endif

#ifdef DFINDER_SAVE_DEVICE_LIST
uint8_t ClearDevices(void *deviceList)
{
    uint32_t i;
    int64_t idx = -1;
    DeviceInfo *dev = NULL;
    uint8_t deviceRemoved = NSTACKX_FALSE;

    if (deviceList == NULL) {
        return deviceRemoved;
    }

    for (i = 0; i < g_maxDeviceNum; i++) {
        dev = DatabaseGetNextRecord(deviceList, &idx);
        if (dev == NULL) {
            break;
        }
        DatabaseFreeRecord(deviceList, (void *)dev);
        deviceRemoved = NSTACKX_TRUE;
    }
    return deviceRemoved;
}
#endif /* END OF DFINDER_SAVE_DEVICE_LIST */

static void LocalDeviceOffline(void *data)
{
#ifdef DFINDER_SAVE_DEVICE_LIST
    uint8_t deviceRemoved;
    (void)data;
    (void)ClearDevices(g_deviceListBackup);
    DFINDER_LOGW(TAG, "clear device list backup");
    deviceRemoved = ClearDevices(g_deviceList);
    DFINDER_LOGW(TAG, "clear device list");
#ifdef DFINDER_SUPPORT_MULTI_NIF
    for (uint32_t i = 0; i < NSTACKX_MAX_LISTENED_NIF_NUM; ++i) {
        CoapServerDestroyWithIdx(i);
    }
#else
    CoapServerDestroy();
#endif /* END OF DFINDER_SUPPORT_MULTI_NIF */
    if (deviceRemoved) {
        DeviceListChangeHandle();
    }
#else
    (void)data;
#endif /* END OF DFINDER_SAVE_DEVICE_LIST */
}

#if !defined(DFINDER_SUPPORT_MULTI_NIF) && !defined(DFINDER_USE_MINI_NSTACKX)
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
    DFINDER_LOGD(TAG, "CoapP2pServerInitDelay, retry %u times", g_p2pRetryCount);
    if (CoapP2pServerInit(&g_p2pIp) == NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "CoapP2pServerInitDelay success");
        g_p2pRetryCount = 0;
        return;
    }
    if (g_p2pRetryCount >= NSTACKX_P2PUSB_SERVERINIT_MAX_RETRY_TIMES) {
        DFINDER_LOGE(TAG, "CoapP2pServerInitDelay retry reach max times");
        g_p2pRetryCount = 0;
        (void)memset_s(&g_p2pIp, sizeof(g_p2pIp), 0, sizeof(g_p2pIp));
        return;
    }
    TimerSetTimeout(g_p2pServerInitDeferredTimer, g_serverInitRetryBackoffList[g_p2pRetryCount], NSTACKX_FALSE);
    g_p2pRetryCount++;
}

static void CoapUsbServerInitDelayHandler(void *data)
{
    DFINDER_LOGD(TAG, "CoapUsbServerInitDelay, retry %u times", g_usbRetryCount);
    (void)data;
    if (CoapUsbServerInit(&g_usbIp) == NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "CoapUsbServerInitDelay success");
        g_usbRetryCount = 0;
        (void)memset_s(&g_usbIp, sizeof(g_usbIp), 0, sizeof(g_usbIp));
        return;
    }
    if (g_usbRetryCount >= NSTACKX_P2PUSB_SERVERINIT_MAX_RETRY_TIMES) {
        DFINDER_LOGE(TAG, "CoapUsbServerInitDelay retry reach max times");
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
        DFINDER_LOGE(TAG, "g_p2pServerInitDeferredTimer start failed");
        return NSTACKX_EFAILED;
    }
    (void)memset_s(&g_p2pIp, sizeof(g_p2pIp), 0, sizeof(g_p2pIp));
    g_usbServerInitDeferredTimer = TimerStart(epollfd, 0, NSTACKX_FALSE, CoapUsbServerInitDelayHandler, NULL);
    if (g_usbServerInitDeferredTimer == NULL) {
        DFINDER_LOGE(TAG, "g_UsbServerInitDeferredTimer start failed");
        return NSTACKX_EFAILED;
    }
    (void)memset_s(&g_usbIp, sizeof(g_usbIp), 0, sizeof(g_usbIp));

    return NSTACKX_EOK;
}
#endif /* END OF (!DFINDER_USE_MINI_NSTACKX) && (!DFINDER_SUPPORT_MULTI_NIF) */

#ifdef DFINDER_SUPPORT_MULTI_NIF
static void DeviceListChangeHandleMultiNif()
{
    uint32_t count = g_maxDeviceNum;
    DFINDER_LOGD(TAG, "max device num:%d", g_maxDeviceNum);
    size_t listLen = sizeof(NSTACKX_DeviceInfo) * count;
    NSTACKX_DeviceInfo *deviceList = (NSTACKX_DeviceInfo *)malloc(listLen);
    if (deviceList == NULL) {
        DFINDER_LOGE(TAG, "malloc for device list failed when for multi network interface");
        return;
    }
    (void)memset_s(deviceList, listLen, 0, listLen);
    GetDeviceListWithReportIdx(g_deviceList, deviceList, &count, true);
    if (count == 0) {
        DFINDER_LOGW(TAG, "MULTI_NIF count is zero, do not notify");
        free(deviceList);
        return;
    }
    NotifyDeviceListChanged(deviceList, count);
    if (CoapDiscoverRequestOngoing()) {
        NotifyDeviceFound(deviceList, count);
    }
    free(deviceList);
}
#endif

#ifdef DFINDER_SAVE_DEVICE_LIST
#ifndef DFINDER_SUPPORT_MULTI_NIF
static DeviceInfo *CreateNewDevice(void *deviceList, const DeviceInfo *deviceInfo)
{
    /* Allocate DB for newly joined device */
    DeviceInfo *internalDevice = DatabaseAllocRecord(deviceList);
    if (internalDevice == NULL) {
        DFINDER_LOGE(TAG, "Failed to allocate device info");
        return NULL;
    }
    *internalDevice = *deviceInfo;
    if (strcpy_s(internalDevice->networkName, NSTACKX_MAX_INTERFACE_NAME_LEN,
        g_localDeviceInfo.networkName) != EOK) {
        DFINDER_LOGE(TAG, "copy local nif name failed");
        DatabaseFreeRecord(deviceList, (void*)internalDevice);
        return NULL;
    }
    internalDevice->updateState = DFINDER_UPDATE_STATE_NULL;
    return internalDevice;
}
#endif

#ifdef DFINDER_SUPPORT_MULTI_NIF
static DeviceInfo *CreateNewDeviceWithIdx(void *deviceList, const DeviceInfo *deviceInfo, uint8_t idx)
{
    DFINDER_LOGD(TAG, "crete new device with idx-%hhu", idx);
    uint8_t updated;
    /* Allocate DB for newly joined device */
    DeviceInfo *internalDevice = DatabaseAllocRecord(deviceList);
    if (internalDevice == NULL) {
        DFINDER_LOGE(TAG, "Failed to allocate device info");
        return NULL;
    }
    *internalDevice = *deviceInfo;

    const char *lNifName = GetLocalNifNameWithIdx(idx);
    if (lNifName == NULL) {
        DFINDER_LOGE(TAG, "get local nif name with idx-%hhu failed", idx);
        DatabaseFreeRecord(deviceList, (void *)internalDevice);
        return NULL;
    }

    DFINDER_LOGD(TAG, "create new device, nif name to copy is: %s", lNifName);
    if (strcpy_s(internalDevice->localIfInfoAll[0].localIfInfo.networkName,
        NSTACKX_MAX_INTERFACE_NAME_LEN, lNifName) != EOK) {
        DFINDER_LOGE(TAG, "report network name copy failed");
        DatabaseFreeRecord(deviceList, (void *)internalDevice);
        return NULL;
    }
    internalDevice->nextNifIdx = 1;
    internalDevice->localIfInfoAll[0].deviceRemoteChannelInfo[0].remoteChannelInfo = deviceInfo->netChannelInfo;
    ClockGetTime(CLOCK_MONOTONIC, &internalDevice->localIfInfoAll[0].deviceRemoteChannelInfo[0].lastRecvTime);
    internalDevice->localIfInfoAll[0].nextRemoteIdx = 1;
    internalDevice->localIfInfoAll[0].deviceRemoteChannelInfo[0].updateState = DFINDER_UPDATE_STATE_NULL;

    if (CheckAndUpdateBusinessAll(&internalDevice->localIfInfoAll[0].deviceRemoteChannelInfo[0].businessDataAll,
        &internalDevice->businessData, &updated) != NSTACKX_EOK) {
        DatabaseFreeRecord(deviceList, (void *)internalDevice);
        return NULL;
    }

    return internalDevice;
}
#endif

static int32_t UpdateCapabilityBitmap(DeviceInfo *internalDevice, const DeviceInfo *deviceInfo,
    uint8_t *updated)
{
    if (internalDevice == NULL || deviceInfo == NULL || updated == NULL) {
        DFINDER_LOGE(TAG, "UpdateCapabilityBitmap, input parameter error");
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
        DFINDER_LOGE(TAG, "UpdateCapabilityBitmap, memset_s fails");
        return NSTACKX_EFAILED;
    }
    if (deviceInfo->capabilityBitmapNum) {
        if (memcpy_s(internalDevice->capabilityBitmap, sizeof(internalDevice->capabilityBitmap),
            deviceInfo->capabilityBitmap, deviceInfo->capabilityBitmapNum * sizeof(uint32_t)) != EOK) {
            DFINDER_LOGE(TAG, "UpdateCapabilityBitmap, capabilityBitmap copy error");
            return NSTACKX_EFAILED;
        }
    }
    return NSTACKX_EOK;
}

static int32_t UpdateDeviceInfoInner(DeviceInfo *internalDevice, const DeviceInfo *deviceInfo,
    uint8_t *updated)
{
    if (internalDevice == NULL || deviceInfo == NULL) {
        DFINDER_LOGE(TAG, "UpdateDeviceInfo input error");
        return NSTACKX_EFAILED;
    }
    if (internalDevice->deviceType != deviceInfo->deviceType) {
        DFINDER_LOGE(TAG, "deviceType is different");
        return NSTACKX_EFAILED;
    }

    if (strcmp(internalDevice->deviceName, deviceInfo->deviceName) != 0) {
        if (strcpy_s(internalDevice->deviceName, sizeof(internalDevice->deviceName), deviceInfo->deviceName) != EOK) {
            DFINDER_LOGE(TAG, "deviceName copy error");
            return NSTACKX_EFAILED;
        }
        *updated = NSTACKX_TRUE;
    }

    if (strlen(deviceInfo->version) > 0 && strcmp(internalDevice->version, deviceInfo->version) != 0) {
        if (strcpy_s(internalDevice->version, sizeof(internalDevice->version), deviceInfo->version) != EOK) {
            DFINDER_LOGE(TAG, "hicom version copy error");
            return NSTACKX_EFAILED;
        }
        *updated = NSTACKX_TRUE;
    }

    if (UpdateCapabilityBitmap(internalDevice, deviceInfo, updated) != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "UpdateCapabilityBitmap fails");
        return NSTACKX_EFAILED;
    }

    return NSTACKX_EOK;
}

static void GetNetChannelChangeIdx(const LocalIfInfoAll *ifInfoAll, size_t size, uint8_t *changeIdx)
{
    struct timespec nowTime;
    ClockGetTime(CLOCK_MONOTONIC, &nowTime);
    uint32_t temp, max = 0;
    for (uint32_t i = 0; i < size; i++) {
        temp = GetTimeDiffUs(&nowTime, &ifInfoAll->deviceRemoteChannelInfo[i].lastRecvTime);
        if (max < temp) {
            max = temp;
            *changeIdx = i;
        }
    }
}

static void UpdateDeviceNetChannelInfo(DeviceInfo *internalDevice, const DeviceInfo *deviceInfo, uint8_t *updated)
{
#ifdef DFINDER_SUPPORT_MULTI_NIF
    uint8_t updateChannel = NSTACKX_TRUE;
    uint8_t curNifIdx = internalDevice->nextNifIdx - 1;
    uint8_t i;
    for (i = 0; i < NSTACKX_MAX_NET_CHANNEL_NUM; ++i) {
        if ((memcmp(&internalDevice->localIfInfoAll[curNifIdx].deviceRemoteChannelInfo[i].remoteChannelInfo,
            &deviceInfo->netChannelInfo, sizeof(deviceInfo->netChannelInfo)) == 0) &&
            (internalDevice->portNumber == deviceInfo->portNumber)) {
            DFINDER_LOGD(TAG, "same remote channel info found at idx %u", i);
            ClockGetTime(CLOCK_MONOTONIC,
                &internalDevice->localIfInfoAll[curNifIdx].deviceRemoteChannelInfo[i].lastRecvTime);
            internalDevice->localIfInfoAll[curNifIdx].nextRemoteIdx = i + 1;
            updateChannel = NSTACKX_FALSE;
            break;
        }
    }
    if (updateChannel) {
        i = internalDevice->localIfInfoAll[curNifIdx].nextRemoteIdx;
        if (i >= NSTACKX_MAX_NET_CHANNEL_NUM) {
            DFINDER_LOGE(TAG, "next remote idx is over range, Replace one");
            uint8_t changeIdx = 0;
            GetNetChannelChangeIdx(&internalDevice->localIfInfoAll[curNifIdx], NSTACKX_MAX_NET_CHANNEL_NUM, &changeIdx);
            internalDevice->portNumber = deviceInfo->portNumber;
            internalDevice->localIfInfoAll[curNifIdx].deviceRemoteChannelInfo[changeIdx].remoteChannelInfo =
                deviceInfo->netChannelInfo;
            ClockGetTime(CLOCK_MONOTONIC,
                &internalDevice->localIfInfoAll[curNifIdx].deviceRemoteChannelInfo[i].lastRecvTime);
            internalDevice->localIfInfoAll[curNifIdx].nextRemoteIdx = changeIdx + 1;
            *updated = NSTACKX_TRUE;
        } else {
            DFINDER_LOGD(TAG, "copy net channel info to next idx, idx-%u", i);
            internalDevice->portNumber = deviceInfo->portNumber;
            internalDevice->localIfInfoAll[curNifIdx].deviceRemoteChannelInfo[i].remoteChannelInfo =
                deviceInfo->netChannelInfo;
            ClockGetTime(CLOCK_MONOTONIC,
                &internalDevice->localIfInfoAll[curNifIdx].deviceRemoteChannelInfo[i].lastRecvTime);
            ++(internalDevice->localIfInfoAll[curNifIdx].nextRemoteIdx);
            *updated = NSTACKX_TRUE;
        }
    }
#else
    if (memcmp(&internalDevice->netChannelInfo, &deviceInfo->netChannelInfo, sizeof(deviceInfo->netChannelInfo)) ||
        (internalDevice->portNumber != deviceInfo->portNumber)) {
        (void)memcpy_s(&internalDevice->netChannelInfo, sizeof(internalDevice->netChannelInfo),
            &deviceInfo->netChannelInfo, sizeof(deviceInfo->netChannelInfo));
        internalDevice->portNumber = deviceInfo->portNumber;
        *updated = NSTACKX_TRUE;
    }
#endif
}

static uint32_t CheckAndUpdateBusinessAll(BusinessDataAll *a, const BusinessDataAll *b, uint8_t *updated)
{
    if (b->isBroadcast == NSTACKX_TRUE) {
        if (strcmp(a->businessDataBroadcast, b->businessDataBroadcast) != 0) {
            if (strcpy_s(a->businessDataBroadcast, NSTACKX_MAX_BUSINESS_DATA_LEN,
                b->businessDataBroadcast) != EOK) {
                return NSTACKX_EFAILED;
            }
            *updated = NSTACKX_TRUE;
        }
    } else {
        if (strcmp(a->businessDataUnicast, b->businessDataUnicast) != 0) {
            if (strcpy_s(a->businessDataUnicast, NSTACKX_MAX_BUSINESS_DATA_LEN,
                b->businessDataUnicast) != EOK) {
                return NSTACKX_EFAILED;
            }
            *updated = NSTACKX_TRUE;
        }
    }
    a->isBroadcast = b->isBroadcast;
    return NSTACKX_EOK;
}

static int32_t UpdateDeviceInfoBusinessData(DeviceInfo *internalDevice, const DeviceInfo *deviceInfo, uint8_t *updated)
{
#ifdef DFINDER_SUPPORT_MULTI_NIF
    uint8_t curNifIdx = internalDevice->nextNifIdx - 1;
    uint8_t curChannelIdx = internalDevice->localIfInfoAll[curNifIdx].nextRemoteIdx - 1;

    if (CheckAndUpdateBusinessAll(&internalDevice->localIfInfoAll[curNifIdx].
        deviceRemoteChannelInfo[curChannelIdx].businessDataAll, &deviceInfo->businessData, updated) != NSTACKX_EOK) {
        return NSTACKX_EFAILED;
    }

#else
    if (CheckAndUpdateBusinessAll(&internalDevice->businessData, &deviceInfo->businessData, updated) != NSTACKX_EOK) {
        return NSTACKX_EFAILED;
    }
#endif
    return NSTACKX_EOK;
}

static void UpdateDeviceListChangeStateWhenActive(UpdateState *curState, uint8_t *updated)
{
    switch (*curState) {
        case DFINDER_UPDATE_STATE_NULL:
            *curState = DFINDER_UPDATE_STATE_UNICAST;
            *updated = NSTACKX_TRUE;
            break;
        case DFINDER_UPDATE_STATE_BROADCAST:
            if (*updated == NSTACKX_TRUE) {
                *curState = DFINDER_UPDATE_STATE_UNICAST;
            } else {
                *curState = DFINDER_UPDATE_STATE_ALL;
                *updated = NSTACKX_TRUE;
            }
            break;
        case DFINDER_UPDATE_STATE_UNICAST:
            break;
        case DFINDER_UPDATE_STATE_ALL:
            if (*updated == NSTACKX_TRUE) {
                *curState = DFINDER_UPDATE_STATE_UNICAST;
            }
            break;
        default:
            break;
    }
}

static void UpdateDeviceListChangeStateWhenPassive(UpdateState *curState, uint8_t *updated)
{
    switch (*curState) {
        case DFINDER_UPDATE_STATE_NULL:
            *curState = DFINDER_UPDATE_STATE_BROADCAST;
            *updated = NSTACKX_TRUE;
            break;
        case DFINDER_UPDATE_STATE_BROADCAST:
            break;
        case DFINDER_UPDATE_STATE_UNICAST:
            if (*updated == NSTACKX_TRUE) {
                *curState = DFINDER_UPDATE_STATE_BROADCAST;
            } else {
                *curState = DFINDER_UPDATE_STATE_ALL;
                *updated = NSTACKX_TRUE;
            }
            break;
        case DFINDER_UPDATE_STATE_ALL:
            if (*updated == NSTACKX_TRUE) {
                *curState = DFINDER_UPDATE_STATE_BROADCAST;
            }
            break;
        default:
            break;
    }
}

static void CheckAndUpdateDeviceListChangeState(DeviceInfo *internalDevice,
    const DeviceInfo *deviceInfo, uint8_t *updated)
{
#ifdef DFINDER_SUPPORT_MULTI_NIF
    uint8_t curNifIdx = internalDevice->nextNifIdx - 1;
    uint8_t curChannelIdx = internalDevice->localIfInfoAll[curNifIdx].nextRemoteIdx - 1;
    UpdateState *curState = &(internalDevice->localIfInfoAll[curNifIdx].
        deviceRemoteChannelInfo[curChannelIdx].updateState);
#else
    UpdateState *curState = &(internalDevice->updateState);
#endif
    if (deviceInfo->discoveryType == NSTACKX_DISCOVERY_TYPE_PASSIVE) {
        UpdateDeviceListChangeStateWhenPassive(curState, updated);
    } else {
        UpdateDeviceListChangeStateWhenActive(curState, updated);
    }
}

static int32_t UpdateDeviceInfo(DeviceInfo *internalDevice, const DeviceInfo *deviceInfo, uint8_t *updatedPtr)
{
    uint8_t updated = NSTACKX_FALSE;
    if (UpdateDeviceInfoInner(internalDevice, deviceInfo, &updated) != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "UpdateDeviceInfoInner error");
        return NSTACKX_EFAILED;
    }

    if (strcmp(internalDevice->deviceHash, deviceInfo->deviceHash) != 0) {
        if (strcpy_s(internalDevice->deviceHash, sizeof(internalDevice->deviceHash), deviceInfo->deviceHash) != EOK) {
            DFINDER_LOGE(TAG, "deviceHash copy error");
            return NSTACKX_EFAILED;
        }
        updated = NSTACKX_TRUE;
    }

    if (internalDevice->mode != deviceInfo->mode) {
        internalDevice->mode = deviceInfo->mode;
        updated = NSTACKX_TRUE;
    }

    if (strcmp(internalDevice->serviceData, deviceInfo->serviceData) != 0) {
        if (strcpy_s(internalDevice->serviceData, NSTACKX_MAX_SERVICE_DATA_LEN, deviceInfo->serviceData) != EOK) {
            DFINDER_LOGE(TAG, "serviceData copy error");
            return NSTACKX_EFAILED;
        }
        updated = NSTACKX_TRUE;
    }
    if (internalDevice->businessType != deviceInfo->businessType) {
        internalDevice->businessType = deviceInfo->businessType;
        updated = NSTACKX_TRUE;
    }

    if (UpdateDeviceInfoBusinessData(internalDevice, deviceInfo, &updated) != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "businessData copy error");
        return NSTACKX_EFAILED;
    }
    if (strcpy_s(internalDevice->networkName, NSTACKX_MAX_INTERFACE_NAME_LEN,
        g_localDeviceInfo.networkName) != EOK) {
        DFINDER_LOGE(TAG, "copy local report nif name failed");
        return NSTACKX_EFAILED;
    }
    internalDevice->discoveryType = deviceInfo->discoveryType;
    *updatedPtr |= updated;
    return NSTACKX_EOK;
}

#ifdef DFINDER_SUPPORT_MULTI_NIF
static int32_t UpdateDeviceInfoWithIdx(DeviceInfo *internalDevice, const DeviceInfo *deviceInfo,
    uint8_t *updatedPtr, uint8_t idx)
{
    uint8_t updated = NSTACKX_FALSE;
    uint8_t needUpdateNif = NSTACKX_TRUE;
    uint8_t i;
    const char *lNifName = GetLocalNifNameWithIdx(idx);
    if (lNifName == NULL) {
        DFINDER_LOGE(TAG, "get local nif name with idx-%hhu failed", idx);
        return NSTACKX_EFAILED;
    }

    for (i = 0; i < NSTACKX_MAX_LISTENED_NIF_NUM; ++i) {
        if (strcmp(internalDevice->localIfInfoAll[i].localIfInfo.networkName, lNifName) == 0) {
            DFINDER_LOGD(TAG, "same nif name found, at idx-%u", i);
            needUpdateNif = NSTACKX_FALSE;
            internalDevice->nextNifIdx = i + 1;
            break;
        }
    }

    if (needUpdateNif) {
        i = internalDevice->nextNifIdx;
        if (i >= NSTACKX_MAX_LISTENED_NIF_NUM) {
            DFINDER_LOGE(TAG, "next nif idx is over range, Replace one");
            uint8_t changeIdx = internalDevice->nextNifIdx % NSTACKX_MAX_LISTENED_NIF_NUM;
            if (strcpy_s(internalDevice->localIfInfoAll[changeIdx].localIfInfo.networkName,
                NSTACKX_MAX_INTERFACE_NAME_LEN, lNifName) != EOK) {
                DFINDER_LOGE(TAG, "copy local report nif name failed");
                return NSTACKX_EFAILED;
            }
            /* rely on NSTACKX_MAX_LISTENED_NIF_NUM == 2 */
            internalDevice->nextNifIdx = changeIdx + 1;
            updated = NSTACKX_TRUE;
        } else {
            DFINDER_LOGD(TAG, "not first time found, nif name to copy is: %s, idx is: %u", lNifName, i);
            if (strcpy_s(internalDevice->localIfInfoAll[i].localIfInfo.networkName,
                NSTACKX_MAX_INTERFACE_NAME_LEN, lNifName) != EOK) {
                DFINDER_LOGE(TAG, "copy local report nif name failed");
                return NSTACKX_EFAILED;
            }
            ++(internalDevice->nextNifIdx);
            updated = NSTACKX_TRUE;
        }
    }
    UpdateDeviceNetChannelInfo(internalDevice, deviceInfo, &updated);
    if (UpdateDeviceInfo(internalDevice, deviceInfo, &updated) != NSTACKX_EOK) {
        return NSTACKX_EFAILED;
    }

    *updatedPtr = updated;
    return NSTACKX_EOK;
}
#endif

static void DeviceListChangeHandle(void)
{
    size_t deviceListLen = sizeof(NSTACKX_DeviceInfo) * g_maxDeviceNum;
    NSTACKX_DeviceInfo *deviceList = (NSTACKX_DeviceInfo *)malloc(deviceListLen);
    if (deviceList == NULL) {
        DFINDER_LOGE(TAG, "malloc for device list failed");
        return;
    }
    uint32_t count = g_maxDeviceNum;
    (void)memset_s(deviceList, deviceListLen, 0, deviceListLen);
    GetDeviceList(g_deviceList, deviceList, &count, true);
    if (count == 0) {
        DFINDER_LOGW(TAG, "count is zero, do not notify");
        free(deviceList);
        return;
    }
    NotifyDeviceListChanged(deviceList, count);
    if (CoapDiscoverRequestOngoing()) {
        NotifyDeviceFound(deviceList, count);
    }
    free(deviceList);
}

static int32_t UpdateDeviceDbInDeviceList(const DeviceInfo *deviceInfo, uint8_t idx, uint8_t forceUpdate)
{
    DeviceInfo *internalDevice = NULL;
    uint8_t updated = NSTACKX_FALSE;
    internalDevice = GetDeviceInfoById(deviceInfo->deviceId, g_deviceList);
    if (internalDevice == NULL) {
#ifdef DFINDER_SUPPORT_MULTI_NIF
        internalDevice = CreateNewDeviceWithIdx(g_deviceList, deviceInfo, idx);
#else
        (void)idx;
        internalDevice = CreateNewDevice(g_deviceList, deviceInfo);
#endif
        if (internalDevice == NULL) {
            IncStatistics(STATS_OVER_DEVICE_LIMIT);
            return NSTACKX_ENOMEM;
        }
        updated = NSTACKX_TRUE;
    } else {
#ifdef DFINDER_SUPPORT_MULTI_NIF
        if (UpdateDeviceInfoWithIdx(internalDevice, deviceInfo, &updated, idx) != NSTACKX_EOK) {
#else
        (void)idx;
        (void)UpdateDeviceNetChannelInfo(internalDevice, deviceInfo, &updated);
        if (UpdateDeviceInfo(internalDevice, deviceInfo, &updated) != NSTACKX_EOK) {
#endif
            return NSTACKX_EFAILED;
        }
    }
    CheckAndUpdateDeviceListChangeState(internalDevice, deviceInfo, &updated);
    internalDevice->update = updated;
    if (updated || forceUpdate) {
        DFINDER_LOGD(TAG, "updated is: %hhu, forceUpdate is: %hhu", updated, forceUpdate);
#ifdef DFINDER_SUPPORT_MULTI_NIF
        DeviceListChangeHandleMultiNif();
#else
        DeviceListChangeHandle();
#endif
    }
    return NSTACKX_EOK;
}

static int32_t UpdateDeviceDbEx(const DeviceInfo *deviceInfo, uint8_t forceUpdate)
{
    if (deviceInfo == NULL) {
        return NSTACKX_EINVAL;
    }
    if (UpdateDeviceDbInDeviceList(deviceInfo, 0, forceUpdate) != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "update when receive broadcast fail");
        return NSTACKX_EFAILED;
    }
    return NSTACKX_EOK;
}

int32_t UpdateDeviceDb(const DeviceInfo *deviceInfo, uint8_t forceUpdate)
{
    int32_t ret = UpdateDeviceDbEx(deviceInfo, forceUpdate);
    if (ret != NSTACKX_EOK) {
        IncStatistics(STATS_UPDATE_DEVICE_DB_FAILED);
    }
    return ret;
}
#else
int32_t DeviceInfoNotify(const DeviceInfo *deviceInfo, uint8_t forceUpdate)
{
    NSTACKX_DeviceInfo notifyDevice;

    (void)forceUpdate;
    if (!MatchDeviceFilter(deviceInfo)) {
        return NSTACKX_EOK;
    }
    (void)memset_s(&notifyDevice, sizeof(notifyDevice), 0, sizeof(notifyDevice));
    if (GetNotifyDeviceInfo(&notifyDevice, deviceInfo) != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "GetNotifyDeviceInfo failed");
        return NSTACKX_EFAILED;
    }
    NotifyDeviceListChanged(&notifyDevice, NSTACKX_MAX_DEVICE_NUM);
    if (CoapDiscoverRequestOngoing()) {
        NotifyDeviceFound(&notifyDevice, NSTACKX_MAX_DEVICE_NUM);
    }
    return NSTACKX_EOK;
}
#endif /* END OF DFINDER_SAVE_DEVICE_LIST */

#ifdef DFINDER_SUPPORT_MULTI_NIF
int32_t UpdateDeviceDbWithIdx(const DeviceInfo *deviceInfo, uint8_t forceUpdate, uint8_t idx)
{
    if (deviceInfo == NULL) {
        return NSTACKX_EINVAL;
    }
    if (UpdateDeviceDbInDeviceList(deviceInfo, idx, forceUpdate) != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "update when receive broadcast fail with multi nif");
        return NSTACKX_EFAILED;
    }
    return NSTACKX_EOK;
}
#endif /* END OF DFINDER_SUPPORT_MULTI_NIF */

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
        DFINDER_LOGE(TAG, "pares deviceList fails");
        return NSTACKX_EFAILED;
    }

    if (deviceInfo->mode != DEFAULT_MODE) {
        if (!cJSON_AddNumberToObject(item, "mode", deviceInfo->mode)) {
            DFINDER_LOGE(TAG, "add mode to object failed");
        }
    }
    if (!cJSON_AddStringToObject(item, "hwAccountHashVal", deviceInfo->deviceHash)) {
        DFINDER_LOGE(TAG, "add hwAccountHashVal to object failed");
    }
    const char *ver = (strlen(deviceInfo->version) == 0) ? NSTACKX_DEFAULT_VER : deviceInfo->version;
    if (!cJSON_AddStringToObject(item, "version", ver)) {
        DFINDER_LOGE(TAG, "add hwAccountHashVal to object failed");
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
    if (deviceNum != PUBLISH_DEVICE_NUM || deviceInfo == NULL || deviceList == NULL) {
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
        DFINDER_LOGE(TAG, "GetReservedInfo Failed");
        return;
    }
    deviceList[0].deviceType = deviceInfo->deviceType;
}

static bool MatchDeviceFilter(const DeviceInfo *deviceInfo)
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

#ifdef DFINDER_SUPPORT_MULTI_NIF
static int32_t AddBusinessDataStringToJsonObj(const char* businessData, cJSON *item)
{
    if (businessData == NULL || strlen(businessData) > NSTACKX_MAX_BUSINESS_DATA_LEN) {
        DFINDER_LOGE(TAG, "AddBusinessDataStringToJsonObj error");
        return NSTACKX_EFAILED;
    }
    if (!cJSON_AddStringToObject(item, "bData", businessData)) {
        DFINDER_LOGE(TAG, "cJSON_AddStringToObject: businessData error");
        return NSTACKX_EFAILED;
    }
    return NSTACKX_EOK;
}

int32_t BuildBusinessDataJsonPayload(const DeviceInfo *deviceInfo, uint8_t curNifIdx,
    uint8_t curChannelIdx, cJSON *item)
{
    const DeviceRemoteChannelInfo *temp =
        &deviceInfo->localIfInfoAll[curNifIdx].deviceRemoteChannelInfo[curChannelIdx];
    if (temp->businessDataAll.isBroadcast == NSTACKX_TRUE) {
        return AddBusinessDataStringToJsonObj(temp->businessDataAll.businessDataBroadcast, item);
    } else {
        return AddBusinessDataStringToJsonObj(temp->businessDataAll.businessDataUnicast, item);
    }
}
#endif

static int8_t SetServiceDataFromDeviceInfo(cJSON *item, const DeviceInfo *deviceInfo)
{
    if (item == NULL || deviceInfo == NULL) {
        DFINDER_LOGE(TAG, "item or deviceInfo is null");
        return NSTACKX_EFAILED;
    }
    if (strlen(deviceInfo->serviceData) != 0 && strlen(deviceInfo->serviceData) < NSTACKX_MAX_SERVICE_DATA_LEN) {
        if (!cJSON_AddStringToObject(item, "serviceData", deviceInfo->serviceData)) {
            DFINDER_LOGE(TAG, "cJSON_AddStringToObject: serviceData error");
            return NSTACKX_EFAILED;
        }
    }
#ifndef DFINDER_USE_MINI_NSTACKX
    if (strlen(deviceInfo->extendServiceData) != 0 &&
        strlen(deviceInfo->extendServiceData) < NSTACKX_MAX_EXTEND_SERVICE_DATA_LEN) {
        if (!cJSON_AddStringToObject(item, "extendServiceData", deviceInfo->extendServiceData)) {
            DFINDER_LOGE(TAG, "cJSON_AddStringToObject: extendServiceData error");
            return NSTACKX_EFAILED;
        }
    }
#endif

#ifdef DFINDER_SUPPORT_MULTI_NIF
    uint8_t curNifIdx = deviceInfo->nextNifIdx - 1;
    uint8_t curChannelIdx = deviceInfo->localIfInfoAll[curNifIdx].nextRemoteIdx - 1;
    if (BuildBusinessDataJsonPayload(deviceInfo, curNifIdx, curChannelIdx, item) != NSTACKX_EOK) {
        return NSTACKX_EFAILED;
    }
#else
    if (deviceInfo->businessData.isBroadcast == NSTACKX_TRUE) {
        if (strlen(deviceInfo->businessData.businessDataBroadcast) != 0 &&
            strlen(deviceInfo->businessData.businessDataBroadcast) < NSTACKX_MAX_BUSINESS_DATA_LEN) {
            if (!cJSON_AddStringToObject(item, "bData", deviceInfo->businessData.businessDataBroadcast)) {
                DFINDER_LOGE(TAG, "cJSON_AddStringToObject: businessData error");
                return NSTACKX_EFAILED;
            }
        }
    } else {
        if (strlen(deviceInfo->businessData.businessDataUnicast) != 0 &&
            strlen(deviceInfo->businessData.businessDataUnicast) < NSTACKX_MAX_BUSINESS_DATA_LEN) {
            if (!cJSON_AddStringToObject(item, "bData", deviceInfo->businessData.businessDataUnicast)) {
                DFINDER_LOGE(TAG, "cJSON_AddStringToObject: businessData error");
                return NSTACKX_EFAILED;
            }
        }
    }
#endif
    return NSTACKX_EOK;
}

static int32_t SetReservedInfoFromDeviceInfoInner(NSTACKX_DeviceInfo *deviceList, uint32_t idx,
    const DeviceInfo *deviceInfo, const NetChannelInfo *netChannelInfo)
{
    char wifiIpAddr[NSTACKX_MAX_IP_STRING_LEN];
    char *ver = NULL;
    char *newData = NULL;
    int32_t ret  = NSTACKX_EFAILED;
    if (deviceList == NULL) {
        DFINDER_LOGE(TAG, "deviceList or deviceInfo is null");
        return NSTACKX_EINVAL;
    }

    (void)memset_s(wifiIpAddr, sizeof(wifiIpAddr), 0, sizeof(wifiIpAddr));
    (void)inet_ntop(AF_INET, &netChannelInfo->wifiApInfo.ip, wifiIpAddr, sizeof(wifiIpAddr));
    if (sprintf_s(deviceList[idx].reservedInfo, sizeof(deviceList[idx].reservedInfo),
        NSTACKX_RESERVED_INFO_JSON_FORMAT, wifiIpAddr) == -1) {
        DFINDER_LOGE(TAG, "sprintf_s reservedInfo with wifiIpAddr fails");
        return NSTACKX_EAGAIN;
    }
    cJSON *item = cJSON_Parse(deviceList[idx].reservedInfo);
    if (item == NULL) {
        DFINDER_LOGE(TAG, "pares deviceList fails");
        return NSTACKX_EINVAL;
    }

    if (deviceInfo->mode != 0 && !cJSON_AddNumberToObject(item, "mode", deviceInfo->mode)) {
        goto L_END;
    }
    if (!cJSON_AddStringToObject(item, "hwAccountHashVal", deviceInfo->deviceHash)) {
        goto L_END;
    }
    ver = (strlen(deviceInfo->version) == 0) ? NSTACKX_DEFAULT_VER : (char *)deviceInfo->version;
    if (!cJSON_AddStringToObject(item, "version", ver)) {
        goto L_END;
    }
    if (SetServiceDataFromDeviceInfo(item, deviceInfo) != NSTACKX_EOK) {
        goto L_END;
    }
    newData = cJSON_Print(item);
    if (newData == NULL) {
        goto L_END;
    }
    (void)memset_s(deviceList[idx].reservedInfo, sizeof(deviceList[idx].reservedInfo),
                   0, sizeof(deviceList[idx].reservedInfo));
    if (strcpy_s(deviceList[idx].reservedInfo, sizeof(deviceList[idx].reservedInfo), newData) != EOK) {
        free(newData);
        DFINDER_LOGE(TAG, "strcpy_s fails");
        goto L_END;
    }
    free(newData);
    ret = NSTACKX_EOK;
L_END:
    cJSON_Delete(item);
    return ret;
}

#ifdef DFINDER_SUPPORT_MULTI_NIF
static void CopyDeviceListType(const DeviceInfo *deviceInfo, NSTACKX_DeviceInfo *device)
{
    device->discoveryType = deviceInfo->discoveryType;
    device->deviceType = deviceInfo->deviceType;
    device->businessType = deviceInfo->businessType;
    device->mode = deviceInfo->mode;
    device->update = deviceInfo->update;
}

static int32_t SetReservedInfoFromDeviceInfoWithIdx(NSTACKX_DeviceInfo *deviceList, uint32_t idx,
    const DeviceInfo *deviceInfo)
{
    uint8_t curNifIdx = deviceInfo->nextNifIdx - 1;
    uint8_t curChannelIdx = deviceInfo->localIfInfoAll[curNifIdx].nextRemoteIdx - 1;
    return SetReservedInfoFromDeviceInfoInner(deviceList, idx, deviceInfo,
        &deviceInfo->localIfInfoAll[curNifIdx].deviceRemoteChannelInfo[curChannelIdx].remoteChannelInfo);
}
#endif

static int32_t SetReservedInfoFromDeviceInfo(NSTACKX_DeviceInfo *deviceList, uint32_t idx,
    const DeviceInfo *deviceInfo)
{
    return SetReservedInfoFromDeviceInfoInner(deviceList, idx, deviceInfo, &deviceInfo->netChannelInfo);
}

#ifdef DFINDER_SUPPORT_MULTI_NIF
static void GetDeviceListWithReportIdx(void *dbList, NSTACKX_DeviceInfo *deviceList, uint32_t *deviceCountPtr,
    bool doFilter)
{
    DeviceInfo *deviceInfo = NULL;
    int64_t idx = -1;
    uint32_t count = 0;

    for (uint32_t i = 0; i < g_maxDeviceNum; i++) {
        if (count >= *deviceCountPtr) {
            break;
        }

        deviceInfo = DatabaseGetNextRecord(dbList, &idx);
        if (deviceInfo == NULL) {
            DFINDER_LOGE(TAG, "deviceInfo is null");
            break;
        }

        if (doFilter && !MatchDeviceFilter(deviceInfo)) {
            DFINDER_LOGW(TAG, "filter device");
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
                DFINDER_LOGE(TAG, "memcpy failed");
                break;
            }
        }

        int8_t result = SetReservedInfoFromDeviceInfoWithIdx(deviceList, count, deviceInfo);
        if (result == NSTACKX_EAGAIN) {
            DFINDER_LOGE(TAG, "set reserved info from device info failed, sprintf_s or strcpy_s fails");
            break;
        } else if (result == NSTACKX_EINVAL || result == NSTACKX_EFAILED) {
            DFINDER_LOGE(TAG, "set reserved info from device info failed");
            return;
        }
        uint8_t curNifIdx = deviceInfo->nextNifIdx - 1;
        if (strcpy_s(deviceList[count].networkName, sizeof(deviceList[count].networkName),
                deviceInfo->localIfInfoAll[curNifIdx].localIfInfo.networkName) != EOK) {
            DFINDER_LOGE(TAG, "copy deviceList[count].networkName failed");
            break;
        }
        CopyDeviceListType(deviceInfo, &deviceList[count]);
        deviceInfo->update = NSTACKX_FALSE;
        ++count;
    }

    *deviceCountPtr = count;
}
#endif /* END OF DFINDER_SUPPORT_MULTI_NIF */

#ifdef DFINDER_SAVE_DEVICE_LIST
static void GetDeviceList(void *dbList, NSTACKX_DeviceInfo *deviceList, uint32_t *deviceCountPtr, bool doFilter)
{
    DeviceInfo *deviceInfo = NULL;
    int64_t idx = -1;
    uint32_t count = 0;
    uint32_t i;

    for (i = 0; i < g_maxDeviceNum; i++) {
        if (count >= *deviceCountPtr) {
            break;
        }

        deviceInfo = DatabaseGetNextRecord(dbList, &idx);
        if (deviceInfo == NULL) {
            break;
        }

        if (doFilter && !MatchDeviceFilter(deviceInfo)) {
            continue;
        }

        if (strcpy_s(deviceList[count].version, sizeof(deviceList[count].version), deviceInfo->version) != EOK ||
            strcpy_s(deviceList[count].deviceName, sizeof(deviceList[count].deviceName),
                     deviceInfo->deviceName) != EOK ||
            strcpy_s(deviceList[count].deviceId, sizeof(deviceList[count].deviceId), deviceInfo->deviceId) != EOK) {
            DFINDER_LOGE(TAG, "string copy failure when getting device list");
            break;
        }
        deviceList[count].capabilityBitmapNum = deviceInfo->capabilityBitmapNum;
        if (deviceInfo->capabilityBitmapNum) {
            if (memcpy_s(deviceList[count].capabilityBitmap, sizeof(deviceList[count].capabilityBitmap),
                deviceInfo->capabilityBitmap, deviceInfo->capabilityBitmapNum * sizeof(uint32_t)) != EOK) {
                break;
            }
        }

        deviceList[count].discoveryType = deviceInfo->discoveryType;
        int8_t result = SetReservedInfoFromDeviceInfo(deviceList, count, deviceInfo);
        if (result == NSTACKX_EAGAIN) {
            DFINDER_LOGE(TAG, "SetReservedInfoFromDeviceInfo fails, sprintf_s or strcpy_s fails");
            break;
        } else if (result == NSTACKX_EINVAL || result == NSTACKX_EFAILED) {
            DFINDER_LOGE(TAG, "SetReservedInfoFromDeviceInfo fails");
            break;
        }
        if (strcpy_s(deviceList[count].networkName, sizeof(deviceList[count].networkName),
            deviceInfo->networkName) != EOK) {
            DFINDER_LOGE(TAG, "copy networkName failed");
            break;
        }
        deviceList[count].deviceType = deviceInfo->deviceType;
        deviceList[count].mode = deviceInfo->mode;
        deviceList[count].update = deviceInfo->update;
        deviceList[count].businessType = deviceInfo->businessType;
        deviceInfo->update = NSTACKX_FALSE;
        ++count;
    }

    *deviceCountPtr = count;
}

void GetDeviceListWrapper(NSTACKX_DeviceInfo *deviceList, uint32_t *deviceCountPtr, bool doFilter)
{
    GetDeviceList(g_deviceList, deviceList, deviceCountPtr, doFilter);
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
        DFINDER_LOGE(TAG, "NULL input, can't compare");
        return NSTACKX_FALSE;
    }

    if (strcmp(rec->deviceId, my->deviceId) == 0) {
        return NSTACKX_TRUE;
    }
    return NSTACKX_FALSE;
}
#endif /* END OF DFINDER_SAVE_DEVICE_LIST */

#ifndef DFINDER_SAVE_DEVICE_LIST
static int32_t GetNotifyDeviceInfo(NSTACKX_DeviceInfo *notifyDevice, const DeviceInfo *deviceInfo)
{
    if ((strcpy_s(notifyDevice->deviceId, sizeof(notifyDevice->deviceId), deviceInfo->deviceId) != EOK) ||
        (strcpy_s(notifyDevice->deviceName, sizeof(notifyDevice->deviceName), deviceInfo->deviceName) != EOK) ||
        (strcpy_s(notifyDevice->version, sizeof(notifyDevice->version), deviceInfo->version) != EOK)) {
        DFINDER_LOGE(TAG, "strcpy_s fails");
        return NSTACKX_EFAILED;
    }
    notifyDevice->capabilityBitmapNum = deviceInfo->capabilityBitmapNum;
    if (deviceInfo->capabilityBitmapNum) {
        if (memcpy_s(notifyDevice->capabilityBitmap, sizeof(notifyDevice->capabilityBitmap),
            deviceInfo->capabilityBitmap, deviceInfo->capabilityBitmapNum * sizeof(uint32_t)) != EOK) {
            DFINDER_LOGE(TAG, "memcpy_s fails");
            return NSTACKX_EFAILED;
        }
    }

    int8_t result = SetReservedInfoFromDeviceInfo(notifyDevice, 0, deviceInfo);
    if (result != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "SetReservedInfoFromDeviceInfo fails: %hhd", result);
        return result;
    }
    notifyDevice->discoveryType = deviceInfo->discoveryType;
    notifyDevice->deviceType = deviceInfo->deviceType;
    notifyDevice->mode = deviceInfo->mode;
    notifyDevice->businessType = deviceInfo->businessType;

    return NSTACKX_EOK;
}
#endif /* END OF DFINDER_SAVE_DEVICE_LIST */

#ifdef DFINDER_SUPPORT_MULTI_NIF
static char *GetLocalNifName(void)
{
    struct in_addr ipAddr;
    for (uint32_t i = 0; i < NSTACKX_MAX_LISTENED_NIF_NUM; ++i) {
        if (inet_pton(AF_INET, g_localDeviceInfo.localIfInfoAll[i].localIfInfo.networkIpAddr, &ipAddr) == 1 &&
            (ipAddr.s_addr != 0)) {
            return g_localDeviceInfo.localIfInfoAll[i].localIfInfo.networkName;
        }
    }
    return NULL;
}

char *GetLocalNifNameWithIdx(uint32_t idx)
{
    struct in_addr ipAddr;
    if (inet_pton(AF_INET, g_localDeviceInfo.localIfInfoAll[idx].localIfInfo.networkIpAddr, &ipAddr) == 1 &&
        (ipAddr.s_addr != 0)) {
        return g_localDeviceInfo.localIfInfoAll[idx].localIfInfo.networkName;
    }
    return NULL;
}

static char *GetLocalNifIpWithIdx(struct in_addr *ip, uint32_t idx)
{
    if (inet_pton(AF_INET, g_localDeviceInfo.localIfInfoAll[idx].localIfInfo.networkIpAddr, ip) == 1 &&
        (ip->s_addr != 0)) {
        return g_localDeviceInfo.localIfInfoAll[idx].localIfInfo.networkIpAddr;
    }
    return NULL;
}
#else
static const NetworkInterfaceInfo *GetLocalInterface(void)
{
    /* Ethernet have higher priority */
    if (g_interfaceList[NSTACKX_ETH_INDEX].ip.s_addr) {
        return &g_interfaceList[NSTACKX_ETH_INDEX];
    }

    if (g_interfaceList[NSTACKX_WLAN_INDEX].ip.s_addr) {
        return &g_interfaceList[NSTACKX_WLAN_INDEX];
    }

#ifndef DFINDER_USE_MINI_NSTACKX
    if (g_interfaceList[NSTACKX_P2P_INDEX].ip.s_addr) {
        return &g_interfaceList[NSTACKX_P2P_INDEX];
    }

    if (g_interfaceList[NSTACKX_USB_INDEX].ip.s_addr) {
        return &g_interfaceList[NSTACKX_USB_INDEX];
    }
#endif /* END OF DFINDER_USE_MINI_NSTACKX */

    return NULL;
}

void GetLocalIp(struct in_addr *ip)
{
    const NetworkInterfaceInfo *ifInfo = GetLocalInterface();
    if (ifInfo != NULL) {
        (void)memcpy_s(ip, sizeof(struct in_addr),
                       &ifInfo->ip, sizeof(struct in_addr));
    } else {
        (void)memset_s(ip, sizeof(struct in_addr), 0, sizeof(struct in_addr));
    }
}
#endif /* END OF DFINDER_SUPPORT_MULTI_NIF */

/* Return NSTACKX_TRUE if ifName prefix is the same, else return false */
static uint8_t NetworkInterfaceNamePrefixCmp(const char *ifName, const char *prefix)
{
    if (strlen(ifName) < strlen(prefix)) {
        return NSTACKX_FALSE;
    }

    if (memcmp(ifName, prefix, strlen(prefix)) == 0) {
        return NSTACKX_TRUE;
    } else {
        return NSTACKX_FALSE;
    }
}

#ifdef DFINDER_SUPPORT_MULTI_NIF
int32_t UpdateLocalNetworkInterface(void)
{
    uint32_t i;
    struct in_addr ipAddr;
    uint8_t upState = NSTACKX_FALSE;

    for (i = 0; i < g_localDeviceInfo.ifNums; ++i) {
        if (g_localDeviceInfo.ifState[i] == IF_STATE_INIT) {
            continue;
        }
        if (g_localDeviceInfo.ifState[i] == IF_STATE_REMAIN_UP) {
            upState = NSTACKX_TRUE;
        }
        g_localDeviceInfo.ifState[i] = IF_STATE_INIT;
        (void)inet_pton(AF_INET, g_localDeviceInfo.localIfInfoAll[i].localIfInfo.networkIpAddr, &ipAddr);
        if (ipAddr.s_addr == 0) {
            DFINDER_LOGI(TAG, "trying to bring down interface %s",
                g_localDeviceInfo.localIfInfoAll[i].localIfInfo.networkName);
            CoapServerDestroyWithIdx(i);
        } else {
            DFINDER_LOGI(TAG, "trying to bring up interface %s",
                g_localDeviceInfo.localIfInfoAll[i].localIfInfo.networkName);
            TimerSetTimeout(g_offlineDeferredTimer, 0, NSTACKX_FALSE);
            // init the i-th coap server correspond to the i-th nif
            CoapServerInitWithIdx(&ipAddr, i, g_localDeviceInfo.localIfInfoAll[i].localIfInfo.networkName);
            upState = NSTACKX_TRUE;
        }
    }
    if (!upState) {
        DFINDER_LOGD(TAG, "all interfaces are down");
        TimerSetTimeout(g_offlineDeferredTimer, NSTACKX_OFFLINE_DEFERRED_DURATION, NSTACKX_FALSE);
    }
    return NSTACKX_EOK;
}
#else
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
        DFINDER_LOGI(TAG, "ip not changed");
        return NSTACKX_EOK;
    }

    /* Cleanup device db when Wifi AP disconnected. */
    if (interfaceInfo->ip.s_addr == 0) {
        /*
         * We don't cleanup DB and transport immediately.
         * Instead, defer the event for a while in case WiFi connected again.
         */
        DFINDER_LOGE(TAG, "g_networkType is %s and interfaceInfo is %s", g_networkType,  interfaceInfo->name);
        if (strcmp(g_networkType, interfaceInfo->name) != 0 && strcmp(g_networkType, "") != 0) {
            DFINDER_LOGE(TAG, "into ignore");
            return NSTACKX_EOK;
        }
        TimerSetTimeout(g_offlineDeferredTimer, NSTACKX_OFFLINE_DEFERRED_DURATION, NSTACKX_FALSE);
    } else {
        TimerSetTimeout(g_offlineDeferredTimer, 0, NSTACKX_FALSE);
        int32_t ret = memcpy_s(g_networkType, sizeof(g_networkType), interfaceInfo->name, sizeof(interfaceInfo->name));
        if (ret != EOK) {
            DFINDER_LOGE(TAG, "memcpy_s error");
            return NSTACKX_EFAILED;
        }
        struct in_addr ip;
        (void)memcpy_s(&ip, sizeof(struct in_addr), &interfaceInfo->ip, sizeof(struct in_addr));
        CoapServerInit(&ip);
    }

    return NSTACKX_EOK;
}
#endif  /* END OF DFINDER_SUPPORT_MULTI_NIF */

#if !defined(DFINDER_SUPPORT_MULTI_NIF) && !defined(DFINDER_USE_MINI_NSTACKX)
void SetP2pIp(const struct in_addr *ip)
{
    if (ip == NULL) {
        return;
    }
    if (memcpy_s(&g_p2pIp, sizeof(struct in_addr), ip, sizeof(struct in_addr)) != EOK) {
        DFINDER_LOGE(TAG, "memcpy_s failed");
    }
}

static void TryToInitP2pCoapServer(struct in_addr ip)
{
    /* ignore p2p service when new ip is 0. */
    if (ip.s_addr == 0) {
        DFINDER_LOGE(TAG, "p2p newIp is 0");
        return;
    }
    StopP2pServerInitRetryTimer();
    if (CoapP2pServerInit(&ip) != NSTACKX_EOK) { /* If init fail, start retry */
        DFINDER_LOGE(TAG, "start p2p init delayed");
        if (g_p2pServerInitDeferredTimer == NULL) {
            return;
        }
        /* if CoapP2pServerInit failed, update the g_p2pIp */
        SetP2pIp(&ip);
        TimerSetTimeout(g_p2pServerInitDeferredTimer, g_serverInitRetryBackoffList[0], NSTACKX_FALSE);
        g_p2pRetryCount++;
        return;
    }
    DFINDER_LOGD(TAG, "start p2p init success");
}

int32_t UpdateLocalNetworkInterfaceP2pMode(const NetworkInterfaceInfo *interfaceInfo, uint16_t nlmsgType)
{
    struct in_addr newIp;

    if (interfaceInfo == NULL) {
        return NSTACKX_EINVAL;
    }

#ifdef SUPPORT_SMARTGENIUS
    if (nlmsgType == RTM_DELADDR) {
        DFINDER_LOGD(TAG, "p2p delete address, call CoapP2pServerDestroy()");
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
            DFINDER_LOGE(TAG, "newIp memcpy_s failed");
            return NSTACKX_EFAILED;
        }
    } else {
        DFINDER_LOGI(TAG, "NetworkInterfaceNamePrefixCmp p2p fail");
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
        DFINDER_LOGE(TAG, "memcpy_s failed");
    }
}

static void TryToInitUsbCoapServer(struct in_addr ip)
{
    /* ignore usb service when new ip is 0. */
    if (ip.s_addr == 0) {
        DFINDER_LOGE(TAG, "usb newIp is 0");
        return;
    }

    StopUsbServerInitRetryTimer();
    if (CoapUsbServerInit(&ip) != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "start usb init delayed");
        if (g_usbServerInitDeferredTimer == NULL) {
            return;
        }

        /* if CoapUsbServerInit failed, update the g_p2pIp */
        SetUsbIp(&ip);

        TimerSetTimeout(g_usbServerInitDeferredTimer, g_serverInitRetryBackoffList[0], NSTACKX_FALSE);
        g_usbRetryCount++;
        return;
    }
    DFINDER_LOGI(TAG, "start usb init success");
}

int32_t UpdateLocalNetworkInterfaceUsbMode(const NetworkInterfaceInfo *interfaceInfo, uint16_t nlmsgType)
{
    struct in_addr newIp;

    if (interfaceInfo == NULL) {
        return NSTACKX_EINVAL;
    }

#ifdef SUPPORT_SMARTGENIUS
    if (nlmsgType == RTM_DELADDR) {
        DFINDER_LOGD(TAG, "usb delete address, call CoapUsbServerDestroy()");
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
            DFINDER_LOGE(TAG, "newIp memcpy_s failed");
            return NSTACKX_EFAILED;
        }
    } else {
        return NSTACKX_EINVAL;
    }
    TryToInitUsbCoapServer(newIp);
    return NSTACKX_EOK;
}
#endif /* END OF (!DFINDER_SUPPORT_MULTI_NIF) && (!DFINDER_USE_MINI_NSTACKX) */

void SetModeInfo(uint8_t mode)
{
    g_localDeviceInfo.mode = mode;
}

uint8_t GetModeInfo(void)
{
    return g_localDeviceInfo.mode;
}

int32_t GetNetworkName(char *name, int32_t len)
{
#ifdef NSTACKX_WITH_LITEOS_M
    if (name == NULL) {
        LOGE(TAG, "input invalid para!");
        return NSTACKX_EFAILED;
    }
    if (strcpy_s(name, len, g_localDeviceInfo.networkName) != EOK) {
        LOGE(TAG, "get network name copy error!");
        return NSTACKX_EFAILED;
    }
#else
    (void)name;
    (void)len;
#endif
    return NSTACKX_EOK;
}

void SetDeviceHash(uint64_t deviceHash)
{
    (void)memset_s(g_localDeviceInfo.deviceHash, sizeof(g_localDeviceInfo.deviceHash),
        0, sizeof(g_localDeviceInfo.deviceHash));
    if (sprintf_s(g_localDeviceInfo.deviceHash, DEVICE_HASH_LEN,
        "%ju", deviceHash) == -1) {
        DFINDER_LOGE(TAG, "set device hash error");
    }
}

#ifdef DFINDER_SUPPORT_MULTI_NIF
static void UpdateLocalMultiNifState(const NSTACKX_LocalDeviceInfo *devInfo)
{
    struct in_addr ipAddr;
    uint32_t i;
    for (i = 0; i < NSTACKX_MAX_LISTENED_NIF_NUM; ++i) {
        CoapServerDestroyWithIdx(i);
        g_localDeviceInfo.ifState[i] = IF_STATE_INIT;
    }
    for (i = 0; i < devInfo->ifNums && i < NSTACKX_MAX_LISTENED_NIF_NUM; ++i) {
        (void)inet_pton(AF_INET, devInfo->localIfInfo[i].networkIpAddr, &ipAddr);
        if (strcpy_s(g_localDeviceInfo.localIfInfoAll[i].localIfInfo.networkName,
            sizeof(g_localDeviceInfo.localIfInfoAll[i].localIfInfo.networkName),
            devInfo->localIfInfo[i].networkName) != EOK) {
            DFINDER_LOGE(TAG, "Failed to copy network name for index %u", i);
            return;
        }
        if (strcpy_s(g_localDeviceInfo.localIfInfoAll[i].localIfInfo.networkIpAddr,
            sizeof(g_localDeviceInfo.localIfInfoAll[i].localIfInfo.networkIpAddr),
            devInfo->localIfInfo[i].networkIpAddr) != EOK) {
            DFINDER_LOGE(TAG, "Failed to copy network address for index %u", i);
            return;
        }
        g_localDeviceInfo.ifState[i] = IF_STATE_UPDATED;
    }
    g_localDeviceInfo.ifNums = devInfo->ifNums;
}
#endif

int32_t ConfigureLocalDeviceInfo(const NSTACKX_LocalDeviceInfo *devInfo)
{
    char deviceId[NSTACKX_MAX_DEVICE_ID_LEN];
    struct in_addr ipAddr;
    NetworkInterfaceInfo interfaceInfo;

    (void)memset_s(&interfaceInfo, sizeof(interfaceInfo), 0, sizeof(interfaceInfo));
    /* Backup device id */
    (void)memcpy_s(deviceId, sizeof(deviceId), g_localDeviceInfo.deviceId, sizeof(deviceId));
    if (strcpy_s(g_localDeviceInfo.deviceId, sizeof(g_localDeviceInfo.deviceId), devInfo->deviceId) != EOK) {
        DFINDER_LOGE(TAG, "Invalid device id!");
        /* Restore device id if some error happens */
        if (memcpy_s(g_localDeviceInfo.deviceId, sizeof(g_localDeviceInfo.deviceId),
            deviceId, sizeof(deviceId)) != EOK) {
            DFINDER_LOGE(TAG, "deviceId copy error and can't restore device id!");
        }
        return NSTACKX_EINVAL;
    }
#ifdef DFINDER_SUPPORT_MULTI_NIF
    UpdateLocalMultiNifState(devInfo);
    UpdateLocalNetworkInterface();
    (void)ipAddr;
#else
    if ((strnlen(devInfo->networkIpAddr, NSTACKX_MAX_IP_STRING_LEN) < NSTACKX_MAX_IP_STRING_LEN) &&
        (inet_pton(AF_INET, devInfo->networkIpAddr, &ipAddr) == 1) &&
#ifdef NSTACKX_WITH_LITEOS_M
        ((strcpy_s(interfaceInfo.name, sizeof(interfaceInfo.name), devInfo->networkName) == EOK) &&
        (strcpy_s(g_localDeviceInfo.networkName, sizeof(g_localDeviceInfo.networkName),
            devInfo->networkName) == EOK))) {
#else
        (strcpy_s(interfaceInfo.name, sizeof(interfaceInfo.name), devInfo->networkName) == EOK)) {
#endif /* END OF NSTACKX_WITH_LITEOS_M */
        interfaceInfo.ip = ipAddr;
        UpdateLocalNetworkInterface(&interfaceInfo);
    } else {
        DFINDER_LOGD(TAG, "Invalid if name or ip address. Ignore");
    }
#endif /* END OF DFINDER_SUPPORT_MULTI_NIF */
    if (strnlen(devInfo->name, NSTACKX_MAX_DEVICE_NAME_LEN) == 0 || (strncpy_s(g_localDeviceInfo.deviceName,
        sizeof(g_localDeviceInfo.deviceName), devInfo->name, NSTACKX_MAX_DEVICE_NAME_LEN - 1) != EOK)) {
        DFINDER_LOGW(TAG, "Invalid device name. Will use default name");
        (void)strcpy_s(g_localDeviceInfo.deviceName, sizeof(g_localDeviceInfo.deviceName), NSTACKX_DEFAULT_DEVICE_NAME);
    }

    if (strcpy_s(g_localDeviceInfo.version, sizeof(g_localDeviceInfo.version), devInfo->version) != EOK) {
        DFINDER_LOGE(TAG, "Invalid version!");
        return NSTACKX_EINVAL;
    }

    g_localDeviceInfo.deviceType = devInfo->deviceType;
    g_localDeviceInfo.businessType = devInfo->businessType;
    return NSTACKX_EOK;
}

void ConfigureLocalDeviceName(const char *localDeviceName)
{
    char backupDevName[NSTACKX_MAX_DEVICE_NAME_LEN] = {0};
    if (memcpy_s(backupDevName, sizeof(backupDevName), g_localDeviceInfo.deviceName,
        sizeof(g_localDeviceInfo.deviceName)) != EOK) {
        DFINDER_LOGE(TAG, "backup local device name failed!");
        return;
    }
    if (strncpy_s(g_localDeviceInfo.deviceName, NSTACKX_MAX_DEVICE_NAME_LEN,
        localDeviceName, NSTACKX_MAX_DEVICE_NAME_LEN - 1) != EOK) {
        DFINDER_LOGW(TAG, "copy local device failed, will use current name");
        if (strcpy_s(g_localDeviceInfo.deviceName, NSTACKX_MAX_DEVICE_NAME_LEN, backupDevName) != EOK) {
            DFINDER_LOGE(TAG, "config device name failed and cannot restore!");
        }
    }
}

static CoapBroadcastType CheckAdvertiseInfo(const uint32_t advertiseCount, const uint32_t advertiseDuration)
{
    if ((advertiseCount == 0) && (advertiseDuration == 0)) {
        return COAP_BROADCAST_TYPE_DEFAULT;
    }
    return COAP_BROADCAST_TYPE_USER;
}

void ConfigureDiscoverySettings(const NSTACKX_DiscoverySettings *discoverySettings)
{
    if (discoverySettings->businessData == NULL) {
        DFINDER_LOGE(TAG, "businessData null");
        return;
    }

    SetModeInfo(discoverySettings->discoveryMode);
    if (strncpy_s(g_localDeviceInfo.businessData.businessDataBroadcast, NSTACKX_MAX_BUSINESS_DATA_LEN,
        discoverySettings->businessData, discoverySettings->length) != EOK) {
        DFINDER_LOGE(TAG, "businessData copy error");
        return;
    }
    uint32_t advertiseCount = discoverySettings->advertiseCount;
    uint32_t advertiseDuration = discoverySettings->advertiseDuration;
    CoapBroadcastType ret = CheckAdvertiseInfo(advertiseCount, advertiseDuration);
    if (ret == COAP_BROADCAST_TYPE_DEFAULT) {
        SetCoapDiscoverType(COAP_BROADCAST_TYPE_DEFAULT);
    } else if (ret == COAP_BROADCAST_TYPE_USER) {
        SetCoapDiscoverType(COAP_BROADCAST_TYPE_USER);
        SetCoapUserDiscoverInfo(advertiseCount, advertiseDuration);
    }
    g_localDeviceInfo.businessType = discoverySettings->businessType;

    return;
}

const DeviceInfo *GetLocalDeviceInfoPtr(void)
{
    return &g_localDeviceInfo;
}

#ifdef DFINDER_SUPPORT_MULTI_NIF
uint8_t IsApConnected(void)
{
    struct in_addr ipAddr;
    for (uint32_t i = 0; i < NSTACKX_MAX_LISTENED_NIF_NUM; ++i) {
        if (inet_pton(AF_INET, g_localDeviceInfo.localIfInfoAll[i].localIfInfo.networkIpAddr, &ipAddr) == 1 &&
            (ipAddr.s_addr != 0)) {
            return NSTACKX_TRUE;
        }
    }
    DFINDER_LOGD(TAG, "all ap are not connected");
    return NSTACKX_FALSE;
}

uint8_t IsApConnectedWithIdx(uint32_t idx)
{
    struct in_addr ipAddr;
    if (inet_pton(AF_INET, g_localDeviceInfo.localIfInfoAll[idx].localIfInfo.networkIpAddr, &ipAddr) == 1 &&
        (ipAddr.s_addr != 0)) {
        DFINDER_LOGE(TAG, "inet_pton success");
        return NSTACKX_TRUE;
    }
    return NSTACKX_EFAILED;
}
#else
uint8_t IsWifiApConnected(void)
{
    struct in_addr ip;
    GetLocalIp(&ip);
    if (ip.s_addr != 0) {
        return NSTACKX_TRUE;
    } else {
        return NSTACKX_FALSE;
    }
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
#endif /* END OF DFINDER_SUPPORT_MULTI_NIF */

#ifdef DFINDER_SUPPORT_MULTI_NIF
int32_t GetLocalIpStringWithIdx(char *ipString, size_t length, uint32_t idx)
{
    struct in_addr ip;
    GetLocalNifIpWithIdx(&ip, idx);
    if (ip.s_addr == 0) {
        DFINDER_LOGE(TAG, "ip.s_addr is 0");
        return NSTACKX_EFAILED;
    }
    if (inet_ntop(AF_INET, &ip, ipString, length) == NULL) {
        DFINDER_LOGE(TAG, "inet_pton failed");
        return NSTACKX_EFAILED;
    }
    return NSTACKX_EOK;
}
#endif

#if !defined(DFINDER_SUPPORT_MULTI_NIF) && !defined(DFINDER_USE_MINI_NSTACKX)
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
#endif /* END OF (!DFINDER_SUPPORT_MULTI_NIF) && (!DFINDER_USE_MINI_NSTACKX) */

#ifdef DFINDER_SUPPORT_MULTI_NIF
int32_t GetLocalInterfaceName(char *ifName, size_t ifNameLength)
{
    const char *ifInfo = GetLocalNifName();
    if (ifInfo == NULL) {
        return NSTACKX_EFAILED;
    }
    if (strcpy_s(ifName, ifNameLength, ifInfo) != EOK) {
        return NSTACKX_EFAILED;
    }
    return NSTACKX_EOK;
}

int32_t GetLocalInterfaceNameWithIdx(char *ifName, size_t ifNameLen, uint32_t idx)
{
    const char *ifInfo = GetLocalNifNameWithIdx(idx);
    if (ifInfo == NULL) {
        DFINDER_LOGE(TAG, "get local nif name with idx-%u failed, it is NULL", idx);
        return NSTACKX_EFAILED;
    }
    if (strcpy_s(ifName, ifNameLen, ifInfo) != EOK) {
        DFINDER_LOGE(TAG, "strcpy_s copy ifInfo failed");
        return NSTACKX_EFAILED;
    }
    return NSTACKX_EOK;
}
#else
int32_t GetLocalInterfaceName(char *ifName, size_t ifNameLength)
{
    const NetworkInterfaceInfo *ifInfo = GetLocalInterface();
    if (ifInfo == NULL || ifName == NULL) {
        return NSTACKX_EFAILED;
    }

    if (strcpy_s(ifName, ifNameLength, ifInfo->name) != EOK) {
        return NSTACKX_EFAILED;
    }

    return NSTACKX_EOK;
}
#endif /* END OF DFINDER_SUPPORT_MULTI_NIF */

#ifndef DFINDER_USE_MINI_NSTACKX
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

#ifdef _WIN32
uint8_t IsWlanIpAddr(const struct in_addr *ifAddr)
{
    if (ifAddr == NULL) {
        return NSTACKX_FALSE;
    }
    if (ifAddr->s_addr == g_interfaceList[NSTACKX_WLAN_INDEX].ip.s_addr) {
        DFINDER_LOGE(TAG, "IsWlanIpAddr success");
        return NSTACKX_TRUE;
    }

    return NSTACKX_FALSE;
}

uint8_t IsEthIpAddr(const struct in_addr *ifAddr)
{
    if (ifAddr == NULL) {
        return NSTACKX_FALSE;
    }

    if (ifAddr->s_addr == g_interfaceList[NSTACKX_ETH_INDEX].ip.s_addr) {
        DFINDER_LOGE(TAG, "IsEthIpAddr success");
        return NSTACKX_TRUE;
    }

    return NSTACKX_FALSE;
}

uint8_t IsP2pIpAddr(const struct in_addr *ifAddr)
{
    if (ifAddr == NULL) {
        return NSTACKX_FALSE;
    }

    if (ifAddr->s_addr == g_interfaceList[NSTACKX_P2P_INDEX].ip.s_addr) {
        DFINDER_LOGE(TAG, "IsP2pIpAddr success");
        return NSTACKX_TRUE;
    }

    return NSTACKX_FALSE;
}

uint8_t IsUsbIpAddr(const struct in_addr *ifAddr)
{
    if (ifAddr == NULL) {
        return NSTACKX_FALSE;
    }

    if (ifAddr->s_addr == g_interfaceList[NSTACKX_USB_INDEX].ip.s_addr) {
        DFINDER_LOGE(TAG, "IsUsbIpAddr success");
        return NSTACKX_TRUE;
    }

    return NSTACKX_FALSE;
}

#else
uint8_t IsWlanIpAddr(const char *ifName)
{
    if (ifName == NULL) {
        return NSTACKX_FALSE;
    }

    if (NetworkInterfaceNamePrefixCmp(ifName, g_interfaceList[NSTACKX_WLAN_INDEX].name)) {
        DFINDER_LOGE(TAG, "IsWlanIpAddr success");
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
        DFINDER_LOGE(TAG, "IsEthIpAddr success");
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
        DFINDER_LOGE(TAG, "IsP2pIpAddr success");
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
        DFINDER_LOGE(TAG, "IsUsbIpAddr success");
        return NSTACKX_TRUE;
    }

    return NSTACKX_FALSE;
}
#endif
#endif /* END OF DFINDER_USE_MINI_NSTACKX */

int32_t RegisterCapability(uint32_t capabilityBitmapNum, uint32_t capabilityBitmap[])
{
    (void)memset_s(g_localDeviceInfo.capabilityBitmap, sizeof(g_localDeviceInfo.capabilityBitmap),
        0, sizeof(g_localDeviceInfo.capabilityBitmap));
    if (capabilityBitmapNum) {
        if (memcpy_s(g_localDeviceInfo.capabilityBitmap, sizeof(g_localDeviceInfo.capabilityBitmap),
            capabilityBitmap, sizeof(uint32_t) * capabilityBitmapNum) != EOK) {
            DFINDER_LOGE(TAG, "capabilityBitmap copy error");
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
            DFINDER_LOGE(TAG, "FilterCapabilityBitmap copy error");
            return NSTACKX_EFAILED;
        }
    }
    g_filterCapabilityBitmapNum = capabilityBitmapNum;
    return NSTACKX_EOK;
}

int32_t RegisterServiceData(const char *serviceData)
{
    if (serviceData == NULL) {
        DFINDER_LOGE(TAG, "device db init failed");
        return NSTACKX_EINVAL;
    }

    if (strncpy_s(g_localDeviceInfo.serviceData, NSTACKX_MAX_SERVICE_DATA_LEN,
                  serviceData, strlen(serviceData)) != EOK) {
        DFINDER_LOGE(TAG, "serviceData copy error");
        return NSTACKX_EFAILED;
    }
    return NSTACKX_EOK;
}

#ifndef DFINDER_USE_MINI_NSTACKX
int32_t RegisterExtendServiceData(const char *extendServiceData)
{
    if (extendServiceData == NULL) {
        DFINDER_LOGE(TAG, "device db init failed");
        return NSTACKX_EINVAL;
    }

    if (strcpy_s(g_localDeviceInfo.extendServiceData, NSTACKX_MAX_EXTEND_SERVICE_DATA_LEN, extendServiceData) != EOK) {
        DFINDER_LOGE(TAG, "extendServiceData copy error");
        return NSTACKX_EFAILED;
    }
    return NSTACKX_EOK;
}
#endif /* END OF DFINDER_USE_MINI_NSTACKX */

void DeviceModuleClean(void)
{
    if (g_deviceInited == NSTACKX_FALSE) {
        return;
    }

    TimerDelete(g_offlineDeferredTimer);
    g_offlineDeferredTimer = NULL;

#ifdef DFINDER_SAVE_DEVICE_LIST
    if (g_deviceList != NULL) {
        ClearDevices(g_deviceList);
        DFINDER_LOGW(TAG, "clear device list");
        DatabaseClean(g_deviceList);
        g_deviceList = NULL;
    }
    if (g_deviceListBackup != NULL) {
        ClearDevices(g_deviceListBackup);
        DFINDER_LOGW(TAG, "clear device list backup");
        DatabaseClean(g_deviceListBackup);
        g_deviceListBackup = NULL;
    }
#endif /* END OF DFINDER_SAVE_DEVICE_LIST */

    g_deviceInited = NSTACKX_FALSE;
    return;
}

#ifndef DFINDER_SUPPORT_MULTI_NIF
static void GlobalInterfaceListInit(void)
{
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
}
#endif

static void SetMaxDeviceNum(uint32_t maxDeviceNum)
{
#ifdef DFINDER_SAVE_DEVICE_LIST
    if (maxDeviceNum < NSTACKX_MIN_DEVICE_NUM || maxDeviceNum > NSTACKX_MAX_DEVICE_NUM) {
        DFINDER_LOGE(TAG, "illegal device num passed in, set device num to default value");
        maxDeviceNum = NSTACKX_DEFAULT_DEVICE_NUM;
    }
#else
    maxDeviceNum = NSTACKX_MAX_DEVICE_NUM;
#endif
    g_maxDeviceNum = maxDeviceNum;
}

int32_t DeviceModuleInit(EpollDesc epollfd, uint32_t maxDeviceNum)
{
    if (g_deviceInited) {
        return NSTACKX_EOK;
    }
    SetMaxDeviceNum(maxDeviceNum);
    (void)memset_s(&g_localDeviceInfo, sizeof(g_localDeviceInfo), 0, sizeof(g_localDeviceInfo));
#ifndef DFINDER_SUPPORT_MULTI_NIF
    (void)memset_s(g_networkType, sizeof(g_networkType), 0, sizeof(g_networkType));
#endif

#ifdef DFINDER_SAVE_DEVICE_LIST
    int32_t ret = NSTACKX_EFAILED;
    g_deviceList = DatabaseInit(g_maxDeviceNum, sizeof(DeviceInfo), IsSameDevice);
    if (g_deviceList == NULL) {
        DFINDER_LOGE(TAG, "device db init failed");
        return NSTACKX_ENOMEM;
    }
    g_deviceListBackup = DatabaseInit(g_maxDeviceNum, sizeof(DeviceInfo), IsSameDevice);
    if (g_deviceListBackup == NULL) {
        DFINDER_LOGE(TAG, "device db backup init failed");
        ret = NSTACKX_ENOMEM;
        goto L_ERR_DEVICE_DB_BACKUP_LIST;
    }
#endif
    g_offlineDeferredTimer = TimerStart(epollfd, 0, NSTACKX_FALSE, LocalDeviceOffline, NULL);
    if (g_offlineDeferredTimer == NULL) {
        DFINDER_LOGE(TAG, "device offline deferred timer start failed");
#ifdef DFINDER_SAVE_DEVICE_LIST
        goto L_ERR_DEFERRED_TIMER;
#else
        return NSTACKX_EFAILED;
#endif
    }
#ifndef DFINDER_SUPPORT_MULTI_NIF
    GlobalInterfaceListInit();
#endif
    return NSTACKX_EOK;

#ifdef DFINDER_SAVE_DEVICE_LIST
/* Call TimerDelete(g_offlineDeferredTimer) when add module. */
L_ERR_DEFERRED_TIMER:
    DatabaseClean(g_deviceListBackup);
    g_deviceListBackup = NULL;
L_ERR_DEVICE_DB_BACKUP_LIST:
    DatabaseClean(g_deviceList);
    g_deviceList = NULL;
    return ret;
#endif
}

#ifdef DFINDER_SAVE_DEVICE_LIST
static int32_t BackupDeviceDBEx(void)
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
        DFINDER_LOGE(TAG, "clear backupDB error");
    }

    for (uint32_t i = 0; i < g_maxDeviceNum; i++) {
        deviceInfo = DatabaseGetNextRecord(db, &idx);
        if (deviceInfo == NULL) {
            break;
        }

        DeviceInfo *newDeviceInfo = DatabaseAllocRecord(backupDB);
        if (newDeviceInfo == NULL) {
            DFINDER_LOGE(TAG, "allocate device info failure");
            return NSTACKX_EFAILED;
        }
        if (memcpy_s(newDeviceInfo, sizeof(DeviceInfo), deviceInfo, sizeof(DeviceInfo)) != EOK) {
            DFINDER_LOGE(TAG, "memcpy failure");
            return NSTACKX_EFAILED;
        }
    }
    return NSTACKX_EOK;
}

int32_t BackupDeviceDB(void)
{
    int32_t ret = BackupDeviceDBEx();
    if (ret != NSTACKX_EOK) {
        IncStatistics(STATS_BACKUP_DEVICE_DB_FAILED);
    }
    return ret;
}

void *GetDeviceDB(void)
{
    return g_deviceList;
}

void *GetDeviceDBBackup(void)
{
    return g_deviceListBackup;
}
#endif /* END OF DFINDER_SAVE_DEVICE_LIST */

#ifndef DFINDER_SUPPORT_MULTI_NIF
#ifndef DFINDER_USE_MINI_NSTACKX
void UpdateAllNetworkInterfaceNameIfNeed(const NetworkInterfaceInfo *interfaceInfo)
{
    if (interfaceInfo == NULL) {
        DFINDER_LOGE(TAG, "NetworkInterfaceInfo is Null");
        return;
    }
    for (int i = 0; i < NSTACKX_MAX_INTERFACE_NUM; i++) {
        if (strlen(g_interfaceList[i].name) != 0 &&
            strncmp(interfaceInfo->name, g_interfaceList[i].name, strlen(g_interfaceList[i].name)) == 0) {
            return;
        }
    }
    for (int i = 0; i < NSTACKX_MAX_INTERFACE_NUM; i++) {
        for (int j = 0; j < INTERFACE_NAME_POSSIBLE; j++) {
            if (!(strlen(g_interfacePrefixList[i].name[j]) != 0 &&
                strncmp(interfaceInfo->name, g_interfacePrefixList[i].name[j],
                        strlen(g_interfacePrefixList[i].name[j])) == 0)) {
                continue;
            }
            if (strncpy_s(g_interfaceList[i].name, sizeof(g_interfaceList[i].name),
                g_interfacePrefixList[i].name[j], strlen(g_interfacePrefixList[i].name[j])) != EOK) {
                DFINDER_LOGE(TAG, "interface update failed");
            }
            return;
        }
    }
}

static void PadNetworkInterfaceInfo(NetworkInterfaceInfo *intInfo, const struct in_addr *addr, const char *name)
{
    if (intInfo == NULL || addr == NULL || name == NULL) {
        return;
    }
    (void)memset_s(intInfo, sizeof(NetworkInterfaceInfo), 0, sizeof(NetworkInterfaceInfo));
    (void)memcpy_s(&intInfo->ip, sizeof(struct in_addr), addr, sizeof(struct in_addr));
    if (strcpy_s(intInfo->name, sizeof(intInfo->name), name) != EOK) {
        DFINDER_LOGE(TAG, "interface name copy failed");
    }
}

#ifndef _WIN32
static void UpdateInterface(struct ifreq *buf, uint8_t *isUpdated, NetworkInterfaceInfo *ethIntInfo,
                            NetworkInterfaceInfo *wlanIntInfo)
{
    struct sockaddr_in *sa = (struct sockaddr_in *)&(buf->ifr_addr);
    if (IsEthIpAddr(buf->ifr_name) && !isUpdated[NSTACKX_ETH_INDEX]) {
        PadNetworkInterfaceInfo(ethIntInfo, &sa->sin_addr, buf->ifr_name);
        isUpdated[NSTACKX_ETH_INDEX] = NSTACKX_TRUE;
        return;
    }
    if (IsWlanIpAddr(buf->ifr_name) && !isUpdated[NSTACKX_WLAN_INDEX]) {
        PadNetworkInterfaceInfo(wlanIntInfo, &sa->sin_addr, buf->ifr_name);
        isUpdated[NSTACKX_WLAN_INDEX] = NSTACKX_TRUE;
        return;
    }

    /* p2p or usb new ip does not write to g_interfaceList */
    if (IsP2pIpAddr(buf->ifr_name) && !isUpdated[NSTACKX_P2P_INDEX]) {
        TryToInitP2pCoapServer(sa->sin_addr);
        isUpdated[NSTACKX_P2P_INDEX] = NSTACKX_TRUE;
        return;
    }
    if (IsUsbIpAddr(buf->ifr_name) && !isUpdated[NSTACKX_USB_INDEX]) {
        TryToInitUsbCoapServer(sa->sin_addr);
        isUpdated[NSTACKX_USB_INDEX] = NSTACKX_TRUE;
        return;
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
        UpdateInterface(&buf[i], isUpdated, &ethIntInfo, &wlanIntInfo);
    }
    close(fd);
    if (isUpdated[NSTACKX_ETH_INDEX] && UpdateLocalNetworkInterface(&ethIntInfo) != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "Update eth interface failed");
    }
    if (!isUpdated[NSTACKX_ETH_INDEX] && isUpdated[NSTACKX_WLAN_INDEX] &&
        UpdateLocalNetworkInterface(&wlanIntInfo) != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "Update wlan interface failed");
    }
}
#else
static void UpdateInterface(InterfaceInfo *buf, uint8_t *isUpdated, NetworkInterfaceInfo *ethIntInfo,
                            NetworkInterfaceInfo *wlanIntInfo)
{
    struct in_addr *sa = (struct in_addr *)&(buf->ipAddr);
    if (IsEthIpAddr(sa) && !isUpdated[NSTACKX_ETH_INDEX]) {
        PadNetworkInterfaceInfo(ethIntInfo, sa, buf->name);
        isUpdated[NSTACKX_ETH_INDEX] = NSTACKX_TRUE;
        return;
    }
    if (IsWlanIpAddr(sa) && !isUpdated[NSTACKX_WLAN_INDEX]) {
        PadNetworkInterfaceInfo(wlanIntInfo, sa, buf->name);
        isUpdated[NSTACKX_WLAN_INDEX] = NSTACKX_TRUE;
        return;
    }

    /* p2p or usb new ip does not write to g_interfaceList */
    if (IsP2pIpAddr(sa) && !isUpdated[NSTACKX_P2P_INDEX]) {
        TryToInitP2pCoapServer(*sa);
        isUpdated[NSTACKX_P2P_INDEX] = NSTACKX_TRUE;
        return;
    }
    if (IsUsbIpAddr(sa) && !isUpdated[NSTACKX_USB_INDEX]) {
        TryToInitUsbCoapServer(*sa);
        isUpdated[NSTACKX_USB_INDEX] = NSTACKX_TRUE;
        return;
    }
}

void GetLocalNetworkInterface(void *arg)
{
    uint8_t isUpdated[NSTACKX_MAX_INTERFACE_NUM] = {0};
    NetworkInterfaceInfo wlanIntInfo, ethIntInfo;
    (void)arg;

    InterfaceInfo interfaceList[INTERFACE_MAX];
    int interfaceInfoSize = 0;
    if (GetInterfaceList(interfaceList, &interfaceInfoSize) == NSTACKX_EFAILED) {
        DFINDER_LOGE(TAG, "GetInterfaceList failed");
        return NSTACKX_EFAILED;
    }

    for (int i = 0; i < interfaceInfoSize; i++) {
        UpdateInterface(&interfaceList[i], isUpdated, &ethIntInfo, &wlanIntInfo);
    }

    if (isUpdated[NSTACKX_ETH_INDEX] && UpdateLocalNetworkInterface(&ethIntInfo) != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "Update eth interface failed");
    }
    if (!isUpdated[NSTACKX_ETH_INDEX] && isUpdated[NSTACKX_WLAN_INDEX] &&
        UpdateLocalNetworkInterface(&wlanIntInfo) != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "Update wlan interface failed");
    }
}
#endif
#endif /* END OF DFINDER_USE_MINI_NSTACKX */
#endif /* END OF DFINDER_SUPPORT_MULTI_NIF */

void ResetDeviceTaskCount(uint8_t isBusy)
{
    if (g_offlineDeferredTimer != NULL) {
        if (isBusy) {
            DFINDER_LOGI(TAG, "in this busy interval: g_offlineDeferredTimer task count %llu",
                         g_offlineDeferredTimer->task.count);
        }
        g_offlineDeferredTimer->task.count = 0;
    }
#if !defined(DFINDER_SUPPORT_MULTI_NIF) && !defined(DFINDER_USE_MINI_NSTACK)
    if (g_p2pServerInitDeferredTimer != NULL) {
        if (isBusy) {
            DFINDER_LOGI(TAG, "in this busy interval: g_p2pServerInitDeferredTimer task count %llu",
                         g_p2pServerInitDeferredTimer->task.count);
        }
        g_p2pServerInitDeferredTimer->task.count = 0;
    }

    if (g_usbServerInitDeferredTimer != NULL) {
        if (isBusy) {
            DFINDER_LOGI(TAG, "in this busy interval: g_usbServerInitDeferredTimer task count %llu",
                         g_usbServerInitDeferredTimer->task.count);
        }
        g_usbServerInitDeferredTimer->task.count = 0;
    }
#endif /* END OF (!DFINDER_SUPPORT_MULTI_NIF) && (!DFINDER_USE_MINI_NSTACKX) */
}

int32_t SetLocalDeviceBusinessDataUnicast(const char* businessData, uint32_t length)
{
    if (strncpy_s(g_localDeviceInfo.businessData.businessDataUnicast, NSTACKX_MAX_BUSINESS_DATA_LEN,
        businessData, length) != EOK)  {
        DFINDER_LOGE(TAG, "businessData copy error");
        return NSTACKX_EFAILED;
    }
    return NSTACKX_EOK;
}
