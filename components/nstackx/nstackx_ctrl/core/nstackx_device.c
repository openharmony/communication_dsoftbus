/*
 * Copyright (C) 2021-2023 Huawei Device Co., Ltd.
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
#include "coap_app.h"
#include "coap_discover.h"
#include "json_payload.h"
#include "nstackx_statistics.h"
#include "nstackx_device_local.h"
#include "nstackx_device_remote.h"

#define TAG "nStackXDFinder"

#define NSTACKX_RESERVED_INFO_WIFI_IP "wifiIpAddr"

#define NSTACKX_MAX_INTERFACE_NUM (IFACE_TYPE_USB + 1)
#ifdef DFINDER_USE_INTERFACE_PREFIX_WLAN0
#define NSTACKX_WLAN_INTERFACE_NAME_PREFIX "wlan0"
#else
#define NSTACKX_WLAN_INTERFACE_NAME_PREFIX "wlan"
#endif
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

static uint32_t g_maxDeviceNum;
static uint32_t g_filterCapabilityBitmapNum = 0;
static uint32_t g_filterCapabilityBitmap[NSTACKX_MAX_CAPABILITY_NUM] = {0};
/* g_interfaceList store the actual interface name prefix for one platform */
static NetworkInterfaceInfo g_interfaceList[NSTACKX_MAX_INTERFACE_NUM];
static SeqAll g_seqAll = {0, 0, 0};
static uint32_t g_notifyTimeoutMs = 0;
static pthread_mutex_t g_filterCapabilityLock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_maxDeviceNumLock = PTHREAD_MUTEX_INITIALIZER;

#ifndef DFINDER_USE_MINI_NSTACKX
/*
 * g_interfacePrefixList store all interface name prefix to adapt different platform
 * when platform interface name prefix update, just update g_interfacePrefixList
 */
static const NetworkInterfacePrefiexPossible g_interfacePrefixList[NSTACKX_MAX_INTERFACE_NUM] = {
    {{"eth", "", ""}},
    {{NSTACKX_WLAN_INTERFACE_NAME_PREFIX, "ap", ""}},
    {{"p2p-p2p0-", "p2p-wlan0-", "p2p0"}},
    {{"rndis0", "", ""}}
};

#endif /* END OF (!DFINDER_USE_MINI_NSTACKX) */

int32_t DeviceInfoNotify(const DeviceInfo *deviceInfo)
{
    if (!MatchDeviceFilter(deviceInfo)) {
        return NSTACKX_EOK;
    }
    NSTACKX_DeviceInfo notifyDevice;
    (void)memset_s(&notifyDevice, sizeof(notifyDevice), 0, sizeof(notifyDevice));
    if (GetNotifyDeviceInfo(&notifyDevice, deviceInfo) != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "get notify device info failed");
        return NSTACKX_EFAILED;
    }
    notifyDevice.update = NSTACKX_TRUE;
    NotifyDeviceListChanged(&notifyDevice, 1);
    if (CoapDiscoverRequestOngoing()) {
        NotifyDeviceFound(&notifyDevice, 1);
    }
    return NSTACKX_EOK;
}

#ifdef DFINDER_SAVE_DEVICE_LIST
static int32_t UpdateDeviceDbInDeviceList(const CoapCtxType *coapCtx, const DeviceInfo *deviceInfo,
    uint8_t forceUpdate, uint8_t receiveBcast)
{
    const char *deviceId = deviceInfo->deviceId;
    NSTACKX_InterfaceInfo info;
    if (strcpy_s(info.networkIpAddr, NSTACKX_MAX_IP_STRING_LEN, GetLocalIfaceIpStr(coapCtx->iface)) != EOK ||
        strcpy_s(info.networkName, NSTACKX_MAX_INTERFACE_NAME_LEN, GetLocalIfaceName(coapCtx->iface)) != EOK) {
        DFINDER_LOGE(TAG, "copy interfaceinfo failed");
        return NSTACKX_EFAILED;
    }
    const struct in_addr *remoteIp = &(deviceInfo->netChannelInfo.wifiApInfo.ip);
    int8_t updated = NSTACKX_FALSE;
    if (UpdateRemoteNodeByDeviceInfo(deviceId, &info, remoteIp, deviceInfo, &updated) != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "update remote node by deviceinfo failed");
        return NSTACKX_EFAILED;
    }
    if (!receiveBcast && (ShouldAutoReplyUnicast(deviceInfo->businessType) != NSTACKX_TRUE)) {
        return updated ? DeviceInfoNotify(deviceInfo) : NSTACKX_EOK;
    }
    if (updated || forceUpdate) {
        DFINDER_LOGD(TAG, "updated is: %hhu, forceUpdate is: %hhu", updated, forceUpdate);
        DeviceInfoNotify(deviceInfo);
    }
    return NSTACKX_EOK;
}

int32_t UpdateDeviceDb(const CoapCtxType *coapCtx, const DeviceInfo *deviceInfo, uint8_t forceUpdate,
    uint8_t receiveBcast)
{
    int32_t ret = UpdateDeviceDbInDeviceList(coapCtx, deviceInfo, forceUpdate, receiveBcast);
    if (ret != NSTACKX_EOK) {
        IncStatistics(STATS_UPDATE_DEVICE_DB_FAILED);
    }
    return ret;
}

#endif /* END OF DFINDER_SAVE_DEVICE_LIST */

int32_t ReportDiscoveredDevice(const CoapCtxType *coapCtx, const DeviceInfo *deviceInfo,
    uint8_t forceUpdate, uint8_t receiveBcast)
{
#ifdef DFINDER_SAVE_DEVICE_LIST
    return UpdateDeviceDb(coapCtx, deviceInfo, forceUpdate, receiveBcast);
#else
    (void)coapCtx;
    (void)forceUpdate;
    (void)receiveBcast;
    return DeviceInfoNotify(deviceInfo);
#endif
}

bool MatchDeviceFilter(const DeviceInfo *deviceInfo)
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

static int32_t SetServiceDataFromDeviceInfo(cJSON *item, const DeviceInfo *deviceInfo)
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
    return NSTACKX_EOK;
}

int32_t SetReservedInfoFromDeviceInfo(NSTACKX_DeviceInfo *deviceList, const DeviceInfo *deviceInfo)
{
    char wifiIpAddr[NSTACKX_MAX_IP_STRING_LEN];
    int32_t ret  = NSTACKX_EFAILED;

    (void)memset_s(wifiIpAddr, sizeof(wifiIpAddr), 0, sizeof(wifiIpAddr));
    (void)inet_ntop(AF_INET, &deviceInfo->netChannelInfo.wifiApInfo.ip, wifiIpAddr, sizeof(wifiIpAddr));
    if (sprintf_s(deviceList->reservedInfo, sizeof(deviceList->reservedInfo),
        NSTACKX_RESERVED_INFO_JSON_FORMAT, wifiIpAddr) == -1) {
        DFINDER_LOGE(TAG, "sprintf_s reservedInfo with wifiIpAddr fails");
        return NSTACKX_EAGAIN;
    }
    cJSON *item = cJSON_Parse(deviceList->reservedInfo);
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
    if (SetServiceDataFromDeviceInfo(item, deviceInfo) != NSTACKX_EOK) {
        goto L_END;
    }
    char *newData = cJSON_Print(item);
    if (newData == NULL) {
        goto L_END;
    }
    (void)memset_s(deviceList->reservedInfo, sizeof(deviceList->reservedInfo),
                   0, sizeof(deviceList->reservedInfo));
    if (strcpy_s(deviceList->reservedInfo, sizeof(deviceList->reservedInfo), newData) != EOK) {
        cJSON_free(newData);
        DFINDER_LOGE(TAG, "strcpy_s fails");
        goto L_END;
    }
    cJSON_free(newData);
    ret = NSTACKX_EOK;
L_END:
    cJSON_Delete(item);
    return ret;
}

int32_t GetNotifyDeviceInfo(NSTACKX_DeviceInfo *notifyDevice, const DeviceInfo *deviceInfo)
{
    if ((strcpy_s(notifyDevice->deviceId, sizeof(notifyDevice->deviceId), deviceInfo->deviceId) != EOK) ||
        (strcpy_s(notifyDevice->deviceName, sizeof(notifyDevice->deviceName), deviceInfo->deviceName) != EOK)) {
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

    int32_t result = SetReservedInfoFromDeviceInfo(notifyDevice, deviceInfo);
    if (result != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "SetReservedInfoFromDeviceInfo fails: %hhd", result);
        return result;
    }

    if (strcpy_s(notifyDevice->networkName, sizeof(notifyDevice->networkName), deviceInfo->networkName) != EOK) {
        DFINDER_LOGE(TAG, "copy networkName failed");
        return NSTACKX_EFAILED;
    }

    notifyDevice->discoveryType = deviceInfo->discoveryType;
    notifyDevice->deviceType = deviceInfo->deviceType;
    notifyDevice->mode = deviceInfo->mode;
    notifyDevice->businessType = deviceInfo->businessType;
    return NSTACKX_EOK;
}

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

void SetModeInfo(uint8_t mode)
{
    SetLocalDeviceMode(mode);
}

uint8_t GetModeInfo(void)
{
    return GetLocalDeviceMode();
}

static CoapBroadcastType CheckAdvertiseInfo(const uint32_t advertiseCount, const uint32_t advertiseDuration)
{
    if ((advertiseCount == 0) && (advertiseDuration == 0)) {
        return COAP_BROADCAST_TYPE_DEFAULT;
    }
    return COAP_BROADCAST_TYPE_USER;
}

#define NOTIFY_TIMEOUT_FLUCATION_MS 500

static void SetNotifyTimeoutMs(uint32_t timeoutMs)
{
    g_notifyTimeoutMs = timeoutMs;
}

uint32_t GetNotifyTimeoutMs(void)
{
    return g_notifyTimeoutMs;
}

int32_t ConfigureDiscoverySettings(const NSTACKX_DiscoverySettings *discoverySettings)
{
    if (discoverySettings->businessData == NULL) {
        DFINDER_LOGE(TAG, "businessData null");
        return NSTACKX_EINVAL;
    }
    SetModeInfo(discoverySettings->discoveryMode);
    if (SetLocalDeviceBusinessData(discoverySettings->businessData, NSTACKX_FALSE) != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "businessData copy error");
        return NSTACKX_EFAILED;
    }
    SetLocalDeviceBusinessType(discoverySettings->businessType);
    DFINDER_LOGD(TAG, "disc, local device business type set to: %hu", GetLocalDeviceBusinessType());
    uint32_t advertiseCount = discoverySettings->advertiseCount;
    uint32_t advertiseDuration = discoverySettings->advertiseDuration;
    // support fallback to default: 12 times with 5 sec
    CoapBroadcastType ret = CheckAdvertiseInfo(advertiseCount, advertiseDuration);
    if (ret == COAP_BROADCAST_TYPE_DEFAULT) {
        SetCoapDiscoverType(COAP_BROADCAST_TYPE_DEFAULT);
        SetNotifyTimeoutMs(NSTACKX_MIN_ADVERTISE_DURATION + NOTIFY_TIMEOUT_FLUCATION_MS);
    } else if (ret == COAP_BROADCAST_TYPE_USER) {
        SetCoapDiscoverType(COAP_BROADCAST_TYPE_USER);
        SetCoapUserDiscoverInfo(advertiseCount, advertiseDuration);
        SetNotifyTimeoutMs(advertiseDuration + NOTIFY_TIMEOUT_FLUCATION_MS);
    }
    IncreaseSequenceNumber(NSTACKX_TRUE);
    return NSTACKX_EOK;
}

int32_t DiscConfigInner(const DFinderDiscConfig *discConfig)
{
    if (discConfig->businessData == NULL) {
        DFINDER_LOGE(TAG, "business data is null");
        return NSTACKX_EINVAL;
    }
    SetModeInfo(discConfig->discoveryMode);
    if (SetLocalDeviceBusinessData(discConfig->businessData, NSTACKX_FALSE) != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "copy business data failed");
        return  NSTACKX_EFAILED;
    }
    SetCoapDiscoverType(COAP_BROADCAST_TYPE_USER_DEFINE_INTERVAL);
    // do not support fallback to default: 12 times with 5 sec
    return SetCoapDiscConfig(discConfig);
}

int32_t SetFilterCapability(uint32_t capabilityBitmapNum, uint32_t capabilityBitmap[])
{
    if (PthreadMutexLock(&g_filterCapabilityLock) != 0) {
        DFINDER_LOGE(TAG, "failed to lock");
        return NSTACKX_EFAILED;
    }
    if (!memcmp(capabilityBitmap, g_filterCapabilityBitmap, sizeof(uint32_t) * capabilityBitmapNum)) {
        if (PthreadMutexUnlock(&g_filterCapabilityLock) != 0) {
            DFINDER_LOGE(TAG, "failed to unlock");
            return NSTACKX_EFAILED;
        }
        return NSTACKX_EOK;
    }
    (void)memset_s(g_filterCapabilityBitmap, sizeof(g_filterCapabilityBitmap),
        0, sizeof(g_filterCapabilityBitmap));
    if (capabilityBitmapNum) {
        if (memcpy_s(g_filterCapabilityBitmap, sizeof(g_filterCapabilityBitmap),
            capabilityBitmap, sizeof(uint32_t) * capabilityBitmapNum) != EOK) {
            DFINDER_LOGE(TAG, "FilterCapabilityBitmap copy error");
            if (PthreadMutexUnlock(&g_filterCapabilityLock) != 0) {
                DFINDER_LOGE(TAG, "failed to unlock");
            }
            return NSTACKX_EFAILED;
        }
    }
    g_filterCapabilityBitmapNum = capabilityBitmapNum;
    if (PthreadMutexUnlock(&g_filterCapabilityLock) != 0) {
        DFINDER_LOGE(TAG, "failed to unlock");
        return NSTACKX_EFAILED;
    }
    return NSTACKX_EOK;
}

uint32_t *GetFilterCapability(uint32_t *capabilityBitmapNum)
{
    if (capabilityBitmapNum != NULL) {
        *capabilityBitmapNum = g_filterCapabilityBitmapNum;
    }

    return g_filterCapabilityBitmap;
}

void IncreaseSequenceNumber(uint8_t sendBcast)
{
    if (sendBcast) {
        ++g_seqAll.seqBcast;
    } else {
        ++g_seqAll.seqUcast;
    }
}

uint16_t GetSequenceNumber(uint8_t sendBcast)
{
    return (sendBcast) ? g_seqAll.seqBcast : g_seqAll.seqUcast;
}

void ResetSequenceNumber(void)
{
    (void)memset_s(&g_seqAll, sizeof(g_seqAll), 0, sizeof(g_seqAll));
}

static void FilterCapabilityInit()
{
    (void)memset_s(g_filterCapabilityBitmap, sizeof(g_filterCapabilityBitmap),
        0, sizeof(g_filterCapabilityBitmap));
    g_filterCapabilityBitmapNum = 0;
}

void DeviceModuleClean(void)
{
#ifdef DFINDER_SAVE_DEVICE_LIST
    RemoteDeviceListDeinit();
#endif /* END OF DFINDER_SAVE_DEVICE_LIST */

    LocalDeviceDeinit();
}

static void GlobalInterfaceListInit()
{
    (void)memset_s(g_interfaceList, sizeof(g_interfaceList), 0, sizeof(g_interfaceList));
    (void)strcpy_s(g_interfaceList[IFACE_TYPE_WLAN].name,
        sizeof(g_interfaceList[IFACE_TYPE_WLAN].name), NSTACKX_WLAN_INTERFACE_NAME_PREFIX);
    (void)strcpy_s(g_interfaceList[IFACE_TYPE_ETH].name,
        sizeof(g_interfaceList[IFACE_TYPE_ETH].name), NSTACKX_ETH_INTERFACE_NAME_PREFIX);
    (void)strcpy_s(g_interfaceList[IFACE_TYPE_P2P].name,
        sizeof(g_interfaceList[IFACE_TYPE_P2P].name), NSTACKX_P2P_INTERFACE_NAME_PREFIX);
    (void)strcpy_s(g_interfaceList[IFACE_TYPE_P2P].alias,
        sizeof(g_interfaceList[IFACE_TYPE_P2P].alias), NSTACKX_P2P_WLAN_INTERFACE_NAME_PREFIX);
    (void)strcpy_s(g_interfaceList[IFACE_TYPE_USB].name,
        sizeof(g_interfaceList[IFACE_TYPE_USB].name), NSTACKX_USB_INTERFACE_NAME_PREFIX);
}

void SetMaxDeviceNum(uint32_t maxDeviceNum)
{
    if (PthreadMutexLock(&g_maxDeviceNumLock) != 0) {
        DFINDER_LOGE(TAG, "failed to lock");
        return;
    }
#ifdef DFINDER_SAVE_DEVICE_LIST
    if (maxDeviceNum < NSTACKX_MIN_DEVICE_NUM || maxDeviceNum > NSTACKX_MAX_DEVICE_NUM) {
        DFINDER_LOGE(TAG, "illegal device num passed in, set device num to default value");
        maxDeviceNum = NSTACKX_DEFAULT_DEVICE_NUM;
    }
    uint32_t remoteNodeCnt = GetRemoteNodeCount();
    if (maxDeviceNum < remoteNodeCnt) {
        uint32_t diffNum = remoteNodeCnt - maxDeviceNum;
        DFINDER_LOGI(TAG, "maxDeviceNum is less than remoteNodeCount, remove %u oldest nodes", diffNum);
        RemoveOldestNodesWithCount(diffNum);
    }
#else
    maxDeviceNum = NSTACKX_MAX_DEVICE_NUM;
#endif
    g_maxDeviceNum = maxDeviceNum;
    DFINDER_LOGD(TAG, "the maxDeviceNum is set to: %u", g_maxDeviceNum);
    if (PthreadMutexUnlock(&g_maxDeviceNumLock) != 0) {
        DFINDER_LOGE(TAG, "failed to unlock");
    }
}

uint32_t GetMaxDeviceNum(void)
{
    return g_maxDeviceNum;
}

int32_t DeviceModuleInit(EpollDesc epollfd, uint32_t maxDeviceNum)
{
    SetMaxDeviceNum(maxDeviceNum);
#ifdef DFINDER_SAVE_DEVICE_LIST
    SetDeviceListAgingTime(NSTACKX_DEFAULT_AGING_TIME);
#endif
    FilterCapabilityInit();

    if (LocalDeviceInit(epollfd) != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "local device init failed");
        return NSTACKX_EFAILED;
    }

#ifdef DFINDER_SAVE_DEVICE_LIST
    if (RemoteDeviceListInit() != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "remote device list init failed");
        return NSTACKX_EFAILED;
    }
#endif

    GlobalInterfaceListInit();

    return NSTACKX_EOK;
}

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

#endif /* END OF DFINDER_USE_MINI_NSTACKX */

void ResetDeviceTaskCount(uint8_t isBusy)
{
    ResetLocalDeviceTaskCount(isBusy);
}

uint8_t GetIfaceType(const char *ifname)
{
    uint8_t i;
    for (i = IFACE_TYPE_ETH; i < NSTACKX_MAX_INTERFACE_NUM; i++) {
        if (NetworkInterfaceNamePrefixCmp(ifname, g_interfaceList[i].name) ||
            (g_interfaceList[i].alias[0] != '\0' && NetworkInterfaceNamePrefixCmp(ifname, g_interfaceList[i].name))) {
            return i;
        }
    }

    return IFACE_TYPE_UNKNOWN;
}
