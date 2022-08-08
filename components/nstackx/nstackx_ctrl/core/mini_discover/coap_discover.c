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

#include "coap_discover.h"

#include <errno.h>
#include <string.h>

#include "coap_adapter.h"
#include "coap_app.h"
#include "json_payload.h"
#include "lwip/sockets.h"
#include "nstackx_device.h"
#include "nstackx_error.h"
#include "nstackx_dfinder_log.h"
#include "nstackx_timer.h"
#include "securec.h"
#include "nstackx_statistics.h"

#define TAG "nStackXCoAP"

#define COAP_URI_BUFFER_LENGTH 64 /* the size of the buffer or variable used to save uri. */

/*
 * 1st discover interval: 100ms
 * 2nd ~ 3rd discover interval: 200ms
 * Remaining discover interval (9 times): 500ms
 */
#define COAP_DEFAULT_DISCOVER_COUNT 12
#define COAP_FIRST_DISCOVER_COUNT_RANGE 1
#define COAP_SECOND_DISCOVER_COUNT_RANGE 3
#define COAP_FIRST_DISCOVER_INTERVAL 100
#define COAP_SECOND_DISCOVER_INTERVAL 200
#define COAP_LAST_DISCOVER_INTERVAL 500

static Timer *g_discoverTimer = NULL;
static uint32_t g_discoverCount;
static uint32_t g_coapMaxDiscoverCount = COAP_DEFAULT_DISCOVER_COUNT;
static uint32_t g_coapDiscoverType = COAP_BROADCAST_TYPE_DEFAULT;
static uint32_t g_coapUserMaxDiscoverCount;
static uint32_t g_coapUserDiscoverInterval;
static uint32_t g_coapDiscoverTargetCount;
static uint8_t g_userRequest;
static uint8_t g_forceUpdate;

static int32_t CheckBusinessTypeCanNotify(const uint8_t businessType)
{
    uint8_t localBusinessType = GetLocalDeviceInfoPtr()->businessType;
    if (businessType == localBusinessType) {
        return NSTACKX_EOK;
    }
    if ((localBusinessType == NSTACKX_BUSINESS_TYPE_NEARBY) ||
        (businessType == NSTACKX_BUSINESS_TYPE_NEARBY)) {
        return NSTACKX_EFAILED;
    }
    return NSTACKX_EOK;
}

static int32_t HndPostServiceDiscoverInner(const uint8_t *buf, size_t size, char **remoteUrl, DeviceInfo *deviceInfo)
{
    if (GetServiceDiscoverInfo(buf, size, deviceInfo, remoteUrl) != NSTACKX_EOK) {
        return NSTACKX_EFAILED;
    }
    if (CheckBusinessTypeCanNotify(deviceInfo->businessType) != NSTACKX_EOK) {
        return NSTACKX_EFAILED;
    }
    /* receive coap broadcast, set peer device's discovery type to passive,
     * to identify the local device is in passive discovery
     */
    deviceInfo->discoveryType = (*remoteUrl != NULL) ? NSTACKX_DISCOVERY_TYPE_PASSIVE : NSTACKX_DISCOVERY_TYPE_ACTIVE;
    if (deviceInfo->mode == PUBLISH_MODE_UPLINE || deviceInfo->mode == PUBLISH_MODE_OFFLINE) {
        DFINDER_LOGD(TAG, "peer is not DISCOVER_MODE");
        size_t deviceListLen = sizeof(NSTACKX_DeviceInfo) * PUBLISH_DEVICE_NUM;
        NSTACKX_DeviceInfo *deviceList = (NSTACKX_DeviceInfo *)malloc(deviceListLen);
        if (deviceList == NULL) {
            DFINDER_LOGE(TAG, "malloc device list failed");
            return NSTACKX_ENOMEM;
        }
        (void)memset_s(deviceList, deviceListLen, 0, deviceListLen);
        PushPublishInfo(deviceInfo, deviceList, PUBLISH_DEVICE_NUM);
        NotifyDeviceFound(deviceList, PUBLISH_DEVICE_NUM);
        free(deviceList);
        return NSTACKX_EFAILED;
    }
    return NSTACKX_EOK;
}

void GetBuildCoapParam(const CoapPacket *pkt, const char *remoteUrl, const char *remoteIp, CoapBuildParam *param)
{
    param->remoteIp = (char *)remoteIp;
    param->uriPath = COAP_DEVICE_DISCOVER_URI;
    if (remoteUrl != NULL) {
        param->msgType = COAP_TYPE_CON;
        param->methodType = COAP_METHOD_POST;
        param->msgId = CoapSoftBusMsgId();
    } else {
        param->msgType = COAP_TYPE_ACK;
        param->methodType = COAP_RESPONSE_201;
        param->msgId = pkt->header.varSection.msgId;
    }
}

/* this is a tmp func */
static int32_t CreateUnicastCoapParam(const char *remoteUrl, const char *remoteIp, CoapBuildParam *param)
{
    if ((remoteUrl == NULL) || (remoteIp == NULL)) {
        return NSTACKX_EFAILED;
    }
    param->remoteIp = (char *)remoteIp;
    param->uriPath = COAP_DEVICE_DISCOVER_URI;
    param->msgType = COAP_TYPE_CON;
    param->methodType = COAP_METHOD_POST;
    param->msgId = CoapSoftBusMsgId();
    return NSTACKX_EOK;
}

static int32_t HndPostServiceDiscoverEx(const CoapPacket *pkt)
{
    int32_t ret = NSTACKX_EFAILED;
    if (pkt == NULL) {
        return ret;
    }
    char *remoteUrl = NULL;
    CoapBuildParam param;
    (void)memset_s(&param, sizeof(CoapBuildParam), 0, sizeof(CoapBuildParam));
    char wifiIpAddr[NSTACKX_MAX_IP_STRING_LEN] = {0};
    DeviceInfo *deviceInfo = (DeviceInfo *)malloc(sizeof(DeviceInfo));
    if (deviceInfo == NULL) {
        DFINDER_LOGE(TAG, "malloc device info failed");
        return ret;
    }
    (void)memset_s(deviceInfo, sizeof(DeviceInfo), 0, sizeof(DeviceInfo));
    if (HndPostServiceDiscoverInner(pkt->payload.buffer, pkt->payload.len, &remoteUrl, deviceInfo) != NSTACKX_EOK) {
        goto FAIL;
    }
    if (GetModeInfo() == PUBLISH_MODE_UPLINE || GetModeInfo() == PUBLISH_MODE_OFFLINE) {
        DFINDER_LOGD(TAG, "local is not DISCOVER_MODE");
        goto FAIL;
    }
#ifdef DFINDER_SAVE_DEVICE_LIST
    if (UpdateDeviceDb(deviceInfo, g_forceUpdate) != NSTACKX_EOK) {
#else
    if (DeviceInfoNotify(&deviceInfo, g_forceUpdate) != NSTACKX_EOK) {
#endif /* END OF DFINDER_SAVE_DEVICE_LIST */
        goto FAIL;
    }
    if (g_forceUpdate) {
        g_forceUpdate = NSTACKX_FALSE;
    }
    if (deviceInfo->mode == PUBLISH_MODE_PROACTIVE) {
        DFINDER_LOGD(TAG, "peer is PUBLISH_MODE_PROACTIVE");
        goto FAIL;
    }
    (void)inet_ntop(AF_INET, &(deviceInfo->netChannelInfo.wifiApInfo.ip), wifiIpAddr, sizeof(wifiIpAddr));
    GetBuildCoapParam(pkt, remoteUrl, wifiIpAddr, &param);
    if (remoteUrl != NULL) {
        if (CheckBusinessTypeReplyUnicast(deviceInfo->businessType) == NSTACKX_EOK) {
            (void)CoapSendMessage(&param, NSTACKX_FALSE, false);
        }
    } else {
        (void)CoapSendMessage(&param, NSTACKX_FALSE, true);
    }
    ret = NSTACKX_EOK;
FAIL:
    free(remoteUrl);
    free(deviceInfo);
    return ret;
}

void HndPostServiceDiscover(const CoapPacket *pkt)
{
    if (HndPostServiceDiscoverEx(pkt) != NSTACKX_EOK) {
        IncStatistics(STATS_HANDLE_DEVICE_DISCOVER_MSG_FAILED);
    }
}

static uint32_t GetDiscoverInterval(uint32_t discoverCount)
{
    switch (g_coapDiscoverType) {
        case COAP_BROADCAST_TYPE_DEFAULT:
            return GetDefaultDiscoverInterval(discoverCount);
        case COAP_BROADCAST_TYPE_USER:
            return g_coapUserDiscoverInterval;
        default:
            return GetDefaultDiscoverInterval(discoverCount);
    }
}

static void CoapServiceDiscoverStop(void)
{
    g_discoverCount = 0;
    g_forceUpdate = NSTACKX_FALSE;
    SetModeInfo(DISCOVER_MODE);
#ifdef DFINDER_SAVE_DEVICE_LIST
    ClearDevices(GetDeviceDBBackup());
    DFINDER_LOGW(TAG, "clear device list backup");
#endif /* END OF DFINDER_SAVE_DEVICE_LIST */
    g_coapDiscoverType = COAP_BROADCAST_TYPE_DEFAULT;
    g_coapMaxDiscoverCount = COAP_DEFAULT_DISCOVER_COUNT;
    /* Can call PostDeviceFindWrapper() to notify user if needed. */
    g_userRequest = NSTACKX_FALSE;
}

static int32_t CoapPostServiceDiscoverEx(void)
{
    char ipString[NSTACKX_MAX_IP_STRING_LEN] = {0};
    char ifName[NSTACKX_MAX_INTERFACE_NAME_LEN] = {0};

    if (GetNetworkName(ifName, sizeof(ifName)) != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "get local interface name error");
        return NSTACKX_EFAILED;
    }

    struct ifreq ifr;
    if (strncpy_s(ifr.ifr_name, sizeof(ifr.ifr_name), ifName, strlen(ifName)) != EOK) {
        DFINDER_LOGE(TAG, "copy netIfName:%s fail", ifName);
        return NSTACKX_EFAILED;
    }
    int32_t fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        DFINDER_LOGE(TAG, "create socket fd failed, errno = %d", errno);
        return NSTACKX_EFAILED;
    }
    if (lwip_ioctl(fd, SIOCGIFBRDADDR, (char*)&ifr) < 0) {
        DFINDER_LOGE(TAG, "ioctl fail, errno = %d", errno);
        lwip_close(fd);
        return NSTACKX_EFAILED;
    }
    lwip_close(fd);
    if (inet_ntop(AF_INET, &(((struct sockaddr_in *)&(ifr.ifr_addr))->sin_addr), ipString, sizeof(ipString)) == NULL) {
        return NSTACKX_EFAILED;
    }
    CoapBuildParam param = {0};
    param.remoteIp = ipString;
    param.uriPath = COAP_DEVICE_DISCOVER_URI;
    param.msgType = COAP_TYPE_NONCON;
    param.methodType = COAP_METHOD_POST;
    param.msgId = CoapSoftBusMsgId();
    if (CoapSendMessage(&param, NSTACKX_TRUE, false) != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "coap broadcast failed");
        return NSTACKX_EFAILED;
    }
    return NSTACKX_EOK;
}

static int32_t CoapPostServiceDiscover(void)
{
    int32_t ret = CoapPostServiceDiscoverEx();
    if (ret != NSTACKX_EOK) {
        IncStatistics(STATS_POST_SD_REQUEST_FAILED);
    }
    return ret;
}

static void CoapServiceDiscoverTimerHandle(void *argument)
{
    uint32_t discoverInterval;

    (void)argument;

    if (g_discoverCount >= g_coapDiscoverTargetCount || !IsWifiApConnected()) {
        /* Discover done, or wifi AP disconnected. */
        CoapServiceDiscoverStop();
        return;
    }

    if (CoapPostServiceDiscover() != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "failed to post service discover request");
        goto L_ERR_SERVICE_DISCOVER;
    }
    DFINDER_LOGI(TAG, "the %u times for device discover.", g_discoverCount + 1);

    /* Restart timer */
    discoverInterval = GetDiscoverInterval(g_discoverCount);

    ++g_discoverCount;
    if (TimerSetTimeout(g_discoverTimer, discoverInterval, NSTACKX_FALSE) != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "failed to set timer for service discover");
        goto L_ERR_SERVICE_DISCOVER;
    }
    return;

L_ERR_SERVICE_DISCOVER:
    /* Abort service discover by not starting timer. */
    DFINDER_LOGE(TAG, "abort service discover, have tried %u request", g_discoverCount);
    /* Reset g_discoverCount to allow new request from user. */
    g_discoverCount = 0;
}

static void SetCoapMaxDiscoverCount(void)
{
    switch (g_coapDiscoverType) {
        case COAP_BROADCAST_TYPE_USER:
            g_coapMaxDiscoverCount = g_coapUserMaxDiscoverCount;
            break;
        case COAP_BROADCAST_TYPE_DEFAULT:
            g_coapMaxDiscoverCount = COAP_DEFAULT_DISCOVER_COUNT;
            break;
        default:
            g_coapMaxDiscoverCount = COAP_DEFAULT_DISCOVER_COUNT;
            break;
    }
}

static void CoapServiceDiscoverFirstTime(void)
{
    SetCoapMaxDiscoverCount();
    g_coapDiscoverTargetCount = g_coapMaxDiscoverCount;
    if (CoapPostServiceDiscover() != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "failed to post service discover request");
        return;
    }

    uint32_t discoverInterval = GetDiscoverInterval(g_discoverCount);
    if (TimerSetTimeout(g_discoverTimer, discoverInterval, NSTACKX_FALSE) != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "failed to set timer for service discover");
        return;
    }
    ++g_discoverCount;
    DFINDER_LOGI(TAG, "the first time for device discover.");
}

void CoapServiceDiscoverInner(uint8_t userRequest)
{
    if (!IsWifiApConnected()) {
        IncStatistics(STATS_START_SD_FAILED);
        DFINDER_LOGI(TAG, "Network not connected when discovery inner for mini");
        return;
    }

    if (userRequest) {
        DFINDER_LOGD(TAG, "user request for discovery inner");
        g_userRequest = NSTACKX_TRUE;
        g_forceUpdate = NSTACKX_TRUE;
    }

    if (g_coapDiscoverTargetCount > 0 && g_discoverCount >= g_coapDiscoverTargetCount) {
        g_discoverCount = 0;
        SetModeInfo(DISCOVER_MODE);
#ifdef DFINDER_SAVE_DEVICE_LIST
        DFINDER_LOGW(TAG, "clear device list backup for mini");
        ClearDevices(GetDeviceDBBackup());
#endif /* END OF DFINDER_SAVE_DEVICE_LIST */
        TimerSetTimeout(g_discoverTimer, 0, NSTACKX_FALSE);
    }

    if (g_discoverCount) {
        /* Service discover is ongoing, return. */
        return;
    }
#ifdef DFINDER_SAVE_DEVICE_LIST
    /* First discover */
    if (BackupDeviceDB() != NSTACKX_EOK) {
        IncStatistics(STATS_START_SD_FAILED);
        DFINDER_LOGE(TAG, "backup device list fail");
        return;
    }
    ClearDevices(GetDeviceDB());
    DFINDER_LOGW(TAG, "clear device list");
#endif /* END OF DFINDER_SAVE_DEVICE_LIST */
    SetModeInfo(DISCOVER_MODE);
    CoapServiceDiscoverFirstTime();
}

void CoapServiceDiscoverInnerAn(uint8_t userRequest)
{
    if (!IsWifiApConnected()) {
        IncStatistics(STATS_START_SD_FAILED);
        return;
    }

    if (userRequest) {
        g_userRequest = NSTACKX_TRUE;
    }

    if (g_discoverCount != 0) {
        g_discoverCount = 0;
        /* Service discover is ongoing, reset. */
        TimerSetTimeout(g_discoverTimer, 0, NSTACKX_FALSE);
    }
    CoapServiceDiscoverFirstTime();
}

void CoapServiceDiscoverInnerConfigurable(uint8_t userRequest)
{
    if (!IsWifiApConnected()) {
        IncStatistics(STATS_START_SD_FAILED);
        DFINDER_LOGI(TAG, "Network not connected when discovery inner for configurable");
        return;
    }

    if (userRequest) {
        DFINDER_LOGD(TAG, "user request for discovery configurable");
        g_userRequest = NSTACKX_TRUE;
        g_forceUpdate = NSTACKX_TRUE;
    }

    if (g_coapDiscoverTargetCount > 0 && g_discoverCount >= g_coapDiscoverTargetCount) {
        g_discoverCount = 0;
#ifdef DFINDER_SAVE_DEVICE_LIST
        ClearDevices(GetDeviceDBBackup());
        DFINDER_LOGW(TAG, "clear device list backup");
#endif /* END OF DFINDER_SAVE_DEVICE_LIST */
        TimerSetTimeout(g_discoverTimer, 0, NSTACKX_FALSE);
    }

    if (g_discoverCount != 0) {
        g_discoverCount = 0;
        /* Service discover is ongoing, return. */
        TimerSetTimeout(g_discoverTimer, 0, NSTACKX_FALSE);
    }
#ifdef DFINDER_SAVE_DEVICE_LIST
    /* First discover */
    if (BackupDeviceDB() != NSTACKX_EOK) {
        IncStatistics(STATS_START_SD_FAILED);
        DFINDER_LOGE(TAG, "backup device list fail");
        return;
    }
    ClearDevices(GetDeviceDB());
    DFINDER_LOGW(TAG, "clear device list");
#endif /* END OF DFINDER_SAVE_DEVICE_LIST */
    CoapServiceDiscoverFirstTime();
}

void CoapServiceDiscoverStopInner(void)
{
    TimerSetTimeout(g_discoverTimer, 0, NSTACKX_FALSE);
    CoapServiceDiscoverStop();
    DFINDER_LOGI(TAG, "device discover stopped");
}

uint8_t CoapDiscoverRequestOngoing(void)
{
    return (g_discoverCount > 0 && g_userRequest);
}

int32_t CoapDiscoverInit(EpollDesc epollfd)
{
    (void)epollfd;
    if (g_discoverTimer == NULL) {
        g_discoverTimer = TimerStart(epollfd, 0, NSTACKX_FALSE, CoapServiceDiscoverTimerHandle, NULL);
    }
    if (g_discoverTimer == NULL) {
        DFINDER_LOGE(TAG, "failed to start timer for service discover");
        return NSTACKX_EFAILED;
    }
    CoapSoftBusInitMsgId();
    g_userRequest = NSTACKX_FALSE;
    g_forceUpdate = NSTACKX_FALSE;
    g_discoverCount = 0;
    return NSTACKX_EOK;
}

void CoapDiscoverDeinit(void)
{
    if (g_discoverTimer != NULL) {
        TimerDelete(g_discoverTimer);
        g_discoverTimer = NULL;
    }
}

void ResetCoapDiscoverTaskCount(uint8_t isBusy)
{
    if (g_discoverTimer != NULL) {
        if (isBusy) {
            DFINDER_LOGI(TAG, "in this busy interval: g_discoverTimer task count %llu", g_discoverTimer->task.count);
        }
        g_discoverTimer->task.count = 0;
    }
}

void SetCoapDiscoverType(CoapBroadcastType type)
{
    g_coapDiscoverType = (uint32_t)type;
}

static int32_t SendDiscoveryRspEx(const NSTACKX_ResponseSettings *responseSettings)
{
    if (responseSettings == NULL) {
        return NSTACKX_EFAILED;
    }

    if (responseSettings->businessData == NULL) {
        DFINDER_LOGE(TAG, "businessData is null");
        return NSTACKX_EFAILED;
    }

    if (SetLocalDeviceBusinessDataUnicast(responseSettings->businessData,
                                          responseSettings->length) != NSTACKX_EOK) {
        return NSTACKX_EFAILED;
    }
    char remoteUrl[NSTACKX_MAX_URI_BUFFER_LENGTH] = {0};
    char host[NSTACKX_MAX_IP_STRING_LEN] = {0};
    if (strncpy_s(host, sizeof(host), responseSettings->remoteIp,
        strlen(responseSettings->remoteIp)) != EOK) {
        DFINDER_LOGE(TAG, "discoveryRsp remoteIp copy error");
        return NSTACKX_EFAILED;
    }
    if (sprintf_s(remoteUrl, sizeof(remoteUrl), "coap://%s/" COAP_DEVICE_DISCOVER_URI, host) < 0) {
        DFINDER_LOGE(TAG, "failed to get discoveryRsp remoteUrl");
        return NSTACKX_EFAILED;
    }
    CoapBuildParam param = {0};
    CreateUnicastCoapParam(remoteUrl, host, &param);
    return CoapSendMessage(&param, NSTACKX_FALSE, false);
}

void SendDiscoveryRsp(const NSTACKX_ResponseSettings *responseSettings)
{
    if (SendDiscoveryRspEx(responseSettings) != NSTACKX_EOK) {
        IncStatistics(STATS_SEND_SD_RESPONSE_FAILED);
    }
}

void SetCoapUserDiscoverInfo(uint32_t advCount, uint32_t advDuration)
{
    g_coapUserMaxDiscoverCount = advCount;
    if (advCount == 0) {
        return;
    }
    g_coapUserDiscoverInterval = advDuration / advCount;
}
