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
#include "nstackx_log.h"
#include "nstackx_timer.h"
#include "nstackx_error.h"
#include "nstackx_device.h"
#include "securec.h"

#define TAG "nStackXCoAP"

#define COAP_URI_BUFFER_LENGTH 64 /* the size of the buffer or variable used to save uri. */
#define COAP_MAX_NUM_SUBSCRIBE_MODULE_COUNT 32 /* the maximum count of subscribed module */

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
#define COAP_RECV_COUNT_INTERVAL 1000
#define COAP_DISVOCER_MAX_RATE 200

static Timer *g_discoverTimer = NULL;
static uint32_t g_discoverCount;
static uint32_t g_coapMaxDiscoverCount = COAP_DEFAULT_DISCOVER_COUNT;
static uint32_t g_coapDiscoverTargetCount;
static uint8_t g_userRequest;
static uint8_t g_forceUpdate;
static Timer *g_recvRecountTimer = NULL;
static uint32_t g_recvDiscoverMsgNum;

static int32_t GetServiceDiscoverInfo(const uint8_t *buf, size_t size, DeviceInfo *deviceInfo, char **remoteUrlPtr)
{
    uint8_t *newBuf = NULL;
    if (size <= 0) {
        return NSTACKX_EFAILED;
    }
    if (buf[size - 1] != '\0') {
        newBuf = (uint8_t *)calloc(size + 1, 1U);
        if (newBuf == NULL) {
            LOGE(TAG, "data is not end with 0 and new buf calloc error");
            return NSTACKX_ENOMEM;
        }
        if (memcpy_s(newBuf, size + 1, buf, size) != EOK) {
            LOGE(TAG, "data is not end with 0 and memcpy data error");
            goto L_COAP_ERR;
        }
        LOGI(TAG, "data is not end with 0");
        buf = newBuf;
    }
    if (ParseServiceDiscover(buf, deviceInfo, remoteUrlPtr) != NSTACKX_EOK) {
        LOGE(TAG, "parse service discover error");
        goto L_COAP_ERR;
    }

    if (newBuf != NULL) {
        free(newBuf);
    }

    return NSTACKX_EOK;
L_COAP_ERR:
    if (newBuf != NULL) {
        free(newBuf);
    }
    return NSTACKX_EFAILED;
}

static void IncreaseRecvDiscoverNum(void)
{
    if (g_recvDiscoverMsgNum < UINT32_MAX) {
        g_recvDiscoverMsgNum++;
    }
}

static int32_t HndPostServiceDiscoverInner(const uint8_t *buf, size_t size, char **remoteUrl, DeviceInfo *deviceInfo)
{
    IncreaseRecvDiscoverNum();
    if (g_recvDiscoverMsgNum > COAP_DISVOCER_MAX_RATE) {
        return NSTACKX_EFAILED;
    }

    (void)memset_s(deviceInfo, sizeof(*deviceInfo), 0, sizeof(*deviceInfo));
    if (GetServiceDiscoverInfo(buf, size, deviceInfo, remoteUrl) != NSTACKX_EOK) {
        return NSTACKX_EFAILED;
    }
    if (deviceInfo->mode == PUBLISH_MODE_UPLINE || deviceInfo->mode == PUBLISH_MODE_OFFLINE) {
        LOGD(TAG, "peer is not DISCOVER_MODE");
        size_t deviceListLen = sizeof(NSTACKX_DeviceInfo) * PUBLISH_DEVICE_NUM;
        NSTACKX_DeviceInfo *deviceList = (NSTACKX_DeviceInfo *)malloc(deviceListLen);
        if (deviceList == NULL) {
            LOGE(TAG, "malloc device list failed");
            return NSTACKX_ENOMEM;
        }
        (void)memset_s(deviceList, deviceListLen, 0, deviceListLen);
        PushPublishInfo(deviceInfo, deviceList, PUBLISH_DEVICE_NUM);
        NotifyDeviceFound(deviceList, PUBLISH_DEVICE_NUM);
        return NSTACKX_EFAILED;
    }
    return NSTACKX_EOK;
}

void HndPostServiceDiscover(const CoapPacket *pkt)
{
    if (pkt == NULL) {
        return;
    }
    char *remoteUrl = NULL;
    DeviceInfo *deviceInfo = (DeviceInfo *)malloc(sizeof(DeviceInfo));
    if (deviceInfo == NULL) {
        LOGE(TAG, "malloc device info failed");
        return;
    }
    (void)memset_s(deviceInfo, sizeof(DeviceInfo), 0, sizeof(DeviceInfo));
    if (HndPostServiceDiscoverInner(pkt->payload.buffer, pkt->payload.len, &remoteUrl, deviceInfo) != NSTACKX_EOK) {
        free(remoteUrl);
        free(deviceInfo);
        return;
    }
    if (GetModeInfo() == PUBLISH_MODE_UPLINE || GetModeInfo() == PUBLISH_MODE_OFFLINE) {
        LOGD(TAG, "local is not DISCOVER_MODE");
        free(remoteUrl);
        free(deviceInfo);
        return;
    }
    if (UpdateDeviceDb(deviceInfo, g_forceUpdate) != NSTACKX_EOK) {
        free(remoteUrl);
        free(deviceInfo);
        return;
    }
    if (g_forceUpdate) {
        g_forceUpdate = NSTACKX_FALSE;
    }
    if (deviceInfo->mode == PUBLISH_MODE_PROACTIVE) {
        LOGD(TAG, "peer is PUBLISH_MODE_PROACTIVE");
        free(remoteUrl);
        free(deviceInfo);
        return;
    }
    if (remoteUrl != NULL) {
        char wifiIpAddr[NSTACKX_MAX_IP_STRING_LEN];
        (void)memset_s(wifiIpAddr, sizeof(wifiIpAddr), 0, sizeof(wifiIpAddr));
        (void)inet_ntop(AF_INET, &(deviceInfo->netChannelInfo.wifiApInfo.ip), wifiIpAddr, sizeof(wifiIpAddr));
        CoapResponseService(pkt, remoteUrl, wifiIpAddr);
        free(remoteUrl);
    }
    free(deviceInfo);
}

static uint32_t GetDiscoverInterval(uint32_t discoverCount)
{
    if (discoverCount < COAP_FIRST_DISCOVER_COUNT_RANGE) {
        return COAP_FIRST_DISCOVER_INTERVAL;
    } else if (discoverCount < COAP_SECOND_DISCOVER_COUNT_RANGE) {
        return COAP_SECOND_DISCOVER_INTERVAL;
    }
    return COAP_LAST_DISCOVER_INTERVAL;
}

static void CoapServiceDiscoverStop(void)
{
    g_discoverCount = 0;
    g_forceUpdate = NSTACKX_FALSE;
    SetModeInfo(DISCOVER_MODE);
    ClearDevices(GetDeviceDBBackup());
    LOGW(TAG, "clear device list backup");
    /* Can call PostDeviceFindWrapper() to notify user if needed. */
    g_userRequest = NSTACKX_FALSE;
}

static int32_t CoapSendRequest(void)
{
    LOGI(TAG, "not support active discovery in mini system.");
    return NSTACKX_EOK;
}

static int32_t CoapPostServiceDiscover(void)
{
    char ifName[NSTACKX_MAX_INTERFACE_NAME_LEN] = {0};
    char ipString[NSTACKX_MAX_IP_STRING_LEN] = {0};
    char discoverUri[COAP_URI_BUFFER_LENGTH] = {0};
    char *data = NULL;

    if (GetLocalInterfaceName(ifName, sizeof(ifName)) != NSTACKX_EOK) {
        return NSTACKX_EFAILED;
    }

    if (GetIfBroadcastIp(ifName, ipString, sizeof(ipString)) != NSTACKX_EOK) {
        return NSTACKX_EFAILED;
    }

    if (sprintf_s(discoverUri, sizeof(discoverUri), "coap://%s/%s", ipString, COAP_DEVICE_DISCOVER_URI) < 0) {
        return NSTACKX_EFAILED;
    }
    data = PrepareServiceDiscover(NSTACKX_TRUE);
    if (data == NULL) {
        LOGE(TAG, "failed to prepare coap data");
        return NSTACKX_EFAILED;
    }

    return CoapSendRequest();
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
        LOGE(TAG, "failed to post service discover request");
        goto L_ERR_SERVICE_DISCOVER;
    }
    LOGI(TAG, "the %d times for device discover.", g_discoverCount + 1);

    /* Restart timer */
    discoverInterval = GetDiscoverInterval(g_discoverCount);

    ++g_discoverCount;
    if (TimerSetTimeout(g_discoverTimer, discoverInterval, NSTACKX_FALSE) != NSTACKX_EOK) {
        LOGE(TAG, "failed to set timer for service discover");
        goto L_ERR_SERVICE_DISCOVER;
    }
    return;

L_ERR_SERVICE_DISCOVER:
    /* Abort service discover by not starting timer. */
    LOGE(TAG, "abort service discover, have tried %u request", g_discoverCount);
    /* Reset g_discoverCount to allow new request from user. */
    g_discoverCount = 0;
    return;
}

void CoapServiceDiscoverInner(uint8_t userRequest)
{
    uint32_t discoverInterval;
    if (!IsWifiApConnected()) {
        return;
    }

    if (userRequest) {
        g_userRequest = NSTACKX_TRUE;
        g_forceUpdate = NSTACKX_TRUE;
    }

    if (g_coapDiscoverTargetCount > 0 && g_discoverCount >= g_coapDiscoverTargetCount) {
        g_discoverCount = 0;
        SetModeInfo(DISCOVER_MODE);
        ClearDevices(GetDeviceDBBackup());
        LOGW(TAG, "clear device list backup");
        TimerSetTimeout(g_discoverTimer, 0, NSTACKX_FALSE);
    }

    if (g_discoverCount) {
        /* Service discover is ongoing, return. */
        return;
    } else {
        /* First discover */
        if (BackupDeviceDB() != NSTACKX_EOK) {
            LOGE(TAG, "backup device list fail");
            return;
        }
        ClearDevices(GetDeviceDB());
        LOGW(TAG, "clear device list");
        g_coapDiscoverTargetCount = g_coapMaxDiscoverCount;
    }
    SetModeInfo(DISCOVER_MODE);
    if (CoapPostServiceDiscover() != NSTACKX_EOK) {
        LOGE(TAG, "failed to post service discover request");
        return;
    }

    discoverInterval = GetDiscoverInterval(g_discoverCount);
    if (TimerSetTimeout(g_discoverTimer, discoverInterval, NSTACKX_FALSE) != NSTACKX_EOK) {
        LOGE(TAG, "failed to set timer for service discover");
        return;
    }
    ++g_discoverCount;
    LOGI(TAG, "the first time for device discover.");

    return;
}

void CoapServiceDiscoverInnerAn(uint8_t userRequest)
{
    if (!IsWifiApConnected()) {
        return;
    }

    if (userRequest) {
        g_userRequest = NSTACKX_TRUE;
    }

    if (g_discoverCount) {
        g_discoverCount = 0;
        /* Service discover is ongoing, reset. */
        TimerSetTimeout(g_discoverTimer, 0, NSTACKX_FALSE);
    } else {
        g_coapDiscoverTargetCount = g_coapMaxDiscoverCount;
    }

    if (CoapPostServiceDiscover() != NSTACKX_EOK) {
        LOGE(TAG, "failed to post service discover request");
        return;
    }

    uint32_t discoverInterval = GetDiscoverInterval(g_discoverCount);
    if (TimerSetTimeout(g_discoverTimer, discoverInterval, NSTACKX_FALSE) != NSTACKX_EOK) {
        LOGE(TAG, "failed to set timer for service discover");
        return;
    }
    ++g_discoverCount;
    LOGI(TAG, "the first time for device discover.");

    return;
}

void CoapServiceDiscoverStopInner(void)
{
    TimerSetTimeout(g_discoverTimer, 0, NSTACKX_FALSE);
    CoapServiceDiscoverStop();
    LOGI(TAG, "device discover stopped");
}

uint8_t CoapDiscoverRequestOngoing(void)
{
    return (g_discoverCount > 0 && g_userRequest);
}

static void CoapRecvRecountTimerHandle(void *argument)
{
    (void)argument;
    if (g_recvDiscoverMsgNum > COAP_DISVOCER_MAX_RATE) {
        LOGI(TAG, "received %u discover msg in this interval", g_recvDiscoverMsgNum);
    }
    g_recvDiscoverMsgNum = 0;
    return;
}

int32_t CoapDiscoverInit(EpollDesc epollfd)
{
    (void)epollfd;
    CoapSoftBusInitMsgId();
    g_userRequest = NSTACKX_FALSE;
    g_forceUpdate = NSTACKX_FALSE;
    g_recvDiscoverMsgNum = 0;
    g_discoverCount = 0;
    return NSTACKX_EOK;
}

void CoapDiscoverDeinit(void)
{
    if (g_discoverTimer != NULL) {
        TimerDelete(g_discoverTimer);
        g_discoverTimer = NULL;
    }
    if (g_recvRecountTimer != NULL) {
        TimerDelete(g_recvRecountTimer);
        g_recvRecountTimer = NULL;
    }
}

void ResetCoapDiscoverTaskCount(uint8_t isBusy)
{
    if (g_discoverTimer != NULL) {
        if (isBusy) {
            LOGI(TAG, "in this busy interval: g_discoverTimer task count %llu", g_discoverTimer->task.count);
        }
        g_discoverTimer->task.count = 0;
    }
    if (g_recvRecountTimer != NULL) {
        if (isBusy) {
            LOGI(TAG, "in this busy interval: g_recvRecountTimer task count %llu", g_recvRecountTimer->task.count);
        }
        g_recvRecountTimer->task.count = 0;
    }
}
