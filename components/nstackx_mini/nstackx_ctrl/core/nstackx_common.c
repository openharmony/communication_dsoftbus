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

#include "nstackx_common.h"

#include <pthread.h>
#include <securec.h>
#include <semaphore.h>
#include <unistd.h>
#include "cJSON.h"

#include "coap_discover/coap_app.h"
#include "coap_discover/coap_discover.h"
#include "nstackx.h"
#include "nstackx_device.h"
#include "nstackx_epoll.h"
#include "nstackx_error.h"
#include "nstackx_event.h"
#include "nstackx_log.h"
#include "nstackx_timer.h"
#include "nstackx_util.h"

#define TAG "nStackXDFinder"

enum {
    NSTACKX_INIT_STATE_START = 0,
    NSTACKX_INIT_STATE_ONGOING,
    NSTACKX_INIT_STATE_DONE,
};

static EpollDesc g_epollfd = INVALID_EPOLL_DESC;
static List g_eventNodeChain = {&(g_eventNodeChain), &(g_eventNodeChain)};
static pthread_t g_tid;
static uint8_t g_validTidFlag = NSTACKX_FALSE;
static uint8_t g_terminateFlag = NSTACKX_FALSE;

static NSTACKX_Parameter g_parameter;
static uint8_t g_nstackInitState;

#define EVENT_COUNT_RATE_INTERVAL 2000 /* 2 SECONDS */
#define MAX_EVENT_PROCESS_NUM_PER_INTERVAL 700
#define MAX_CONTINUOUS_BUSY_INTERVAL_NUM 20

typedef struct {
    uint32_t epollWaitTimeoutCount;
    uint32_t epollWaitEventCount;
    struct timespec measureBefore;
} EventProcessRatePara;
static EventProcessRatePara g_processRatePara;
static uint32_t g_continuousBusyIntervals;

void NotifyDFinderMsgRecver(DFinderMsgType msgType)
{
    if (g_parameter.onDFinderMsgReceived != NULL) {
        g_parameter.onDFinderMsgReceived(msgType);
    }
}

static void ResetMainEpollTaskCount(uint8_t isBusy)
{
    EpollTask *task = GetEpollTask(&g_eventNodeChain, g_epollfd);
    if (task == NULL) {
        return;
    }
    if (isBusy) {
        LOGI(TAG, "in this busy interval: main epoll task count %llu", task->count);
    }
    task->count = 0;
}

uint8_t IsBusyInterval(uint32_t eventCount, uint32_t timeMs)
{
    uint8_t retFlag;
    if ((uint64_t)eventCount * EVENT_COUNT_RATE_INTERVAL <
        MAX_EVENT_PROCESS_NUM_PER_INTERVAL * (uint64_t)timeMs) {
        retFlag = NSTACKX_FALSE;
    } else {
        retFlag = NSTACKX_TRUE;
    }

    ResetMainEpollTaskCount(retFlag);
    ResetCoapSocketTaskCount(retFlag);
    ResetCoapDiscoverTaskCount(retFlag);
    ResetDeviceTaskCount(retFlag);

    return retFlag;
}

static void CalculateEventProcessRate(void)
{
    struct timespec now;
    ClockGetTime(CLOCK_MONOTONIC, &now);
    uint32_t measureElapse = GetTimeDiffMs(&now, &g_processRatePara.measureBefore);
    if (measureElapse > EVENT_COUNT_RATE_INTERVAL) {
        uint32_t totalCount = g_processRatePara.epollWaitEventCount + g_processRatePara.epollWaitTimeoutCount;
        if (!IsBusyInterval(totalCount, measureElapse)) {
            g_continuousBusyIntervals = 0;
        } else {
            LOGI(TAG, "main loop seems to be busy in the past interval. Timeout count %u, event count %u",
                 g_processRatePara.epollWaitTimeoutCount, g_processRatePara.epollWaitEventCount);
            g_continuousBusyIntervals++;
            if (g_continuousBusyIntervals >= MAX_CONTINUOUS_BUSY_INTERVAL_NUM) {
                LOGE(TAG, "main loop seems to be busy in the past %u intervals. notify user to restart",
                     g_continuousBusyIntervals);
                NotifyDFinderMsgRecver(DFINDER_ON_TOO_BUSY);
                g_continuousBusyIntervals = 0;
            }
        }
        g_processRatePara.epollWaitTimeoutCount = 0;
        g_processRatePara.epollWaitEventCount = 0;
        ClockGetTime(CLOCK_MONOTONIC, &g_processRatePara.measureBefore);
    }
}

static void *NstackMainLoop(void *arg)
{
    int32_t ret;
    (void)arg;
    (void)memset_s(&g_processRatePara, sizeof(g_processRatePara), 0, sizeof(g_processRatePara));
    pthread_setname_np(pthread_self(), "Nstack");
    g_continuousBusyIntervals = 0;
    ClockGetTime(CLOCK_MONOTONIC, &g_processRatePara.measureBefore);
    while (g_terminateFlag == NSTACKX_FALSE) {
        ret = EpollLoop(g_epollfd, -1);
        if (ret == NSTACKX_EFAILED) {
            LOGE(TAG, "epoll loop failed");
            break;
        } else if (ret == NSTACKX_ETIMEOUT) {
            g_processRatePara.epollWaitTimeoutCount++;
        } else if (ret > 0) {
            g_processRatePara.epollWaitEventCount++;
        }
        CalculateEventProcessRate();
    }
    return NULL;
}

EpollDesc GetMainLoopEpollFd(void)
{
    return g_epollfd;
}

List *GetMainLoopEvendChain(void)
{
    return &g_eventNodeChain;
}

static int32_t InternalInit(EpollDesc epollfd)
{
    int32_t ret = EventModuleInit(&g_eventNodeChain, g_epollfd);
    if (ret != NSTACKX_EOK) {
        return ret;
    }

    ret = DeviceModuleInit(epollfd);
    if (ret != NSTACKX_EOK) {
        return ret;
    }

    ret = CoapServerInit(NULL);
    if (ret != NSTACKX_EOK) {
        return ret;
    }

    ret = CoapDiscoverInit(epollfd);
    if (ret != NSTACKX_EOK) {
        return ret;
    }

    return NSTACKX_EOK;
}

int32_t NSTACKX_Init(const NSTACKX_Parameter *parameter)
{
    int32_t ret;
    if (g_nstackInitState != NSTACKX_INIT_STATE_START) {
        return NSTACKX_EOK;
    }

    g_nstackInitState = NSTACKX_INIT_STATE_ONGOING;
    cJSON_InitHooks(NULL);
    SetLogLevel(NSTACKX_LOG_LEVEL_DEBUG);

#ifdef NSTACKX_WITH_LITEOS
    EpollEventPtrInit(); /* init g_epollEventPtrMutex g_epollEventPtrArray */
#endif

    g_epollfd = CreateEpollDesc();
    if (!IsEpollDescValid(g_epollfd)) {
        LOGE(TAG, "epoll create fail! errno: %d", errno);
        g_nstackInitState = NSTACKX_INIT_STATE_START;
        return NSTACKX_EFAILED;
    }

    LOGD(TAG, "nstack ctrl create epollfd %d", REPRESENT_EPOLL_DESC(g_epollfd));
    ret = InternalInit(g_epollfd);
    if (ret != NSTACKX_EOK) {
        goto L_ERR_INIT;
    }

    g_terminateFlag = NSTACKX_FALSE;
    g_validTidFlag = NSTACKX_FALSE;
    ret = PthreadCreate(&g_tid, NULL, NstackMainLoop, NULL);
    if (ret != 0) {
        LOGE(TAG, "thread create failed");
        goto L_ERR_INIT;
    }
    g_validTidFlag = NSTACKX_TRUE;

    (void)memset_s(&g_parameter, sizeof(g_parameter), 0, sizeof(g_parameter));
    if (parameter != NULL) {
        (void)memcpy_s(&g_parameter, sizeof(g_parameter), parameter, sizeof(NSTACKX_Parameter));
    }

    g_nstackInitState = NSTACKX_INIT_STATE_DONE;
    LOGI(TAG, "DFinder init successfully");
    return NSTACKX_EOK;

L_ERR_INIT:
    NSTACKX_Deinit();
    return ret;
}

static void ReportMainLoopStopInner(void *argument)
{
    (void)argument;
    LOGI(TAG, "receive message to stop main loop");
}

static void ReportMainLoopStop(void)
{
    if (g_nstackInitState != NSTACKX_INIT_STATE_DONE) {
        LOGE(TAG, "NSTACKX_Ctrl is not initiated yet");
        return;
    }
    if (PostEvent(&g_eventNodeChain, g_epollfd, ReportMainLoopStopInner, NULL) != NSTACKX_EOK) {
        LOGE(TAG, "Failed to start device discover!");
    }
}

void NSTACKX_Deinit(void)
{
    if (g_nstackInitState == NSTACKX_INIT_STATE_START) {
        return;
    }
    if (g_validTidFlag) {
        g_terminateFlag = NSTACKX_TRUE;
        ReportMainLoopStop();
        PthreadJoin(g_tid, NULL);
        g_validTidFlag = NSTACKX_FALSE;
    }

    CoapDiscoverDeinit();
    CoapServerDestroy();
    DeviceModuleClean();
    EventNodeChainClean(&g_eventNodeChain);
    if (IsEpollDescValid(g_epollfd)) {
        CloseEpollDesc(g_epollfd);
        g_epollfd = INVALID_EPOLL_DESC;
    }

    g_nstackInitState = NSTACKX_INIT_STATE_START;
    LOGI(TAG, "deinit successfully");
}

static void DeviceDiscoverInner(void *argument)
{
    (void)argument;
    CoapServiceDiscoverInner(INNER_DISCOVERY);

    /* If both Wifi AP and BLE are disabled, we should also notify user, with empty list. */
    if (!IsWifiApConnected()) {
        NotifyDeviceFound(NULL, 0);
    }
}

static void DeviceDiscoverInnerAn(void *argument)
{
    (void)argument;
    CoapServiceDiscoverInnerAn(INNER_DISCOVERY);
}

static void DeviceDiscoverStopInner(void *argument)
{
    (void)argument;
    CoapServiceDiscoverStopInner();
}

int32_t NSTACKX_StartDeviceFind(void)
{
    if (g_nstackInitState != NSTACKX_INIT_STATE_DONE) {
        LOGE(TAG, "NSTACKX_Ctrl is not initiated yet");
        return NSTACKX_EFAILED;
    }
    if (PostEvent(&g_eventNodeChain, g_epollfd, DeviceDiscoverInner, NULL) != NSTACKX_EOK) {
        LOGE(TAG, "Failed to start device discover!");
        return NSTACKX_EFAILED;
    }
    return NSTACKX_EOK;
}

int32_t NSTACKX_StartDeviceFindAn(uint8_t mode)
{
    if (g_nstackInitState != NSTACKX_INIT_STATE_DONE) {
        LOGE(TAG, "NSTACKX_Ctrl is not initiated yet");
        return NSTACKX_EFAILED;
    }
    SetModeInfo(mode);
    if (PostEvent(&g_eventNodeChain, g_epollfd, DeviceDiscoverInnerAn, NULL) != NSTACKX_EOK) {
        LOGE(TAG, "Failed to start device discover!");
        return NSTACKX_EFAILED;
    }
    return NSTACKX_EOK;
}

int32_t NSTACKX_StopDeviceFind(void)
{
    if (g_nstackInitState != NSTACKX_INIT_STATE_DONE) {
        LOGE(TAG, "NSTACKX_Ctrl is not initiated yet");
        return NSTACKX_EFAILED;
    }
    if (PostEvent(&g_eventNodeChain, g_epollfd, DeviceDiscoverStopInner, NULL) != NSTACKX_EOK) {
        LOGE(TAG, "Failed to stop device discover!");
        return NSTACKX_EFAILED;
    }
    return NSTACKX_EOK;
}

static void ConfigureLocalDeviceInfoInner(void *argument)
{
    NSTACKX_LocalDeviceInfo *localDeviceInfo = argument;

    ConfigureLocalDeviceInfo(localDeviceInfo);
    free(localDeviceInfo);
}

int32_t NSTACKX_RegisterDevice(const NSTACKX_LocalDeviceInfo *localDeviceInfo)
{
    NSTACKX_LocalDeviceInfo *dupLocalDeviceInfo = NULL;
    LOGE(TAG, "begin to NSTACKX_RegisterDevice!");
    if (g_nstackInitState != NSTACKX_INIT_STATE_DONE) {
        LOGE(TAG, "NSTACKX_Ctrl is not initiated yet");
        return NSTACKX_EFAILED;
    }

    if (localDeviceInfo == NULL) {
        LOGE(TAG, "Invalid local device info");
        return NSTACKX_EINVAL;
    }

    dupLocalDeviceInfo = malloc(sizeof(NSTACKX_LocalDeviceInfo));
    if (dupLocalDeviceInfo == NULL) {
        LOGE(TAG, "malloc failed");
        return NSTACKX_ENOMEM;
    }

    if (memcpy_s(dupLocalDeviceInfo, sizeof(NSTACKX_LocalDeviceInfo),
        localDeviceInfo, sizeof(NSTACKX_LocalDeviceInfo)) != EOK) {
        LOGE(TAG, "cp failed");
        free(dupLocalDeviceInfo);
        return NSTACKX_EFAILED;
    }
    if (PostEvent(&g_eventNodeChain, g_epollfd, ConfigureLocalDeviceInfoInner, dupLocalDeviceInfo) != NSTACKX_EOK) {
        LOGE(TAG, "Failed to configure local device info!");
        free(dupLocalDeviceInfo);
        return NSTACKX_EFAILED;
    }
    return NSTACKX_EOK;
}

int32_t NSTACKX_RegisterDeviceAn(const NSTACKX_LocalDeviceInfo *localDeviceInfo, uint64_t deviceHash)
{
    NSTACKX_LocalDeviceInfo *dupLocalDeviceInfo = NULL;

    if (g_nstackInitState != NSTACKX_INIT_STATE_DONE) {
        LOGE(TAG, "NSTACKX_Ctrl is not initiated yet");
        return NSTACKX_EFAILED;
    }

    if (localDeviceInfo == NULL) {
        LOGE(TAG, "Invalid local device info");
        return NSTACKX_EINVAL;
    }

    dupLocalDeviceInfo = malloc(sizeof(NSTACKX_LocalDeviceInfo));
    if (dupLocalDeviceInfo == NULL) {
        return NSTACKX_ENOMEM;
    }

    if (memcpy_s(dupLocalDeviceInfo, sizeof(NSTACKX_LocalDeviceInfo),
        localDeviceInfo, sizeof(NSTACKX_LocalDeviceInfo)) != EOK) {
        free(dupLocalDeviceInfo);
        return NSTACKX_EFAILED;
    }
    if (PostEvent(&g_eventNodeChain, g_epollfd, ConfigureLocalDeviceInfoInner, dupLocalDeviceInfo) != NSTACKX_EOK) {
        LOGE(TAG, "Failed to configure local device info!");
        free(dupLocalDeviceInfo);
        return NSTACKX_EFAILED;
    }
    SetDeviceHash(deviceHash);
    return NSTACKX_EOK;
}

typedef struct {
    uint32_t capabilityBitmapNum;
    uint32_t capabilityBitmap[NSTACKX_MAX_CAPABILITY_NUM];
} CapabilityProcessData;

static void RegisterCapabilityInner(void *argument)
{
    LOGI(TAG, "Register Capability Inner");
    CapabilityProcessData *capabilityData = argument;

    RegisterCapability(capabilityData->capabilityBitmapNum, capabilityData->capabilityBitmap);
    free(capabilityData);
}

static void SetFilterCapabilityInner(void *argument)
{
    LOGI(TAG, "Set Filter Capability Inner");
    CapabilityProcessData *capabilityData = argument;

    SetFilterCapability(capabilityData->capabilityBitmapNum, capabilityData->capabilityBitmap);
    free(capabilityData);
}

static int32_t NSTACKX_CapabilityHandle(uint32_t capabilityBitmapNum, uint32_t capabilityBitmap[], EventHandle handle)
{
    CapabilityProcessData *capabilityData = NULL;

    if (g_nstackInitState != NSTACKX_INIT_STATE_DONE) {
        LOGE(TAG, "NSTACKX_Ctrl is not initiated yet");
        return NSTACKX_EFAILED;
    }

    if (capabilityBitmapNum > NSTACKX_MAX_CAPABILITY_NUM) {
        LOGE(TAG, "capabilityBitmapNum (%u) exceed max number", capabilityBitmapNum);
        return NSTACKX_EINVAL;
    }

    capabilityData = calloc(1U, sizeof(CapabilityProcessData));
    if (capabilityData == NULL) {
        return NSTACKX_ENOMEM;
    }

    if ((capabilityBitmapNum != 0) && memcpy_s(capabilityData->capabilityBitmap,
        sizeof(capabilityData->capabilityBitmap), capabilityBitmap, capabilityBitmapNum * sizeof(uint32_t)) != EOK) {
        free(capabilityData);
        return NSTACKX_EINVAL;
    }
    capabilityData->capabilityBitmapNum = capabilityBitmapNum;

    if (PostEvent(&g_eventNodeChain, g_epollfd, handle, capabilityData) != NSTACKX_EOK) {
        LOGE(TAG, "Failed to register capability!");
        free(capabilityData);
        return NSTACKX_EFAILED;
    }
    return NSTACKX_EOK;
}

int32_t NSTACKX_RegisterCapability(uint32_t capabilityBitmapNum, uint32_t capabilityBitmap[])
{
    LOGI(TAG, "Register Capability");
    return NSTACKX_CapabilityHandle(capabilityBitmapNum, capabilityBitmap, RegisterCapabilityInner);
}

int32_t NSTACKX_SetFilterCapability(uint32_t capabilityBitmapNum, uint32_t capabilityBitmap[])
{
    LOGI(TAG, "Set Filter Capability");
    return NSTACKX_CapabilityHandle(capabilityBitmapNum, capabilityBitmap, SetFilterCapabilityInner);
}

static void RegisterServiceDataInner(void *argument)
{
    LOGI(TAG, "Register Service Data Inner");
    char *serviceData = argument;
    if (RegisterServiceData(serviceData) != NSTACKX_EOK) {
        LOGE(TAG, "RegisterServiceData failed");
    }
    free(serviceData);
}

int32_t NSTACKX_RegisterServiceData(const char *serviceData)
{
    LOGI(TAG, "Register Service Data");
    char *serviceDataTmp = NULL;

    if (serviceData == NULL) {
        LOGE(TAG, "serviceData is null");
        return NSTACKX_EINVAL;
    }
    if (g_nstackInitState != NSTACKX_INIT_STATE_DONE) {
        LOGE(TAG, "NSTACKX_Ctrl is not initiated yet");
        return NSTACKX_EFAILED;
    }
    if (strlen(serviceData) >= NSTACKX_MAX_SERVICE_DATA_LEN) {
        LOGE(TAG, "serviceData (%u) exceed max number", strlen(serviceData));
        return NSTACKX_EINVAL;
    }

    serviceDataTmp = calloc(1U, NSTACKX_MAX_SERVICE_DATA_LEN);
    if (serviceDataTmp == NULL) {
        return NSTACKX_ENOMEM;
    }
    if (strncpy_s(serviceDataTmp, NSTACKX_MAX_SERVICE_DATA_LEN, serviceData, strlen(serviceData)) != EOK) {
        LOGE(TAG, "Failed to copy serviceData");
        free(serviceDataTmp);
        return NSTACKX_EINVAL;
    }
    if (PostEvent(&g_eventNodeChain, g_epollfd, RegisterServiceDataInner, serviceDataTmp) != NSTACKX_EOK) {
        LOGE(TAG, "Failed to register serviceData!");
        free(serviceDataTmp);
        return NSTACKX_EFAILED;
    }
    return NSTACKX_EOK;
}

typedef struct {
    NSTACKX_DeviceInfo *deviceList;
    uint32_t *deviceCountPtr;
    sem_t wait;
} GetDeviceListMessage;

static void GetDeviceListInner(void *argument)
{
    GetDeviceListMessage *message = argument;

    GetDeviceList(message->deviceList, message->deviceCountPtr, true);
    SemPost(&message->wait);
}

int32_t NSTACKX_GetDeviceList(NSTACKX_DeviceInfo *deviceList, uint32_t *deviceCountPtr)
{
    GetDeviceListMessage message = {
        .deviceList = deviceList,
        .deviceCountPtr = deviceCountPtr,
    };

    if (g_nstackInitState != NSTACKX_INIT_STATE_DONE) {
        LOGE(TAG, "NSTACKX_Ctrl is not initiated yet");
        return NSTACKX_EFAILED;
    }

    if (deviceList == NULL || deviceCountPtr == NULL) {
        LOGE(TAG, "Device list or count pointer is NULL");
        return NSTACKX_EINVAL;
    }

    if (SemInit(&message.wait, 0, 0)) {
        return NSTACKX_EFAILED;
    }

    if (PostEvent(&g_eventNodeChain, g_epollfd, GetDeviceListInner, &message) != NSTACKX_EOK) {
        LOGE(TAG, "Failed to get device list");
        SemDestroy(&message.wait);
        return NSTACKX_EFAILED;
    }

    SemWait(&message.wait);
    SemDestroy(&message.wait);
    return NSTACKX_EOK;
}

void NotifyDeviceListChanged(const NSTACKX_DeviceInfo *deviceList, uint32_t deviceCount)
{
    if (g_parameter.onDeviceListChanged != NULL) {
        LOGI(TAG, "notify callback: device list changed");
        g_parameter.onDeviceListChanged(deviceList, deviceCount);
        LOGI(TAG, "finish to notify device list changed");
    } else {
        LOGI(TAG, "notify callback: device list changed callback is null");
    }
}

void NotifyDeviceFound(const NSTACKX_DeviceInfo *deviceList, uint32_t deviceCount)
{
    if (g_parameter.onDeviceFound != NULL) {
        LOGI(TAG, "notify callback: device found");
        g_parameter.onDeviceFound(deviceList, deviceCount);
        LOGI(TAG, "finish to notify device found");
    } else {
        LOGI(TAG, "notify callback: device found callback is null");
    }
}
