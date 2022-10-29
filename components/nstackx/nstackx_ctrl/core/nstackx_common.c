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

#include <securec.h>
#ifndef _WIN32
#include <pthread.h>
#include <semaphore.h>
#include <unistd.h>
#endif
#include "cJSON.h"

#include "coap_app.h"
#include "coap_discover.h"
#include "nstackx.h"
#include "nstackx_device.h"
#include "nstackx_epoll.h"
#include "nstackx_error.h"
#include "nstackx_event.h"
#include "nstackx_dfinder_log.h"
#include "nstackx_smartgenius.h"
#include "nstackx_timer.h"
#include "nstackx_util.h"
#include "json_payload.h"
#include "nstackx_statistics.h"
#include "nstackx_dfinder_hidump.h"
#include "nstackx_dfinder_hievent.h"

#ifdef DFINDER_USE_MINI_NSTACKX
#include "cmsis_os2.h"
#include "ohos_init.h"
#define DFINDER_THREAD_STACK_SIZE (1024 * 32)
#endif

#define TAG "nStackXDFinder"
#define DFINDER_THREAD_NAME TAG

enum {
    NSTACKX_INIT_STATE_START = 0,
    NSTACKX_INIT_STATE_ONGOING,
    NSTACKX_INIT_STATE_DONE,
};

#ifdef DFINDER_USE_MINI_NSTACKX
static osThreadId_t g_threadId;
#else
static pthread_t g_tid;
#endif

static EpollDesc g_epollfd = INVALID_EPOLL_DESC;
static List g_eventNodeChain = {&(g_eventNodeChain), &(g_eventNodeChain)};

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

static int32_t CheckDiscoverySettings(const NSTACKX_DiscoverySettings *discoverySettings);

List *GetEventNodeChain(void)
{
    return &g_eventNodeChain;
}

EpollDesc GetEpollFD(void)
{
    return g_epollfd;
}

void NotifyDFinderMsgRecver(DFinderMsgType msgType)
{
    if (g_parameter.onDFinderMsgReceived != NULL) {
        g_parameter.onDFinderMsgReceived(msgType);
    }
}

/* check if we need to reply a unicast based on businessType. */
int32_t CheckBusinessTypeReplyUnicast(uint8_t businessType)
{
    switch (businessType) {
        case NSTACKX_BUSINESS_TYPE_NULL:
            return NSTACKX_EOK;

        case NSTACKX_BUSINESS_TYPE_HICOM:
            return NSTACKX_EOK;

        case NSTACKX_BUSINESS_TYPE_SOFTBUS:
            return NSTACKX_EFAILED;

        case NSTACKX_BUSINESS_TYPE_NEARBY:
            return NSTACKX_EOK;

        default: /* Unknown businessType */
            return NSTACKX_EOK;
    }
}

uint32_t GetDefaultDiscoverInterval(uint32_t discoverCount)
{
    if (discoverCount < COAP_FIRST_DISCOVER_COUNT_RANGE) {
        return COAP_FIRST_DISCOVER_INTERVAL;
    } else if (discoverCount < COAP_SECOND_DISCOVER_COUNT_RANGE) {
        return COAP_SECOND_DISCOVER_INTERVAL;
    } else {
        return COAP_LAST_DISCOVER_INTERVAL;
    }
}

int32_t GetServiceDiscoverInfo(const uint8_t *buf, size_t size, DeviceInfo *deviceInfo, char **remoteUrlPtr)
{
    uint8_t *newBuf = NULL;
    if (size <= 0) {
        return NSTACKX_EFAILED;
    }
    if (buf[size - 1] != '\0') {
        newBuf = (uint8_t *)calloc(size + 1, 1U);
        if (newBuf == NULL) {
            DFINDER_LOGE(TAG, "data is not end with 0 and new buf calloc error");
            return NSTACKX_ENOMEM;
        }
        if (memcpy_s(newBuf, size + 1, buf, size) != EOK) {
            DFINDER_LOGE(TAG, "data is not end with 0 and memcpy data error");
            goto L_COAP_ERR;
        }
        DFINDER_LOGI(TAG, "data is not end with 0");
        buf = newBuf;
    }
    if (ParseServiceDiscover(buf, deviceInfo, remoteUrlPtr) != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "parse service discover error");
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

static void ResetMainEpollTaskCount(uint8_t isBusy)
{
    EpollTask *task = GetEpollTask(&g_eventNodeChain, g_epollfd);
    if (task == NULL) {
        return;
    }
    if (isBusy) {
        DFINDER_LOGI(TAG, "in this busy interval: main epoll task count %llu", task->count);
    }
    task->count = 0;
}

static uint8_t IsBusyInterval(uint32_t eventCount, uint32_t timeMs)
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
#ifndef DFINDER_USE_MINI_NSTACKX
    ResetSmartGeniusTaskCount(retFlag);
#endif /* END OF DFINDER_USE_MINI_NSTACKX */

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
            DFINDER_LOGI(TAG, "main loop seems to be busy in the past interval. Timeout count %u, event count %u",
                         g_processRatePara.epollWaitTimeoutCount, g_processRatePara.epollWaitEventCount);
            g_continuousBusyIntervals++;
            if (g_continuousBusyIntervals >= MAX_CONTINUOUS_BUSY_INTERVAL_NUM) {
                DFINDER_LOGE(TAG, "main loop seems to be busy in the past %u intervals. notify user to restart",
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
    g_continuousBusyIntervals = 0;
    ClockGetTime(CLOCK_MONOTONIC, &g_processRatePara.measureBefore);
#ifndef DFINDER_USE_MINI_NSTACKX
    SetThreadName(DFINDER_THREAD_NAME);
#endif
    while (g_terminateFlag == NSTACKX_FALSE) {
#ifndef DFINDER_USE_MINI_NSTACKX
        uint32_t timeout = RegisterCoAPEpollTask(g_epollfd);
        ret = EpollLoop(g_epollfd, timeout);
#else
        ret = EpollLoop(g_epollfd, -1);
#endif /* END OF DFINDER_USE_MINI_NSTACKX */
        if (ret == NSTACKX_EFAILED) {
            IncStatistics(STATS_EPOLL_ERROR);
            DFINDER_LOGE(TAG, "epoll loop failed");
#ifndef DFINDER_USE_MINI_NSTACKX
            DeRegisterCoAPEpollTask();
#endif /* END OF DFINDER_USE_MINI_NSTACKX */
            break;
        } else if (ret == NSTACKX_ETIMEOUT) {
            g_processRatePara.epollWaitTimeoutCount++;
        } else if (ret > 0) {
            g_processRatePara.epollWaitEventCount++;
        } else {
            /* do nothing */
        }
        CalculateEventProcessRate();
#ifndef DFINDER_USE_MINI_NSTACKX
        DeRegisterCoAPEpollTask();
#endif /* END OF DFINDER_USE_MINI_NSTACKX */
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

static int32_t InternalInit(EpollDesc epollfd, uint32_t maxDeviceNum)
{
    int32_t ret = EventModuleInit(&g_eventNodeChain, g_epollfd);
    if (ret != NSTACKX_EOK) {
        return ret;
    }

    ret = DeviceModuleInit(epollfd, maxDeviceNum);
    if (ret != NSTACKX_EOK) {
        return ret;
    }

#if !defined(DFINDER_SUPPORT_MULTI_NIF) && !defined(DFINDER_USE_MINI_NSTACKX)
    ret = P2pUsbTimerInit(epollfd);
    if (ret != NSTACKX_EOK) {
        return ret;
    }
#endif

#ifdef _WIN32
    ret = CoapThreadInit();
    if (ret != NSTACKX_EOK) {
        return ret;
    }
#endif

#ifndef DFINDER_SUPPORT_MULTI_NIF
    ret = CoapServerInit(NULL);
    if (ret != NSTACKX_EOK) {
        return ret;
    }
#endif

    ret = CoapDiscoverInit(epollfd);
    if (ret != NSTACKX_EOK) {
        return ret;
    }

#ifndef DFINDER_USE_MINI_NSTACKX
    ret = SmartGeniusInit(epollfd);
#endif /* END OF DFINDER_USE_MINI_NSTACKX */
    return ret;
}

static int32_t NstackxInitInner(uint32_t maxDeviceNum)
{
    int32_t ret;
#ifdef DFINDER_USE_MINI_NSTACKX
    ret = InternalInit(g_epollfd, maxDeviceNum);
    if (ret != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "internal init failed");
        return ret;
    }
#endif
    g_terminateFlag = NSTACKX_FALSE;
    g_validTidFlag = NSTACKX_FALSE;
#ifndef DFINDER_USE_MINI_NSTACKX
    ret = PthreadCreate(&g_tid, NULL, NstackMainLoop, NULL);
    if (ret != 0) {
        DFINDER_LOGE(TAG, "thread create failed");
        return ret;
    }
#else
    osThreadAttr_t attr = {0};
    attr.name = DFINDER_THREAD_NAME;
    attr.stack_size = DFINDER_THREAD_STACK_SIZE;
    // osPriorityNormal equals 24
    attr.priority = osPriorityNormal;
    g_threadId = osThreadNew((osThreadFunc_t)NstackMainLoop, NULL, &attr);
    if (g_threadId == NULL) {
        DFINDER_LOGE(TAG, "thread create failed with attribute settings");
        return NSTACKX_EFAILED;
    }
#endif
    g_validTidFlag = NSTACKX_TRUE;
#ifndef DFINDER_USE_MINI_NSTACKX
    ret = InternalInit(g_epollfd, maxDeviceNum);
    if (ret != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "internal init failed");
        return ret;
    }
#endif
    return ret;
}

int32_t NSTACKX_Init(const NSTACKX_Parameter *parameter)
{
    int32_t ret;

    if (g_nstackInitState != NSTACKX_INIT_STATE_START) {
        return NSTACKX_EOK;
    }

    g_nstackInitState = NSTACKX_INIT_STATE_ONGOING;
    cJSON_InitHooks(NULL);
#ifdef ENABLE_USER_LOG
    SetDFinderLogLevel(DFINDER_LOG_LEVEL_DEBUG);
#endif
    SetLogLevel(NSTACKX_LOG_LEVEL_DEBUG);

#ifdef NSTACKX_WITH_LITEOS
    EpollEventPtrInit(); /* init g_epollEventPtrMutex g_epollEventPtrArray */
#endif

    g_epollfd = CreateEpollDesc();
    if (!IsEpollDescValid(g_epollfd)) {
        DFINDER_LOGE(TAG, "epoll creat fail! errno: %d", errno);
        g_nstackInitState = NSTACKX_INIT_STATE_START;
        return NSTACKX_EFAILED;
    }

    DFINDER_LOGD(TAG, "nstack ctrl creat epollfd %d", REPRESENT_EPOLL_DESC(g_epollfd));
#ifdef DFINDER_SAVE_DEVICE_LIST
    ret = NstackxInitInner(parameter != NULL ? parameter->maxDeviceNum : NSTACKX_DEFAULT_DEVICE_NUM);
#else
    ret = NstackxInitInner(parameter != NULL ? parameter->maxDeviceNum : NSTACKX_MAX_DEVICE_NUM);
#endif
    if (ret != NSTACKX_EOK) {
        goto L_ERR_INIT;
    }
    (void)memset_s(&g_parameter, sizeof(g_parameter), 0, sizeof(g_parameter));
    if (parameter != NULL) {
        (void)memcpy_s(&g_parameter, sizeof(g_parameter), parameter, sizeof(NSTACKX_Parameter));
    }

#ifndef DFINDER_USE_MINI_NSTACKX
    CoapInitSubscribeModuleInner(); /* initialize subscribe module number */
#endif /* END OF DFINDER_USE_MINI_NSTACKX */

    g_nstackInitState = NSTACKX_INIT_STATE_DONE;
    DFINDER_LOGI(TAG, "DFinder init successfully");
    return NSTACKX_EOK;

L_ERR_INIT:
    NSTACKX_Deinit();
    return ret;
}

#ifdef DFINDER_USE_MINI_NSTACKX
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
        LOGE(TAG, "Failed to report mainloop stop!");
    }
}
#endif

void NSTACKX_Deinit(void)
{
    if (g_nstackInitState == NSTACKX_INIT_STATE_START) {
        return;
    }
    if (g_validTidFlag) {
        g_terminateFlag = NSTACKX_TRUE;
#ifndef DFINDER_USE_MINI_NSTACKX
        PthreadJoin(g_tid, NULL);
#else
        ReportMainLoopStop();
        if (osThreadTerminate(g_threadId) != osOK) {
            LOGE(TAG, "os thread terminate failed");
        }
#endif
        g_validTidFlag = NSTACKX_FALSE;
    }
#ifndef DFINDER_USE_MINI_NSTACKX
    SmartGeniusClean();
#endif /* END OF DFINDER_USE_MINI_NSTACKX */
    CoapDiscoverDeinit();
#ifdef DFINDER_SUPPORT_MULTI_NIF
    for (uint32_t i = 0; i < NSTACKX_MAX_LISTENED_NIF_NUM; ++i) {
        DFINDER_LOGE(TAG, "nstackx_deinit nif with idx-%u", i);
        CoapServerDestroyWithIdx(i);
    }
#else
#ifndef DFINDER_USE_MINI_NSTACKX
    DestroyP2pUsbServerInitRetryTimer();
#endif /* END OF DFINDER_USE_MINI_NSTACKX */
    CoapServerDestroy();
#ifndef DFINDER_USE_MINI_NSTACKX
    CoapP2pServerDestroy();
    CoapUsbServerDestroy();
#endif /* END OF DFINDER_USE_MINI_NSTACKX */
#endif /* END OF DFINDER_SUPPORT_MULTI_NIF */
#ifdef _WIN32
    CoapThreadDestory();
#endif
    DeviceModuleClean();
    EventNodeChainClean(&g_eventNodeChain);
    if (IsEpollDescValid(g_epollfd)) {
        CloseEpollDesc(g_epollfd);
        g_epollfd = INVALID_EPOLL_DESC;
    }
    ResetStatistics();
    ResetEventFunc();
    g_nstackInitState = NSTACKX_INIT_STATE_START;
    DFINDER_LOGI(TAG, "deinit successfully");
}

static void DeviceDiscoverInner(void *argument)
{
    (void)argument;
    CoapServiceDiscoverInner(INNER_DISCOVERY);

#ifdef DFINDER_SUPPORT_MULTI_NIF
    if (!IsApConnected()) {
        DFINDER_LOGE(TAG, "all ap not connected, notify user with empty list");
        NotifyDeviceFound(NULL, 0);
    }
#else
    /* If both Wifi AP and BLE are disabled, we should also notify user, with empty list. */
    if (!IsWifiApConnected()) {
        NotifyDeviceFound(NULL, 0);
    }
#endif
}

static void DeviceDiscoverInnerAn(void *argument)
{
    (void)argument;
    CoapServiceDiscoverInnerAn(INNER_DISCOVERY);
}

static void DeviceDiscoverInnerConfigurable(void *argument)
{
    NSTACKX_DiscoverySettings *discoverySettings = argument;
    if (discoverySettings->businessType != GetLocalDeviceInfoPtr()->businessType) {
        DFINDER_LOGE(TAG, "businessType is diff when check discover settings");
        free(discoverySettings->businessData);
        free(discoverySettings);
        return;
    }
    ConfigureDiscoverySettings(discoverySettings);
    free(discoverySettings->businessData);
    free(discoverySettings);
    CoapServiceDiscoverInnerConfigurable(INNER_DISCOVERY);
}

static void DeviceDiscoverStopInner(void *argument)
{
    (void)argument;
    CoapServiceDiscoverStopInner();
    NotifyStatisticsEvent();
}

int32_t NSTACKX_StartDeviceFind(void)
{
    if (g_nstackInitState != NSTACKX_INIT_STATE_DONE) {
        DFINDER_LOGE(TAG, "NSTACKX_Ctrl is not initiated yet");
        return NSTACKX_EFAILED;
    }
    if (PostEvent(&g_eventNodeChain, g_epollfd, DeviceDiscoverInner, NULL) != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "Failed to start device discover!");
        return NSTACKX_EFAILED;
    }
    return NSTACKX_EOK;
}

int32_t NSTACKX_StartDeviceFindAn(uint8_t mode)
{
    if (g_nstackInitState != NSTACKX_INIT_STATE_DONE) {
        DFINDER_LOGE(TAG, "NSTACKX_Ctrl is not initiated yet");
        return NSTACKX_EFAILED;
    }
    SetModeInfo(mode);
    if (PostEvent(&g_eventNodeChain, g_epollfd, DeviceDiscoverInnerAn, NULL) != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "Failed to start device discover!");
        return NSTACKX_EFAILED;
    }
    return NSTACKX_EOK;
}

int32_t NSTACKX_StopDeviceFind(void)
{
    if (g_nstackInitState != NSTACKX_INIT_STATE_DONE) {
        DFINDER_LOGE(TAG, "NSTACKX_Ctrl is not initiated yet");
        return NSTACKX_EFAILED;
    }
    if (PostEvent(&g_eventNodeChain, g_epollfd, DeviceDiscoverStopInner, NULL) != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "Failed to stop device discover!");
        return NSTACKX_EFAILED;
    }
    return NSTACKX_EOK;
}

static int32_t CopyDiscoverySettings(NSTACKX_DiscoverySettings *dupDiscoverySettings,
                                     const NSTACKX_DiscoverySettings *discoverySettings)
{
    dupDiscoverySettings->businessType = discoverySettings->businessType;
    dupDiscoverySettings->discoveryMode = discoverySettings->discoveryMode;
    dupDiscoverySettings->length = discoverySettings->length;
    if (discoverySettings->businessData != NULL) {
        if (strncpy_s(dupDiscoverySettings->businessData, (dupDiscoverySettings->length + 1),
            discoverySettings->businessData, discoverySettings->length) != EOK) {
            DFINDER_LOGE(TAG, "businessData strncpy failed");
            return NSTACKX_EINVAL;
        }
    }
    dupDiscoverySettings->advertiseCount = discoverySettings->advertiseCount;
    dupDiscoverySettings->advertiseDuration = discoverySettings->advertiseDuration;
    return NSTACKX_EOK;
}

static int32_t CheckDiscoverySettings(const NSTACKX_DiscoverySettings *discoverySettings)
{
    if (discoverySettings == NULL) {
        DFINDER_LOGE(TAG, "Invalid discoverySettings info");
        return NSTACKX_EINVAL;
    }
    if ((discoverySettings->businessData == NULL) && (discoverySettings->length != 0)) {
        DFINDER_LOGE(TAG, "Invalid discoverySettings bData info");
        return NSTACKX_EINVAL;
    }
    if (discoverySettings->length >= NSTACKX_MAX_BUSINESS_DATA_LEN) {
        DFINDER_LOGE(TAG, "businessData length is too long");
        return NSTACKX_EINVAL;
    }
    uint32_t advertiseCount = discoverySettings->advertiseCount;
    uint32_t advertiseDuration = discoverySettings->advertiseDuration;
    if ((advertiseCount == 0) && (advertiseDuration == 0)) {
        return NSTACKX_EOK;
    }
    if ((advertiseCount < NSTACKX_MIN_ADVERTISE_COUNT) || (advertiseCount > NSTACKX_MAX_ADVERTISE_COUNT) ||
        (advertiseDuration < NSTACKX_MIN_ADVERTISE_DURATION) || (advertiseDuration > NSTACKX_MAX_ADVERTISE_DURATION)) {
        DFINDER_LOGE(TAG, "Invalid discoverySettings advertise info");
        return NSTACKX_EINVAL;
    }
    return NSTACKX_EOK;
}

int32_t NSTACKX_StartDeviceDiscovery(const NSTACKX_DiscoverySettings *discoverySettings)
{
    DFINDER_LOGI(TAG, "begin to NSTACKX_StartDeviceDiscovery!");
    if (g_nstackInitState != NSTACKX_INIT_STATE_DONE) {
        DFINDER_LOGE(TAG, "NSTACKX_Ctrl is not initiated yet");
        return NSTACKX_EFAILED;
    }
    if (CheckDiscoverySettings(discoverySettings) != NSTACKX_EOK) {
        return NSTACKX_EINVAL;
    }

    NSTACKX_DiscoverySettings *dupDiscoverySettings = malloc(sizeof(NSTACKX_DiscoverySettings));
    if (dupDiscoverySettings == NULL) {
        DFINDER_LOGE(TAG, "malloc failed");
        return NSTACKX_ENOMEM;
    }
    dupDiscoverySettings->businessData = (char *)calloc((discoverySettings->length + 1), sizeof(char));
    if (dupDiscoverySettings->businessData == NULL) {
        DFINDER_LOGE(TAG, "businessData calloc fail");
        free(dupDiscoverySettings);
        return NSTACKX_ENOMEM;
    }
    if (CopyDiscoverySettings(dupDiscoverySettings, discoverySettings) != NSTACKX_EOK) {
        free(dupDiscoverySettings->businessData);
        free(dupDiscoverySettings);
        return NSTACKX_EINVAL;
    }

    if (PostEvent(&g_eventNodeChain, g_epollfd, DeviceDiscoverInnerConfigurable, dupDiscoverySettings) != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "Failed to start device discover!");
        free(dupDiscoverySettings->businessData);
        free(dupDiscoverySettings);
        return NSTACKX_EFAILED;
    }
    return NSTACKX_EOK;
}

#ifndef DFINDER_USE_MINI_NSTACKX
static void SubscribeModuleInner(void *argument)
{
    (void)argument;
    CoapSubscribeModuleInner(INNER_DISCOVERY);
}

int32_t NSTACKX_SubscribeModule(void)
{
    if (g_nstackInitState != NSTACKX_INIT_STATE_DONE) {
        DFINDER_LOGE(TAG, "NSTACKX_Ctrl is not initiated yet");
        return NSTACKX_EFAILED;
    }
    if (PostEvent(&g_eventNodeChain, g_epollfd, SubscribeModuleInner, NULL) != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "Failed to subscribe module!");
        return NSTACKX_EFAILED;
    }
    return NSTACKX_EOK;
}

static void UnsubscribeModuleInner(void *argument)
{
    (void)argument;
    CoapUnsubscribeModuleInner(INNER_DISCOVERY);
}

int32_t NSTACKX_UnsubscribeModule(void)
{
    if (g_nstackInitState != NSTACKX_INIT_STATE_DONE) {
        return NSTACKX_EFAILED;
    }

    if (PostEvent(&g_eventNodeChain, g_epollfd, UnsubscribeModuleInner, NULL) != NSTACKX_EOK) {
        return NSTACKX_EFAILED;
    }
    return NSTACKX_EOK;
}
#endif /* END OF DFINDER_USE_MINI_NSTACKX */

static void ConfigureLocalDeviceInfoInner(void *argument)
{
    NSTACKX_LocalDeviceInfo *localDeviceInfo = argument;

    ConfigureLocalDeviceInfo(localDeviceInfo);
    free(localDeviceInfo);
}

static void ConfigureLocalDeviceNameInner(void *argument)
{
    char *localDevName = (char *)argument;

    ConfigureLocalDeviceName(localDevName);
    free(localDevName);
}

#ifndef _WIN32
static int32_t VerifyNifNameIp(const char *networkName, const char *networkIp, uint32_t *matchCnt)
{
    if (networkName == NULL || networkIp == NULL || matchCnt == NULL) {
        DFINDER_LOGE(TAG, "invalid nif info passed in");
        return NSTACKX_EINVAL;
    }
    struct in_addr ipAddr;
    if (inet_pton(AF_INET, networkIp, &ipAddr) != 1) {
        return NSTACKX_EINVAL;
    }
    ++(*matchCnt);
    return NSTACKX_EOK;
}

static int32_t CheckNifInfoPassedIn(const NSTACKX_LocalDeviceInfo *localDeviceInfo)
{
    uint32_t matchCnt = 0;
#ifdef DFINDER_SUPPORT_MULTI_NIF
    for (uint32_t i = 0; i < localDeviceInfo->ifNums; ++i) {
        if (VerifyNifNameIp(localDeviceInfo->localIfInfo[i].networkName,
            localDeviceInfo->localIfInfo[i].networkIpAddr, &matchCnt) != NSTACKX_EOK) {
            return NSTACKX_EFAILED;
        }
    }
    return (matchCnt == localDeviceInfo->ifNums) ? NSTACKX_EOK : NSTACKX_EFAILED;
#else
    int32_t verifyResult;
    if (localDeviceInfo->ifNums == 0) {
        verifyResult = VerifyNifNameIp(localDeviceInfo->networkName, localDeviceInfo->networkIpAddr, &matchCnt);
        return verifyResult;
    } else {
        verifyResult = VerifyNifNameIp(localDeviceInfo->localIfInfo[0].networkName,
            localDeviceInfo->localIfInfo[0].networkIpAddr, &matchCnt);
        if ((verifyResult == NSTACKX_EOK) && (matchCnt == localDeviceInfo->ifNums)) {
            return NSTACKX_EOK;
        }
        return NSTACKX_EFAILED;
    }
#endif
}
#endif

#ifndef DFINDER_SUPPORT_MULTI_NIF
static int32_t CopyNifNameAndIp(NSTACKX_LocalDeviceInfo *destDev, const NSTACKX_LocalDeviceInfo *srcDev)
{
    if (destDev == NULL || srcDev == NULL) {
        DFINDER_LOGE(TAG, "invalid device info passed in");
        return NSTACKX_EINVAL;
    }
    if (srcDev->ifNums != 0) {
        if (strcpy_s(destDev->networkName, NSTACKX_MAX_INTERFACE_NAME_LEN, srcDev->localIfInfo[0].networkName) != EOK) {
            DFINDER_LOGE(TAG, "network name strcpy failed");
            return NSTACKX_EFAILED;
        }
        if (strcpy_s(destDev->networkIpAddr, NSTACKX_MAX_IP_STRING_LEN, srcDev->localIfInfo[0].networkIpAddr) != EOK) {
            DFINDER_LOGE(TAG, "network ip strcpy failed");
            return NSTACKX_EFAILED;
        }
    }
    return NSTACKX_EOK;
}
#endif

int32_t NSTACKX_RegisterDevice(const NSTACKX_LocalDeviceInfo *localDeviceInfo)
{
    DFINDER_LOGI(TAG, "begin to NSTACKX_RegisterDevice!");
    if (g_nstackInitState != NSTACKX_INIT_STATE_DONE) {
        DFINDER_LOGE(TAG, "NSTACKX_Ctrl is not initiated yet");
        return NSTACKX_EFAILED;
    }

    if (localDeviceInfo == NULL) {
        DFINDER_LOGE(TAG, "Invalid local device info");
        return NSTACKX_EINVAL;
    }

#ifdef DFINDER_SUPPORT_MULTI_NIF
    if (localDeviceInfo->ifNums > NSTACKX_MAX_LISTENED_NIF_NUM || localDeviceInfo->ifNums == 0) {
#else
    if (localDeviceInfo->ifNums > NSTACKX_MAX_LISTENED_NIF_NUM) {
#endif
        DFINDER_LOGE(TAG, "Invalid ifNums %hhu", localDeviceInfo->ifNums);
        return NSTACKX_EINVAL;
    }
#ifndef _WIN32
    if (CheckNifInfoPassedIn(localDeviceInfo) != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "check nif info passed in return fail");
        return NSTACKX_EFAILED;
    }
#endif
    NSTACKX_LocalDeviceInfo *dupLocalDeviceInfo = malloc(sizeof(NSTACKX_LocalDeviceInfo));
    if (dupLocalDeviceInfo == NULL) {
        return NSTACKX_ENOMEM;
    }

    if (memcpy_s(dupLocalDeviceInfo, sizeof(NSTACKX_LocalDeviceInfo),
        localDeviceInfo, sizeof(NSTACKX_LocalDeviceInfo)) != EOK) {
        DFINDER_LOGE(TAG, "memcpy failed");
        goto L_ERROR;
    }
#ifndef DFINDER_SUPPORT_MULTI_NIF
    if (CopyNifNameAndIp(dupLocalDeviceInfo, localDeviceInfo) != NSTACKX_EOK) {
        goto L_ERROR;
    }
#endif
    if (PostEvent(&g_eventNodeChain, g_epollfd, ConfigureLocalDeviceInfoInner, dupLocalDeviceInfo) != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "Failed to configure local device info!");
        goto L_ERROR;
    }
    return NSTACKX_EOK;
L_ERROR:
    free(dupLocalDeviceInfo);
    return NSTACKX_EFAILED;
}

int32_t NSTACKX_RegisterDeviceName(const char *devName)
{
    if (g_nstackInitState != NSTACKX_INIT_STATE_DONE) {
        DFINDER_LOGE(TAG, "NSTACKX_Ctrl is not initiated yet");
        return NSTACKX_EFAILED;
    }
    if (devName == NULL || devName[0] == '\0') {
        DFINDER_LOGE(TAG, "register local device name is invalid");
        return NSTACKX_EFAILED;
    }
    char *dupDevName = (char *)malloc(sizeof(char) * NSTACKX_MAX_DEVICE_NAME_LEN);
    if (dupDevName == NULL) {
        return NSTACKX_ENOMEM;
    }
    if (strncpy_s(dupDevName, NSTACKX_MAX_DEVICE_NAME_LEN, devName, strlen(devName)) != EOK) {
        DFINDER_LOGE(TAG, "strncpy dupDevName failed");
        free(dupDevName);
        return NSTACKX_EFAILED;
    }
    if (PostEvent(&g_eventNodeChain, g_epollfd, ConfigureLocalDeviceNameInner, dupDevName) != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "Failed to configure local device name!");
        free(dupDevName);
        return NSTACKX_EFAILED;
    }
    return NSTACKX_EOK;
}

int32_t NSTACKX_RegisterDeviceAn(const NSTACKX_LocalDeviceInfo *localDeviceInfo, uint64_t deviceHash)
{
    NSTACKX_LocalDeviceInfo *dupLocalDeviceInfo = NULL;

    if (g_nstackInitState != NSTACKX_INIT_STATE_DONE) {
        DFINDER_LOGE(TAG, "NSTACKX_Ctrl is not initiated yet");
        return NSTACKX_EFAILED;
    }

    if (localDeviceInfo == NULL) {
        DFINDER_LOGE(TAG, "Invalid local device info");
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
        DFINDER_LOGE(TAG, "Failed to configure local device info!");
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
    CapabilityProcessData *capabilityData = argument;

    SetFilterCapability(capabilityData->capabilityBitmapNum, capabilityData->capabilityBitmap);
    free(capabilityData);
}

static int32_t NSTACKX_CapabilityHandle(uint32_t capabilityBitmapNum, uint32_t capabilityBitmap[], EventHandle handle)
{
    CapabilityProcessData *capabilityData = NULL;

    if (g_nstackInitState != NSTACKX_INIT_STATE_DONE) {
        DFINDER_LOGE(TAG, "NSTACKX_Ctrl is not initiated yet");
        return NSTACKX_EFAILED;
    }

    if (capabilityBitmapNum > NSTACKX_MAX_CAPABILITY_NUM) {
        DFINDER_LOGE(TAG, "capabilityBitmapNum (%u) exceed max number", capabilityBitmapNum);
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
        DFINDER_LOGE(TAG, "Failed to register capability!");
        free(capabilityData);
        return NSTACKX_EFAILED;
    }
    return NSTACKX_EOK;
}

int32_t NSTACKX_RegisterCapability(uint32_t capabilityBitmapNum, uint32_t capabilityBitmap[])
{
    DFINDER_LOGI(TAG, "Register Capability");
    return NSTACKX_CapabilityHandle(capabilityBitmapNum, capabilityBitmap, RegisterCapabilityInner);
}

int32_t NSTACKX_SetFilterCapability(uint32_t capabilityBitmapNum, uint32_t capabilityBitmap[])
{
    DFINDER_LOGI(TAG, "Set Filter Capability");
    return NSTACKX_CapabilityHandle(capabilityBitmapNum, capabilityBitmap, SetFilterCapabilityInner);
}

static void RegisterServiceDataInner(void *argument)
{
    LOGI(TAG, "Register Service Data Inner");
    char *serviceData = argument;
    if (RegisterServiceData(serviceData) != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "RegisterServiceData failed");
    }
    free(serviceData);
}

int32_t NSTACKX_RegisterServiceData(const char *serviceData)
{
    LOGI(TAG, "Register Service Data");
    char *serviceDataTmp = NULL;

    if (serviceData == NULL) {
        DFINDER_LOGE(TAG, "serviceData is null");
        return NSTACKX_EINVAL;
    }
    if (g_nstackInitState != NSTACKX_INIT_STATE_DONE) {
        DFINDER_LOGE(TAG, "NSTACKX_Ctrl is not initiated yet");
        return NSTACKX_EFAILED;
    }
    if (strlen(serviceData) >= NSTACKX_MAX_SERVICE_DATA_LEN) {
        DFINDER_LOGE(TAG, "serviceData (%u) exceed max number", strlen(serviceData));
        return NSTACKX_EINVAL;
    }

    serviceDataTmp = calloc(1U, NSTACKX_MAX_SERVICE_DATA_LEN);
    if (serviceDataTmp == NULL) {
        return NSTACKX_ENOMEM;
    }
    if (strncpy_s(serviceDataTmp, NSTACKX_MAX_SERVICE_DATA_LEN, serviceData, strlen(serviceData)) != EOK) {
        DFINDER_LOGE(TAG, "Failed to copy serviceData");
        free(serviceDataTmp);
        return NSTACKX_EINVAL;
    }
    if (PostEvent(&g_eventNodeChain, g_epollfd, RegisterServiceDataInner, serviceDataTmp) != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "Failed to register serviceData!");
        free(serviceDataTmp);
        return NSTACKX_EFAILED;
    }
    return NSTACKX_EOK;
}

#ifndef DFINDER_USE_MINI_NSTACKX
static void RegisterExtendServiceDataInner(void *argument)
{
    char *extendServiceData = argument;
    if (RegisterExtendServiceData(extendServiceData) != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "RegisterExtendServiceData failed");
    }
    free(extendServiceData);
}

int32_t NSTACKX_RegisterExtendServiceData(const char *extendServiceData)
{
    char *extendServiceDataTmp = NULL;

    if (extendServiceData == NULL) {
        DFINDER_LOGE(TAG, "extendServiceData is null");
        return NSTACKX_EINVAL;
    }
    if (g_nstackInitState != NSTACKX_INIT_STATE_DONE) {
        DFINDER_LOGE(TAG, "NSTACKX_Ctrl is not initiated yet");
        return NSTACKX_EFAILED;
    }
    if (strlen(extendServiceData) >= NSTACKX_MAX_EXTEND_SERVICE_DATA_LEN) {
        DFINDER_LOGE(TAG, "extendServiceData (%u) exceed max number", strlen(extendServiceData));
        return NSTACKX_EINVAL;
    }

    extendServiceDataTmp = calloc(1, NSTACKX_MAX_EXTEND_SERVICE_DATA_LEN);
    if (extendServiceDataTmp == NULL) {
        return NSTACKX_ENOMEM;
    }
    if (strncpy_s(extendServiceDataTmp, NSTACKX_MAX_EXTEND_SERVICE_DATA_LEN, extendServiceData,
        strlen(extendServiceData)) != EOK) {
        DFINDER_LOGE(TAG, "Failed to copy extendServiceData");
        free(extendServiceDataTmp);
        return NSTACKX_EINVAL;
    }
    if (PostEvent(&g_eventNodeChain, g_epollfd, RegisterExtendServiceDataInner, extendServiceDataTmp) != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "Failed to register extendServiceData!");
        free(extendServiceDataTmp);
        return NSTACKX_EFAILED;
    }
    return NSTACKX_EOK;
}

#ifndef DFINDER_SUPPORT_MULTI_NIF
static void SendMsgInner(void *arg)
{
    MsgCtx *msg = arg;
    if (msg == NULL) {
        DFINDER_LOGE(TAG, "SendMsgInner: msg is NULL");
        return;
    }
    if (strlen(msg->p2pAddr) != 0) {
        DFINDER_LOGD(TAG, "Enter WifiDirect send");
        msg->err = CoapSendServiceMsgWithDefiniteTargetIp(msg, NULL);
    } else {
#ifdef DFINDER_SAVE_DEVICE_LIST
        DeviceInfo *deviceInfo = GetDeviceInfoById(msg->deviceId, GetDeviceDB());
        if (deviceInfo == NULL) {
            DFINDER_LOGW(TAG, "no device found in device list, try to find in backup");
            deviceInfo = GetDeviceInfoById(msg->deviceId, GetDeviceDBBackup());
            if (deviceInfo == NULL) {
                DFINDER_LOGE(TAG, "no device found in device list backup yet");
            }
        }
        msg->err = CoapSendServiceMsg(msg, deviceInfo);
#else
        DFINDER_LOGE(TAG, "Invalid p2pAddr");
        msg->err = NSTACKX_EINVAL;
#endif /* #ifdef DFINDER_SAVE_DEVICE_LIST */
    }
    SemPost(&msg->wait);
}

static int32_t NSTACKX_SendMsgParamCheck(const char *moduleName, const char *deviceId, const uint8_t *data,
    uint32_t len)
{
    if (moduleName == NULL || strlen(moduleName) > NSTACKX_MAX_MODULE_NAME_LEN) {
        DFINDER_LOGE(TAG, "Invalid module name");
        return NSTACKX_EINVAL;
    }

    if (deviceId == NULL || strlen(deviceId) > NSTACKX_MAX_DEVICE_ID_LEN) {
        DFINDER_LOGE(TAG, "Invalid device id");
        return NSTACKX_EINVAL;
    }

    if (data == NULL || len == 0 || len > NSTACKX_MAX_SENDMSG_DATA_LEN) {
        DFINDER_LOGE(TAG, "Null data to send");
        return NSTACKX_EINVAL;
    }
    return NSTACKX_EOK;
}

static MsgCtx *NSTACKX_GetMsgCtx(const char *moduleName, const char *deviceId, const uint8_t *data,
    uint32_t len, const char *ipaddr, uint8_t type)
{
    MsgCtx *msg = NULL;

    msg = calloc(1U, sizeof(MsgCtx));
    if (msg == NULL) {
        DFINDER_LOGE(TAG, "MsgCtx malloc fail");
        return NULL;
    }
    if ((strcpy_s(msg->deviceId, sizeof(msg->deviceId), deviceId) != EOK) ||
        (strcpy_s(msg->moduleName, sizeof(msg->moduleName), moduleName) != EOK)) {
        DFINDER_LOGE(TAG, "Cpy deviceId fail");
        goto FAILED;
    }
    if (ipaddr != NULL) {
        if (strcpy_s(msg->p2pAddr, sizeof(msg->p2pAddr), ipaddr) != EOK) {
            DFINDER_LOGE(TAG, "Cpy p2pAddr fail.");
            goto FAILED;
        }
    }
    msg->data = malloc(len);
    if (msg->data == NULL) {
        DFINDER_LOGE(TAG, "Msg data malloc fail");
        goto FAILED;
    }
    if (memcpy_s(msg->data, len, data, len) != EOK) {
        DFINDER_LOGE(TAG, "Msg data memcpy error");
        goto FAILED;
    }
    msg->len = len;
    msg->type = type;
    msg->err = NSTACKX_EOK;
    if (SemInit(&(msg->wait), 0, 0)) {
        DFINDER_LOGE(TAG, "sem init fail");
        goto FAILED;
    }

    return msg;
FAILED:
    free(msg->data);
    free(msg);
    return NULL;
}
#endif /* #ifndef DFINDER_SUPPORT_MULTI_NIF */

int32_t NSTACKX_SendMsgDirect(const char *moduleName, const char *deviceId, const uint8_t *data,
    uint32_t len, const char *ipaddr, uint8_t type)
{
#ifdef DFINDER_SUPPORT_MULTI_NIF
    (void)moduleName;
    (void)deviceId;
    (void)data;
    (void)len;
    (void)ipaddr;
    (void)type;
    DFINDER_LOGE(TAG, "Do not support SendMsgDirect");
    return NSTACKX_EFAILED;
#else
    MsgCtx *msg = NULL;
    int32_t ret = NSTACKX_EOK;
    DFINDER_LOGD(TAG, "NSTACKX_SendMsgDirect");
    if (g_nstackInitState != NSTACKX_INIT_STATE_DONE) {
        DFINDER_LOGE(TAG, "NSTACKX_Ctrl is not initiated yet");
        return NSTACKX_EFAILED;
    }
    if (ipaddr == NULL) {
        DFINDER_LOGE(TAG, "ipaddr needed");
        return NSTACKX_EINVAL;
    }
    if (NSTACKX_SendMsgParamCheck(moduleName, deviceId, data, len) != NSTACKX_EOK) {
        return NSTACKX_EINVAL;
    }
    msg = NSTACKX_GetMsgCtx(moduleName, deviceId, data, len, ipaddr, type);
    if (msg == NULL) {
        return NSTACKX_EFAILED;
    }
    if (PostEvent(&g_eventNodeChain, g_epollfd, SendMsgInner, msg) != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "Failed to send msg");
        ret = NSTACKX_EFAILED;
    }
    if (ret == NSTACKX_EOK) {
        SemWait(&(msg->wait));
        ret = msg->err;
    }
    SemDestroy(&(msg->wait));
    free(msg->data);
    free(msg);
    return ret;
#endif /* #ifdef DFINDER_SUPPORT_MULTI_NIF */
}

int32_t NSTACKX_SendMsg(const char *moduleName, const char *deviceId, const uint8_t *data, uint32_t len)
{
#ifdef DFINDER_SUPPORT_MULTI_NIF
    (void)moduleName;
    (void)deviceId;
    (void)data;
    (void)len;
    DFINDER_LOGE(TAG, "Do not support SendMsgDirect");
    return NSTACKX_EFAILED;
#else
#ifdef DFINDER_SAVE_DEVICE_LIST
    int32_t ret = NSTACKX_EOK;
    if (g_nstackInitState != NSTACKX_INIT_STATE_DONE) {
        DFINDER_LOGE(TAG, "NSTACKX_Ctrl is not initiated yet");
        return NSTACKX_EFAILED;
    }
    if (NSTACKX_SendMsgParamCheck(moduleName, deviceId, data, len) != NSTACKX_EOK) {
        return NSTACKX_EINVAL;
    }
    MsgCtx *msg = NSTACKX_GetMsgCtx(moduleName, deviceId, data, len, NULL, SERVER_TYPE_WLANORETH);
    if (msg == NULL) {
        return NSTACKX_EFAILED;
    }
    if (PostEvent(&g_eventNodeChain, g_epollfd, SendMsgInner, msg) != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "failed to send msg");
        ret = NSTACKX_EFAILED;
    }
    if (ret == NSTACKX_EOK) {
        SemWait(&(msg->wait));
        ret = msg->err;
    }
    SemDestroy(&(msg->wait));
    free(msg->data);
    free(msg);
    return ret;
#else
    (void)moduleName;
    (void)deviceId;
    (void)data;
    (void)len;

    DFINDER_LOGE(TAG, "SendMsg not supported");

    return NSTACKX_EFAILED;
#endif /* END OF DFINDER_SAVE_DEVICE_LIST */
#endif /* #ifdef DFINDER_SUPPORT_MULTI_NIF */
}
#endif /* END OF DFINDER_USE_MINI_NSTACKX */

static void SendDiscoveryRspInner(void *arg)
{
    NSTACKX_ResponseSettings *responseSettings = arg;
    if (responseSettings->businessType != GetLocalDeviceInfoPtr()->businessType) {
        DFINDER_LOGE(TAG, "businessType is diff when check response settings");
        free(responseSettings->businessData);
        free(responseSettings);
        return;
    }
    SendDiscoveryRsp(responseSettings);
    free(responseSettings->businessData);
    free(responseSettings);
}

static int32_t CopyResponseSettings(NSTACKX_ResponseSettings *dupResponseSettings,
                                    const NSTACKX_ResponseSettings *responseSettings)
{
    dupResponseSettings->businessType = responseSettings->businessType;
    dupResponseSettings->length = responseSettings->length;
    if (responseSettings->businessData != NULL) {
        if (strncpy_s(dupResponseSettings->businessData, (dupResponseSettings->length + 1),
            responseSettings->businessData, responseSettings->length) != EOK) {
            DFINDER_LOGE(TAG, "businessData strncpy failed");
            return NSTACKX_EINVAL;
        }
    }
    if (strncpy_s(dupResponseSettings->localNetworkName, NSTACKX_MAX_INTERFACE_NAME_LEN,
        responseSettings->localNetworkName, strlen(responseSettings->localNetworkName)) != EOK) {
        DFINDER_LOGE(TAG, "localNetworkName strncpy failed");
        return NSTACKX_EINVAL;
    }
    if (strncpy_s(dupResponseSettings->remoteIp, NSTACKX_MAX_IP_STRING_LEN,
        responseSettings->remoteIp, strlen(responseSettings->remoteIp)) != EOK) {
        DFINDER_LOGE(TAG, "remoteIp strncpy failed");
        return NSTACKX_EINVAL;
    }
    return NSTACKX_EOK;
}

static int32_t CheckResponseSettings(const NSTACKX_ResponseSettings *responseSettings)
{
    if (responseSettings == NULL) {
        DFINDER_LOGE(TAG, "Invalid responseSettings info");
        return NSTACKX_EINVAL;
    }
    if ((responseSettings->businessData == NULL) && (responseSettings->length != 0)) {
        DFINDER_LOGE(TAG, "Invalid responseSettings bData info");
        return NSTACKX_EINVAL;
    }
    if (responseSettings->length >= NSTACKX_MAX_BUSINESS_DATA_LEN) {
        DFINDER_LOGE(TAG, "businessData length is too long");
        return NSTACKX_EINVAL;
    }
    return NSTACKX_EOK;
}

int32_t NSTACKX_SendDiscoveryRsp(const NSTACKX_ResponseSettings *responseSettings)
{
    DFINDER_LOGI(TAG, "begin to NSTACKX_SendDiscoveryRsp!");
    if (g_nstackInitState != NSTACKX_INIT_STATE_DONE) {
        DFINDER_LOGE(TAG, "NSTACKX_Ctrl is not initiated yet");
        return NSTACKX_EFAILED;
    }
    if (CheckResponseSettings(responseSettings) != NSTACKX_EOK) {
        return NSTACKX_EINVAL;
    }

    NSTACKX_ResponseSettings *dupResponseSettings = malloc(sizeof(NSTACKX_ResponseSettings));
    if (dupResponseSettings == NULL) {
        DFINDER_LOGE(TAG, "malloc failed");
        return NSTACKX_ENOMEM;
    }
    dupResponseSettings->businessData = (char *)calloc((responseSettings->length + 1), sizeof(char));
    if (dupResponseSettings->businessData == NULL) {
        DFINDER_LOGE(TAG, "businessData calloc failed");
        free(dupResponseSettings);
        return NSTACKX_ENOMEM;
    }
    if (CopyResponseSettings(dupResponseSettings, responseSettings) != NSTACKX_EOK) {
        free(dupResponseSettings->businessData);
        free(dupResponseSettings);
        return NSTACKX_EINVAL;
    }

    if (PostEvent(&g_eventNodeChain, g_epollfd, SendDiscoveryRspInner, dupResponseSettings) != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "Failed to send responseSettings info!");
        free(dupResponseSettings->businessData);
        free(dupResponseSettings);
        return NSTACKX_EFAILED;
    }
    return NSTACKX_EOK;
}

#ifdef DFINDER_SAVE_DEVICE_LIST
static void GetDeviceListInner(void *argument)
{
    GetDeviceListMessage *message = argument;

    GetDeviceListWrapper(message->deviceList, message->deviceCountPtr, true);
    SemPost(&message->wait);
}
#endif

int32_t NSTACKX_GetDeviceList(NSTACKX_DeviceInfo *deviceList, uint32_t *deviceCountPtr)
{
#ifdef DFINDER_SAVE_DEVICE_LIST
    GetDeviceListMessage message = {
        .deviceList = deviceList,
        .deviceCountPtr = deviceCountPtr,
    };
    if (g_nstackInitState != NSTACKX_INIT_STATE_DONE) {
        DFINDER_LOGE(TAG, "NSTACKX_Ctrl is not initiated yet");
        return NSTACKX_EFAILED;
    }
    if (deviceList == NULL || deviceCountPtr == NULL) {
        DFINDER_LOGE(TAG, "Device list or count pointer is NULL");
        return NSTACKX_EINVAL;
    }
    if (SemInit(&message.wait, 0, 0)) {
        return NSTACKX_EFAILED;
    }
    if (PostEvent(&g_eventNodeChain, g_epollfd, GetDeviceListInner, &message) != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "Failed to get device list");
        SemDestroy(&message.wait);
        return NSTACKX_EFAILED;
    }
    SemWait(&message.wait);
    SemDestroy(&message.wait);
    return NSTACKX_EOK;
#else
    (void)deviceList;
    (void)deviceCountPtr;

    DFINDER_LOGE(TAG, "device list not supported");

    return NSTACKX_EFAILED;
#endif /* END OF DFINDER_SAVE_DEVICE_LIST */
}

void NotifyDeviceListChanged(const NSTACKX_DeviceInfo *deviceList, uint32_t deviceCount)
{
    if (g_parameter.onDeviceListChanged != NULL) {
        DFINDER_LOGI(TAG, "notify callback: device list changed");
        g_parameter.onDeviceListChanged(deviceList, deviceCount);
        DFINDER_LOGI(TAG, "finish to notify device list changed");
    } else {
        DFINDER_LOGI(TAG, "notify callback: device list changed callback is null");
    }
}

void NotifyDeviceFound(const NSTACKX_DeviceInfo *deviceList, uint32_t deviceCount)
{
    if (g_parameter.onDeviceFound != NULL) {
        DFINDER_LOGI(TAG, "notify callback: device found");
        g_parameter.onDeviceFound(deviceList, deviceCount);
        DFINDER_LOGI(TAG, "finish to notify device found");
    } else {
        DFINDER_LOGI(TAG, "notify callback: device found callback is null");
    }
}

#ifndef DFINDER_USE_MINI_NSTACKX
void NotifyMsgReceived(const char *moduleName, const char *deviceId, const uint8_t *data, uint32_t len)
{
    if (g_parameter.onMsgReceived != NULL) {
        DFINDER_LOGI(TAG, "notify callback: message received, data length %u", len);
        g_parameter.onMsgReceived(moduleName, deviceId, data, len);
        DFINDER_LOGI(TAG, "finish to notify msg received");
    } else {
        DFINDER_LOGI(TAG, "notify callback: message received callback is null");
    }
}

int32_t NSTACKX_InitRestart(const NSTACKX_Parameter *parameter)
{
#ifdef DFINDER_SUPPORT_MULTI_NIF
    (void)parameter;
    return NSTACKX_EOK;
#else
    DFINDER_LOGI(TAG, "NSTACKX_InitRestart");
    int32_t ret = NSTACKX_Init(parameter);
    if (ret == NSTACKX_EOK) {
        if (PostEvent(&g_eventNodeChain, g_epollfd, GetLocalNetworkInterface, NULL) != NSTACKX_EOK) {
            DFINDER_LOGE(TAG, "Failed to GetLocalNetworkInterface");
        }
    }
    return ret;
#endif
}

static void DeviceDiscoverInnerRestart(void *argument)
{
    (void)argument;
    CoapServiceDiscoverInner(NSTACKX_FALSE);
}

void NSTACKX_StartDeviceFindRestart(void)
{
    if (g_nstackInitState != NSTACKX_INIT_STATE_DONE) {
        DFINDER_LOGE(TAG, "NSTACKX_Ctrl is not initiated yet");
        return;
    }
    DFINDER_LOGI(TAG, "start device find for restart");
    if (PostEvent(&g_eventNodeChain, g_epollfd, DeviceDiscoverInnerRestart, NULL) != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "Failed to start device discover!");
        return;
    }
    return;
}
#endif /* END OF DFINDER_USE_MINI_NSTACKX */

#ifdef ENABLE_USER_LOG
int32_t NSTACKX_DFinderRegisterLog(DFinderLogCallback userLogCallback)
{
    if (userLogCallback == NULL) {
        DFINDER_LOGE(TAG, "logImpl null");
        return NSTACKX_EFAILED;
    }
    int32_t ret = SetLogCallback(userLogCallback);
    return ret;
}
#endif

#ifdef NSTACKX_DFINDER_HIDUMP
#define MAX_DUMP_ARGC 10
int NSTACKX_DFinderDump(const char **argv, uint32_t argc, void *softObj, DFinderDumpFunc dump)
{
    if (g_nstackInitState != NSTACKX_INIT_STATE_DONE) {
        DFINDER_LOGE(TAG, "NSTACKX_Ctrl is not initiated yet");
        return NSTACKX_EFAILED;
    }

    if (dump == NULL) {
        DFINDER_LOGE(TAG, "dump is null");
        return NSTACKX_EINVAL;
    }
    
    if (argc == 0 || argc > MAX_DUMP_ARGC) {
        DFINDER_LOGE(TAG, "argc is invalid %u", argc);
        return NSTACKX_EINVAL;
    }
    
    if (argv == NULL) {
        DFINDER_LOGE(TAG, "argv is null");
        return NSTACKX_EINVAL;
    }
    
    uint32_t i;
    for (i = 0; i < argc; i++) {
        if (argv[i] == NULL) {
            DFINDER_LOGE(TAG, "argv[%u] is null", i);
            return NSTACKX_EINVAL;
        }
    }

    return DFinderDump(argv, argc, softObj, dump);
}
#else
int NSTACKX_DFinderDump(const char **argv, uint32_t argc, void *softObj, DFinderDumpFunc dump)
{
    (void)argv;
    (void)argc;
    (void)softObj;
    (void)dump;
    DFINDER_LOGE(TAG, "Unsupport dfinder dump");
    return NSTACKX_NOTSUPPORT;
}
#endif

int NSTACKX_DFinderSetEventFunc(void *softobj, DFinderEventFunc func)
{
    if (g_nstackInitState != NSTACKX_INIT_STATE_DONE) {
        DFINDER_LOGE(TAG, "NSTACKX_Ctrl is not initiated yet");
        return NSTACKX_EFAILED;
    }

    if (func == NULL) {
        DFINDER_LOGE(TAG, "func is null");
        return NSTACKX_EINVAL;
    }

    return SetEventFunc(softobj, func);
}
