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

#include "nstackx_common.h"

#include <securec.h>
#ifndef _WIN32
#include <pthread.h>
#include <semaphore.h>
#include <stdatomic.h>
#include <unistd.h>
#endif
#include "cJSON.h"

#ifndef DFINDER_USE_MINI_NSTACKX
#include <coap3/coap.h>
#endif

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
#include "nstackx_device_local.h"
#include "nstackx_device_remote.h"

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

static pthread_mutex_t g_threadInitLock = PTHREAD_MUTEX_INITIALIZER;
static NSTACKX_Parameter g_parameter;
static atomic_uint_fast8_t g_nstackInitState = NSTACKX_INIT_STATE_START;
static atomic_uint_fast8_t g_nstackThreadInitState = NSTACKX_INIT_STATE_START;
static bool g_isNotifyPerDevice;

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
static int32_t RegisterDeviceWithType(const NSTACKX_LocalDeviceInfoV2 *localDeviceInfo, int registerType);

bool GetIsNotifyPerDevice(void)
{
    return g_isNotifyPerDevice;
}

#ifdef DFINDER_SUPPORT_COVERITY_TAINTED_SET
void Coverity_Tainted_Set(void *buf)
{
    (void)buf;
}
#endif

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

int32_t ShouldAutoReplyUnicast(uint8_t businessType)
{
    switch (businessType) {
        case NSTACKX_BUSINESS_TYPE_SOFTBUS:
        case NSTACKX_BUSINESS_TYPE_AUTONET:
        case NSTACKX_BUSINESS_TYPE_STRATEGY:
            return NSTACKX_FALSE;
        case NSTACKX_BUSINESS_TYPE_NULL:
        case NSTACKX_BUSINESS_TYPE_HICOM:
        case NSTACKX_BUSINESS_TYPE_NEARBY:
        default:
            return NSTACKX_TRUE;
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

int32_t GetServiceDiscoverInfo(const uint8_t *buf, size_t size, struct DeviceInfo *deviceInfo, char **remoteUrlPtr)
{
    uint8_t *newBuf = NULL;
    if (size <= 0) {
        DFINDER_LOGE(TAG, "buf size <= 0");
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

int32_t GetServiceNotificationInfo(const uint8_t *buf, size_t size, NSTACKX_NotificationConfig *notification)
{
    uint8_t *newBuf = NULL;
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
    if (ParseServiceNotification(buf, notification) != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "parse service notification error");
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
    uint8_t retFlag = NSTACKX_TRUE;
    if ((uint64_t)eventCount * EVENT_COUNT_RATE_INTERVAL <
        MAX_EVENT_PROCESS_NUM_PER_INTERVAL * (uint64_t)timeMs) {
        retFlag = NSTACKX_FALSE;
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
    if (measureElapse <= EVENT_COUNT_RATE_INTERVAL) {
        return;
    }
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

#ifdef _WIN32
    ret = CoapThreadInit();
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

#ifdef DFINDER_USE_MINI_NSTACKX
static void ReportMainLoopStopInner(void *argument)
{
    (void)argument;
    DFINDER_LOGI(TAG, "receive message to stop main loop");
}

static void ReportMainLoopStop(void)
{
    if (g_nstackThreadInitState != NSTACKX_INIT_STATE_DONE) {
        DFINDER_LOGE(TAG, "NSTACKX_Ctrl is not initiated yet");
        return;
    }
    if (PostEvent(&g_eventNodeChain, g_epollfd, ReportMainLoopStopInner, NULL) != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "Failed to report mainloop stop!");
    }
}
#endif

int32_t NSTACKX_ThreadInit(void)
{
    if (g_nstackInitState != NSTACKX_INIT_STATE_DONE) {
        DFINDER_LOGE(TAG, "nstack is not initiated foundation yet");
        return NSTACKX_EFAILED;
    }
    if (PthreadMutexLock(&g_threadInitLock) != 0) {
        DFINDER_LOGE(TAG, "Failed to lock");
        return NSTACKX_EFAILED;
    }
    DFINDER_LOGI(TAG, "nstack begin init thread");
    if (g_nstackThreadInitState != NSTACKX_INIT_STATE_START) {
        (void)PthreadMutexUnlock(&g_threadInitLock);
        return NSTACKX_EOK;
    }
    g_nstackThreadInitState = NSTACKX_INIT_STATE_ONGOING;
    g_terminateFlag = NSTACKX_FALSE;
    g_validTidFlag = NSTACKX_FALSE;
#ifndef DFINDER_USE_MINI_NSTACKX
    int32_t ret = PthreadCreate(&g_tid, NULL, NstackMainLoop, NULL);
    if (ret != 0) {
        DFINDER_LOGE(TAG, "thread create failed");
        g_terminateFlag = NSTACKX_TRUE;
        (void)PthreadMutexUnlock(&g_threadInitLock);
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
        g_terminateFlag = NSTACKX_TRUE;
        (void)PthreadMutexUnlock(&g_threadInitLock);
        return NSTACKX_EFAILED;
    }
#endif
    g_validTidFlag = NSTACKX_TRUE;
    g_nstackThreadInitState = NSTACKX_INIT_STATE_DONE;
    (void)PthreadMutexUnlock(&g_threadInitLock);
    return NSTACKX_EOK;
}

void NSTACKX_ThreadDeinit(void)
{
    if (g_nstackThreadInitState == NSTACKX_INIT_STATE_START) {
        return;
    }
    DFINDER_LOGI(TAG, "nstack begin deinit thread");
    if (PthreadMutexLock(&g_threadInitLock) != 0) {
        DFINDER_LOGE(TAG, "Failed to lock");
        return;
    }
    if (g_validTidFlag) {
        g_terminateFlag = NSTACKX_TRUE;
#ifndef DFINDER_USE_MINI_NSTACKX
        PthreadJoin(g_tid, NULL);
#else
        ReportMainLoopStop();
        if (osThreadTerminate(g_threadId) != osOK) {
            DFINDER_LOGE(TAG, "os thread terminate failed");
        }
#endif
        g_validTidFlag = NSTACKX_FALSE;
    }
    g_nstackThreadInitState = NSTACKX_INIT_STATE_START;
    (void)PthreadMutexUnlock(&g_threadInitLock);
}

#if !defined(DFINDER_USE_MINI_NSTACKX) && !defined(DFINDER_ENABLE_COAP_LOG)
static void CoapLogHandler(coap_log_t level, const char *message)
{
    (void)level;
    (void)message;
}
#endif

static void InitLogLevel(void)
{
    // default log
    SetLogLevel(NSTACKX_LOG_LEVEL_DEBUG);

    // user defined log
#ifdef ENABLE_USER_LOG
    SetDFinderLogLevel(DFINDER_LOG_LEVEL_DEBUG);
#endif

#ifndef DFINDER_USE_MINI_NSTACKX
    // opensource libcoap log
#ifdef DFINDER_ENABLE_COAP_LOG
    coap_set_log_level(COAP_LOG_DEBUG);
#else
    coap_set_log_handler(CoapLogHandler);
#endif
#endif
}

static int32_t NstackxInitEx(const NSTACKX_Parameter *parameter, bool isNotifyPerDevice)
{
    Coverity_Tainted_Set((void *)parameter);

    int32_t ret;

    if (g_nstackInitState != NSTACKX_INIT_STATE_START) {
        return NSTACKX_EOK;
    }

    g_nstackInitState = NSTACKX_INIT_STATE_ONGOING;
    cJSON_InitHooks(NULL);

    InitLogLevel();

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
    ret = InternalInit(g_epollfd, parameter != NULL ? parameter->maxDeviceNum : NSTACKX_DEFAULT_DEVICE_NUM);
#else
    ret = InternalInit(g_epollfd, parameter != NULL ? parameter->maxDeviceNum : NSTACKX_MAX_DEVICE_NUM);
#endif
    if (ret != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "internal init failed, ret=%d", ret);
        goto L_ERR_INIT;
    }
    (void)memset_s(&g_parameter, sizeof(g_parameter), 0, sizeof(g_parameter));
    if (parameter != NULL) {
        (void)memcpy_s(&g_parameter, sizeof(g_parameter), parameter, sizeof(NSTACKX_Parameter));
    }

#ifndef DFINDER_USE_MINI_NSTACKX
    CoapInitSubscribeModuleInner(); /* initialize subscribe module number */
#endif /* END OF DFINDER_USE_MINI_NSTACKX */
    g_isNotifyPerDevice = isNotifyPerDevice;
    g_nstackInitState = NSTACKX_INIT_STATE_DONE;
    DFINDER_LOGI(TAG, "DFinder init successfully");
    return NSTACKX_EOK;

L_ERR_INIT:
    NSTACKX_Deinit();
    return ret;
}

int32_t NSTACKX_Init(const NSTACKX_Parameter *parameter)
{
    return NstackxInitEx(parameter, false);
}
 
int32_t NSTACKX_InitV2(const NSTACKX_Parameter *parameter, bool isNotifyPerDevice)
{
    return NstackxInitEx(parameter, isNotifyPerDevice);
}

void NSTACKX_Deinit(void)
{
    if (g_nstackInitState == NSTACKX_INIT_STATE_START) {
        return;
    }
    NSTACKX_ThreadDeinit();
#ifndef DFINDER_USE_MINI_NSTACKX
    SmartGeniusClean();
#endif /* END OF DFINDER_USE_MINI_NSTACKX */
    CoapDiscoverDeinit();

#ifdef _WIN32
    CoapThreadDestroy();
#endif
    DeviceModuleClean();
    EventNodeChainClean(&g_eventNodeChain);
    if (IsEpollDescValid(g_epollfd)) {
        CloseEpollDesc(g_epollfd);
        g_epollfd = INVALID_EPOLL_DESC;
    }
    ResetStatistics();
    ResetEventFunc();
    ResetSequenceNumber();
    g_nstackInitState = NSTACKX_INIT_STATE_START;
    DFINDER_LOGI(TAG, "deinit successfully");
}

static void DeviceDiscoverInner(void *argument)
{
    if (!IsCoapContextReady()) {
        DFINDER_LOGE(TAG, "no iface is ready, notify user with empty list");
        NotifyDeviceFound(NULL, 0);
        return;
    }

    (void)argument;
    SetCoapDiscoverType(COAP_BROADCAST_TYPE_DEFAULT);
    SetLocalDeviceBusinessType(NSTACKX_BUSINESS_TYPE_NULL);
    CoapServiceDiscoverInner(INNER_DISCOVERY);
}

static void DeviceDiscoverInnerAn(void *argument)
{
    (void)argument;
    SetCoapDiscoverType(COAP_BROADCAST_TYPE_DEFAULT);
    SetLocalDeviceBusinessType(NSTACKX_BUSINESS_TYPE_NULL);
    CoapServiceDiscoverInnerAn(INNER_DISCOVERY);
}

static void DeviceDiscoverInnerConfigurable(void *argument)
{
    NSTACKX_DiscoverySettings *discoverySettings = argument;
    int32_t configResult = ConfigureDiscoverySettings(discoverySettings);
    free(discoverySettings->businessData);
    free(discoverySettings);
    if (configResult != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "config discovery settings failed");
        return;
    }
    CoapServiceDiscoverInnerConfigurable(INNER_DISCOVERY);
}

static void DiscConfig(void *argument)
{
    DFinderDiscConfig *discConfig = argument;
    uint8_t businessTypeLocal = GetLocalDeviceBusinessType();
    if (discConfig->businessType != businessTypeLocal) {
        DFINDER_LOGE(TAG, "business type is different, config: %hhu, local: %hhu",
            discConfig->businessType, businessTypeLocal);
        free(discConfig->businessData);
        free(discConfig->bcastInterval);
        free(discConfig);
        return;
    }
    int32_t configResult = DiscConfigInner(discConfig);
    free(discConfig->businessData);
    free(discConfig->bcastInterval);
    free(discConfig);
    if (configResult != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "config for discover failed");
        return;
    }
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
    if (g_nstackThreadInitState != NSTACKX_INIT_STATE_DONE) {
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
    Coverity_Tainted_Set((void *)&mode);
    if (g_nstackThreadInitState != NSTACKX_INIT_STATE_DONE) {
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
    if (g_nstackThreadInitState != NSTACKX_INIT_STATE_DONE) {
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
    if (g_nstackThreadInitState != NSTACKX_INIT_STATE_DONE) {
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

static int32_t CopyDiscConfig(const DFinderDiscConfig *src, DFinderDiscConfig *dst)
{
    dst->businessType = src->businessType;
    dst->discoveryMode = src->discoveryMode;
    dst->intervalArrLen = src->intervalArrLen;
    for (size_t idx = 0; idx < dst->intervalArrLen; ++idx) {
        (dst->bcastInterval)[idx] = (src->bcastInterval)[idx];
    }
    if (src->businessData != NULL) {
        if (strncpy_s(dst->businessData, dst->businessDataLen, src->businessData, src->businessDataLen) != EOK) {
            DFINDER_LOGE(TAG, "copy business data failed");
            return NSTACKX_EFAILED;
        }
    }
    return NSTACKX_EOK;
}

static int32_t CheckDiscInterval(uint32_t *intervalArr, uint32_t arrLen)
{
    if (intervalArr == NULL || arrLen == 0) {
        DFINDER_LOGE(TAG, "illegal param, arrlen: %ld", arrLen);
        return NSTACKX_EINVAL;
    }
    // check interval values one by one
    for (size_t i = 0; i < arrLen; ++i) {
        if (intervalArr[i] < NSTACKX_MIN_ADVERTISE_INTERVAL || intervalArr[i] > NSTACKX_MAX_ADVERTISE_INTERVAL) {
            DFINDER_LOGE(TAG, "invalid interval");
            return NSTACKX_EINVAL;
        }
    }
    return NSTACKX_EOK;
}

static int32_t CheckDiscConfig(const DFinderDiscConfig *discConfig)
{
    if (discConfig == NULL) {
        DFINDER_LOGE(TAG, "disc config passed in is null");
        return NSTACKX_EINVAL;
    }
    // minus one for the first broadcast without interval
    if (discConfig->bcastInterval == NULL || discConfig->intervalArrLen > (NSTACKX_MAX_ADVERTISE_COUNT - 1) ||
        discConfig->intervalArrLen == 0) {
        DFINDER_LOGE(TAG, "invalid broadcast interval params");
        return NSTACKX_EINVAL;
    }
    if (CheckDiscInterval(discConfig->bcastInterval, discConfig->intervalArrLen) != NSTACKX_EOK) {
        return NSTACKX_EINVAL;
    }
    if ((discConfig->businessData == NULL) && (discConfig->businessDataLen != 0)) {
        DFINDER_LOGE(TAG, "invalid business data params");
        return NSTACKX_EINVAL;
    }
    if (discConfig->businessDataLen >= NSTACKX_MAX_BUSINESS_DATA_LEN) {
        DFINDER_LOGE(TAG, "business data is too long");
        return NSTACKX_EINVAL;
    }
    return NSTACKX_EOK;
}

int32_t NSTACKX_StartDeviceDiscoveryWithConfig(const DFinderDiscConfig *discConfig)
{
    DFINDER_LOGI(TAG, "dfinder start disc with config");
    if (g_nstackThreadInitState != NSTACKX_INIT_STATE_DONE) {
        DFINDER_LOGE(TAG, "nstackx ctrl is not initialed yet");
        return NSTACKX_EFAILED;
    }
    if (CheckDiscConfig(discConfig) != NSTACKX_EOK) {
        return NSTACKX_EINVAL;
    }
    DFinderDiscConfig *dupDiscConfig = (DFinderDiscConfig *)malloc(sizeof(DFinderDiscConfig));
    if (dupDiscConfig == NULL) {
        DFINDER_LOGE(TAG, "malloc for duplicate disc config failed");
        return NSTACKX_ENOMEM;
    }
    dupDiscConfig->bcastInterval = (uint32_t *)malloc(sizeof(uint32_t) * (discConfig->intervalArrLen));
    if (dupDiscConfig->bcastInterval == NULL) {
        DFINDER_LOGE(TAG, "malloc for duplicate broadcast interval failed");
        free(dupDiscConfig);
        return NSTACKX_ENOMEM;
    }
    dupDiscConfig->businessData = (char *)calloc((discConfig->businessDataLen + 1), sizeof(char));
    if (dupDiscConfig->businessData == NULL) {
        DFINDER_LOGE(TAG, "malloc for duplicate business data failed");
        free(dupDiscConfig->bcastInterval);
        free(dupDiscConfig);
        return NSTACKX_ENOMEM;
    }
    // 1 to store the terminator
    dupDiscConfig->businessDataLen = discConfig->businessDataLen + 1;
    if (CopyDiscConfig(discConfig, dupDiscConfig) != NSTACKX_EOK) {
        free(dupDiscConfig->businessData);
        free(dupDiscConfig->bcastInterval);
        free(dupDiscConfig);
        return NSTACKX_EFAILED;
    }
    if (PostEvent(&g_eventNodeChain, g_epollfd, DiscConfig, dupDiscConfig) != NSTACKX_EOK) {
        free(dupDiscConfig->businessData);
        free(dupDiscConfig->bcastInterval);
        free(dupDiscConfig);
        return NSTACKX_EFAILED;
    }
    return NSTACKX_EOK;
}

#ifndef DFINDER_USE_MINI_NSTACKX
int32_t NSTACKX_SubscribeModule(void)
{
    if (g_nstackInitState != NSTACKX_INIT_STATE_DONE) {
        DFINDER_LOGE(TAG, "NSTACKX_Ctrl is not initiated yet");
        return NSTACKX_EFAILED;
    }
    CoapSubscribeModuleInner(INNER_DISCOVERY);
    return NSTACKX_EOK;
}

int32_t NSTACKX_UnsubscribeModule(void)
{
    if (g_nstackInitState != NSTACKX_INIT_STATE_DONE) {
        return NSTACKX_EFAILED;
    }
    CoapUnsubscribeModuleInner(INNER_DISCOVERY);
    return NSTACKX_EOK;
}
#endif /* END OF DFINDER_USE_MINI_NSTACKX */

static bool IsNetworkNameValid(const char *networkName, size_t len)
{
    if (!StringHasEOF(networkName, len)) {
        DFINDER_LOGE(TAG, "network name is not ended");
        return NSTACKX_FALSE;
    }

    return NSTACKX_TRUE;
}

static bool IsIpAddressValid(const char *ipStr, size_t len)
{
    if (!StringHasEOF(ipStr, len)) {
        DFINDER_LOGE(TAG, "ip addr is not ended");
        return NSTACKX_FALSE;
    }

    struct in_addr ipAddr;
    if (len != 0 && ipStr[0] != '\0' && inet_pton(AF_INET, ipStr, &ipAddr) != 1) {
        DFINDER_LOGE(TAG, "invalid ip address");
        return NSTACKX_FALSE;
    }

    return NSTACKX_TRUE;
}

static int32_t CheckInterfaceInfo(const NSTACKX_InterfaceInfo *ifaces, uint32_t count)
{
    for (uint32_t i = 0; i < count; ++i) {
        if (!IsNetworkNameValid(ifaces[i].networkName, sizeof(ifaces[i].networkName)) ||
            !IsIpAddressValid(ifaces[i].networkIpAddr, sizeof(ifaces[i].networkIpAddr))) {
            DFINDER_LOGE(TAG, "invalid network name or ip address of No.%u local iface", i);
            return NSTACKX_EINVAL;
        }
    }

    return NSTACKX_EOK;
}

static int CheckLocalDeviceInfo(const NSTACKX_LocalDeviceInfo *localDeviceInfo)
{
    if (g_nstackInitState != NSTACKX_INIT_STATE_DONE) {
        DFINDER_LOGE(TAG, "NSTACKX_Ctrl is not initiated yet");
        return NSTACKX_EFAILED;
    }

    if (localDeviceInfo == NULL) {
        DFINDER_LOGE(TAG, "Invalid local device info");
        return NSTACKX_EINVAL;
    }

    if (!StringHasEOF(localDeviceInfo->deviceId, sizeof(localDeviceInfo->deviceId)) ||
        !StringHasEOF(localDeviceInfo->name, sizeof(localDeviceInfo->name))) {
        DFINDER_LOGE(TAG, "device id or device name is not ended");
        return NSTACKX_EINVAL;
    }

    if (localDeviceInfo->ifNums > NSTACKX_MAX_LISTENED_NIF_NUM) {
        DFINDER_LOGE(TAG, "invalid iface number %u", localDeviceInfo->ifNums);
        return NSTACKX_EINVAL;
    } else if (localDeviceInfo->ifNums == 0) {
        if (!IsNetworkNameValid(localDeviceInfo->networkName, sizeof(localDeviceInfo->networkName)) ||
            !IsIpAddressValid(localDeviceInfo->networkIpAddr, sizeof(localDeviceInfo->networkIpAddr))) {
            DFINDER_LOGE(TAG, "invalid network name or ip address when iface number is 0");
            return NSTACKX_EINVAL;
        }
    }

    return NSTACKX_EOK;
}

static void DeviceInfoV2Init(NSTACKX_LocalDeviceInfoV2 *v2,
    const NSTACKX_LocalDeviceInfo *localDeviceInfo, bool hasDeviceHash, uint64_t deviceHash)
{
    v2->name = localDeviceInfo->name;
    v2->deviceId = localDeviceInfo->deviceId;
    v2->deviceType = localDeviceInfo->deviceType;
    v2->businessType = localDeviceInfo->businessType;
    v2->hasDeviceHash = hasDeviceHash;
    v2->deviceHash = deviceHash;
}

static int32_t RegisterDeviceWithDeviceHash(const NSTACKX_LocalDeviceInfo *localDeviceInfo,
    bool hasDeviceHash, uint64_t deviceHash)
{
    int ret = CheckLocalDeviceInfo(localDeviceInfo);
    if (ret != NSTACKX_EOK) {
        return ret;
    }

    NSTACKX_LocalDeviceInfoV2 v2;
    DeviceInfoV2Init(&v2, localDeviceInfo, hasDeviceHash, deviceHash);

    NSTACKX_InterfaceInfo ifaceInfo = { {0}, {0} };
    if (localDeviceInfo->ifNums == 0) {
        if (strcpy_s(ifaceInfo.networkName, sizeof(ifaceInfo.networkName), localDeviceInfo->networkName) != EOK ||
            strcpy_s(ifaceInfo.networkIpAddr, sizeof(ifaceInfo.networkIpAddr),
            localDeviceInfo->networkIpAddr) != EOK) {
            DFINDER_LOGE(TAG, "copy network name or ip addr failed");
            return NSTACKX_EINVAL;
        }
        v2.localIfInfo = &ifaceInfo;
        v2.ifNums = 1;
    } else {
        v2.localIfInfo = &localDeviceInfo->localIfInfo[0];
        v2.ifNums = localDeviceInfo->ifNums;
    }

    return RegisterDeviceWithType(&v2, hasDeviceHash ? REGISTER_TYPE_UPDATE_SPECIFIED : REGISTER_TYPE_UPDATE_ALL);
}

int32_t NSTACKX_RegisterDevice(const NSTACKX_LocalDeviceInfo *localDeviceInfo)
{
    Coverity_Tainted_Set((void *)localDeviceInfo);
    DFINDER_LOGI(TAG, "begin to NSTACKX_RegisterDevice!");

    return RegisterDeviceWithDeviceHash(localDeviceInfo, NSTACKX_FALSE, 0);
}

static void ConfigureLocalDeviceNameInner(void *argument)
{
    char *localDevName = (char *)argument;

    ConfigureLocalDeviceName(localDevName);
    free(localDevName);
}

int32_t NSTACKX_RegisterDeviceName(const char *devName)
{
    if (devName == NULL || devName[0] == '\0') {
        DFINDER_LOGE(TAG, "register local device name is invalid");
        return NSTACKX_EINVAL;
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
    Coverity_Tainted_Set((void *)localDeviceInfo);
    Coverity_Tainted_Set((void *)&deviceHash);

    DFINDER_LOGI(TAG, "begin to NSTACKX_RegisterDeviceAn!");
    return RegisterDeviceWithDeviceHash(localDeviceInfo, NSTACKX_TRUE, deviceHash);
}

struct RegDeviceInfo {
    const NSTACKX_LocalDeviceInfoV2 *info;
    int registerType;
    int32_t err;
    sem_t wait;
};

static void RegisterDeviceV2(void *arg)
{
    struct RegDeviceInfo *regInfo = (struct RegDeviceInfo *)arg;
    regInfo->err = RegisterLocalDeviceV2(regInfo->info, regInfo->registerType);
    SemPost(&regInfo->wait);
}

#define NSTACKX_MAX_LOCAL_IFACE_NUM 10

static int32_t RegisterDeviceWithType(const NSTACKX_LocalDeviceInfoV2 *localDeviceInfo, int registerType)
{
    if (localDeviceInfo == NULL || localDeviceInfo->name == NULL ||
        localDeviceInfo->deviceId == NULL || localDeviceInfo->ifNums > NSTACKX_MAX_LOCAL_IFACE_NUM ||
        (localDeviceInfo->ifNums != 0 && localDeviceInfo->localIfInfo == NULL) ||
        CheckInterfaceInfo(localDeviceInfo->localIfInfo, localDeviceInfo->ifNums) != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "invalid args");
        return NSTACKX_EINVAL;
    }

    if (g_nstackThreadInitState != NSTACKX_INIT_STATE_DONE) {
        return (int32_t)RegisterLocalDeviceV2(localDeviceInfo, registerType);
    }

    struct RegDeviceInfo regInfo;
    if (SemInit(&regInfo.wait, 0, 0)) {
        DFINDER_LOGE(TAG, "sem init fail");
        return NSTACKX_EBUSY;
    }

    regInfo.info = localDeviceInfo;
    regInfo.registerType = registerType;
    regInfo.err = NSTACKX_EOK;

    if (PostEvent(&g_eventNodeChain, g_epollfd, RegisterDeviceV2, &regInfo) != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "Failed to configure local device info!");
        SemDestroy(&regInfo.wait);
        return NSTACKX_EBUSY;
    }

    SemWait(&regInfo.wait);
    SemDestroy(&regInfo.wait);
    return regInfo.err;
}

int32_t NSTACKX_RegisterDeviceV2(const NSTACKX_LocalDeviceInfoV2 *localDeviceInfo)
{
    Coverity_Tainted_Set((void *)localDeviceInfo);

    if (g_nstackInitState != NSTACKX_INIT_STATE_DONE) {
        DFINDER_LOGE(TAG, "NSTACKX_Ctrl is not initiated yet");
        return NSTACKX_EFAILED;
    }

    return RegisterDeviceWithType(localDeviceInfo, REGISTER_TYPE_UPDATE_ALL);
}

typedef struct {
    uint32_t capabilityBitmapNum;
    uint32_t capabilityBitmap[NSTACKX_MAX_CAPABILITY_NUM];
} CapabilityProcessData;

static void RegisterCapabilityInner(void *argument)
{
    CapabilityProcessData *capabilityData = argument;

    (void)SetLocalDeviceCapability(capabilityData->capabilityBitmapNum, capabilityData->capabilityBitmap);
    free(capabilityData);
}

static void SetFilterCapabilityInner(void *argument)
{
    CapabilityProcessData *capabilityData = argument;

    (void)SetFilterCapability(capabilityData->capabilityBitmapNum, capabilityData->capabilityBitmap);
    free(capabilityData);
}

static int32_t NSTACKX_CapabilityHandle(uint32_t capabilityBitmapNum, uint32_t capabilityBitmap[], EventHandle handle)
{
    Coverity_Tainted_Set((void *)&capabilityBitmapNum);
    Coverity_Tainted_Set((void *)capabilityBitmap);

    CapabilityProcessData *capabilityData = NULL;

    if (g_nstackInitState != NSTACKX_INIT_STATE_DONE) {
        DFINDER_LOGE(TAG, "NSTACKX_Ctrl is not initiated yet");
        return NSTACKX_EFAILED;
    }

    if (capabilityBitmapNum != 0 && capabilityBitmap == NULL) {
        DFINDER_LOGE(TAG, "bitmap array is null");
        return NSTACKX_EFAILED;
    }

    if (capabilityBitmapNum > NSTACKX_MAX_CAPABILITY_NUM) {
        DFINDER_LOGE(TAG, "capabilityBitmapNum (%u) exceed max number", capabilityBitmapNum);
        return NSTACKX_EINVAL;
    }

    if (g_nstackThreadInitState != NSTACKX_INIT_STATE_DONE) {
        if (handle == RegisterCapabilityInner) {
            return (int32_t)SetLocalDeviceCapability(capabilityBitmapNum, capabilityBitmap);
        }
        if (handle == SetFilterCapabilityInner) {
            return SetFilterCapability(capabilityBitmapNum, capabilityBitmap);
        }
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
    DFINDER_LOGD(TAG, "begin to call NSTACKX_RegisterCapability");
    return NSTACKX_CapabilityHandle(capabilityBitmapNum, capabilityBitmap, RegisterCapabilityInner);
}

int32_t NSTACKX_SetFilterCapability(uint32_t capabilityBitmapNum, uint32_t capabilityBitmap[])
{
    DFINDER_LOGI(TAG, "Set Filter Capability");
    return NSTACKX_CapabilityHandle(capabilityBitmapNum, capabilityBitmap, SetFilterCapabilityInner);
}
typedef struct {
    uint32_t maxDeviceNum;
    sem_t wait;
} SetMaxDeviceNumMsg;

static void SetMaxDeviceNumInner(void *argument)
{
    SetMaxDeviceNumMsg *msg = (SetMaxDeviceNumMsg *)argument;
    SetMaxDeviceNum(msg->maxDeviceNum);
    SemPost(&msg->wait);
}

int32_t NSTACKX_SetMaxDeviceNum(uint32_t maxDeviceNum)
{
    SetMaxDeviceNumMsg msg = {
        .maxDeviceNum = maxDeviceNum,
    };
    if (g_nstackInitState != NSTACKX_INIT_STATE_DONE) {
        DFINDER_LOGE(TAG, "NSTACKX_Ctrl is not initiated yet");
        return NSTACKX_EFAILED;
    }
    if (g_nstackThreadInitState != NSTACKX_INIT_STATE_DONE) {
        SetMaxDeviceNum(maxDeviceNum);
        return NSTACKX_EOK;
    }
    if (SemInit(&msg.wait, 0, 0)) {
        DFINDER_LOGE(TAG, "Failed to init sem!");
        return NSTACKX_EFAILED;
    }
    if (PostEvent(&g_eventNodeChain, g_epollfd, SetMaxDeviceNumInner, &msg) != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "Failed to set max device num!");
        SemDestroy(&msg.wait);
        return NSTACKX_EFAILED;
    }
    SemWait(&msg.wait);
    SemDestroy(&msg.wait);
    return NSTACKX_EOK;
}

#ifdef DFINDER_SAVE_DEVICE_LIST
int32_t NSTACKX_SetDeviceListAgingTime(uint32_t agingTime)
{
    if (g_nstackInitState != NSTACKX_INIT_STATE_DONE) {
        DFINDER_LOGE(TAG, "NSTACKX_Ctrl is not initiated yet");
        return NSTACKX_EFAILED;
    }
    SetDeviceListAgingTime(agingTime);
    return NSTACKX_EOK;
}
#else
int32_t NSTACKX_SetDeviceListAgingTime(uint32_t agingTime)
{
    (void)agingTime;
    DFINDER_LOGE(TAG, "device list not supported");
    return NSTACKX_EFAILED;
}
#endif /* END OF DFINDER_SAVE_DEVICE_LIST */

int32_t NSTACKX_ScreenStatusChange(bool isScreenOn)
{
#ifdef DFINDER_SUPPORT_SET_SCREEN_STATUS
    SetScreenStatus(isScreenOn);
#else
    (void)isScreenOn;
    DFINDER_LOGI(TAG, "do not support set screen status");
#endif
    return NSTACKX_EOK;
}

static void RegisterServiceDataInner(void *argument)
{
    char *serviceData = argument;
    if (SetLocalDeviceServiceData(serviceData) != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "RegisterServiceData failed");
    }
    free(serviceData);
}

int32_t NSTACKX_RegisterServiceData(const char *serviceData)
{
    Coverity_Tainted_Set((void *)serviceData);

    DFINDER_LOGD(TAG, "begin to call NSTACKX_RegisterServiceData");
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
    if (g_nstackThreadInitState != NSTACKX_INIT_STATE_DONE) {
        return SetLocalDeviceServiceData(serviceData);
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

static void RegisterBusinessDataInner(void *argument)
{
    DFINDER_LOGI(TAG, "Register Business Data Inner");
    char *businessData = argument;
    if (SetLocalDeviceBusinessData(businessData, NSTACKX_TRUE) != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "RegisterBusinessData failed");
    }
    free(businessData);
}

int32_t NSTACKX_RegisterBusinessData(const char *businessData)
{
    DFINDER_LOGI(TAG, "begin to call NSTACKX_RegisterBusinessData");

    char *businessDataTmp = NULL;
    if (businessData == NULL) {
        DFINDER_LOGE(TAG, "businessData is null");
        return NSTACKX_EINVAL;
    }
    if (g_nstackInitState != NSTACKX_INIT_STATE_DONE) {
        DFINDER_LOGE(TAG, "NSTACKX_Ctrl is not initiated yet");
        return NSTACKX_EFAILED;
    }
    if (strlen(businessData) >= NSTACKX_MAX_BUSINESS_DATA_LEN) {
        DFINDER_LOGE(TAG, "businessData (%u) exceed max data len", strlen(businessData));
        return NSTACKX_EINVAL;
    }
    if (g_nstackThreadInitState != NSTACKX_INIT_STATE_DONE) {
        return (int32_t)SetLocalDeviceBusinessData(businessData, NSTACKX_TRUE);
    }

    businessDataTmp = calloc(1, NSTACKX_MAX_BUSINESS_DATA_LEN);
    if (businessDataTmp == NULL) {
        DFINDER_LOGE(TAG, "businessDataTmp is null");
        return NSTACKX_ENOMEM;
    }
    if (strncpy_s(businessDataTmp, NSTACKX_MAX_BUSINESS_DATA_LEN, businessData,
        strlen(businessData)) != EOK) {
        DFINDER_LOGE(TAG, "Failed to copy businessData");
        free(businessDataTmp);
        return NSTACKX_EFAILED;
    }
    if (PostEvent(&g_eventNodeChain, g_epollfd, RegisterBusinessDataInner, businessDataTmp) != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "Failed to register businessData!");
        free(businessDataTmp);
        return NSTACKX_EFAILED;
    }

    return NSTACKX_EOK;
}

#ifndef DFINDER_USE_MINI_NSTACKX
static void RegisterExtendServiceDataInner(void *argument)
{
    char *extendServiceData = argument;
    if (SetLocalDeviceExtendServiceData(extendServiceData) != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "RegisterExtendServiceData failed");
    }
    free(extendServiceData);
}
#endif

int32_t NSTACKX_RegisterExtendServiceData(const char *extendServiceData)
{
#ifndef DFINDER_USE_MINI_NSTACKX
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
    if (g_nstackThreadInitState != NSTACKX_INIT_STATE_DONE) {
        return SetLocalDeviceExtendServiceData(extendServiceData);
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
#else
    (void)extendServiceData;
    DFINDER_LOGI(TAG, "NSTACKX_RegisterExtendServiceData not supported");
    return NSTACKX_EOK;
#endif
}

#ifndef DFINDER_USE_MINI_NSTACKX
struct DirectMsgCtx {
    MsgCtx msg;
    const char *ipStr;
    struct in_addr ip;
};

static void SendMsgDirectInner(void *arg)
{
    struct DirectMsgCtx *msg = arg;
    DFINDER_LOGD(TAG, "Enter WifiDirect send");
    msg->msg.err = CoapSendServiceMsg(&msg->msg, msg->ipStr, &msg->ip);
    SemPost(&msg->msg.wait);
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

static int MsgCtxInit(MsgCtx *msg, const char *moduleName, const char *deviceId, const uint8_t *data, uint32_t len)
{
    if (SemInit(&msg->wait, 0, 0)) {
        DFINDER_LOGE(TAG, "sem init fail");
        return NSTACKX_EFAILED;
    }

    msg->deviceId = deviceId;
    msg->moduleName = moduleName;
    msg->data = data;
    msg->len = len;
    msg->err = NSTACKX_EOK;

    return NSTACKX_EOK;
}
#endif

int32_t NSTACKX_SendMsgDirect(const char *moduleName, const char *deviceId, const uint8_t *data,
    uint32_t len, const char *ipaddr, uint8_t type)
{
#ifndef DFINDER_USE_MINI_NSTACKX
    int32_t ret = NSTACKX_EOK;
    DFINDER_LOGD(TAG, "NSTACKX_SendMsgDirect");
    if (g_nstackThreadInitState != NSTACKX_INIT_STATE_DONE) {
        DFINDER_LOGE(TAG, "NSTACKX_Ctrl is not initiated yet");
        return NSTACKX_EFAILED;
    }
    if (ipaddr == NULL) {
        DFINDER_LOGE(TAG, "ipaddr needed");
        return NSTACKX_EINVAL;
    }

    if (type > SERVER_TYPE_USB) {
        DFINDER_LOGE(TAG, "invalid type %hhu", type);
        return NSTACKX_EINVAL;
    }

    if (NSTACKX_SendMsgParamCheck(moduleName, deviceId, data, len) != NSTACKX_EOK) {
        return NSTACKX_EINVAL;
    }

    struct DirectMsgCtx directMsg;
    if (inet_pton(AF_INET, ipaddr, &directMsg.ip) != 1 || directMsg.ip.s_addr == 0) {
        DFINDER_LOGE(TAG, "invalid ip addr");
        return NSTACKX_EINVAL;
    }
    directMsg.ipStr = ipaddr;
    directMsg.msg.type = type;
    if (MsgCtxInit(&directMsg.msg, moduleName, deviceId, data, len) != NSTACKX_EOK) {
        return NSTACKX_EFAILED;
    }

    if (PostEvent(&g_eventNodeChain, g_epollfd, SendMsgDirectInner, &directMsg) != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "Failed to send msg");
        ret = NSTACKX_EFAILED;
    }
    if (ret == NSTACKX_EOK) {
        SemWait(&directMsg.msg.wait);
        ret = directMsg.msg.err;
    }
    SemDestroy(&directMsg.msg.wait);
    return ret;
#else
    (void)moduleName;
    (void)deviceId;
    (void)data;
    (void)len;
    (void)ipaddr;
    (void)type;
    DFINDER_LOGI(TAG, "NSTACKX_SendMsgDirect not supported");
    return NSTACKX_EFAILED;
#endif
}

#if defined(DFINDER_SAVE_DEVICE_LIST) && !defined(DFINDER_USE_MINI_NSTACKX)
static void SendMsgInner(void *arg)
{
    MsgCtx *msg = arg;
    const struct in_addr *remoteIp = GetRemoteDeviceIp(msg->deviceId);
    if (remoteIp == NULL) {
        DFINDER_LOGE(TAG, "no device found");
        msg->err = NSTACKX_EINVAL;
    } else {
        char ipStr[INET_ADDRSTRLEN] = {0};
        if (inet_ntop(AF_INET, remoteIp, ipStr, sizeof(ipStr)) != NULL) {
            msg->err = CoapSendServiceMsg(msg, ipStr, remoteIp);
        } else {
            DFINDER_LOGE(TAG, "ip format failed");
        }
    }

    SemPost(&msg->wait);
}
#endif

int32_t NSTACKX_SendMsg(const char *moduleName, const char *deviceId, const uint8_t *data, uint32_t len)
{
    Coverity_Tainted_Set((void *)moduleName);
    Coverity_Tainted_Set((void *)deviceId);
    Coverity_Tainted_Set((void *)data);
    Coverity_Tainted_Set((void *)&len);
#if defined(DFINDER_SAVE_DEVICE_LIST) && !defined(DFINDER_USE_MINI_NSTACKX)
    int32_t ret = NSTACKX_EOK;
    if (g_nstackThreadInitState != NSTACKX_INIT_STATE_DONE) {
        DFINDER_LOGE(TAG, "NSTACKX_Ctrl is not initiated yet");
        return NSTACKX_EFAILED;
    }
    if (NSTACKX_SendMsgParamCheck(moduleName, deviceId, data, len) != NSTACKX_EOK) {
        return NSTACKX_EINVAL;
    }

    MsgCtx msg;
    msg.type = INVALID_TYPE;
    if (MsgCtxInit(&msg, moduleName, deviceId, data, len) != NSTACKX_EOK) {
        return NSTACKX_EFAILED;
    }

    if (PostEvent(&g_eventNodeChain, g_epollfd, SendMsgInner, &msg) != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "failed to send msg");
        ret = NSTACKX_EFAILED;
    }
    if (ret == NSTACKX_EOK) {
        SemWait(&msg.wait);
        ret = msg.err;
    }
    SemDestroy(&msg.wait);
    return ret;
#else
    (void)moduleName;
    (void)deviceId;
    (void)data;
    (void)len;
    DFINDER_LOGI(TAG, "SendMsg not supported");
    return NSTACKX_EFAILED;
#endif
}

static void SendDiscoveryRspInner(void *arg)
{
    NSTACKX_ResponseSettings *responseSettings = arg;
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
    if (g_nstackThreadInitState != NSTACKX_INIT_STATE_DONE) {
        DFINDER_LOGE(TAG, "NSTACKX_Ctrl is not initiated yet");
        return NSTACKX_EFAILED;
    }
    if (CheckResponseSettings(responseSettings) != NSTACKX_EOK) {
        return NSTACKX_EINVAL;
    }

    DFINDER_LOGI(TAG, "response settings, business type: %hu, local network name: %s",
        responseSettings->businessType, responseSettings->localNetworkName);

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

    GetDeviceList(message->deviceList, message->deviceCountPtr, true);
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
    if (g_nstackThreadInitState != NSTACKX_INIT_STATE_DONE) {
        GetDeviceList(deviceList, deviceCountPtr, true);
        return NSTACKX_EOK;
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

void NotificationReceived(const NSTACKX_NotificationConfig *notification)
{
    if (g_parameter.onNotificationReceived != NULL) {
        DFINDER_LOGI(TAG, "notify callback: notification received");
        g_parameter.onNotificationReceived(notification);
        DFINDER_LOGI(TAG, "finish to notify notification received");
    } else {
        DFINDER_LOGI(TAG, "notify callback: notification received callback is null");
    }
}

#ifndef DFINDER_USE_MINI_NSTACKX
void NotifyMsgReceived(const char *moduleName, const char *deviceId, const uint8_t *data,
    uint32_t len, const char *srcIp)
{
    if (g_parameter.onMsgReceived != NULL) {
        DFINDER_LOGI(TAG, "notify callback: message received, data length %u", len);
        g_parameter.onMsgReceived(moduleName, deviceId, data, len, srcIp);
        DFINDER_LOGI(TAG, "finish to notify msg received");
    } else {
        DFINDER_LOGI(TAG, "notify callback: message received callback is null");
    }
}

int32_t NSTACKX_InitRestart(const NSTACKX_Parameter *parameter)
{
    Coverity_Tainted_Set((void *)parameter);

#if defined(_WIN32) || defined(DFINDER_USE_MINI_NSTACKX)
    DFINDER_LOGE(TAG, "do not support init restart");
    (void)parameter;
    return NSTACKX_EFAILED;
#else
    DFINDER_LOGI(TAG, "NSTACKX_InitRestart");
    int32_t ret = NSTACKX_Init(parameter);
    if (ret == NSTACKX_EOK) {
        if (PostEvent(&g_eventNodeChain, g_epollfd, DetectLocalIface, NULL) != NSTACKX_EOK) {
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
    if (g_nstackThreadInitState != NSTACKX_INIT_STATE_DONE) {
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
    DFINDER_LOGE(TAG, "unsupport dfinder dump");
    return NSTACKX_NOTSUPPORT;
}
#endif

int NSTACKX_DFinderSetEventFunc(void *softobj, DFinderEventFunc func)
{
    if (g_nstackInitState != NSTACKX_INIT_STATE_DONE) {
        DFINDER_LOGE(TAG, "NSTACKX_Ctrl is not initiated yet");
        return NSTACKX_EFAILED;
    }
    if (g_nstackThreadInitState != NSTACKX_INIT_STATE_DONE) {
        return SetEventFuncDirectly(softobj, func);
    }

    return SetEventFunc(softobj, func);
}

static int32_t CheckNotificationConfig(const NSTACKX_NotificationConfig *config)
{
    if (config == NULL) {
        DFINDER_LOGE(TAG, "notification config passed in is null");
        return NSTACKX_EINVAL;
    }
    if (config->businessType >= NSTACKX_BUSINESS_TYPE_MAX) {
        DFINDER_LOGE(TAG, "invalid business type %hhu in notification config", config->businessType);
        return NSTACKX_EINVAL;
    }
    if (config->msg == NULL) {
        DFINDER_LOGE(TAG, "msg in notification config is null");
        return NSTACKX_EINVAL;
    }
    if (strlen(config->msg) != config->msgLen || config->msgLen == 0 ||
        config->msgLen >= NSTACKX_MAX_NOTIFICATION_DATA_LEN) {
        DFINDER_LOGE(TAG, "actual msg len %zu, msg len %zu in config", strlen(config->msg), config->msgLen);
        return NSTACKX_EINVAL;
    }
    // advertise count: [0, 100], first interval in intervalMs should be 0
    if (config->intervalLen == 0 || config->intervalLen > NSTACKX_MAX_ADVERTISE_COUNT) {
        DFINDER_LOGE(TAG, "invalid interval len %hhu in notification config, max support %d",
            config->intervalLen, NSTACKX_MAX_ADVERTISE_COUNT);
        return NSTACKX_EINVAL;
    }
    if (config->intervalsMs == NULL) {
        DFINDER_LOGE(TAG, "broadcast intervals in notification config is null");
        return NSTACKX_EINVAL;
    }
    // interval: [0 ms, 10000 ms]
    if (config->intervalsMs[0] != 0) {
        DFINDER_LOGE(TAG, "first interval should be 0 to indicate send notification immediately");
        return NSTACKX_EINVAL;
    }
    for (size_t i = 1; i < config->intervalLen; ++i) {
        if (config->intervalsMs[i] < NSTACKX_MIN_ADVERTISE_INTERVAL ||
            config->intervalsMs[i] > NSTACKX_MAX_ADVERTISE_INTERVAL) {
            DFINDER_LOGE(TAG, "invalid interval[%zu] = %hu, support max: %d min: %d",
                i, config->intervalsMs[i], NSTACKX_MAX_ADVERTISE_INTERVAL, NSTACKX_MIN_ADVERTISE_INTERVAL);
            return NSTACKX_EINVAL;
        }
    }
    return NSTACKX_EOK;
}

static int32_t CopyNotificationConfig(NSTACKX_NotificationConfig *dst, const NSTACKX_NotificationConfig *src)
{
    dst->businessType = src->businessType;
    if (strncpy_s(dst->msg, src->msgLen + 1, src->msg, src->msgLen) != EOK) {
        DFINDER_LOGE(TAG, "copy notification msg to duplicated one fail");
        return NSTACKX_EFAILED;
    }
    dst->msgLen = src->msgLen;
    for (size_t i = 0; i < src->intervalLen; ++i) {
        (dst->intervalsMs)[i] = (src->intervalsMs)[i];
    }
    dst->intervalLen = src->intervalLen;
    return NSTACKX_EOK;
}

static void NotificationInner(void *argument)
{
    NSTACKX_NotificationConfig *config = (NSTACKX_NotificationConfig *)argument;
    int32_t retMsg = LocalizeNotificationMsg(config->msg);
    int32_t retInterval = LocalizeNotificationInterval(config->intervalsMs, config->intervalLen);
    free(config->intervalsMs);
    free(config->msg);
    free(config);
    if (retMsg != NSTACKX_EOK || retInterval != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "stop running service notification cause localize config fail");
        return;
    }
    CoapServiceNotification();
}

int32_t NSTACKX_SendNotification(const NSTACKX_NotificationConfig *config)
{
    DFINDER_LOGI(TAG, "begin to call NSTACKX_SendNotification");

    if (g_nstackThreadInitState != NSTACKX_INIT_STATE_DONE) {
        DFINDER_LOGE(TAG, "dfinder not inited");
        return NSTACKX_EFAILED;
    }
    if (CheckNotificationConfig(config) != NSTACKX_EOK) {
        return NSTACKX_EINVAL;
    }
    NSTACKX_NotificationConfig *dupConfig = (NSTACKX_NotificationConfig *)calloc(1, sizeof(NSTACKX_NotificationConfig));
    if (dupConfig == NULL) {
        DFINDER_LOGE(TAG, "calloc for notification config fail, size wanted: %zu", sizeof(NSTACKX_NotificationConfig));
        return NSTACKX_ENOMEM;
    }
    dupConfig->msg = (char *)calloc((config->msgLen + 1), sizeof(char));
    if (dupConfig->msg == NULL) {
        DFINDER_LOGE(TAG, "calloc for msg in notification fail, size wanted: %zu", config->msgLen + 1);
        free(dupConfig);
        return NSTACKX_ENOMEM;
    }
    dupConfig->intervalsMs = (uint16_t *)calloc(config->intervalLen, sizeof(uint16_t));
    if (dupConfig->intervalsMs == NULL) {
        DFINDER_LOGE(TAG, "calloc for intervals fail, size wanted: %zu", sizeof(uint16_t) * (config->intervalLen));
        free(dupConfig->msg);
        free(dupConfig);
        return NSTACKX_ENOMEM;
    }
    if (CopyNotificationConfig(dupConfig, config) != NSTACKX_EOK) {
        free(dupConfig->intervalsMs);
        free(dupConfig->msg);
        free(dupConfig);
        return NSTACKX_EFAILED;
    }
    if (PostEvent(&g_eventNodeChain, g_epollfd, NotificationInner, dupConfig) != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "post event failed to run notification inner");
        free(dupConfig->intervalsMs);
        free(dupConfig->msg);
        free(dupConfig);
        return NSTACKX_EFAILED;
    }
    return NSTACKX_EOK;
}

static void NotificationStop(void *argument)
{
    (void)argument;
    CoapServiceNotificationStop();
}

int32_t NSTACKX_StopSendNotification(uint8_t businessType)
{
    DFINDER_LOGI(TAG, "begin to call NSTACKX_StopSendNotification, business type: %hhu", businessType);

    if (g_nstackThreadInitState != NSTACKX_INIT_STATE_DONE) {
        DFINDER_LOGE(TAG, "dfinder not inited");
        return NSTACKX_EFAILED;
    }
    if (businessType >= NSTACKX_BUSINESS_TYPE_MAX) {
        DFINDER_LOGE(TAG, "invalid business type %hhu to stop send notification", businessType);
        return NSTACKX_EINVAL;
    }
    if (PostEvent(&g_eventNodeChain, g_epollfd, NotificationStop, NULL) != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "post event failed to run stop device discover");
        return NSTACKX_EFAILED;
    }
    return NSTACKX_EOK;
}
