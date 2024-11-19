/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "softbus_adapter_timer.h"

#include <sys/time.h>
#include <time.h>
#include "cmsis_os2.h"
#include "comm_log.h"
#include "softbus_error_code.h"

#define MS_PER_SECOND  1000
#define US_PER_MSECOND 1000
#define NS_PER_USECOND 1000

static TimerFunc g_timerFunc = NULL;

static void HandleTimeoutAdapterFun(void)
{
    if (g_timerFunc != NULL) {
        g_timerFunc();
    }
}

void SetTimerFunc(TimerFunc func)
{
    g_timerFunc = func;
}

void *SoftBusCreateTimer(void **timerId, unsigned int type)
{
    (void)timerId;

    void *id = osTimerNew((osTimerFunc_t)HandleTimeoutAdapterFun, (osTimerType_t)type, NULL, NULL);
    if (id != NULL) {
        COMM_LOGI(COMM_ADAPTER, "create timer success");
        return id;
    }
    COMM_LOGE(COMM_ADAPTER, "create timer failed");
    return NULL;
}

int SoftBusStartTimer(void *timerId, unsigned int ms)
{
    if (timerId == NULL) {
        COMM_LOGE(COMM_ADAPTER, "timerId is NULL");
        return SOFTBUS_ERR;
    }
    if (osTimerStart(timerId, ms * osKernelGetTickFreq() / MS_PER_SECOND) != osOK) {
        COMM_LOGE(COMM_ADAPTER, "start timer failed");
        (void)osTimerDelete(timerId);
        return SOFTBUS_ERR;
    }
    COMM_LOGI(COMM_ADAPTER, "start timer success");
    return SOFTBUS_OK;
}

int SoftBusDeleteTimer(void *timerId)
{
    if (timerId == NULL) {
        COMM_LOGE(COMM_ADAPTER, "timerId is NULL");
        return SOFTBUS_ERR;
    }
    if (osTimerDelete(timerId) != osOK) {
        COMM_LOGE(COMM_ADAPTER, "delete timer failed");
        return SOFTBUS_ERR;
    }
    COMM_LOGI(COMM_ADAPTER, "delete timer success");
    return SOFTBUS_OK;
}

int SoftBusSleepMs(unsigned int ms)
{
    osDelay(ms * osKernelGetTickFreq() / MS_PER_SECOND);
    return SOFTBUS_OK;
}

int32_t SoftBusGetTime(SoftBusSysTime *sysTime)
{
    if (sysTime == NULL) {
        COMM_LOGW(COMM_ADAPTER, "sysTime is null");
        return SOFTBUS_INVALID_PARAM;
    }
    struct timeval time = {0};
    gettimeofday(&time, NULL);
    sysTime->sec = time.tv_sec;
    sysTime->usec = time.tv_usec;
    return SOFTBUS_OK;
}

int32_t SoftBusGetRealTime(SoftBusSysTime *sysTime)
{
    if (sysTime == NULL) {
        COMM_LOGW(COMM_ADAPTER, "sysTime is null");
        return SOFTBUS_INVALID_PARAM;
    }
    struct timespec time = {0};
    (void)clock_gettime(CLOCK_BOOTTIME, &time);
    sysTime->sec = time.tv_sec;
    sysTime->usec = time.tv_nsec / NS_PER_USECOND;
    return SOFTBUS_OK;
}

uint64_t SoftBusGetSysTimeMs(void)
{
    struct timeval time;
    time.tv_sec = 0;
    time.tv_usec = 0;
    if (gettimeofday(&time, NULL) != 0) {
        COMM_LOGI(COMM_ADAPTER, "get sys time fail");
        return 0;
    }
    uint64_t ms = (uint64_t)time.tv_sec * MS_PER_SECOND + (uint64_t)time.tv_usec / US_PER_MSECOND;
    return ms;
}

const char *SoftBusFormatTimestamp(uint64_t timestamp)
{
    return "0000-00-00 00:00:00.000";
}
