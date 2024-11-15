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

#include <errno.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#ifdef SOFTBUS_STANDARD_OS
#include "ffrt.h"
#endif

#include "comm_log.h"
#include "securec.h"
#include "softbus_def.h"
#include "softbus_error_code.h"

#define MS_PER_SECOND 1000
#define US_PER_MSECOND 1000
#define NS_PER_USECOND 1000
#define DATE_TIME_BUFF_LEN 24 // yyyy-MM-dd HH:mm:ss.SSS

static unsigned int g_timerType;
__attribute__((no_sanitize("hwaddress"))) static TimerFunc g_timerFunc = NULL;
static _Thread_local char g_dateTimeBuff[DATE_TIME_BUFF_LEN] = {0};

__attribute__((no_sanitize("hwaddress"))) static void HandleTimeoutAdapterFun(union sigval para)
{
    (void)para;
    if (g_timerFunc != NULL) {
        g_timerFunc();
    }
}

__attribute__((no_sanitize("hwaddress"))) void SetTimerFunc(TimerFunc func)
{
    g_timerFunc = func;
}

#ifdef SOFTBUS_STANDARD_OS
static void HandleTimeoutFunWithFfrt(void *data)
{
    (void)data;
    if (g_timerFunc != NULL) {
        g_timerFunc();
    }
}

int32_t SoftBusStartTimerWithFfrt(int32_t *timerHandle, uint64_t timeout, bool repeat)
{
    if (timerHandle == NULL) {
        COMM_LOGE(COMM_ADAPTER, "timerHandle is null");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = ffrt_timer_start(ffrt_qos_default, timeout, NULL, HandleTimeoutFunWithFfrt, repeat);
    if (ret == ffrt_error) {
        COMM_LOGE(COMM_ADAPTER, "timer start with ffrt fail, ret=%{public}d", ret);
        return SOFTBUS_TIMER_ERR;
    }
    *timerHandle = ret;
    COMM_LOGI(COMM_ADAPTER, "timer start with ffrt succ, timerHandle=%{public}d", *timerHandle);
    return SOFTBUS_OK;
}

void SoftBusStopTimerWithFfrt(int32_t timerHandle)
{
    if (timerHandle < 0) {
        COMM_LOGE(COMM_ADAPTER, "invalid timerHandle=%{public}d", timerHandle);
        return;
    }
    int32_t ret = ffrt_timer_stop(ffrt_qos_default, timerHandle);
    if (ret != ffrt_success) {
        COMM_LOGE(COMM_ADAPTER, "timer stop with ffrt fail, timerHandle=%{public}d, ret=%{public}d", timerHandle, ret);
        return;
    }
    COMM_LOGI(COMM_ADAPTER, "timer stop with ffrt succ, timerHandle=%{public}d", timerHandle);
}
#endif

void *SoftBusCreateTimer(void **timerId, unsigned int type)
{
    if (timerId == NULL) {
        COMM_LOGE(COMM_ADAPTER, "timerId is null");
        return NULL;
    }
    struct sigevent envent;
    (void)memset_s(&envent, sizeof(envent), 0, sizeof(envent));
    envent.sigev_notify = SIGEV_THREAD;
    envent.sigev_notify_function = HandleTimeoutAdapterFun;
    envent.sigev_notify_attributes = NULL;

    g_timerType = type;
    if (timer_create(CLOCK_REALTIME, &envent, timerId) != 0) {
        COMM_LOGE(COMM_ADAPTER, "timer create error, errnoCode=%{public}d", errno);
        return NULL;
    }

    return *timerId;
}

int SoftBusStartTimer(void *timerId, unsigned int tickets)
{
    if (timerId == NULL) {
        COMM_LOGE(COMM_ADAPTER, "timerId is null");
        return SOFTBUS_ERR;
    }
    struct itimerspec value;
    (void)memset_s(&value, sizeof(value), 0, sizeof(value));
    value.it_value.tv_sec = tickets / MS_PER_SECOND;
    value.it_value.tv_nsec = 0;
    if (g_timerType == TIMER_TYPE_ONCE) {
        value.it_interval.tv_sec = 0;
        value.it_interval.tv_nsec = 0;
    } else {
        value.it_interval.tv_sec = tickets / MS_PER_SECOND;
        value.it_interval.tv_nsec = 0;
    }

    if (timer_settime(timerId, 0, &value, NULL) != 0) {
        COMM_LOGE(COMM_ADAPTER, "timer start error, errnoCode=%{public}d", errno);
        return SOFTBUS_ERR;
    }

    return SOFTBUS_OK;
}

int SoftBusDeleteTimer(void *timerId)
{
    if (timerId == NULL) {
        COMM_LOGE(COMM_ADAPTER, "timerId is null");
        return SOFTBUS_ERR;
    }

    if (timer_delete(timerId) != 0) {
        COMM_LOGE(COMM_ADAPTER, "timer delete err, errnoCode=%{public}d", errno);
        return SOFTBUS_ERR;
    }

    return SOFTBUS_OK;
}

int SoftBusSleepMs(unsigned int ms)
{
    int ret;
    struct timeval tm;
    tm.tv_sec = ms / MS_PER_SECOND;
    tm.tv_usec = (ms % MS_PER_SECOND) * US_PER_MSECOND;

    do {
        ret = select(0, NULL, NULL, NULL, &tm);
    } while ((ret == -1) && (errno == EINTR));

    return SOFTBUS_ERR;
}

int32_t SoftBusGetTime(SoftBusSysTime *sysTime)
{
    if (sysTime == NULL) {
        COMM_LOGI(COMM_ADAPTER, "sysTime is null");
        return SOFTBUS_INVALID_PARAM;
    }
    struct timespec time = {0};
    (void)clock_gettime(CLOCK_MONOTONIC, &time);

    sysTime->sec = time.tv_sec;
    sysTime->usec = time.tv_nsec / NS_PER_USECOND;
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
    return (uint64_t)time.tv_sec * MS_PER_SECOND + (uint64_t)time.tv_usec / US_PER_MSECOND;
}

const char *SoftBusFormatTimestamp(uint64_t timestamp)
{
    uint32_t milliseconds = timestamp % MS_PER_SECOND;
    time_t seconds = (time_t)(timestamp / MS_PER_SECOND);
    struct tm formatedDateTime;

#if (defined( __WINDOWS__ ))
    if (localtime_s(&formatedDateTime, &seconds) != 0) {
#else
    if (localtime_r(&seconds, &formatedDateTime) == NULL) {
#endif // __WINDOWS__
        COMM_LOGE(COMM_ADAPTER, "get localtime failed");
        return NULL;
    }

    const int32_t BASE_YEAR = 1900;
    const int32_t BASE_MONTH = 1;
    int32_t ret = sprintf_s(g_dateTimeBuff, DATE_TIME_BUFF_LEN, "%04d-%02d-%02d %02d:%02d:%02d.%03u",
        formatedDateTime.tm_year + BASE_YEAR, formatedDateTime.tm_mon + BASE_MONTH, formatedDateTime.tm_mday,
        formatedDateTime.tm_hour, formatedDateTime.tm_min, formatedDateTime.tm_sec, milliseconds);
    if (ret < 0) {
        COMM_LOGE(COMM_ADAPTER, "sprintf failed, ret=%{public}d", ret);
        return NULL;
    }

    g_dateTimeBuff[DATE_TIME_BUFF_LEN - 1] = '\0';
    return g_dateTimeBuff;
}
