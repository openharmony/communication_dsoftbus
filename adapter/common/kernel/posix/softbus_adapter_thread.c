/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "softbus_adapter_thread.h"

#include <pthread.h>
#include <sched.h>
#include <securec.h>
#include <string.h>

#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"

static pthread_mutex_t g_adapterStaticLock = PTHREAD_MUTEX_INITIALIZER;
/* mutex */
int32_t SoftBusMutexAttrInit(SoftBusMutexAttr *mutexAttr)
{
    if (mutexAttr == NULL) {
        COMM_LOGE(COMM_ADAPTER, "mutexAttr is null");
        return SOFTBUS_INVALID_PARAM;
    }

    mutexAttr->type = SOFTBUS_MUTEX_NORMAL;
    return SOFTBUS_OK;
}

int32_t SoftBusMutexInit(SoftBusMutex *mutex, SoftBusMutexAttr *mutexAttr)
{
    if (mutex == NULL) {
        COMM_LOGE(COMM_ADAPTER, "mutex is null");
        return SOFTBUS_INVALID_PARAM;
    }
    if (pthread_mutex_lock(&g_adapterStaticLock) != 0) {
        COMM_LOGE(COMM_ADAPTER, "mutex init : g_adapterStaticLock lock failed");
        return SOFTBUS_ERR;
    }
    if ((void *)*mutex != NULL) {
        (void)pthread_mutex_unlock(&g_adapterStaticLock);
        return SOFTBUS_OK;
    }
    pthread_mutex_t *tempMutex;
    tempMutex = (pthread_mutex_t *)SoftBusCalloc(sizeof(pthread_mutex_t));
    if (tempMutex == NULL) {
        COMM_LOGE(COMM_ADAPTER, "tempMutex is null");
        (void)pthread_mutex_unlock(&g_adapterStaticLock);
        return SOFTBUS_INVALID_PARAM;
    }

    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    if (mutexAttr == NULL) {
#ifndef __LITEOS_M__
        pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_NORMAL);
#else
        pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
#endif
    } else if (mutexAttr->type == SOFTBUS_MUTEX_NORMAL) {
        pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_NORMAL);
    } else if (mutexAttr->type == SOFTBUS_MUTEX_RECURSIVE) {
        pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
    }

    int32_t ret = pthread_mutex_init(tempMutex, &attr);
    if (ret != 0) {
        COMM_LOGE(COMM_ADAPTER, "SoftBusMutexInit failed, ret=%{public}d", ret);
        SoftBusFree(tempMutex);
        tempMutex = NULL;
        (void)pthread_mutex_unlock(&g_adapterStaticLock);
        return SOFTBUS_ERR;
    }

    *mutex = (SoftBusMutex)tempMutex;
    (void)pthread_mutex_unlock(&g_adapterStaticLock);
    return SOFTBUS_OK;
}

int32_t SoftBusMutexLockInner(SoftBusMutex *mutex)
{
    return pthread_mutex_lock((pthread_mutex_t *)*mutex);
}

int32_t SoftBusMutexUnlockInner(SoftBusMutex *mutex)
{
    return pthread_mutex_unlock((pthread_mutex_t *)*mutex);
}

int32_t SoftBusMutexDestroy(SoftBusMutex *mutex)
{
    if ((mutex == NULL) || ((void *)(*mutex) == NULL)) {
        COMM_LOGD(COMM_ADAPTER, "mutex is null");
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t ret = pthread_mutex_destroy((pthread_mutex_t *)*mutex);
    if (ret != 0) {
        COMM_LOGE(COMM_ADAPTER, "SoftBusMutexDestroy failed, ret=%{public}d", ret);
        SoftBusFree((void *)*mutex);
        *mutex = (SoftBusMutex)NULL;
        return SOFTBUS_ERR;
    }

    SoftBusFree((void *)*mutex);
    *mutex = (SoftBusMutex)NULL;
    return SOFTBUS_OK;
}

/* pthread */
int32_t SoftBusThreadAttrInit(SoftBusThreadAttr *threadAttr)
{
    if (threadAttr == NULL) {
        COMM_LOGE(COMM_ADAPTER, "threadAttr is null");
        return SOFTBUS_INVALID_PARAM;
    }

#ifndef __LITEOS_M__
    threadAttr->policy = SOFTBUS_SCHED_OTHER;
#else
    threadAttr->policy = SOFTBUS_SCHED_RR;
#endif
    threadAttr->detachState = SOFTBUS_THREAD_JOINABLE;
    threadAttr->stackSize = 0;
    threadAttr->prior = SOFTBUS_PRIORITY_DEFAULT;
    threadAttr->taskName = NULL;

    return SOFTBUS_OK;
}

static int32_t SoftbusSetThreadPolicy(SoftBusThreadAttr *threadAttr, pthread_attr_t *attr)
{
    if (threadAttr->policy == SOFTBUS_SCHED_OTHER) {
        pthread_attr_setschedpolicy(attr, SCHED_OTHER);
    } else if (threadAttr->policy == SOFTBUS_SCHED_RR) {
        pthread_attr_setschedpolicy(attr, SCHED_RR);
    } else {
        COMM_LOGE(COMM_ADAPTER, "set policy error");
        return SOFTBUS_INVALID_PARAM;
    }

    return SOFTBUS_OK;
}

static int32_t SoftbusSetThreadDetachState(SoftBusThreadAttr *threadAttr, pthread_attr_t *attr)
{
    if (threadAttr->detachState == SOFTBUS_THREAD_JOINABLE) {
        pthread_attr_setdetachstate(attr, PTHREAD_CREATE_JOINABLE);
    } else if (threadAttr->detachState == SOFTBUS_THREAD_DETACH) {
        pthread_attr_setdetachstate(attr, PTHREAD_CREATE_DETACHED);
    } else {
        COMM_LOGE(COMM_ADAPTER, "set detachState error");
        return SOFTBUS_INVALID_PARAM;
    }

    return SOFTBUS_OK;
}

static int32_t SoftbusSetThreadPeriority(SoftBusThreadAttr *threadAttr, pthread_attr_t *attr)
{
#ifdef __linux__
    /* periorityParam is between 1 and 99 in linux */
    #define PTHREAD_PERIOR_LOWEST 1
    #define PTHREAD_PERIOR_LOW 33
    #define PTHREAD_PERIOR_HIGH 66
    #define PTHREAD_PERIOR_HIGHEST 99
#else
    /* periorityParam is between 0 and 31 in liteOS */
    #define PTHREAD_PERIOR_LOWEST 30
    #define PTHREAD_PERIOR_LOW 20
    #define PTHREAD_PERIOR_HIGH 10
    #define PTHREAD_PERIOR_HIGHEST 0
#endif

    struct sched_param periorityParam;
    (void)memset_s(&periorityParam, sizeof(periorityParam), 0, sizeof(periorityParam));
    struct sched_param defaultPeri;
    pthread_attr_getschedparam(attr, &defaultPeri);
    switch (threadAttr->prior) {
        case SOFTBUS_PRIORITY_DEFAULT:
            periorityParam.sched_priority = defaultPeri.sched_priority;
            break;
        case SOFTBUS_PRIORITY_LOWEST:
            periorityParam.sched_priority = PTHREAD_PERIOR_LOWEST;
            break;
        case SOFTBUS_PRIORITY_LOW:
            periorityParam.sched_priority = PTHREAD_PERIOR_LOW;
            break;
        case SOFTBUS_PRIORITY_HIGH:
            periorityParam.sched_priority = PTHREAD_PERIOR_HIGH;
            break;
        case SOFTBUS_PRIORITY_HIGHEST:
            periorityParam.sched_priority = PTHREAD_PERIOR_HIGHEST;
            break;
        default:
            periorityParam.sched_priority = defaultPeri.sched_priority;
            break;
    }
    pthread_attr_setschedparam(attr, &periorityParam);

    return SOFTBUS_OK;
}

static int32_t SoftBusConfTransPthreadAttr(SoftBusThreadAttr *threadAttr, pthread_attr_t *attr)
{
    if ((threadAttr == NULL) || (attr == NULL)) {
        COMM_LOGE(COMM_ADAPTER, "threadAttr or attr is null");
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t ret = SoftbusSetThreadPolicy(threadAttr, attr);
    if (ret != SOFTBUS_OK) {
        COMM_LOGE(COMM_ADAPTER, "SoftbusSetThreadPolicy failed, ret=%{public}d", ret);
        return SOFTBUS_ERR;
    }

    ret = SoftbusSetThreadDetachState(threadAttr, attr);
    if (ret != SOFTBUS_OK) {
        COMM_LOGE(COMM_ADAPTER, "SoftbusSetThreadDetachState failed, ret=%{public}d", ret);
        return SOFTBUS_ERR;
    }

    ret = SoftbusSetThreadPeriority(threadAttr, attr);
    if (ret != SOFTBUS_OK) {
        COMM_LOGE(COMM_ADAPTER, "SoftbusSetThreadPeriority failed, ret=%{public}d", ret);
        return SOFTBUS_ERR;
    }

    uint64_t stackSize = threadAttr->stackSize;
    if (stackSize != 0) {
        ret = pthread_attr_setstacksize(attr, stackSize);
        if (ret != 0) {
            COMM_LOGE(COMM_ADAPTER, "pthread_attr_setstacksize failed, ret=%{public}d", ret);
            return SOFTBUS_ERR;
        }
    }

    return SOFTBUS_OK;
}

int32_t SoftBusThreadCreate(SoftBusThread *thread, SoftBusThreadAttr *threadAttr,
    void *(*threadEntry) (void *), void *arg)
{
    if (thread == NULL) {
        COMM_LOGE(COMM_ADAPTER, "thread is null");
        return SOFTBUS_INVALID_PARAM;
    }

    if (threadEntry == NULL) {
        COMM_LOGE(COMM_ADAPTER, "threadEntry is null");
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t ret;
    if (threadAttr == NULL) {
        ret = pthread_create((pthread_t *)thread, NULL, threadEntry, arg);
        if (ret != 0) {
            COMM_LOGE(COMM_ADAPTER, "Thread create failed, ret=%{public}d", ret);
            return SOFTBUS_ERR;
        }
    } else {
        pthread_attr_t attr;
        ret = pthread_attr_init(&attr);
        if (ret != 0) {
            COMM_LOGE(COMM_ADAPTER, "pthread_attr_init failed, ret=%{public}d", ret);
            return SOFTBUS_ERR;
        }
        ret = SoftBusConfTransPthreadAttr(threadAttr, &attr);
        if (ret != 0) {
            COMM_LOGE(COMM_ADAPTER, "SoftBusConfTransPthreadAttr failed, ret=%{public}d", ret);
            return SOFTBUS_ERR;
        }
        ret = pthread_create((pthread_t *)thread, &attr, threadEntry, arg);
        if (ret != 0) {
            COMM_LOGE(COMM_ADAPTER, "Thread create failed, ret=%{public}d", ret);
            return SOFTBUS_ERR;
        }

        if (threadAttr->taskName != NULL) {
            ret = SoftBusThreadSetName(*thread, threadAttr->taskName);
            if (ret != 0) {
                COMM_LOGE(COMM_ADAPTER, "Thread set name failed, ret=%{public}d", ret);
            }
        }
    }

    return SOFTBUS_OK;
}

int32_t SoftBusThreadJoin(SoftBusThread thread, void **value)
{
    if (thread <= 0) {
        COMM_LOGE(COMM_ADAPTER, "thread is invalid");
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t ret = pthread_join((pthread_t)thread, value);
    if (ret != 0) {
        COMM_LOGE(COMM_ADAPTER, "Thread join failed, ret=%{public}d", ret);
        return SOFTBUS_ERR;
    }

    return SOFTBUS_OK;
}

int32_t SoftBusThreadSetName(SoftBusThread thread, const char *name)
{
    if (thread <= 0) {
        COMM_LOGE(COMM_ADAPTER, "thread is invalid");
        return SOFTBUS_INVALID_PARAM;
    }

    if (name == NULL) {
        COMM_LOGE(COMM_ADAPTER, "name is null");
        return SOFTBUS_INVALID_PARAM;
    }

    if (strlen(name) >= TASK_NAME_MAX_LEN) {
        COMM_LOGE(COMM_ADAPTER, "set thread name length >= TASK_NAME_MAX_LEN");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = pthread_setname_np((pthread_t)thread, name);
    if (ret != 0) {
        COMM_LOGE(COMM_ADAPTER, "Thread set name failed, ret=%{public}d", ret);
        return SOFTBUS_ERR;
    }

    return SOFTBUS_OK;
}

SoftBusThread SoftBusThreadGetSelf(void)
{
    return (SoftBusThread)pthread_self();
}

/* cond */
int32_t SoftBusCondInit(SoftBusCond *cond)
{
    if (cond == NULL) {
        COMM_LOGE(COMM_ADAPTER, "cond is null");
        return SOFTBUS_INVALID_PARAM;
    }
    pthread_condattr_t attr = {0};
    int32_t ret = pthread_condattr_init(&attr);
    if (ret != 0) {
        COMM_LOGE(COMM_ADAPTER, "pthread_condattr_init failed, ret=%{public}d", ret);
        return SOFTBUS_ERR;
    }
    ret = pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
    if (ret != 0) {
        COMM_LOGE(COMM_ADAPTER, "set clock failed, ret=%{public}d", ret);
        return SOFTBUS_ERR;
    }

    pthread_cond_t *tempCond = (pthread_cond_t *)SoftBusCalloc(sizeof(pthread_cond_t));
    if (tempCond == NULL) {
        COMM_LOGE(COMM_ADAPTER, "tempCond is null");
        return SOFTBUS_ERR;
    }
    ret = pthread_cond_init(tempCond, &attr);
    if (ret != 0) {
        COMM_LOGE(COMM_ADAPTER, "SoftBusCondInit failed, ret=%{public}d", ret);
        SoftBusFree(tempCond);
        tempCond = NULL;
        return SOFTBUS_ERR;
    }

    *cond = (SoftBusCond)tempCond;
    return SOFTBUS_OK;
}

int32_t SoftBusCondSignal(SoftBusCond *cond)
{
    if ((cond == NULL) || ((void *)(*cond) == NULL)) {
        COMM_LOGE(COMM_ADAPTER, "cond is null");
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t ret = pthread_cond_signal((pthread_cond_t *)*cond);
    if (ret != 0) {
        COMM_LOGE(COMM_ADAPTER, "SoftBusCondSignal failed, ret=%{public}d", ret);
        return SOFTBUS_ERR;
    }

    return SOFTBUS_OK;
}

int32_t SoftBusCondBroadcast(SoftBusCond *cond)
{
    if ((cond == NULL) || ((void *)(*cond) == NULL)) {
        COMM_LOGE(COMM_ADAPTER, "cond is null");
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t ret = pthread_cond_broadcast((pthread_cond_t *)*cond);
    if (ret != 0) {
        COMM_LOGE(COMM_ADAPTER, "SoftBusCondBroadcast failed, ret=%{public}d", ret);
        return SOFTBUS_ERR;
    }

    return SOFTBUS_OK;
}

int32_t SoftBusCondWait(SoftBusCond *cond, SoftBusMutex *mutex, SoftBusSysTime *time)
{
#define USECTONSEC 1000
    if ((cond == NULL) || ((void *)(*cond) == NULL)) {
        COMM_LOGE(COMM_ADAPTER, "cond is null");
        return SOFTBUS_INVALID_PARAM;
    }

    if ((mutex == NULL) || ((void *)(*mutex) == NULL)) {
        COMM_LOGE(COMM_ADAPTER, "mutex is null");
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t ret;
    if (time == NULL) {
        ret = pthread_cond_wait((pthread_cond_t *)*cond, (pthread_mutex_t *)*mutex);
        if (ret != 0) {
            COMM_LOGE(COMM_ADAPTER, "SoftBusCondWait failed, ret=%{public}d", ret);
            return SOFTBUS_ERR;
        }
    } else {
        struct timespec tv;
        tv.tv_sec = time->sec;
        tv.tv_nsec = time->usec * USECTONSEC;
        ret = pthread_cond_timedwait((pthread_cond_t *)*cond, (pthread_mutex_t *)*mutex, &tv);
        if (ret == ETIMEDOUT) {
            COMM_LOGD(COMM_ADAPTER, "SoftBusCondTimedWait timeout, ret=%{public}d", ret);
            return SOFTBUS_TIMOUT;
        }

        if (ret != 0) {
            COMM_LOGE(COMM_ADAPTER, "SoftBusCondTimedWait failed, ret=%{public}d", ret);
            return SOFTBUS_ERR;
        }
    }

    return SOFTBUS_OK;
}

int32_t SoftBusCondDestroy(SoftBusCond *cond)
{
    if ((cond == NULL) || ((void *)(*cond) == NULL)) {
        COMM_LOGE(COMM_ADAPTER, "cond is null");
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t ret = pthread_cond_destroy((pthread_cond_t *)*cond);
    if (ret != 0) {
        COMM_LOGE(COMM_ADAPTER, "SoftBusCondDestroy failed, ret=%{public}d", ret);
        SoftBusFree((void *)*cond);
        *cond = (SoftBusCond)NULL;
        return SOFTBUS_ERR;
    }

    SoftBusFree((void *)*cond);
    *cond = (SoftBusCond)NULL;
    return SOFTBUS_OK;
}
