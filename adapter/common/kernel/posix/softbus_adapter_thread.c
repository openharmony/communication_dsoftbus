/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#include <stdio.h>
#include <string.h>

#include "softbus_adapter_log.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "softbus_errcode.h"

static pthread_mutex_t g_adapterStaticLock = PTHREAD_MUTEX_INITIALIZER;
/* mutex */
int32_t SoftBusMutexAttrInit(SoftBusMutexAttr *mutexAttr)
{
    if (mutexAttr == NULL) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "mutexAttr is null");
        return SOFTBUS_INVALID_PARAM;
    }

    mutexAttr->type = SOFTBUS_MUTEX_NORMAL;
    return SOFTBUS_OK;
}

int32_t SoftBusMutexInit(SoftBusMutex *mutex, SoftBusMutexAttr *mutexAttr)
{
    if (pthread_mutex_lock(&g_adapterStaticLock) != 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "mutex init : g_adapterStaticLock lock failed");
        return SOFTBUS_ERR;
    }
    if (mutex == NULL) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "mutex is null");
        (void)pthread_mutex_unlock(&g_adapterStaticLock);
        return SOFTBUS_INVALID_PARAM;
    }
    if ((void *)*mutex != NULL) {
        HILOG_WARN(SOFTBUS_HILOG_ID, "mutex is already init");
        (void)pthread_mutex_unlock(&g_adapterStaticLock);
        return SOFTBUS_OK;
    }
    pthread_mutex_t *tempMutex;
    tempMutex = (pthread_mutex_t *)SoftBusCalloc(sizeof(pthread_mutex_t));
    if (tempMutex == NULL) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "tempMutex is null");
        (void)pthread_mutex_unlock(&g_adapterStaticLock);
        return SOFTBUS_INVALID_PARAM;
    }

    int ret;
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

    ret = pthread_mutex_init(tempMutex, &attr);
    if (ret != 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "SoftBusMutexInit failed, ret[%{public}d]", ret);
        SoftBusFree(tempMutex);
        tempMutex = NULL;
        (void)pthread_mutex_unlock(&g_adapterStaticLock);
        return SOFTBUS_ERR;
    }

    *mutex = (SoftBusMutex)tempMutex;
    (void)pthread_mutex_unlock(&g_adapterStaticLock);
    return SOFTBUS_OK;
}

int32_t SoftBusMutexLock(SoftBusMutex *mutex)
{
    if ((mutex == NULL) || ((void *)(*mutex) == NULL)) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "mutex is null");
        return SOFTBUS_INVALID_PARAM;
    }

    int ret;
    ret = pthread_mutex_lock((pthread_mutex_t *)*mutex);
    if (ret != 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "SoftBusMutexLock failed, ret[%{public}d]", ret);
        return SOFTBUS_LOCK_ERR;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusMutexUnlock(SoftBusMutex *mutex)
{
    if ((mutex == NULL) || ((void *)(*mutex) == NULL)) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "mutex is null");
        return SOFTBUS_INVALID_PARAM;
    }

    int ret;
    ret = pthread_mutex_unlock((pthread_mutex_t *)*mutex);
    if (ret != 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "SoftBusMutexUnlock failed, ret[%{public}d]", ret);
        return SOFTBUS_LOCK_ERR;
    }

    return SOFTBUS_OK;
}

int32_t SoftBusMutexDestroy(SoftBusMutex *mutex)
{
    if ((mutex == NULL) || ((void *)(*mutex) == NULL)) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "mutex is null");
        return SOFTBUS_INVALID_PARAM;
    }

    int ret;
    ret = pthread_mutex_destroy((pthread_mutex_t *)*mutex);
    if (ret != 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "SoftBusMutexDestroy failed, ret[%{public}d]", ret);
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
        HILOG_ERROR(SOFTBUS_HILOG_ID, "threadAttr is null");
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
        HILOG_ERROR(SOFTBUS_HILOG_ID, "set policy error");
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
        HILOG_ERROR(SOFTBUS_HILOG_ID, "set detachState error");
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
    int ret;
    if ((threadAttr == NULL) || (attr == NULL)) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "threadAttr or attr is null");
        return SOFTBUS_INVALID_PARAM;
    }

    ret = SoftbusSetThreadPolicy(threadAttr, attr);
    if (ret != SOFTBUS_OK) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "SoftbusSetThreadPolicy failed, ret[%{public}d]", ret);
        return SOFTBUS_ERR;
    }

    ret = SoftbusSetThreadDetachState(threadAttr, attr);
    if (ret != SOFTBUS_OK) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "SoftbusSetThreadDetachState failed, ret[%{public}d]", ret);
        return SOFTBUS_ERR;
    }

    ret = SoftbusSetThreadPeriority(threadAttr, attr);
    if (ret != SOFTBUS_OK) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "SoftbusSetThreadPeriority failed, ret[%{public}d]", ret);
        return SOFTBUS_ERR;
    }

    uint64_t stackSize = threadAttr->stackSize;
    if (stackSize != 0) {
        ret = pthread_attr_setstacksize(attr, stackSize);
        if (ret != 0) {
            HILOG_ERROR(SOFTBUS_HILOG_ID, "pthread_attr_setstacksize failed, ret[%{public}d]", ret);
            return SOFTBUS_ERR;
        }
    }

    return SOFTBUS_OK;
}

int32_t SoftBusThreadCreate(SoftBusThread *thread, SoftBusThreadAttr *threadAttr, void *(*threadEntry) (void *),
    void *arg)
{
    if (thread == NULL) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "thread is null");
        return SOFTBUS_INVALID_PARAM;
    }

    if (threadEntry == NULL) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "threadEntry is null");
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t ret;
    if (threadAttr == NULL) {
        ret = pthread_create((pthread_t *)thread, NULL, threadEntry, arg);
        if (ret != 0) {
            HILOG_ERROR(SOFTBUS_HILOG_ID, "Thread create failed, ret[%{public}d]", ret);
            return SOFTBUS_ERR;
        }
    } else {
        pthread_attr_t attr;
        ret = pthread_attr_init(&attr);
        if (ret != 0) {
            HILOG_ERROR(SOFTBUS_HILOG_ID, "pthread_attr_init failed, ret[%{public}d]", ret);
            return SOFTBUS_ERR;
        }
        ret = SoftBusConfTransPthreadAttr(threadAttr, &attr);
        if (ret != 0) {
            HILOG_ERROR(SOFTBUS_HILOG_ID, "SoftBusConfTransPthreadAttr failed, ret[%{public}d]", ret);
            return SOFTBUS_ERR;
        }
        ret = pthread_create((pthread_t *)thread, &attr, threadEntry, arg);
        if (ret != 0) {
            HILOG_ERROR(SOFTBUS_HILOG_ID, "Thread create failed, ret[%{public}d]", ret);
            return SOFTBUS_ERR;
        }

        if (threadAttr->taskName != NULL) {
            ret = SoftBusThreadSetName(*thread, threadAttr->taskName);
            if (ret != 0) {
                HILOG_ERROR(SOFTBUS_HILOG_ID, "Thread set name failed, ret[%{public}d]", ret);
                return SOFTBUS_ERR;
            }
        }
    }

    return SOFTBUS_OK;
}

int32_t SoftBusThreadJoin(SoftBusThread thread, void **value)
{
    if (thread <= 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "thread is invalid");
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t ret = pthread_join((pthread_t)thread, value);
    if (ret != 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "Thread join failed, ret[%{public}d]", ret);
        return SOFTBUS_ERR;
    }

    return SOFTBUS_OK;
}

int32_t SoftBusThreadSetName(SoftBusThread thread, const char *name)
{
    if (thread <= 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "thread is invalid");
        return SOFTBUS_INVALID_PARAM;
    }

    if (name == NULL) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "name is null");
        return SOFTBUS_INVALID_PARAM;
    }
    
    if (strlen(name) >= TASK_NAME_MAX_LEN) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "set thread name length >= TASK_NAME_MAX_LEN");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = pthread_setname_np((pthread_t)thread, name);
    if (ret != 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "Thread set name failed, ret[%{public}d]", ret);
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
        HILOG_ERROR(SOFTBUS_HILOG_ID, "cond is null");
        return SOFTBUS_INVALID_PARAM;
    }
    pthread_condattr_t attr = {0};
    int ret = pthread_condattr_init(&attr);
    if (ret != 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "pthread_condattr_init failed, ret[%{public}d]", ret);
        return SOFTBUS_ERR;
    }
    ret = pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
    if (ret != 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "set clock failed, ret[%{public}d]", ret);
        return SOFTBUS_ERR;
    }

    pthread_cond_t *tempCond = (pthread_cond_t *)SoftBusCalloc(sizeof(pthread_cond_t));
    if (tempCond == NULL) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "tempCond is null");
        return SOFTBUS_ERR;
    }
    ret = pthread_cond_init(tempCond, &attr);
    if (ret != 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "SoftBusCondInit failed, ret[%{public}d]", ret);
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
        HILOG_ERROR(SOFTBUS_HILOG_ID, "cond is null");
        return SOFTBUS_INVALID_PARAM;
    }

    int ret;
    ret = pthread_cond_signal((pthread_cond_t *)*cond);
    if (ret != 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "SoftBusCondSignal failed, ret[%{public}d]", ret);
        return SOFTBUS_ERR;
    }

    return SOFTBUS_OK;
}

int32_t SoftBusCondBroadcast(SoftBusCond *cond)
{
    if ((cond == NULL) || ((void *)(*cond) == NULL)) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "cond is null");
        return SOFTBUS_INVALID_PARAM;
    }

    int ret;
    ret = pthread_cond_broadcast((pthread_cond_t *)*cond);
    if (ret != 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "SoftBusCondBroadcast failed, ret[%{public}d]", ret);
        return SOFTBUS_ERR;
    }

    return SOFTBUS_OK;
}

int32_t SoftBusCondWait(SoftBusCond *cond, SoftBusMutex *mutex, SoftBusSysTime *time)
{
#define USECTONSEC 1000
    if ((cond == NULL) || ((void *)(*cond) == NULL)) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "cond is null");
        return SOFTBUS_INVALID_PARAM;
    }

    if ((mutex == NULL) || ((void *)(*mutex) == NULL)) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "mutex is null");
        return SOFTBUS_INVALID_PARAM;
    }

    int ret;
    if (time == NULL) {
        ret = pthread_cond_wait((pthread_cond_t *)*cond, (pthread_mutex_t *)*mutex);
        if (ret != 0) {
            HILOG_ERROR(SOFTBUS_HILOG_ID, "SoftBusCondWait failed, ret[%{public}d]", ret);
            return SOFTBUS_ERR;
        }
    } else {
        struct timespec tv;
        tv.tv_sec = time->sec;
        tv.tv_nsec = time->usec * USECTONSEC;
        ret = pthread_cond_timedwait((pthread_cond_t *)*cond, (pthread_mutex_t *)*mutex, &tv);
        if (ret != 0 && ret != ETIMEDOUT) {
            HILOG_ERROR(SOFTBUS_HILOG_ID, "SoftBusCondTimedWait failed, ret[%{public}d]", ret);
            return SOFTBUS_ERR;
        }
    }

    return SOFTBUS_OK;
}

int32_t SoftBusCondDestroy(SoftBusCond *cond)
{
    if ((cond == NULL) || ((void *)(*cond) == NULL)) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "cond is null");
        return SOFTBUS_INVALID_PARAM;
    }

    int ret;
    ret = pthread_cond_destroy((pthread_cond_t *)*cond);
    if (ret != 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "SoftBusCondDestroy failed, ret[%{public}d]", ret);
        SoftBusFree((void *)*cond);
        *cond = (SoftBusCond)NULL;
        return SOFTBUS_ERR;
    }

    SoftBusFree((void *)*cond);
    *cond = (SoftBusCond)NULL;
    return SOFTBUS_OK;
}
