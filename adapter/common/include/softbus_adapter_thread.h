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

#ifndef SOFTBUS_ADAPTER_THREAD_H
#define SOFTBUS_ADAPTER_THREAD_H

#include <stdint.h>
#include "softbus_adapter_timer.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#define TASK_NAME_MAX_LEN (16)
typedef enum {
    SOFTBUS_SCHED_OTHER,
    SOFTBUS_SCHED_RR
} SoftBusSched;

typedef enum {
    SOFTBUS_THREAD_JOINABLE,
    SOFTBUS_THREAD_DETACH
}SoftBusDetachState;

typedef enum {
    SOFTBUS_PRIORITY_LOWEST,
    SOFTBUS_PRIORITY_LOW,
    SOFTBUS_PRIORITY_DEFAULT,
    SOFTBUS_PRIORITY_HIGH,
    SOFTBUS_PRIORITY_HIGHEST
} SoftBusThreadPriority;


typedef struct {
    const char *taskName;
    int32_t policy;
    int32_t detachState;
    uint64_t stackSize;
    SoftBusThreadPriority prior;
} SoftBusThreadAttr;

typedef enum {
    SOFTBUS_MUTEX_NORMAL,
    SOFTBUS_MUTEX_RECURSIVE
} SoftBusMutexType;

typedef struct {
    SoftBusMutexType type;
} SoftBusMutexAttr;

typedef uintptr_t SoftBusThread;
typedef uintptr_t SoftBusMutex;
typedef uintptr_t SoftBusCond;
/* mutex */
int32_t SoftBusMutexAttrInit(SoftBusMutexAttr *mutexAttr);
int32_t SoftBusMutexInit(SoftBusMutex *mutex, SoftBusMutexAttr *mutexAttr);
int32_t SoftBusMutexLock(SoftBusMutex *mutex);
int32_t SoftBusMutexUnlock(SoftBusMutex *mutex);
int32_t SoftBusMutexDestroy(SoftBusMutex *mutex);

/* pthread */
int32_t SoftBusThreadAttrInit(SoftBusThreadAttr *threadAttr);
int32_t SoftBusThreadCreate(SoftBusThread *thread, SoftBusThreadAttr *threadAttr, void *(*threadEntry)(void *),
    void *arg);
int32_t SoftBusThreadJoin(SoftBusThread thread, void **value);
int32_t SoftBusThreadSetName(SoftBusThread thread, const char *name);
SoftBusThread SoftBusThreadGetSelf(void);

/* cond */
int32_t SoftBusCondInit(SoftBusCond *cond);
int32_t SoftBusCondSignal(SoftBusCond *cond);
int32_t SoftBusCondBroadcast(SoftBusCond *cond);
int32_t SoftBusCondWait(SoftBusCond *cond, SoftBusMutex *mutex, SoftBusSysTime *time);
int32_t SoftBusCondDestroy(SoftBusCond *cond);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif
