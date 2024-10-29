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

#ifndef SOFTBUS_ADAPTER_THREAD_H
#define SOFTBUS_ADAPTER_THREAD_H

#include <stdbool.h>
#include <stdint.h>

#include "comm_log.h"
#include "softbus_adapter_timer.h"
#include "softbus_error_code.h"

#ifdef __cplusplus
extern "C" {
#endif

#define TASK_NAME_MAX_LEN (16)

typedef enum {
    SOFTBUS_SCHED_OTHER,
    SOFTBUS_SCHED_RR
} SoftBusSched;

typedef enum {
    SOFTBUS_THREAD_JOINABLE,
    SOFTBUS_THREAD_DETACH
} SoftBusDetachState;

typedef enum {
    SOFTBUS_PRIORITY_LOWEST,
    SOFTBUS_PRIORITY_LOW,
    SOFTBUS_PRIORITY_DEFAULT,
    SOFTBUS_PRIORITY_HIGH,
    SOFTBUS_PRIORITY_HIGHEST
} SoftBusThreadPriority;

typedef struct {
    int32_t policy;
    int32_t detachState;
    SoftBusThreadPriority prior;
    const char *taskName;
    uint64_t stackSize;
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

// mutex
int32_t SoftBusMutexAttrInit(SoftBusMutexAttr *mutexAttr);
int32_t SoftBusMutexInit(SoftBusMutex *mutex, SoftBusMutexAttr *mutexAttr);
int32_t SoftBusMutexLockInner(SoftBusMutex *mutex);
int32_t SoftBusMutexUnlockInner(SoftBusMutex *mutex);
int32_t SoftBusMutexDestroy(SoftBusMutex *mutex);

static inline bool CheckMutexIsNull(const SoftBusMutex *mutex)
{
    return (mutex == NULL) || ((void *)(*mutex) == NULL);
}

#define SoftBusMutexLock(mutex)                                                        \
({                                                                                     \
    int32_t ret = SOFTBUS_OK;                                                          \
    if (CheckMutexIsNull(mutex)) {                                                     \
        COMM_LOGD(COMM_ADAPTER, "SoftBusMutexLock mutex is null");                     \
        ret = SOFTBUS_INVALID_PARAM;                                                   \
    } else {                                                                           \
        ret = SoftBusMutexLockInner(mutex);                                            \
        if (ret != 0) {                                                                \
            COMM_LOGE(COMM_ADAPTER, "SoftBusMutexLock failed, ret=%{public}d", ret);   \
            ret = SOFTBUS_LOCK_ERR;                                                    \
        }                                                                              \
    }                                                                                  \
    ret;                                                                               \
})

#define SoftBusMutexUnlock(mutex)                                                      \
({                                                                                     \
    int32_t ret = SOFTBUS_OK;                                                          \
    if (CheckMutexIsNull(mutex)) {                                                     \
        COMM_LOGE(COMM_ADAPTER, "SoftBusMutexUnlock mutex is null");                   \
        ret = SOFTBUS_INVALID_PARAM;                                                   \
    } else {                                                                           \
        ret = SoftBusMutexUnlockInner(mutex);                                          \
        if (ret != 0) {                                                                \
            COMM_LOGE(COMM_ADAPTER, "SoftBusMutexUnlock failed, ret=%{public}d", ret); \
            ret = SOFTBUS_LOCK_ERR;                                                    \
        }                                                                              \
    }                                                                                  \
    ret;                                                                               \
})

static inline void SoftBusMutexUnlockAuto(SoftBusMutex **mutex)
{
    if (mutex) {
        SoftBusMutexUnlock(*mutex);
    }
}

#define SOFTBUS_LOCK_GUARD(mutex) \
    __attribute__((cleanup(SoftBusMutexUnlockAuto), unused)) SoftBusMutex *lockGuard##mutex = &mutex

// pthread
int32_t SoftBusThreadAttrInit(SoftBusThreadAttr *threadAttr);
int32_t SoftBusThreadCreate(SoftBusThread *thread, SoftBusThreadAttr *threadAttr, void *(*threadEntry)(void *),
    void *arg);
int32_t SoftBusThreadJoin(SoftBusThread thread, void **value);
int32_t SoftBusThreadSetName(SoftBusThread thread, const char *name);
SoftBusThread SoftBusThreadGetSelf(void);

// cond
int32_t SoftBusCondInit(SoftBusCond *cond);
int32_t SoftBusCondSignal(SoftBusCond *cond);
int32_t SoftBusCondBroadcast(SoftBusCond *cond);
int32_t SoftBusCondWait(SoftBusCond *cond, SoftBusMutex *mutex, SoftBusSysTime *time);
int32_t SoftBusCondDestroy(SoftBusCond *cond);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif // SOFTBUS_ADAPTER_THREAD_H
