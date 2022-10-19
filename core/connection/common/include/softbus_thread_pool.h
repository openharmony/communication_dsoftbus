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

#ifndef THREAD_POOL_H
#define THREAD_POOL_H

#include <stdbool.h>
#include <stdint.h>
#include "softbus_adapter_thread.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif
typedef enum {
    ONCE = 0,
    PERSISTENT = 1,
} JobMode;

typedef int32_t (*JobTask)(void *arg);
struct Job {
    int32_t (*callbackFunction)(void *arg);
    void *arg;
    struct Job *next;
    JobMode jobMode;
    SoftBusMutex mutex;
    uintptr_t handle;
    bool runnable;
};

typedef struct Job Job;

typedef struct {
    int32_t threadNum;
    int32_t queueMaxNum;
    Job *head;
    Job *tail;
    SoftBusThread *pthreads;
    SoftBusMutex mutex;
    SoftBusCond queueEmpty;
    SoftBusCond queueNotEmpty;
    SoftBusCond queueNotFull;
    int32_t queueCurNum;
    int32_t queueClose;
    int32_t poolClose;
} ThreadPool;

ThreadPool* ThreadPoolInit(int32_t threadNum, int32_t queueMaxNum);

int32_t ThreadPoolAddJob(ThreadPool *pool, int32_t (*callbackFunction)(void *arg),
    void *arg, JobMode jobMode, uintptr_t handle);

int32_t ThreadPoolRemoveJob(ThreadPool *pool, uintptr_t handle);

int32_t ThreadPoolDestroy(ThreadPool *pool);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif /* THREAD_POOL_H */