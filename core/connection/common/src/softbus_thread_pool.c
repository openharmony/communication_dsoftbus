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

#include "softbus_thread_pool.h"

#include "softbus_adapter_mem.h"
#include "softbus_errcode.h"
#include "softbus_log.h"

#ifndef MIN_STACK_SIZE
#define MIN_STACK_SIZE 0x8000
#endif
#define THREAD_POOL_NAME "SoftBusConnect"

typedef void *(*Runnable)(void *argv);
typedef struct ThreadAttr ThreadAttr;

struct ThreadAttr {
    const char *name;
    uint32_t stackSize;
    SoftBusThreadPriority priority;
};

static int32_t CreateThread(Runnable run, void *argv, const ThreadAttr *attr, uint32_t *threadId);
static ThreadPool* CreateThreadPool(int32_t threadNum, int32_t queueMaxNum);
static void JobCheck(ThreadPool *pool, Job *job);
static void ThreadPoolWorker(void *arg);

static int32_t CreateThread(Runnable run, void *argv, const ThreadAttr *attr, uint32_t *threadId)
{
    SoftBusThreadAttr threadAttrInfo;
    SoftBusThreadAttrInit(&threadAttrInfo);

    threadAttrInfo.stackSize = (attr->stackSize | MIN_STACK_SIZE);
    threadAttrInfo.prior = attr->priority;
#ifndef __aarch64__
    threadAttrInfo.policy = SOFTBUS_SCHED_RR;
#endif
    int32_t errCode = SoftBusThreadCreate((SoftBusThread *)threadId, &threadAttrInfo, run, argv);

    return errCode;
}

static ThreadPool* CreateThreadPool(int32_t threadNum, int32_t queueMaxNum)
{
    if (threadNum <= 0 || queueMaxNum <= 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "Invalid para.");
        return NULL;
    }
    ThreadPool *pool = (ThreadPool *)SoftBusCalloc(sizeof(ThreadPool));
    if (pool == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "Failed to malloc ThreadPool");
        return NULL;
    }
    pool->threadNum = threadNum;
    pool->queueMaxNum = queueMaxNum;
    pool->queueCurNum = 0;
    pool->head = NULL;
    pool->tail = NULL;
    if (SoftBusMutexInit(&(pool->mutex), NULL) != SOFTBUS_OK) {
        SoftBusFree(pool);
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "Failed to init mutex");
        return NULL;
    }
    if (SoftBusCondInit(&(pool->queueEmpty)) != SOFTBUS_OK) {
        SoftBusFree(pool);
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "Failed to init cond queueEmpty");
        return NULL;
    }
    if (SoftBusCondInit(&(pool->queueNotEmpty)) != SOFTBUS_OK) {
        SoftBusFree(pool);
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "Failed to init cond queueNotEmpty");
        return NULL;
    }
    if (SoftBusCondInit(&(pool->queueNotFull)) != SOFTBUS_OK) {
        SoftBusFree(pool);
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "Failed to init cond queueNotFull");
        return NULL;
    }
    return pool;
}

ThreadPool *ThreadPoolInit(int32_t threadNum, int32_t queueMaxNum)
{
    if (threadNum <= 0 || queueMaxNum <= 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "Invalid para.");
        return NULL;
    }
    ThreadPool *pool = CreateThreadPool(threadNum, queueMaxNum);
    if (pool == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "Failed to create thread pool");
        return NULL;
    }
    int32_t countSuccess = 0;
    pool->pthreads = (SoftBusThread *)SoftBusCalloc((int32_t)(sizeof(SoftBusThread) * threadNum));
    if (pool->pthreads == NULL) {
        SoftBusFree(pool);
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "Failed to malloc pthreads");
        return NULL;
    }
    pool->queueClose = 0;
    pool->poolClose = 0;
    if (SoftBusMutexLock(&(pool->mutex)) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "%s:lock failed", __func__);
        goto EXIT;
    }

    for (int32_t i = 0; i < pool->threadNum; ++i) {
        ThreadAttr attr = {"ThreadPoolWorker", 0, SOFTBUS_PRIORITY_LOWEST};
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "create pthread now.");
        if (CreateThread((Runnable)ThreadPoolWorker, (void *)pool, &attr, (uint32_t *)&(pool->pthreads[i])) != 0) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "create pthreads no. [%d] failed\n", i);
            pool->pthreads[i] = (SoftBusThread)0;
        } else {
            ++countSuccess;
        }
    }

    if (countSuccess < pool->threadNum) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "Failed to create %d threads", pool->threadNum - countSuccess);
    }
    if (countSuccess == 0) {
        SoftBusMutexUnlock(&pool->mutex);
        goto EXIT;
    }
    SoftBusMutexUnlock(&(pool->mutex));
    return pool;

EXIT:
    SoftBusMutexDestroy(&pool->mutex);
    SoftBusCondDestroy(&pool->queueEmpty);
    SoftBusCondDestroy(&pool->queueNotEmpty);
    SoftBusCondDestroy(&pool->queueNotFull);
    SoftBusFree(pool->pthreads);
    SoftBusFree(pool);
    return NULL;
}

static void JobCheck(ThreadPool *pool, Job *job)
{
    if (pool->queueClose || pool->poolClose) {
        job->runnable = false;
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "Threadpool starts to close...");
    }
    if (job->jobMode == PERSISTENT && job->runnable == true) {
        pool->queueCurNum++;
        pool->tail->next = job;
        pool->tail = job;
    }
    if (pool->queueCurNum == 0) {
        pool->head = pool->tail = NULL;
    } else {
        pool->head = job->next;
    }
    if (pool->tail != NULL) {
        pool->tail->next = NULL;
    }
}

static void ThreadPoolWorker(void *arg)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "ThreadPoolWorker Start");
    if (arg == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "ThreadPoolWorker arg is NULL");
        return;
    }
    ThreadPool *pool = (ThreadPool *)arg;
    Job *job = NULL;
    SoftBusThreadSetName(SoftBusThreadGetSelf(), THREAD_POOL_NAME);
    while (1) {
        if (SoftBusMutexLock(&(pool->mutex)) != 0) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "%s:lock failed", __func__);
            return;
        }
        while ((pool->queueCurNum == 0) && !pool->poolClose) {
            SoftBusCondWait(&(pool->queueNotEmpty), &(pool->mutex), NULL);
        }
        if (pool->poolClose || pool->queueCurNum <= 0) {
            SoftBusMutexUnlock(&(pool->mutex));
            break;
        }
        pool->queueCurNum--;
        job = pool->head;
        if (SoftBusMutexLock(&(job->mutex)) != 0) {
            pool->queueCurNum++;
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "%s:lock failed", __func__);
            SoftBusMutexUnlock(&(pool->mutex));
            continue;
        }
        JobCheck(pool, job);
        if (pool->queueCurNum == 0) {
            SoftBusCondSignal(&(pool->queueEmpty));
        }
        if (pool->queueCurNum == pool->queueMaxNum - 1) {
            SoftBusCondBroadcast(&(pool->queueNotFull));
        }
        SoftBusMutexUnlock(&(pool->mutex));

        // copy job task relative variables to run it after leave job mutex
        bool runnable = job->runnable;
        JobTask task = job->callbackFunction;
        void *arguement = job->arg;
        if (job->jobMode == ONCE || job->runnable == false) {
            SoftBusMutexUnlock(&(job->mutex));
            SoftBusMutexDestroy(&(job->mutex));
            SoftBusFree(job);
            job = NULL;
        } else {
            SoftBusMutexUnlock(&(job->mutex));
        }
        if (runnable) {
            (void)(task(arguement));
        }
    }
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "ThreadPoolWorker Exit");
}

static int32_t CheckThreadPoolAddReady(ThreadPool *pool, int32_t (*callbackFunction)(void *arg))
{
    if (pool == NULL || callbackFunction == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&(pool->mutex)) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "%s:lock failed", __func__);
        return SOFTBUS_LOCK_ERR;
    }
    if (pool->queueCurNum == pool->queueMaxNum) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "queueCurNum equals queueMaxNum, just quit");
        SoftBusMutexUnlock(&(pool->mutex));
        return SOFTBUS_ERR;
    }
    while ((pool->queueCurNum == pool->queueMaxNum) && !(pool->queueClose || pool->poolClose)) {
        SoftBusCondWait(&(pool->queueNotFull), &(pool->mutex), NULL);
    }
    if (pool->queueClose || pool->poolClose) {
        SoftBusMutexUnlock(&(pool->mutex));
        return SOFTBUS_ERR;
    }
    // will call SoftBusMutexUnlock in ThreadPoolAddJob
    return SOFTBUS_OK;
}

int32_t ThreadPoolAddJob(ThreadPool *pool, int32_t (*callbackFunction)(void *arg), void *arg,
    JobMode jobMode, uintptr_t handle)
{
    int32_t ret = CheckThreadPoolAddReady(pool, callbackFunction);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    Job* job = pool->head;
    while (job != NULL) {
        if (job->handle == handle && job->runnable == true) {
            SoftBusMutexUnlock(&(pool->mutex));
            return SOFTBUS_ALREADY_EXISTED;
        }
        job = job->next;
    }
    job = (Job *)SoftBusCalloc(sizeof(Job));
    if (job == NULL) {
        SoftBusMutexUnlock(&(pool->mutex));
        return SOFTBUS_MALLOC_ERR;
    }
    job->callbackFunction = callbackFunction;
    job->arg = arg;
    job->jobMode = jobMode;
    job->handle = handle;
    job->runnable = true;
    job->next = NULL;
    if (SoftBusMutexInit(&(job->mutex), NULL)) {
        SoftBusFree(job);
        SoftBusMutexUnlock(&(pool->mutex));
        return SOFTBUS_ERR;
    }
    if (pool->head == NULL) {
        pool->head = pool->tail = job;
        SoftBusCondBroadcast(&(pool->queueNotEmpty));
    } else {
        pool->tail->next = job;
        pool->tail = job;
    }
    pool->queueCurNum++;
    SoftBusMutexUnlock(&(pool->mutex));
    return SOFTBUS_OK;
}

int32_t ThreadPoolRemoveJob(ThreadPool *pool, uintptr_t handle)
{
    if (pool == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "ThreadPoolRemoveJob failed, pool == NULL");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&(pool->mutex)) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "%s:lock failed", __func__);
        return SOFTBUS_LOCK_ERR;
    }
    Job* job = pool->head;
    while (job != NULL) {
        if (job->handle == handle && job->jobMode == PERSISTENT && job->runnable == true) {
            break;
        }
        job = job->next;
    }
    if (job != NULL && job->runnable == true && job->jobMode == PERSISTENT) {
        if (SoftBusMutexLock(&(job->mutex)) != 0) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "%s:lock failed", __func__);
            return SOFTBUS_LOCK_ERR;
        }
        job->runnable = false;
        SoftBusMutexUnlock(&(job->mutex));
    }
    SoftBusMutexUnlock(&(pool->mutex));
    return SOFTBUS_OK;
}

int32_t ThreadPoolDestroy(ThreadPool *pool)
{
    if (pool == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&(pool->mutex)) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "%s:lock failed", __func__);
        return SOFTBUS_LOCK_ERR;
    }
    if (pool->queueClose || pool->poolClose) {
        SoftBusMutexUnlock(&(pool->mutex));
        return SOFTBUS_OK;
    }
    pool->queueClose = 1;
    while (pool->queueCurNum != 0) {
        SoftBusCondWait(&(pool->queueEmpty), &(pool->mutex), NULL);
    }
    pool->poolClose = 1;
    SoftBusMutexUnlock(&(pool->mutex));
    SoftBusCondBroadcast(&(pool->queueNotEmpty));
    SoftBusCondBroadcast(&(pool->queueNotFull));
    for (int32_t i = 0; i < pool->threadNum; ++i) {
        if (pool->pthreads != NULL) {
            SoftBusThreadJoin(pool->pthreads[i], NULL);
        }
    }
    SoftBusMutexDestroy(&(pool->mutex));
    SoftBusCondDestroy(&(pool->queueEmpty));
    SoftBusCondDestroy(&(pool->queueNotEmpty));
    SoftBusCondDestroy(&(pool->queueNotFull));
    SoftBusFree(pool->pthreads);
    Job* job = NULL;
    while (pool->head != NULL) {
        job = pool->head;
        pool->head = job->next;
        SoftBusFree(job);
    }
    SoftBusFree(pool);
    return SOFTBUS_OK;
}
