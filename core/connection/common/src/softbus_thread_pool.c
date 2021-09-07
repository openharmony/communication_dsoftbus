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

#include "softbus_thread_pool.h"

#include <sys/prctl.h>

#include "softbus_adapter_mem.h"
#include "softbus_errcode.h"
#include "softbus_log.h"

#ifndef MIN_STACK_SIZE
#define MIN_STACK_SIZE 0x2000
#define THREAD_PRIORITY 20
#endif
#define THREAD_POOL_NAME "THREAD_POOL_WORKER"

typedef void *(*Runnable)(void *argv);
typedef struct ThreadAttr ThreadAttr;

struct ThreadAttr {
    const char *name;
    uint32_t stackSize;
    uint8_t priority;
};

static int32_t CreateThread(Runnable run, void *argv, const ThreadAttr *attr, uint32_t *threadId);
static ThreadPool* CreateThreadPool(int32_t threadNum, int32_t queueMaxNum);
static void JobCheck(ThreadPool *pool, Job *job);
static void ThreadPoolWorker(void *arg);

static int32_t CreateThread(Runnable run, void *argv, const ThreadAttr *attr, uint32_t *threadId)
{
    pthread_attr_t threadAttr;
    pthread_attr_init(&threadAttr);
    pthread_attr_setstacksize(&threadAttr, (attr->stackSize | MIN_STACK_SIZE));
    struct sched_param sched = {attr->priority};
    pthread_attr_setschedparam(&threadAttr, &sched);
    pthread_attr_setdetachstate(&threadAttr, PTHREAD_CREATE_JOINABLE);
    int32_t errCode = pthread_create((pthread_t *)threadId, &threadAttr, run, argv);
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
    if (pthread_mutex_init(&(pool->mutex), NULL)) {
        SoftBusFree(pool);
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "Failed to init mutex");
        return NULL;
    }
    if (pthread_cond_init(&(pool->queueEmpty), NULL)) {
        SoftBusFree(pool);
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "Failed to init cond queueEmpty");
        return NULL;
    }
    if (pthread_cond_init(&(pool->queueNotEmpty), NULL)) {
        SoftBusFree(pool);
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "Failed to init cond queueNotEmpty");
        return NULL;
    }
    if (pthread_cond_init(&(pool->queueNotFull), NULL)) {
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

    pool->pthreads = (pthread_t *)SoftBusCalloc(sizeof(pthread_t) * threadNum);
    if (pool->pthreads == NULL) {
        SoftBusFree(pool);
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "Failed to malloc pthreads");
        return NULL;
    }
    pool->queueClose = 0;
    pool->poolClose = 0;
    if (pthread_mutex_lock(&(pool->mutex)) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "lock failed");
        goto EXIT;
    }
    int32_t countSuccess = 0;
    for (int32_t i = 0; i < pool->threadNum; ++i) {
        ThreadAttr attr = {"ThreadPoolWorker", 0, THREAD_PRIORITY};
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "create pthread now.");
        if (CreateThread((Runnable)ThreadPoolWorker, (void *)pool, &attr, (uint32_t *)&(pool->pthreads[i])) != 0) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "create pthreads no. [%d] failed\n", i);
            pool->pthreads[i] = (pthread_t)0;
        } else {
            ++countSuccess;
        }
    }
    if (countSuccess < pool->threadNum) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "Failed to create %d threads", pool->threadNum - countSuccess);
    }
    if (countSuccess == 0) {
        pthread_mutex_unlock(&pool->mutex);
        goto EXIT;
    }
    pthread_mutex_unlock(&(pool->mutex));
    return pool;

EXIT:
    pthread_mutex_destroy(&pool->mutex);
    pthread_cond_destroy(&pool->queueEmpty);
    pthread_cond_destroy(&pool->queueNotEmpty);
    pthread_cond_destroy(&pool->queueNotFull);
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
    pthread_setname_np(pthread_self(), THREAD_POOL_NAME);
    while (1) {
        if (pthread_mutex_lock(&(pool->mutex)) != 0) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "lock failed");
            return;
        }
        while ((pool->queueCurNum == 0) && !pool->poolClose) {
            pthread_cond_wait(&(pool->queueNotEmpty), &(pool->mutex));
        }
        if (pool->poolClose || pool->queueCurNum <= 0) {
            pthread_mutex_unlock(&(pool->mutex));
            break;
        }
        pool->queueCurNum--;
        job = pool->head;
        if (pthread_mutex_lock(&(job->mutex)) != 0) {
            pool->queueCurNum++;
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "lock failed");
            pthread_mutex_unlock(&(pool->mutex));
            continue;
        }
        JobCheck(pool, job);
        if (pool->queueCurNum == 0) {
            pthread_cond_signal(&(pool->queueEmpty));
        }
        if (pool->queueCurNum == pool->queueMaxNum - 1) {
            pthread_cond_broadcast(&(pool->queueNotFull));
        }
        pthread_mutex_unlock(&(pool->mutex));
        if (job->runnable) {
            (void)(*(job->callbackFunction))(job->arg);
        }
        if (job->jobMode == ONCE || job->runnable == false) {
            pthread_mutex_unlock(&(job->mutex));
            pthread_mutex_destroy(&(job->mutex));
            SoftBusFree(job);
            job = NULL;
        }
        if (job != NULL) {
            pthread_mutex_unlock(&(job->mutex));
        }
    }
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "ThreadPoolWorker Exit");
}

static int32_t CheckThreadPoolAddReady(ThreadPool *pool, int32_t (*callbackFunction)(void *arg))
{
    if (pool == NULL || callbackFunction == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (pthread_mutex_lock(&(pool->mutex)) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    if (pool->queueCurNum == pool->queueMaxNum) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "queueCurNum equals queueMaxNum, just quit");
        pthread_mutex_unlock(&(pool->mutex));
        return SOFTBUS_ERR;
    }
    while ((pool->queueCurNum == pool->queueMaxNum) && !(pool->queueClose || pool->poolClose)) {
        pthread_cond_wait(&(pool->queueNotFull), &(pool->mutex));
    }
    if (pool->queueClose || pool->poolClose) {
        pthread_mutex_unlock(&(pool->mutex));
        return SOFTBUS_ERR;
    }
    // will call pthread_mutex_unlock in ThreadPoolAddJob
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
            pthread_mutex_unlock(&(pool->mutex));
            return SOFTBUS_ALREADY_EXISTED;
        }
        job = job->next;
    }
    job = (Job *)SoftBusCalloc(sizeof(Job));
    if (job == NULL) {
        pthread_mutex_unlock(&(pool->mutex));
        return SOFTBUS_MALLOC_ERR;
    }
    job->callbackFunction = callbackFunction;
    job->arg = arg;
    job->jobMode = jobMode;
    job->handle = handle;
    job->runnable = true;
    job->next = NULL;
    if (pthread_mutex_init(&(job->mutex), NULL)) {
        SoftBusFree(job);
        pthread_mutex_unlock(&(pool->mutex));
        return SOFTBUS_ERR;
    }
    if (pool->head == NULL) {
        pool->head = pool->tail = job;
        pthread_cond_broadcast(&(pool->queueNotEmpty));
    } else {
        pool->tail->next = job;
        pool->tail = job;
    }
    pool->queueCurNum++;
    pthread_mutex_unlock(&(pool->mutex));
    return SOFTBUS_OK;
}

int32_t ThreadPoolRemoveJob(ThreadPool *pool, uintptr_t handle)
{
    if (pool == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "ThreadPoolRemoveJob failed, pool == NULL");
        return SOFTBUS_INVALID_PARAM;
    }
    if (pthread_mutex_lock(&(pool->mutex)) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "lock failed");
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
        if (pthread_mutex_lock(&(job->mutex)) != 0) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "lock failed");
            pthread_mutex_unlock(&(job->mutex));
            return SOFTBUS_LOCK_ERR;
        }
        job->runnable = false;
        pthread_mutex_unlock(&(job->mutex));
    }
    pthread_mutex_unlock(&(pool->mutex));
    return SOFTBUS_OK;
}

int32_t ThreadPoolDestroy(ThreadPool *pool)
{
    if (pool == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (pthread_mutex_lock(&(pool->mutex)) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    if (pool->queueClose || pool->poolClose) {
        pthread_mutex_unlock(&(pool->mutex));
        return SOFTBUS_OK;
    }
    pool->queueClose = 1;
    while (pool->queueCurNum != 0) {
        pthread_cond_wait(&(pool->queueEmpty), &(pool->mutex));
    }
    pool->poolClose = 1;
    pthread_mutex_unlock(&(pool->mutex));
    pthread_cond_broadcast(&(pool->queueNotEmpty));
    pthread_cond_broadcast(&(pool->queueNotFull));
    for (int32_t i = 0; i < pool->threadNum; ++i) {
        if (pool->pthreads != NULL) {
            pthread_join(pool->pthreads[i], NULL);
        }
    }
    pthread_mutex_destroy(&(pool->mutex));
    pthread_cond_destroy(&(pool->queueEmpty));
    pthread_cond_destroy(&(pool->queueNotEmpty));
    pthread_cond_destroy(&(pool->queueNotFull));
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
