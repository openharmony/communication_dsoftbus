/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#ifndef NSTACKX_UTIL_H
#define NSTACKX_UTIL_H

#include "nstackx_dev.h"
#include "sys_util.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    CPU_IDX_0 = 0,
    CPU_IDX_1,
    CPU_IDX_2,
    CPU_IDX_3,
    CPU_IDX_4,
    CPU_IDX_5,
    CPU_IDX_6,
    CPU_IDX_7,
} CpuIdx;

#define FIRST_CPU_NUM_LEVEL 8
#define SECOND_CPU_NUM_LEVEL 4
#define THIRD_CPU_NUM_LEVEL 2
#define MAX_THREAD_NAME_LEN 100
#define THREAD_MAXIMUM_PRIORITY (-20)

#define BLOCK_LEN          512
#define MAX_NAME_LEN       99

NSTACKX_EXPORT int32_t GetTargetFileSize(const char *dir, uint64_t *size);
NSTACKX_EXPORT int32_t CheckPathSeprator(const char *path);
NSTACKX_EXPORT int32_t CheckFilenameSeprator(const char *fileName);
NSTACKX_EXPORT uint32_t GetFileNameLen(const char *dir);
NSTACKX_EXPORT int32_t GetFileName(const char *dir, char *name, uint32_t nameLen);
NSTACKX_EXPORT uint8_t IsAccessiblePath(const char *fileName, int32_t mode, uint32_t fileType);
NSTACKX_EXPORT int32_t TestAndCreateDirectory(const char *path);
NSTACKX_EXPORT uint8_t IsFileNameLegal(const char *fileName);
NSTACKX_EXPORT uint8_t IsExistingFile(const char *fileName);

NSTACKX_EXPORT void StartThreadBindCore(int32_t cpu);
NSTACKX_EXPORT void BindThreadToTargetMask(pid_t tid, uint32_t cpuMask);
NSTACKX_EXPORT int32_t GetCpuNum(void);
NSTACKX_EXPORT void SetThreadName(const char *name);
NSTACKX_EXPORT void ClockGetTime(clockid_t id, struct timespec *tp);
NSTACKX_EXPORT void SetMaximumPriorityForThread(void);

/* pthread series */
NSTACKX_EXPORT void SemGetValue(sem_t *sem, int *sval);
NSTACKX_EXPORT void SemPost(sem_t *sem);
NSTACKX_EXPORT void SemWait(sem_t *sem);
NSTACKX_EXPORT void SemDestroy(sem_t *sem);
NSTACKX_EXPORT int32_t SemInit(sem_t *sem, int pshared, unsigned int value);
NSTACKX_EXPORT int32_t PthreadMutexInit(pthread_mutex_t *mutex, const pthread_mutexattr_t *attr);
NSTACKX_EXPORT void PthreadMutexDestroy(pthread_mutex_t *mutex);
NSTACKX_EXPORT int32_t PthreadMutexLock(pthread_mutex_t *mutex);
NSTACKX_EXPORT int32_t PthreadMutexUnlock(pthread_mutex_t *mutex);
NSTACKX_EXPORT int32_t PthreadCreate(pthread_t *tid, const pthread_attr_t *attr, void *(*entry)(void *), void *arg);
NSTACKX_EXPORT void PthreadJoin(pthread_t thread, void **retval);

NSTACKX_EXPORT int32_t IpAddrAnonymousFormat(char *buf, size_t len, const struct sockaddr *addr, size_t addrLen);

#ifdef __cplusplus
}
#endif

#endif // NSTACKX_UTIL_H
