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

NSTACKX_EXPORT void ClockGetTime(clockid_t id, struct timespec *tp);

/* pthread series */
NSTACKX_EXPORT void SemGetValue(sem_t *sem, int *sval);
NSTACKX_EXPORT void SemPost(sem_t *sem);
NSTACKX_EXPORT void SemWait(sem_t *sem);
NSTACKX_EXPORT void SemDestroy(sem_t *sem);
NSTACKX_EXPORT int32_t SemInit(sem_t *sem, int pshared, uint32_t value);
NSTACKX_EXPORT int32_t PthreadMutexInit(pthread_mutex_t *mutex, const pthread_mutexattr_t *attr);
NSTACKX_EXPORT void PthreadMutexDestroy(pthread_mutex_t *mutex);
NSTACKX_EXPORT int32_t PthreadMutexLock(pthread_mutex_t *mutex);
NSTACKX_EXPORT int32_t PthreadMutexUnlock(pthread_mutex_t *mutex);
NSTACKX_EXPORT int32_t PthreadCreate(pthread_t *tid, const pthread_attr_t *attr, void *(*entry)(void *), void *arg);
NSTACKX_EXPORT void PthreadJoin(pthread_t thread, void **retval);

#ifdef __cplusplus
}
#endif

#endif // NSTACKX_UTIL_H
