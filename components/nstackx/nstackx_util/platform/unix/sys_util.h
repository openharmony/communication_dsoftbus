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

#ifndef SYS_UTIL_H
#define SYS_UTIL_H

#include "nstackx_common_header.h"

#ifdef __cplusplus
extern "C" {
#endif

#if defined(MIPS)
#include <stdatomic.h>
#endif

#define PATH_SEPARATOR '/'
#define INVALID_TID (pthread_t)(-1)

typedef uint64_t atomic_t;

#define NSTACKX_ATOM_FETCH(ptr) (*ptr)
#define NSTACKX_ATOM_SET(ptr, i) ((*ptr) = (i))
#if defined(MIPS)
#define NSTACKX_ATOM_FETCH_INC(ptr) __atomic_fetch_add((ptr), 1, __ATOMIC_SEQ_CST)
#define NSTACKX_ATOM_FETCH_DEC(ptr) __atomic_fetch_sub((ptr), 1, __ATOMIC_SEQ_CST)
#define NSTACKX_ATOM_ADD_RETURN(ptr, i) __atomic_add_fetch((ptr), i, __ATOMIC_SEQ_CST)
#define NSTACKX_ATOM_FETCH_ADD(ptr, val) __atomic_fetch_add((ptr), (val), __ATOMIC_SEQ_CST)
#define NSTACKX_ATOM_FETCH_SUB(ptr, val) __atomic_fetch_sub((ptr), (val), __ATOMIC_SEQ_CST)
#else
#define NSTACKX_ATOM_FETCH_INC(ptr) __sync_fetch_and_add((ptr), 1)
#define NSTACKX_ATOM_FETCH_DEC(ptr) __sync_fetch_and_sub((ptr), 1)
#define NSTACKX_ATOM_ADD_RETURN(ptr, i) __sync_add_and_fetch((ptr), i)
#define NSTACKX_ATOM_FETCH_ADD(ptr, val) __sync_fetch_and_add((ptr), (val))
#define NSTACKX_ATOM_FETCH_SUB(ptr, val) __sync_fetch_and_sub((ptr), (val))
#endif

static inline int32_t GetErrno(void)
{
    return errno;
}

#define CloseSocketInner CloseDesc
#define gettid() (pid_t)syscall(__NR_gettid)
NSTACKX_EXPORT void CloseDesc(int32_t desc);
NSTACKX_EXPORT int32_t GetInterfaceList(struct ifconf *ifc, struct ifreq *buf, uint32_t size);
NSTACKX_EXPORT int32_t GetInterfaceIP(int32_t fd, struct ifreq *interface);
NSTACKX_EXPORT int32_t GetTargetInterface(const struct sockaddr_in *dstAddr, struct ifreq *localDev);

#ifdef __cplusplus
}
#endif

#endif // NSTACKX_UTIL_H
