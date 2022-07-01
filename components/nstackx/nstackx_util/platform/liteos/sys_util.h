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

#ifndef htobe64
#define PP_HTON64(x) ((((x) & (uint64_t)0x00000000000000ffULL) << 56) | \
                      (((x) & (uint64_t)0xff00000000000000ULL) >> 56) | \
                      (((x) & (uint64_t)0x000000000000ff00ULL) << 40) | \
                      (((x) & (uint64_t)0x00ff000000000000ULL) >> 40) | \
                      (((x) & (uint64_t)0x0000000000ff0000ULL) << 24) | \
                      (((x) & (uint64_t)0x0000ff0000000000ULL) >> 24) | \
                      (((x) & (uint64_t)0x00000000ff000000ULL) <<  8) | \
                      (((x) & (uint64_t)0x000000ff00000000ULL) >>  8))
#if BYTE_ORDER == BIG_ENDIAN
#define htobe64(x) (x)
#define htole64(x) PP_HTON64(x)
#define be64toh(x) (x)
#define le64toh(x) PP_HTON64(x)
#else
#define htobe64(x) PP_HTON64(x)
#define htole64(x) (x)
#define be64toh(x) PP_HTON64(x)
#define le64toh(x) (x)
#endif /* BYTE_ORDER == BIG_ENDIAN */
#endif /* htobe64 */

#define PATH_SEPARATOR '/'
#define INVALID_TID (pthread_t)(-1)

#ifdef LWIP_LITEOS_A_COMPAT
#ifndef atomic_t
typedef uint64_t atomic_t;
#endif

#define NSTACKX_ATOM_FETCH(ptr) (*ptr)
#define NSTACKX_ATOM_SET(ptr, i) ((*ptr) = (i))
#define NSTACKX_ATOM_FETCH_INC(ptr) __sync_fetch_and_add((ptr), 1)
#define NSTACKX_ATOM_FETCH_DEC(ptr) __sync_fetch_and_sub((ptr), 1)
#define NSTACKX_ATOM_ADD_RETURN(ptr, i) __sync_add_and_fetch((ptr), i)
#define NSTACKX_ATOM_FETCH_ADD(ptr, val) __sync_fetch_and_add((ptr), (val))
#define NSTACKX_ATOM_FETCH_SUB(ptr, val) __sync_fetch_and_sub((ptr), (val))

#else /* LWIP_LITEOS_A_COMPAT */
#define NSTACKX_ATOM_FETCH(ptr) atomic_read(ptr)
#define NSTACKX_ATOM_SET(ptr, i) atomic_set(ptr, i)
#define NSTACKX_ATOM_FETCH_INC(ptr) atomic_inc(ptr)
#define NSTACKX_ATOM_FETCH_DEC(ptr) atomic_dec(ptr)
#define NSTACKX_ATOM_ADD_RETURN(ptr, i) atomic_add_return(i, ptr)
#define NSTACKX_ATOM_FETCH_ADD(ptr, val) atomic_add((val), (ptr))
#define NSTACKX_ATOM_FETCH_SUB(ptr, val) atomic_sub((val), (ptr))
#endif /* LWIP_LITEOS_A_COMPAT */

static inline int32_t GetErrno(void)
{
    return errno;
}

#define CloseSocketInner CloseDesc
#define gettid() (pid_t)pthread_self()
NSTACKX_EXPORT void CloseDesc(int32_t desc);
NSTACKX_EXPORT int32_t GetInterfaceList(struct ifconf *ifc, struct ifreq *buf, uint32_t size);
NSTACKX_EXPORT int32_t GetInterfaceIP(int32_t fd, struct ifreq *interface);
NSTACKX_EXPORT int32_t GetTargetInterface(const struct sockaddr_in *dstAddr, struct ifreq *localDev);

#ifdef __cplusplus
}
#endif

#endif // NSTACKX_UTIL_H
