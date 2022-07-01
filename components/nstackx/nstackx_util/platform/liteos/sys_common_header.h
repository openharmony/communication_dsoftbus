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

#ifndef SYS_COMMON_HEADER_H
#define SYS_COMMON_HEADER_H

#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <semaphore.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <mqueue.h>

#ifndef LWIP_LITEOS_A_COMPAT
#include "asm/atomic.h"
#include "lwip/sockets.h"
#else
#include <net/if.h>
#include <limits.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#endif /* LWIP_LITEOS_A_COMPAT */

#ifndef offsetof
#define offsetof(type, member) __builtin_offsetof(type, member)
#endif

#define container_of(ptr, type, member) ({  \
    void *__mptr = (void *)(ptr);  \
    (type *)((char *)__mptr - offsetof(type, member));  \
})

#define NSTACKX_EXPORT extern
#define NSTACKX_EXPORT_VARIABLE

typedef int32_t SocketDesc;

#define INVALID_SOCKET (-1)

#ifdef LWIP_LITEOS_A_COMPAT
#ifndef LWIP_SOCKET_OFFSET
#define LWIP_SOCKET_OFFSET 0
#endif

#ifndef LWIP_CONFIG_NUM_SOCKETS
#define LWIP_CONFIG_NUM_SOCKETS 128
#endif
#endif /* LWIP_LITEOS_A_COMPAT */

#endif // SYS_COMMON_HEADER_H
