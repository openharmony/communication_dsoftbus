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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <net/if.h>
#include <pthread.h>
#include <semaphore.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/select.h>
#include <sys/types.h>
#include <syscall.h>
#include <unistd.h>

#include <linux/limits.h>

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

#endif // SYS_COMMON_HEADER_H
