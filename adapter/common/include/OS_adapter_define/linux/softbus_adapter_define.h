/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef SOFTBUS_ADAPTER_DEFINE_H
#define SOFTBUS_ADAPTER_DEFINE_H

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/* sys/socket.h */
#define SOFTBUS_PF_UNSPEC_ PF_UNSPEC
#define SOFTBUS_AF_UNSPEC_ AF_UNSPEC
#define SOFTBUS_PF_INET_ PF_INET
#define SOFTBUS_AF_INET_ AF_INET

#define SOFTBUS_PF_INET6_ PF_INET6
#define SOFTBUS_AF_INET6_ AF_INET6

#define SOFTBUS_PF_NETLINK_ PF_NETLINK
#define SOFTBUS_AF_NETLINK_ AF_NETLINK

#define SOFTBUS_SOCK_STREAM_ SOCK_STREAM
#define SOFTBUS_SOCK_DGRAM_ SOCK_DGRAM
#define SOFTBUS_SOCK_RAW_ SOCK_RAW

#define SOFTBUS_SOCK_CLOEXEC_ SOCK_CLOEXEC
#define SOFTBUS_SOCK_NONBLOCK_ SOCK_NONBLOCK

#define SOFTBUS_SOL_SOCKET_ SOL_SOCKET

#define SOFTBUS_SO_REUSEADDR_ SO_REUSEADDR
#define SOFTBUS_SO_RCVBUF_ SO_RCVBUF
#define SOFTBUS_SO_SNDBUF_ SO_SNDBUF
#define SOFTBUS_SO_KEEPALIVE_ SO_KEEPALIVE
#define SOFTBUS_SO_REUSEPORT_ SO_REUSEPORT
#define SOFTBUS_SO_RCVBUFFORCE_ SO_RCVBUFFORCE
#define SOFTBUS_SO_BINDTODEVICE_ SO_BINDTODEVICE

#define SOFTBUS_TCP_KEEPIDLE_ TCP_KEEPIDLE
#define SOFTBUS_TCP_KEEPINTVL_ TCP_KEEPINTVL
#define SOFTBUS_TCP_KEEPCNT_ TCP_KEEPCNT
#define SOFTBUS_TCP_USER_TIMEOUT_ TCP_USER_TIMEOUT

#define SOFTBUS_SHUT_RD_ SHUT_RD
#define SOFTBUS_SHUT_WR_ SHUT_WR
#define SOFTBUS_SHUT_RDWR_ SHUT_RDWR

/* netinet/in.h */
#define SOFTBUS_IPPROTO_IP_ IPPROTO_IP
#define SOFTBUS_IPPROTO_TCP_ IPPROTO_TCP

#define SOFTBUS_IP_TOS_ IP_TOS

/* netinet/tcp.h */
#define SOFTBUS_TCP_NODELAY_ TCP_NODELAY

/* fcntl.h */
#define SOFTBUS_F_GETFL_ F_GETFL
#define SOFTBUS_F_SETFL_ F_SETFL

#define SOFTBUS_O_NONBLOCK_ O_NONBLOCK

/* select.h */
/* linux support 1024, liteos support 640 */
#define SOFTBUS_FD_SETSIZE_ FD_SETSIZE


#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif

