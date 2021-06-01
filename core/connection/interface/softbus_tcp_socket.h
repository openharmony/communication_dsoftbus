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

#ifndef SOFTBUS_TCP_SOCKET_H
#define SOFTBUS_TCP_SOCKET_H

#include <errno.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/uio.h>

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#ifndef TEMP_FAILURE_RETRY
#define TEMP_FAILURE_RETRY(expression) \
( \
    __extension__ \
    ( \
    {   \
    long int __result; \
    do __result = (long int) (expression); \
    while ((__result == -1L) && (errno == EINTR)); \
    __result; \
    } \
    ) \
)
#endif

enum {
    SOFTBUS_SOCKET_OUT, // writable
    SOFTBUS_SOCKET_IN, // readable
    SOFTBUS_SOCKET_EXCEPTION, // exception
};

int32_t OpenTcpServerSocket(const char *ip, int32_t port);
int32_t OpenTcpClientSocket(const char *peerIp, const char *myIp, int32_t port);
int32_t GetTcpSockPort(int32_t fd);
ssize_t SendTcpData(int32_t fd, const char *buf, size_t len, int32_t timeout);
ssize_t RecvTcpData(int32_t fd, char *buf, size_t len, int32_t timeout);
void CloseTcpFd(int32_t fd);
void TcpShutDown(int32_t fd);
int32_t SetTcpKeepAlive(int32_t fd, int32_t seconds);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif // SOFTBUS_TCP_SOCKET_H
