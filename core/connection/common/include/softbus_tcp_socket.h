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

#include <sys/types.h>
#include "softbus_adapter_errcode.h"
#include "softbus_socket.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

const SocketInterface *GetTcpProtocol(void);

int32_t SetIpTos(int fd, uint32_t tos);
int32_t BindTcpClientAddr(int32_t domain, int fd, const char *inputAddr);
int32_t SocketConnect(int32_t fd, int32_t domain, const ConnectOption *option);
void SetClientOption(int fd);
void SetServerOption(int fd);
int32_t GetTcpSockPort(int32_t fd);
int BindLocalIP(int32_t domain, int fd, const char *localIP, uint16_t port);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif // SOFTBUS_TCP_SOCKET_H
