/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef SOFTBUS_HTP_SOCKET_H
#define SOFTBUS_HTP_SOCKET_H

#include <sys/types.h>

#include "softbus_adapter_errcode.h"
#include "softbus_socket.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

typedef struct {
    unsigned char addr[6];
    unsigned char pad[6]; /* the inet framework need size of addr >= 16 */
} SoftBusMacAddrHtp;

typedef struct {
    unsigned int addr[6];
    unsigned char pad[6]; /* the inet framework need size of addr >= 16 */
} SoftBusIpAddrHtp;

typedef struct {
    unsigned int flowinfo; /* IPv6 flow information */
    unsigned int addr[6];  /* IPv6 address */
    unsigned char pad[6];  /* IPv6 scope-id*/
} SoftBusIp6AddrHtp;

typedef struct {
    unsigned short sa_family;
    unsigned char port;
    unsigned char type;
    union {
        SoftBusMacAddrHtp mac;
        SoftBusIpAddrHtp ip;
        SoftBusIp6AddrHtp ipv6;
    };
} SoftBusSockAddrHtp;

const SocketInterface *GetHtpProtocol(void);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif // SOFTBUS_HTP_SOCKET_H
