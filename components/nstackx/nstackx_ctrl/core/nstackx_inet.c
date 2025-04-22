/*
 * Copyright (C) 2025-2025 Huawei Device Co., Ltd.
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

#include "nstackx_inet.h"

#ifdef __cplusplus
extern "C" {
#endif

#define IPV4_LOOP_IP "127.0.0.1"
#define IPV6_LOOP_IP "::1"
#define INET_IPV6_LEN 16

uint8_t InetGetAfType(const char *ipStr, union InetAddr *addr)
{
    if (inet_pton(AF_INET, ipStr, &addr->in) > 0) {
        return AF_INET;
    }
    if (inet_pton(AF_INET6, ipStr, &addr->in6) > 0) {
        return AF_INET6;
    }

    return AF_ERROR;
}

static inline bool Inet6Equal(const union InetAddr *a, const union InetAddr *b)
{
    return (memcmp(a->in6.s6_addr, b->in6.s6_addr, INET_IPV6_LEN) == 0);
}

static void InetAddrZero(union InetAddr *ip)
{
    int i;
    for (i = 0; i < (int)sizeof(struct in6_addr); i++) {
        ip->in6.s6_addr[i] = 0;
    }
}

bool InetEqual(uint8_t af, const union InetAddr *a, const union InetAddr *b)
{
    if (af == AF_INET) {
        return (a->in.s_addr == b->in.s_addr);
    }

    return Inet6Equal(a, b);
}

bool InetEqualZero(uint8_t af, const union InetAddr *a)
{
    union InetAddr zero;
    InetAddrZero(&zero);
    return InetEqual(af, a, &zero);
}

bool InetEqualNone(uint8_t af, const union InetAddr *a)
{
    int i;
    union InetAddr none;

    for (i = 0; i < (int)sizeof(struct in6_addr); i++) {
        none.in6.s6_addr[i] = 0xff; // INADDR_NONE 0xff
    }

    return InetEqual(af, a, &none);
}

bool InetEqualLoop(uint8_t af, const char *ip)
{
    const char *loopIp = af == AF_INET ? IPV4_LOOP_IP : IPV6_LOOP_IP;
    return (strlen(ip) == strlen(loopIp) && strcmp(ip, loopIp) == 0);
}
#ifdef __cplusplus
}
#endif