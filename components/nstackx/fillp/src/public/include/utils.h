/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#ifndef FILLP_UTILS_H
#define FILLP_UTILS_H
#include <time.h>
#include "fillp_os.h"
#include "opt.h"
#include "fillp_function.h"
#include "log.h"
#include "securec.h"

#ifdef __cplusplus
extern "C" {
#endif

#define UTILS_FLAGS_SET(_flag, _f) ((_flag) |= (_f))
#define UTILS_FLAGS_GET(_flag, _f) ((_flag) & (_f))
#define UTILS_FLAGS_CLEAN(_flag, _f) ((_flag) &= ~(_f))
#define UTILS_FLAGS_RESET(_flag) ((_flag) &= 0u)
#define UTILS_FLAGS_CHECK(_flag, _f) (((_flag) & (_f)) == (_f))

#define UTILS_ARRAY_LEN(_a) (sizeof(_a) / sizeof((_a)[0]))

#define UTILS_MIN(a, b) ((a) < (b) ? (a) : (b))
#define UTILS_MAX(a, b) ((a) > (b) ? (a) : (b))

#define FILLP_UTILS_MS2US(ms) ((ms) * 1000)
#define FILLP_UTILS_US2MS(us) ((us) / 1000)
#define FILLP_UTILS_US2S(us) ((us) / 1000000)
#define FILLP_UTILS_S2US(s)  ((s) * 1000000)

#define FILLP_UTILS_KBPS2BPS(kbps) ((kbps) * 1000)
#define FILLP_UTILS_BPS2KBPS(bps)  ((bps) / 1000)
#define FILLP_UTILS_BIT2BYTE(bit)  ((bit) >> 3)

#define UTILS_GET_ADDRPORT(addr) ((struct sockaddr_in*) (addr))->sin_port
#define IPV6_ADDR_LEN 16

__inline static FILLP_UINT32 UtilsIpv4AddrPortKey(FILLP_UINT16 port, struct sockaddr_in *remoteAddr)
{
    return (port ^ (remoteAddr)->sin_addr.s_addr);
}

__inline static FILLP_UINT32 UtilsIpv6AddrPortKey(FILLP_UINT16 port, struct sockaddr_in6 *remoteAddr)
{
    FILLP_INT i;
    for (i = 0; i < IPV6_ADDR_LEN; i++) {
        port ^= ((remoteAddr)->sin6_addr.s6_addr[i]);
    }
    return (FILLP_UINT32)port;
}

__inline static FILLP_UINT32 UtilsAddrHashKey(struct sockaddr_in *addr)
{
    FILLP_INT port = UTILS_GET_ADDRPORT(addr);
    socklen_t addrLen = sizeof(struct sockaddr);

    if (((struct sockaddr_in *)(void *)addr)->sin_family == AF_INET6) {
        addrLen = sizeof(struct sockaddr_in6);
    }

    if (addrLen == sizeof(struct sockaddr)) {
        return UtilsIpv4AddrPortKey((FILLP_UINT16)port, addr);
    } else {
        return UtilsIpv6AddrPortKey((FILLP_UINT16)port, (struct sockaddr_in6 *)addr);
    }
}

__inline static FILLP_BOOL UtilsIpv6AddrMatch(FILLP_CONST struct sockaddr_in6 *a, FILLP_CONST struct sockaddr_in6 *b)
{
    FILLP_INT i;
    for (i = 0; i < IPV6_ADDR_LEN; i++) {
        if ((a)->sin6_addr.s6_addr[i] != (b)->sin6_addr.s6_addr[i]) {
            return FILLP_FALSE;
        }
    }
    return FILLP_TRUE;
}

#define UTILS_ADDR_FAMILY_MATCH(a, b) (((struct sockaddr_in *)(void *)(a))->sin_family == \
    ((struct sockaddr_in *)(void *)(b))->sin_family)

#define UTILS_ADDR_PORT_MATCH(a, b) (((struct sockaddr_in *)(void *)(a))->sin_port == \
    ((struct sockaddr_in *)(void *)(b))->sin_port)

#define UTILS_IPV4_ADDR_MATCH(a, b) ((a)->sin_addr.s_addr == (b)->sin_addr.s_addr && \
    UTILS_ADDR_PORT_MATCH((a), (b)))

#define UTILS_IPV6_ADDR_MATCH(a, b) (UTILS_ADDR_PORT_MATCH((a), (b)) && \
    UtilsIpv6AddrMatch((a), (b)))

static __inline FILLP_BOOL UtilsAddrMatch(FILLP_CONST struct sockaddr_in *addrA, FILLP_CONST struct sockaddr_in *addrB)
{
    if (!UTILS_ADDR_FAMILY_MATCH(addrA, addrB)) {
        return FILLP_FALSE;
    }

    if (addrA->sin_family == AF_INET) {
        return (FILLP_BOOL)UTILS_IPV4_ADDR_MATCH(addrA, addrB);
    } else {
        return (FILLP_BOOL)UTILS_IPV6_ADDR_MATCH((struct sockaddr_in6 *)addrA, (struct sockaddr_in6 *)addrB);
    }
}

static __inline void UtilsAddrCopy(struct sockaddr *dest, struct sockaddr *src)
{
    FillpErrorType err;
    if (((struct sockaddr_in *)(void *)src)->sin_family == AF_INET) {
        err = memcpy_s(dest, sizeof(struct sockaddr_in), src, sizeof(struct sockaddr_in));
    } else {
        err = memcpy_s(dest, sizeof(struct sockaddr_in6), src, sizeof(struct sockaddr_in6));
    }
    if (err != EOK) {
        FILLP_LOGERR("utils_addr_copy memcpy_s failed : %d", err);
    }
}

static __inline size_t UtilsAddrValidLength(struct sockaddr_in *addr)
{
    if (((struct sockaddr_in *)(void *)addr)->sin_family == AF_INET) {
        return sizeof(struct sockaddr_in);
    }

    return sizeof(struct sockaddr_in6);
}

#ifdef __cplusplus
}
#endif

#endif /* FILLP_UTILS_H */