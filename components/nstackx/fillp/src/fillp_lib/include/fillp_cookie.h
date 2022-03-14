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

#ifndef FILLP_COOKIE_H
#define FILLP_COOKIE_H

#include "fillptypes.h"

#ifdef __cplusplus
extern "C" {
#endif


#define FILLP_KEYSIZE             32u
/* Max allowed cookie lifetime is 20 seconds + what ever default configured bu user only */
#define FILLP_MAX_COOKIE_LIFETIME (20 * 1000 * 1000)
/* get STALE_COOKIE error from the server, client add the this preserver time and send the new connect request */
#define FILLP_CLIENT_COOKIE_PRESERVE_TIME (10 * 1000 * 1000)

#define FILLP_BYTES_TO_STORE_COOKIE_GENERATION_TIME 16
/* Below structures are exchanged over network, so there should be no padding, so use pack 1 */
#pragma pack(1)

typedef struct FillpCookieContentSt {
    FILLP_UINT8 digest[FILLP_KEYSIZE];                            /* * HMAC-SHA256 Digest * */
    FILLP_UCHAR arr[FILLP_BYTES_TO_STORE_COOKIE_GENERATION_TIME]; /* time of cookie generation */
    FILLP_UINT32 lifeTime;                                        /* life time in milliseconds */
    FILLP_UINT32 localPacketSeqNumber;                            /* local packet sequence number */

    FILLP_UINT32 remotePacketSeqNumber; /* remote packet sequence number */

    FILLP_UINT32 localMessageSeqNumber; /* local Message sequence number */

    FILLP_UINT32 remoteMessageSeqNumber; /* remote Message sequence number */
    FILLP_UINT32 remoteSendCache;        /* client send to server cache , same as server recv cache */

    FILLP_UINT32 remoteRecvCache; /* client recv from server cache, same as server send cache */
    /* Serever port number. local address is not required is enough to identify the serever uniquily */
    FILLP_UINT16 srcPort;
    FILLP_UINT16 addressType; /* Address type */

    struct sockaddr_in6 remoteSockIpv6Addr;
} FillpCookieContent;


typedef struct InnerfillpCookieContentCalculate {
    FILLP_UINT8 digest[FILLP_KEYSIZE];                            /* * HMAC-SHA256 Digest * */
    FILLP_UCHAR arr[FILLP_BYTES_TO_STORE_COOKIE_GENERATION_TIME]; /* time of cookie generation */
    FILLP_UINT32 lifeTime;                                        /* life time in milliseconds */
    FILLP_UINT32 localPacketSeqNumber;                            /* local packet sequence number */

    FILLP_UINT32 remotePacketSeqNumber; /* remote packet sequence number */

    FILLP_UINT32 localMessageSeqNumber; /* local Message sequence number */

    FILLP_UINT32 remoteMessageSeqNumber; /* remote Message sequence number */
    FILLP_UINT32 remoteSendCache;        /* client send to server cache , same as server recv cache */

    FILLP_UINT32 remoteRecvCache; /* client recv from server cache, same as server send cache */
    /* Serever port number. local address is not required is enough to identify the serever uniquily */
    FILLP_UINT16 srcPort;
    FILLP_UINT16 addressType; /* Address type */

    struct sockaddr_in6 remoteSockIpv6Addr;
    struct sockaddr_in6 localSockIpv6Addr;
} FillpCookieContentCalculate;

#pragma pack()

typedef struct FillpMacInfoStruct {
    FILLP_UINT8 currentMacKey[FILLP_KEYSIZE];
    FILLP_UINT8 oldMacKey[FILLP_KEYSIZE];
    FILLP_ULLONG switchOverTime;
} FillpMacInfo;

void FillpMacTimerExpire(FillpMacInfo *macInfo, FILLP_LLONG curTime);


#ifdef __cplusplus
}
#endif


#endif /* FILLP_COOKIE_H */
