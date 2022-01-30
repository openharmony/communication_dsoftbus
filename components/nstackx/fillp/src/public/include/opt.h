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

#ifndef FILLP_OPT_H
#define FILLP_OPT_H

#include "fillptypes.h"
#include "constant.h"
#include "pdt_fc.h"

#ifdef __cplusplus
extern "C" {
#endif

#define IP_HLEN 20
#define UDP_HLEN 8

#define FILLP_VLEN 1

struct NetBuf {
    FILLP_INT len; // (data length+option)
    FILLP_UINT8 padd[4];
    struct sockaddr_in6 addr;
    struct FtSocket *ftSock;
    FILLP_CHAR *p;
};


#define FILLP_MAX_STACK_RATE (10 * 1000 * 1000)      /* 10 Gbps */
#define FILLP_MAX_STACK_RECV_RATE (10 * 1000 * 1000) /* 10 Gbps */

#define FILLP_ITEM_MULT_NUM 2          /* fillp item multiplication number */
#define FILLP_SPUNGE_EVENTG_MULT_NUM 3 /* multiplication number for spunge event queue */
#define FILLP_TIME_PRECISION 3         /* time precision */

#define FILLP_RTT_TIME_LEVEL1_HALF 100000
#define FILLP_RTT_TIME_LEVEL1 200000 /* rtt time */
#define FILLP_RTT_TIME_LEVEL2 400000 /* min packet interval if rtt is more then default rtt */
#define FILLP_NODATARECV_PACK_INTERVAL 500000

#define FILLP_ONE_THIRD_OF_RTT 3  /* one third part of rtt */
#define FILLP_ONE_FOURTH_OF_RTT 4 /* one fourth part of rtt */
#define FILLP_ONE_FIFTH_OF_RTT 5  /* one fifth part of rtt */
#define FILLP_ONE_SIXTH_OF_RTT 6
#define FILLP_ONE_SEVEN_OF_RTT 7
#define FILLP_ONE_EIGHTH_OF_RTT 8

#define FILLP_MIN_NACK_INTERVAL 20000

/* max server allow send cache */
#define FILLP_DEFAULT_APP_MAX_SERVER_ALLOW_SEND_CACHE FILLP_MAX_SERVER_ALLOW_SEND_RECV_CACHE
/* max server allow recv catche */
#define FILLP_DEFAULT_APP_MAX_SERVER_ALLOW_RECV_CACHE FILLP_MAX_SERVER_ALLOW_SEND_RECV_CACHE

#define FILLP_WR_DATA_CHECK_INTERVAL (50 * 1000)

#define FILLP_DEFAULT_APP_OPPOSITE_SET_RATE 0 /* Only for Server */

#define FILLP_DEFAULT_MB_TO_KB_FACTOR 1000 /* recv rate in MB */

#define FILLP_DEFAULT_OPPOSITE_SET_PERCENTAGE 100 /* Only for Server */
#define FILLP_DEFAULT_MAX_RATE_PERCENTAGE 100
#define FILLP_MAX_LOSS_PERCENTAGE 100

#ifdef __cplusplus
}
#endif

#endif /* FILLP_OPT_H */
