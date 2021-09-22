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

#ifndef NSTACKX_NLMSG_H
#define NSTACKX_NLMSG_H
#include <linux/rtnetlink.h>
#include <linux/gen_stats.h>
#include <linux/pkt_sched.h>

#include <asm/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <unistd.h>

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <securec.h>

#define MAX_NETLINK_BUFFER_LEN 32768

typedef void (*NLCB)(struct nlmsghdr *h, void *arg, void *value);
struct NlmsgCallback {
    NLCB nlcb;
    void *arg;
    void *value;
};

static inline int32_t NlMax(int32_t a, int32_t b)
{
    return (a < b) ? b : a;
}

static inline int32_t NlMin(int32_t a, int32_t b)
{
    return (a < b) ? a : b;
}

int32_t NetlinkSocketInit();
int32_t SendNetlinkRequest(int32_t nlSockFd, int32_t ifIndex, uint16_t type);
int32_t RecvNetlinkResponse(int32_t nlSockFd, struct NlmsgCallback *nlcb);
void RecvNetlinkParseAttr(struct rtattr *rta, int32_t len, struct rtattr *tb[], int32_t max);
#endif
