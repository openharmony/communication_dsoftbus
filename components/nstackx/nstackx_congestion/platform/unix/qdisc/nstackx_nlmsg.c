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

#include "nstackx_nlmsg.h"

#include <errno.h>
#include <pthread.h>

#include "nstackx_error.h"
#include "nstackx_log.h"
#include "nstackx_timer.h"
#include "nstackx_util.h"

#define TAG "nStackXCongestion"
#define NETLINK_REQUEST_IOV_NUM 2

int32_t NetlinkSocketInit()
{
    int32_t nlSockFd = socket(PF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (nlSockFd < 0) {
        LOGE(TAG, "Open netlink socket failed");
        return NSTACKX_EFAILED;
    }

    struct sockaddr_nl nlSockSrcAddr;
    (void)memset_s(&nlSockSrcAddr, sizeof(nlSockSrcAddr), 0, sizeof(nlSockSrcAddr));
    nlSockSrcAddr.nl_family = AF_NETLINK;
    nlSockSrcAddr.nl_groups = 0;

    int32_t ret = bind(nlSockFd, (struct sockaddr *)&nlSockSrcAddr, sizeof(nlSockSrcAddr));
    if (ret < 0) {
        LOGE(TAG, "Bind failed");
        CloseSocketInner(nlSockFd);
        return NSTACKX_EFAILED;
    }
    return nlSockFd;
}

int32_t SendNetlinkRequest(int32_t nlSockFd, int32_t ifIndex, uint16_t type)
{
    static uint32_t requestReqIndex = 0;
    if (nlSockFd < 0 || ifIndex < 0) {
        return NSTACKX_EFAILED;
    }

    struct tcmsg t = { .tcm_family = AF_UNSPEC };
    t.tcm_ifindex = ifIndex;

    void *req = (void *)&t;
    int32_t len = sizeof(t);

    struct nlmsghdr nlh = {
        .nlmsg_len = NLMSG_LENGTH((uint32_t)len),
        .nlmsg_type = type,
        .nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST,
        .nlmsg_seq = requestReqIndex,
    };
    requestReqIndex++;

    struct iovec iov[NETLINK_REQUEST_IOV_NUM] = {
        {
            .iov_base = &nlh,
            .iov_len = sizeof(nlh)
        },
        {
            .iov_base = req,
            .iov_len = len
        }
    };

    struct sockaddr_nl nlSockDstAddr = { .nl_family = AF_NETLINK };

    struct msghdr requestMsg = {
        .msg_name = &nlSockDstAddr,
        .msg_namelen = sizeof(nlSockDstAddr),
        .msg_iov = iov,
        .msg_iovlen = NETLINK_REQUEST_IOV_NUM,
    };

    ssize_t ret = sendmsg(nlSockFd, &requestMsg, 0);
    if (ret <= 0) {
        LOGE(TAG, "ret %d errno %d", ret, errno);
        return NSTACKX_EFAILED;
    }

    return NSTACKX_EOK;
}

static int32_t ParseNetlinkMsg(char *buf, int32_t recvlen, struct NlmsgCallback *nlcb)
{
    struct nlmsghdr *h = (struct nlmsghdr *)buf;
    int32_t msglen = recvlen;

    while (NLMSG_OK(h, (__u32)msglen)) {
        if (h->nlmsg_type == NLMSG_DONE) {
            return NLMSG_DONE;
        }
        if (h->nlmsg_type == NLMSG_ERROR) {
            LOGE(TAG, "h->nlmsg_type == NLMSG_ERROR");
            return NLMSG_ERROR;
        }
        nlcb->nlcb(h, nlcb->arg, nlcb->value);
        h = NLMSG_NEXT(h, msglen);
    }
    return NLMSG_NOOP;
}

int32_t RecvNetlinkResponse(int32_t nlSockFd, struct NlmsgCallback *nlcb)
{
    struct sockaddr_nl nlAddr;
    struct iovec iovRecv;
    int32_t ret;
    int32_t parseValue = NLMSG_DONE;
    iovRecv.iov_base = NULL;
    iovRecv.iov_len = 0;

    struct msghdr msg = {
        .msg_name = &nlAddr,
        .msg_namelen = sizeof(nlAddr),
        .msg_iov = &iovRecv,
        .msg_iovlen = 1,
    };

    int32_t recvLen;
    char buf[MAX_NETLINK_BUFFER_LEN] = {0};
    iovRecv.iov_base = buf;
    iovRecv.iov_len = MAX_NETLINK_BUFFER_LEN;

    while (1) {
        recvLen = (int32_t)recvmsg(nlSockFd, &msg, 0);
        if (recvLen <= 0) {
            LOGE(TAG, "2 recvlen %d netlink receive error %s (%d)", recvLen, strerror(errno), errno);
            return NSTACKX_EFAILED;
        }

        ret = ParseNetlinkMsg(buf, recvLen, nlcb);
        if (ret == NLMSG_DONE) {
            break;
        } else if (ret == NLMSG_ERROR) {
            parseValue = NLMSG_ERROR;
        }
    }
    if (parseValue == NLMSG_ERROR) {
        return NSTACKX_EFAILED;
    }

    return NSTACKX_EOK;
}

void RecvNetlinkParseAttr(struct rtattr *rta, int32_t len, struct rtattr *tb[], int32_t max)
{
    size_t tbLength = ((size_t)sizeof(struct rtattr *) * (size_t)(max + 1));
    (void)memset_s(tb, tbLength, 0, tbLength);
    for (; RTA_OK(rta, len); rta = RTA_NEXT(rta, len)) {
        if ((rta->rta_type <= max) && (!tb[rta->rta_type])) {
            tb[rta->rta_type] = rta;
        }
    }
}
