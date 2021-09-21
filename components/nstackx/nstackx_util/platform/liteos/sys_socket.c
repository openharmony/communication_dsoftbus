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

#include "nstackx_socket.h"
#include "nstackx_log.h"
#include "nstackx_error.h"
#include "nstackx_util.h"
#include "nstackx_dev.h"
#include "securec.h"

#define DEFAULT_UDP_MSS 1472
#define DEFAULT_MAX_BUF 4096
#define IOV_CNT 2

#define TAG "nStackXSocket"
#ifndef SOL_UDP
#define SOL_UDP 17
#endif

void SocketModuleClean(void)
{
    return;
}

int32_t SocketModuleInit(void)
{
    return NSTACKX_EOK;
}

int32_t SetSocketNonBlock(SocketDesc fd)
{
    int32_t flag;

    flag = fcntl(fd, F_GETFL, 0);
    if (flag < 0) {
        LOGE(TAG, "fcntl GETFL error");
        return NSTACKX_EFAILED;
    }

    if (fcntl(fd, F_SETFL, (unsigned int)flag | O_NONBLOCK) < 0) {
        LOGE(TAG, "fcntl SETFL error");
        return NSTACKX_EFAILED;
    }
    return NSTACKX_EOK;
}

int32_t SocketOpInProgress(void)
{
    return errno == EINPROGRESS;
}

int32_t SocketOpWouldBlock(void)
{
    return errno == EAGAIN || errno == EWOULDBLOCK;
}

int32_t SupportGSO(void)
{
    return 0;
}

void CheckGSOSupport(void)
{
    LOGI(TAG, "kernel does not support UDP GSO");
}

#ifndef UDP_SEGMENT
#define UDP_SEGMENT     103
#endif

static inline void SetupCmsg(struct cmsghdr *cm, uint16_t mss)
{
    cm->cmsg_level = SOL_UDP;
    cm->cmsg_type = UDP_SEGMENT;
    cm->cmsg_len = CMSG_LEN(sizeof(mss));
    *(uint16_t *)(void *)CMSG_DATA(cm) = mss;
}

static inline int32_t IsSocketValid(const Socket *s)
{
    return !(s == NULL || s->protocol != NSTACKX_PROTOCOL_UDP);
}

int32_t SocketSendEx(const Socket *s, uint16_t mss, const struct iovec *iov, uint32_t cnt)
{
    int32_t ret = NSTACKX_EFAILED;
    char ctrl[CMSG_SPACE(sizeof(uint16_t))] = {0};
    struct msghdr mh;

    if (!IsSocketValid(s)) {
        LOGE(TAG, "invalid socket input\n");
        return ret;
    }

    mh.msg_name = (struct sockaddr *)&s->dstAddr;
    mh.msg_namelen = sizeof(struct sockaddr_in);
    mh.msg_iov = (struct iovec *)iov;
    mh.msg_iovlen = (size_t)cnt;
    mh.msg_control = ctrl;
    mh.msg_controllen = sizeof(ctrl);
    mh.msg_flags = 0;

    SetupCmsg(CMSG_FIRSTHDR(&mh), mss);

    ret = (int32_t)sendmsg(s->sockfd, &mh, 0);
    if (ret <= 0) {
        ret = CheckSocketError();
    }

    return ret;
}

