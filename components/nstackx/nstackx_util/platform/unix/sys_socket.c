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

static int32_t g_gsoSupport = 0;

int32_t SupportGSO(void)
{
    return g_gsoSupport;
}

void SocketModuleClean(void)
{
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
#ifndef NSTACKX_WITH_HMOS_LINUX
static int32_t SendUdpSegment(struct sockaddr_in *sa)
{
    int32_t err;
    char ctrl[CMSG_SPACE(sizeof(uint16_t))] = {0};
    struct msghdr mh;
    char buf[DEFAULT_UDP_MSS];
    struct iovec iov[IOV_CNT] = {
        {
            .iov_base = buf,
            .iov_len = sizeof(buf),
        },
        {
            .iov_base = buf,
            .iov_len = sizeof(buf),
        }
    };
    int32_t fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return NSTACKX_EFAILED;
    }

    mh.msg_name = (struct sockaddr *)sa;
    mh.msg_namelen = sizeof(struct sockaddr_in);
    mh.msg_iov = iov;
    mh.msg_iovlen = IOV_CNT;
    mh.msg_control = ctrl;
    mh.msg_controllen = sizeof(ctrl);
    mh.msg_flags = 0;

    SetupCmsg(CMSG_FIRSTHDR(&mh), DEFAULT_UDP_MSS);

    err = (int32_t)sendmsg(fd, &mh, 0);
    if (close(fd) < 0) {
        return NSTACKX_EFAILED;
    }
    return (err == (IOV_CNT * DEFAULT_UDP_MSS)) ? NSTACKX_EOK : NSTACKX_EFAILED;
}

static void RecvUdpSegment(int32_t fd)
{
    ssize_t err;
    char buf[DEFAULT_MAX_BUF];

    err = recvfrom(fd, buf, sizeof(buf), 0, NULL, NULL);
    if (err == DEFAULT_UDP_MSS) {
        err = recvfrom(fd, buf, sizeof(buf), 0, NULL, NULL);
        if (err == DEFAULT_UDP_MSS) {
            g_gsoSupport = 1;
            LOGI(TAG, "kernel support UDP GSO");
        } else {
            LOGI(TAG, "kernel does not support UDP GSO");
        }
    } else {
        LOGI(TAG, "kernel does not support UDP GSO");
    }
}

static int32_t LocalAddrBindAndGet(int32_t fd, struct sockaddr_in *sa)
{
    int32_t err;
    socklen_t len = sizeof(*sa);

    sa->sin_family = AF_INET;
    sa->sin_port = 0;
    sa->sin_addr.s_addr = inet_addr("127.0.0.1");
    err = bind(fd, (struct sockaddr *)sa, len);
    if (err) {
        return NSTACKX_EFAILED;
    }

    err = getsockname(fd, (struct sockaddr *)sa, &len);
    if (err) {
        return NSTACKX_EFAILED;
    }
    return NSTACKX_EOK;
}
#endif

void CheckGSOSupport(void)
{
#ifndef NSTACKX_WITH_HMOS_LINUX
    int32_t fd;
    struct sockaddr_in sa = {0};

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return;
    }
    if (LocalAddrBindAndGet(fd, &sa) != NSTACKX_EOK) {
        goto L_OUT;
    }

    if (SendUdpSegment(&sa) != NSTACKX_EOK) {
        goto L_OUT;
    }

    RecvUdpSegment(fd);

L_OUT:
    CloseSocketInner(fd);
#endif
}

int32_t SocketOpInProgress(void)
{
    return errno == EINPROGRESS;
}

int32_t SocketOpWouldBlock(void)
{
    return errno == EAGAIN || errno == EWOULDBLOCK;
}
