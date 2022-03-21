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

#include "check_gso_support.h"
#ifdef FILLP_SUPPORT_GSO
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <error.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#define IOV_CNT 2
#define RECV_BUF 4096

FILLP_INT g_gsoSupport = FILLP_FALSE;

static FILLP_INT SendUdpSegment(struct sockaddr_in *sa)
{
    FILLP_INT err;
    FILLP_CHAR ctrl[CMSG_SPACE(sizeof(FILLP_UINT16))] = {0};
    struct msghdr mh;
    struct cmsghdr *cm = FILLP_NULL_PTR;
    FILLP_CHAR buf[CFG_MSS];
    FILLP_UINT16 *valp = FILLP_NULL_PTR;

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
    FILLP_INT fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return FILLP_FALSE;
    }

    mh.msg_name = (struct sockaddr *)sa;
    mh.msg_namelen = sizeof(struct sockaddr_in);
    mh.msg_iov = iov;
    mh.msg_iovlen = IOV_CNT;
    mh.msg_control = ctrl;
    mh.msg_controllen = sizeof(ctrl);
    mh.msg_flags = 0;

    cm = CMSG_FIRSTHDR(&mh);
    cm->cmsg_level = SOL_UDP;
    cm->cmsg_type = UDP_SEGMENT;
    cm->cmsg_len = CMSG_LEN(sizeof(FILLP_UINT16));
    valp = (FILLP_UINT16 *)(void *)CMSG_DATA(cm);
    *valp = CFG_MSS;

    err = (FILLP_INT)sendmsg(fd, &mh, 0);
    (void)close(fd);
    return (err == (IOV_CNT * CFG_MSS)) ? FILLP_TRUE : FILLP_FALSE;
}

static void RecvUdpSegment(FILLP_INT fd)
{
    FILLP_INT err;
    FILLP_CHAR buf[RECV_BUF];

    err = (FILLP_INT)recvfrom(fd, buf, sizeof(buf), 0, FILLP_NULL_PTR, FILLP_NULL_PTR);
    if (err == CFG_MSS) {
        err = (FILLP_INT)recvfrom(fd, buf, sizeof(buf), 0, FILLP_NULL_PTR, FILLP_NULL_PTR);
        if (err == CFG_MSS) {
            g_gsoSupport = FILLP_TRUE;
            FILLP_LOGINF("kernel support UDP GSO");
        } else {
            FILLP_LOGINF("kernel does not support UDP GSO");
        }
    } else {
        FILLP_LOGINF("kernel does not support UDP GSO");
    }
}

void CheckGSOSupport(void)
{
    static FILLP_BOOL chked = FILLP_FALSE;
    FILLP_INT ret;
    FILLP_INT fd = -1;
    struct sockaddr_in sa = {0};
    socklen_t len = sizeof(sa);

    if (chked != FILLP_FALSE) {
        return;
    }

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        FILLP_LOGERR("check gso create socket failed");
        return;
    }

    sa.sin_family = AF_INET;
    sa.sin_port = 0;
    sa.sin_addr.s_addr = inet_addr("127.0.0.1");

    ret = bind(fd, (struct sockaddr *)&sa, len);
    if (ret) {
        FILLP_LOGERR("check gso bind failed");
        goto L_OUT;
    }

    ret = getsockname(fd, (struct sockaddr *)&sa, &len);
    if (ret) {
        FILLP_LOGERR("check gso getsockname failed");
        goto L_OUT;
    }

    if (SendUdpSegment(&sa) != FILLP_TRUE) {
        FILLP_LOGERR("check gso send failed");
        goto L_OUT;
    }

    RecvUdpSegment(fd);
    chked = FILLP_TRUE;
L_OUT:
    (void)close(fd);
}
#endif
