/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "lnn_linkwatch.h"

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifndef __MUSL__
#define __MUSL__
#endif

#include <securec.h>
#include <time.h>
#include <unistd.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "softbus_adapter_errcode.h"
#include "softbus_adapter_socket.h"
#include "softbus_errcode.h"
#include "softbus_log.h"


#define NETLINK_BUF_LEN 1024

static int32_t AddAttr(struct nlmsghdr *nlMsgHdr, uint32_t maxLen, int32_t type,
    const uint8_t *data, uint32_t attrLen)
{
    int32_t len = RTA_LENGTH(attrLen);
    struct rtattr *rta = NULL;

    if (NLMSG_ALIGN(nlMsgHdr->nlmsg_len) + RTA_ALIGN(len) > maxLen) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "AddAttr ERROR: message exceeded bound of %d\n", maxLen);
        return SOFTBUS_ERR;
    }
    rta = ((struct rtattr *) (((uint8_t *) (nlMsgHdr)) + NLMSG_ALIGN((nlMsgHdr)->nlmsg_len)));
    rta->rta_type = (uint16_t)type;
    rta->rta_len = (uint16_t)len;
    if (memcpy_s(RTA_DATA(rta), rta->rta_len, data, attrLen) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "AddAttr ERROR: memcpy attr failed");
        return SOFTBUS_MEM_ERR;
    }
    nlMsgHdr->nlmsg_len = NLMSG_ALIGN(nlMsgHdr->nlmsg_len) + RTA_ALIGN(len);
    return SOFTBUS_OK;
}

static int32_t ProcessNetlinkAnswer(struct nlmsghdr *answer, int32_t bufLen, uint32_t seq)
{
    struct nlmsghdr *hdr = NULL;
    uint32_t len;
    int32_t remain = bufLen;

    for (hdr = (struct nlmsghdr *)answer; remain >= (int32_t)sizeof(*hdr);) {
        len = hdr->nlmsg_len;
        if ((hdr->nlmsg_len - sizeof(*hdr)) < 0 || len > (uint32_t)remain) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "malformed message: len=%d", len);
            return SOFTBUS_ERR;
        }
        if (hdr->nlmsg_seq != seq) {
            // skip that message
            remain -= NLMSG_ALIGN(len);
            hdr = (struct nlmsghdr *)((char *)hdr + NLMSG_ALIGN(len));
            continue;
        }
        if (hdr->nlmsg_type == NLMSG_ERROR) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "ERROR netlink msg");
            return SOFTBUS_ERR;
        }
        return SOFTBUS_OK;
    }
    return SOFTBUS_ERR;
}

static int32_t RtNetlinkTalk(struct nlmsghdr *nlMsgHdr, struct nlmsghdr *answer, uint32_t maxlen)
{
    int32_t status;
    int32_t fd;

    int32_t ret  = SoftBusSocketCreate(SOFTBUS_AF_NETLINK, SOFTBUS_SOCK_RAW, NETLINK_ROUTE, &fd);
    if (ret != SOFTBUS_ADAPTER_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "netlink_socket failed");
        return SOFTBUS_ERR;
    }

    status = SoftBusSocketSend(fd, nlMsgHdr, nlMsgHdr->nlmsg_len, 0);
    if (status != (int32_t)(nlMsgHdr->nlmsg_len)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "Cannot talk to rtnetlink");
        SoftBusSocketClose(fd);
        return SOFTBUS_ERR;
    }

    while (true) {
        status = SoftBusSocketRecv(fd, answer, maxlen, 0);
        if (status < 0) {
            if (status == SOFTBUS_ADAPTER_SOCKET_EINTR || status == SOFTBUS_ADAPTER_SOCKET_EAGAIN) {
                continue;
            }
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "netlink receive error (%d)", status);
            SoftBusSocketClose(fd);
            return SOFTBUS_ERR;
        }
        if (status == 0) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "EOF on netlink\n");
            SoftBusSocketClose(fd);
            return SOFTBUS_ERR;
        }
        SoftBusSocketClose(fd);
        return ProcessNetlinkAnswer(answer, status, nlMsgHdr->nlmsg_seq);
    }
}

static int32_t GetRtAttr(struct rtattr *rta, int32_t len, uint16_t type, uint8_t *value, uint32_t valueLen)
{
    struct rtattr *attr = rta;
    while (RTA_OK(attr, len)) {
        if (attr->rta_type != type) {
            attr = RTA_NEXT(attr, len);
            continue;
        }
        if (memcpy_s(value, valueLen, RTA_DATA(attr), (uint32_t)RTA_PAYLOAD(attr)) != EOK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get attr fail: %d, %d",
                valueLen, RTA_PAYLOAD(attr));
            break;
        }
        return SOFTBUS_OK;
    }
    return SOFTBUS_ERR;
}

bool LnnIsLinkReady(const char *iface)
{
    if (iface == NULL) {
        return false;
    }
    struct ifinfomsg *info = NULL;
    struct {
        struct nlmsghdr hdr;
        struct ifinfomsg info;
        char buf[NETLINK_BUF_LEN];
    } req = {
        .hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg)),
        .hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK,
        .hdr.nlmsg_type = RTM_GETLINK,
        .info.ifi_family = SOFTBUS_PF_UNSPEC,
    };
    struct {
        struct nlmsghdr hdr;
        char buf[NETLINK_BUF_LEN + NETLINK_BUF_LEN];
    } answer;
    int32_t infoDataLen, seq;
    uint8_t carrier;

    seq = time(NULL);
    if (seq < 0) {
        seq = 0;
    }
    req.hdr.nlmsg_seq = ++seq;
    (void)memset_s(&answer, sizeof(answer), 0, sizeof(answer));
    if (AddAttr(&req.hdr, sizeof(req), IFLA_IFNAME, (const uint8_t *)iface, strlen(iface) + 1) != SOFTBUS_OK) {
        return false;
    }
    if (RtNetlinkTalk(&req.hdr, &answer.hdr, sizeof(answer)) != SOFTBUS_OK) {
        return false;
    }
    info = NLMSG_DATA(&answer.hdr);
    infoDataLen = (int32_t)answer.hdr.nlmsg_len - NLMSG_LENGTH(sizeof(struct ifinfomsg));
    if (GetRtAttr(IFLA_RTA(info), infoDataLen, IFLA_CARRIER, &carrier, sizeof(uint8_t)) != SOFTBUS_OK) {
        return false;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "carrier result: %d\n", carrier);
    return carrier != 0;
}