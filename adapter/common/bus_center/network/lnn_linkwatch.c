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
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "lnn_log.h"
#include "softbus_adapter_errcode.h"
#include "softbus_adapter_socket.h"
#include "softbus_def.h"
#include "softbus_error_code.h"

#define NETLINK_BUF_LEN 1024

static int32_t AddAttr(struct nlmsghdr *nlMsgHdr, uint32_t maxLen, uint16_t type,
    const uint8_t *data, uint16_t attrLen)
{
    uint16_t len = RTA_LENGTH(attrLen);
    struct rtattr *rta = NULL;

    if (NLMSG_ALIGN(nlMsgHdr->nlmsg_len) + RTA_ALIGN(len) > maxLen) {
        LNN_LOGE(LNN_BUILDER, "message exceeded bound. maxLen=%{public}d", maxLen);
        return SOFTBUS_NETWORK_INVALID_NLMSG;
    }
    rta = ((struct rtattr *) (((uint8_t *) (nlMsgHdr)) + NLMSG_ALIGN((nlMsgHdr)->nlmsg_len)));
    rta->rta_type = type;
    rta->rta_len = len;
    if (memcpy_s(RTA_DATA(rta), rta->rta_len, data, attrLen) != EOK) {
        LNN_LOGE(LNN_BUILDER, "memcpy attr failed");
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
            LNN_LOGE(LNN_BUILDER, "malformed message: len=%{public}d", len);
            return SOFTBUS_NETWORK_INVALID_NLMSG;
        }
        if (hdr->nlmsg_seq != seq) {
            // skip that message
            remain -= NLMSG_ALIGN(len);
            hdr = (struct nlmsghdr *)((char *)hdr + NLMSG_ALIGN(len));
            continue;
        }
        if (hdr->nlmsg_type == NLMSG_ERROR) {
            LNN_LOGE(LNN_BUILDER, "netlink msg err");
            return SOFTBUS_NETWORK_INVALID_NLMSG;
        }
        return SOFTBUS_OK;
    }
    return SOFTBUS_NETWORK_INVALID_NLMSG;
}

static int32_t RtNetlinkTalk(struct nlmsghdr *nlMsgHdr, struct nlmsghdr *answer, uint32_t maxlen)
{
    int32_t status;
    int32_t fd;

    int32_t ret  = SoftBusSocketCreate(SOFTBUS_AF_NETLINK, SOFTBUS_SOCK_RAW, NETLINK_ROUTE, &fd);
    if (ret != SOFTBUS_ADAPTER_OK) {
        LNN_LOGE(LNN_BUILDER, "netlink_socket failed");
        return SOFTBUS_NETWORK_CREATE_SOCKET_FAILED;
    }

    status = SoftBusSocketSend(fd, nlMsgHdr, nlMsgHdr->nlmsg_len, 0);
    if (status != (int32_t)(nlMsgHdr->nlmsg_len)) {
        LNN_LOGE(LNN_BUILDER, "Cannot talk to rtnetlink");
        SoftBusSocketClose(fd);
        return SOFTBUS_NETWORK_SOCKET_SEND_FAILED;
    }

    while (true) {
        LNN_LOGI(LNN_BUILDER, "SoftBusSocketRecv begin");
        status = SoftBusSocketRecv(fd, answer, maxlen, 0);
        LNN_LOGI(LNN_BUILDER, "SoftBusSocketRecv end");
        if (status < 0) {
            if (status == SOFTBUS_ADAPTER_SOCKET_EINTR || status == SOFTBUS_ADAPTER_SOCKET_EAGAIN) {
                continue;
            }
            LNN_LOGE(LNN_BUILDER, "netlink receive error, status=%{public}d", status);
            SoftBusSocketClose(fd);
            return SOFTBUS_NETWORK_SOCKET_RECV_FAILED;
        }
        if (status == 0) {
            LNN_LOGE(LNN_BUILDER, "EOF on netlink");
            SoftBusSocketClose(fd);
            return SOFTBUS_NETWORK_SOCKET_RECV_FAILED;
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
            LNN_LOGE(LNN_BUILDER, "get attr fail. valueLen=%{public}d, attr=%{public}u",
                valueLen, (uint32_t)RTA_PAYLOAD(attr));
            break;
        }
        return SOFTBUS_OK;
    }
    return SOFTBUS_NETWORK_NETLINK_GET_ATTR_FAILED;
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
    uint16_t len = (uint16_t)strlen(iface) + 1;
    if (AddAttr(&req.hdr, sizeof(req), IFLA_IFNAME, (const uint8_t *)iface, len) != SOFTBUS_OK) {
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
    return carrier != 0;
}