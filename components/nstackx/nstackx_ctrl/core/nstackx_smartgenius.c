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

#include "nstackx_smartgenius.h"
#include <errno.h>
#include <string.h>
#include <securec.h>
#include <sys/types.h>
#ifdef SUPPORT_SMARTGENIUS
#include <sys/socket.h>
#include <unistd.h>
#include <linux/rtnetlink.h>
#include <arpa/inet.h>
#endif /* SUPPORT_SMARTGENIUS */

#include "nstackx_log.h"
#include "nstackx_error.h"
#include "nstackx_util.h"
#include "nstackx_epoll.h"
#include "nstackx_device.h"
#include "nstackx_timer.h"
#include "coap_discover/coap_discover.h"

#define TAG "nStackXDFinder"
#ifdef SUPPORT_SMARTGENIUS
#define BUFLEN 256
#define NSTACKX_POSTPONE_DELAY_MS 500
static EpollTask g_netlinkTask;
static Timer *g_postponeTimer;
static uint8_t g_smartGeniusInit = NSTACKX_FALSE;

static void ParseRTattr(struct rtattr **tb, uint32_t max, struct rtattr *attr, uint32_t len)
{
    /*
     * Use macro RTA_OK() and RTA_NEXT() to iterate attribute list, and fill table "tb" with attribute whose type is not
     * greater than "max".
     */
    for (; RTA_OK(attr, len); attr = RTA_NEXT(attr, len)) {
        if (attr->rta_type <= max) {
            tb[attr->rta_type] = attr;
        }
    }
}

static void IfAddrMsgHandle(struct nlmsghdr *msgHdr)
{
    struct rtattr *tb[IFA_MAX + 1] = {0}; /* Table to store rtnetlink attribute pointers */
    struct ifaddrmsg *ifAddr = NLMSG_DATA(msgHdr); /* Get IP address information from message */
    if (msgHdr->nlmsg_len < NLMSG_SPACE(sizeof(struct ifaddrmsg))) {
        return;
    }
    uint32_t len = msgHdr->nlmsg_len - NLMSG_SPACE(sizeof(struct ifaddrmsg));
    NetworkInterfaceInfo interfaceInfo;

    (void)memset_s(&interfaceInfo, sizeof(interfaceInfo), 0, sizeof(interfaceInfo));
    /* Parse attribute in "ifAddr", and store attribute pointers in "tb" */
    ParseRTattr(tb, IFA_MAX, IFA_RTA(ifAddr), len);
    if (tb[IFA_LABEL] == NULL || tb[IFA_ADDRESS] == NULL) {
        return;
    }

    /* Use macro RTA_DATA() to get network insterface name from attribute "IFA_LABEL". */
    if (!FilterNetworkInterface((char *)RTA_DATA(tb[IFA_LABEL]))) {
        return;
    }

    if (ifAddr->ifa_family != AF_INET) {
        return;
    }

    if (strcpy_s(interfaceInfo.name, sizeof(interfaceInfo.name), (char *)RTA_DATA(tb[IFA_LABEL])) != EOK) {
        return;
    }

    if (msgHdr->nlmsg_type == RTM_NEWADDR) {
        if (memcpy_s(&interfaceInfo.ip, sizeof(interfaceInfo.ip),
            RTA_DATA(tb[IFA_ADDRESS]), sizeof(interfaceInfo.ip)) != EOK) {
            return;
        }
        /* delay 500 ms after WiFi connection avoid "Network Unreachable" error, only activate when wlan/eth online */
        if (!(IsUsbIpAddr((char *)RTA_DATA(tb[IFA_LABEL])) || IsP2pIpAddr((char *)RTA_DATA(tb[IFA_LABEL])))) {
            TimerSetTimeout(g_postponeTimer, NSTACKX_POSTPONE_DELAY_MS, NSTACKX_FALSE);
        }
        LOGD(TAG, "Interface %s got new address.", interfaceInfo.name);
    } else {
        LOGD(TAG, "Interface %s delete address.", interfaceInfo.name);
    }

    if (IsP2pIpAddr((char *)RTA_DATA(tb[IFA_LABEL]))) {
        UpdateLocalNetworkInterfaceP2pMode(&interfaceInfo, msgHdr->nlmsg_type);
    } else if (IsUsbIpAddr((char *)RTA_DATA(tb[IFA_LABEL]))) {
        UpdateLocalNetworkInterfaceUsbMode(&interfaceInfo, msgHdr->nlmsg_type);
    } else {
        UpdateLocalNetworkInterface(&interfaceInfo);
    }
}

static void SmartGeniusCallback(void *arg)
{
    struct nlmsghdr *innerNlmsghdr = NULL;
    struct nlmsgerr *nlmErr = NULL;
    char innerBuf[BUFLEN] = {0};
    struct sockaddr_nl peer = {AF_NETLINK, 0, 0, 0};
    int len;
    socklen_t socklen;
    EpollTask *task = arg;

    socklen = sizeof(struct sockaddr_nl);
    len = recvfrom(task->taskfd, innerBuf, BUFLEN, 0, (struct sockaddr *)&peer, &socklen);
    if (len <= 0) {
        LOGE(TAG, "recvfrom error %d", errno);
        return;
    }

    innerNlmsghdr = (struct nlmsghdr *)innerBuf;
    switch (innerNlmsghdr->nlmsg_type) {
        case RTM_NEWADDR:
        case RTM_DELADDR: {
            IfAddrMsgHandle(innerNlmsghdr);
            break;
        }
        case NLMSG_ERROR: {
            nlmErr = NLMSG_DATA(innerNlmsghdr);
            if (nlmErr->error == 0) {
                LOGD(TAG, "NLMSG_ACK");
            } else {
                LOGE(TAG, "NLMSG_ERROR");
            }
            break;
        }
        default:
            break;
    }
    return;
}

static void PostponeTimerHandle(void *data)
{
    (void)data;
    CoapServiceDiscoverInner(0);
}

int32_t SmartGeniusInit(EpollDesc epollfd)
{
    socklen_t len;
    struct sockaddr_nl local = {0};
    int fd = -1;

    if (g_smartGeniusInit) {
        return NSTACKX_EOK;
    }

    local.nl_family = AF_NETLINK;
    local.nl_groups = RTMGRP_NOTIFY | RTMGRP_IPV4_IFADDR | RTMGRP_IPV4_ROUTE | RTMGRP_LINK;
    local.nl_pid = getpid();
    len = sizeof(local);

    fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (fd < 0) {
        LOGE(TAG, "unable to create netlink socket: %d", errno);
        return NSTACKX_EFAILED;
    }

    if (bind(fd, (struct sockaddr *)&local, sizeof(local)) < 0) {
        LOGE(TAG, "bind for netlink socket failed: %d", errno);
        close(fd);
        return NSTACKX_EFAILED;
    }

    if (getsockname(fd, (struct sockaddr *)&local, &len) < 0) {
        LOGE(TAG, "getsockname failed: %d", errno);
        close(fd);
        return NSTACKX_EFAILED;
    }

    g_netlinkTask.taskfd = fd;
    g_netlinkTask.epollfd = epollfd;
    g_netlinkTask.readHandle = SmartGeniusCallback;
    g_netlinkTask.writeHandle = NULL;
    g_netlinkTask.errorHandle = NULL;
    g_netlinkTask.endHandle = NULL;
    g_netlinkTask.count = 0;
    if (RegisterEpollTask(&g_netlinkTask, EPOLLIN) != NSTACKX_EOK) {
        close(fd);
        LOGE(TAG, "RegisterEpollTask fail");
        return NSTACKX_EFAILED;
    }

    g_postponeTimer = TimerStart(epollfd, 0, NSTACKX_FALSE, PostponeTimerHandle, NULL);
    if (g_postponeTimer == NULL) {
        DeRegisterEpollTask(&g_netlinkTask);
        close(g_netlinkTask.taskfd);
        LOGE(TAG, "Create timer fail");
        return NSTACKX_EFAILED;
    }

    g_smartGeniusInit = NSTACKX_TRUE;
    return NSTACKX_EOK;
}

void SmartGeniusClean(void)
{
    if (!g_smartGeniusInit) {
        return;
    }

    TimerDelete(g_postponeTimer);
    g_postponeTimer = NULL;
    DeRegisterEpollTask(&g_netlinkTask);
    close(g_netlinkTask.taskfd);
    g_smartGeniusInit = NSTACKX_FALSE;
}

void ResetSmartGeniusTaskCount(uint8_t isBusy)
{
    if (isBusy) {
        LOGI(TAG, "in this busy interval: g_netlinkTask count %llu", g_netlinkTask.count);
    }
    g_netlinkTask.count = 0;

    if (g_postponeTimer != NULL) {
        if (isBusy) {
            LOGI(TAG, "in this busy interval: g_postponeTimer task count %llu", g_postponeTimer->task.count);
        }
        g_postponeTimer->task.count = 0;
    }
}
#else
int32_t SmartGeniusInit(EpollDesc epollfd)
{
    (void)epollfd;
    return NSTACKX_EOK;
}

void SmartGeniusClean(void)
{
}

void ResetSmartGeniusTaskCount(uint8_t isBusy)
{
    (void)isBusy;
}
#endif /* SUPPORT_SMARTGENIUS */
