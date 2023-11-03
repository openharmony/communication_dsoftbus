/*
 * Copyright (C) 2021-2023 Huawei Device Co., Ltd.
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
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <arpa/inet.h>
#endif /* SUPPORT_SMARTGENIUS */
#include <time.h>

#include "nstackx_dfinder_log.h"
#include "nstackx_error.h"
#include "nstackx_util.h"
#include "nstackx_epoll.h"
#include "nstackx_device.h"
#include "nstackx_timer.h"
#include "coap_discover/coap_discover.h"
#include "nstackx_statistics.h"
#include "nstackx_device_local.h"
#include "nstackx_device_remote.h"

#define TAG "nStackXDFinder"
#ifdef SUPPORT_SMARTGENIUS
#define BUFLEN 256
#define NSTACKX_POSTPONE_DELAY_MS 500
#define NSTACKX_NETLINK_RECOVER_MS 300000 // 5min
#define NSTACKX_ERROR_INTERVAL_S 5 // 5s

typedef enum {
    NETLINK_SOCKET_READ_EVENT = 0,
    NETLINK_SOCKET_WRITE_EVENT,
    NETLINK_SOCKET_ERROR_EVENT,
    NETLINK_SOCKET_EVENT
} NetLinkSocketEventType;
static uint64_t g_netlinkSocketEventNum[NETLINK_SOCKET_EVENT];

static EpollTask g_netlinkTask;
static uint8_t g_smartGeniusInit = NSTACKX_FALSE;
static Timer *g_recoverTimer;
static long g_lastErrorTimeS = -1;

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

static int CreateNetLinkSocketFd()
{
    struct sockaddr_nl local = {0};
    local.nl_family = AF_NETLINK;
    local.nl_groups = RTMGRP_NOTIFY | RTMGRP_IPV4_IFADDR | RTMGRP_IPV4_ROUTE | RTMGRP_LINK;
    local.nl_pid = getpid();
    socklen_t len = sizeof(local);

    int fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (fd < 0) {
        DFINDER_LOGE(TAG, "unable to create netlink socket: %d", errno);
        return NSTACKX_EFAILED;
    }
    if (bind(fd, (struct sockaddr *)&local, len) < 0) {
        DFINDER_LOGE(TAG, "bind for netlink socket failed: %d", errno);
        close(fd);
        return NSTACKX_EFAILED;
    }
    if (getsockname(fd, (struct sockaddr *)&local, &len)) {
        DFINDER_LOGE(TAG, "getsockname failed: %d", errno);
        close(fd);
        return NSTACKX_EFAILED;
    }
    return fd;
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

    if (ifAddr->ifa_family != AF_INET) {
        return;
    }

    if (strcpy_s(interfaceInfo.name, sizeof(interfaceInfo.name), (char *)RTA_DATA(tb[IFA_LABEL])) != EOK) {
        return;
    }

    UpdateAllNetworkInterfaceNameIfNeed(&interfaceInfo);

    /* Use macro RTA_DATA() to get network insterface name from attribute "IFA_LABEL". */
    uint8_t ifaceType = GetIfaceType((char *)RTA_DATA(tb[IFA_LABEL]));
    if (ifaceType >= IFACE_TYPE_UNKNOWN) {
        DFINDER_LOGE(TAG, "unknown iface type %s", (char *)RTA_DATA(tb[IFA_LABEL]));
        return;
    }

    if (msgHdr->nlmsg_type == RTM_NEWADDR) {
        if (memcpy_s(&interfaceInfo.ip, sizeof(interfaceInfo.ip),
            RTA_DATA(tb[IFA_ADDRESS]), sizeof(interfaceInfo.ip)) != EOK) {
            return;
        }
        DFINDER_LOGD(TAG, "Interface %s got new address.", interfaceInfo.name);
        AddLocalIface(interfaceInfo.name, &interfaceInfo.ip);
    } else {
        DFINDER_LOGD(TAG, "Interface %s delete address.", interfaceInfo.name);
        RemoveLocalIface(interfaceInfo.name);
    }
}

static void SmartGeniusCallback(void *arg)
{
    g_netlinkSocketEventNum[NETLINK_SOCKET_READ_EVENT]++;
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
        IncStatistics(STATS_SOCKET_ERROR);
        DFINDER_LOGE(TAG, "recvfrom error %d", errno);
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
                DFINDER_LOGD(TAG, "NLMSG_ACK");
            } else {
                DFINDER_LOGE(TAG, "NLMSG_ERROR");
            }
            break;
        }
        default:
            break;
    }
    return;
}

static void NetlinkWriteHandle(void *data)
{
    (void)data;
    g_netlinkSocketEventNum[NETLINK_SOCKET_WRITE_EVENT]++;
}

static void NetlinkErrorHandle(void *data UNUSED)
{
    g_netlinkSocketEventNum[NETLINK_SOCKET_ERROR_EVENT]++;
    DFINDER_LOGE(TAG, "Netlink Socket ErrorHandle");
    struct timespec errorTime;
    if (clock_gettime(CLOCK_MONOTONIC, &errorTime) != 0) {
        DFINDER_LOGE(TAG, "Get current time fail");
        NotifyDFinderMsgRecver(DFINDER_ON_INNER_ERROR);
        return;
    }
    long currErrorTimeS = errorTime.tv_sec;
    if (g_lastErrorTimeS > 0 && (currErrorTimeS - g_lastErrorTimeS < NSTACKX_ERROR_INTERVAL_S)) {
        // if exception triggered more than twice within 5s: close socket and restart it after 5min
        (void)DeRegisterEpollTask(&g_netlinkTask);
        close(g_netlinkTask.taskfd);
        g_netlinkTask.taskfd = -1;
        if (TimerSetTimeout(g_recoverTimer, NSTACKX_NETLINK_RECOVER_MS, NSTACKX_FALSE) != NSTACKX_EOK) {
            DFINDER_LOGE(TAG, "Timer setting timer fail");
            g_lastErrorTimeS = currErrorTimeS;
            NotifyDFinderMsgRecver(DFINDER_ON_INNER_ERROR);
            return;
        }
        g_lastErrorTimeS = -1;
        return;
    }
    g_lastErrorTimeS = currErrorTimeS;
}

static void RecoverNetLinkTask()
{
    if (!g_smartGeniusInit) {
        return;
    }
    g_netlinkTask.taskfd = CreateNetLinkSocketFd();
    if (g_netlinkTask.taskfd < 0) {
        DFINDER_LOGE(TAG, "unable to create netlink socket: %d", errno);
        NotifyDFinderMsgRecver(DFINDER_ON_INNER_ERROR);
        return;
    }
    if (RegisterEpollTask(&g_netlinkTask, EPOLLIN) != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "RegisterEpollTask fail");
        close(g_netlinkTask.taskfd);
        g_netlinkTask.taskfd = -1;
        NotifyDFinderMsgRecver(DFINDER_ON_INNER_ERROR);
        return;
    }
    DFINDER_LOGI(TAG, "Recover netlink task success");
}

int32_t SmartGeniusInit(EpollDesc epollfd)
{
    if (g_smartGeniusInit) {
        return NSTACKX_EOK;
    }
    int fd = CreateNetLinkSocketFd();
    if (fd < 0) {
        DFINDER_LOGE(TAG, "unable to create netlink socket");
        return NSTACKX_EFAILED;
    }
    g_netlinkTask.taskfd = fd;
    g_netlinkTask.epollfd = epollfd;
    g_netlinkTask.readHandle = SmartGeniusCallback;
    g_netlinkTask.writeHandle = NetlinkWriteHandle;
    g_netlinkTask.errorHandle = NetlinkErrorHandle;
    g_netlinkTask.count = 0;
    if (RegisterEpollTask(&g_netlinkTask, EPOLLIN) != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "RegisterEpollTask fail");
        goto L_CLOSE;
    }
    g_recoverTimer = TimerStart(epollfd, 0, NSTACKX_FALSE, RecoverNetLinkTask, NULL);
    if (g_recoverTimer == NULL) {
        DFINDER_LOGE(TAG, "Create recover timer fail");
        goto L_ERR;
    }
    g_lastErrorTimeS = -1;
    g_smartGeniusInit = NSTACKX_TRUE;
    return NSTACKX_EOK;
L_ERR:
    (void)DeRegisterEpollTask(&g_netlinkTask);
L_CLOSE:
    close(g_netlinkTask.taskfd);
    g_netlinkTask.taskfd = -1;
    return NSTACKX_EFAILED;
}

void SmartGeniusClean(void)
{
    if (!g_smartGeniusInit) {
        return;
    }

    TimerDelete(g_recoverTimer);
    g_recoverTimer = NULL;
    g_lastErrorTimeS = -1;
    if (g_netlinkTask.taskfd != -1) {
        (void)DeRegisterEpollTask(&g_netlinkTask);
        close(g_netlinkTask.taskfd);
        g_netlinkTask.taskfd = -1;
    }
    g_smartGeniusInit = NSTACKX_FALSE;
}

void ResetSmartGeniusTaskCount(uint8_t isBusy)
{
    if (isBusy) {
        DFINDER_LOGI(TAG, "in this busy interval: g_netlinkTask count %llu", g_netlinkTask.count);
    }
    g_netlinkTask.count = 0;

    if (isBusy) {
        DFINDER_LOGI(TAG, "SmartGeniusCallback has been called %lu times",
            g_netlinkSocketEventNum[NETLINK_SOCKET_READ_EVENT]);
        DFINDER_LOGI(TAG, "NetlinkWriteHandle has been called %lu times",
            g_netlinkSocketEventNum[NETLINK_SOCKET_WRITE_EVENT]);
        DFINDER_LOGI(TAG, "NetlinkErrorHandle has benn called %lu times",
            g_netlinkSocketEventNum[NETLINK_SOCKET_ERROR_EVENT]);
    }
    (void)memset_s(g_netlinkSocketEventNum, sizeof(g_netlinkSocketEventNum), 0, sizeof(g_netlinkSocketEventNum));
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
