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

#include "nstackx_qdisc.h"

#include <errno.h>
#include <pthread.h>

#include "nstackx_congestion.h"
#include "nstackx_error.h"
#include "nstackx_log.h"
#include "nstackx_nlmsg.h"
#include "nstackx_timer.h"


#define TAG "nStackXCongestion"
#define SEND_NETLINK_REQUEST_COUNT 2

static int32_t ProcessQdiscInfoInner(struct rtattr *tb[], int32_t parent)
{
    struct rtattr *tbs[TCA_STATS_MAX + 1] = {0};
    (void)parent;

    struct rtattr *rta = RTA_DATA(tb[TCA_STATS2]); // tb is trusted
    int32_t len = (int32_t)RTA_PAYLOAD(tb[TCA_STATS2]);

    RecvNetlinkParseAttr(rta, len, tbs, TCA_STATS_MAX);

    if (tbs[TCA_STATS_QUEUE] != NULL) {
        struct gnet_stats_queue q = {0};
        len = NlMin((int32_t)RTA_PAYLOAD(tbs[TCA_STATS_QUEUE]), (int32_t)sizeof(q));
        if (memcpy_s(&q, len, RTA_DATA(tbs[TCA_STATS_QUEUE]), len) == NSTACKX_EOK) {
            return q.qlen;
        } else {
            LOGE(TAG, "memcpy_s failed");
        }
    }

    return 0;
}

static int32_t CheckTcMsgRecv(struct tcmsg *tcMsgRecv, int32_t ifIndex, int32_t protocol)
{
    if (tcMsgRecv->tcm_ifindex != ifIndex || tcMsgRecv->tcm_parent != (uint32_t)protocol) {
        return NSTACKX_EINVAL;
    }
    return NSTACKX_EOK;
}

static void ProcessQdiscInfo(struct nlmsghdr *h, void *arg, void *value)
{
    QdiscArg *qdiscArg = (QdiscArg *)arg;
    QdiscValue *qdiscValue = (QdiscValue *)value;

    int32_t ifIndex = qdiscArg->ifIndex;
    int32_t protocol = qdiscArg->protocol;
    if (h->nlmsg_type != RTM_NEWQDISC && h->nlmsg_type != RTM_DELQDISC) {
        LOGE(TAG, "Not a qdisc\n");
        return;
    }
    struct tcmsg *tcMsgRecv = NLMSG_DATA(h); // h is trusted
    struct rtattr *tb[TCA_MAX + 1] = {0};
    int32_t len = (int32_t)(h->nlmsg_len);
    len -= NLMSG_LENGTH(sizeof(*tcMsgRecv));
    if (len < 0) {
        LOGE(TAG, "Wrong len %d", len);
        return;
    }

    if (CheckTcMsgRecv(tcMsgRecv, ifIndex, protocol) != NSTACKX_EOK) {
        return;
    }

    struct rtattr *rta = TCA_RTA(tcMsgRecv);
    RecvNetlinkParseAttr(rta, len, tb, TCA_MAX);

    if (tb[TCA_KIND] == NULL) {
        LOGE(TAG, "NULL KIND!");
        return;
    }

    qdiscValue->qlen = ProcessQdiscInfoInner(tb, tcMsgRecv->tcm_parent);

    return;
}

static int32_t GetQdiscUsedLength(const char *devName, int32_t protocol, int32_t *len)
{
    int32_t sockFd;
    int32_t ret;
    int32_t sendNetlinkRequestCount = SEND_NETLINK_REQUEST_COUNT;
    struct NlmsgCallback nlcb;
    QdiscArg qdiscArg;
    QdiscValue qdiscValue = {0};
    qdiscArg.ifIndex = (int32_t)if_nametoindex(devName);
    qdiscArg.protocol = protocol;

    nlcb.nlcb = ProcessQdiscInfo;
    nlcb.arg = &qdiscArg;
    nlcb.value = &qdiscValue;

    sockFd = NetlinkSocketInit();
    if (sockFd < 0) {
        return NSTACKX_EFAILED;
    }

    while (sendNetlinkRequestCount > 0) {
        ret = SendNetlinkRequest(sockFd, qdiscArg.ifIndex, RTM_GETQDISC);
        if (ret == NSTACKX_EOK) {
            ret = RecvNetlinkResponse(sockFd, &nlcb);
            if (ret == NSTACKX_EOK) {
                break;
            }
        }
        sendNetlinkRequestCount--;
    }
    if (ret == NSTACKX_EOK) {
        *len = qdiscValue.qlen;
    }
    if (close(sockFd) < 0)  {
        LOGE(TAG, "close failed.");
        return NSTACKX_EFAILED;
    }

    return ret;
}

static inline int32_t CheckQdiscAllLen(int32_t qdiscAllLen)
{
    if (qdiscAllLen < QDISC_MIN_LENGTH || qdiscAllLen > QDISC_MAX_LENGTH) {
        return NSTACKX_EFAILED;
    }
    return NSTACKX_EOK;
}

static int32_t GetQdiscAllLengthFromFile(const char *devName)
{
    char qdiscFileName[QDISC_FILE_NAME_NAX_LENGTH] = {0};
    int32_t ret = sprintf_s(
        qdiscFileName, QDISC_FILE_NAME_NAX_LENGTH, "/sys/devices/virtual/net/%s/tx_queue_len", devName);
    if (ret <= 0) {
        LOGE(TAG, "sprintf_s failed, ret %d errno %d", ret, errno);
        return ret;
    }

    char *fileName = qdiscFileName;
    char absolutePath[PATH_MAX + 1] = {0}; // +1 is avoiding array out of bound
    if (realpath(qdiscFileName, absolutePath) == NULL) {
        LOGE(TAG, "realpath failed");
    } else {
        fileName = absolutePath;
    }

    if (strstr(fileName, "..") != NULL) {
        LOGE(TAG, "file name is not canonical form");
        return NSTACKX_EFAILED;
    }

    FILE *fd = fopen(fileName, "r");
    if (fd == NULL) {
        LOGE(TAG, "file open failed, errno %d", errno);
        return NSTACKX_EFAILED;
    }

    int32_t qdiscAllLen;
    ret = fscanf_s(fd, "%d", &qdiscAllLen);
    if (ret != 1 || CheckQdiscAllLen(qdiscAllLen) != NSTACKX_EOK) {
        LOGE(TAG, "fscanf_s error ret %d qdiscAllLen %d.", ret, qdiscAllLen);
        if (fclose(fd) < 0) {
            LOGE(TAG, "close failed.");
        }
        return NSTACKX_EFAILED;
    }
    LOGI(TAG, "qdiscAllLen is %d.", qdiscAllLen);
    if (fclose(fd) < 0) {
        LOGE(TAG, "close failed.");
        return NSTACKX_EFAILED;
    }

    return qdiscAllLen;
}

static int32_t GetQdiscAllLength(const char *devName)
{
    static int32_t searchFlag = 0;
    static int32_t qdiscAllLength = QDISC_DEFAULT_LENGTH;

    if (searchFlag == 0) {
        int32_t tmpQdiscAllLength = GetQdiscAllLengthFromFile(devName);
        if (tmpQdiscAllLength >= QDISC_MIN_LENGTH && tmpQdiscAllLength <= QDISC_MAX_LENGTH) {
            qdiscAllLength = tmpQdiscAllLength;
        }
        searchFlag = 1;
    }
    return qdiscAllLength;
}

static uint32_t GetQdiscLeftLengthPolicy(int32_t qdiscAllLength, int32_t qdiscUsedLen)
{
    uint32_t len;

    if (qdiscUsedLen >= qdiscAllLength - FIRST_QDISC_LEN) {
        len = 1;
    } else if (qdiscUsedLen >= qdiscAllLength - SECOND_QDISC_LEN) {
        len = 2; /* only send 2 packets */
    } else {
        len = qdiscAllLength - SECOND_QDISC_LEN - qdiscUsedLen + 1;
    }
    return len;
}

int32_t GetQdiscLeftLength(const char *devName, int32_t protocol, uint32_t *len)
{
    int32_t qdiscAllLength = GetQdiscAllLength(devName);
    int32_t qdiscUsedLen;
    int32_t ret = GetQdiscUsedLength(devName, protocol, &qdiscUsedLen);
    if (ret == NSTACKX_EOK) {
        *len = GetQdiscLeftLengthPolicy(qdiscAllLength, qdiscUsedLen);
    }
    return ret;
}
