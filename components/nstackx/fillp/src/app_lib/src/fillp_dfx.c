/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "fillp_dfx.h"
#include <limits.h>
#include "sockets.h"
#include "socket_common.h"
#include "log.h"
#include "res.h"
#include "spunge.h"
#include "securec.h"
#include "log.h"
#include "spunge_message.h"
#include "nstackx_getopt.h"
#include "nstackx_util.h"
#include "nstackx_error.h"

#define FILLP_DFX_PKT_EVT_DROP_THRESHOLD 1000
static struct Hlist g_fillpDfxPktPraseFailList = {
    {
        .pprev = (struct HlistNode **)&g_fillpDfxPktPraseFailList,
    },
    .size = 0,
};
static FillpDfxEventCb g_fillpDfxEvtCb = FILLP_NULL_PTR;
static void *g_fillpDfxSoftObj = FILLP_NULL_PTR;

typedef struct {
    struct HlistNode node;
    FILLP_INT sockIdx;
    FILLP_UINT32 dropCnt;
    FILLP_UINT32 lastReportCnt;
} FillpDfxPktParseFailNode;

typedef union {
    struct {
        FILLP_UINT32 sockIdx;
        FillpDfxLinkEvtType linkEvtType;
    } linkEvt;
    struct {
        FILLP_UINT32 sockIdx;
        FillpDfxPktEvtType pktEvtType;
        /* FILLP_DFX_PKT_PARSE_FAIL: dropCnt means pkt count */
        /* FILLP_DFX_PKT_SEMI_RELIABLE_DROP: dropCnt means frame count */
        FILLP_UINT32 dropCnt;
    } pktEvt;
    struct {
        FILLP_UINT32 sockIdx;
        FILLP_UINT32 rtt;
        FILLP_UINT32 totalReceivedPkt;
        FILLP_UINT32 totalReceivedBytes;
        FILLP_UINT32 totalSendPkt;
        FILLP_UINT32 totalSendBytes;
        FILLP_UINT32 jitter; /* ms */
    } sockQos;
} FillpDfxEvtArgs;

#define FILLP_DFX_LINK_EVT_PARA_NUM 2
#define FILLP_DFX_PKT_EVT_PARA_NUM 3
#define FILLP_DFX_SOCK_QOS_EVT_PARA_NUM 7
#define FILLP_EVT_MAX_PARA_NUM FILLP_DFX_SOCK_QOS_EVT_PARA_NUM

typedef enum {
    FILLP_DFX_EVT_LINK_EXCEPTION,
    FILLP_DFX_EVT_PKT_EXCEPTION,
    FILLP_DFX_EVT_SOCK_QOS_STATUS,
    FILLP_DFX_EVT_DFX_MAX,
} FillpDfxEvt;

static const FillpDfxEvent g_fillpDfxEvtMsg[FILLP_DFX_EVT_DFX_MAX] = {
    [FILLP_DFX_EVT_LINK_EXCEPTION] = {
        .eventName = "FILLP_LINK_EVT",
        .type = FILLP_DFX_EVENT_TYPE_FAULT,
        .level = FILLP_DFX_EVENT_LEVEL_MINOR,
        .paramNum = FILLP_DFX_LINK_EVT_PARA_NUM,
    },
    [FILLP_DFX_EVT_PKT_EXCEPTION] = {
        .eventName = "FILLP_PKT_EVT",
        .type = FILLP_DFX_EVENT_TYPE_STATISTIC,
        .level = FILLP_DFX_EVENT_LEVEL_MINOR,
        .paramNum = FILLP_DFX_PKT_EVT_PARA_NUM,
    },
    [FILLP_DFX_EVT_SOCK_QOS_STATUS] = {
        .eventName = "FILLP_SOCK_QOS_EVT",
        .type = FILLP_DFX_EVENT_TYPE_STATISTIC,
        .level = FILLP_DFX_EVENT_LEVEL_MINOR,
        .paramNum = FILLP_DFX_SOCK_QOS_EVT_PARA_NUM,
    },
};

static const FillpDfxEventParam g_fillpDfxEvtParam[FILLP_DFX_EVT_DFX_MAX][FILLP_EVT_MAX_PARA_NUM] = {
    [FILLP_DFX_EVT_LINK_EXCEPTION] = {
        {
            .type = FILLP_DFX_PARAM_TYPE_UINT32,
            .paramName = "SOCK_IDX",
        },
        {
            .type = FILLP_DFX_PARAM_TYPE_UINT8,
            .paramName = "LINK_EVT_TYPE",
        },
    },
    [FILLP_DFX_EVT_PKT_EXCEPTION] = {
        {
            .type = FILLP_DFX_PARAM_TYPE_UINT32,
            .paramName = "SOCK_IDX",
        },
        {
            .type = FILLP_DFX_PARAM_TYPE_UINT8,
            .paramName = "PKT_EVT_TYPE",
        },
        {
            .type = FILLP_DFX_PARAM_TYPE_UINT32,
            .paramName = "DROP_CNT",
        },
    },
    [FILLP_DFX_EVT_SOCK_QOS_STATUS] = {
        {
            .type = FILLP_DFX_PARAM_TYPE_UINT32,
            .paramName = "SOCK_IDX",
        },
        {
            .type = FILLP_DFX_PARAM_TYPE_UINT32,
            .paramName = "RTT",
        },
        {
            .type = FILLP_DFX_PARAM_TYPE_UINT32,
            .paramName = "TOTAL_RECV_PKT",
        },
        {
            .type = FILLP_DFX_PARAM_TYPE_UINT32,
            .paramName = "TOTAL_RECV_BYTES",
        },
        {
            .type = FILLP_DFX_PARAM_TYPE_UINT32,
            .paramName = "TOTAL_SEND_PKT",
        },
        {
            .type = FILLP_DFX_PARAM_TYPE_UINT32,
            .paramName = "TOTAL_SEND_BYTES",
        },
        {
            .type = FILLP_DFX_PARAM_TYPE_UINT32,
            .paramName = "JITTER",
        },
    },
};

static void DfxEvtGetParamAddr(const FillpDfxEvtArgs *args, FillpDfxEvt evt, const void *paramVal[])
{
    const void *paramValTmp[FILLP_DFX_EVT_DFX_MAX][FILLP_EVT_MAX_PARA_NUM] = {
        [FILLP_DFX_EVT_LINK_EXCEPTION] = {
            &args->linkEvt.sockIdx,
            &args->linkEvt.linkEvtType,
        },
        [FILLP_DFX_EVT_PKT_EXCEPTION] = {
            &args->pktEvt.sockIdx,
            &args->pktEvt.pktEvtType,
            &args->pktEvt.dropCnt,
        },
        [FILLP_DFX_EVT_SOCK_QOS_STATUS] = {
            &args->sockQos.sockIdx,
            &args->sockQos.rtt,
            &args->sockQos.totalReceivedPkt,
            &args->sockQos.totalReceivedBytes,
            &args->sockQos.totalSendPkt,
            &args->sockQos.totalSendBytes,
            &args->sockQos.jitter,
        },
    };
    (void)memcpy_s((void *)paramVal, sizeof(void *) * FILLP_EVT_MAX_PARA_NUM,
        (void *)paramValTmp[evt], sizeof(void *) * FILLP_EVT_MAX_PARA_NUM);
}

void FillpDfxDoEvtCbSet(void *softObj, FillpDfxEventCb evtCb)
{
    g_fillpDfxEvtCb = evtCb;
    g_fillpDfxSoftObj = softObj;
}

FILLP_INT FillpDfxEvtCbSet(void *softObj, FillpDfxEventCb evtCb)
{
    if ((g_spunge == FILLP_NULL_PTR) || (!g_spunge->hasInited)) {
        FILLP_LOGERR("Fillp not init!");
        return -1;
    }
    FILLP_INT err;
    struct SpungeHiEventCbMsg msg;

    msg.softObj = softObj;
    msg.cb = evtCb;

    err = SpungePostMsg(SPUNGE_GET_CUR_INSTANCE(), &msg, MSG_TYPE_SET_HIEVENT_CB, FILLP_TRUE);
    if (err != ERR_OK) {
        FILLP_LOGERR("Failed to post msg to fillp to set Hievent callback");
        return -1;
    }
    return 0;
}

static void DfxEvtParamValCpy(void *dstVal, const void *srcVal, FillpDfxEventParamType type)
{
    switch (type) {
        case FILLP_DFX_PARAM_TYPE_BOOL:
        case FILLP_DFX_PARAM_TYPE_UINT8:
            *(FILLP_UINT8 *)dstVal = *(FILLP_UINT8 *)srcVal;
            break;
        case FILLP_DFX_PARAM_TYPE_UINT16:
            *(FILLP_UINT16 *)dstVal = *(FILLP_UINT16 *)srcVal;
            break;
        case FILLP_DFX_PARAM_TYPE_INT32:
        case FILLP_DFX_PARAM_TYPE_UINT32:
        case FILLP_DFX_PARAM_TYPE_FLOAT:
            *(FILLP_UINT32 *)dstVal = *(FILLP_UINT32 *)srcVal;
            break;
        case FILLP_DFX_PARAM_TYPE_UINT64:
        case FILLP_DFX_PARAM_TYPE_DOUBLE:
            *(FILLP_ULLONG *)dstVal = *(FILLP_ULLONG *)srcVal;
            break;
        case FILLP_DFX_PARAM_TYPE_STRING:
            if (strcpy_s(dstVal, FILLP_DFX_EVENT_NAME_LEN, srcVal) != EOK) {
                FILLP_LOGERR("strcpy_s failed");
            }
            break;
        default:
            FILLP_LOGERR("unknow param type!");
            break;
    }
}

static FillpDfxEventParam *FillpCreateDfxEvtParam(const FillpDfxEvtArgs *args, FillpDfxEvt evt, FILLP_UINT32 paramNum)
{
    FILLP_UINT8 i;
    const void *paramVal[FILLP_EVT_MAX_PARA_NUM];
    (void)memset_s(paramVal, sizeof(paramVal), 0, sizeof(paramVal));
    DfxEvtGetParamAddr(args, evt, &paramVal[0]);
    FillpDfxEventParam *param = (FillpDfxEventParam *)calloc(paramNum, sizeof(FillpDfxEventParam));
    if (param == FILLP_NULL_PTR) {
        FILLP_LOGERR("calloc param failed!");
        return FILLP_NULL_PTR;
    }
    (void)memcpy_s(param, paramNum * sizeof(FillpDfxEventParam),
        &g_fillpDfxEvtParam[evt], paramNum * sizeof(FillpDfxEventParam));
    for (i = 0; i < paramNum; i++) {
        DfxEvtParamValCpy(&param[i].val, paramVal[i], param[i].type);
    }
    return param;
}

static void FillpDfxEvtNotify(const FillpDfxEvtArgs *args, FillpDfxEvt evt)
{
    if (g_fillpDfxEvtCb == FILLP_NULL_PTR) {
        return;
    }
    FillpDfxEvent msg;
    (void)memcpy_s(&msg, sizeof(FillpDfxEvent), &g_fillpDfxEvtMsg[evt], sizeof(FillpDfxEvent));

    msg.paramArray = FillpCreateDfxEvtParam(args, evt, msg.paramNum);
    if (msg.paramArray == FILLP_NULL_PTR) {
        return;
    }
    g_fillpDfxEvtCb(g_fillpDfxSoftObj, &msg);
    free(msg.paramArray);
}

static void FillpDfxSockQosNotify(const struct FtSocket *sock)
{
    FillpDfxEvtArgs args;
    (void)memset_s(&args, sizeof(args), 0, sizeof(args));
    args.sockQos.sockIdx = (FILLP_UINT32)sock->index;

    const struct FillpPcb *pcb = &sock->netconn->pcb->fpcb;
    const struct FillpStatisticsTraffic *traffic = &(pcb->statistics.traffic);
    const struct FillAppFcStastics *appFcStastics = &(pcb->statistics.appFcStastics);

    args.sockQos.rtt = appFcStastics->periodRtt;
    args.sockQos.totalReceivedPkt = traffic->totalRecved;
    args.sockQos.totalReceivedBytes = traffic->totalRecvedBytes;

    args.sockQos.totalSendPkt = traffic->totalSend;
    args.sockQos.totalSendBytes = traffic->totalSendBytes;
    args.sockQos.jitter = (FILLP_UINT32)FILLP_UTILS_US2MS(sock->jitter);

    FillpDfxEvtNotify(&args, FILLP_DFX_EVT_SOCK_QOS_STATUS);
}

static FillpDfxPktParseFailNode *DfxGetPktPraseFailNode(FILLP_INT sockIdx)
{
    struct HlistNode *pos = FILLP_NULL_PTR;
    struct HlistNode *next = FILLP_NULL_PTR;
    HLIST_FOREACH_SAFE(pos, next, &g_fillpDfxPktPraseFailList) {
        FillpDfxPktParseFailNode *node = (FillpDfxPktParseFailNode *)pos;
        if (node->sockIdx == sockIdx) {
            return node;
        }
    }
    return FILLP_NULL_PTR;
}

void FillpDfxSockLinkAndQosNotify(const struct FtSocket *sock, FillpDfxLinkEvtType evtType)
{
    FillpDfxEvtArgs args;
    (void)memset_s(&args, sizeof(args), 0, sizeof(args));
    args.linkEvt.sockIdx = (FILLP_UINT32)sock->index;
    args.linkEvt.linkEvtType = evtType;
    FillpDfxEvtNotify(&args, FILLP_DFX_EVT_LINK_EXCEPTION);

    if (sock->netconn->state == CONN_STATE_CONNECTED) {
        FillpDfxSockQosNotify(sock);
    }

    FillpDfxPktParseFailNode *node = DfxGetPktPraseFailNode(sock->index);
    if (node == FILLP_NULL_PTR) {
        return;
    }
    if (node->dropCnt == node->lastReportCnt) {
        HlistDelNode(&node->node);
        free(node);
        return;
    }
    (void)memset_s(&args, sizeof(args), 0, sizeof(args));
    args.pktEvt.sockIdx = (FILLP_UINT32)sock->index;
    args.pktEvt.pktEvtType = FILLP_DFX_PKT_PARSE_FAIL;
    args.pktEvt.dropCnt = node->dropCnt;
    HlistDelNode(&node->node);
    free(node);
    FillpDfxEvtNotify(&args, FILLP_DFX_EVT_PKT_EXCEPTION);
}

void FillpDfxPktNotify(FILLP_INT sockIdx, FillpDfxPktEvtType evtType, FILLP_UINT32 dropCnt)
{
    FillpDfxPktParseFailNode *node = FILLP_NULL_PTR;
    if (evtType == FILLP_DFX_PKT_PARSE_FAIL) {
        node = DfxGetPktPraseFailNode(sockIdx);
        if (node == FILLP_NULL_PTR) {
            node = (FillpDfxPktParseFailNode *)calloc(1U, sizeof(FillpDfxPktParseFailNode));
            if (node == FILLP_NULL_PTR) {
                FILLP_LOGERR("calloc node failed!");
                return;
            }
            HlistAddTail(&g_fillpDfxPktPraseFailList, &node->node);
        }
        node->dropCnt += dropCnt;
        if (node->dropCnt - node->lastReportCnt < FILLP_DFX_PKT_EVT_DROP_THRESHOLD) {
            return;
        }
    }
    FillpDfxEvtArgs args;
    (void)memset_s(&args, sizeof(args), 0, sizeof(args));
    args.pktEvt.sockIdx = (FILLP_UINT32)sockIdx;
    args.pktEvt.pktEvtType = evtType;
    if (evtType == FILLP_DFX_PKT_PARSE_FAIL) {
        args.pktEvt.dropCnt = node->dropCnt;
        node->lastReportCnt = node->dropCnt;
    } else {
        args.pktEvt.dropCnt = dropCnt;
    }
    FillpDfxEvtNotify(&args, FILLP_DFX_EVT_PKT_EXCEPTION);
}

#ifdef FILLP_ENABLE_DFX_HIDUMPER
#define CRLF "\r\n"
#define FILLP_DFX_DUMP_BUF_LEN (2048U)
#define FILLP_DFX_DUMP_ONE_SOCK_BUF (102U)
#define FILLP_DFX_DUMP_MAX_ARGC (20U)
#define FILLP_DFX_DUMP_STRTOL_BASE (10)
#define FILLP_DFX_DUMP_MAX_OPT_ARG_LEN (10U)

#define FILLP_DUMP_MSG_ADD_CHECK(data, len, fmt, ...) do { \
    FILLP_INT ret = sprintf_s(data + len, FILLP_DFX_DUMP_BUF_LEN - len, fmt, ##__VA_ARGS__); \
    if (ret < 0) { \
        FILLP_LOGERR("dumper buffer over %u bytes", FILLP_DFX_DUMP_BUF_LEN); \
        return FILLP_FAILURE; \
    } \
    len += (FILLP_UINT32)ret; \
} while (0)

static FILLP_INT DoShowHelp(FILLP_CHAR *data, FILLP_UINT32 *len)
{
    FILLP_DUMP_MSG_ADD_CHECK(data, *len, CRLF"Usage: dstream <opt>"CRLF);
    FILLP_DUMP_MSG_ADD_CHECK(data, *len, "       -h         show this help"CRLF);
    FILLP_DUMP_MSG_ADD_CHECK(data, *len, "       -V         show version"CRLF);
    FILLP_DUMP_MSG_ADD_CHECK(data, *len, "       -l         show debug log level"CRLF);
    FILLP_DUMP_MSG_ADD_CHECK(data, *len, "       -n         show socket list, and info of socket"CRLF);
    FILLP_DUMP_MSG_ADD_CHECK(data, *len, "       -s <fd>    show socket <fd> common config and flow config"CRLF);
    FILLP_DUMP_MSG_ADD_CHECK(data, *len, "       -q <fd>    show socket <fd> qos"CRLF);
    FILLP_DUMP_MSG_ADD_CHECK(data, *len, "       -f <fd>    show socket <fd> frame info"CRLF);
    FILLP_DUMP_MSG_ADD_CHECK(data, *len, "       -m <0/1>   disable/enable management message"CRLF);
    return FILLP_SUCCESS;
}

static FILLP_INT FillpDumpShowHelp(void *softObj, FillpDfxDumpFunc dump)
{
    FILLP_CHAR data[FILLP_DFX_DUMP_BUF_LEN];
    FILLP_UINT32 len = 0;
    if (DoShowHelp(data, &len) != FILLP_SUCCESS) {
        return FILLP_FAILURE;
    }
    dump(softObj, data, len);
    return FILLP_SUCCESS;
}

static inline FILLP_INT DoShowVersion(FILLP_CHAR *data, FILLP_UINT32 *len)
{
    FILLP_DUMP_MSG_ADD_CHECK(data, *len, CRLF FILLP_VERSION CRLF);
    return FILLP_SUCCESS;
}

static FILLP_INT FillpDumpShowVer(void *softObj, FillpDfxDumpFunc dump)
{
    FILLP_CHAR data[FILLP_DFX_DUMP_BUF_LEN];
    FILLP_UINT32 len = 0;
    if (DoShowVersion(data, &len) != FILLP_SUCCESS) {
        return FILLP_FAILURE;
    }
    dump(softObj, data, len);
    return FILLP_SUCCESS;
}

static inline FILLP_INT DoShowLogLevel(FILLP_CHAR *data, FILLP_UINT32 *len)
{
    FILLP_DUMP_MSG_ADD_CHECK(data, *len, CRLF"Current log level: %hhu"CRLF, g_fillpLmGlobal.debugLevel);
    return FILLP_SUCCESS;
}

static FILLP_INT FillpDumpShowLogLevel(void *softObj, FillpDfxDumpFunc dump)
{
    FILLP_CHAR data[FILLP_DFX_DUMP_BUF_LEN];
    FILLP_UINT32 len = 0;
    if (DoShowLogLevel(data, &len) != FILLP_SUCCESS) {
        return FILLP_FAILURE;
    }
    dump(softObj, data, len);
    return FILLP_SUCCESS;
}

static FILLP_INT32 DoShowSockConfigRes(FILLP_INT sockIndex, FILLP_CONST struct GlobalAppResource *resource,
    FILLP_CHAR *data, FILLP_UINT32 *len)
{
    FILLP_CONST struct GlobalAppCommon *common = &resource->common;
    FILLP_CONST struct GlobalAppFlowControl *fc = &resource->flowControl;
    FILLP_DUMP_MSG_ADD_CHECK(data, *len, CRLF"Following are config resource data for socket %d:"CRLF, sockIndex);
    FILLP_DUMP_MSG_ADD_CHECK(data, *len, "Max udp tx burst number: %u"CRLF, resource->udp.txBurst);
    FILLP_DUMP_MSG_ADD_CHECK(data, *len, "Keep alive timeout: %u"CRLF, common->keepAliveTime);
    FILLP_DUMP_MSG_ADD_CHECK(data, *len, "Max server allow send cache: %u"CRLF, common->maxServerAllowSendCache);
    FILLP_DUMP_MSG_ADD_CHECK(data, *len, "Max server allow receive cache: %u"CRLF, common->maxServerAllowRecvCache);
    FILLP_DUMP_MSG_ADD_CHECK(data, *len, "Max send cache: %u"CRLF, common->sendCache);
    FILLP_DUMP_MSG_ADD_CHECK(data, *len, "Max receive cache: %u"CRLF, common->recvCache);
    FILLP_DUMP_MSG_ADD_CHECK(data, *len, "Max send buffer size: %u"CRLF, common->udpSendBufSize);
    FILLP_DUMP_MSG_ADD_CHECK(data, *len, "Enable nack delay flag: %hhu"CRLF, common->enableNackDelay);
    FILLP_DUMP_MSG_ADD_CHECK(data, *len, "Nack delay timeout: %lld"CRLF, common->nackDelayTimeout);
    FILLP_DUMP_MSG_ADD_CHECK(data, *len, "Enlarge pack interval falg: %hhu"CRLF, common->enlargePackIntervalFlag);
    FILLP_DUMP_MSG_ADD_CHECK(data, *len, "Max receive buffer size: %u"CRLF, common->recvBufSize);
    FILLP_DUMP_MSG_ADD_CHECK(data, *len, "Flow control: opposite set rate: %u"CRLF, fc->oppositeSetRate);
    FILLP_DUMP_MSG_ADD_CHECK(data, *len, "              use const stack send rate: %hhu"CRLF, fc->constRateEnbale);
    FILLP_DUMP_MSG_ADD_CHECK(data, *len, "              max send rate: %u Kbps"CRLF, fc->maxRate);
    FILLP_DUMP_MSG_ADD_CHECK(data, *len, "              max recv rate: %u Kbps"CRLF, fc->maxRecvRate);
    FILLP_DUMP_MSG_ADD_CHECK(data, *len, "              packet size: %hu"CRLF, fc->pktSize);
    FILLP_DUMP_MSG_ADD_CHECK(data, *len, "              slow start: %hhu"CRLF, fc->slowStart);
    FILLP_DUMP_MSG_ADD_CHECK(data, *len, "Timer config: connection timeout: %u(s)"CRLF, common->connectTimeout);
    FILLP_DUMP_MSG_ADD_CHECK(data, *len, "              retry timeout: %hu(s)"CRLF, common->connRetryTimeout);
    FILLP_DUMP_MSG_ADD_CHECK(data, *len, "              disconnect retry timeout: %u(s)"CRLF,
        common->disconnectRetryTimeout);
    FILLP_DUMP_MSG_ADD_CHECK(data, *len, "------- End of socket config resource data -------"CRLF);
    return FILLP_SUCCESS;
}

static inline FILLP_INT DumpInvalidSock(FILLP_INT sockIndex, FILLP_CHAR *data, FILLP_UINT32 *len)
{
    FILLP_DUMP_MSG_ADD_CHECK(data, *len, "Invalid socket index %d"CRLF, sockIndex);
    return FILLP_SUCCESS;
}

static FILLP_INT FillpDumpShowSockResource(FILLP_INT sockIndex, void *softObj, FillpDfxDumpFunc dump)
{
    FILLP_CHAR data[FILLP_DFX_DUMP_BUF_LEN];
    FILLP_UINT32 len = 0;
    struct FtSocket *sock = SockApiGetAndCheck(sockIndex);
    if (sock == FILLP_NULL_PTR) {
        if (DumpInvalidSock(sockIndex, data, &len) == FILLP_SUCCESS) {
            dump(softObj, data, len);
        }
        return FILLP_FAILURE;
    }

    FILLP_INT32 isOk = DoShowSockConfigRes(sockIndex, &sock->resConf, data, &len);
    (void)SYS_ARCH_RWSEM_RDPOST(&sock->sockConnSem);
    if (isOk != FILLP_SUCCESS) {
        return FILLP_FAILURE;
    }
    dump(softObj, data, len);
    return FILLP_SUCCESS;
}

static inline FILLP_INT32 DoShowSockListTitle(FILLP_CHAR *data, FILLP_UINT32 *len)
{
    FILLP_DUMP_MSG_ADD_CHECK(data, *len, CRLF"%5s\t %6s\t %6s\t %6s\t %6s\t %30s\t %5s\t %30s\t %5s\t %12s"CRLF,
        "Sock", "Unsend", "Unack", "Redun", "Unrecv", "LocalIP", "Port", "PeerIP", "Port", "State");
    return FILLP_SUCCESS;
}

static const char *g_sockStateStr[CONN_STATE_CLOSED + 1] = {
    "IDLE",
    "LISTENING",
    "CONNECTING",
    "CONNECTED",
    "CLOSING",
    "CLOSED",
};

static FILLP_INT32 DoShowSockList(FILLP_CONST struct FtSocket *sock, FILLP_CHAR *data, FILLP_UINT32 *len)
{
    struct sockaddr_in *local = (struct sockaddr_in *)&sock->netconn->pcb->localAddr;
    struct sockaddr_in *peer = (struct sockaddr_in *)&sock->netconn->pcb->remoteAddr;
    const struct FillpSendPcb *sendPcb = &sock->netconn->pcb->fpcb.send;
    FILLP_CHAR localAddr[INET6_ADDRSTRLEN];
    FILLP_CHAR peerAddr[INET6_ADDRSTRLEN];

    FILLP_INT ipLen = IpAddrAnonymousFormat(localAddr, sizeof(localAddr),
        (const struct sockaddr *)local, sizeof(struct sockaddr_in6));
    if (ipLen == NSTACKX_EFAILED) {
        (void)strcpy_s(localAddr, INET6_ADDRSTRLEN, "NONE");
    }

    if (sock->netconn->state > CONN_STATE_LISTENING) {
        ipLen = IpAddrAnonymousFormat(peerAddr, sizeof(peerAddr),
            (const struct sockaddr *)peer, sizeof(struct sockaddr_in6));
        if (ipLen == NSTACKX_EFAILED) {
            FILLP_LOGERR("Anonymous remoteAddr failed");
            return FILLP_FAILURE;
        }
    } else {
        (void)strcpy_s(peerAddr, INET6_ADDRSTRLEN, "NONE");
    }

    FILLP_DUMP_MSG_ADD_CHECK(data, *len, "%5d\t %6u\t %6u\t %6u\t %6u\t %30s\t %5hu\t %30s\t %5hu\t %12s"CRLF,
        sock->index, sendPcb->unSendList.size, sendPcb->unackList.count, sendPcb->redunList.nodeNum,
        sendPcb->unrecvList.nodeNum, localAddr, FILLP_NTOHS(local->sin_port), peerAddr, FILLP_NTOHS(peer->sin_port),
        g_sockStateStr[sock->netconn->state]);
    return FILLP_SUCCESS;
}

static FILLP_INT FillpDumpShowSockList(void *softObj, FillpDfxDumpFunc dump)
{
    if ((g_spunge == FILLP_NULL_PTR) || (!g_spunge->hasInited) || (g_spunge->sockTable == FILLP_NULL_PTR)) {
        FILLP_LOGERR("Fillp not init!");
        return FILLP_FAILURE;
    }
    struct FtSocket *sock = FILLP_NULL_PTR;
    FILLP_UINT32 len = 0;

    FILLP_CHAR *data = (FILLP_CHAR *)calloc(1U, g_spunge->resConf.maxSockNum * FILLP_DFX_DUMP_ONE_SOCK_BUF);
    if (data == FILLP_NULL_PTR) {
        const FILLP_CHAR *errMsg = "socket list dump buffer calloc failed!";
        dump(softObj, errMsg, strlen(errMsg) + 1);
        return FILLP_FAILURE;
    }
    if (DoShowSockListTitle(data, &len) != FILLP_SUCCESS) {
        free(data);
        return FILLP_FAILURE;
    }

    FILLP_UINT16 i;
    for (i = 0; i < SYS_ARCH_ATOMIC_READ(&g_spunge->sockTable->used); i++) {
        sock = SockApiGetAndCheck(i);
        if (sock == FILLP_NULL_PTR) {
            continue;
        }
        if (sock->netconn == FILLP_NULL_PTR || sock->netconn->pcb == FILLP_NULL_PTR) {
            (void)SYS_ARCH_RWSEM_RDPOST(&sock->sockConnSem);
            continue;
        }
        FILLP_INT isOk = DoShowSockList(sock, data, &len);
        (void)SYS_ARCH_RWSEM_RDPOST(&sock->sockConnSem);
        if (isOk != FILLP_SUCCESS) {
            free(data);
            return FILLP_FAILURE;
        }
    }
    dump(softObj, data, len);
    free(data);
    return FILLP_SUCCESS;
}

static FILLP_INT DoShowSockQos(FILLP_CONST struct FtSocket *sock, FILLP_CHAR *data, FILLP_UINT32 *len)
{
    const struct FillpPcb *pcb = &sock->netconn->pcb->fpcb;
    const struct FillpStatisticsTraffic *traffic = &(pcb->statistics.traffic);
    const struct FillAppFcStastics *appFcStastics = &(pcb->statistics.appFcStastics);
    FILLP_UINT32 trafficLiveTime = (FILLP_UINT32)FILLP_UTILS_US2S(SYS_ARCH_GET_CUR_TIME_LONGLONG() -
        pcb->connTimestamp);
    trafficLiveTime = (trafficLiveTime == 0) ? 1 : trafficLiveTime;

    FILLP_DUMP_MSG_ADD_CHECK(data, *len, CRLF"%8s\t %12s\t %13s\t %19s\t %18s\t %10s\t %10s\t %19s\t %19s\t %10s"CRLF,
        "Rtt(ms)", "ReceivedPkt", "ReceivedBytes", "RecvPktLoss(0.01%)", "RecvBytesRate(Bps)",
        "SendPkt", "SendBytes", "SendPktLoss(0.01%)", "SendBytesRate(Bps)", "Jetter(us)");
    FILLP_DUMP_MSG_ADD_CHECK(data, *len, "%8u\t %12u\t %13u\t %19u\t %18u\t %10u\t %10u\t %19u\t %19u\t %10lld\t"CRLF,
        appFcStastics->periodRtt,
        traffic->totalRecved,
        traffic->totalRecvedBytes,
        (traffic->totalRecved == 0) ? 0 :
        (traffic->totalRecvLost * FILLP_RECV_PKT_LOSS_H_PERCISION * FILLP_RECV_PKT_LOSS_MAX / traffic->totalRecved),
        traffic->totalRecvedBytes / trafficLiveTime,

        traffic->totalSend,
        traffic->totalSendBytes,
        (traffic->totalSend == 0) ? 0 :
        (traffic->totalRetryed * FILLP_RECV_PKT_LOSS_H_PERCISION * FILLP_RECV_PKT_LOSS_MAX / traffic->totalSend),
        traffic->totalSendBytes / trafficLiveTime,
        sock->jitter);
    return FILLP_SUCCESS;
}

static struct FtSocket *FillpDfxGetSock(FILLP_INT sockIndex, void *softObj, FillpDfxDumpFunc dump,
    FILLP_CHAR *data, FILLP_UINT32 *len)
{
    struct FtSocket *sock = SockApiGetAndCheck(sockIndex);
    if (sock == FILLP_NULL_PTR || sock->netconn == FILLP_NULL_PTR || sock->netconn->pcb == FILLP_NULL_PTR) {
        if (sock != FILLP_NULL_PTR) {
            (void)SYS_ARCH_RWSEM_RDPOST(&sock->sockConnSem);
        }
        if (DumpInvalidSock(sockIndex, data, len) == FILLP_SUCCESS) {
            dump(softObj, data, *len);
        }
        return FILLP_NULL_PTR;
    }
    return sock;
}

typedef FILLP_INT (*FillpDumpSockDataShowCb)(FILLP_CONST struct FtSocket *sock, FILLP_CHAR *data, FILLP_UINT32 *len);

static FILLP_INT FillpDumpShowSockData(FILLP_INT sockIndex, void *softObj, FillpDfxDumpFunc dump,
    FillpDumpSockDataShowCb showCb)
{
    FILLP_CHAR data[FILLP_DFX_DUMP_BUF_LEN];
    FILLP_UINT32 len = 0;
    struct FtSocket *sock = FillpDfxGetSock(sockIndex, softObj, dump, data, &len);
    if (sock == FILLP_NULL_PTR) {
        return FILLP_FAILURE;
    }

    FILLP_INT isOk = showCb(sock, data, &len);
    (void)SYS_ARCH_RWSEM_RDPOST(&sock->sockConnSem);
    if (isOk != FILLP_SUCCESS) {
        return FILLP_FAILURE;
    }
    dump(softObj, data, len);
    return FILLP_SUCCESS;
}

static FILLP_INT FillpDumpShowSockQos(FILLP_INT sockIndex, void *softObj, FillpDfxDumpFunc dump)
{
    return FillpDumpShowSockData(sockIndex, softObj, dump, DoShowSockQos);
}

static FILLP_INT DoShowFrameStats(FILLP_CONST struct FtSocket *sock, FILLP_CHAR *data, FILLP_UINT32 *len)
{
    struct FillpFrameStats *stats = &sock->netconn->pcb->fpcb.frameHandle.stats;
    FILLP_DUMP_MSG_ADD_CHECK(data, *len, CRLF"%20s\t %20s\t %20s\t %20s"CRLF,
        "iFrameCount", "iFrameTotalSize", "pFrameCount", "pFrameTotalSize");
    FILLP_DUMP_MSG_ADD_CHECK(data, *len, "%20u\t %20llu\t %20u\t %20llu"CRLF,
        stats->iFrameCount, stats->iFrameTotalSize, stats->pFrameCount, stats->pFrameTotalSize);
    return FILLP_SUCCESS;
}

static FILLP_INT FillpDumpShowFrameStats(FILLP_INT sockIndex, void *softObj, FillpDfxDumpFunc dump)
{
    return FillpDumpShowSockData(sockIndex, softObj, dump, DoShowFrameStats);
}

static FILLP_INT FillpDumpMgtMsgCb(FILLP_INT optVal, void *softObj, FillpDfxDumpFunc dump)
{
    const FILLP_CHAR *successMsg = "management message set success";
    const FILLP_CHAR *failMsg = "management message set fail";
    if (FillpApiSetMgtMsgLog(optVal) != EOK) {
        dump(softObj, failMsg, strlen(failMsg) + 1);
        return FILLP_FAILURE;
    }
    dump(softObj, successMsg, strlen(successMsg) + 1);
    return FILLP_SUCCESS;
}

static const FILLP_CHAR *g_optString = "hlns:q:f:m:V";
static const FILLP_CHAR *g_optErrMsg = "Parse option fail, please check your option!";
typedef FILLP_INT (*FillpDumpOptCb)(FILLP_INT sockIndex, void *softObj, FillpDfxDumpFunc dump);
typedef struct {
    FILLP_INT opt;
    const NstackGetOptMsg *optMsg;
    void *softObj;
    FillpDfxDumpFunc dump;
} FillpDfxDumpOptArgs;

static FILLP_INT FillpDfxCheckArg(FILLP_UINT32 argc, const FILLP_CHAR **argv, FillpDfxDumpFunc dump)
{
    if (dump == NULL) {
        FILLP_LOGERR("dump is null");
        return FILLP_FAILURE;
    }
    if (argc <= 1 || argc > FILLP_DFX_DUMP_MAX_ARGC) {
        FILLP_LOGERR("argc is invalid %u", argc);
        return FILLP_FAILURE;
    }
    if (argv == FILLP_NULL_PTR) {
        FILLP_LOGERR("argv is NULL");
        return FILLP_FAILURE;
    }
    FILLP_UINT32 i;
    for (i = 0; i < argc; i++) {
        if (argv[i] == FILLP_NULL_PTR) {
            FILLP_LOGERR("argv[%d] is NULL", i);
            return FILLP_FAILURE;
        }
    }
    return FILLP_SUCCESS;
}

static FILLP_INT IsCommonOptArgLegal(const FILLP_CHAR *optArgs, FILLP_INT opt)
{
    if (optArgs == FILLP_NULL_PTR) {
        return FILLP_FAILURE;
    }
    size_t len = strnlen(optArgs, FILLP_DFX_DUMP_MAX_OPT_ARG_LEN + 1);
    if (len == 0 || len > FILLP_DFX_DUMP_MAX_OPT_ARG_LEN) {
        return FILLP_FAILURE;
    }
    if (opt == 'm' && (len != 1 || (optArgs[0] != '0' && optArgs[0] != '1'))) {
        return FILLP_FAILURE;
    }

    FILLP_UINT8 i;
    for (i = 0; i < len; i++) {
        if (optArgs[i] < '0' || optArgs[i] > '9') {
            return FILLP_FAILURE;
        }
    }

    return FILLP_SUCCESS;
}

static FILLP_INT FillpDfxDumpGetOptVal(const FillpDfxDumpOptArgs *optArgStr, FILLP_INT *optVal)
{
    const FILLP_CHAR *optArgs = NstackGetOptArgs(optArgStr->optMsg);
    if (IsCommonOptArgLegal(optArgs, optArgStr->opt) != FILLP_SUCCESS) {
        goto INVALID_ARG;
    }
    FILLP_LLONG val = strtoll(optArgs, FILLP_NULL_PTR, FILLP_DFX_DUMP_STRTOL_BASE);
    if (val > INT_MAX) {
        goto INVALID_ARG;
    }
    *optVal = (FILLP_INT)val;
    return FILLP_SUCCESS;

INVALID_ARG:
    optArgStr->dump(optArgStr->softObj, g_optErrMsg, strlen(g_optErrMsg) + 1);
    (void)FillpDumpShowHelp(optArgStr->softObj, optArgStr->dump);
    return FILLP_FAILURE;
}

static FILLP_INT FillpDfxDumpDealOptWithArgs(const FillpDfxDumpOptArgs *optArgStr, FillpDumpOptCb cb)
{
    FILLP_INT optVal;
    if (FillpDfxDumpGetOptVal(optArgStr, &optVal) != FILLP_SUCCESS) {
        return FILLP_FAILURE;
    }
    return cb(optVal, optArgStr->softObj, optArgStr->dump);
}

static FILLP_INT FillpDfxDumpDoParseOpt(const FillpDfxDumpOptArgs *optArgStr)
{
    FILLP_INT ret;
    switch (optArgStr->opt) {
        case 'h':
            ret = FillpDumpShowHelp(optArgStr->softObj, optArgStr->dump);
            break;
        case 'l':
            ret = FillpDumpShowLogLevel(optArgStr->softObj, optArgStr->dump);
            break;
        case 'n':
            ret = FillpDumpShowSockList(optArgStr->softObj, optArgStr->dump);
            break;
        case 's':
            ret = FillpDfxDumpDealOptWithArgs(optArgStr, FillpDumpShowSockResource);
            break;
        case 'q':
            ret = FillpDfxDumpDealOptWithArgs(optArgStr, FillpDumpShowSockQos);
            break;
        case 'f':
            ret = FillpDfxDumpDealOptWithArgs(optArgStr, FillpDumpShowFrameStats);
            break;
        case 'V':
            ret = FillpDumpShowVer(optArgStr->softObj, optArgStr->dump);
            break;
        case 'm':
            ret = FillpDfxDumpDealOptWithArgs(optArgStr, FillpDumpMgtMsgCb);
            break;
        default:
            optArgStr->dump(optArgStr->softObj, g_optErrMsg, strlen(g_optErrMsg) + 1);
            (void)FillpDumpShowHelp(optArgStr->softObj, optArgStr->dump);
            ret = FILLP_FAILURE;
    }
    return ret;
}

FILLP_INT FillpDfxDump(FILLP_UINT32 argc, const FILLP_CHAR **argv, void *softObj, FillpDfxDumpFunc dump)
{
    FILLP_INT opt = 0;
    const FILLP_CHAR *dumpFailMsg = "dump show failed!";
    if (FillpDfxCheckArg(argc, argv, dump) != FILLP_SUCCESS) {
        if (dump != NULL) {
            dump(softObj, g_optErrMsg, strlen(g_optErrMsg) + 1);
            (void)FillpDumpShowHelp(softObj, dump);
        }
        return -1;
    }

    FILLP_BOOL isParseOpt = FILLP_FALSE;
    NstackGetOptMsg optMsg;
    (void)NstackInitGetOptMsg(&optMsg);
    while ((opt = NstackGetOpt(&optMsg, (FILLP_INT32)argc, argv, g_optString)) != NSTACK_GETOPT_END_OF_STR) {
        isParseOpt = FILLP_TRUE;
        FillpDfxDumpOptArgs optArgStr = {opt, &optMsg, softObj, dump};
        if (FillpDfxDumpDoParseOpt(&optArgStr) != FILLP_SUCCESS) {
            dump(softObj, dumpFailMsg, strlen(dumpFailMsg) + 1);
            return -1;
        }
    }
    if (!isParseOpt) {
        dump(softObj, g_optErrMsg, strlen(g_optErrMsg) + 1);
        (void)FillpDumpShowHelp(softObj, dump);
        return -1;
    }
    return 0;
}

#endif /* FILLP_ENABLE_DFX_HIDUMPER */

