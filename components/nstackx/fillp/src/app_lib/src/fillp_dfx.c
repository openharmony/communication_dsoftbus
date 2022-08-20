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
#include "sockets.h"
#include "socket_common.h"
#include "log.h"
#include "res.h"
#include "spunge.h"
#include "securec.h"
#include "nstackx_getopt.h"
#include "log.h"

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
        FILLP_UINT32 recvPktLoss; /* 0.01% */
        FILLP_LLONG recvRateBps; /* bps */
        FILLP_UINT32 sendPktLoss; /* 0.01% */
        FILLP_LLONG sendRateBps; /* bps */
        FILLP_LLONG jitter; /* ms */
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
            .paramName = "RECV_PKT_LOSS",
        },
        {
            .type = FILLP_DFX_PARAM_TYPE_UINT64,
            .paramName = "RECV_RATE_BPS",
        },
        {
            .type = FILLP_DFX_PARAM_TYPE_UINT32,
            .paramName = "SEND_PKT_LOSS",
        },
        {
            .type = FILLP_DFX_PARAM_TYPE_UINT64,
            .paramName = "SEND_RATE_BPS",
        },
        {
            .type = FILLP_DFX_PARAM_TYPE_UINT64,
            .paramName = "JITTER",
        },
    },
};

static void DfxEvtGetParamAddr(FillpDfxEvtArgs *args, FillpDfxEvt evt, void *paramVal[])
{
    void *paramValTmp[FILLP_DFX_EVT_DFX_MAX][FILLP_EVT_MAX_PARA_NUM] = {
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
            &args->sockQos.recvPktLoss,
            &args->sockQos.recvRateBps,
            &args->sockQos.sendPktLoss,
            &args->sockQos.sendRateBps,
            &args->sockQos.jitter,
        },
    };
    (void)memcpy_s((void *)paramVal, sizeof(void *) * FILLP_EVT_MAX_PARA_NUM,
        (void *)paramValTmp[evt], sizeof(void *) * FILLP_EVT_MAX_PARA_NUM);
}

void FillpDfxEvtCbSet(void *softObj, FillpDfxEventCb evtCb)
{
    if (g_fillpDfxEvtCb != FILLP_NULL_PTR) {
        FILLP_LOGERR("fillp dfx event callback already set!");
        return;
    }
    g_fillpDfxEvtCb = evtCb;
    g_fillpDfxSoftObj = softObj;
}

static void DfxEvtParamValCpy(void *dstVal, void * srcVal, FillpDfxEventParamType type)
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

static FillpDfxEventParam *FillpCreateDfxEvtParam(FillpDfxEvtArgs *args, FillpDfxEvt evt, FILLP_UINT32 paramNum)
{
    FILLP_UINT8 i;
    void *paramVal[FILLP_EVT_MAX_PARA_NUM];
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

static void FillpDfxEvtNotify(FillpDfxEvtArgs *args, FillpDfxEvt evt)
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

static void FillpDfxSockQosNotify(FILLP_INT sockIdx)
{
    FillpDfxEvtArgs args;
    (void)memset_s(&args, sizeof(args), 0, sizeof(args));
    args.sockQos.sockIdx = sockIdx;
    struct FtSocket *sock = SockApiGetAndCheck(sockIdx);
    if (sock == FILLP_NULL_PTR) {
        return;
    }
    if (sock->netconn == FILLP_NULL_PTR || sock->netconn->pcb == FILLP_NULL_PTR) {
        (void)SYS_ARCH_RWSEM_RDPOST(&sock->sockConnSem);
        return;
    }

    struct FtNetconn *netconn = (struct FtNetconn *)(sock->netconn);
    struct FillAppFcStastics *appFcStastics = &(netconn->pcb->fpcb.statistics.appFcStastics);

    args.sockQos.rtt = appFcStastics->periodRtt;
    args.sockQos.recvPktLoss = appFcStastics->periodRecvPktLossHighPrecision;
    args.sockQos.recvRateBps = appFcStastics->periodRecvRateBps;
    args.sockQos.sendPktLoss = appFcStastics->periodSendPktLossHighPrecision;
    args.sockQos.sendRateBps = appFcStastics->periodSendRateBps;
    args.sockQos.jitter = FILLP_UTILS_US2MS(sock->jitter);

    (void)SYS_ARCH_RWSEM_RDPOST(&sock->sockConnSem);
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

void FillpDfxSockLinkAndQosNotify(FILLP_INT sockIdx, FillpDfxLinkEvtType evtType)
{
    FillpDfxEvtArgs args;
    (void)memset_s(&args, sizeof(args), 0, sizeof(args));
    args.linkEvt.sockIdx = sockIdx;
    args.linkEvt.linkEvtType = evtType;
    FillpDfxEvtNotify(&args, FILLP_DFX_EVT_LINK_EXCEPTION);

    if (evtType == FILLP_DFX_LINK_VERSION_MISMATCH) {
        return;
    }

    FillpDfxSockQosNotify(sockIdx);

    FillpDfxPktParseFailNode *node = DfxGetPktPraseFailNode(sockIdx);
    if (node == FILLP_NULL_PTR) {
        return;
    }
    if (node->dropCnt == node->lastReportCnt) {
        HlistDelNode(&node->node);
        free(node);
        return;
    }
    (void)memset_s(&args, sizeof(args), 0, sizeof(args));
    args.pktEvt.sockIdx = sockIdx;
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
    args.pktEvt.sockIdx = sockIdx;
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
#define FUZZY_IN_ADDR(addr) ((uint8_t *)(addr))[0], ((uint8_t *)(addr))[1], ((uint8_t *)(addr))[2]
#define FILLP_DFX_DUMP_IP_PROT_LEN (10)

#define FILLP_DUMP_MSG_ADD_CHECK(data, len, fmt, ...) do { \
    FILLP_INT ret = sprintf_s(data + len, FILLP_DFX_DUMP_BUF_LEN - len, fmt, ##__VA_ARGS__); \
    if (ret < 0) { \
        FILLP_LOGERR("dumper buffer over %u bytes", FILLP_DFX_DUMP_BUF_LEN); \
        return FILLP_FAILURE; \
    } \
    len += ret; \
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

static void FillpDumpShowHelp(void *softObj, FillpDfxDumpFunc dump)
{
    FILLP_CHAR data[FILLP_DFX_DUMP_BUF_LEN];
    FILLP_UINT32 len = 0;
    if (DoShowHelp(data, &len) != FILLP_SUCCESS) {
        return;
    }
    dump(softObj, data, len);
}

static inline FILLP_INT DoShowVersion(FILLP_CHAR *data, FILLP_UINT32 *len)
{
    FILLP_DUMP_MSG_ADD_CHECK(data, *len, CRLF FILLP_VERSION CRLF);
    return FILLP_SUCCESS;
}

static void FillpDumpShowVer(void *softObj, FillpDfxDumpFunc dump)
{
    FILLP_CHAR data[FILLP_DFX_DUMP_BUF_LEN];
    FILLP_UINT32 len = 0;
    if (DoShowVersion(data, &len) != FILLP_SUCCESS) {
        return;
    }
    dump(softObj, data, len);
}

static inline FILLP_INT DoShowLogLevel(FILLP_CHAR *data, FILLP_UINT32 *len)
{
    FILLP_DUMP_MSG_ADD_CHECK(data, *len, CRLF"Current log level: %hhu"CRLF, g_fillpLmGlobal.debugLevel);
    return FILLP_SUCCESS;
}

static void FillpDumpShowLogLevel(void *softObj, FillpDfxDumpFunc dump)
{
    FILLP_CHAR data[FILLP_DFX_DUMP_BUF_LEN];
    FILLP_UINT32 len = 0;
    if (DoShowLogLevel(data, &len) != FILLP_SUCCESS) {
        return;
    }
    dump(softObj, data, len);
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
    FILLP_DUMP_MSG_ADD_CHECK(data, *len, "              use const stack send rate: %u"CRLF, fc->constRateEnbale);
    FILLP_DUMP_MSG_ADD_CHECK(data, *len, "              max send rate: %u Kbps"CRLF, fc->maxRate);
    FILLP_DUMP_MSG_ADD_CHECK(data, *len, "              max recv rate: %u Kbps"CRLF, fc->maxRecvRate);
    FILLP_DUMP_MSG_ADD_CHECK(data, *len, "              packet size: %u"CRLF, fc->pktSize);
    FILLP_DUMP_MSG_ADD_CHECK(data, *len, "              slow start: %u"CRLF, fc->slowStart);
    FILLP_DUMP_MSG_ADD_CHECK(data, *len, "Timer config: connection timeout: %u(s)"CRLF, common->connectTimeout);
    FILLP_DUMP_MSG_ADD_CHECK(data, *len, "              retry timeout: %u(s)"CRLF, common->connRetryTimeout);
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

static void FillpDumpShowSockResource(FILLP_INT sockIndex, void *softObj, FillpDfxDumpFunc dump)
{
    FILLP_CHAR data[FILLP_DFX_DUMP_BUF_LEN];
    FILLP_UINT32 len = 0;
    struct FtSocket *sock = SockApiGetAndCheck(sockIndex);
    if (sock == FILLP_NULL_PTR) {
        if (DumpInvalidSock(sockIndex, data, &len) == FILLP_SUCCESS) {
            dump(softObj, data, len);
        }
        return;
    }
    
    FILLP_INT32 isOk = DoShowSockConfigRes(sockIndex, &sock->resConf, data, &len);
    (void)SYS_ARCH_RWSEM_RDPOST(&sock->sockConnSem);
    if (isOk != FILLP_SUCCESS) {
        return;
    }
    dump(softObj, data, len);
}

static inline FILLP_INT32 DoShowSockListTitle(FILLP_CHAR *data, FILLP_UINT32 *len)
{
    FILLP_DUMP_MSG_ADD_CHECK(data, *len, CRLF"%5s\t %6s\t %6s\t %6s\t %6s\t %20s\t %20s\t %5s"CRLF,
        "Sock", "Unsend", "Unack", "Redun", "Unrecv", "LocalIP", "PeerIP", "State");
    return FILLP_SUCCESS;
}

static FILLP_INT32 DoShowSockList(FILLP_CONST struct FtSocket *sock, FILLP_CHAR *data, FILLP_UINT32 *len)
{
    struct sockaddr_in *local = (struct sockaddr_in *)&sock->netconn->pcb->localAddr;
    struct sockaddr_in *peer = (struct sockaddr_in *)&sock->netconn->pcb->remoteAddr;
    const struct FillpSendPcb *sendPcb = &sock->netconn->pcb->fpcb.send;
    FILLP_CHAR localAddr[INET_ADDRSTRLEN + FILLP_DFX_DUMP_IP_PROT_LEN];
    FILLP_CHAR peerAddr[INET_ADDRSTRLEN + FILLP_DFX_DUMP_IP_PROT_LEN];
    FILLP_UINT32 addrLen = 0;
    FILLP_DUMP_MSG_ADD_CHECK(localAddr, addrLen, "%hhu.%hhu.%hhu.***:%hu",
        FUZZY_IN_ADDR(&local->sin_addr), ntohs(local->sin_port));
    addrLen = 0;
    FILLP_DUMP_MSG_ADD_CHECK(peerAddr, addrLen, "%hhu.%hhu.%hhu.***:%hu",
        FUZZY_IN_ADDR(&peer->sin_addr), ntohs(peer->sin_port));
    FILLP_DUMP_MSG_ADD_CHECK(data, *len, "%5d\t %6u\t %6u\t %6u\t %6u\t %20s\t %20s\t %5hhu"CRLF,
        sock->index, sendPcb->unSendList.size, sendPcb->unackList.size, sendPcb->redunList.nodeNum,
        sendPcb->unrecvList.nodeNum, localAddr, peerAddr, sock->netconn->state);
    return FILLP_SUCCESS;
}

static void FillpDumpShowSockList(void *softObj, FillpDfxDumpFunc dump)
{
    struct FtSocket *sock = FILLP_NULL_PTR;
    FILLP_UINT32 len = 0;

    FILLP_CHAR *data = (FILLP_CHAR *)calloc(1U, g_spunge->resConf.maxSockNum * FILLP_DFX_DUMP_ONE_SOCK_BUF);
    if (data == FILLP_NULL_PTR) {
        const FILLP_CHAR *errMsg = "socket list dump buffer calloc failed!";
        dump(softObj, errMsg, strlen(errMsg) + 1);
        return;
    }
    if (DoShowSockListTitle(data, &len) != FILLP_SUCCESS) {
        free(data);
        return;
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
            return;
        }
    }
    dump(softObj, data, len);
    free(data);
}

static FILLP_INT DoShowSockQos(FILLP_CONST struct FtSocket *sock, FILLP_CHAR *data, FILLP_UINT32 *len)
{
    struct FillAppFcStastics *appFcStastics = &(sock->netconn->pcb->fpcb.statistics.appFcStastics);
    FILLP_DUMP_MSG_ADD_CHECK(data, *len, CRLF"%8s\t %18s\t %18s\t %16s\t %16s\t %10s"CRLF,
        "Rtt(ms)", "RecvPktLoss(0.01%%)", "SendPktLoss(0.01%%)", "RecvRateBps(bps)", "SendRateBps(bps)", "Jetter(us)");
    FILLP_DUMP_MSG_ADD_CHECK(data, *len, "%8u\t %18u\t %18u\t %16llu\t %16llu\t %10lld"CRLF,
        appFcStastics->periodRtt,
        appFcStastics->periodRecvPktLossHighPrecision,
        appFcStastics->periodSendPktLossHighPrecision,
        appFcStastics->periodRecvRateBps,
        appFcStastics->periodSendRateBps,
        sock->jitter);
    return FILLP_SUCCESS;
}

static void FillpDumpShowSockQos(FILLP_INT sockIndex, void *softObj, FillpDfxDumpFunc dump)
{
    FILLP_CHAR data[FILLP_DFX_DUMP_BUF_LEN];
    FILLP_UINT32 len = 0;
    struct FtSocket *sock = SockApiGetAndCheck(sockIndex);
    if (sock == FILLP_NULL_PTR || sock->netconn == FILLP_NULL_PTR || sock->netconn->pcb == FILLP_NULL_PTR) {
        if (sock != FILLP_NULL_PTR) {
            (void)SYS_ARCH_RWSEM_RDPOST(&sock->sockConnSem);
        }
        if (DumpInvalidSock(sockIndex, data, &len) == FILLP_SUCCESS) {
            dump(softObj, data, len);
        }
        return;
    }

    FILLP_INT isOk = DoShowSockQos(sock, data, &len);
    (void)SYS_ARCH_RWSEM_RDPOST(&sock->sockConnSem);
    if (isOk != FILLP_SUCCESS) {
        return;
    }
    dump(softObj, data, len);
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

static void FillpDumpShowFrameStats(FILLP_INT sockIndex, void *softObj, FillpDfxDumpFunc dump)
{
    FILLP_CHAR data[FILLP_DFX_DUMP_BUF_LEN];
    FILLP_UINT32 len = 0;
    struct FtSocket *sock = SockApiGetAndCheck(sockIndex);
    if (sock == FILLP_NULL_PTR || sock->netconn == FILLP_NULL_PTR || sock->netconn->pcb == FILLP_NULL_PTR) {
        if (sock != FILLP_NULL_PTR) {
            (void)SYS_ARCH_RWSEM_RDPOST(&sock->sockConnSem);
        }
        if (DumpInvalidSock(sockIndex, data, &len) == FILLP_SUCCESS) {
            dump(softObj, data, len);
        }
        return;
    }
    FILLP_INT isOk = DoShowFrameStats(sock, data, &len);
    (void)SYS_ARCH_RWSEM_RDPOST(&sock->sockConnSem);
    if (isOk != FILLP_SUCCESS) {
        return;
    }
    dump(softObj, data, len);
}

static const FILLP_CHAR *g_optString = "hlmns:q:f:V";

static FILLP_INT FillpDfxCheckArg(FILLP_UINT32 argc, const FILLP_CHAR **argv, FillpDfxDumpFunc dump)
{
    if (dump == NULL) {
        FILLP_LOGERR("dump is null");
        return FILLP_FAILURE;
    }
    if (argc == 0 || argc > FILLP_DFX_DUMP_MAX_ARGC) {
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

FILLP_INT FillpDfxDump(FILLP_UINT32 argc, const FILLP_CHAR **argv, void *softObj, FillpDfxDumpFunc dump)
{
    FILLP_INT opt = 0;
    FILLP_INT ret = 0;
    const FILLP_CHAR *errMsg = "Parse option fail, please check your option!";
    if (FillpDfxCheckArg(argc, argv, dump) != FILLP_SUCCESS) {
        goto FAIL;
    }

    NstackGetOptMsg optMsg;
    (void)NstackInitGetOptMsg(&optMsg);
    while ((opt = NstackGetOpt(&optMsg, argc, argv, g_optString)) != NSTACK_GETOPT_END_OF_STR) {
        switch (opt) {
            case 'h':
                FillpDumpShowHelp(softObj, dump);
                break;
            case 'l':
                FillpDumpShowLogLevel(softObj, dump);
                break;
            case 'n':
                FillpDumpShowSockList(softObj, dump);
                break;
            case 's':
                ret = strtol(NstackGetOptArgs(&optMsg), FILLP_NULL_PTR, FILLP_DFX_DUMP_STRTOL_BASE);
                FillpDumpShowSockResource(ret, softObj, dump);
                break;
            case 'q':
                ret = strtol(NstackGetOptArgs(&optMsg), FILLP_NULL_PTR, FILLP_DFX_DUMP_STRTOL_BASE);
                FillpDumpShowSockQos(ret, softObj, dump);
                break;
            case 'f':
                ret = strtol(NstackGetOptArgs(&optMsg), FILLP_NULL_PTR, FILLP_DFX_DUMP_STRTOL_BASE);
                FillpDumpShowFrameStats(ret, softObj, dump);
                break;
            case 'V':
                FillpDumpShowVer(softObj, dump);
                break;
            case 'm':
                ret = strtol(NstackGetOptArgs(&optMsg), FILLP_NULL_PTR, FILLP_DFX_DUMP_STRTOL_BASE);
                (void)FillpApiSetMgtMsgLog(ret);
                break;
            default:
                goto FAIL;
        }
    }
    return 0;
FAIL:
    if (dump != NULL) {
        dump(softObj, errMsg, strlen(errMsg) + 1);
        FillpDumpShowHelp(softObj, dump);
    }
    return -1;
}

#endif /* FILLP_ENABLE_DFX_HIDUMPER */

