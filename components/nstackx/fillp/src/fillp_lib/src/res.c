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

#include "fillpinc.h"
#include "res.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
Description: Global resource
Value Range: None
Access: Used to maintain global udp resources, common resources and floe control resources
Remarks:
*/
struct GlobalResource g_resource = {
    {
        FILLP_DEFAULT_RX_BURST,         /* udp.rxBurst */
        FILLP_DEFAULT_UDP_SEND_MSG_NUM, /* udp.numMsgSend */
        FILLP_DEFAULT_MMSG_SUPPORT,     /* udp.supportMmsg */
        0                               /* udp.Padd */
    },
    {
        FILLP_DEFAULT_RECV_CACHE_PKT_NUM_BUFFER_SIZE,    /* common.recvCachePktNumBufferSize */
        FILLP_DEFAULT_RECV_CACHE_PKT_NUM_BUFFER_TIMEOUT, /* common.recvCachePktNumBufferTimeout */
        FILLP_DEFAULT_MAX_SOCK_NUM,                      /* common.maxSockNum */
        FILLP_DEFAULT_MAX_CONNECTION_NUM,                /* common.maxConnNum */
        FILLP_DEFAULT_INST_NUM,                          /* common.maxInstNum */
        FILLP_DEFAULT_BFULL_CPU,                         /* common.fullCpuEnable */
        FILLP_DEFAULT_BOUT_OF_ORDER_CACHE_FEATURE,       /* common.outOfOrderCacheEnable */
        FILLP_DEFAULT_CPU_CORE_USE,                      /* common.cpuCoreUse */
        0,                                               /* common.reserve */
        FILLP_DYMM_INST_SEND_BUF_SIZE,                   /* common.sendCache */
        FILLP_DYMM_INST_RECV_BUF_SIZE,                   /* common.recvCache */
        0,                                               /* uint32_reserve */
    },
    {
        FILLP_DEFAULT_CORE_MAX_RATE,           /* flowControl.maxRate */
        FILLP_DEFAULT_CORE_MAX_RECV_RATE,      /* flowControl.maxRecvRate */
        FILLP_DEFAULT_INITIAL_RATE,            /* flowControl.initialRate in Kbps */
        FILLP_DEFAULT_OPPOSITE_SET_PERCENTAGE, /* flowControl.oppositeSetPercentage */
        FILLP_DEFAULT_MAX_RATE_PERCENTAGE,     /* flowControl.maxRatePercentage */
        FILLP_DEFAULT_NACK_REPEAT_TIMES,       /* flowControl.nackRepeatTimes */
        FILLP_DEFAULT_PKT_LOSS_ALLOW,          /* flowControl.pktLossAllow */
        FILLP_ALG_DEFAULT_TYPE,                /* flowControl.fcAlg */
        FILLP_FAIRNESS_TYPE_NONE,              /* flowControl.supportFairness */
        FILLP_DEFAULT_STACK_CORE_LIMIT_RATE    /* flowControl.limitRate */
    },
    FILLP_FC_PKT_LOSS_PROBE_THRESH_MAX_EXT,       /* pktLossThresHoldMax */
    FILLP_TIMING_WHEEL_ACCURACY_EXT,              /* timingWheelAccuracy */
    FILLP_MAXIMAL_ACK_NUM_LIMITATION_EXT,         /* maximalAckNumLimit */
    FILLP_SEND_ONE_ACK_NUM_EXT,                   /* sendOneAckNum */
    FILLP_CPU_PAUSE_TIME_EXT,                     /* cpuPauseTime */
    FILLP_RETRANSMIT_CMP_TIME_EXT,                /* retransmitCmpTime */
    0,                                            /* reserve */
    FILLP_DEFAULT_MIN_RATE_EXT,                   /* minRate */
    FILLP_MIN_PACK_INTERVAL_EXT,                  /* minPackInterval */
    FILLP_UNSEND_BOX_LOOP_CHECK_BURST_EXT,        /* unsendBoxLoopCheckBurst */
    0,                                            /* reserv */
    FILLP_INST_UNSEND_BOX_SIZE_EXT,               /* instUnsendBoxSize */
    FILLP_DEFAULT_NACK_RETRY_LEN_EXT,             /* nackRetryLen */
    0,                                            /* reserved */
    FILLP_FLOW_CONTROL_MULTI_NUM_INITIAL_VAL_EXT, /* fcControlMultiNumInitialValue */
    FILLP_FC_MULTI_ADJUST_CONST_EXT,              /* fcMultiAdjustConst */
    FILLP_FLOW_CONTROL_MULTI_NUM_STEP_EXT,        /* fcMultiNumStep */
    FILLP_FC_NINETY_PERCENT_VAL_EXT,               /* fcNightyPercentVal */
    FILLP_DEFAULT_BFULL_CPU_THRESHOLD_RATE_EXT,   /* fullCpuUseThresholdRate */
    0                                             /* uint32_reserve */
};


#if FILLP_DEFAULT_UDP_SEND_MSG_NUM > FILLP_VLEN /* refer to FillpSendOne function for more details */
#error "FILLP_DEFAULT_UDP_SEND_MSG_NUM can't be greater then FILLP_VLEN"
#endif

void InitGlobalResourceDefault(void)
{
    g_resource.udp.rxBurst = FILLP_DEFAULT_RX_BURST;
    g_resource.udp.supportMmsg = FILLP_DEFAULT_MMSG_SUPPORT;
    g_resource.udp.numMsgSend = FILLP_DEFAULT_UDP_SEND_MSG_NUM;
    g_resource.common.recvCachePktNumBufferSize = FILLP_DEFAULT_RECV_CACHE_PKT_NUM_BUFFER_SIZE;
    g_resource.common.recvCachePktNumBufferTimeout = FILLP_DEFAULT_RECV_CACHE_PKT_NUM_BUFFER_TIMEOUT;
    g_resource.common.maxSockNum = FILLP_DEFAULT_MAX_SOCK_NUM;
    g_resource.common.maxConnNum = FILLP_DEFAULT_MAX_CONNECTION_NUM;
    g_resource.common.maxInstNum = FILLP_DEFAULT_INST_NUM;
    g_resource.common.fullCpuEnable = FILLP_DEFAULT_BFULL_CPU;
    g_resource.common.outOfOrderCacheEnable = FILLP_DEFAULT_BOUT_OF_ORDER_CACHE_FEATURE;
    g_resource.common.cpuCoreUse = FILLP_DEFAULT_CPU_CORE_USE;
    g_resource.common.sendCache = FILLP_DYMM_INST_SEND_BUF_SIZE;
    g_resource.common.recvCache = FILLP_DYMM_INST_RECV_BUF_SIZE;

    g_resource.flowControl.maxRate = FILLP_DEFAULT_MAX_RATE;
    g_resource.flowControl.maxRecvRate = FILLP_DEFAULT_MAX_RECV_RATE;
    g_resource.flowControl.initialRate = FILLP_DEFAULT_INITIAL_RATE; /* Kbps */
    g_resource.flowControl.oppositeSetPercentage = FILLP_DEFAULT_OPPOSITE_SET_PERCENTAGE;
    g_resource.flowControl.maxRatePercentage = FILLP_DEFAULT_MAX_RATE_PERCENTAGE;
    g_resource.flowControl.nackRepeatTimes = FILLP_DEFAULT_NACK_REPEAT_TIMES;
    g_resource.flowControl.pktLossAllow = FILLP_DEFAULT_PKT_LOSS_ALLOW;

    g_resource.flowControl.supportFairness = FILLP_FAIRNESS_TYPE_NONE;
    g_resource.flowControl.limitRate = FILLP_DEFAULT_STACK_CORE_LIMIT_RATE;

    g_resource.pktLossThresHoldMax = FILLP_FC_PKT_LOSS_PROBE_THRESH_MAX_EXT;
    g_resource.timingWheelAccuracy = FILLP_TIMING_WHEEL_ACCURACY_EXT;
    g_resource.maximalAckNumLimit = FILLP_MAXIMAL_ACK_NUM_LIMITATION_EXT;
    g_resource.sendOneAckNum = FILLP_SEND_ONE_ACK_NUM_EXT;
    g_resource.cpuPauseTime = FILLP_CPU_PAUSE_TIME_EXT;
    g_resource.retransmitCmpTime = FILLP_RETRANSMIT_CMP_TIME_EXT;
    g_resource.minRate = FILLP_DEFAULT_MIN_RATE_EXT;
    g_resource.minPackInterval = FILLP_MIN_PACK_INTERVAL_EXT;
    g_resource.unsendBoxLoopCheckBurst = FILLP_UNSEND_BOX_LOOP_CHECK_BURST_EXT;
    g_resource.instUnsendBoxSize = FILLP_INST_UNSEND_BOX_SIZE_EXT;
    g_resource.nackRetryLen = FILLP_DEFAULT_NACK_RETRY_LEN_EXT;
    g_resource.fcControlMultiNumInitialValue = FILLP_FLOW_CONTROL_MULTI_NUM_INITIAL_VAL_EXT;
    g_resource.fcMultiAdjustConst = FILLP_FC_MULTI_ADJUST_CONST_EXT;
    g_resource.fcMultiNumStep = FILLP_FLOW_CONTROL_MULTI_NUM_STEP_EXT;
    g_resource.fcNightyPercentVal = FILLP_FC_NINETY_PERCENT_VAL_EXT;
    g_resource.fullCpuUseThresholdRate = FILLP_DEFAULT_BFULL_CPU_THRESHOLD_RATE_EXT;
}
#ifdef __cplusplus
}
#endif
