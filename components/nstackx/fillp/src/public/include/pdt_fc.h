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

#ifndef FILLP_PDT_FLOWCONTROL_H
#define FILLP_PDT_FLOWCONTROL_H
#include "fillptypes.h"

#ifdef PDT_UT
#include "pdt_fc_ut.h"
#endif /* PDT_UT */

#ifdef PDT_MIRACAST
#include "pdt_fc_miracast.h"
#endif /* PDT_MIRACAST */

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#ifndef FILLP_PDT_INFO
#error "No pdt information!!!"
#endif

#ifndef FILLP_OFFERING_INFO
#define FILLP_OFFERING_INFO "nStack RivulNet"
#endif

#define FILLP_VERSION_DATE "[2022-08-30]"

#define FILLP_STACK_SPACE "          "

#define FILLP_VERSION \
    FILLP_OFFERING_INFO " 205.0.2 (" FILLP_PDT_ALG ") " FILLP_STACK_SPACE FILLP_PDT_INFO FILLP_VERSION_DATE

#ifndef MAX_SPUNGEINSTANCE_NUM
#define MAX_SPUNGEINSTANCE_NUM 1
#endif

#ifndef FILLP_DEFAULT_INST_NUM
#define FILLP_DEFAULT_INST_NUM 1
#endif

#ifndef FILLP_DEFAULT_APP_SEND_CACHE
#define FILLP_DEFAULT_APP_SEND_CACHE 819200 /* size of send cache */
#endif

#ifndef FILLP_DEFAULT_APP_RECV_CACHE
#define FILLP_DEFAULT_APP_RECV_CACHE 819200 /* size of recv cache */
#endif

#ifndef FILLP_DEFAULT_MAX_RATE
#define FILLP_DEFAULT_MAX_RATE (20 * 1000) /* max rate */
#endif

#ifndef FILLP_DEFAULT_CORE_MAX_RATE
#define FILLP_DEFAULT_CORE_MAX_RATE (10 * 1000 * 1000) /* max rate */
#endif

#ifndef FILLP_DEFAULT_CORE_MAX_RECV_RATE
#define FILLP_DEFAULT_CORE_MAX_RECV_RATE FILLP_DEFAULT_CORE_MAX_RATE
#endif

#ifndef FILLP_DEFAULT_APP_PKT_SIZE
#define FILLP_DEFAULT_APP_PKT_SIZE 1300 /* default pkt size to cal flow rate */
#endif

#ifndef FILLP_MAX_PKT_SIZE
#define FILLP_MAX_PKT_SIZE 9000
#endif

#ifndef FILLP_DEFAULT_APP_SLOW_START
#define FILLP_DEFAULT_APP_SLOW_START FILLP_TRUE /* slow start */
#endif

#ifndef FILLP_DEFAULT_APP_KEEP_ALIVE_TIME
#define FILLP_DEFAULT_APP_KEEP_ALIVE_TIME (200 * 1000) /* keep alive time, ms */
#endif

#ifndef FILLP_DEFAULT_MAX_SOCK_NUM
#ifdef FILLP_LW_LITEOS
#define FILLP_DEFAULT_MAX_SOCK_NUM 10
#else
#define FILLP_DEFAULT_MAX_SOCK_NUM (1024)
#endif
#endif

#ifndef FILLP_DEFAULT_MAX_CONNECTION_NUM
#ifdef FILLP_LW_LITEOS
#define FILLP_DEFAULT_MAX_CONNECTION_NUM 10
#else
#define FILLP_DEFAULT_MAX_CONNECTION_NUM (1024)
#endif
#endif

#ifndef FILLP_DEFAULT_BFULL_CPU
#define FILLP_DEFAULT_BFULL_CPU  FILLP_TRUE
#endif

#ifndef FILLP_DEFAULT_INITIAL_RATE
#define FILLP_DEFAULT_INITIAL_RATE 2000
#endif

#ifndef FILLP_DEFAULT_PKT_LOSS_ALLOW
#define FILLP_DEFAULT_PKT_LOSS_ALLOW 8
#endif

#ifndef FILLP_DEFAULT_NACK_REPEAT_TIMES
#define FILLP_DEFAULT_NACK_REPEAT_TIMES 5
#endif

#ifndef FILLP_MIN_PACK_INTERVAL
#define FILLP_MIN_PACK_INTERVAL (50 * 1000) /* min packet interval if rtt is less then default rtt */
#endif

#ifndef FILLP_DEFAULT_APP_PACK_INTERVAL
#define FILLP_DEFAULT_APP_PACK_INTERVAL (20 * 1000) /* packet interval (us) */
#endif

#ifndef FILLP_MINIMUM_SELECT_TIME
#define FILLP_MINIMUM_SELECT_TIME 10000 // us
#endif

#ifndef FILLP_DELAY_NACK_ENABLE
#define FILLP_DELAY_NACK_ENABLE FILLP_TRUE
#endif

#ifndef FILLP_ADHOC_PACK_ENABLE
#define FILLP_ADHOC_PACK_ENABLE FILLP_FALSE
#endif

#ifndef FILLP_TIMING_WHEEL_SLOT_NUM
#define FILLP_TIMING_WHEEL_SLOT_NUM 8
#endif

#ifndef FILLP_TIMING_WHEEL_ACCURACY
#define FILLP_TIMING_WHEEL_ACCURACY 100 /* us */
#endif

#ifndef FILLP_ALG_DEFAULT_TYPE
#define FILLP_ALG_DEFAULT_TYPE FILLP_ALG_BASE
#endif /* FILLP_ALG_DEFAULT_TYPE */

#ifndef FILLP_DYMM_INCREASE_STEP_SEND
#define FILLP_DYMM_INCREASE_STEP_SEND 1024
#endif /* FILLP_DYMM_INCREASE_STEP_SEND */

#ifndef FILLP_DYMM_INCREASE_STEP_RECV
#define FILLP_DYMM_INCREASE_STEP_RECV 1024
#endif /* FILLP_DYMM_INCREASE_STEP_RECV */

#ifndef FILLP_INST_UNSEND_BOX_SIZE
#define FILLP_INST_UNSEND_BOX_SIZE 819200
#endif

#ifndef FILLP_DYMM_INST_RECV_BUF_SIZE
#define FILLP_DYMM_INST_RECV_BUF_SIZE 819200
#endif

#ifndef FILLP_DYMM_INST_SEND_BUF_SIZE
#define FILLP_DYMM_INST_SEND_BUF_SIZE 819200
#endif

#ifndef FILLP_PRIV_RECV_SIZE
#define FILLP_PRIV_RECV_SIZE 10
#endif

#ifndef FILLP_DEFAULT_APP_TX_BURST
/* GlobalAppResource structure default values start */
#ifdef FILLP_LINUX
#define FILLP_DEFAULT_APP_TX_BURST 102400 /* tx burst */
#else
#define FILLP_DEFAULT_APP_TX_BURST 1400 /* tx burst */
#endif
#endif

#ifndef FILLP_DEFAULT_RX_BURST
/* GlobalResource structure default values start */
#ifdef FILLP_LINUX

#define FILLP_DEFAULT_RX_BURST 102400 /* max pkt number to recv each cycle */
#else
#define FILLP_DEFAULT_RX_BURST 1400 /* max pkt number to recv each cycle */
#endif
#endif

#ifndef FILLP_DEFAULT_DISCONNECT_TIMER_INTERVAL
#define FILLP_DEFAULT_DISCONNECT_TIMER_INTERVAL 200 /* ms */
#endif

#ifndef FILLP_DEFAULT_CONNECT_RETRY_TIMER_INTERVAL
#define FILLP_DEFAULT_CONNECT_RETRY_TIMER_INTERVAL 200 /* ms */
#endif

#ifndef FILLP_DEFAULT_APP_CONNECT_TIMEOUT
#define FILLP_DEFAULT_APP_CONNECT_TIMEOUT (10 * 1000) /* ms */
#endif

#ifndef FILLP_CPU_PAUSE_TIME
#define FILLP_CPU_PAUSE_TIME 100 /* sleep time */
#endif

#ifndef FILLP_DEFAULT_NACK_DELAY_TIME
#define FILLP_DEFAULT_NACK_DELAY_TIME 20000
#endif

#ifndef FILLP_DEFAULT_NACK_RETRY_LEN
#define FILLP_DEFAULT_NACK_RETRY_LEN 128
#endif

#ifndef FILLP_DEFAULT_NACK_RETRY_NUM
#define FILLP_DEFAULT_NACK_RETRY_NUM 1
#endif

#ifndef FILLP_DEFAULT_PACK_RETRY_NACK
#define FILLP_DEFAULT_PACK_RETRY_NACK FILLP_FALSE
#endif

#ifndef FILLP_DEFAULT_ENLARGE_PACK_INTERVAL
#define FILLP_DEFAULT_ENLARGE_PACK_INTERVAL FILLP_TRUE
#endif

#ifndef FILLP_UNSEND_BOX_LOOP_CHECK_BURST

#define FILLP_UNSEND_BOX_LOOP_CHECK_BURST 1024
#endif

#ifndef FILLP_DEFAULT_UDP_SEND_BUFSIZE
#ifdef FILLP_MAC
#define FILLP_DEFAULT_UDP_SEND_BUFSIZE (1 * 1024 * 1024) /* send buffer size */
#else
#define FILLP_DEFAULT_UDP_SEND_BUFSIZE (16 * 1024 * 1024) /* send buffer size */
#endif
#endif

#ifndef FILLP_DEFAULT_UDP_RECV_BUFSIZE
#ifdef FILLP_MAC
#define FILLP_DEFAULT_UDP_RECV_BUFSIZE (1 * 1024 * 1024) /* recv buffer size */
#else
#define FILLP_DEFAULT_UDP_RECV_BUFSIZE (16 * 1024 * 1024) /* recv buffer size */
#endif
#endif

#ifndef FILLP_DEFAULT_MAX_RECV_RATE
#define FILLP_DEFAULT_MAX_RECV_RATE FILLP_DEFAULT_MAX_RATE
#endif

#ifndef FILLP_DEFAULT_RECV_CACHE_PKT_NUM_BUFFER_SIZE
#define FILLP_DEFAULT_RECV_CACHE_PKT_NUM_BUFFER_SIZE 100
#endif

#ifndef FILLP_DEFAULT_RECV_CACHE_PKT_NUM_BUFFER_TIMEOUT
#define FILLP_DEFAULT_RECV_CACHE_PKT_NUM_BUFFER_TIMEOUT 25
#endif

#ifndef FILLP_DEFAULT_BOUT_OF_ORDER_CACHE_FEATURE
#define FILLP_DEFAULT_BOUT_OF_ORDER_CACHE_FEATURE FILLP_FALSE
#endif

#ifndef FILLP_DEFAULT_CPU_CORE_USE
#define FILLP_DEFAULT_CPU_CORE_USE 0
#endif

#ifndef FILLP_DEFAULT_MIN_RATE
#define FILLP_DEFAULT_MIN_RATE 350
#endif

#ifndef FILLP_DEFAULT_MMSG_SUPPORT
#define FILLP_DEFAULT_MMSG_SUPPORT FILLP_FALSE
#endif

#ifndef FILLP_DEFAULT_UDP_SEND_MSG_NUM
#define FILLP_DEFAULT_UDP_SEND_MSG_NUM 1
#endif

#ifndef FILLP_FC_PKT_LOSS_IN_RANGE_THRESHOLD
#define FILLP_FC_PKT_LOSS_IN_RANGE_THRESHOLD 15
#endif

#ifndef FILLP_FC_PKT_LOSS_PROBE_THRESH_MAX
#define FILLP_FC_PKT_LOSS_PROBE_THRESH_MAX 3
#endif

#ifndef FILLP_FC_PKT_LOSS_PROBE_THRESH_MIN
#define FILLP_FC_PKT_LOSS_PROBE_THRESH_MIN 2
#endif

#ifndef FILLP_FC_MULTI_ADJUST_CONST
#define FILLP_FC_MULTI_ADJUST_CONST 1.00
#endif

#ifndef FILLP_FLOW_CONTROL_MULTI_NUM_STEP
#define FILLP_FLOW_CONTROL_MULTI_NUM_STEP 0.10
#endif

#ifndef FILLP_FC_NINETY_PERCENT_VAL
#define FILLP_FC_NINETY_PERCENT_VAL(value) ((value) * 0.8)
#endif

#ifndef FILLP_FLOW_CONTROL_MULTI_NUM_INITIAL_VAL
#define FILLP_FLOW_CONTROL_MULTI_NUM_INITIAL_VAL 2.4
#endif

#ifndef FILLP_RETRANSMIT_CMP_TIME
#define FILLP_RETRANSMIT_CMP_TIME 1
#endif

#ifndef FILLP_LOG_WITH_TIME
#define FILLP_LOG_WITH_TIME 1
#endif

#ifndef FILLP_DYMM_INIT_SEND_SIZE
#define FILLP_DYMM_INIT_SEND_SIZE 4096
#endif

#ifndef FILLP_DYMM_INIT_RECV_SIZE
#define FILLP_DYMM_INIT_RECV_SIZE 4096
#endif

#ifndef FILLP_APP_FC_STASTICS_INTERVAL
#define FILLP_APP_FC_STASTICS_INTERVAL (500 * 1000) // 500ms
#endif

#ifndef FILLP_APP_FC_STASTICS_MAX_INTERVAL
#define FILLP_APP_FC_STASTICS_MAX_INTERVAL (1000 * 1000) // 1s
#endif

#ifndef FILLP_DEFAULT_CONST_RATE_ENABLE
#define FILLP_DEFAULT_CONST_RATE_ENABLE FILLP_FALSE
#endif

#ifndef FILLP_FRAME_MTU
#define FILLP_FRAME_MTU 1500
#endif

#ifndef FILLP_HLEN
#define FILLP_HLEN 12
#endif

#ifndef FILLP_MAX_SEND_INTERVAL
#define FILLP_MAX_SEND_INTERVAL (10000 << 3)
#endif

#ifndef FILLP_MAX_CONNECT_TIMEOUT
#define FILLP_MAX_CONNECT_TIMEOUT (300 * 1000) /* ms */
#endif

#ifndef FILLP_MAX_CONNECT_RETRY_TIMER_INTERVAL
#define FILLP_MAX_CONNECT_RETRY_TIMER_INTERVAL (10 * 1000) /* ms */
#endif

#ifndef FILLP_MAX_DISCONNECT_TIMER_INTERVAL
#define FILLP_MAX_DISCONNECT_TIMER_INTERVAL (10 * 1000) /* ms */
#endif

#ifndef FILLP_MAX_KEEP_ALIVE_TIME
#define FILLP_MAX_KEEP_ALIVE_TIME (3600 * 1000) // ms
#endif

#ifndef FILLP_MIN_KEEP_ALIVE_TIMER
#define FILLP_MIN_KEEP_ALIVE_TIMER 100 // ms
#endif

#ifndef FILLP_MAX_SOCK_NUMBER
#define FILLP_MAX_SOCK_NUMBER (1024 * 2)
#endif

#ifndef FILLP_MAX_CONN_NUMBER
#define FILLP_MAX_CONN_NUMBER (1024 * 2)
#endif

#ifndef FILLP_MAX_STACK_OPPOSITE_SET_RATE
#define FILLP_MAX_STACK_OPPOSITE_SET_RATE (10 * 1000 * 1000) /* max opposite set rate value */
#endif

#ifndef FILLP_MAX_TX_RX_BURST
#define FILLP_MAX_TX_RX_BURST 0x7fff
#endif

#ifndef FILLP_MIN_APP_PACK_INTERVAL
#define FILLP_MIN_APP_PACK_INTERVAL (1 * 1000) /* (1 * 1000)us */
#endif

#ifndef FILLP_MAX_APP_PACK_INTERVAL
#define FILLP_MAX_APP_PACK_INTERVAL (1000 * 1000) /* (1000 * 1000)us */
#endif

/* App have to take care when configuring tx burst, because if it
                                      is configured as big value, then the no of cycles of sending the
                                            data will be more. This will make performance dip to the app */
/* In FillpProcessConnConfirm, there is a multiplication with pktSize which
   should not cross the FILLP_MAX_INT_VALUE. As the pktSize cannot be exceeded
   more than 1500, below MAX value is changed from 0x7FFFFFFF to 1431648 (0x15D860).
   This is at the server side, default value is 81920. Thed MAX value is big
   enough for real time usecase scenario, hence no impact with this change
*/
#ifndef FILLP_MAX_SERVER_ALLOW_SEND_RECV_CACHE
#define FILLP_MAX_SERVER_ALLOW_SEND_RECV_CACHE 0x15D860 /* max server allow send or recv cache */
#endif

#ifndef FILLP_MAX_ALLOW_SEND_RECV_CACHE
#define FILLP_MAX_ALLOW_SEND_RECV_CACHE FILLP_MAX_SERVER_ALLOW_SEND_RECV_CACHE /* Max allow send or recv cache */
#endif

#ifndef FILLP_MAX_TIMER_RECV_CACHE_PKT_NUMBUFF
#define FILLP_MAX_TIMER_RECV_CACHE_PKT_NUMBUFF 300 /* max value of recv catche  number buffer timer */
#endif

#ifndef FILLP_MIN_TIMER_RECV_CACHE_PKT_NUMBUFF
#define FILLP_MIN_TIMER_RECV_CACHE_PKT_NUMBUFF 10 /* min value of recv catche  number buffer timer */
#endif

#ifndef FILLP_MAX_STACK_RECV_CACHE_PKT_NUM_BUFF_SIZE
#define FILLP_MAX_STACK_RECV_CACHE_PKT_NUM_BUFF_SIZE 10000 /* max value of stacak recv catche pakt num buff size */
#endif

#ifndef FILLP_MAX_STACK_OPPOSITE_SET_PERCENTAGE
#define FILLP_MAX_STACK_OPPOSITE_SET_PERCENTAGE 100 /* max value of stack opposite set percentage */
#endif

#ifndef FILLP_MAX_STACK_NACK_REPEAT_TIMES
#define FILLP_MAX_STACK_NACK_REPEAT_TIMES 0xFF /* max stack nack repeat times */
#endif

#ifndef FILLP_MAX_STACK_PACKET_LOSS_ALLOWED
#define FILLP_MAX_STACK_PACKET_LOSS_ALLOWED 100 /* max packet loss allowed */
#endif

#ifndef FILLP_MAX_STACK_RATE_PERCENTAGE
#define FILLP_MAX_STACK_RATE_PERCENTAGE 100 /* max stack rate percentage */
#endif

#ifndef FILLP_DEFAULT_DAT_OPT_TIMESTAMP_ENABLE
#define FILLP_DEFAULT_DAT_OPT_TIMESTAMP_ENABLE FILLP_FALSE
#endif

#ifndef FILLP_MAXIMAL_ACK_NUM_LIMITATION
#define FILLP_MAXIMAL_ACK_NUM_LIMITATION 0
#endif

#ifndef FILLP_SEND_ONE_ACK_NUM
#define FILLP_SEND_ONE_ACK_NUM 0
#endif

#ifndef MAX_RANDOM_LEV
#define MAX_RANDOM_LEV 1024
#endif

#ifndef FILLP_UNACK_HASH_SIZE
#define FILLP_UNACK_HASH_SIZE 512
#endif

#ifndef FILLP_MAX_PKTSEQ_HASH_SIZE
#define FILLP_MAX_PKTSEQ_HASH_SIZE 512    // Be sure it is power of 2
#endif

#ifndef FILLP_DEFAULT_STACK_CORE_LIMIT_RATE
#define FILLP_DEFAULT_STACK_CORE_LIMIT_RATE 0
#endif

#ifndef FILLP_FC_PKT_LOSS_PROBE_THRESH_MAX_EXT
#define FILLP_FC_PKT_LOSS_PROBE_THRESH_MAX_EXT 5
#endif

#ifndef FILLP_TIMING_WHEEL_ACCURACY_EXT
#define FILLP_TIMING_WHEEL_ACCURACY_EXT 64
#endif

#ifndef FILLP_MAXIMAL_ACK_NUM_LIMITATION_EXT
#define FILLP_MAXIMAL_ACK_NUM_LIMITATION_EXT 0
#endif

#ifndef FILLP_SEND_ONE_ACK_NUM_EXT
#define FILLP_SEND_ONE_ACK_NUM_EXT 0
#endif

#ifndef FILLP_CPU_PAUSE_TIME_EXT
#define FILLP_CPU_PAUSE_TIME_EXT 100
#endif

#ifndef FILLP_RETRANSMIT_CMP_TIME_EXT
#define FILLP_RETRANSMIT_CMP_TIME_EXT 1
#endif

#ifndef FILLP_DEFAULT_MIN_RATE_EXT
#define FILLP_DEFAULT_MIN_RATE_EXT 500
#endif

#ifndef FILLP_MIN_PACK_INTERVAL_EXT
#define FILLP_MIN_PACK_INTERVAL_EXT 30000
#endif

#ifndef FILLP_UNSEND_BOX_LOOP_CHECK_BURST_EXT
#define FILLP_UNSEND_BOX_LOOP_CHECK_BURST_EXT 1024
#endif

#ifndef FILLP_INST_UNSEND_BOX_SIZE_EXT
#define FILLP_INST_UNSEND_BOX_SIZE_EXT 8192
#endif

#ifndef FILLP_DEFAULT_NACK_RETRY_LEN_EXT
#define FILLP_DEFAULT_NACK_RETRY_LEN_EXT 120
#endif

#ifndef FILLP_FLOW_CONTROL_MULTI_NUM_INITIAL_VAL_EXT
#define FILLP_FLOW_CONTROL_MULTI_NUM_INITIAL_VAL_EXT 2.4
#endif

#ifndef FILLP_FC_MULTI_ADJUST_CONST_EXT
#define FILLP_FC_MULTI_ADJUST_CONST_EXT 1.2
#endif

#ifndef FILLP_FLOW_CONTROL_MULTI_NUM_STEP_EXT
#define FILLP_FLOW_CONTROL_MULTI_NUM_STEP_EXT 0.042
#endif

#ifndef FILLP_FC_NINETY_PERCENT_VAL_EXT
#define FILLP_FC_NINETY_PERCENT_VAL_EXT 0.8
#endif

#ifndef FILLP_DEFAULT_BFULL_CPU_THRESHOLD_RATE_EXT
#define FILLP_DEFAULT_BFULL_CPU_THRESHOLD_RATE_EXT (500 * 1000) /* In kbps */
#endif

#ifndef FILLP_DEFAULT_DESTROY_STACK_WITHOUT_WAIT_SOCKET_CLOSE
#define FILLP_DEFAULT_DESTROY_STACK_WITHOUT_WAIT_SOCKET_CLOSE FILLP_FALSE
#endif

#ifndef FILLP_DEFAULT_SUPPORT_CHARACTERS
#define FILLP_DEFAULT_SUPPORT_CHARACTERS 0
#endif

#ifndef FILLP_DEFAULT_RECVBOX_BRUST
#define FILLP_DEFAULT_RECVBOX_BRUST 100
#endif

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* FILLP_PDT_FLOWCONTROL_H */
