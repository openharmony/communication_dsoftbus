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

#ifndef FILLP_PDT_FC_MIRACAST_H
#define FILLP_PDT_FC_MIRACAST_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#ifdef PDT_MIRACAST

#define FILLP_PDT_INFO "PDT:Miracast"
#define FILLP_PDT_ALG "FILLP"

#define MAX_SPUNGEINSTANCE_NUM 1
#define FILLP_DEFAULT_INST_NUM 1

#define FILLP_ALG_DEFAULT_TYPE FILLP_ALG_BASE

#define FILLP_DEFAULT_APP_PKT_SIZE 1460 /* default pkt size to cal flow rate */

#define FILLP_DEFAULT_APP_SEND_CACHE 8192 /* size of send cache */
#define FILLP_DEFAULT_APP_RECV_CACHE 8192 /* size of recv cache */
#define FILLP_DYMM_INIT_SEND_SIZE 4096
#define FILLP_DYMM_INIT_RECV_SIZE 4096
#define FILLP_DYMM_INCREASE_STEP_SEND 512
#define FILLP_DYMM_INCREASE_STEP_RECV 512

#define FILLP_DEFAULT_MSG_SEND_CACHE 512 /* size of send cache */
#define FILLP_DEFAULT_MSG_RECV_CACHE 512 /* size of recv cache */
#define FILLP_MSG_DYMM_INIT_SEND_SIZE 512
#define FILLP_MSG_DYMM_INIT_RECV_SIZE 512

#define FILLP_DEFAULT_APP_SLOW_START FILLP_TRUE /* slow start */

#define FILLP_DEFAULT_BFULL_CPU FILLP_FALSE

/* pack setting */
#define FILLP_DEFAULT_APP_PACK_INTERVAL (10 * 1000) /* (10 * 1000)us */
#define FILLP_DEFAULT_ENLARGE_PACK_INTERVAL FILLP_FALSE
#define FILLP_ADHOC_PACK_ENABLE FILLP_TRUE
#define ADHOC_PACK_TRIGGLE_THRESHOLD 200

/* nack setting */
#define FILLP_DEFAULT_NACK_REPEAT_TIMES 3
#define FILLP_DELAY_NACK_ENABLE FILLP_FALSE
#define FILLP_DEFAULT_SEND_HISTORY_NACK FILLP_TRUE

/* resend setting */
#define FILLP_RETRANSMIT_CMP_TIME 1
#define FILLP_RETRANSMIT_CMP_TIME_EXT 1

#define FILLP_MINIMUM_SELECT_TIME 1000 /* us */

#define FILLP_TIMING_WHEEL_ACCURACY 5  /* us */
#define FILLP_MAX_SEND_INTERVAL (1000 << 3)

#define FILLP_LOG_WITH_TIME 1

#define FILLP_CPU_PAUSE_TIME 10      /* sleep time */
#define FILLP_RCV_CPU_PAUSE_TIME 100 /* sleep time, design for miracast to low the power */

#define FILLP_DEFAULT_APP_TX_BURST 44 /* tx burst */
#define FILLP_DEFAULT_RX_BURST 1024    /* max pkt number to recv each cycle */
#define FILLP_UNSEND_BOX_LOOP_CHECK_BURST 1024

#define FILLP_MAXIMAL_ACK_NUM_LIMITATION (2000)
#define FILLP_SEND_ONE_ACK_NUM (100)

#define FILLP_MAX_CONNECT_TIMEOUT (3600 * 1000) /* ms */

#define FILLP_DEFAULT_DESTROY_STACK_WITHOUT_WAIT_SOCKET_CLOSE FILLP_TRUE
#define FILLP_DEFAULT_RECVBOX_BRUST 1024

#define FILLP_DEFAULT_MIN_RATE 5000u                    /* 5 Mbps */
#define FILLP_DEFAULT_INITIAL_RATE 5000u                /* 5 Mbps */
#define FILLP_DEFAULT_MAX_RATE 500000                   /* 50 Mbps */

#endif

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* FILLP_PDT_FC_MIRACAST_H */
