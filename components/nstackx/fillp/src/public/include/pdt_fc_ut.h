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

#ifndef FILLP_PDT_FC_UT_H
#define FILLP_PDT_FC_UT_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#ifdef PDT_UT

#ifdef FILLP_CPU
#define FILLP_X86 "X86"
#define FILLP_X64 "X64"

#else
#define FILLP_CPU ""
#endif

#ifdef FILLP_OSVER
#define FILLP_WIN32_VC10 "WIN32_VC10"
#define FILLP_SUSE11SP1_32 "SUSE11SP1_32"
#define FILLP_SUSE11SP1_64 "SUSE11SP1_64"

#else
#define FILLP_OSVER ""
#endif

#define FILLP_STACK_SPACE "          "

#define FILLP_PDT_INFO "PDT:UT"
#define FILLP_PDT_ALG "VTP"

#define MAX_SPUNGEINSTANCE_NUM 1
#define FILLP_DEFAULT_INST_NUM 1

#define SOCK_SEND_SEM 1
#define SOCK_RECV_SEM 1

#define FILLP_DEFAULT_APP_SEND_CACHE 2048 /* size of send cache */

#define FILLP_DEFAULT_APP_RECV_CACHE 2048 /* size of recv cache */

#define FILLP_DEFAULT_MAX_RATE (1 * 1000) /* max rate */

#define FILLP_DEFAULT_APP_SLOW_START FILLP_TRUE /* slow start */

#define FILLP_DEFAULT_BFULL_CPU FILLP_FALSE

#define FILLP_DEFAULT_INITIAL_RATE 350
#define FILLP_DEFAULT_MIN_RATE 350

#define FILLP_DEFAULT_PKT_LOSS_ALLOW 8
#define FILLP_DEFAULT_NACK_REPEAT_TIMES 5

#define FILLP_MIN_PACK_INTERVAL (50 * 1000)

#define FILLP_MINIMUM_SELECT_TIME 1000 // us

#define FILLP_DELAY_NACK_ENABLE FILLP_TRUE

#define FILLP_DEFAULT_ENLARGE_PACK_INTERVAL FILLP_TRUE

#define FILLP_DEFAULT_SEND_HISTORY_NACK FILLP_TRUE

#define FILLP_TIMING_WHEEL_ACCURACY 64 /* us */

#define FILLP_DEFAULT_HISTORY_NACK_PKT_NACK_NUM 5

#define FILLP_DEFAULT_NACK_RETRY_LEN 120
#define FILLP_FC_MULTI_ADJUST_CONST 1.25
#define FILLP_FLOW_CONTROL_MULTI_NUM_STEP 0.0392
#define FILLP_FC_NINETY_PERCENT_VAL(value) ((value) * 0.95)

/* GlobalAppResource structure default values start */
#ifdef FILLP_LINUX
#define FILLP_DEFAULT_APP_TX_BURST 4096 /* tx burst */
#else
#define FILLP_DEFAULT_APP_TX_BURST 1400 /* tx burst */
#endif

/* GlobalResource structure default values start */
#ifdef FILLP_LINUX
#define FILLP_DEFAULT_RX_BURST 4096 /* max pkt number to recv each cycle */
#else
#define FILLP_DEFAULT_RX_BURST 1400 /* max pkt number to recv each cycle */
#endif

#define FILLP_CPU_PAUSE_TIME 100 /* sleep time */

#define FILLP_UNSEND_BOX_LOOP_CHECK_BURST 1024

#endif

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif