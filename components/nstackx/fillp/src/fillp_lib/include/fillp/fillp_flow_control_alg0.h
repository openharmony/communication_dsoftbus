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

#ifndef FILLP_FC_ALG0_H
#define FILLP_FC_ALG0_H

#include "fillp/fillp_pcb.h"
#include "fillp/fillp.h"
#include "fillp_flow_control.h"


#ifdef __cplusplus
extern "C" {
#endif

#define FILLP_FC0_DEFAULT_RATE 200000

#define FILLP_FC0_PACK_RECV_INTERVAL_SAMPLE_NUM 20   /* num of the interval in two adjacent PACK received  */

enum FillpFcAlg0State {
    FILLP_FC0_STATE_INIT,
    FILLP_FC0_STATE_BW_PROBE
};

struct FillpRttSample {
    FILLP_LLONG t; /* rtt time */
    FILLP_LLONG v; /* rtt value */
};

#define FILLP_FC0_PROBE_HISTORY_PACK_MAX_RATE_NUM 11

struct FillpFlowControlAlg0 {
    struct FillpFlowControl *flowControl;
    FILLP_UINT32 maxRecvRate;          /* kbps */
    FILLP_UINT32 maxRateAllowed;
    FILLP_UINT8 fcState;             /* is rate detecting or stable */
    FILLP_UINT8 historyMaxRecvRateIndex;
    FILLP_UINT8 sendRateIncreaseGainIndex;
    FILLP_UINT32 packDeltaUsArrayIndex;
    struct FillpMaxRateSample historyMaxRecvRate; /* State for the parameterized max tracker */
    FILLP_UINT32 packDeltaUsArray[FILLP_FC0_PACK_RECV_INTERVAL_SAMPLE_NUM];
};

#ifdef __cplusplus
}
#endif

#endif /* FILLP_FC_ALG0_H */
