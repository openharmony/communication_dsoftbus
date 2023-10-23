/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#ifndef P2P_V1_PROCESSOR_H
#define P2P_V1_PROCESSOR_H

#include "wifi_direct_processor.h"

#ifdef __cplusplus
extern "C" {
#endif

enum P2pV1ProcessorState {
    P2P_V1_PROCESSOR_STATE_AVAILABLE = 0,
    P2P_V1_PROCESSOR_STATE_WAITING_RESPONSE = 1,
    P2P_V1_PROCESSOR_STATE_WAITING_REQUEST = 2,
    P2P_V1_PROCESSOR_STATE_WAITING_CREAT_GROUP = 3,
    P2P_V1_PROCESSOR_STATE_WAITING_CONNECT_GROUP = 4,
    P2P_V1_PROCESSOR_STATE_WAITING_DISCONNECT = 5,
    P2P_V1_PROCESSOR_STATE_WAITING_REMOVE_GROUP = 6,
    P2P_V1_PROCESSOR_STATE_WAITING_CLIENT_JOIN = 7,
};

struct P2pV1Processor {
    PROCESSOR_BASE;

    enum P2pV1ProcessorState currentState;
    struct InnerLink *currentInnerLink;
    struct NegotiateMessage *pendingRequestMsg;
    int32_t goPort;
    int32_t pendingErrorCode;
};

struct P2pV1Processor* GetP2pV1Processor(void);

#ifdef __cplusplus
}
#endif
#endif