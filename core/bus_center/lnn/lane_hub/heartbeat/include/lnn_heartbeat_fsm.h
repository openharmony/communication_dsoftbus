/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef LNN_HEARTBEAT_FSM_H
#define LNN_HEARTBEAT_FSM_H

#include "common_list.h"
#include "lnn_heartbeat_medium_mgr.h"
#include "lnn_state_machine.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    STATE_HB_INDEX_MIN = 0,
    STATE_HB_NONE_INDEX = STATE_HB_INDEX_MIN,
    STATE_HB_NORMAL_NODE_INDEX,
    STATE_HB_MASTER_NODE_INDEX,
    STATE_HB_INDEX_MAX,
} LnnHeartbeatState;

typedef enum {
    EVENT_HB_MIN = 0,
    EVENT_HB_AS_MASTER_NODE,
    EVENT_HB_AS_NORMAL_NODE,
    EVENT_HB_IN_NONE_STATE,
    EVENT_HB_PROCESS_SEND_ONCE,
    EVENT_HB_SEND_ONE_BEGIN = 5,
    EVENT_HB_SEND_ONE_END,
    EVENT_HB_CHECK_DEV_STATUS,
    EVENT_HB_START_PROCESS,
    EVENT_HB_STOP_SPECIFIC,
    EVENT_HB_SET_MEDIUM_PARAM = 10,
    EVENT_HB_UPDATE_SEND_INFO,
    EVENT_HB_SCREEN_OFF_CHECK_STATUS,
    EVENT_HB_MAX,
} LnnHeartbeatEventType;

typedef struct {
    ListNode node;
    uint16_t id;
    LnnHeartbeatType hbType;

    char fsmName[HB_FSM_NAME_LEN];
    FsmStateMachine fsm;
    LnnHeartbeatState state;
    LnnHeartbeatStrategyType strategyType;
} LnnHeartbeatFsm;

typedef struct {
    LnnHeartbeatType hbType;
    bool wakeupFlag;
    bool isRelay;
    bool *isRemoved;
} LnnRemoveSendEndMsgPara;

typedef struct {
    LnnHeartbeatType hbType;
    ConnectionAddrType addrType;
    bool hasNetworkId;
    bool isWakeUp;
    const char networkId[NETWORK_ID_BUF_LEN];
} LnnCheckDevStatusMsgPara;

typedef struct {
    LnnHeartbeatType hbType;
    LnnHeartbeatStrategyType strategyType;
    bool isRelay;
    bool isSyncData;
} LnnProcessSendOnceMsgPara;

int32_t LnnStartHeartbeatFsm(LnnHeartbeatFsm *hbFsm);
int32_t LnnStopHeartbeatFsm(LnnHeartbeatFsm *hbFsm);

int32_t LnnPostNextSendOnceMsgToHbFsm(LnnHeartbeatFsm *hbFsm, const LnnProcessSendOnceMsgPara *para,
    uint64_t delayMillis);
int32_t LnnPostSendBeginMsgToHbFsm(LnnHeartbeatFsm *hbFsm, LnnHeartbeatType type, bool wakeupFlag,
    LnnProcessSendOnceMsgPara *msgPara, uint64_t delayMillis);
int32_t LnnPostSendEndMsgToHbFsm(LnnHeartbeatFsm *hbFsm, LnnHeartbeatSendEndData *custData, uint64_t delayMillis);
int32_t LnnPostStartMsgToHbFsm(LnnHeartbeatFsm *hbFsm, uint64_t delayMillis);
int32_t LnnPostStopMsgToHbFsm(LnnHeartbeatFsm *hbFsm, LnnHeartbeatType type);
int32_t LnnPostTransStateMsgToHbFsm(LnnHeartbeatFsm *hbFsm, LnnHeartbeatEventType evtType);
int32_t LnnPostSetMediumParamMsgToHbFsm(LnnHeartbeatFsm *hbFsm, const LnnHeartbeatMediumParam *para);
int32_t LnnPostCheckDevStatusMsgToHbFsm(LnnHeartbeatFsm *hbFsm, const LnnCheckDevStatusMsgPara *para,
    uint64_t delayMillis);
int32_t LnnPostUpdateSendInfoMsgToHbFsm(LnnHeartbeatFsm *hbFsm, LnnHeartbeatUpdateInfoType type);
int32_t LnnPostScreenOffCheckDevMsgToHbFsm(LnnHeartbeatFsm *hbFsm, const LnnCheckDevStatusMsgPara *para,
    uint64_t delayMillis);

void LnnRemoveSendEndMsg(LnnHeartbeatFsm *hbFsm, LnnHeartbeatType type, bool wakeupFlag, bool isRelay, bool *isRemoved);
void LnnRemoveCheckDevStatusMsg(LnnHeartbeatFsm *hbFsm, LnnCheckDevStatusMsgPara *msgPara);
void LnnRemoveScreenOffCheckStatusMsg(LnnHeartbeatFsm *hbFsm, LnnCheckDevStatusMsgPara *msgPara);
void LnnRemoveProcessSendOnceMsg(LnnHeartbeatFsm *hbFsm, LnnHeartbeatType hbType,
    LnnHeartbeatStrategyType strategyType);

LnnHeartbeatFsm *LnnCreateHeartbeatFsm(void);
void LnnDestroyHeartbeatFsm(LnnHeartbeatFsm *hbFsm);

#ifdef __cplusplus
}
#endif
#endif /* LNN_HEARTBEAT_FSM_H */
