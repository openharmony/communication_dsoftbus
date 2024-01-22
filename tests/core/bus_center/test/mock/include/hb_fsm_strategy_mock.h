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

#ifndef HEARTBEAT_FSM_STRATEGY_H
#define HEARTBEAT_FSM_STRATEGY_H

#include "lnn_heartbeat_fsm.h"
#include "lnn_heartbeat_ctrl.h"
#include "lnn_heartbeat_utils.h"
#include <gmock/gmock.h>
#include <mutex>

namespace OHOS {
class HeartBeatFSMStrategyInterface {
public:
    HeartBeatFSMStrategyInterface() {};
    virtual ~HeartBeatFSMStrategyInterface() {};

    virtual int32_t LnnPostSendEndMsgToHbFsm(LnnHeartbeatFsm *hbFsm, LnnHeartbeatSendEndData *custData,
        uint64_t delayMillis) = 0;
    virtual int32_t LnnPostSendBeginMsgToHbFsm(LnnHeartbeatFsm *hbFsm, LnnHeartbeatType type, bool wakeupFlag,
        LnnProcessSendOnceMsgPara *msgPara, uint64_t delayMillis) = 0;
    virtual SoftBusScreenState GetScreenState(void) = 0;
    virtual bool LnnCheckSupportedHbType(LnnHeartbeatType *srcType, LnnHeartbeatType *dstType) = 0;
    virtual int32_t LnnPostStartMsgToHbFsm(LnnHeartbeatFsm *hbFsm, uint64_t delayMillis) = 0;
};
class HeartBeatFSMStrategyInterfaceMock : public HeartBeatFSMStrategyInterface {
public:
    HeartBeatFSMStrategyInterfaceMock();
    ~HeartBeatFSMStrategyInterfaceMock() override;

    MOCK_METHOD3(LnnPostSendEndMsgToHbFsm, int32_t(LnnHeartbeatFsm *, LnnHeartbeatSendEndData *, uint64_t));
    MOCK_METHOD5(LnnPostSendBeginMsgToHbFsm, int32_t(LnnHeartbeatFsm *, LnnHeartbeatType, bool,
        LnnProcessSendOnceMsgPara *, uint64_t));
    MOCK_METHOD0(GetScreenState, SoftBusScreenState(void));
    MOCK_METHOD2(LnnCheckSupportedHbType, bool(LnnHeartbeatType *, LnnHeartbeatType *));
    MOCK_METHOD2(LnnPostStartMsgToHbFsm, int32_t(LnnHeartbeatFsm *, uint64_t));
};
} // namespace OHOS
#endif // HEARTBEAT_FSM_STRATEGY_H
