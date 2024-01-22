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

#include "hb_fsm_strategy_mock.h"
#include "softbus_error_code.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_hbFSMStrategyInterface;
HeartBeatFSMStrategyInterfaceMock::HeartBeatFSMStrategyInterfaceMock()
{
    g_hbFSMStrategyInterface = reinterpret_cast<void *>(this);
}

HeartBeatFSMStrategyInterfaceMock::~HeartBeatFSMStrategyInterfaceMock()
{
    g_hbFSMStrategyInterface = nullptr;
}

static HeartBeatFSMStrategyInterface *HeartBeatFSMStrategyInterfaceInstance()
{
    return reinterpret_cast<HeartBeatFSMStrategyInterfaceMock *>(g_hbFSMStrategyInterface);
}

extern "C" {
int32_t LnnPostSendEndMsgToHbFsm(LnnHeartbeatFsm *hbFsm, LnnHeartbeatSendEndData *custData, uint64_t delayMillis)
{
    return HeartBeatFSMStrategyInterfaceInstance()->LnnPostSendEndMsgToHbFsm(hbFsm, custData, delayMillis);
}

int32_t LnnPostSendBeginMsgToHbFsm(LnnHeartbeatFsm *hbFsm, LnnHeartbeatType type, bool wakeupFlag,
    LnnProcessSendOnceMsgPara *msgPara, uint64_t delayMillis)
{
    return HeartBeatFSMStrategyInterfaceInstance()->LnnPostSendBeginMsgToHbFsm(hbFsm, type, wakeupFlag,
        msgPara, delayMillis);
}

SoftBusScreenState GetScreenState(void)
{
    return HeartBeatFSMStrategyInterfaceInstance()->GetScreenState();
}

bool LnnCheckSupportedHbType(LnnHeartbeatType *srcType, LnnHeartbeatType *dstType)
{
    return HeartBeatFSMStrategyInterfaceInstance()->LnnCheckSupportedHbType(srcType, dstType);
}

int32_t LnnPostStartMsgToHbFsm(LnnHeartbeatFsm *hbFsm, uint64_t delayMillis)
{
    return HeartBeatFSMStrategyInterfaceInstance()->LnnPostStartMsgToHbFsm(hbFsm, delayMillis);
}
}
} // namespace OHOS
