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
    return HeartBeatFSMStrategyInterfaceInstance()->LnnPostSendBeginMsgToHbFsm(
        hbFsm, type, wakeupFlag, msgPara, delayMillis);
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

bool LnnVisitHbTypeSet(VisitHbTypeCb callback, LnnHeartbeatType *typeSet, void *data)
{
    return HeartBeatFSMStrategyInterfaceInstance()->LnnVisitHbTypeSet(callback, typeSet, data);
}

LnnHeartbeatType LnnConvertConnAddrTypeToHbType(ConnectionAddrType addrType)
{
    return HeartBeatFSMStrategyInterfaceInstance()->LnnConvertConnAddrTypeToHbType(addrType);
}

int32_t LnnConvertHbTypeToId(LnnHeartbeatType type)
{
    return HeartBeatFSMStrategyInterfaceInstance()->LnnConvertHbTypeToId(type);
}

bool LnnIsSupportBurstFeature(const char *networkId)
{
    return HeartBeatFSMStrategyInterfaceInstance()->LnnIsSupportBurstFeature(networkId);
}

int32_t LnnPostSetMediumParamMsgToHbFsm(LnnHeartbeatFsm *hbFsm, const LnnHeartbeatMediumParam *para)
{
    return HeartBeatFSMStrategyInterfaceInstance()->LnnPostSetMediumParamMsgToHbFsm(hbFsm, para);
}

int32_t LnnPostCheckDevStatusMsgToHbFsm(
    LnnHeartbeatFsm *hbFsm, const LnnCheckDevStatusMsgPara *para, uint64_t delayMillis)
{
    return HeartBeatFSMStrategyInterfaceInstance()->LnnPostCheckDevStatusMsgToHbFsm(hbFsm, para, delayMillis);
}

int32_t LnnPostScreenOffCheckDevMsgToHbFsm(
    LnnHeartbeatFsm *hbFsm, const LnnCheckDevStatusMsgPara *para, uint64_t delayMillis)
{
    return HeartBeatFSMStrategyInterfaceInstance()->LnnPostScreenOffCheckDevMsgToHbFsm(hbFsm, para, delayMillis);
}

LnnHeartbeatFsm *LnnCreateHeartbeatFsm(void)
{
    return HeartBeatFSMStrategyInterfaceInstance()->LnnCreateHeartbeatFsm();
}

int32_t LnnStartHeartbeatFsm(LnnHeartbeatFsm *hbFsm)
{
    return HeartBeatFSMStrategyInterfaceInstance()->LnnStartHeartbeatFsm(hbFsm);
}

void LnnRemoveScreenOffCheckStatusMsg(LnnHeartbeatFsm *hbFsm, LnnCheckDevStatusMsgPara *msgPara)
{
    return HeartBeatFSMStrategyInterfaceInstance()->LnnRemoveScreenOffCheckStatusMsg(hbFsm, msgPara);
}

void LnnRemoveCheckDevStatusMsg(LnnHeartbeatFsm *hbFsm, LnnCheckDevStatusMsgPara *msgPara)
{
    return HeartBeatFSMStrategyInterfaceInstance()->LnnRemoveCheckDevStatusMsg(hbFsm, msgPara);
}

int32_t LnnPostStopMsgToHbFsm(LnnHeartbeatFsm *hbFsm, LnnHeartbeatType type)
{
    return HeartBeatFSMStrategyInterfaceInstance()->LnnPostStopMsgToHbFsm(hbFsm, type);
}

int32_t LnnStopHeartbeatFsm(LnnHeartbeatFsm *hbFsm)
{
    return HeartBeatFSMStrategyInterfaceInstance()->LnnStopHeartbeatFsm(hbFsm);
}

void LnnRemoveSendEndMsg(LnnHeartbeatFsm *hbFsm, LnnHeartbeatType type, bool wakeupFlag, bool isRelay, bool *isRemoved)
{
    return HeartBeatFSMStrategyInterfaceInstance()->LnnRemoveSendEndMsg(hbFsm, type, wakeupFlag, isRelay, isRemoved);
}

int32_t LnnPostNextSendOnceMsgToHbFsm(
    LnnHeartbeatFsm *hbFsm, const LnnProcessSendOnceMsgPara *para, uint64_t delayMillis)
{
    return HeartBeatFSMStrategyInterfaceInstance()->LnnPostNextSendOnceMsgToHbFsm(hbFsm, para, delayMillis);
}

void LnnRemoveProcessSendOnceMsg(LnnHeartbeatFsm *hbFsm, LnnHeartbeatType hbType, LnnHeartbeatStrategyType strategyType)
{
    return HeartBeatFSMStrategyInterfaceInstance()->LnnRemoveProcessSendOnceMsg(hbFsm, hbType, strategyType);
}

void LnnHbClearRecvList(void)
{
    return HeartBeatFSMStrategyInterfaceInstance()->LnnHbClearRecvList();
}

int32_t LnnFsmRemoveMessage(FsmStateMachine *fsm, int32_t msgType)
{
    return HeartBeatFSMStrategyInterfaceInstance()->LnnFsmRemoveMessage(fsm, msgType);
}

int32_t LnnGetLocalNumU64Info(InfoKey key, uint64_t *info)
{
    return HeartBeatFSMStrategyInterfaceInstance()->LnnGetLocalNumU64Info(key, info);
}

int32_t LnnGetRemoteNumU64Info(const char *networkId, InfoKey key, uint64_t *info)
{
    return HeartBeatFSMStrategyInterfaceInstance()->LnnGetRemoteNumU64Info(networkId, key, info);
}

bool IsFeatureSupport(uint64_t feature, FeatureCapability capaBit)
{
    return HeartBeatFSMStrategyInterfaceInstance()->IsFeatureSupport(feature, capaBit);
}

uint32_t GenerateRandomNumForHb(uint32_t randMin, uint32_t randMax)
{
    return HeartBeatFSMStrategyInterfaceInstance()->GenerateRandomNumForHb(randMin, randMax);
}

bool LnnIsMultiDeviceOnline(void)
{
    return HeartBeatFSMStrategyInterfaceInstance()->LnnIsMultiDeviceOnline();
}
}
} // namespace OHOS
