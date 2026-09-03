/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "lnn_heartbeat_fsm.h"
#include "lnn_log.h"
#include "softbus_error_code.h"

int32_t LnnStartHeartbeatFsm(LnnHeartbeatFsm *hbFsm)
{
    (void)hbFsm;

    return SOFTBUS_OK;
}

int32_t LnnStopHeartbeatFsm(LnnHeartbeatFsm *hbFsm)
{
    (void)hbFsm;

    return SOFTBUS_OK;
}

int32_t LnnPostNextSendOnceMsgToHbFsm(
    LnnHeartbeatFsm *hbFsm, const LnnProcessSendOnceMsgPara *para, uint64_t delayMillis)
{
    (void)hbFsm;
    (void)para;
    (void)delayMillis;

    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnPostSendBeginMsgToHbFsm(LnnHeartbeatFsm *hbFsm, LnnHeartbeatType type, bool wakeupFlag,
    LnnProcessSendOnceMsgPara *msgPara, uint64_t delayMillis)
{
    (void)hbFsm;
    (void)type;
    (void)wakeupFlag;
    (void)msgPara;
    (void)delayMillis;

    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnPostSendEndMsgToHbFsm(LnnHeartbeatFsm *hbFsm, LnnHeartbeatSendEndData *custData, uint64_t delayMillis)
{
    (void)hbFsm;
    (void)custData;
    (void)delayMillis;

    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnPostStartMsgToHbFsm(LnnHeartbeatFsm *hbFsm, uint64_t delayMillis)
{
    (void)hbFsm;
    (void)delayMillis;

    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnPostStopMsgToHbFsm(LnnHeartbeatFsm *hbFsm, LnnHeartbeatType type)
{
    (void)hbFsm;
    (void)type;

    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnPostTransStateMsgToHbFsm(LnnHeartbeatFsm *hbFsm, LnnHeartbeatEventType evtType)
{
    (void)hbFsm;
    (void)evtType;

    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnPostSetMediumParamMsgToHbFsm(LnnHeartbeatFsm *hbFsm, const LnnHeartbeatMediumParam *para)
{
    (void)hbFsm;
    (void)para;

    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnPostCheckDevStatusMsgToHbFsm(
    LnnHeartbeatFsm *hbFsm, const LnnCheckDevStatusMsgPara *para, uint64_t delayMillis)
{
    (void)hbFsm;
    (void)para;
    (void)delayMillis;

    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnPostUpdateSendInfoMsgToHbFsm(LnnHeartbeatFsm *hbFsm, LnnHeartbeatUpdateInfoType type)
{
    (void)hbFsm;
    (void)type;

    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnPostScreenOffCheckDevMsgToHbFsm(
    LnnHeartbeatFsm *hbFsm, const LnnCheckDevStatusMsgPara *para, uint64_t delayMillis)
{
    (void)hbFsm;
    (void)para;
    (void)delayMillis;

    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnPostSleCheckDevStatusMsgToHbFsm(
    LnnHeartbeatFsm *hbFsm, const LnnCheckDevStatusMsgPara *para, uint64_t delayMillis)
{
    (void)hbFsm;
    (void)para;
    (void)delayMillis;

    return SOFTBUS_NOT_IMPLEMENT;
}

void LnnRemoveSendEndMsg(LnnHeartbeatFsm *hbFsm, LnnProcessSendOnceMsgPara *msg, bool wakeupFlag, bool *isRemoved)
{
    (void)hbFsm;
    (void)msg;
    (void)wakeupFlag;
    if (isRemoved != NULL) {
        *isRemoved = false;
    }
}

void LnnRemoveCheckDevStatusMsg(LnnHeartbeatFsm *hbFsm, LnnCheckDevStatusMsgPara *msgPara)
{
    (void)hbFsm;
    (void)msgPara;
}

void LnnRemoveScreenOffCheckStatusMsg(LnnHeartbeatFsm *hbFsm, LnnCheckDevStatusMsgPara *msgPara)
{
    (void)hbFsm;
    (void)msgPara;
}

void LnnRemoveProcessSendOnceMsg(
    LnnHeartbeatFsm *hbFsm, LnnHeartbeatType hbType, LnnHeartbeatStrategyType strategyType)
{
    (void)hbFsm;
    (void)hbType;
    (void)strategyType;
}

void LnnRemoveSleCheckStatusMsg(LnnHeartbeatFsm *hbFsm, LnnCheckDevStatusMsgPara *msgPara)
{
    (void)hbFsm;
    (void)msgPara;
}

LnnHeartbeatFsm *LnnCreateHeartbeatFsm(void)
{
    return NULL;
}

void LnnDestroyHeartbeatFsm(LnnHeartbeatFsm *hbFsm)
{
    (void)hbFsm;
}
