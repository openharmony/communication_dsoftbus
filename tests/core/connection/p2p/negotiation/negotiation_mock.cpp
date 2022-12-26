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
#include <atomic>
#include "negotiation_mock.h"
#include "softbus_error_code.h"
#include "p2plink_device.h"

/* implement related global function of Adapter */
bool P2pLinkIsEnable()
{
    return NegotiationMock::GetMock()->P2pLinkIsEnable();
}

bool GetJsonObjectStringItem(const cJSON *json, const char * const string, char *target,
                             uint32_t targetLen)
{
    return NegotiationMock::GetMock()->GetJsonObjectStringItem(json, string, target, targetLen);
}

bool P2pLinkIsDisconnectState()
{
    return NegotiationMock::GetMock()->P2pLinkIsDisconnectState();
}

void P2pLinkFsmMsgProc(const FsmStateMachine *fsm, int32_t msgType, void *param)
{
    return NegotiationMock::GetMock()->P2pLinkFsmMsgProc(fsm, msgType, param);
}

bool GetJsonObjectNumberItem(const cJSON *json, const char * const string, int *target)
{
    return NegotiationMock::GetMock()->GetJsonObjectNumberItem(json, string, target);
}

int32_t P2plinkUnpackRepsonseMsg(const cJSON *data, P2pContentType type, P2pRespMsg *response)
{
    return NegotiationMock::GetMock()->P2plinkUnpackRepsonseMsg(data, type, response);
}

void P2pLinkFsmTransactState(FsmStateMachine *fsm, FsmState *state)
{
    return NegotiationMock::GetMock()->P2pLinkFsmTransactState(fsm, state);
}

void P2pLinkFsmMsgProcDelayDel(int32_t msgType)
{
    return NegotiationMock::GetMock()->P2pLinkFsmMsgProcDelayDel(msgType);
}

int32_t P2pLinkSetPeerWifiCfgInfo(const char *cfgData)
{
    return NegotiationMock::GetMock()->P2pLinkSetPeerWifiCfgInfo(cfgData);
}

void P2pLinkRemoveGroup()
{
    return NegotiationMock::GetMock()->P2pLinkRemoveGroup();
}

bool P2pLinkGetDhcpState()
{
    return NegotiationMock::GetMock()->P2pLinkGetDhcpState();
}

void P2pLinkFsmMsgProcDelay(const FsmStateMachine *fsm, int32_t msgType, void *param,
                            uint64_t delayMs)
{
    return NegotiationMock::GetMock()->P2pLinkFsmMsgProcDelay(fsm, msgType, param, delayMs);
}

/* definition for class AdapterMock */
NegotiationMock::NegotiationMock()
{
    mock.store(this);
}

NegotiationMock::~NegotiationMock()
{
    mock.store(nullptr);
}

void NegotiationMock::ActionOfP2pLinkFsmMsgProc(const FsmStateMachine *fsm, int32_t msgType, void *param)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "ActionOfP2pLinkFsmMsgProc Start");
}

bool NegotiationMock::ActionOfGetJsonObjectStringItem(const cJSON *json, const char * const string, char *target,
                                                      uint32_t targetLen)
{
    return true;
}

bool NegotiationMock::ActionOfGetJsonObjectNumberItem(const cJSON *json, const char * const string, int *target)
{
    *target = CONTENT_TYPE_GO_INFO;
    return true;
}

void NegotiationMock::ActionOfP2pLinkFsmTransactState(FsmStateMachine *fsm, FsmState *state)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "ActionOfP2pLinkFsmTransactState Start");
}

void NegotiationMock::ActionOfP2pLinkFsmMsgProcDelayDel(int32_t msgType)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "ActionOfP2pLinkFsmMsgProcDelayDel Start");
}

int32_t NegotiationMock::ActionOfP2pLinkSetPeerWifiCfgInfo(const char *cfgData)
{
    return SOFTBUS_OK;
}

void NegotiationMock::ActionOfP2pLinkRemoveGroup()
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "ActionOfP2pLinkRemoveGroup Start");
}

bool NegotiationMock::ActionOfP2pLinkGetDhcpState()
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "ActionOfP2pLinkGetDhcpState Start");
    return true;
}

void NegotiationMock::ActionOfP2pLinkFsmMsgProcDelay(const FsmStateMachine *fsm, int32_t msgType, void *param,
                            uint64_t delayMs)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "ActionOfP2pLinkFsmMsgProcDelay Start");
}

void NegotiationMock::SetupSuccessStub()
{
    EXPECT_CALL(*this, P2pLinkFsmMsgProc).WillRepeatedly(NegotiationMock::ActionOfP2pLinkFsmMsgProc);
    EXPECT_CALL(*this, GetJsonObjectStringItem).WillRepeatedly(NegotiationMock::ActionOfGetJsonObjectStringItem);
    EXPECT_CALL(*this, GetJsonObjectNumberItem).WillRepeatedly(NegotiationMock::ActionOfGetJsonObjectNumberItem);
    EXPECT_CALL(*this, P2pLinkFsmTransactState).WillRepeatedly(NegotiationMock::ActionOfP2pLinkFsmTransactState);
    EXPECT_CALL(*this, P2pLinkFsmMsgProcDelayDel).WillRepeatedly(NegotiationMock::ActionOfP2pLinkFsmMsgProcDelayDel);
    EXPECT_CALL(*this, P2pLinkSetPeerWifiCfgInfo).WillRepeatedly(NegotiationMock::ActionOfP2pLinkSetPeerWifiCfgInfo);
    EXPECT_CALL(*this, P2pLinkRemoveGroup).WillRepeatedly(NegotiationMock::ActionOfP2pLinkRemoveGroup);
    EXPECT_CALL(*this, P2pLinkGetDhcpState).WillRepeatedly(NegotiationMock::ActionOfP2pLinkGetDhcpState);
    EXPECT_CALL(*this, P2pLinkFsmMsgProcDelay).WillRepeatedly(NegotiationMock::ActionOfP2pLinkFsmMsgProcDelay);
}