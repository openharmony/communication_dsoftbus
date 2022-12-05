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
#include "manager_mock.h"
#include <atomic>
#include "softbus_log.h"
#include "softbus_error_code.h"
#include "p2plink_device.h"

/* implement related global function of manager */
void P2pLinkLoopConnectDevice(P2pLoopMsg msgType, void *arg)
{
    return ManagerMock::GetMock()->P2pLinkLoopConnectDevice(msgType, arg);
}

void P2pLinkLoopDisconnectDev(P2pLoopMsg msgType, void *arg)
{
    return ManagerMock::GetMock()->P2pLinkLoopDisconnectDev(msgType, arg);
}

int32_t P2pLinkManagerInit(void)
{
    return ManagerMock::GetMock()->P2pLinkManagerInit();
}

void P2pLinkSetDevStateCallback(const P2pLinkPeerDevStateCb *cb)
{
    return ManagerMock::GetMock()->P2pLinkSetDevStateCallback(cb);
}

char* P2pLinkGetMyIp(void)
{
    return ManagerMock::GetMock()->P2pLinkGetMyIp();
}

bool P2pLinkIsEnable(void)
{
    return ManagerMock::GetMock()->P2pLinkIsEnable();
}

ConnectedNode *P2pLinkGetConnedDevByMac(const char *peerMac)
{
    return ManagerMock::GetMock()->P2pLinkGetConnedDevByMac(peerMac);
}

P2pLinkRole P2pLinkGetRole(void)
{
    return ManagerMock::GetMock()->P2pLinkGetRole();
}

int32_t P2pLinkNegoGetFinalRole(int32_t peerRole, int32_t peerExpectRole, const char *peerGoMac, bool isSupportBridge)
{
    return ManagerMock::GetMock()->P2pLinkNegoGetFinalRole(peerRole, peerExpectRole, peerGoMac, isSupportBridge);
}

ConnectedNode *P2pLinkGetConnedDevByPeerIp(const char *peerIp)
{
    return ManagerMock::GetMock()->P2pLinkGetConnedDevByPeerIp(peerIp);
}

/* definition for class ManagerMock */
ManagerMock::ManagerMock()
{
    mock.store(this);
}

ManagerMock::~ManagerMock()
{
    mock.store(nullptr);
}

void ManagerMock::ActionOfP2pLinkLoopConnectDevice(P2pLoopMsg msgType, void *arg)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "ActionOfP2pLinkLoopConnectDevice Start");
}

void ManagerMock::ActionOfP2pLinkLoopDisconnectDev(P2pLoopMsg msgType, void *arg)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "ActionOfP2pLinkLoopDisconnectDev Start");
}

int32_t ManagerMock::ActionOfP2pLinkManagerInit()
{
    return SOFTBUS_OK;
}

void ManagerMock::ActionOfP2pLinkSetDevStateCallback(const P2pLinkPeerDevStateCb *cb)
{
    p2pLinkPeerDevStateCb = cb;
}

char* ManagerMock::ActionOfP2pLinkGetMyIp()
{
    return g_myIp;
}

bool ManagerMock::ActionOfP2pLinkIsEnable()
{
    return true;
}

ConnectedNode* ManagerMock::ActionOfP2pLinkGetConnedDevByMac(const char *peerMac)
{
    return &g_connectedNode;
}

P2pLinkRole ManagerMock::ActionOfP2pLinkGetRole()
{
    return ROLE_GO;
}

int32_t ManagerMock::ActionOfP2pLinkNegoGetFinalRole(int32_t peerRole, int32_t peerExpectRole, const char *peerGoMac,
                                                     bool isSupportBridge)
{
    return ROLE_GO;
}

ConnectedNode* ManagerMock::ActionOfP2pLinkGetConnedDevByPeerIp(const char *peerIp)
{
    return &g_connectedNode;
}

void ManagerMock::SetupSuccessStub()
{
    EXPECT_CALL(*this, P2pLinkLoopConnectDevice).WillRepeatedly(ManagerMock::ActionOfP2pLinkLoopConnectDevice);
    EXPECT_CALL(*this, P2pLinkManagerInit).WillRepeatedly(ManagerMock::ActionOfP2pLinkManagerInit);
    EXPECT_CALL(*this, P2pLinkLoopDisconnectDev).WillRepeatedly(ManagerMock::ActionOfP2pLinkLoopDisconnectDev);
    EXPECT_CALL(*this, P2pLinkSetDevStateCallback).WillRepeatedly(ManagerMock::ActionOfP2pLinkSetDevStateCallback);
    EXPECT_CALL(*this, P2pLinkGetMyIp).WillRepeatedly(ManagerMock::ActionOfP2pLinkGetMyIp);
    EXPECT_CALL(*this, P2pLinkIsEnable).WillRepeatedly(ManagerMock::ActionOfP2pLinkIsEnable);
    EXPECT_CALL(*this, P2pLinkGetConnedDevByMac).WillRepeatedly(ManagerMock::ActionOfP2pLinkGetConnedDevByMac);
    EXPECT_CALL(*this, P2pLinkGetRole).WillRepeatedly(ManagerMock::ActionOfP2pLinkGetRole);
    EXPECT_CALL(*this, P2pLinkNegoGetFinalRole).WillRepeatedly(ManagerMock::ActionOfP2pLinkNegoGetFinalRole);
    EXPECT_CALL(*this, P2pLinkGetConnedDevByPeerIp).WillRepeatedly(ManagerMock::ActionOfP2pLinkGetConnedDevByPeerIp);
}