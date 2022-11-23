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
#ifndef MANAGER_MOCK_H
#define MANAGER_MOCK_H

#include <atomic>
#include <mutex>
#include <gmock/gmock.h>
#include "p2plink_loop.h"
#include "p2plink_manager.h"
#include "p2plink_device.h"
#include "p2plink_common.h"
#include "p2plink_negotiation.h"

class ManagerInterface {
public:
    virtual void P2pLinkLoopConnectDevice(P2pLoopMsg msgType, void *arg) = 0;
    virtual void P2pLinkLoopDisconnectDev(P2pLoopMsg msgType, void *arg) = 0;
    virtual int32_t P2pLinkManagerInit(void) = 0;
    virtual void P2pLinkSetDevStateCallback(const P2pLinkPeerDevStateCb *cb) = 0;
    virtual char* P2pLinkGetMyIp(void) = 0;
    virtual bool P2pLinkIsEnable(void) = 0;
    virtual ConnectedNode *P2pLinkGetConnedDevByMac(const char *peerMac) = 0;
    virtual P2pLinkRole P2pLinkGetRole(void) = 0;
    virtual int32_t P2pLinkNegoGetFinalRole(int32_t peerRole, int32_t peerExpectRole, const char *peerGoMac,
                                            bool isSupportBridge) = 0;
    virtual ConnectedNode *P2pLinkGetConnedDevByPeerIp(const char *peerIp) = 0;
};

class ManagerMock : public ManagerInterface {
public:
    static ManagerMock* GetMock()
    {
        return mock.load();
    }

    ManagerMock();
    ~ManagerMock();

    void SetupSuccessStub();

    MOCK_METHOD(void, P2pLinkLoopConnectDevice, (P2pLoopMsg msgType, void *arg), (override));
    static void ActionOfP2pLinkLoopConnectDevice(P2pLoopMsg msgType, void *arg);

    MOCK_METHOD(int32_t, P2pLinkManagerInit, (), (override));
    static int32_t ActionOfP2pLinkManagerInit();

    MOCK_METHOD(void, P2pLinkLoopDisconnectDev, (P2pLoopMsg msgType, void *arg), (override));
    static void ActionOfP2pLinkLoopDisconnectDev(P2pLoopMsg msgType, void *arg);

    MOCK_METHOD(void, P2pLinkSetDevStateCallback, (const P2pLinkPeerDevStateCb *cb), (override));
    static void ActionOfP2pLinkSetDevStateCallback(const P2pLinkPeerDevStateCb *cb);

    MOCK_METHOD(char*, P2pLinkGetMyIp, (), (override));
    static char* ActionOfP2pLinkGetMyIp();

    MOCK_METHOD(bool, P2pLinkIsEnable, (), (override));
    static bool ActionOfP2pLinkIsEnable();

    MOCK_METHOD(ConnectedNode*, P2pLinkGetConnedDevByMac, (const char *peerMac), (override));
    static ConnectedNode* ActionOfP2pLinkGetConnedDevByMac(const char *peerMac);

    MOCK_METHOD(P2pLinkRole, P2pLinkGetRole, (), (override));
    static P2pLinkRole ActionOfP2pLinkGetRole();

    MOCK_METHOD(int32_t, P2pLinkNegoGetFinalRole, (int32_t peerRole, int32_t peerExpectRole, const char *peerGoMac,
                                                   bool isSupportBridge), (override));
    static int32_t ActionOfP2pLinkNegoGetFinalRole(int32_t peerRole, int32_t peerExpectRole, const char *peerGoMac,
                                                   bool isSupportBridge);

    MOCK_METHOD(ConnectedNode*, P2pLinkGetConnedDevByPeerIp, (const char *peerIp), (override));
    static ConnectedNode* ActionOfP2pLinkGetConnedDevByPeerIp(const char *peerIp);

    static inline const P2pLinkPeerDevStateCb *p2pLinkPeerDevStateCb {};
    static inline char g_myIp[P2P_IP_LEN] = {0};
    static inline ConnectedNode g_connectedNode {};
private:
    static inline std::atomic<ManagerMock*> mock = nullptr;
};
#endif