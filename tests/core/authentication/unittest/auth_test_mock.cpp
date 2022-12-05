/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "auth_common.h"
#include "auth_hichain.h"
#include "auth_interface.h"
#include "auth_manager.h"
#include "auth_net_ledger_mock.h"
#include "auth_request.h"
#include "lnn_connection_mock.h"
#include "lnn_hichain_mock.h"
#include "lnn_socket_mock.h"
#include "message_handler.h"
#include "softbus_access_token_test.h"
#include "softbus_adapter_mem.h"
#include "softbus_errcode.h"
#include "softbus_feature_config.h"
#include "softbus_log.h"
#include <cinttypes>
#include <gtest/gtest.h>
#include <securec.h>
#include <sys/time.h>

namespace OHOS {
using namespace testing;
using namespace testing::ext;

uint64_t g_connectionId = 8590065691;
uint32_t g_requestId = 88;
int64_t g_seqServer = 3;
ConnModule moduleId = MODULE_DEVICE_AUTH;
uint8_t g_devInfo[5] = { 0x10, 0x2, 0x14, 0x08, 0x06 };
uint8_t g_sessionKey[SESSION_KEY_LENGTH];
int32_t g_len = 200;
int g_operationCode = 0;
static const int MILLIS = 15;
const char *g_returnData = nullptr;
static const char TESTMAC[MAC_LEN] = "11:22:33:44:55:66";
const AuthConnInfo connInfo = {
    .type = AUTH_LINK_TYPE_BR,
    .info.brInfo.brMac = "11:22:33:44:55:66",
    .peerUid = "002",
};
const AuthVerifyCallback callBack = {
    .onVerifyPassed = LnnConnectInterfaceMock::OnVerifyPassed,
    .onVerifyFailed = LnnConnectInterfaceMock::onVerifyFailed,
};
const AuthSessionInfo info = {
    .isServer = true,
    .connInfo = connInfo,
};

NodeInfo nodeInfo;
struct MockInterfaces {
    LnnConnectInterfaceMock *connMock;
    LnnHichainInterfaceMock *hichainMock;
    AuthNetLedgertInterfaceMock *ledgermock;
    LnnSocketInterfaceMock *socketMock;
};
AuthDataHead devIdHead = {
    .dataType = DATA_TYPE_DEVICE_ID,
    .module = MODULE_DEVICE_AUTH,
    .seq = g_seqServer,
    .flag = SERVER_SIDE_FLAG,
};
AuthDataHead devAuthHead = {
    .dataType = DATA_TYPE_AUTH,
    .module = MODULE_DEVICE_AUTH,
    .seq = g_seqServer,
    .flag = SERVER_SIDE_FLAG,
};
AuthDataHead devInfoAuthHead = {
    .dataType = DATA_TYPE_DEVICE_INFO,
    .module = MODULE_DEVICE_AUTH,
    .seq = g_seqServer,
    .flag = SERVER_SIDE_FLAG,
};
AuthDataHead closeAckHead = {
    .dataType = DATA_TYPE_CLOSE_ACK,
    .module = MODULE_DEVICE_AUTH,
    .seq = g_seqServer,
    .flag = SERVER_SIDE_FLAG,
};
AuthVerifyListener listener = {
    .onDeviceVerifyPass = &AuthNetLedgertInterfaceMock::OnDeviceVerifyPass,
    .onDeviceNotTrusted = &AuthNetLedgertInterfaceMock::OnDeviceNotTrusted,
    .onDeviceDisconnect = &AuthNetLedgertInterfaceMock::OnDeviceDisconnect,
};
LocalNetLedger g_localNetLedger = {
    .localInfo = nodeInfo,
    .lock = AuthNetLedgertInterfaceMock::mutex,
    .status = LL_INIT_SUCCESS,
};

void SendSignal()
{
    ALOGI("SendSignal");
    if (SoftBusMutexLock(&LnnHichainInterfaceMock::mutex) != SOFTBUS_OK) {
        ALOGE("SendSignal Lock failed");
        return;
    }
    AuthNetLedgertInterfaceMock::gFLAG = true;
    SoftBusCondSignal(&LnnHichainInterfaceMock::cond);
    SoftBusMutexUnlock(&LnnHichainInterfaceMock::mutex);
    ALOGI("SendSignal end");
}

void ClientFSMCreate(MockInterfaces *mockInterface, GroupAuthManager &authManager, DeviceGroupManager &groupManager)
{
    int64_t authSeq = 3;
    uint64_t connId = 8590065691;
    AuthConnInfo connInfo = {
        .type = AUTH_LINK_TYPE_BR,
        .info.brInfo.brMac = "11:22:33:44:55:66",
        .peerUid = "001",
    };
    bool isServer = false;
    (void)memset_s(&nodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    ON_CALL(*mockInterface->connMock, ConnConnectDevice(_, _, _)).WillByDefault(Return(SOFTBUS_OK));
    groupManager.regDataChangeListener = LnnHichainInterfaceMock::InvokeDataChangeListener;
    groupManager.unRegDataChangeListener = LnnHichainInterfaceMock::ActionofunRegDataChangeListener;
    authManager.authDevice = LnnHichainInterfaceMock::InvokeAuthDevice;
    ON_CALL(*mockInterface->connMock, ConnSetConnectCallback(_, _))
        .WillByDefault(LnnConnectInterfaceMock::ActionofConnSetConnectCallback);
    ON_CALL(*mockInterface->connMock, ConnGetHeadSize()).WillByDefault(Return(sizeof(ConnPktHead)));
    ON_CALL(*mockInterface->hichainMock, InitDeviceAuthService()).WillByDefault(Return(0));
    ON_CALL(*mockInterface->hichainMock, GetGaInstance()).WillByDefault(Return(&authManager));
    ON_CALL(*mockInterface->hichainMock, GetGmInstance()).WillByDefault(Return(&groupManager));
    ON_CALL(*mockInterface->ledgermock, LnnGetLocalStrInfo).WillByDefault(Return(SOFTBUS_OK));
    int32_t ret = AuthInit();
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ON_CALL(*mockInterface->connMock, ConnPostBytes).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(*mockInterface->socketMock, ConnOpenClientSocket(_, _, _)).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(*mockInterface->connMock, ConnGetConnectionInfo)
        .WillByDefault(LnnConnectInterfaceMock::ActionofConnGetConnectionInfo);
    ON_CALL(*mockInterface->ledgermock, LnnGetLocalNodeInfo).WillByDefault(Return(&g_localNetLedger.localInfo));
    ON_CALL(*mockInterface->ledgermock, LnnGetBtMac).WillByDefault(Return(TESTMAC));
    const unsigned char val = 0x01;
    SoftbusSetConfig(SOFTBUS_INT_AUTH_ABILITY_COLLECTION, &val, sizeof(val));
    ret = AuthStartVerify(&connInfo, g_requestId, &callBack);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    AuthSessionStartAuth(authSeq, g_requestId, connId, &connInfo, isServer);
    SoftBusSleepMs(MILLIS);
}

bool WaitForSignal()
{
#define USECTONSEC 1000LL
    SoftBusSysTime now;
    if (SoftBusGetTime(&now) != SOFTBUS_OK) {
        ALOGE("BrSoftBusCondWait SoftBusGetTime failed");
        return SOFTBUS_ERR;
    }
    int64_t time = now.sec * USECTONSEC * USECTONSEC + now.usec + MILLIS * USECTONSEC;
    SoftBusSysTime tv;
    tv.sec = time / USECTONSEC / USECTONSEC;
    tv.usec = time % (USECTONSEC * USECTONSEC);
    if (!AuthNetLedgertInterfaceMock::gFLAG) {
        int ret = SoftBusCondWait(&LnnHichainInterfaceMock::cond, &LnnHichainInterfaceMock::mutex, &tv);
        (void)SoftBusMutexUnlock(&LnnHichainInterfaceMock::mutex);
        return (ret == SOFTBUS_OK);
    } else {
        SoftBusSleepMs(MILLIS);
        AuthNetLedgertInterfaceMock::gFLAG = false;
    }
    return true;
}

NodeInfo CreateInfo(NodeInfo &nodeInfo)
{
    return nodeInfo;
}

class AuthTestCallBack : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void AuthTestCallBack::SetUpTestCase()
{
    AuthNetLedgertInterfaceMock::gFLAG = false;
    RegAuthVerifyListener(&listener);
    (void)SoftBusMutexInit(&LnnHichainInterfaceMock::mutex, nullptr);
    SoftBusCondInit(&LnnHichainInterfaceMock::cond);
}

void AuthTestCallBack::TearDownTestCase()
{
    AuthNetLedgertInterfaceMock::gFLAG = false;
    SoftBusCondDestroy(&LnnHichainInterfaceMock::cond);
    SoftBusMutexDestroy(&LnnHichainInterfaceMock::mutex);
}

void AuthTestCallBack::SetUp()
{
    LooperInit();
    ALOGI("AuthTestCallBack start.");
}

void AuthTestCallBack::TearDown()
{
    LooperDeinit();
}

/*
 * @tc.name: ON_DATA_RECEVIED_Test_001
 * @tc.desc: client devicedid received
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTestCallBack, CLINET_ON_DATA_RECEVIED_Test_001, TestSize.Level1)
{
    GroupAuthManager authManager;
    DeviceGroupManager groupManager;
    NiceMock<LnnConnectInterfaceMock> connMock;
    NiceMock<LnnHichainInterfaceMock> hichainMock;
    NiceMock<AuthNetLedgertInterfaceMock> ledgermock;
    NiceMock<LnnSocketInterfaceMock> socketMock;
    MockInterfaces mockInterface = {
        .connMock = &connMock,
        .hichainMock = &hichainMock,
        .ledgermock = &ledgermock,
        .socketMock = &socketMock,
    };
    ClientFSMCreate(&mockInterface, authManager, groupManager);
    authManager.authDevice = LnnHichainInterfaceMock::AuthDeviceConnSend;
    char *data = AuthNetLedgertInterfaceMock::Pack(g_seqServer, &info, devIdHead);
    LnnConnectInterfaceMock::g_conncallback.OnDataReceived(g_connectionId, moduleId, g_seqServer, data, g_len);
    (void)SoftBusMutexLock(&LnnHichainInterfaceMock::mutex);
    int ret = SoftBusCondWait(&LnnHichainInterfaceMock::cond, &LnnHichainInterfaceMock::mutex, nullptr);
    (void)SoftBusMutexUnlock(&LnnHichainInterfaceMock::mutex);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    SoftBusFree(data);
    AuthDeviceDeinit();
}

/*
 * @tc.name: onTransmit
 * @tc.desc: client hichain transmit
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTestCallBack, onTransmit_Test_001, TestSize.Level1)
{
    GroupAuthManager authManager;
    DeviceGroupManager groupManager;
    NiceMock<LnnConnectInterfaceMock> connMock;
    NiceMock<LnnHichainInterfaceMock> hichainMock;
    NiceMock<AuthNetLedgertInterfaceMock> ledgermock;
    NiceMock<LnnSocketInterfaceMock> socketMock;
    MockInterfaces mockInterface = {
        .connMock = &connMock,
        .hichainMock = &hichainMock,
        .ledgermock = &ledgermock,
        .socketMock = &socketMock,
    };
    ClientFSMCreate(&mockInterface, authManager, groupManager);
    WaitForSignal();
    char *data = AuthNetLedgertInterfaceMock::Pack(g_seqServer, &info, devIdHead);
    LnnConnectInterfaceMock::g_conncallback.OnDataReceived(g_connectionId, moduleId, g_seqServer, data, g_len);
    authManager.processData = LnnHichainInterfaceMock::ActionOfProcessData;
    WaitForSignal();
    HichainProcessData(g_seqServer, g_devInfo, g_len);
    EXPECT_CALL(connMock, ConnPostBytes).WillRepeatedly(DoAll(SendSignal, Return(SOFTBUS_OK)));
    LnnHichainInterfaceMock::g_devAuthCb.onTransmit(g_seqServer, g_devInfo, g_len);
    if (AuthNetLedgertInterfaceMock::gFLAG == false) {
        bool ret = WaitForSignal();
        EXPECT_TRUE(ret);
    }
    EXPECT_TRUE(AuthNetLedgertInterfaceMock::gFLAG == true);
    SoftBusFree(data);
    AuthDeviceDeinit();
}

/*
 * @tc.name: OnFinish_Test_001
 * @tc.desc: client finished callback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTestCallBack, OnFinish_Test_001, TestSize.Level1)
{
    GroupAuthManager authManager;
    DeviceGroupManager groupManager;
    NiceMock<LnnConnectInterfaceMock> connMock;
    NiceMock<LnnHichainInterfaceMock> hichainMock;
    NiceMock<AuthNetLedgertInterfaceMock> ledgermock;
    NiceMock<LnnSocketInterfaceMock> socketMock;
    MockInterfaces mockInterface = {
        .connMock = &connMock,
        .hichainMock = &hichainMock,
        .ledgermock = &ledgermock,
        .socketMock = &socketMock,
    };
    ClientFSMCreate(&mockInterface, authManager, groupManager);
    WaitForSignal();
    char *data = AuthNetLedgertInterfaceMock::Pack(g_seqServer, &info, devIdHead);
    LnnConnectInterfaceMock::g_conncallback.OnDataReceived(g_connectionId, moduleId, g_seqServer, data, g_len);
    authManager.processData = LnnHichainInterfaceMock::ActionOfProcessData;
    HichainProcessData(g_seqServer, g_devInfo, g_len);
    WaitForSignal();
    SoftBusFree(data);
    char *data2 = AuthNetLedgertInterfaceMock::Pack(g_seqServer, &info, devAuthHead);
    LnnConnectInterfaceMock::g_conncallback.OnDataReceived(g_connectionId, moduleId, g_seqServer, data2, g_len);
    WaitForSignal();
    SoftBusFree(data2);
    LnnHichainInterfaceMock::g_devAuthCb.onSessionKeyReturned(g_seqServer, g_sessionKey, SESSION_KEY_LENGTH);
    WaitForSignal();
    EXPECT_CALL(connMock, ConnPostBytes).WillRepeatedly(DoAll(SendSignal, Return(SOFTBUS_OK)));
    LnnHichainInterfaceMock::g_devAuthCb.onFinish(g_seqServer, g_operationCode, g_returnData);
    bool ret = WaitForSignal();
    EXPECT_TRUE(ret);
    char *data3 = AuthNetLedgertInterfaceMock::Pack(g_seqServer, &info, devInfoAuthHead);
    LnnConnectInterfaceMock::g_conncallback.OnDataReceived(g_connectionId, moduleId, g_seqServer, data3, g_len);
    WaitForSignal();
    SoftBusFree(data3);
    char *data4 = AuthNetLedgertInterfaceMock::Pack(g_seqServer, &info, closeAckHead);
    LnnConnectInterfaceMock::g_conncallback.OnDataReceived(g_connectionId, moduleId, g_seqServer, data4, g_len);
    ret = WaitForSignal();
    EXPECT_TRUE(ret);
    SoftBusFree(data4);
    AuthDeviceDeinit();
}
} // namespace OHOS