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

#include <cinttypes>
#include <gtest/gtest.h>
#include <securec.h>
#include <sys/time.h>

#include "auth_common.h"
#include "auth_common_mock.h"
#include "auth_hichain.h"
#include "auth_interface.h"
#include "auth_log.h"
#include "auth_manager.h"
#include "auth_net_ledger_mock.h"
#include "auth_request.h"
#include "auth_session_message.h"
#include "bus_center_adapter.h"
#include "lnn_connection_mock.h"
#include "lnn_hichain_mock.h"
#include "lnn_socket_mock.h"
#include "message_handler.h"
#include "softbus_access_token_test.h"
#include "softbus_adapter_bt_common.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"
#include "softbus_feature_config.h"

namespace OHOS {
using namespace testing;
using namespace testing::ext;
#define TEST_UDID         "123456ABCDEF"
#define TEST_UUID         "6984321642"
#define DEV_NAME          "DEVTEST"
#define TEST_MAC          "11:22:33:44:55:66"
#define TEST_NETWORKID    "ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00"
#define VERSION_TYPE_LITE "LITE"
static const uint32_t REQUEST_ID = 88;
static const bool TEST_IS_P2P = false;
static const int64_t SEQ_SERVER = 3;
static const int32_t TEST_P2P_ROLE = 1;
static const uint32_t TEST_NET_CAPACITY = 3;
static const uint16_t TEST_DATA_CHANGE_FLAG = 1;
static const uint64_t TEST_SUP_PROTOCOLS = 453213535465;
static const ConnModule MODULE_ID = MODULE_DEVICE_AUTH;
static const uint8_t DEVICE_INFO[5] = { 0x10, 0x2, 0x14, 0x08, 0x06 };
uint8_t g_sessionKey[SESSION_KEY_LENGTH];
static const int32_t TEST_DATA_LEN = 600;
static const int32_t OPER_CODE = 0;
static const int32_t DELAY_TIME = 15;
static const char *g_retData = nullptr;
static uint64_t g_connId = 8590065691;
const AuthConnInfo g_connInfo = {
    .type = AUTH_LINK_TYPE_BR,
    .info.brInfo.brMac = TEST_MAC,
    .peerUid = "002",
};
const AuthVerifyCallback callBack = {
    .onVerifyPassed = LnnConnectInterfaceMock::OnVerifyPassed,
    .onVerifyFailed = LnnConnectInterfaceMock::onVerifyFailed,
};
const AuthSessionInfo info = {
    .isServer = true,
    .connInfo = g_connInfo,
};
const AuthSessionInfo info2 = {
    .isServer = false,
    .connId = g_connId,
    .connInfo = g_connInfo,
};
struct MockInterfaces {
    LnnConnectInterfaceMock *connMock;
    LnnHichainInterfaceMock *hichainMock;
    AuthNetLedgertInterfaceMock *ledgerMock;
    LnnSocketInterfaceMock *socketMock;
    AuthCommonInterfaceMock *authMock;
};
AuthDataHead devIdHead = {
    .dataType = DATA_TYPE_DEVICE_ID,
    .module = MODULE_DEVICE_AUTH,
    .seq = SEQ_SERVER,
    .flag = SERVER_SIDE_FLAG,
};
AuthDataHead devAuthHead = {
    .dataType = DATA_TYPE_AUTH,
    .module = MODULE_DEVICE_AUTH,
    .seq = SEQ_SERVER,
    .flag = SERVER_SIDE_FLAG,
};
AuthDataHead devInfoAuthHead = {
    .dataType = DATA_TYPE_DEVICE_INFO,
    .module = MODULE_DEVICE_AUTH,
    .seq = SEQ_SERVER,
    .flag = SERVER_SIDE_FLAG,
};
AuthDataHead closeAckHead = {
    .dataType = DATA_TYPE_CLOSE_ACK,
    .module = MODULE_DEVICE_AUTH,
    .seq = SEQ_SERVER,
    .flag = SERVER_SIDE_FLAG,
};
AuthVerifyListener g_listener = {
    .onDeviceVerifyPass = &AuthNetLedgertInterfaceMock::OnDeviceVerifyPass,
    .onDeviceNotTrusted = &AuthNetLedgertInterfaceMock::OnDeviceNotTrusted,
    .onDeviceDisconnect = &AuthNetLedgertInterfaceMock::OnDeviceDisconnect,
};
NodeInfo g_localInfo = {
    .versionType = VERSION_TYPE_LITE,
    .uuid = TEST_UUID,
    .networkId = TEST_NETWORKID,
    .netCapacity = TEST_NET_CAPACITY,
    .isBleP2p = TEST_IS_P2P,
    .p2pInfo.p2pMac = TEST_MAC,
    .supportedProtocols = TEST_SUP_PROTOCOLS,
    .dataChangeFlag = TEST_DATA_CHANGE_FLAG,
};
void SendSignal()
{
    AUTH_LOGI(AUTH_TEST, "SendSignal");
    if (SoftBusMutexLock(&LnnHichainInterfaceMock::mutex) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_TEST, "SendSignal Lock failed");
        return;
    }
    AuthNetLedgertInterfaceMock::isRuned = true;
    (void)SoftBusCondSignal(&LnnHichainInterfaceMock::cond);
    (void)SoftBusMutexUnlock(&LnnHichainInterfaceMock::mutex);
    AUTH_LOGI(AUTH_TEST, "SendSignal end");
}

void ClientFSMCreate(MockInterfaces *mockInterface, GroupAuthManager &authManager, DeviceGroupManager &groupManager)
{
    bool isServer = false;
    memset_s(g_localInfo.offlineCode, OFFLINE_CODE_BYTE_SIZE, 0, OFFLINE_CODE_BYTE_SIZE);
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
    ON_CALL(*mockInterface->ledgerMock, LnnGetLocalStrInfo).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(*mockInterface->authMock, LnnAsyncCallbackDelayHelper(_, _, _, _)).WillByDefault(Return(SOFTBUS_OK));
    int32_t ret = AuthInit();
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ON_CALL(*mockInterface->connMock, ConnPostBytes).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(*mockInterface->socketMock, ConnOpenClientSocket(_, _, _)).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(*mockInterface->connMock, ConnGetConnectionInfo)
        .WillByDefault(LnnConnectInterfaceMock::ActionofConnGetConnectionInfo);
    ON_CALL(*mockInterface->ledgerMock, LnnGetDeviceName).WillByDefault(Return(DEV_NAME));
    ON_CALL(*mockInterface->ledgerMock, LnnConvertIdToDeviceType).WillByDefault(Return(const_cast<char *>(TYPE_PAD)));
    ON_CALL(*mockInterface->ledgerMock, LnnGetDeviceUdid).WillByDefault(Return(TEST_UDID));
    ON_CALL(*mockInterface->ledgerMock, LnnGetP2pRole).WillByDefault(Return(TEST_P2P_ROLE));
    ON_CALL(*mockInterface->ledgerMock, LnnGetP2pMac).WillByDefault(Return(TEST_MAC));
    ON_CALL(*mockInterface->ledgerMock, LnnGetSupportedProtocols).WillByDefault(Return(TEST_SUP_PROTOCOLS));
    ON_CALL(*mockInterface->ledgerMock, LnnGetLocalNodeInfo).WillByDefault(Return(&g_localInfo));
    ON_CALL(*mockInterface->ledgerMock, LnnGetBtMac).WillByDefault(Return(TEST_MAC));
    ON_CALL(*mockInterface->authMock, SoftBusGetBtState).WillByDefault(Return(BLE_ENABLE));
    const unsigned char val = 0x01;
    SoftbusSetConfig(SOFTBUS_INT_AUTH_ABILITY_COLLECTION, &val, sizeof(val));
    ret = AuthStartVerify(&g_connInfo, REQUEST_ID, &callBack, AUTH_MODULE_LNN, true);

    EXPECT_TRUE(ret == SOFTBUS_OK);
    AuthParam authInfo = {
        .authSeq = SEQ_SERVER,
        .requestId = REQUEST_ID,
        .connId = g_connId,
        .isServer = isServer,
        .isFastAuth = false,
    };
    AuthSessionStartAuth(&authInfo, &g_connInfo);
    SoftBusSleepMs(DELAY_TIME);
}

bool WaitForSignal()
{
#define USECTONSEC 1000LL
    SoftBusSysTime now;
    if (SoftBusGetTime(&now) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_TEST, "BrSoftBusCondWait SoftBusGetTime failed");
        return false;
    }
    int64_t time = now.sec * USECTONSEC * USECTONSEC + now.usec + DELAY_TIME * USECTONSEC;
    SoftBusSysTime tv;
    tv.sec = time / USECTONSEC / USECTONSEC;
    tv.usec = time % (USECTONSEC * USECTONSEC);
    if (SoftBusMutexLock(&LnnHichainInterfaceMock::mutex) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_TEST, "Wait signal Lock failed");
        return false;
    }
    if (!AuthNetLedgertInterfaceMock::isRuned) {
        int32_t ret = SoftBusCondWait(&LnnHichainInterfaceMock::cond, &LnnHichainInterfaceMock::mutex, &tv);
        (void)SoftBusMutexUnlock(&LnnHichainInterfaceMock::mutex);
        return (ret == SOFTBUS_OK);
    } else {
        (void)SoftBusMutexUnlock(&LnnHichainInterfaceMock::mutex);
        SoftBusSleepMs(DELAY_TIME);
        AuthNetLedgertInterfaceMock::isRuned = false;
    }
    return true;
}

NodeInfo CreateInfo(NodeInfo &nodeInfo)
{
    return nodeInfo;
}

class AuthTestCallBackTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void AuthTestCallBackTest::SetUpTestCase()
{
    AuthNetLedgertInterfaceMock::isRuned = false;
    RegAuthVerifyListener(&g_listener);
    (void)SoftBusMutexInit(&LnnHichainInterfaceMock::mutex, nullptr);
    SoftBusCondInit(&LnnHichainInterfaceMock::cond);
}

void AuthTestCallBackTest::TearDownTestCase()
{
    AuthNetLedgertInterfaceMock::isRuned = false;
    SoftBusCondDestroy(&LnnHichainInterfaceMock::cond);
    SoftBusMutexDestroy(&LnnHichainInterfaceMock::mutex);
}

void AuthTestCallBackTest::SetUp()
{
    LooperInit();
    AUTH_LOGI(AUTH_TEST, "AuthTestCallBackTest start.");
}

void AuthTestCallBackTest::TearDown()
{
    LooperDeinit();
}

void AuthInitMock(LnnConnectInterfaceMock &connMock, LnnHichainInterfaceMock &hichainMock, GroupAuthManager authManager,
    DeviceGroupManager groupManager)
{
    groupManager.regDataChangeListener = LnnHichainInterfaceMock::InvokeDataChangeListener;
    authManager.authDevice = LnnHichainInterfaceMock::InvokeAuthDevice;
    groupManager.unRegDataChangeListener = LnnHichainInterfaceMock::ActionofunRegDataChangeListener;
    ON_CALL(connMock, ConnSetConnectCallback(_, _)).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(hichainMock, InitDeviceAuthService()).WillByDefault(Return(0));
    ON_CALL(hichainMock, GetGaInstance()).WillByDefault(Return(&authManager));
    ON_CALL(hichainMock, GetGmInstance()).WillByDefault(Return(&groupManager));
}

/*
 * @tc.name: AUTH_CALLBACK_TEST_001
 * @tc.desc: auth callback test
 * @tc.type: FUNC
 * @tc.require:
 */

HWTEST_F(AuthTestCallBackTest, AUTH_CALLBACK_TEST_001, TestSize.Level1)
{
    GroupAuthManager authManager;
    DeviceGroupManager groupManager;
    NiceMock<LnnConnectInterfaceMock> connMock;
    NiceMock<LnnHichainInterfaceMock> hichainMock;
    NiceMock<AuthNetLedgertInterfaceMock> ledgerMock;
    NiceMock<LnnSocketInterfaceMock> socketMock;
    NiceMock<AuthCommonInterfaceMock> authMock;
    MockInterfaces mockInterface = {
        .connMock = &connMock,
        .hichainMock = &hichainMock,
        .ledgerMock = &ledgerMock,
        .socketMock = &socketMock,
        .authMock = &authMock,
    };
    AuthInitMock(connMock, hichainMock, authManager, groupManager);
    ClientFSMCreate(&mockInterface, authManager, groupManager);
    WaitForSignal();
    char *data = AuthNetLedgertInterfaceMock::Pack(SEQ_SERVER, &info, devIdHead);
    LnnConnectInterfaceMock::g_conncallback.OnDataReceived(g_connId, MODULE_ID, SEQ_SERVER, data, TEST_DATA_LEN);
    authManager.processData = LnnHichainInterfaceMock::ActionOfProcessData;
    HichainProcessData(SEQ_SERVER, DEVICE_INFO, TEST_DATA_LEN);
    EXPECT_CALL(connMock, ConnPostBytes).WillRepeatedly(DoAll(SendSignal, Return(SOFTBUS_OK)));
    LnnHichainInterfaceMock::g_devAuthCb.onTransmit(SEQ_SERVER, DEVICE_INFO, TEST_DATA_LEN);
    EXPECT_TRUE(AuthNetLedgertInterfaceMock::isRuned == true);
    WaitForSignal();
    SoftBusFree(data);
    char *data2 = AuthNetLedgertInterfaceMock::Pack(SEQ_SERVER, &info, devAuthHead);
    LnnConnectInterfaceMock::g_conncallback.OnDataReceived(g_connId, MODULE_ID, SEQ_SERVER, data2, TEST_DATA_LEN);
    WaitForSignal();
    SoftBusFree(data2);
    EXPECT_CALL(authMock, LnnGetNetworkIdByUuid).WillRepeatedly(Return(SOFTBUS_OK));
    LnnHichainInterfaceMock::g_devAuthCb.onSessionKeyReturned(SEQ_SERVER, g_sessionKey, SESSION_KEY_LENGTH);
    WaitForSignal();
    EXPECT_CALL(connMock, ConnPostBytes).WillRepeatedly(DoAll(SendSignal, Return(SOFTBUS_OK)));
    LnnHichainInterfaceMock::g_devAuthCb.onFinish(SEQ_SERVER, OPER_CODE, g_retData);
    WaitForSignal();
    EXPECT_CALL(connMock, ConnPostBytes)
        .WillRepeatedly(DoAll(SendSignal, LnnConnectInterfaceMock::ActionOfConnPostBytes));
    PostDeviceInfoMessage(SEQ_SERVER, &info2);
    WaitForSignal();
    LnnConnectInterfaceMock::g_conncallback.OnDataReceived(
        g_connId, MODULE_ID, SEQ_SERVER, LnnConnectInterfaceMock::g_encryptData, TEST_DATA_LEN);
    WaitForSignal();
    char *data4 = AuthNetLedgertInterfaceMock::Pack(SEQ_SERVER, &info, closeAckHead);
    LnnConnectInterfaceMock::g_conncallback.OnDataReceived(g_connId, MODULE_ID, SEQ_SERVER, data4, TEST_DATA_LEN);
    WaitForSignal();
    SoftBusFree(data4);
}
} // namespace OHOS