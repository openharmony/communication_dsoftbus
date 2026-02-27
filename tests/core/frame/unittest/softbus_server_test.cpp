/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "iservice_registry.h"
#include "softbus_common.h"
#include "softbus_error_code.h"
#include "softbus_server.h"
#include "softbus_server_test_mock.h"
#include "system_ability_definition.h"
#include <gtest/gtest.h>
#include "softbus_server.cpp"

using namespace testing;
using namespace testing::ext;

namespace OHOS {

#define TEST_SESSION_NAME_SIZE_MAX 256

using GetGCMFunc = GeneralConnectionManager* (*)(void);
auto g_realGetGCM = reinterpret_cast<GetGCMFunc>(dlsym(RTLD_NEXT, "GetGeneralConnectionManager"));

class SoftbusServerTest : public testing::Test {
public:
    SoftbusServerTest()
    {}
    ~SoftbusServerTest()
    {}
    static void SetUpTestCase()
    {}
    static void TearDownTestCase()
    {}
    void SetUp() override
    {}
    void TearDown() override
    {}
};

static sptr<IRemoteObject> GenerateRemoteObject(void)
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr != nullptr) {
        return samgr->GetSystemAbility(SOFTBUS_SERVER_SA_ID);
    }
    return nullptr;
}

/*
 * @tc.name: SoftbusServerTest001
 * @tc.desc: Verify the SoftbusRegisterService function
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(SoftbusServerTest, SoftbusServerTest001, TestSize.Level1)
{
    sptr<OHOS::SoftBusServer> softBusServer = new OHOS::SoftBusServer(SOFTBUS_SERVER_SA_ID, true);
    ASSERT_NE(nullptr, softBusServer);

    int32_t ret = softBusServer->SoftbusRegisterService("test", nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    sptr<IRemoteObject> obj = GenerateRemoteObject();
    ret = softBusServer->SoftbusRegisterService("test", obj);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: SoftbusServerTest002
 * @tc.desc: Verify the OpenAuthSession function
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(SoftbusServerTest, SoftbusServerTest002, TestSize.Level1)
{
    sptr<OHOS::SoftBusServer> softBusServer = new OHOS::SoftBusServer(SOFTBUS_SERVER_SA_ID, true);
    ASSERT_NE(nullptr, softBusServer);
    ConnectionAddr addr;
    addr.type = CONNECTION_ADDR_MAX;

    int32_t ret = softBusServer->OpenAuthSession("test", nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = softBusServer->OpenAuthSession("test", &addr);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_CONNECT_TYPE, ret);
}

/*
 * @tc.name: SoftbusServerTest003
 * @tc.desc: Verify the Dump function
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(SoftbusServerTest, SoftbusServerTest003, TestSize.Level1)
{
    sptr<OHOS::SoftBusServer> softBusServer = new OHOS::SoftBusServer(SOFTBUS_SERVER_SA_ID, true);
    ASSERT_NE(nullptr, softBusServer);
    int32_t fd = -1;
    std::vector<std::u16string> args;

    int32_t ret = softBusServer->Dump(fd, args);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    fd = 0;
    ret = softBusServer->Dump(fd, args);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: SoftbusServerTest004
 * @tc.desc: Verify the GetSoftbusSpecObject function
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(SoftbusServerTest, SoftbusServerTest004, TestSize.Level1)
{
    sptr<OHOS::SoftBusServer> softBusServer = new OHOS::SoftBusServer(SOFTBUS_SERVER_SA_ID, true);
    ASSERT_NE(nullptr, softBusServer);
    sptr<IRemoteObject> object = nullptr;
    int32_t ret = softBusServer->GetSoftbusSpecObject(object);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: SoftbusServerTest005
 * @tc.desc: Verify the GetBusCenterExObj function
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(SoftbusServerTest, SoftbusServerTest005, TestSize.Level1)
{
    sptr<OHOS::SoftBusServer> softBusServer = new OHOS::SoftBusServer(SOFTBUS_SERVER_SA_ID, true);
    ASSERT_NE(nullptr, softBusServer);
    sptr<IRemoteObject> object = nullptr;
    int32_t ret = softBusServer->GetBusCenterExObj(object);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: SoftbusServerTest006
 * @tc.desc: Verify the EvaluateQos function
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(SoftbusServerTest, SoftbusServerTest006, TestSize.Level1)
{
    sptr<OHOS::SoftBusServer> softBusServer = new OHOS::SoftBusServer(SOFTBUS_SERVER_SA_ID, true);
    ASSERT_NE(nullptr, softBusServer);
    NiceMock<SoftbusServerTestInterfaceMock> softbusServerMock;
    char networkId[NETWORK_ID_BUF_LEN] = "test";
    TransDataType dataType = DATA_TYPE_BYTES;

    EXPECT_CALL(softbusServerMock, IsValidString(_, _))
        .WillRepeatedly(Return(false));
    int32_t ret = softBusServer->EvaluateQos(networkId, dataType, nullptr, 0);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    EXPECT_CALL(softbusServerMock, IsValidString(_, _))
        .WillRepeatedly(Return(true));
    ret = softBusServer->EvaluateQos(networkId, dataType, nullptr, 0);
    EXPECT_EQ(SOFTBUS_NETWORK_NODE_OFFLINE, ret);
}

/*
 * @tc.name: SoftbusServerTest007
 * @tc.desc: ConvertConnectType api test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(SoftbusServerTest, SoftbusServerTest007, TestSize.Level1)
{
    int ret = ConvertConnectType(CONNECTION_ADDR_BR);
    EXPECT_EQ(ret, CONNECT_BR);
    ret = ConvertConnectType(CONNECTION_ADDR_BLE);
    EXPECT_EQ(ret, CONNECT_BLE);
    ret = ConvertConnectType(CONNECTION_ADDR_ETH);
    EXPECT_EQ(ret, CONNECT_TCP);
    ret = ConvertConnectType(CONNECTION_ADDR_WLAN);
    EXPECT_EQ(ret, CONNECT_TCP);
    ret = ConvertConnectType(CONNECTION_ADDR_NCM);
    EXPECT_EQ(ret, CONNECT_TCP);
}

/*
 * @tc.name: SoftbusServerTest008
 * @tc.desc: SoftbusRegisterService api test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(SoftbusServerTest, SoftbusServerTest008, TestSize.Level1)
{
    sptr<OHOS::SoftBusServer> softBusServer = new OHOS::SoftBusServer(SOFTBUS_SERVER_SA_ID, true);
    EXPECT_NE(softBusServer, nullptr);
    sptr<IRemoteObject> obj = GenerateRemoteObject();
    EXPECT_NE(obj, nullptr);

    int32_t ret = softBusServer->SoftbusRegisterService("test008", obj);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = softBusServer->SoftbusRegisterService("test008", obj);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: SoftbusServerTest009
 * @tc.desc: OpenAuthSession api test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(SoftbusServerTest, SoftbusServerTest009, TestSize.Level1)
{
    sptr<OHOS::SoftBusServer> softBusServer = new OHOS::SoftBusServer(SOFTBUS_SERVER_SA_ID, true);
    EXPECT_NE(softBusServer, nullptr);

    NiceMock<SoftbusServerTestInterfaceMock> softbusServerMock;
    EXPECT_CALL(softbusServerMock, IsValidString(_, _))
        .WillRepeatedly(Return(true));

    ConnectionAddr addr1;
    addr1.type = CONNECTION_ADDR_WLAN;
    int32_t ret = softBusServer->OpenAuthSession("test", &addr1);
    EXPECT_EQ(ret, -1);
    addr1.type = CONNECTION_ADDR_BR;
    ret = softBusServer->OpenAuthSession("test", &addr1);
    EXPECT_EQ(ret, -1);
    addr1.type = CONNECTION_ADDR_BLE;
    ret = softBusServer->OpenAuthSession("test", &addr1);
    EXPECT_EQ(ret, -1);
    addr1.type = CONNECTION_ADDR_ETH;
    ret = softBusServer->OpenAuthSession("test", &addr1);
    EXPECT_EQ(ret, -1);
}

/*
 * @tc.name: SoftbusServerTest010
 * @tc.desc: adapter func test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(SoftbusServerTest, SoftbusServerTest010, TestSize.Level1)
{
    sptr<OHOS::SoftBusServer> softBusServer = new OHOS::SoftBusServer(SOFTBUS_SERVER_SA_ID, true);
    EXPECT_NE(softBusServer, nullptr);

    int32_t ret = softBusServer->UnregDataLevelChangeCb(nullptr);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = softBusServer->StopRangeForMsdp(nullptr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = softBusServer->SyncTrustedRelationShip(nullptr, nullptr, 0);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = softBusServer->ProcessInnerEvent(0, nullptr, 0);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = softBusServer->PrivilegeCloseChannel(0, 0, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = softBusServer->PrivilegeCloseChannel(0, 0, "test");
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: SoftbusServerTest011
 * @tc.desc: adapter func test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(SoftbusServerTest, SoftbusServerTest011, TestSize.Level1)
{
    sptr<OHOS::SoftBusServer> softBusServer = new OHOS::SoftBusServer(SOFTBUS_SERVER_SA_ID, true);
    EXPECT_NE(softBusServer, nullptr);

    int32_t ret = softBusServer->OpenBrProxy(nullptr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = softBusServer->CloseBrProxy(0);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_SERVER_NOINIT);
    ret = softBusServer->SendBrProxyData(0, nullptr, 0);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = softBusServer->SetListenerState(0, 0, false);
    EXPECT_EQ(ret, SOFTBUS_TRANS_SESSION_SERVER_NOINIT);
    ret = softBusServer->IsProxyChannelEnabled(0);
    EXPECT_EQ(ret, 1);
}

/*
 * @tc.name: SoftbusServerTest012
 * @tc.desc: ConvertTransType api test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(SoftbusServerTest, SoftbusServerTest012, TestSize.Level1)
{
    LaneTransType ret;
    TransDataType dataType = DATA_TYPE_MESSAGE;
    ret = ConvertTransType(dataType);
    EXPECT_EQ(ret, LANE_T_MSG);
    dataType = DATA_TYPE_BYTES;
    ret = ConvertTransType(dataType);
    EXPECT_EQ(ret, LANE_T_BYTE);
    dataType = DATA_TYPE_FILE;
    ret = ConvertTransType(dataType);
    EXPECT_EQ(ret, LANE_T_FILE);
    dataType = DATA_TYPE_RAW_STREAM;
    ret = ConvertTransType(dataType);
    EXPECT_EQ(ret, LANE_T_RAW_STREAM);
    dataType = DATA_TYPE_VIDEO_STREAM;
    ret = ConvertTransType(dataType);
    EXPECT_EQ(ret, LANE_T_COMMON_VIDEO);
    dataType = DATA_TYPE_AUDIO_STREAM;
    ret = ConvertTransType(dataType);
    EXPECT_EQ(ret, LANE_T_COMMON_VOICE);
    dataType = DATA_TYPE_SLICE_STREAM;
    ret = ConvertTransType(dataType);
    EXPECT_EQ(ret, LANE_T_RAW_STREAM);
    dataType = DATA_TYPE_RAW_STREAM_ENCRYPED;
    ret = ConvertTransType(dataType);
    EXPECT_EQ(ret, LANE_T_BUTT);
}

/*
 * @tc.name: SoftbusServerTest013
 * @tc.desc: ConnGetPeerDeviceId api test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(SoftbusServerTest, SoftbusServerTest013, TestSize.Level1)
{
    sptr<OHOS::SoftBusServer> softBusServer = new OHOS::SoftBusServer(SOFTBUS_SERVER_SA_ID, true);
    EXPECT_NE(softBusServer, nullptr);
    NiceMock<SoftbusServerTestInterfaceMock> softbusServerMock;

    using GetGCMFunc = GeneralConnectionManager* (*)(void);
    auto realGetGCM = reinterpret_cast<GetGCMFunc>(dlsym(RTLD_NEXT, "GetGeneralConnectionManager"));
    EXPECT_NE(realGetGCM, nullptr);

    EXPECT_CALL(softbusServerMock, GetGeneralConnectionManager())
        .WillOnce(Return(nullptr))
        .WillRepeatedly(Invoke(realGetGCM));

    int32_t ret = softBusServer->ConnGetPeerDeviceId(0, nullptr, 0);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);

    ret = softBusServer->ConnGetPeerDeviceId(0, nullptr, 0);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: SoftbusServerTest014
 * @tc.desc: Connect api test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(SoftbusServerTest, SoftbusServerTest014, TestSize.Level1)
{
    sptr<OHOS::SoftBusServer> softBusServer = new OHOS::SoftBusServer(SOFTBUS_SERVER_SA_ID, true);
    EXPECT_NE(softBusServer, nullptr);
    NiceMock<SoftbusServerTestInterfaceMock> softbusServerMock;

    EXPECT_CALL(softbusServerMock, GetGeneralConnectionManager())
        .WillOnce(Return(nullptr))
        .WillRepeatedly(Invoke(g_realGetGCM));

    int32_t ret = softBusServer->Connect(nullptr, nullptr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);

    ret = softBusServer->Connect(nullptr, nullptr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_STRCPY_ERR);

    ret = softBusServer->Connect(nullptr, "test", nullptr);
    EXPECT_EQ(ret, SOFTBUS_STRCPY_ERR);

    ret = softBusServer->Connect("test", "test", nullptr);
    EXPECT_EQ(ret, SOFTBUS_CONN_GENERAL_CREATE_CLIENT_MAX);
}

/*
 * @tc.name: SoftbusServerTest015
 * @tc.desc: Disconnect api test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(SoftbusServerTest, SoftbusServerTest015, TestSize.Level1)
{
    sptr<OHOS::SoftBusServer> softBusServer = new OHOS::SoftBusServer(SOFTBUS_SERVER_SA_ID, true);
    EXPECT_NE(softBusServer, nullptr);
    NiceMock<SoftbusServerTestInterfaceMock> softbusServerMock;

    EXPECT_CALL(softbusServerMock, GetGeneralConnectionManager())
        .WillOnce(Return(nullptr))
        .WillRepeatedly(Invoke(g_realGetGCM));

    int32_t ret = softBusServer->Disconnect(0);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);

    ret = softBusServer->Disconnect(0);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: SoftbusServerTest016
 * @tc.desc: Send api test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(SoftbusServerTest, SoftbusServerTest016, TestSize.Level1)
{
    sptr<OHOS::SoftBusServer> softBusServer = new OHOS::SoftBusServer(SOFTBUS_SERVER_SA_ID, true);
    EXPECT_NE(softBusServer, nullptr);
    NiceMock<SoftbusServerTestInterfaceMock> softbusServerMock;

    EXPECT_CALL(softbusServerMock, GetGeneralConnectionManager())
        .WillOnce(Return(nullptr))
        .WillRepeatedly(Invoke(g_realGetGCM));

    int32_t ret = softBusServer->Send(0, nullptr, 0);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);

    ret = softBusServer->Send(0, nullptr, 0);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: SoftbusServerTest017
 * @tc.desc: Send api test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(SoftbusServerTest, SoftbusServerTest017, TestSize.Level1)
{
    sptr<OHOS::SoftBusServer> softBusServer = new OHOS::SoftBusServer(SOFTBUS_SERVER_SA_ID, true);
    EXPECT_NE(softBusServer, nullptr);
    NiceMock<SoftbusServerTestInterfaceMock> softbusServerMock;

    EXPECT_CALL(softbusServerMock, GetGeneralConnectionManager())
        .WillOnce(Return(nullptr))
        .WillRepeatedly(Invoke(g_realGetGCM));

    int32_t ret = softBusServer->ConnGetPeerDeviceId(0, nullptr, 0);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);

    ret = softBusServer->ConnGetPeerDeviceId(0, nullptr, 0);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}
}