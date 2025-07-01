/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>
#include <dlfcn.h>
#include <gmock/gmock.h>
#include "wifi_direct_init.h"
#include "softbus_error_code.h"

using namespace testing::ext;
using namespace testing;
using ::testing::_;
using ::testing::Invoke;

namespace OHOS::SoftBus {
class MockDlsym {
public:
    MOCK_METHOD(void *, dlopen, (const char *fileName, int flag));
    MOCK_METHOD(void *, dlsym, (void *handle, const char *symbol));
};

NiceMock<MockDlsym> *mockDlsym;

extern "C" {
// mock dlopen
void *dlopen(const char *fileName, int flag)
{
    if (mockDlsym == nullptr) {
        mockDlsym = new NiceMock<MockDlsym>();
    }
    return mockDlsym->dlopen(fileName, flag);
}

// mock dlsym
void *dlsym(void *handle, const char *symbol)
{
    if (mockDlsym == nullptr) {
        mockDlsym = new NiceMock<MockDlsym>();
    }
    return mockDlsym->dlsym(handle, symbol);
}
}

class WifiDirectInitTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override { }
    void TearDown() override { }
};
void WifiDirectInitTest::SetUpTestCase() {};
void WifiDirectInitTest::TearDownTestCase() {};

void AddAuthConnectionTest(const LnnEventBasicInfo *info)
{
    (void)info;
}

/*
 * @tc.name: ReAuthTransListener
 * @tc.desc: test register listerner
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectInitTest, ReAuthTransListener001, TestSize.Level1)
{
    mockDlsym = new NiceMock<MockDlsym>();
    EXPECT_CALL(*mockDlsym, dlopen(_, _)).WillRepeatedly(Return(nullptr));
    int32_t ret = DBinderSoftbusServer::GetInstance().RegAuthTransListener(MODULE_P2P_LINK, nullptr);
    EXPECT_EQ(ret, SOFTBUS_WIFI_DIRECT_DLOPEN_FAILED);

    ret = 1;
    EXPECT_CALL(*mockDlsym, dlopen(_, _)).WillRepeatedly(Return((void *)&ret));
    EXPECT_CALL(*mockDlsym, dlsym(_, _)).WillRepeatedly(Return(nullptr));
    ret = DBinderSoftbusServer::GetInstance().RegAuthTransListener(MODULE_P2P_LINK, nullptr);
    EXPECT_EQ(ret, SOFTBUS_WIFI_DIRECT_DLSYM_FAILED);
}

/*
 * @tc.name: AuthGetDeviceUuid
 * @tc.desc: test get device uuid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectInitTest, AuthGetDeviceUuid002, TestSize.Level1)
{
    EXPECT_CALL(*mockDlsym, dlsym(_, _)).WillRepeatedly(Return(nullptr));
    int32_t ret = DBinderSoftbusServer::GetInstance().AuthGetDeviceUuid(1, nullptr, 1);
    EXPECT_EQ(ret, SOFTBUS_WIFI_DIRECT_DLSYM_FAILED);
}

/*
 * @tc.name: AuthPostTransData AuthCloseConn
 * @tc.desc: test post data, close connection
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectInitTest, AuthPostTransData003, TestSize.Level1)
{
    AuthHandle handle = {
        .authId = 1,
        .type = 1,
    };
    EXPECT_CALL(*mockDlsym, dlsym(_, _)).WillRepeatedly(Return(nullptr));
    DBinderSoftbusServer::GetInstance().AuthCloseConn(handle);
    int32_t ret = DBinderSoftbusServer::GetInstance().AuthPostTransData(handle, nullptr);
    EXPECT_EQ(ret, SOFTBUS_WIFI_DIRECT_DLSYM_FAILED);
}

/*
 * @tc.name: AuthGetMetaType
 * @tc.desc: test get meta data
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectInitTest, AuthGetMetaType004, TestSize.Level1)
{
    EXPECT_CALL(*mockDlsym, dlsym(_, _)).WillRepeatedly(Return(nullptr));
    int32_t ret = DBinderSoftbusServer::GetInstance().AuthGetMetaType(1, nullptr);
    EXPECT_EQ(ret, SOFTBUS_WIFI_DIRECT_DLSYM_FAILED);
}

/*
 * @tc.name: AuthStartListeningForWifiDirect AuthStopListeningForWifiDirect AuthStopListening
 * @tc.desc: test start listening, stop listening
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectInitTest, AuthStartListeningForWifiDirect005, TestSize.Level1)
{
    EXPECT_CALL(*mockDlsym, dlsym(_, _)).WillRepeatedly(Return(nullptr));
    DBinderSoftbusServer::GetInstance().AuthStopListeningForWifiDirect(AUTH_LINK_TYPE_P2P, AUTH_P2P);
    DBinderSoftbusServer::GetInstance().AuthStopListening(AUTH_LINK_TYPE_P2P);
    int32_t ret =
        DBinderSoftbusServer::GetInstance().AuthStartListeningForWifiDirect(AUTH_LINK_TYPE_P2P, nullptr, 1, nullptr);
    EXPECT_EQ(ret, SOFTBUS_WIFI_DIRECT_DLSYM_FAILED);
}

/*
 * @tc.name: AuthGenRequestId
 * @tc.desc: test get GenRequestId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectInitTest, AuthGenRequestId006, TestSize.Level1)
{
    EXPECT_CALL(*mockDlsym, dlsym(_, _)).WillRepeatedly(Return(nullptr));
    int32_t ret = DBinderSoftbusServer::GetInstance().AuthGenRequestId();
    EXPECT_EQ(ret, SOFTBUS_WIFI_DIRECT_DLSYM_FAILED);
}

/*
 * @tc.name: AuthOpenConn
 * @tc.desc: test open connection
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectInitTest, AuthOpenConn007, TestSize.Level1)
{
    EXPECT_CALL(*mockDlsym, dlsym(_, _)).WillRepeatedly(Return(nullptr));
    int32_t ret = DBinderSoftbusServer::GetInstance().AuthOpenConn(nullptr, 1, nullptr, true);
    EXPECT_EQ(ret, SOFTBUS_WIFI_DIRECT_DLSYM_FAILED);
}

/*
 * @tc.name: LnnConvertDLidToUdid
 * @tc.desc: test dlid convert to udid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectInitTest, LnnConvertDLidToUdid008, TestSize.Level1)
{
    EXPECT_CALL(*mockDlsym, dlsym(_, _)).WillRepeatedly(Return(nullptr));
    const char *remoteUdid = DBinderSoftbusServer::GetInstance().LnnConvertDLidToUdid(nullptr, CATEGORY_UDID);
    EXPECT_EQ(remoteUdid, nullptr);
}

/*
 * @tc.name: TransProxyPipelineRegisterListener
 * @tc.desc: test register listener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectInitTest, TransProxyPipelineRegisterListener009, TestSize.Level1)
{
    EXPECT_CALL(*mockDlsym, dlsym(_, _)).WillRepeatedly(Return(nullptr));
    int32_t ret = DBinderSoftbusServer::GetInstance().TransProxyPipelineRegisterListener(MSG_TYPE_P2P_NEGO, nullptr);
    EXPECT_EQ(ret, SOFTBUS_WIFI_DIRECT_DLSYM_FAILED);
}

/*
 * @tc.name: TransProxyPipelineGetUuidByChannelId
 * @tc.desc: test get uuid by channelid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectInitTest, TransProxyPipelineGetUuidByChannelId010, TestSize.Level1)
{
    EXPECT_CALL(*mockDlsym, dlsym(_, _)).WillRepeatedly(Return(nullptr));
    int32_t ret = DBinderSoftbusServer::GetInstance().TransProxyPipelineGetUuidByChannelId(1, nullptr, 1);
    EXPECT_EQ(ret, SOFTBUS_WIFI_DIRECT_DLSYM_FAILED);
}

/*
 * @tc.name: TransProxyPipelineSendMessage
 * @tc.desc: test send message
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectInitTest, TransProxyPipelineSendMessage011, TestSize.Level1)
{
    EXPECT_CALL(*mockDlsym, dlsym(_, _)).WillRepeatedly(Return(nullptr));
    int32_t ret = DBinderSoftbusServer::GetInstance().TransProxyPipelineSendMessage(1, nullptr, 1, MSG_TYPE_P2P_NEGO);
    EXPECT_EQ(ret, SOFTBUS_WIFI_DIRECT_DLSYM_FAILED);
}

/*
 * @tc.name: LnnEnhanceFuncListGet
 * @tc.desc: test get enhance funclist
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectInitTest, LnnEnhanceFuncListGet012, TestSize.Level1)
{
    EXPECT_CALL(*mockDlsym, dlsym(_, _)).WillRepeatedly(Return(nullptr));
    LnnEnhanceFuncList *pfnLnnEnhanceFuncList = DBinderSoftbusServer::GetInstance().LnnEnhanceFuncListGet();
    EXPECT_EQ(pfnLnnEnhanceFuncList, nullptr);
}

/*
 * @tc.name: LnnGetRemoteStrInfo
 * @tc.desc: test get remote strInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectInitTest, LnnGetRemoteStrInfo013, TestSize.Level1)
{
    EXPECT_CALL(*mockDlsym, dlsym(_, _)).WillRepeatedly(Return(nullptr));
    int32_t ret = DBinderSoftbusServer::GetInstance().LnnGetRemoteStrInfo(nullptr, STRING_KEY_DEV_UDID, nullptr, 1);
    EXPECT_EQ(ret, SOFTBUS_WIFI_DIRECT_DLSYM_FAILED);
}

/*
 * @tc.name: LnnGetNetworkIdByUuid
 * @tc.desc: test get networkid by uuid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectInitTest, LnnGetNetworkIdByUuid014, TestSize.Level1)
{
    EXPECT_CALL(*mockDlsym, dlsym(_, _)).WillRepeatedly(Return(nullptr));
    int32_t ret = DBinderSoftbusServer::GetInstance().LnnGetNetworkIdByUuid(nullptr, nullptr, 1);
    EXPECT_EQ(ret, SOFTBUS_WIFI_DIRECT_DLSYM_FAILED);
}

/*
 * @tc.name: LnnGetLocalStrInfo
 * @tc.desc: test get local strInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectInitTest, LnnGetLocalStrInfo015, TestSize.Level1)
{
    EXPECT_CALL(*mockDlsym, dlsym(_, _)).WillRepeatedly(Return(nullptr));
    int32_t ret = DBinderSoftbusServer::GetInstance().LnnGetLocalStrInfo(STRING_KEY_DEV_UDID, nullptr, 1);
    EXPECT_EQ(ret, SOFTBUS_WIFI_DIRECT_DLSYM_FAILED);
}

/*
 * @tc.name: LnnGetLocalNumU64Info
 * @tc.desc: test get local NumU64Info
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectInitTest, LnnGetLocalNumU64Info016, TestSize.Level1)
{
    EXPECT_CALL(*mockDlsym, dlsym(_, _)).WillRepeatedly(Return(nullptr));
    int32_t ret = DBinderSoftbusServer::GetInstance().LnnGetLocalNumU64Info(STRING_KEY_DEV_UDID, nullptr);
    EXPECT_EQ(ret, SOFTBUS_WIFI_DIRECT_DLSYM_FAILED);
}

/*
 * @tc.name: LnnGetRemoteByteInfo
 * @tc.desc: test get remote byteInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectInitTest, LnnGetRemoteByteInfo017, TestSize.Level1)
{
    EXPECT_CALL(*mockDlsym, dlsym(_, _)).WillRepeatedly(Return(nullptr));
    int32_t ret = DBinderSoftbusServer::GetInstance().LnnGetRemoteByteInfo(nullptr, STRING_KEY_DEV_UDID, nullptr, 1);
    EXPECT_EQ(ret, SOFTBUS_WIFI_DIRECT_DLSYM_FAILED);
}

/*
 * @tc.name: LnnGetRemoteBoolInfoIgnoreOnline
 * @tc.desc: test get remote boolInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectInitTest, LnnGetRemoteBoolInfoIgnoreOnline018, TestSize.Level1)
{
    EXPECT_CALL(*mockDlsym, dlsym(_, _)).WillRepeatedly(Return(nullptr));
    int32_t ret =
        DBinderSoftbusServer::GetInstance().LnnGetRemoteBoolInfoIgnoreOnline(nullptr, STRING_KEY_DEV_UDID, nullptr);
    EXPECT_EQ(ret, SOFTBUS_WIFI_DIRECT_DLSYM_FAILED);
}

/*
 * @tc.name: LnnGetFeatureCapabilty
 * @tc.desc: test get feature capabilty
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectInitTest, LnnGetFeatureCapabilty019, TestSize.Level1)
{
    EXPECT_CALL(*mockDlsym, dlsym(_, _)).WillRepeatedly(Return(nullptr));
    int32_t ret = DBinderSoftbusServer::GetInstance().LnnGetFeatureCapabilty();
    EXPECT_EQ(ret, SOFTBUS_WIFI_DIRECT_DLSYM_FAILED);
}

/*
 * @tc.name: IsFeatureSupport
 * @tc.desc: test is feature support
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectInitTest, IsFeatureSupport020, TestSize.Level1)
{
    EXPECT_CALL(*mockDlsym, dlsym(_, _)).WillRepeatedly(Return(nullptr));
    bool isFeature = DBinderSoftbusServer::GetInstance().IsFeatureSupport(1, BIT_WIFI_P2P_REUSE);
    EXPECT_EQ(isFeature, false);
}

/*
 * @tc.name: LnnSetLocalStrInfo
 * @tc.desc: test set local strInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectInitTest, LnnSetLocalStrInfo021, TestSize.Level1)
{
    EXPECT_CALL(*mockDlsym, dlsym(_, _)).WillRepeatedly(Return(nullptr));
    int32_t ret = DBinderSoftbusServer::GetInstance().LnnSetLocalStrInfo(STRING_KEY_DEV_UDID, nullptr);
    EXPECT_EQ(ret, SOFTBUS_WIFI_DIRECT_DLSYM_FAILED);
}

/*
 * @tc.name: LnnGetOnlineStateById
 * @tc.desc: test get onlineState by id
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectInitTest, LnnGetOnlineStateById022, TestSize.Level1)
{
    EXPECT_CALL(*mockDlsym, dlsym(_, _)).WillRepeatedly(Return(nullptr));
    bool isGetId = DBinderSoftbusServer::GetInstance().LnnGetOnlineStateById(nullptr, CATEGORY_UDID);
    EXPECT_EQ(isGetId, false);
}

/*
 * @tc.name: LnnSetLocalNumInfo
 * @tc.desc: test set local numInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectInitTest, LnnSetLocalNumInfo023, TestSize.Level1)
{
    EXPECT_CALL(*mockDlsym, dlsym(_, _)).WillRepeatedly(Return(nullptr));
    int32_t ret = DBinderSoftbusServer::GetInstance().LnnSetLocalNumInfo(STRING_KEY_DEV_UDID, 1);
    EXPECT_EQ(ret, SOFTBUS_WIFI_DIRECT_DLSYM_FAILED);
}

/*
 * @tc.name: LnnSyncP2pInfo
 * @tc.desc: test sync p2p info
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectInitTest, LnnSyncP2pInfo024, TestSize.Level1)
{
    EXPECT_CALL(*mockDlsym, dlsym(_, _)).WillRepeatedly(Return(nullptr));
    int32_t ret = DBinderSoftbusServer::GetInstance().LnnSyncP2pInfo();
    EXPECT_EQ(ret, SOFTBUS_WIFI_DIRECT_DLSYM_FAILED);
}

/*
 * @tc.name: LnnGetOsTypeByNetworkId
 * @tc.desc: test get os type by networkid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectInitTest, LnnGetOsTypeByNetworkId025, TestSize.Level1)
{
    EXPECT_CALL(*mockDlsym, dlsym(_, _)).WillRepeatedly(Return(nullptr));
    int32_t ret = DBinderSoftbusServer::GetInstance().LnnGetOsTypeByNetworkId(nullptr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_WIFI_DIRECT_DLSYM_FAILED);
}

/*
 * @tc.name: LnnGetRemoteNumInfo
 * @tc.desc: test get remote numInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectInitTest, LnnGetRemoteNumInfo026, TestSize.Level1)
{
    EXPECT_CALL(*mockDlsym, dlsym(_, _)).WillRepeatedly(Return(nullptr));
    int32_t ret = DBinderSoftbusServer::GetInstance().LnnGetRemoteNumInfo(nullptr, STRING_KEY_DEV_UDID, nullptr);
    EXPECT_EQ(ret, SOFTBUS_WIFI_DIRECT_DLSYM_FAILED);
}

/*
 * @tc.name: LnnGetLocalNumInfo
 * @tc.desc: test get local numInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectInitTest, LnnGetLocalNumInfo027, TestSize.Level1)
{
    EXPECT_CALL(*mockDlsym, dlsym(_, _)).WillRepeatedly(Return(nullptr));
    int32_t ret = DBinderSoftbusServer::GetInstance().LnnGetLocalNumInfo(STRING_KEY_DEV_UDID, nullptr);
    EXPECT_EQ(ret, SOFTBUS_WIFI_DIRECT_DLSYM_FAILED);
}

/*
 * @tc.name: LnnGetRemoteNumU64Info
 * @tc.desc: test get remote numU64Info
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectInitTest, LnnGetRemoteNumU64Info028, TestSize.Level1)
{
    EXPECT_CALL(*mockDlsym, dlsym(_, _)).WillRepeatedly(Return(nullptr));
    int32_t ret = DBinderSoftbusServer::GetInstance().LnnGetRemoteNumU64Info(nullptr, STRING_KEY_DEV_UDID, nullptr);
    EXPECT_EQ(ret, SOFTBUS_WIFI_DIRECT_DLSYM_FAILED);
}

/*
 * @tc.name: LnnGetRemoteNodeInfoById
 * @tc.desc: test get remote nodeInfo bt id
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectInitTest, LnnGetRemoteNodeInfoById029, TestSize.Level1)
{
    EXPECT_CALL(*mockDlsym, dlsym(_, _)).WillRepeatedly(Return(nullptr));
    int32_t ret = DBinderSoftbusServer::GetInstance().LnnGetRemoteNodeInfoById(nullptr, CATEGORY_UDID, nullptr);
    EXPECT_EQ(ret, SOFTBUS_WIFI_DIRECT_DLSYM_FAILED);
}

/*
 * @tc.name: LnnGetRemoteNodeInfoByKey
 * @tc.desc: test get remote nodeInfo by key
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectInitTest, LnnGetRemoteNodeInfoByKey030, TestSize.Level1)
{
    EXPECT_CALL(*mockDlsym, dlsym(_, _)).WillRepeatedly(Return(nullptr));
    int32_t ret = DBinderSoftbusServer::GetInstance().LnnGetRemoteNodeInfoByKey(nullptr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_WIFI_DIRECT_DLSYM_FAILED);
}

/*
 * @tc.name: LnnGetAllOnlineNodeInfo
 * @tc.desc: get all online nodeInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectInitTest, LnnGetAllOnlineNodeInfo031, TestSize.Level1)
{
    EXPECT_CALL(*mockDlsym, dlsym(_, _)).WillRepeatedly(Return(nullptr));
    int32_t ret = DBinderSoftbusServer::GetInstance().LnnGetAllOnlineNodeInfo(nullptr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_WIFI_DIRECT_DLSYM_FAILED);
}

/*
 * @tc.name: LnnRegisterEventHandler
 * @tc.desc: register event handler, last test delete mockDlsym.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectInitTest, LnnRegisterEventHandler032, TestSize.Level1)
{
    EXPECT_CALL(*mockDlsym, dlsym(_, _)).WillRepeatedly(Return(nullptr));
    int32_t ret =
        DBinderSoftbusServer::GetInstance().LnnRegisterEventHandler(LNN_EVENT_IP_ADDR_CHANGED, AddAuthConnectionTest);
    EXPECT_EQ(ret, SOFTBUS_WIFI_DIRECT_DLSYM_FAILED);
    delete mockDlsym;
}
} // namespace OHOS::SoftBus