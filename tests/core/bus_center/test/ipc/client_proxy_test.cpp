/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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
#include <securec.h>

#include "bus_center_client_proxy.h"
#include "bus_center_client_proxy_standard.h"
#include "if_system_ability_manager.h"
#include "iremote_object.h"
#include "iservice_registry.h"
#include "softbus_adapter_mem.h"
#include "softbus_bus_center.h"
#include "softbus_error_code.h"

namespace OHOS {
using namespace testing::ext;
using namespace testing;

#define TEST_NETWORK_ID    "6542316a57d"
#define TEST_ADDR          "1111222233334444"
#define TEST_INFO          "567890"
#define TEST_ADDR_TYPE_LEN 17
#define TEST_RET_CODE      0
#define TEST_TYPE          1
#define TEST_LEN           1
#define TEST_VALUE         1
#define INIT_VALUE         1
constexpr char TEST_PKGNAME[] = "testname";
constexpr char TEST_MSG[] = "testmsg";
constexpr char TEST_PROOFINFO[] = "testproofinfo";
constexpr char TEST_DEVICE[] = "14a0a92a428005db2";
constexpr char TEST_SESSIONNAME[] = "testsessionname";
constexpr int32_t REFRESHID = 7;
constexpr int32_t REASON = 8;
constexpr int32_t PUBLISHID = 8;
constexpr int32_t PID = 8;
constexpr int32_t ERRCODE = 7;
constexpr int32_t RETCODE = 7;
constexpr int32_t CHANNELID = 7;
constexpr int32_t CHANNELTYPE = 7;
constexpr int32_t INFOLEN = 1;
constexpr int32_t DEVICELEN = 5;
constexpr int32_t INFOTYPELEN = 8;
constexpr int32_t MSGLEN = 8;
constexpr int32_t PROOFLEN = 7;
constexpr int32_t DEVICETYPEID = 1;

class ClientProxyTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void ClientProxyTest::SetUpTestCase() { }

void ClientProxyTest::TearDownTestCase() { }

void ClientProxyTest::SetUp() { }

void ClientProxyTest::TearDown() { }

/*
 * @tc.name: OnJoinLNNResult
 * @tc.desc: bus center client proxy standard
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientProxyTest, OnJoinLNNResultTest_01, TestSize.Level1)
{
    static const uint32_t SOFTBUS_SA_ID = 4700;
    sptr<ISystemAbilityManager> saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> remoteObject = saManager->GetSystemAbility(SOFTBUS_SA_ID);
    ASSERT_TRUE(remoteObject != nullptr);
    sptr<BusCenterClientProxy> clientProxy = new (std::nothrow) BusCenterClientProxy(remoteObject);
    ASSERT_TRUE(clientProxy != nullptr);
    char *addr = const_cast<char *>(TEST_ADDR);
    void *addrInput = reinterpret_cast<void *>(addr);
    int32_t ret = clientProxy->OnJoinLNNResult(nullptr, TEST_ADDR_TYPE_LEN, TEST_NETWORK_ID, TEST_RET_CODE);
    EXPECT_NE(ret, SOFTBUS_OK);
    ret = clientProxy->OnJoinLNNResult(addrInput, TEST_ADDR_TYPE_LEN, nullptr, TEST_RET_CODE);
    EXPECT_NE(ret, SOFTBUS_OK);
    ret = clientProxy->OnJoinLNNResult(addrInput, TEST_ADDR_TYPE_LEN, TEST_NETWORK_ID, TEST_RET_CODE);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: OnLeaveLNNResult
 * @tc.desc: bus center client proxy standard
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientProxyTest, OnLeaveLNNResultTest_01, TestSize.Level1)
{
    static const uint32_t SOFTBUS_SA_ID = 4700;
    sptr<ISystemAbilityManager> saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> remoteObject = saManager->GetSystemAbility(SOFTBUS_SA_ID);
    ASSERT_TRUE(remoteObject != nullptr);
    sptr<BusCenterClientProxy> clientProxy = new (std::nothrow) BusCenterClientProxy(remoteObject);
    ASSERT_TRUE(clientProxy != nullptr);
    int32_t ret = clientProxy->OnLeaveLNNResult(nullptr, TEST_RET_CODE);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = clientProxy->OnLeaveLNNResult(TEST_NETWORK_ID, TEST_RET_CODE);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: OnNodeOnlineStateChanged
 * @tc.desc: bus center client proxy standard
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientProxyTest, OnNodeOnlineStateChangedTest_01, TestSize.Level1)
{
    static const uint32_t SOFTBUS_SA_ID = 4700;
    sptr<ISystemAbilityManager> saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> remoteObject = saManager->GetSystemAbility(SOFTBUS_SA_ID);
    ASSERT_TRUE(remoteObject != nullptr);
    sptr<BusCenterClientProxy> clientProxy = new (std::nothrow) BusCenterClientProxy(remoteObject);
    ASSERT_TRUE(clientProxy != nullptr);
    bool isOnline = false;
    char *addr = const_cast<char *>(TEST_ADDR);
    void *addrInput = reinterpret_cast<void *>(addr);
    int32_t ret = clientProxy->OnNodeOnlineStateChanged("test", isOnline, nullptr, TEST_ADDR_TYPE_LEN);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = clientProxy->OnNodeOnlineStateChanged("test", isOnline, addrInput, TEST_ADDR_TYPE_LEN);
    EXPECT_FALSE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: OnNodeBasicInfoChanged
 * @tc.desc: bus center client proxy standard
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientProxyTest, OnNodeBasicInfoChangedTest_01, TestSize.Level1)
{
    static const uint32_t SOFTBUS_SA_ID = 4700;
    sptr<ISystemAbilityManager> saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> remoteObject = saManager->GetSystemAbility(SOFTBUS_SA_ID);
    ASSERT_TRUE(remoteObject != nullptr);
    sptr<BusCenterClientProxy> clientProxy = new (std::nothrow) BusCenterClientProxy(remoteObject);
    ASSERT_TRUE(clientProxy != nullptr);
    char *addr = const_cast<char *>(TEST_ADDR);
    void *addrInput = reinterpret_cast<void *>(addr);
    int32_t ret = clientProxy->OnNodeBasicInfoChanged("test", nullptr, TEST_ADDR_TYPE_LEN, TEST_TYPE);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = clientProxy->OnNodeBasicInfoChanged("test", addrInput, TEST_ADDR_TYPE_LEN, TEST_TYPE);
    EXPECT_FALSE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: OnTimeSyncResult
 * @tc.desc: bus center client proxy standard
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientProxyTest, OnTimeSyncResultTest_01, TestSize.Level1)
{
    static const uint32_t SOFTBUS_SA_ID = 4700;
    sptr<ISystemAbilityManager> saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> remoteObject = saManager->GetSystemAbility(SOFTBUS_SA_ID);
    ASSERT_TRUE(remoteObject != nullptr);
    sptr<BusCenterClientProxy> clientProxy = new (std::nothrow) BusCenterClientProxy(remoteObject);
    ASSERT_TRUE(clientProxy != nullptr);
    char *addr = const_cast<char *>(TEST_ADDR);
    void *addrInput = reinterpret_cast<void *>(addr);
    int32_t ret = clientProxy->OnTimeSyncResult(nullptr, TEST_ADDR_TYPE_LEN, TEST_RET_CODE);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = clientProxy->OnTimeSyncResult(addrInput, TEST_ADDR_TYPE_LEN, TEST_RET_CODE);
    EXPECT_FALSE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: OnPublishLNNResult
 * @tc.desc: bus center client proxy standard
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientProxyTest, OnPublishLNNResultTest_01, TestSize.Level1)
{
    static const uint32_t SOFTBUS_SA_ID = 4700;
    sptr<ISystemAbilityManager> saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> remoteObject = saManager->GetSystemAbility(SOFTBUS_SA_ID);
    ASSERT_TRUE(remoteObject != nullptr);
    sptr<BusCenterClientProxy> clientProxy = new (std::nothrow) BusCenterClientProxy(remoteObject);
    ASSERT_TRUE(clientProxy != nullptr);
    clientProxy->OnPublishLNNResult(TEST_RET_CODE, TEST_RET_CODE);

    int32_t ret = ClientOnRefreshLNNResult(TEST_PKGNAME, 0, PUBLISHID, REASON);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: ClientOnRefreshLNNResult
 * @tc.desc: bus center client proxy
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientProxyTest, ClientOnRefreshLNNResult_01, TestSize.Level1)
{
    static const uint32_t SOFTBUS_SA_ID = 4700;
    sptr<ISystemAbilityManager> saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> remoteObject = saManager->GetSystemAbility(SOFTBUS_SA_ID);
    ASSERT_TRUE(remoteObject != nullptr);
    sptr<BusCenterClientProxy> clientProxy = new (std::nothrow) BusCenterClientProxy(remoteObject);
    ASSERT_TRUE(clientProxy != nullptr);
    clientProxy->OnRefreshLNNResult(TEST_RET_CODE, TEST_RET_CODE);

    int32_t ret = ClientOnRefreshLNNResult(TEST_PKGNAME, 0, REFRESHID, REASON);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: ClientOnRefreshDeviceFound
 * @tc.desc: bus center client proxy
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientProxyTest, ClientOnRefreshDeviceFound_01, TestSize.Level1)
{
    static const uint32_t SOFTBUS_SA_ID = 4700;
    sptr<ISystemAbilityManager> saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> remoteObject = saManager->GetSystemAbility(SOFTBUS_SA_ID);
    ASSERT_TRUE(remoteObject != nullptr);
    sptr<BusCenterClientProxy> clientProxy = new (std::nothrow) BusCenterClientProxy(remoteObject);
    ASSERT_TRUE(clientProxy != nullptr);
    char *addr = const_cast<char *>(TEST_ADDR);
    void *addrInput = reinterpret_cast<void *>(addr);
    clientProxy->OnRefreshDeviceFound(addrInput, TEST_ADDR_TYPE_LEN);

    const void *device = "1234";
    uint32_t deviceLen = DEVICELEN;
    int32_t ret = ClientOnRefreshDeviceFound(TEST_PKGNAME, 0, device, deviceLen);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: ClientOnJoinLNNResult_01
 * @tc.desc: bus center client proxy
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientProxyTest, ClientOnJoinLNNResult_01, TestSize.Level1)
{
    char *testAddr = const_cast<char *>(TEST_ADDR);
    void *addr = reinterpret_cast<void *>(testAddr);
    const char *networkId = TEST_NETWORK_ID;
    int32_t ret = ClientOnJoinLNNResult(nullptr, addr, TEST_ADDR_TYPE_LEN, networkId, TEST_RET_CODE);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: ClientOnLeaveLNNResult_01
 * @tc.desc: bus center client proxy
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientProxyTest, ClientOnLeaveLNNResult_01, TestSize.Level1)
{
    const char *networkId = TEST_NETWORK_ID;
    int32_t ret = ClientOnLeaveLNNResult(nullptr, PID, networkId, TEST_RET_CODE);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: ClinetOnNodeOnlineStateChanged_01
 * @tc.desc: bus center client proxy
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientProxyTest, ClinetOnNodeOnlineStateChanged_01, TestSize.Level1)
{
    bool isOnline = true;
    char *testInfo = const_cast<char *>(TEST_INFO);
    void *info = reinterpret_cast<void *>(testInfo);
    int32_t ret = ClinetOnNodeOnlineStateChanged(isOnline, info, INFOTYPELEN);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: ClinetOnNodeBasicInfoChanged_01
 * @tc.desc: bus center client proxy
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientProxyTest, ClinetOnNodeBasicInfoChanged_01, TestSize.Level1)
{
    char *testInfo = const_cast<char *>(TEST_INFO);
    void *info = reinterpret_cast<void *>(testInfo);
    int32_t ret = ClinetOnNodeBasicInfoChanged(info, INFOTYPELEN, TEST_TYPE);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: ClientOnNodeStatusChanged_01
 * @tc.desc: bus center client proxy
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientProxyTest, ClientOnNodeStatusChanged_01, TestSize.Level1)
{
    char *testInfo = const_cast<char *>(TEST_INFO);
    void *info = reinterpret_cast<void *>(testInfo);
    int32_t ret = ClientOnNodeStatusChanged(info, INFOTYPELEN, TEST_TYPE);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_REMOTE_NULL);
}

/*
 * @tc.name: ClinetNotifyDeviceTrustedChange_01
 * @tc.desc: bus center client proxy
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientProxyTest, ClinetNotifyDeviceTrustedChange_01, TestSize.Level1)
{
    int32_t ret = ClinetNotifyDeviceTrustedChange(TEST_TYPE, TEST_MSG, MSGLEN);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: ClientNotifyHichainProofException_01
 * @tc.desc: bus center client proxy
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientProxyTest, ClientNotifyHichainProofException_01, TestSize.Level1)
{
    int32_t ret = ClientNotifyHichainProofException(TEST_PROOFINFO, PROOFLEN, DEVICETYPEID, ERRCODE);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: ClientOnTimeSyncResult_01
 * @tc.desc: bus center client proxy
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientProxyTest, ClientOnTimeSyncResult_01, TestSize.Level1)
{
    const void *info = TEST_INFO;
    int32_t ret = ClientOnTimeSyncResult(nullptr, PID, info, INFOTYPELEN, RETCODE);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: ClientOnTimeSyncResult_02
 * @tc.desc: bus center client proxy
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientProxyTest, ClientOnTimeSyncResult_02, TestSize.Level1)
{
    const void *info = TEST_INFO;
    int32_t ret = ClientOnTimeSyncResult(TEST_PKGNAME, PID, info, INFOTYPELEN, RETCODE);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_REMOTE_NULL);
}

/*
 * @tc.name: ClientOnPublishLNNResult_01
 * @tc.desc: bus center client proxy
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientProxyTest, ClientOnPublishLNNResult_01, TestSize.Level1)
{
    int32_t ret = ClientOnPublishLNNResult(nullptr, PID, PUBLISHID, REASON);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: ClientOnPublishLNNResult_02
 * @tc.desc: bus center client proxy
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientProxyTest, ClientOnPublishLNNResult_02, TestSize.Level1)
{
    static const uint32_t SOFTBUS_SA_ID = 4700;
    sptr<ISystemAbilityManager> saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> remoteObject = saManager->GetSystemAbility(SOFTBUS_SA_ID);
    ASSERT_TRUE(remoteObject != nullptr);
    sptr<BusCenterClientProxy> clientProxy = new (std::nothrow) BusCenterClientProxy(remoteObject);
    ASSERT_TRUE(clientProxy != nullptr);
    clientProxy->OnPublishLNNResult(PUBLISHID, REASON);
    int32_t ret = ClientOnPublishLNNResult(TEST_PKGNAME, PID, PUBLISHID, REASON);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: ClientOnRefreshLNNResult_02
 * @tc.desc: bus center client proxy
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientProxyTest, ClientOnRefreshLNNResult_02, TestSize.Level1)
{
    int32_t ret = ClientOnRefreshLNNResult(nullptr, PID, REFRESHID, REASON);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: ClientOnRefreshDeviceFound_02
 * @tc.desc: bus center client proxy
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientProxyTest, ClientOnRefreshDeviceFound_02, TestSize.Level1)
{
    const void *device = TEST_DEVICE;
    int32_t ret = ClientOnRefreshDeviceFound(nullptr, PID, device, DEVICELEN);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: ClientOnDataLevelChanged_01
 * @tc.desc: bus center client proxy
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientProxyTest, ClientOnDataLevelChanged_01, TestSize.Level1)
{
    const char *networkId = TEST_NETWORK_ID;
    DataLevelInfo *dataLevelInfo = (DataLevelInfo *)SoftBusMalloc(sizeof(DataLevelInfo));
    ASSERT_TRUE(dataLevelInfo != nullptr);
    int32_t ret = ClientOnDataLevelChanged(nullptr, PID, networkId, dataLevelInfo);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    SoftBusFree(dataLevelInfo);
}

/*
 * @tc.name: ClientOnDataLevelChanged_02
 * @tc.desc: bus center client proxy
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientProxyTest, ClientOnDataLevelChanged_02, TestSize.Level1)
{
    DataLevelInfo *dataLevelInfo = (DataLevelInfo *)SoftBusMalloc(sizeof(DataLevelInfo));
    ASSERT_TRUE(dataLevelInfo != nullptr);
    int32_t ret = ClientOnDataLevelChanged(TEST_PKGNAME, PID, nullptr, dataLevelInfo);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    SoftBusFree(dataLevelInfo);
}

/*
 * @tc.name: ClientOnDataLevelChanged_03
 * @tc.desc: bus center client proxy
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientProxyTest, ClientOnDataLevelChanged_03, TestSize.Level1)
{
    const char *networkId = TEST_NETWORK_ID;
    static const uint32_t SOFTBUS_SA_ID = 4700;
    sptr<ISystemAbilityManager> saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> remoteObject = saManager->GetSystemAbility(SOFTBUS_SA_ID);
    ASSERT_TRUE(remoteObject != nullptr);
    sptr<BusCenterClientProxy> clientProxy = new (std::nothrow) BusCenterClientProxy(remoteObject);
    ASSERT_TRUE(clientProxy != nullptr);
    DataLevelInfo *dataLevelInfo = (DataLevelInfo *)SoftBusMalloc(sizeof(DataLevelInfo));
    ASSERT_TRUE(dataLevelInfo != nullptr);
    int32_t ret = ClientOnDataLevelChanged(TEST_PKGNAME, PID, networkId, dataLevelInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(dataLevelInfo);
}

/*
 * @tc.name: OnChannelOpened_01
 * @tc.desc: bus center client proxy standard
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientProxyTest, OnChannelOpened_01, TestSize.Level1)
{
    static const uint32_t SOFTBUS_SA_ID = 4700;
    sptr<ISystemAbilityManager> saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> remoteObject = saManager->GetSystemAbility(SOFTBUS_SA_ID);
    ASSERT_TRUE(remoteObject != nullptr);
    sptr<BusCenterClientProxy> clientProxy = new (std::nothrow) BusCenterClientProxy(remoteObject);
    ASSERT_TRUE(clientProxy != nullptr);
    ChannelInfo *info = (ChannelInfo *)SoftBusMalloc(sizeof(ChannelInfo));
    ASSERT_TRUE(info != nullptr);
    int32_t ret = clientProxy->OnChannelOpened(TEST_SESSIONNAME, info);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(info);
}

/*
 * @tc.name: OnChannelOpenFailed_01
 * @tc.desc: bus center client proxy standard
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientProxyTest, OnChannelOpenFailed_01, TestSize.Level1)
{
    static const uint32_t SOFTBUS_SA_ID = 4700;
    sptr<ISystemAbilityManager> saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> remoteObject = saManager->GetSystemAbility(SOFTBUS_SA_ID);
    ASSERT_TRUE(remoteObject != nullptr);
    sptr<BusCenterClientProxy> clientProxy = new (std::nothrow) BusCenterClientProxy(remoteObject);
    ASSERT_TRUE(clientProxy != nullptr);
    int32_t ret = clientProxy->OnChannelOpenFailed(CHANNELID, CHANNELTYPE, ERRCODE);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: OnChannelLinkDown_01
 * @tc.desc: bus center client proxy standard
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientProxyTest, OnChannelLinkDown_01, TestSize.Level1)
{
    static const uint32_t SOFTBUS_SA_ID = 4700;
    static const int32_t ROUTETYPE = 7;
    sptr<ISystemAbilityManager> saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> remoteObject = saManager->GetSystemAbility(SOFTBUS_SA_ID);
    ASSERT_TRUE(remoteObject != nullptr);
    sptr<BusCenterClientProxy> clientProxy = new (std::nothrow) BusCenterClientProxy(remoteObject);
    ASSERT_TRUE(clientProxy != nullptr);
    int32_t ret = clientProxy->OnChannelLinkDown(TEST_NETWORK_ID, ROUTETYPE);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: OnChannelClosed_01
 * @tc.desc: bus center client proxy standard
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientProxyTest, OnChannelClosed_01, TestSize.Level1)
{
    static const uint32_t SOFTBUS_SA_ID = 4700;
    static const int32_t MESSAGETYPE = 7;
    sptr<ISystemAbilityManager> saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> remoteObject = saManager->GetSystemAbility(SOFTBUS_SA_ID);
    ASSERT_TRUE(remoteObject != nullptr);
    sptr<BusCenterClientProxy> clientProxy = new (std::nothrow) BusCenterClientProxy(remoteObject);
    ASSERT_TRUE(clientProxy != nullptr);
    int32_t ret = clientProxy->OnChannelClosed(CHANNELID, CHANNELTYPE, MESSAGETYPE);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: OnChannelMsgReceived_01
 * @tc.desc: bus center client proxy standard
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientProxyTest, OnChannelMsgReceived_01, TestSize.Level1)
{
    const void *dataInfo = TEST_DEVICE;
    static const uint32_t SOFTBUS_SA_ID = 4700;
    sptr<ISystemAbilityManager> saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> remoteObject = saManager->GetSystemAbility(SOFTBUS_SA_ID);
    ASSERT_TRUE(remoteObject != nullptr);
    sptr<BusCenterClientProxy> clientProxy = new (std::nothrow) BusCenterClientProxy(remoteObject);
    ASSERT_TRUE(clientProxy != nullptr);
    int32_t ret = clientProxy->OnChannelMsgReceived(CHANNELID, CHANNELTYPE, dataInfo, TEST_LEN, TEST_TYPE);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: OnChannelQosEvent_01
 * @tc.desc: bus center client proxy standard
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientProxyTest, OnChannelQosEvent_01, TestSize.Level1)
{
    static const int32_t EVENTID = 7;
    static const int32_t TVCOUNT = 7;
    static const uint32_t SOFTBUS_SA_ID = 4700;
    sptr<ISystemAbilityManager> saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> remoteObject = saManager->GetSystemAbility(SOFTBUS_SA_ID);
    ASSERT_TRUE(remoteObject != nullptr);
    sptr<BusCenterClientProxy> clientProxy = new (std::nothrow) BusCenterClientProxy(remoteObject);
    ASSERT_TRUE(clientProxy != nullptr);
    QosTv *tvList = (QosTv *)SoftBusMalloc(sizeof(QosTv));
    ASSERT_TRUE(tvList != nullptr);
    int32_t ret = clientProxy->OnChannelQosEvent(CHANNELID, CHANNELTYPE, EVENTID, TVCOUNT, tvList);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(tvList);
}

/*
 * @tc.name: OnJoinMetaNodeResult_01
 * @tc.desc: bus center client proxy standard
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientProxyTest, OnJoinMetaNodeResult_01, TestSize.Level1)
{
    static const uint32_t SOFTBUS_SA_ID = 4700;
    char *testInfo = const_cast<char *>(TEST_INFO);
    void *metaInfo = reinterpret_cast<void *>(testInfo);
    sptr<ISystemAbilityManager> saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> remoteObject = saManager->GetSystemAbility(SOFTBUS_SA_ID);
    ASSERT_TRUE(remoteObject != nullptr);
    sptr<BusCenterClientProxy> clientProxy = new (std::nothrow) BusCenterClientProxy(remoteObject);
    ASSERT_TRUE(clientProxy != nullptr);
    int32_t ret = clientProxy->OnJoinMetaNodeResult(nullptr, TEST_ADDR_TYPE_LEN, nullptr, INFOLEN, RETCODE);
    EXPECT_NE(ret, SOFTBUS_OK);
    ret = clientProxy->OnJoinMetaNodeResult(nullptr, TEST_ADDR_TYPE_LEN, metaInfo, INFOLEN, RETCODE);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: OnLeaveMetaNodeResult_01
 * @tc.desc: bus center client proxy standard
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientProxyTest, OnLeaveMetaNodeResult_01, TestSize.Level1)
{
    static const uint32_t SOFTBUS_SA_ID = 4700;
    sptr<ISystemAbilityManager> saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> remoteObject = saManager->GetSystemAbility(SOFTBUS_SA_ID);
    ASSERT_TRUE(remoteObject != nullptr);
    sptr<BusCenterClientProxy> clientProxy = new (std::nothrow) BusCenterClientProxy(remoteObject);
    ASSERT_TRUE(clientProxy != nullptr);
    int32_t ret = clientProxy->OnLeaveMetaNodeResult(nullptr, TEST_RET_CODE);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = clientProxy->OnLeaveMetaNodeResult(TEST_NETWORK_ID, TEST_RET_CODE);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: OnNodeOnlineStateChanged_02
 * @tc.desc: bus center client proxy standard
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientProxyTest, OnNodeOnlineStateChangedTest_02, TestSize.Level1)
{
    static const uint32_t SOFTBUS_SA_ID = 4700;
    sptr<ISystemAbilityManager> saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> remoteObject = saManager->GetSystemAbility(SOFTBUS_SA_ID);
    ASSERT_TRUE(remoteObject != nullptr);
    sptr<BusCenterClientProxy> clientProxy = new (std::nothrow) BusCenterClientProxy(remoteObject);
    ASSERT_TRUE(clientProxy != nullptr);
    bool isOnline = false;
    char *addr = const_cast<char *>(TEST_ADDR);
    void *addrInput = reinterpret_cast<void *>(addr);
    int32_t ret = clientProxy->OnNodeOnlineStateChanged(nullptr, isOnline, addrInput, TEST_ADDR_TYPE_LEN);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: OnNodeBasicInfoChanged_02
 * @tc.desc: bus center client proxy standard
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientProxyTest, OnNodeBasicInfoChangedTest_02, TestSize.Level1)
{
    static const uint32_t SOFTBUS_SA_ID = 4700;
    sptr<ISystemAbilityManager> saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> remoteObject = saManager->GetSystemAbility(SOFTBUS_SA_ID);
    ASSERT_TRUE(remoteObject != nullptr);
    sptr<BusCenterClientProxy> clientProxy = new (std::nothrow) BusCenterClientProxy(remoteObject);
    ASSERT_TRUE(clientProxy != nullptr);
    char *addr = const_cast<char *>(TEST_ADDR);
    void *addrInput = reinterpret_cast<void *>(addr);
    int32_t ret = clientProxy->OnNodeBasicInfoChanged(nullptr, addrInput, TEST_ADDR_TYPE_LEN, TEST_TYPE);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = clientProxy->OnNodeBasicInfoChanged(TEST_PKGNAME, addrInput, TEST_ADDR_TYPE_LEN, TEST_TYPE);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: OnNodeStatusChanged_01
 * @tc.desc: bus center client proxy standard
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientProxyTest, OnNodeStatusChanged_01, TestSize.Level1)
{
    static const uint32_t SOFTBUS_SA_ID = 4700;
    sptr<ISystemAbilityManager> saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> remoteObject = saManager->GetSystemAbility(SOFTBUS_SA_ID);
    ASSERT_TRUE(remoteObject != nullptr);
    sptr<BusCenterClientProxy> clientProxy = new (std::nothrow) BusCenterClientProxy(remoteObject);
    ASSERT_TRUE(clientProxy != nullptr);
    char *info = const_cast<char *>(TEST_INFO);
    void *infoInput = reinterpret_cast<void *>(info);
    int32_t ret = clientProxy->OnNodeStatusChanged(nullptr, infoInput, TEST_ADDR_TYPE_LEN, TEST_TYPE);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = clientProxy->OnNodeStatusChanged(TEST_PKGNAME, nullptr, TEST_ADDR_TYPE_LEN, TEST_TYPE);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = clientProxy->OnNodeStatusChanged(TEST_PKGNAME, infoInput, TEST_ADDR_TYPE_LEN, TEST_TYPE);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_SEND_REQUEST_FAILED);
}

/*
 * @tc.name: OnLocalNetworkIdChanged_01
 * @tc.desc: bus center client proxy standard
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientProxyTest, OnLocalNetworkIdChanged_01, TestSize.Level1)
{
    static const uint32_t SOFTBUS_SA_ID = 4700;
    sptr<ISystemAbilityManager> saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> remoteObject = saManager->GetSystemAbility(SOFTBUS_SA_ID);
    ASSERT_TRUE(remoteObject != nullptr);
    sptr<BusCenterClientProxy> clientProxy = new (std::nothrow) BusCenterClientProxy(remoteObject);
    ASSERT_TRUE(clientProxy != nullptr);
    int32_t ret = clientProxy->OnLocalNetworkIdChanged(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = clientProxy->OnLocalNetworkIdChanged(TEST_PKGNAME);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: OnNodeDeviceTrustedChange_01
 * @tc.desc: bus center client proxy standard
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientProxyTest, OnNodeDeviceTrustedChange_01, TestSize.Level1)
{
    static const uint32_t SOFTBUS_SA_ID = 4700;
    sptr<ISystemAbilityManager> saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> remoteObject = saManager->GetSystemAbility(SOFTBUS_SA_ID);
    ASSERT_TRUE(remoteObject != nullptr);
    sptr<BusCenterClientProxy> clientProxy = new (std::nothrow) BusCenterClientProxy(remoteObject);
    ASSERT_TRUE(clientProxy != nullptr);
    int32_t ret = clientProxy->OnNodeDeviceTrustedChange(nullptr, TEST_TYPE, TEST_MSG, MSGLEN);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = clientProxy->OnNodeDeviceTrustedChange(TEST_PKGNAME, TEST_TYPE, nullptr, MSGLEN);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = clientProxy->OnNodeDeviceTrustedChange(TEST_PKGNAME, TEST_TYPE, TEST_MSG, MSGLEN);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: OnHichainProofException_01
 * @tc.desc: bus center client proxy standard
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientProxyTest, OnHichainProofException_01, TestSize.Level1)
{
    static const uint32_t SOFTBUS_SA_ID = 4700;
    sptr<ISystemAbilityManager> saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> remoteObject = saManager->GetSystemAbility(SOFTBUS_SA_ID);
    ASSERT_TRUE(remoteObject != nullptr);
    sptr<BusCenterClientProxy> clientProxy = new (std::nothrow) BusCenterClientProxy(remoteObject);
    ASSERT_TRUE(clientProxy != nullptr);
    int32_t ret = clientProxy->OnHichainProofException(nullptr, TEST_PROOFINFO, PROOFLEN, DEVICETYPEID, ERRCODE);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = clientProxy->OnHichainProofException(TEST_PKGNAME, TEST_PROOFINFO, 0, DEVICETYPEID, ERRCODE);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

} // namespace OHOS