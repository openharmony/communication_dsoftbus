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

#include <gtest/gtest.h>

#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "trans_client_proxy_standard.h"
#include "trans_type.h"

using namespace std;
using namespace testing::ext;

#define TEST_TMP_DATE 1
#define TEST_ERRTMP_DATE (-1)
#define SOFTBUS_SA_ID 4700

namespace OHOS {
class TransClientProxyStandardTest : public testing::Test {
public:
    TransClientProxyStandardTest() {}
    ~TransClientProxyStandardTest() {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override {}
    void TearDown() override {}
};

void TransClientProxyStandardTest::SetUpTestCase(void) {}
void TransClientProxyStandardTest::TearDownTestCase(void) {}

/**
 * @tc.name: InformPermissionChangeTest001
 * @tc.desc: trans client proxy standard test, use the normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientProxyStandardTest, TransClientProxyStandardTest001, TestSize.Level1)
{
    #define TEST_INVALID 0

    sptr<ISystemAbilityManager> saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> remoteObject = saManager->GetSystemAbility(SOFTBUS_SA_ID);
    ASSERT_TRUE(remoteObject != nullptr);
    sptr<TransClientProxy> clientProxy = new (std::nothrow) TransClientProxy(remoteObject);
    ASSERT_TRUE(clientProxy != nullptr);

    int32_t tmp = TEST_INVALID;

    void *addr = nullptr;
    uint32_t addrTypeLen = TEST_INVALID;
    void *metaInfo = nullptr;
    uint32_t infoLen = TEST_INVALID;
    const char *networkId = nullptr;
    int32_t ret = clientProxy->OnJoinLNNResult(addr, addrTypeLen, networkId, tmp);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = clientProxy->OnJoinMetaNodeResult(addr, addrTypeLen, metaInfo, infoLen, tmp);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = clientProxy->OnLeaveLNNResult(networkId, tmp);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = clientProxy->OnLeaveMetaNodeResult(networkId, tmp);
    EXPECT_EQ(SOFTBUS_OK, ret);

    bool isOnline = false;
    ret = clientProxy->OnNodeOnlineStateChanged("test", isOnline, addr, addrTypeLen);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = clientProxy->OnNodeBasicInfoChanged("test", addr, addrTypeLen, tmp);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = clientProxy->OnTimeSyncResult(addr, addrTypeLen, tmp);
    EXPECT_EQ(SOFTBUS_OK, ret);

    clientProxy->OnPublishLNNResult(tmp, tmp);

    clientProxy->OnRefreshLNNResult(tmp, tmp);

    clientProxy->OnRefreshDeviceFound(addr, addrTypeLen);
}

/**
 * @tc.name: InformPermissionChangeTest002
 * @tc.desc: trans client proxy standard test, use the normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientProxyStandardTest, TransClientProxyStandardTest002, TestSize.Level1)
{
    const char *pkgName = "dms";
    sptr<ISystemAbilityManager> saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> remoteObject = saManager->GetSystemAbility(SOFTBUS_SA_ID);
    ASSERT_TRUE(remoteObject != nullptr);
    sptr<TransClientProxy> clientProxy = new (std::nothrow) TransClientProxy(remoteObject);
    ASSERT_TRUE(clientProxy != nullptr);

    int32_t ret = clientProxy->OnChannelLinkDown(nullptr, TEST_TMP_DATE);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = clientProxy->OnClientPermissionChange(nullptr, TEST_TMP_DATE);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    
    ret = clientProxy->OnClientPermissionChange(pkgName, TEST_ERRTMP_DATE);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: OnCheckCollabRelation001
 * @tc.desc: trans client proxy standard test, use the normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientProxyStandardTest, TransClientProxyStandardTest003, TestSize.Level1)
{
    sptr<ISystemAbilityManager> saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> remoteObject = saManager->GetSystemAbility(SOFTBUS_SA_ID);
    ASSERT_TRUE(remoteObject != nullptr);
    sptr<TransClientProxy> clientProxy = new (std::nothrow) TransClientProxy(remoteObject);
    ASSERT_TRUE(clientProxy != nullptr);

    int32_t ret = clientProxy->OnCheckCollabRelation(nullptr, false, nullptr, 1, 1);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    CollabInfo sourceInfo = {};
    CollabInfo sinkInfo = {};

    ret = clientProxy->OnCheckCollabRelation(&sourceInfo, false, nullptr, 1, 1);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = clientProxy->OnCheckCollabRelation(&sourceInfo, false, &sinkInfo, 1, 1);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_SEND_REQUEST_FAILED, ret);
}

/**
 * @tc.name: OnChannelOpened001
 * @tc.desc: trans client proxy standard test, use the normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientProxyStandardTest, TransClientProxyStandardTest004, TestSize.Level1)
{
    sptr<ISystemAbilityManager> saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> remoteObject = saManager->GetSystemAbility(SOFTBUS_SA_ID);
    ASSERT_TRUE(remoteObject != nullptr);
    sptr<TransClientProxy> clientProxy = new (std::nothrow) TransClientProxy(remoteObject);
    ASSERT_TRUE(clientProxy != nullptr);

    ChannelInfo channel = {0};
    const char *sessionName = "testSessionName";
    int32_t ret = clientProxy->OnChannelOpened(nullptr, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = clientProxy->OnChannelOpened(sessionName, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = clientProxy->OnChannelOpened(sessionName, &channel);
    EXPECT_EQ(SOFTBUS_IPC_ERR, ret);
    channel.isServer = true;
    ret = clientProxy->OnChannelOpened(sessionName, &channel);
    EXPECT_EQ(SOFTBUS_IPC_ERR, ret);
}

/**
 * @tc.name: SetChannelInfo001
 * @tc.desc: trans client proxy standard test, use the normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientProxyStandardTest, TransClientProxyStandardTest005, TestSize.Level1)
{
    sptr<ISystemAbilityManager> saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> remoteObject = saManager->GetSystemAbility(SOFTBUS_SA_ID);
    ASSERT_TRUE(remoteObject != nullptr);
    sptr<TransClientProxy> clientProxy = new (std::nothrow) TransClientProxy(remoteObject);
    ASSERT_TRUE(clientProxy != nullptr);

    const char *sessionName = "testSessionName";
    int32_t ret = clientProxy->SetChannelInfo(sessionName, 1, 1, 1);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_SEND_REQUEST_FAILED, ret);

    ret = clientProxy->SetChannelInfo(nullptr, 1, 1, 1);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**
 * @tc.name: OnClientChannelOnQos001
 * @tc.desc: OnClientChannelOnQos test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientProxyStandardTest, TransClientProxyStandardTest006, TestSize.Level1)
{
    sptr<ISystemAbilityManager> saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> remoteObject = saManager->GetSystemAbility(SOFTBUS_SA_ID);
    ASSERT_TRUE(remoteObject != nullptr);
    sptr<TransClientProxy> clientProxy = new (std::nothrow) TransClientProxy(remoteObject);
    ASSERT_TRUE(clientProxy != nullptr);

    int32_t channelId = 1;
    int32_t channelType = 1;
    QoSEvent event = QOS_SATISFIED;
    const QosTV *qos = nullptr;
    uint32_t count = 1;

    int32_t ret = clientProxy->OnClientChannelOnQos(channelId, channelType, event, qos, count);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**
 * @tc.name: OnBrProxyOpenedQos001
 * @tc.desc: OnBrProxyOpened test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientProxyStandardTest, TransClientProxyStandardTest007, TestSize.Level1)
{
    sptr<ISystemAbilityManager> saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> remoteObject = saManager->GetSystemAbility(SOFTBUS_SA_ID);
    ASSERT_TRUE(remoteObject != nullptr);
    sptr<TransClientProxy> clientProxy = new (std::nothrow) TransClientProxy(remoteObject);
    ASSERT_TRUE(clientProxy != nullptr);

    int32_t channelId = 1;
    int32_t reason = 1;

    int32_t ret = clientProxy->OnBrProxyOpened(channelId, nullptr, nullptr, reason);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    const char *brMac = "11:22:33"; // test value
    const char *uuid = "111111"; // test value
    ret = clientProxy->OnBrProxyOpened(channelId, brMac, uuid, reason);
    EXPECT_NE(SOFTBUS_INVALID_PARAM, ret);
}

/**
 * @tc.name: OnBrProxyDataRecv001
 * @tc.desc: OnBrProxyDataRecv test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientProxyStandardTest, TransClientProxyStandardTest008, TestSize.Level1)
{
    sptr<ISystemAbilityManager> saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> remoteObject = saManager->GetSystemAbility(SOFTBUS_SA_ID);
    ASSERT_TRUE(remoteObject != nullptr);
    sptr<TransClientProxy> clientProxy = new (std::nothrow) TransClientProxy(remoteObject);
    ASSERT_TRUE(clientProxy != nullptr);

    int32_t channelId = 1;
    int32_t len = 1;

    int32_t ret = clientProxy->OnBrProxyDataRecv(channelId, nullptr, len);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    uint8_t data = 1;
    ret = clientProxy->OnBrProxyDataRecv(channelId, &data, len);
    EXPECT_NE(SOFTBUS_INVALID_PARAM, ret);
}

/**
 * @tc.name: OnBrProxyStateChanged001
 * @tc.desc: OnBrProxyStateChanged test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientProxyStandardTest, TransClientProxyStandardTest009, TestSize.Level1)
{
    sptr<ISystemAbilityManager> saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> remoteObject = saManager->GetSystemAbility(SOFTBUS_SA_ID);
    ASSERT_TRUE(remoteObject != nullptr);
    sptr<TransClientProxy> clientProxy = new (std::nothrow) TransClientProxy(remoteObject);
    ASSERT_TRUE(clientProxy != nullptr);

    int32_t channelId = 1;
    int32_t channelState = 1;

    int32_t ret = clientProxy->OnBrProxyStateChanged(channelId, channelState);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**
 * @tc.name: OnBrProxyQueryPermission001
 * @tc.desc: OnBrProxyQueryPermission test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientProxyStandardTest, TransClientProxyStandardTest010, TestSize.Level1)
{
    sptr<ISystemAbilityManager> saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> remoteObject = saManager->GetSystemAbility(SOFTBUS_SA_ID);
    ASSERT_TRUE(remoteObject != nullptr);
    sptr<TransClientProxy> clientProxy = new (std::nothrow) TransClientProxy(remoteObject);
    ASSERT_TRUE(clientProxy != nullptr);

    const char *bundleName = "testName";
    bool isEmpowered = true;

    int32_t ret = clientProxy->OnBrProxyQueryPermission(bundleName, &isEmpowered);
    EXPECT_NE(SOFTBUS_OK, ret);

    clientProxy->OnDataLevelChanged(nullptr, nullptr);
    clientProxy->OnMsdpRangeResult(nullptr);
}
} // namespace OHOS