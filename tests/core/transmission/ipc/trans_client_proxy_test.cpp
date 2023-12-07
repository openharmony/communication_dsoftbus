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
#include "securec.h"

#include "trans_client_proxy.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "iservice_registry.h"
#include "if_system_ability_manager.h"
#include "iremote_object.h"
#include "softbus_server_death_recipient.h"
#include "softbus_client_info_manager.h"
#include "ipc_skeleton.h"
#include "softbus_trans_def.h"
#include "session.h"
#include "softbus_adapter_mem.h"


using namespace std;
using namespace testing::ext;

namespace OHOS {
#define TEST_ERR_PID (-1)
#define TEST_LEN 10
#define TEST_DATA_TYPE 0
#define TEST_PID 2
#define TEST_STATE 1
#define TEST_ERR_CODE 1
#define TEST_CHANNELID 5
#define TEST_CHANNELTYPE 2
#define TEST_REMOTE_TYPE 0
#define TEST_EVENT_ID 2
#define TEST_COUNT 2

const char *g_pkgName = "dms";
const char *g_sessionName = "ohos.distributedschedule.dms.test";
const char *g_errPkgName = "abc";

class TransClientProxyTest : public testing::Test {
public:
    TransClientProxyTest() {}
    ~TransClientProxyTest() {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override {}
    void TearDown() override {}
};

void TransClientProxyTest::SetUpTestCase(void) {}
void TransClientProxyTest::TearDownTestCase(void) {}

/**
 * @tc.name: InformPermissionChangeTest001
 * @tc.desc: information permission change test, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientProxyTest, InformPermissionChangeTest001, TestSize.Level0)
{
    int32_t ret;

    ret = InformPermissionChange(TEST_STATE, nullptr, TEST_PID);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    ret = InformPermissionChange(TEST_STATE, g_pkgName, TEST_PID);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    static const uint32_t SOFTBUS_SA_ID = 4700;
    sptr<ISystemAbilityManager> saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> remoteObject = saManager->GetSystemAbility(SOFTBUS_SA_ID);
    ASSERT_TRUE(remoteObject != nullptr);
    sptr<IRemoteObject::DeathRecipient> abilityDeath = new (std::nothrow) SoftBusDeathRecipient();
    ASSERT_TRUE(abilityDeath != nullptr);
    ret = SoftbusClientInfoManager::GetInstance().SoftbusAddService(g_pkgName, remoteObject, abilityDeath, TEST_PID);
    ASSERT_TRUE(ret == SOFTBUS_OK);
    ret = InformPermissionChange(TEST_STATE, g_pkgName, TEST_PID);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: ClientIpcOnChannelOpenedTest001
 * @tc.desc: client ipc on channel opened test, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientProxyTest, ClientIpcOnChannelOpenedTest001, TestSize.Level0)
{
    int32_t ret;
    ChannelInfo channel;
    char strTmp[] = "ABCDEFG";
    channel.channelId = TEST_CHANNELID;
    channel.channelType = TEST_CHANNELTYPE;
    channel.fd = TEST_DATA_TYPE;
    channel.isServer = true;
    channel.isEnabled = true;
    channel.peerUid = TEST_CHANNELID;
    channel.peerPid = TEST_CHANNELID;
    channel.groupId = strTmp;
    channel.sessionKey = strTmp;
    channel.keyLen = sizeof(channel.sessionKey);
    channel.peerSessionName = strTmp;
    channel.peerDeviceId = strTmp;
    channel.businessType = TEST_COUNT;
    channel.myIp = strTmp;
    channel.streamType = TEST_COUNT;
    channel.isUdpFile = true;
    channel.peerPort = TEST_COUNT;
    channel.peerIp = strTmp;
    channel.routeType = TEST_DATA_TYPE;
    channel.encrypt = TEST_COUNT;
    channel.algorithm = TEST_COUNT;
    channel.crc = TEST_COUNT;

    ret = ClientIpcOnChannelOpened(g_pkgName, g_sessionName, &channel, TEST_PID);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    static const uint32_t SOFTBUS_SA_ID = 4700;
    sptr<ISystemAbilityManager> saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> remoteObject = saManager->GetSystemAbility(SOFTBUS_SA_ID);
    ASSERT_TRUE(remoteObject != nullptr);
    sptr<IRemoteObject::DeathRecipient> abilityDeath = new (std::nothrow) SoftBusDeathRecipient();
    ASSERT_TRUE(abilityDeath != nullptr);
    ret = SoftbusClientInfoManager::GetInstance().SoftbusAddService(g_pkgName, remoteObject, abilityDeath, TEST_PID);
    ASSERT_TRUE(ret == SOFTBUS_OK);
    ret = ClientIpcOnChannelOpened(g_pkgName, g_sessionName, &channel, TEST_PID);
    EXPECT_EQ(SOFTBUS_ERR, ret);
    
    channel.isServer = false;
    ret = ClientIpcOnChannelOpened(g_pkgName, g_sessionName, &channel, TEST_PID);
    EXPECT_EQ(SOFTBUS_ERR, ret);
}

/**
 * @tc.name: ClientIpcOnChannelOpenFailedTest001
 * @tc.desc: client ipc on channel open failed test, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientProxyTest, ClientIpcOnChannelOpenFailedTest001, TestSize.Level0)
{
    int32_t ret;
    ChannelMsg data = {
        .msgChannelId = TEST_CHANNELID,
        .msgChannelType = TEST_CHANNELTYPE,
        .msgPid = TEST_PID,
        .msgPkgName = g_pkgName,
        .msgUuid = nullptr,
        .msgUdid = nullptr
    };
    ret = ClientIpcOnChannelOpenFailed(&data, TEST_ERR_CODE);
    EXPECT_EQ(SOFTBUS_OK, ret);

    static const uint32_t SOFTBUS_SA_ID = 4700;
    sptr<ISystemAbilityManager> saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> remoteObject = saManager->GetSystemAbility(SOFTBUS_SA_ID);
    ASSERT_TRUE(remoteObject != nullptr);
    sptr<IRemoteObject::DeathRecipient> abilityDeath = new (std::nothrow) SoftBusDeathRecipient();
    ASSERT_TRUE(abilityDeath != nullptr);
    ret = SoftbusClientInfoManager::GetInstance().SoftbusAddService(g_pkgName, remoteObject, abilityDeath, TEST_PID);
    ASSERT_TRUE(ret == SOFTBUS_OK);
    ChannelMsg msg = {
        .msgChannelId = TEST_CHANNELID,
        .msgChannelType = TEST_CHANNELTYPE,
        .msgPid = TEST_PID,
        .msgPkgName = g_pkgName,
        .msgUuid = nullptr,
        .msgUdid = nullptr
    };
    ret = ClientIpcOnChannelOpenFailed(&msg, TEST_ERR_CODE);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: ClientIpcOnChannelLinkDownTest001
 * @tc.desc: client ipc on channel link down test, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientProxyTest, ClientIpcOnChannelLinkDownTest001, TestSize.Level0)
{
    int32_t ret;
    char networkId[] = "ABCDEFG";

    ChannelMsg data = {
        .msgPid = TEST_PID,
        .msgPkgName = g_pkgName,
        .msgUuid = nullptr,
        .msgUdid = nullptr
    };
    ret = ClientIpcOnChannelLinkDown(&data, networkId, NULL, TEST_REMOTE_TYPE);
    EXPECT_EQ(SOFTBUS_OK, ret);

    static const uint32_t SOFTBUS_SA_ID = 4700;
    sptr<ISystemAbilityManager> saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> remoteObject = saManager->GetSystemAbility(SOFTBUS_SA_ID);
    ASSERT_TRUE(remoteObject != nullptr);
    sptr<IRemoteObject::DeathRecipient> abilityDeath = new (std::nothrow) SoftBusDeathRecipient();
    ASSERT_TRUE(abilityDeath != nullptr);
    ret = SoftbusClientInfoManager::GetInstance().SoftbusAddService(g_pkgName, remoteObject, abilityDeath, TEST_PID);
    ASSERT_TRUE(ret == SOFTBUS_OK);
    ChannelMsg msg = {
        .msgPid = TEST_PID,
        .msgPkgName = g_pkgName,
        .msgUuid = nullptr,
        .msgUdid = nullptr
    };
    ret = ClientIpcOnChannelLinkDown(&msg, networkId, NULL, TEST_REMOTE_TYPE);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: ClientIpcOnChannelClosedTest001
 * @tc.desc: client ipc on channel closed test, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientProxyTest, ClientIpcOnChannelClosedTest001, TestSize.Level0)
{
    int32_t ret;

    ChannelMsg data = {
        .msgChannelId = TEST_CHANNELID,
        .msgChannelType = TEST_CHANNELTYPE,
        .msgPid = TEST_PID,
        .msgPkgName = g_pkgName,
        .msgUuid = nullptr,
        .msgUdid = nullptr
    };
    ret = ClientIpcOnChannelClosed(&data);
    EXPECT_EQ(SOFTBUS_OK, ret);

    static const uint32_t SOFTBUS_SA_ID = 4700;
    sptr<ISystemAbilityManager> saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> remoteObject = saManager->GetSystemAbility(SOFTBUS_SA_ID);
    ASSERT_TRUE(remoteObject != nullptr);
    sptr<IRemoteObject::DeathRecipient> abilityDeath = new (std::nothrow) SoftBusDeathRecipient();
    ASSERT_TRUE(abilityDeath != nullptr);
    ret = SoftbusClientInfoManager::GetInstance().SoftbusAddService(g_pkgName, remoteObject, abilityDeath, TEST_PID);
    ASSERT_TRUE(ret == SOFTBUS_OK);
    ChannelMsg msg = {
        .msgChannelId = TEST_CHANNELID,
        .msgChannelType = TEST_CHANNELTYPE,
        .msgPid = TEST_PID,
        .msgPkgName = g_pkgName,
        .msgUuid = nullptr,
        .msgUdid = nullptr
    };
    ret = ClientIpcOnChannelClosed(&msg);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: ClientIpcOnChannelMsgReceivedTest001
 * @tc.desc: client ipc on channel msg received test, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientProxyTest, ClientIpcOnChannelMsgReceivedTest001, TestSize.Level0)
{
    int32_t ret;

    TransReceiveData receiveData;
    receiveData.data = (unsigned char *)SoftBusCalloc(TEST_LEN);
    ASSERT_TRUE(receiveData.data != nullptr);
    receiveData.dataLen = TEST_LEN;
    receiveData.dataType = TEST_DATA_TYPE;

    ChannelMsg data = {
        .msgChannelId = TEST_CHANNELID,
        .msgChannelType = TEST_CHANNELTYPE,
        .msgPid = TEST_PID,
        .msgPkgName = g_pkgName,
        .msgUuid = nullptr,
        .msgUdid = nullptr
    };
    ret = ClientIpcOnChannelMsgReceived(&data, &receiveData);
    EXPECT_EQ(SOFTBUS_OK, ret);

    static const uint32_t SOFTBUS_SA_ID = 4700;
    sptr<ISystemAbilityManager> saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> remoteObject = saManager->GetSystemAbility(SOFTBUS_SA_ID);
    ASSERT_TRUE(remoteObject != nullptr);
    sptr<IRemoteObject::DeathRecipient> abilityDeath = new (std::nothrow) SoftBusDeathRecipient();
    ASSERT_TRUE(abilityDeath != nullptr);
    ret = SoftbusClientInfoManager::GetInstance().SoftbusAddService(g_pkgName, remoteObject, abilityDeath, TEST_PID);
    ASSERT_TRUE(ret == SOFTBUS_OK);
    ChannelMsg msg = {
        .msgChannelId = TEST_CHANNELID,
        .msgChannelType = TEST_CHANNELTYPE,
        .msgPid = TEST_PID,
        .msgPkgName = g_pkgName,
        .msgUuid = nullptr,
        .msgUdid = nullptr
    };
    ret = ClientIpcOnChannelMsgReceived(&msg, &receiveData);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: ClientIpcOnChannelQosEventTest001
 * @tc.desc: client ipc on channel qos event test, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientProxyTest, ClientIpcOnChannelQosEventTest001, TestSize.Level0)
{
    int32_t ret;

    QosParam param;
    QosTv tvList;
    param.channelId = TEST_CHANNELID;
    param.channelType = CHANNEL_TYPE_UDP;
    param.eventId = TEST_EVENT_ID;
    param.tvCount = TEST_COUNT;
    param.tvList = &tvList;
    param.pid = TEST_PID;

    ret = ClientIpcOnChannelQosEvent(g_pkgName, &param);
    EXPECT_EQ(SOFTBUS_OK, ret);

    static const uint32_t SOFTBUS_SA_ID = 4700;
    sptr<ISystemAbilityManager> saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> remoteObject = saManager->GetSystemAbility(SOFTBUS_SA_ID);
    ASSERT_TRUE(remoteObject != nullptr);
    sptr<IRemoteObject::DeathRecipient> abilityDeath = new (std::nothrow) SoftBusDeathRecipient();
    ASSERT_TRUE(abilityDeath != nullptr);
    ret = SoftbusClientInfoManager::GetInstance().SoftbusAddService(g_pkgName, remoteObject, abilityDeath, TEST_PID);
    ASSERT_TRUE(ret == SOFTBUS_OK);
    ret = ClientIpcOnChannelQosEvent(g_pkgName, &param);
    EXPECT_EQ(SOFTBUS_OK, ret);
}
} // namespace OHOS