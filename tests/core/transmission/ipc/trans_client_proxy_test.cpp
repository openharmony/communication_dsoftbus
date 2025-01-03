/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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
#include "softbus_client_info_manager.h"
#include "softbus_server_death_recipient.h"
#include "trans_client_proxy.h"

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

static void BuildChannelMsg(ChannelMsg *data)
{
    data->msgChannelId = TEST_CHANNELID;
    data->msgChannelType = TEST_CHANNELTYPE;
    data->msgPid = TEST_PID;
    data->msgPkgName = g_pkgName;
    data->msgUuid = nullptr;
    data->msgUdid = nullptr;
}

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
    EXPECT_EQ(SOFTBUS_INVALID_PKGNAME, ret);

    ret = InformPermissionChange(TEST_STATE, g_pkgName, TEST_PID);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_REMOTE_NULL, ret);

    static const uint32_t SOFTBUS_SA_ID = 4700;
    sptr<ISystemAbilityManager> saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> remoteObject = saManager->GetSystemAbility(SOFTBUS_SA_ID);
    ASSERT_TRUE(remoteObject != nullptr);
    sptr<IRemoteObject::DeathRecipient> abilityDeath = new (std::nothrow) SoftBusDeathRecipient();
    ASSERT_TRUE(abilityDeath != nullptr);
    ret = SoftbusClientInfoManager::GetInstance().SoftbusAddService(g_pkgName, remoteObject, abilityDeath, TEST_PID);
    EXPECT_EQ(SOFTBUS_OK, ret);
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
    channel.channelType = CHANNEL_TYPE_TCP_DIRECT;
    channel.fd = TEST_DATA_TYPE;
    channel.isServer = false;
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
    EXPECT_NE(SOFTBUS_INVALID_PARAM, ret);

    static const uint32_t SOFTBUS_SA_ID = 4700;
    sptr<ISystemAbilityManager> saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> remoteObject = saManager->GetSystemAbility(SOFTBUS_SA_ID);
    ASSERT_TRUE(remoteObject != nullptr);
    sptr<IRemoteObject::DeathRecipient> abilityDeath = new (std::nothrow) SoftBusDeathRecipient();
    ASSERT_TRUE(abilityDeath != nullptr);
    ret = SoftbusClientInfoManager::GetInstance().SoftbusAddService(g_pkgName, remoteObject, abilityDeath, TEST_PID);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = ClientIpcOnChannelOpened(g_pkgName, g_sessionName, &channel, TEST_PID);
    EXPECT_NE(SOFTBUS_INVALID_PARAM, ret);
    
    channel.isServer = false;
    ret = ClientIpcOnChannelOpened(g_pkgName, g_sessionName, &channel, TEST_PID);
    EXPECT_NE(SOFTBUS_INVALID_PARAM, ret);
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
    ChannelMsg data;
    BuildChannelMsg(&data);
    ret = ClientIpcOnChannelOpenFailed(&data, TEST_ERR_CODE);
    EXPECT_EQ(SOFTBUS_OK, ret);

    static const uint32_t SOFTBUS_SA_ID = 4700;
    sptr<ISystemAbilityManager> saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> remoteObject = saManager->GetSystemAbility(SOFTBUS_SA_ID);
    ASSERT_TRUE(remoteObject != nullptr);
    sptr<IRemoteObject::DeathRecipient> abilityDeath = new (std::nothrow) SoftBusDeathRecipient();
    ASSERT_TRUE(abilityDeath != nullptr);
    ret = SoftbusClientInfoManager::GetInstance().SoftbusAddService(g_pkgName, remoteObject, abilityDeath, TEST_PID);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ChannelMsg msg;
    BuildChannelMsg(&msg);
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
    EXPECT_EQ(SOFTBUS_OK, ret);
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
    ChannelMsg data;
    BuildChannelMsg(&data);
    ret = ClientIpcOnChannelClosed(&data);
    EXPECT_EQ(SOFTBUS_OK, ret);

    static const uint32_t SOFTBUS_SA_ID = 4700;
    sptr<ISystemAbilityManager> saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> remoteObject = saManager->GetSystemAbility(SOFTBUS_SA_ID);
    ASSERT_TRUE(remoteObject != nullptr);
    sptr<IRemoteObject::DeathRecipient> abilityDeath = new (std::nothrow) SoftBusDeathRecipient();
    ASSERT_TRUE(abilityDeath != nullptr);
    ret = SoftbusClientInfoManager::GetInstance().SoftbusAddService(g_pkgName, remoteObject, abilityDeath, TEST_PID);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ChannelMsg msg;
    BuildChannelMsg(&msg);
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

    ChannelMsg data;
    BuildChannelMsg(&data);
    ret = ClientIpcOnChannelMsgReceived(&data, &receiveData);
    EXPECT_EQ(SOFTBUS_OK, ret);

    static const uint32_t SOFTBUS_SA_ID = 4700;
    sptr<ISystemAbilityManager> saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> remoteObject = saManager->GetSystemAbility(SOFTBUS_SA_ID);
    ASSERT_TRUE(remoteObject != nullptr);
    sptr<IRemoteObject::DeathRecipient> abilityDeath = new (std::nothrow) SoftBusDeathRecipient();
    ASSERT_TRUE(abilityDeath != nullptr);
    ret = SoftbusClientInfoManager::GetInstance().SoftbusAddService(g_pkgName, remoteObject, abilityDeath, TEST_PID);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ChannelMsg msg;
    BuildChannelMsg(&msg);
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
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = ClientIpcOnChannelQosEvent(g_pkgName, &param);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: ClientIpcOnChannelBindTest001
 * @tc.desc: ClientIpcOnChannelBind test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientProxyTest, ClientIpcOnChannelBindTest001, TestSize.Level0)
{
    ChannelMsg *data = nullptr;
    int32_t ret = ClientIpcOnChannelBind(data);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    data = (ChannelMsg *)SoftBusCalloc(sizeof(ChannelMsg));
    ASSERT_NE(nullptr, data);
    data->msgPid = TEST_PID;
    ret = ClientIpcOnChannelBind(data);
    EXPECT_EQ(SOFTBUS_TRANS_GET_CLIENT_PROXY_NULL, ret);

    static const uint32_t SOFTBUS_SA_ID = 4700;
    sptr<ISystemAbilityManager> saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_TRUE(saManager != nullptr);
    sptr<IRemoteObject> remoteObject = saManager->GetSystemAbility(SOFTBUS_SA_ID);
    ASSERT_TRUE(remoteObject != nullptr);
    sptr<IRemoteObject::DeathRecipient> abilityDeath = new (std::nothrow) SoftBusDeathRecipient();
    ASSERT_TRUE(abilityDeath != nullptr);
    ret = SoftbusClientInfoManager::GetInstance().SoftbusAddService(g_pkgName, remoteObject, abilityDeath, TEST_PID);
    EXPECT_EQ(SOFTBUS_OK, ret);

    data->msgPkgName = g_pkgName;
    ret = ClientIpcOnChannelBind(data);
    EXPECT_EQ(SOFTBUS_OK, ret);
    SoftBusFree(data);
}

/**
 * @tc.name: ClientIpcOnChannelOpenFailedTest002
 * @tc.desc: ClientIpcOnChannelOpenFailed test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientProxyTest, ClientIpcOnChannelOpenFailedTest002, TestSize.Level0)
{
    ChannelMsg *data = nullptr;
    int32_t errCode = 0;
    int32_t ret = ClientIpcOnChannelOpenFailed(data, errCode);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    data = (ChannelMsg *)SoftBusCalloc(sizeof(ChannelMsg));
    ASSERT_NE(nullptr, data);
    data->msgPid = TEST_PID;
    ret = ClientIpcOnChannelOpenFailed(data, errCode);
    EXPECT_EQ(SOFTBUS_TRANS_GET_CLIENT_PROXY_NULL, ret);
    SoftBusFree(data);
}

/**
 * @tc.name: ClientIpcOnChannelLinkDownTest002
 * @tc.desc: ClientIpcOnChannelLinkDown test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientProxyTest, ClientIpcOnChannelLinkDownTest002, TestSize.Level0)
{
    const char *peerIp = "1234"; // test value
    int32_t routeType = TEST_REMOTE_TYPE;
    int32_t ret = ClientIpcOnChannelLinkDown(nullptr, nullptr, peerIp, routeType);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    const char *networkId = "1234"; // test value
    ChannelMsg *data = (ChannelMsg *)SoftBusCalloc(sizeof(ChannelMsg));
    ASSERT_NE(nullptr, data);
    ret = ClientIpcOnChannelLinkDown(data, networkId, peerIp, routeType);
    EXPECT_EQ(SOFTBUS_TRANS_GET_CLIENT_PROXY_NULL, ret);
    SoftBusFree(data);
    data = nullptr;
}

/**
 * @tc.name: ClientIpcOnChannelClosedTest002
 * @tc.desc: ClientIpcOnChannelClosed test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientProxyTest, ClientIpcOnChannelClosedTest002, TestSize.Level0)
{
    ChannelMsg *data = nullptr;
    int32_t ret = ClientIpcOnChannelClosed(data);
    EXPECT_EQ(SOFTBUS_TRANS_GET_CLIENT_PROXY_NULL, ret);

    data = (ChannelMsg *)SoftBusCalloc(sizeof(ChannelMsg));
    ASSERT_NE(nullptr, data);
    data->msgPid = TEST_PID;
    ret = ClientIpcOnChannelClosed(data);
    EXPECT_EQ(SOFTBUS_TRANS_GET_CLIENT_PROXY_NULL, ret);
    SoftBusFree(data);
}

/**
 * @tc.name: ClientIpcSetChannelInfoTest001
 * @tc.desc: ClientIpcSetChannelInfo test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientProxyTest, ClientIpcSetChannelInfoTest001, TestSize.Level0)
{
    int32_t sessionId = TEST_PID;
    int32_t pid = TEST_PID;
    int32_t ret = ClientIpcSetChannelInfo(nullptr, nullptr, sessionId, nullptr, pid);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    TransInfo *transInfo = (TransInfo *)SoftBusCalloc(sizeof(TransInfo));
    ASSERT_NE(nullptr, transInfo);
    transInfo->channelId = TEST_CHANNELID;
    transInfo->channelType = TEST_CHANNELTYPE;
    ret = ClientIpcSetChannelInfo("iShare", "HWiShare", sessionId, transInfo, pid);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_REMOTE_NULL, ret);

    static const uint32_t SOFTBUS_SA_ID = 4700;
    sptr<ISystemAbilityManager> saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_TRUE(saManager != nullptr);
    sptr<IRemoteObject> remoteObject = saManager->GetSystemAbility(SOFTBUS_SA_ID);
    ASSERT_TRUE(remoteObject != nullptr);
    sptr<IRemoteObject::DeathRecipient> abilityDeath = new (std::nothrow) SoftBusDeathRecipient();
    ASSERT_TRUE(abilityDeath != nullptr);
    ret = SoftbusClientInfoManager::GetInstance().SoftbusAddService(g_pkgName, remoteObject, abilityDeath, TEST_PID);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = ClientIpcSetChannelInfo(g_pkgName, g_sessionName, sessionId, transInfo, pid);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_SEND_REQUEST_FAILED, ret);
    SoftBusFree(transInfo);
}

/**
 * @tc.name: ClientIpcOnChannelMsgReceivedTest002
 * @tc.desc: ClientIpcOnChannelMsgReceived test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientProxyTest, ClientIpcOnChannelMsgReceivedTest002, TestSize.Level0)
{
    int32_t ret = ClientIpcOnChannelMsgReceived(nullptr, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ChannelMsg *data = (ChannelMsg *)SoftBusCalloc(sizeof(ChannelMsg));
    ASSERT_NE(nullptr, data);
    data->msgChannelId = TEST_CHANNELID;
    data->msgChannelType = TEST_CHANNELTYPE;
    data->msgPkgName = "iShare";
    data->msgPid = TEST_PID;
    data->msgMessageType = TEST_CHANNELTYPE;

    TransReceiveData *receiveData = (TransReceiveData *)SoftBusCalloc(sizeof(TransReceiveData));
    ASSERT_NE(nullptr, receiveData);
    receiveData->dataLen = TEST_LEN;
    receiveData->dataType = TEST_DATA_TYPE;
    ret = ClientIpcOnChannelMsgReceived(data, receiveData);
    EXPECT_EQ(SOFTBUS_OK, ret);
    SoftBusFree(data);
    SoftBusFree(receiveData);
}

/**
 * @tc.name: ClientIpcOnTransLimitChangeTest001
 * @tc.desc: ClientIpcOnTransLimitChange test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientProxyTest, ClientIpcOnTransLimitChangeTest001, TestSize.Level0)
{
    uint8_t tos = 0;
    int32_t ret = ClientIpcOnTransLimitChange(nullptr, TEST_PID, TEST_CHANNELID, tos);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = ClientIpcOnTransLimitChange(g_pkgName, 1, TEST_CHANNELID, tos);
    EXPECT_NE(SOFTBUS_TRANS_GET_CLIENT_PROXY_NULL, ret);

    ret = ClientIpcOnTransLimitChange(g_pkgName, TEST_PID, TEST_CHANNELID, tos);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: CheckServiceIsRegisteredTest001
 * @tc.desc: CheckServiceIsRegistered test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientProxyTest, CheckServiceIsRegisteredTest001, TestSize.Level0)
{
    int32_t ret = CheckServiceIsRegistered(nullptr, TEST_PID);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = CheckServiceIsRegistered(g_pkgName, TEST_PID);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: ClientIpcChannelOnQosTest001
 * @tc.desc: ClientIpcChannelOnQos test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientProxyTest, ClientIpcChannelOnQosTest001, TestSize.Level0)
{
    int32_t ret = ClientIpcChannelOnQos(nullptr, QOS_SATISFIED, nullptr, QOS_TYPE_BUTT);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ChannelMsg data;
    data.msgPkgName = nullptr;
    ret = ClientIpcChannelOnQos(&data, QOS_SATISFIED, nullptr, QOS_TYPE_BUTT);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    data.msgPkgName = g_pkgName;
    ret = ClientIpcChannelOnQos(&data, QOS_SATISFIED, nullptr, QOS_TYPE_BUTT);
    QosTV qos[] = {
        {QOS_TYPE_MIN_BW, 0},
    };
    ret = ClientIpcChannelOnQos(&data, QOS_SATISFIED, qos, QOS_TYPE_BUTT);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = ClientIpcChannelOnQos(&data, QOS_SATISFIED, qos, 1);
    EXPECT_NE(SOFTBUS_OK, ret);

    data.msgChannelId = TEST_CHANNELID;
    data.msgChannelType = TEST_CHANNELTYPE;
    data.msgPid = TEST_PID;
    ret = ClientIpcChannelOnQos(&data, QOS_SATISFIED, qos, 1);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: ClientIpcCheckCollabRelationTest001
 * @tc.desc: ClientIpcCheckCollabRelation test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientProxyTest, ClientIpcCheckCollabRelationTest001, TestSize.Level0)
{
    int32_t pid = 0;
    CollabInfo sourceInfo = {
        .accountId = 0,
        .deviceId = "ABCDE",
        .pid = 0,
        .tokenId = 0,
        .userId = 0,
    };
    CollabInfo sinkInfo = {
        .accountId = 0,
        .deviceId = "ABCDE",
        .pid = 0,
        .tokenId = 0,
        .userId = 0,
    };
    TransInfo transInfo = {
        .channelId = 0,
        .channelType = 0,
    };
    int32_t ret = ClientIpcCheckCollabRelation(nullptr, pid, &sourceInfo, &sinkInfo, &transInfo);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = ClientIpcCheckCollabRelation(g_pkgName, pid, &sourceInfo, &sinkInfo, &transInfo);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_REMOTE_NULL, ret);
}
} // namespace OHOS
