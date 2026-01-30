/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#include "auth_session_fsm.h"
#include "lnn_connection_mock.h"
#include "lnn_devicename_info.c"
#include "lnn_devicename_info.h"
#include "lnn_net_builder.h"
#include "lnn_net_ledger_mock.h"
#include "lnn_service_mock.h"
#include "lnn_sync_info_manager.h"
#include "lnn_sync_info_mock.h"
#include "softbus_error_code.h"

namespace OHOS {
using namespace testing;
using namespace testing::ext;
NodeInfo *info = { 0 };
constexpr int64_t ACCOUNT_ID = 10;
constexpr char *DEVICE_NAME1 = nullptr;
constexpr char DEVICE_NAME2[] = "ABCDEFG";
constexpr uint32_t MSG_ERR_LEN0 = 0;
constexpr char NODE_UDID[] = "123456ABCDEF";
constexpr char NETWORKID[NETWORK_ID_BUF_LEN] = "123456ABD";
constexpr char DEVICE_NAME3[] = "";

class LNNDeviceNameInfoTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void LNNDeviceNameInfoTest::SetUpTestCase() { }

void LNNDeviceNameInfoTest::TearDownTestCase() { }

void LNNDeviceNameInfoTest::SetUp() { }

void LNNDeviceNameInfoTest::TearDown() { }

/*
 * @tc.name: ON_RECEIVE_DEVICE_NAME_TEST_001
 * @tc.desc: Verify OnReceiveDeviceName handles different info types and message formats
 *           correctly including null parameters and invalid lengths
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDeviceNameInfoTest, ON_RECEIVE_DEVICE_NAME_TEST_001, TestSize.Level1)
{
    char msg[] = "msg";
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    NiceMock<LnnServicetInterfaceMock> serviceMock;
    EXPECT_CALL(ledgerMock, LnnConvertDlId).WillOnce(Return(SOFTBUS_INVALID_PARAM)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ledgerMock, LnnSetDLDeviceInfoName).WillOnce(Return(false)).WillRepeatedly(Return(true));
    EXPECT_CALL(ledgerMock, LnnGetBasicInfoByUdid)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ledgerMock, LnnGetRemoteNodeInfoById)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(serviceMock, LnnNotifyBasicInfoChanged).WillRepeatedly(Return());
    EXPECT_CALL(serviceMock, UpdateProfile).WillRepeatedly(Return());
    OnReceiveDeviceName(LNN_INFO_TYPE_COUNT, NETWORKID, reinterpret_cast<uint8_t *>(msg), strlen(msg) + 1);
    OnReceiveDeviceName(LNN_INFO_TYPE_DEVICE_NAME, NETWORKID, reinterpret_cast<uint8_t *>(msg), MSG_ERR_LEN0);
    OnReceiveDeviceName(LNN_INFO_TYPE_DEVICE_NAME, nullptr, reinterpret_cast<uint8_t *>(msg), strlen(msg) + 1);
    OnReceiveDeviceName(LNN_INFO_TYPE_DEVICE_NAME, NETWORKID, nullptr, strlen(msg));
    OnReceiveDeviceName(LNN_INFO_TYPE_DEVICE_NAME, NETWORKID, reinterpret_cast<uint8_t *>(msg), strlen(msg) + 1);
    OnReceiveDeviceName(LNN_INFO_TYPE_DEVICE_NAME, NETWORKID, reinterpret_cast<uint8_t *>(msg), strlen(msg) + 1);
    OnReceiveDeviceName(LNN_INFO_TYPE_DEVICE_NAME, NETWORKID, reinterpret_cast<uint8_t *>(msg), strlen(msg) + 1);
    OnReceiveDeviceName(LNN_INFO_TYPE_DEVICE_NAME, NETWORKID, reinterpret_cast<uint8_t *>(msg), strlen(msg) + 1);
    OnReceiveDeviceName(LNN_INFO_TYPE_DEVICE_NAME, NETWORKID, reinterpret_cast<uint8_t *>(msg), strlen(msg) + 1);
}

/*
 * @tc.name: ON_RECEIVE_DEVICE_NICK_NAME_TEST_001
 * @tc.desc: Verify OnReceiveDeviceNickName handles nick name sync messages
 *           with different JSON formats and null parameters correctly
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDeviceNameInfoTest, ON_RECEIVE_DEVICE_NICK_NAME_TEST_001, TestSize.Level1)
{
    NodeInfo nodeInfo;
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    EXPECT_CALL(ledgerMock, LnnGetLocalNodeInfo).WillOnce(Return(nullptr)).WillRepeatedly(Return(&nodeInfo));
    EXPECT_CALL(ledgerMock, LnnGetRemoteNodeInfoById)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    char msg1[] = "{\"KEY_NICK_NAME\":\"nickName\"}";
    char msg2[] = "{\"KEY_ACCOUNT\":10}";
    char msg3[] = "{\"KEY_ACCOUNT\":10, \"KEY_NICK_NAME\":\"nickName\"}";
    OnReceiveDeviceNickName(LNN_INFO_TYPE_NICK_NAME, NETWORKID, nullptr, strlen(msg1) + 1);
    OnReceiveDeviceNickName(LNN_INFO_TYPE_COUNT, NETWORKID, reinterpret_cast<uint8_t *>(msg1), strlen(msg1) + 1);
    OnReceiveDeviceNickName(LNN_INFO_TYPE_NICK_NAME, NETWORKID, reinterpret_cast<uint8_t *>(msg1), MSG_ERR_LEN0);
    OnReceiveDeviceNickName(LNN_INFO_TYPE_NICK_NAME, NETWORKID, reinterpret_cast<uint8_t *>(msg1), strlen(msg1) + 1);
    OnReceiveDeviceNickName(LNN_INFO_TYPE_NICK_NAME, NETWORKID, reinterpret_cast<uint8_t *>(msg2), strlen(msg2) + 1);
    OnReceiveDeviceNickName(LNN_INFO_TYPE_NICK_NAME, NETWORKID, reinterpret_cast<uint8_t *>(msg3), strlen(msg3) + 1);
    OnReceiveDeviceNickName(LNN_INFO_TYPE_NICK_NAME, NETWORKID, reinterpret_cast<uint8_t *>(msg3), strlen(msg3) + 1);
    OnReceiveDeviceNickName(LNN_INFO_TYPE_NICK_NAME, NETWORKID, reinterpret_cast<uint8_t *>(msg3), strlen(msg3) + 1);
}

/*
 * @tc.name: LNN_SYNC_DEVICE_NAME_TEST_001
 * @tc.desc: Verify LnnSyncDeviceName syncs device name to remote device
 *           and handles various error conditions correctly
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDeviceNameInfoTest, LNN_SYNC_DEVICE_NAME_TEST_001, TestSize.Level1)
{
    NodeInfo nodeInfo;
    SendSyncInfoParam *data = (SendSyncInfoParam *)SoftBusMalloc(sizeof(SendSyncInfoParam));
    EXPECT_TRUE(data != nullptr);
    memset_s(data, sizeof(SendSyncInfoParam), 0, sizeof(SendSyncInfoParam));
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    EXPECT_CALL(ledgerMock, LnnGetLocalNodeInfo).WillOnce(Return(nullptr)).WillRepeatedly(Return(&nodeInfo));
    EXPECT_CALL(ledgerMock, LnnGetDeviceName).WillOnce(Return(DEVICE_NAME1)).WillRepeatedly(Return(DEVICE_NAME2));
    NiceMock<LnnSyncInfoInterfaceMock> lnnSyncInfoMock;
    EXPECT_CALL(lnnSyncInfoMock, CreateSyncInfoParam).WillOnce(Return(nullptr)).WillRepeatedly(Return(data));
    NiceMock<LnnServicetInterfaceMock> ServiceMock;
    EXPECT_CALL(ServiceMock, LnnAsyncCallbackHelper).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = LnnSyncDeviceName(NETWORKID);
    EXPECT_TRUE(ret == SOFTBUS_NETWORK_GET_LOCAL_NODE_INFO_ERR);
    ret = LnnSyncDeviceName(NETWORKID);
    EXPECT_TRUE(ret == SOFTBUS_NETWORK_GET_DEVICE_INFO_ERR);
    ret = LnnSyncDeviceName(NETWORKID);
    EXPECT_TRUE(ret == SOFTBUS_NETWORK_SEND_SYNC_INFO_FAILED);
    ret = LnnSyncDeviceName(NETWORKID);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    SoftBusFree(data->msg);
    SoftBusFree(data);
}

/*
 * @tc.name: NICK_NAME_MSG_PROC_TEST_001
 * @tc.desc: Verify NickNameMsgProc processes nick name messages with
 *           different node info states and account IDs correctly
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDeviceNameInfoTest, NICK_NAME_MSG_PROC_TEST_001, TestSize.Level1)
{
    NodeInfo nodeInfo = {
        .accountId = ACCOUNT_ID + 1,
    };
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    NiceMock<LnnServicetInterfaceMock> serviceMock;
    EXPECT_CALL(ledgerMock, LnnGetLocalNodeInfo).WillOnce(Return(nullptr)).WillRepeatedly(Return(&nodeInfo));
    EXPECT_CALL(ledgerMock, LnnSetDLDeviceNickName).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ledgerMock, LnnGetBasicInfoByUdid).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));

    NodeInfo peerNodeInfo1 = {
        .deviceInfo.nickName = "nickName",
    };
    NodeInfo peerNodeInfo2 = {
        .deviceInfo.nickName = "diffNickName",
        .deviceInfo.unifiedName = "unifiedName",
        .deviceInfo.unifiedDefaultName = "unifiedDefaultName",
        .deviceInfo.deviceName = "deviceName",
    };
    NodeInfo peerNodeInfo3 = {
        .deviceInfo.nickName = "diffNickName",
        .deviceInfo.unifiedName = "",
        .deviceInfo.unifiedDefaultName = "unifiedDefaultName",
        .deviceInfo.deviceName = "deviceName",
    };
    EXPECT_CALL(ledgerMock, LnnGetRemoteNodeInfoById)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillOnce(DoAll(SetArgPointee<2>(peerNodeInfo1), Return(SOFTBUS_OK)))
        .WillOnce(DoAll(SetArgPointee<2>(peerNodeInfo2), Return(SOFTBUS_OK)))
        .WillRepeatedly(DoAll(SetArgPointee<2>(peerNodeInfo3), Return(SOFTBUS_OK)));
    const char *displayName = "";
    EXPECT_CALL(serviceMock, LnnNotifyBasicInfoChanged).WillRepeatedly(Return());
    EXPECT_CALL(serviceMock, LnnGetDeviceDisplayName)
        .WillRepeatedly(DoAll(SetArgPointee<2>(*(const_cast<char *>(displayName))), Return(SOFTBUS_OK)));
    NickNameMsgProc(NETWORKID, ACCOUNT_ID, "nickName");
    NickNameMsgProc(NETWORKID, ACCOUNT_ID, "nickName");
    NickNameMsgProc(NETWORKID, ACCOUNT_ID, "nickName");
    NickNameMsgProc(NETWORKID, ACCOUNT_ID, "nickName");
    NickNameMsgProc(NETWORKID, ACCOUNT_ID, "nickName");
    NickNameMsgProc(NETWORKID, ACCOUNT_ID, "");
    NickNameMsgProc(NETWORKID, ACCOUNT_ID, "nickName");
    NickNameMsgProc(NETWORKID, ACCOUNT_ID, "nickName");
}

/*
 * @tc.name: NOTIFY_DEVICE_DISPLAY_NAME_CHANGE_TEST_001
 * @tc.desc: Verify NotifyDeviceDisplayNameChange notifies display name
 *           change event to remote devices correctly
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDeviceNameInfoTest, NOTIFY_DEVICE_DISPLAY_NAME_CHANGE_TEST_001, TestSize.Level1)
{
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    NiceMock<LnnServicetInterfaceMock> serviceMock;
    EXPECT_CALL(ledgerMock, LnnGetBasicInfoByUdid)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ledgerMock, LnnGetRemoteNodeInfoById)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(serviceMock, LnnNotifyBasicInfoChanged).WillRepeatedly(Return());
    EXPECT_CALL(serviceMock, UpdateProfile).WillRepeatedly(Return());
    NotifyDeviceDisplayNameChange(NETWORKID, NODE_UDID);
    NotifyDeviceDisplayNameChange(NETWORKID, NODE_UDID);
    NotifyDeviceDisplayNameChange(NETWORKID, NODE_UDID);
}

/*
 * @tc.name: LNN_INIT_DEVICE_NAME_TEST_001
 * @tc.desc: LnnInitDevicename test LnnRegSyncInfoHandler return
 * error
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDeviceNameInfoTest, LNN_INIT_DEVICE_NAME_TEST_001, TestSize.Level1)
{
    NiceMock<LnnSyncInfoInterfaceMock> lnnSyncInfoMock;
    EXPECT_CALL(lnnSyncInfoMock, LnnRegSyncInfoHandler).WillRepeatedly(Return(SOFTBUS_LOCK_ERR));
    int32_t ret = LnnInitDevicename();
    EXPECT_EQ(ret, SOFTBUS_LOCK_ERR);
}

/*
 * @tc.name: LNN_INIT_DEVICE_NAME_TEST_002
 * @tc.desc: LnnInitDevicename test LnnRegSyncInfoHandler return
 * success
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDeviceNameInfoTest, LNN_INIT_DEVICE_NAME_TEST_002, TestSize.Level1)
{
    NiceMock<LnnSyncInfoInterfaceMock> lnnSyncInfoMock;
    EXPECT_CALL(lnnSyncInfoMock, LnnRegSyncInfoHandler).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = LnnInitDevicename();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_SET_LOCAL_DEVICE_NAME_TEST_001
 * @tc.desc: Verify LnnSetLocalDeviceName sets local device name
 *           and syncs to remote devices correctly
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDeviceNameInfoTest, LNN_SET_LOCAL_DEVICE_NAME_TEST_001, TestSize.Level1)
{
    NiceMock<LnnServicetInterfaceMock> serviceMock;
    EXPECT_CALL(serviceMock, LnnNotifyDeviceInfoChanged).WillRepeatedly(Return());
    EXPECT_CALL(serviceMock, LnnNotifyLocalNetworkIdChanged).WillRepeatedly(Return());
    int32_t ret = LnnSetLocalDeviceName(DEVICE_NAME1);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnSetLocalDeviceName(DEVICE_NAME3);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    EXPECT_CALL(ledgerMock, LnnGetLocalStrInfo).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    ret = LnnSetLocalDeviceName(DEVICE_NAME2);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_GET_NODE_INFO_ERR);
    const char *info = "ABCDEFG";
    EXPECT_CALL(ledgerMock, LnnGetLocalStrInfo).WillOnce(DoAll(SetArgPointee<1>(*info), Return(SOFTBUS_OK)));
    ret = LnnSetLocalDeviceName(DEVICE_NAME2);
    EXPECT_EQ(ret, SOFTBUS_OK);
    const char *info1 = "ABCDEFGHIGKL";
    EXPECT_CALL(ledgerMock, LnnGetLocalStrInfo).WillRepeatedly(DoAll(SetArgPointee<1>(*info1), Return(SOFTBUS_OK)));
    EXPECT_CALL(ledgerMock, LnnSetLocalStrInfo)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    ret = LnnSetLocalDeviceName(DEVICE_NAME2);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_SET_NODE_INFO_ERR);
    EXPECT_CALL(ledgerMock, LnnGetAllOnlineNodeInfo)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(DoAll(SetArgPointee<1>(1), Return(SOFTBUS_OK)));
    ret = LnnSetLocalDeviceName(DEVICE_NAME2);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_GET_ALL_NODE_INFO_ERR);
    EXPECT_CALL(ledgerMock, LnnIsLSANode).WillRepeatedly(Return(true));
    ret = LnnSetLocalDeviceName(DEVICE_NAME2);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_ASYNC_DEVICE_NAME_DALEY_TEST_001
 * @tc.desc: Verify LnnAsyncDeviceNameDelay sends device name sync
 *           message asynchronously with delay
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDeviceNameInfoTest, LNN_ASYNC_DEVICE_NAME_DALEY_TEST_001, TestSize.Level1)
{
    NodeInfo nodeInfo;
    (void)memset_s(&nodeInfo, sizeof(nodeInfo), 0, sizeof(nodeInfo));
    SendSyncInfoParam *data = (SendSyncInfoParam *)SoftBusCalloc(sizeof(SendSyncInfoParam));
    ASSERT_TRUE(data != nullptr);
    memset_s(data, sizeof(SendSyncInfoParam), 0, sizeof(SendSyncInfoParam));

    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    EXPECT_CALL(ledgerMock, LnnGetLocalNodeInfo).WillOnce(Return(nullptr)).WillRepeatedly(Return(&nodeInfo));
    EXPECT_CALL(ledgerMock, LnnGetDeviceName).WillOnce(Return(DEVICE_NAME1)).WillRepeatedly(Return(DEVICE_NAME2));
    NiceMock<LnnSyncInfoInterfaceMock> lnnSyncInfoMock;
    EXPECT_CALL(lnnSyncInfoMock, CreateSyncInfoParam).WillOnce(Return(nullptr)).WillRepeatedly(Return(data));
    NiceMock<LnnServicetInterfaceMock> ServiceMock;
    EXPECT_CALL(ServiceMock, LnnAsyncCallbackDelayHelper).WillRepeatedly(Return(SOFTBUS_OK));

    int32_t ret = LnnAsyncDeviceNameDelay(NETWORKID);
    EXPECT_TRUE(ret == SOFTBUS_NETWORK_GET_LOCAL_NODE_INFO_ERR);

    ret = LnnAsyncDeviceNameDelay(NETWORKID);
    EXPECT_TRUE(ret == SOFTBUS_NETWORK_GET_DEVICE_INFO_ERR);

    ret = LnnAsyncDeviceNameDelay(NETWORKID);
    EXPECT_TRUE(ret == SOFTBUS_NETWORK_CREATE_SYNC_INFO_PARAM_FAILED);

    ret = LnnAsyncDeviceNameDelay(NETWORKID);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    SoftBusFree(data);
}

/*
 * @tc.name: LNN_ASYNC_DEVICE_NAME_DELAY_TEST_001
 * @tc.desc: Verify LnnAsyncDeviceNameDelay handles get local node info
 *           failure correctly
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDeviceNameInfoTest, LNN_ASYNC_DEVICE_NAME_DELAY_TEST_001, TestSize.Level1)
{
    NodeInfo *nodeInfo = (NodeInfo *)SoftBusCalloc(sizeof(NodeInfo));
    ASSERT_NE(nodeInfo, nullptr);
    const char *devName = "deviceNickname";
    ASSERT_EQ(strncpy_s(nodeInfo->deviceInfo.deviceName, DEVICE_NAME_BUF_LEN, devName, strlen(devName)), EOK);
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    EXPECT_CALL(ledgerMock, LnnGetLocalNodeInfo).WillOnce(Return(nullptr)).WillRepeatedly(Return(nodeInfo));
    EXPECT_CALL(ledgerMock, LnnGetDeviceName).WillOnce(Return(nullptr)).WillRepeatedly(Return(devName));
    NiceMock<LnnSyncInfoInterfaceMock> lnnSyncInfoMock;
    int32_t ret = LnnAsyncDeviceNameDelay(NETWORKID);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_GET_LOCAL_NODE_INFO_ERR);
    ret = LnnAsyncDeviceNameDelay(NETWORKID);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_GET_DEVICE_INFO_ERR);
    ret = LnnAsyncDeviceNameDelay(NETWORKID);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_CREATE_SYNC_INFO_PARAM_FAILED);
    SoftBusFree(nodeInfo);
}

/*
 * @tc.name: LNN_ASYNC_DEVICE_NAME_DELAY_TEST_002
 * @tc.desc: Verify LnnAsyncDeviceNameDelay returns error when
 *           LnnAsyncCallbackDelayHelper fails
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDeviceNameInfoTest, LNN_ASYNC_DEVICE_NAME_DELAY_TEST_002, TestSize.Level1)
{
    NodeInfo *nodeInfo = (NodeInfo *)SoftBusCalloc(sizeof(NodeInfo));
    ASSERT_NE(nodeInfo, nullptr);
    const char *devName = "deviceNickname";
    SendSyncInfoParam *data = (SendSyncInfoParam *)SoftBusCalloc(sizeof(SendSyncInfoParam));
    ASSERT_NE(data, nullptr);
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    EXPECT_CALL(ledgerMock, LnnGetLocalNodeInfo).WillRepeatedly(Return(nodeInfo));
    EXPECT_CALL(ledgerMock, LnnGetDeviceName).WillRepeatedly(Return(devName));
    NiceMock<LnnSyncInfoInterfaceMock> lnnSyncInfoMock;
    NiceMock<LnnServicetInterfaceMock> ServiceMock;
    EXPECT_CALL(lnnSyncInfoMock, CreateSyncInfoParam).WillRepeatedly(Return(data));
    EXPECT_CALL(ServiceMock, LnnAsyncCallbackDelayHelper).WillRepeatedly(Return(SOFTBUS_NETWORK_SEND_SYNC_INFO_FAILED));
    int32_t ret = LnnAsyncDeviceNameDelay(NETWORKID);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_SEND_SYNC_INFO_FAILED);
    SoftBusFree(nodeInfo);
}

/*
 * @tc.name: LNN_ASYNC_DEVICE_NAME_DELAY_TEST_003
 * @tc.desc: Verify LnnAsyncDeviceNameDelay returns SOFTBUS_OK when
 *           all operations succeed
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDeviceNameInfoTest, LNN_ASYNC_DEVICE_NAME_DELAY_TEST_003, TestSize.Level1)
{
    NodeInfo *nodeInfo = (NodeInfo *)SoftBusCalloc(sizeof(NodeInfo));
    ASSERT_NE(nodeInfo, nullptr);
    const char *devName = "deviceNickname";
    SendSyncInfoParam *data = (SendSyncInfoParam *)SoftBusCalloc(sizeof(SendSyncInfoParam));
    ASSERT_NE(data, nullptr);
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    EXPECT_CALL(ledgerMock, LnnGetLocalNodeInfo).WillRepeatedly(Return(nodeInfo));
    EXPECT_CALL(ledgerMock, LnnGetDeviceName).WillRepeatedly(Return(devName));
    NiceMock<LnnSyncInfoInterfaceMock> lnnSyncInfoMock;
    NiceMock<LnnServicetInterfaceMock> ServiceMock;
    EXPECT_CALL(lnnSyncInfoMock, CreateSyncInfoParam).WillRepeatedly(Return(data));
    EXPECT_CALL(ServiceMock, LnnAsyncCallbackDelayHelper).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = LnnAsyncDeviceNameDelay(NETWORKID);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(nodeInfo);
    SoftBusFree(data);
}

/*
 * @tc.name: LNN_SET_DISPLAY_NAME_TEST_001
 * @tc.desc: Verify LnnSetDisplayName sets display name based on
 *           nick name and account ID correctly
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNDeviceNameInfoTest, LNN_SET_DISPLAY_NAME_TEST_001, TestSize.Level1)
{
    NodeInfo peerNodeInfo = {
        .deviceInfo.nickName = "diffNickName",
        .deviceInfo.unifiedName = "unifiedName",
        .deviceInfo.unifiedDefaultName = "unifiedDefaultName",
        .deviceInfo.deviceName = "deviceName",
    };
    NodeInfo localNodeInfo = {
        .deviceInfo.nickName = "diffNickName",
        .deviceInfo.unifiedName = "",
        .deviceInfo.unifiedDefaultName = "unifiedDefaultName",
        .deviceInfo.deviceName = "deviceName",
        .accountId = ACCOUNT_ID,
    };
    NiceMock<LnnServicetInterfaceMock> serviceMock;
    EXPECT_CALL(serviceMock, LnnGetDeviceDisplayName).WillRepeatedly(Return(SOFTBUS_OK));
    char displayName[] = "displayName";
    const char *nickName = "";
    int64_t accountId = ACCOUNT_ID;
    EXPECT_NO_FATAL_FAILURE(LnnSetDisplayName(displayName, nickName, &peerNodeInfo, &localNodeInfo, accountId));
    EXPECT_EQ(EOK, strcpy_s(peerNodeInfo.deviceInfo.unifiedName, DEVICE_NAME_BUF_LEN, "unifiedDefaultName"));
    EXPECT_NO_FATAL_FAILURE(LnnSetDisplayName(displayName, nickName, &peerNodeInfo, &localNodeInfo, accountId));
    const char *nickNameNew = "nickNameNew";
    EXPECT_NO_FATAL_FAILURE(LnnSetDisplayName(displayName, nickNameNew, &peerNodeInfo, &localNodeInfo, accountId));
    accountId = ACCOUNT_ID + 1;
    (void)memset_s(peerNodeInfo.deviceInfo.unifiedName, DEVICE_NAME_BUF_LEN, 0, DEVICE_NAME_BUF_LEN);
    EXPECT_NO_FATAL_FAILURE(LnnSetDisplayName(displayName, nickNameNew, &peerNodeInfo, &localNodeInfo, accountId));
}
} // namespace OHOS
