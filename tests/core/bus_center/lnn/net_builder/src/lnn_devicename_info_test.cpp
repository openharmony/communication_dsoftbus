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

#include "lnn_connection_mock.h"
#include "lnn_devicename_info.c"
#include "lnn_devicename_info.h"
#include "lnn_net_ledger_mock.h"
#include "lnn_service_mock.h"
#include "lnn_sync_info_mock.h"
#include "softbus_error_code.h"
#include "lnn_sync_info_manager.h"

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
* @tc.desc: on receive device name test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNDeviceNameInfoTest, ON_RECEIVE_DEVICE_NAME_TEST_001, TestSize.Level1)
{
    char msg[] = "msg";
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    NiceMock<LnnServicetInterfaceMock> serviceMock;
    EXPECT_CALL(ledgerMock, LnnConvertDlId).WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ledgerMock, LnnSetDLDeviceInfoName).WillOnce(Return(false))
        .WillRepeatedly(Return(true));
    EXPECT_CALL(ledgerMock, LnnGetBasicInfoByUdid).WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ledgerMock, LnnGetRemoteNodeInfoById).WillOnce(Return(SOFTBUS_INVALID_PARAM))
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
* @tc.desc: on receive device nick name test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNDeviceNameInfoTest, ON_RECEIVE_DEVICE_NICK_NAME_TEST_001, TestSize.Level1)
{
    NodeInfo nodeInfo;
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    EXPECT_CALL(ledgerMock, LnnGetLocalNodeInfo).WillOnce(Return(nullptr))
        .WillRepeatedly(Return(&nodeInfo));
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
* @tc.desc: lnn sync device name test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNDeviceNameInfoTest, LNN_SYNC_DEVICE_NAME_TEST_001, TestSize.Level1)
{
    NodeInfo nodeInfo;
    SendSyncInfoParam *data = (SendSyncInfoParam *)SoftBusMalloc(sizeof(SendSyncInfoParam));
    EXPECT_TRUE(data != NULL);
    memset_s(data, sizeof(SendSyncInfoParam), 0, sizeof(SendSyncInfoParam));
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    EXPECT_CALL(ledgerMock, LnnGetLocalNodeInfo).WillOnce(Return(nullptr))
        .WillRepeatedly(Return(&nodeInfo));
    EXPECT_CALL(ledgerMock, LnnGetDeviceName).WillOnce(Return(DEVICE_NAME1))
        .WillRepeatedly(Return(DEVICE_NAME2));
    NiceMock<LnnSyncInfoInterfaceMock> lnnSyncInfoMock;
    EXPECT_CALL(lnnSyncInfoMock, CreateSyncInfoParam).WillOnce(Return(nullptr))
        .WillRepeatedly(Return(data));
    NiceMock<LnnServicetInterfaceMock> ServiceMock;
    EXPECT_CALL(ServiceMock, LnnAsyncCallbackHelper)
        .WillRepeatedly(Return(SOFTBUS_OK));
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
* @tc.desc: nick name msg proc test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNDeviceNameInfoTest, NICK_NAME_MSG_PROC_TEST_001, TestSize.Level1)
{
    NodeInfo nodeInfo = {
        .accountId = ACCOUNT_ID + 1,
    };
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    NiceMock<LnnServicetInterfaceMock> serviceMock;
    EXPECT_CALL(ledgerMock, LnnGetLocalNodeInfo).WillOnce(Return(nullptr))
        .WillRepeatedly(Return(&nodeInfo));
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
 * @tc.desc: notify device display name change test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNDeviceNameInfoTest, NOTIFY_DEVICE_DISPLAY_NAME_CHANGE_TEST_001, TestSize.Level1)
{
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    NiceMock<LnnServicetInterfaceMock> serviceMock;
    EXPECT_CALL(ledgerMock, LnnGetBasicInfoByUdid).WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ledgerMock, LnnGetRemoteNodeInfoById).WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(serviceMock, LnnNotifyBasicInfoChanged).WillRepeatedly(Return());
    EXPECT_CALL(serviceMock, UpdateProfile).WillRepeatedly(Return());
    NotifyDeviceDisplayNameChange(NETWORKID, NODE_UDID);
    NotifyDeviceDisplayNameChange(NETWORKID, NODE_UDID);
    NotifyDeviceDisplayNameChange(NETWORKID, NODE_UDID);
}

/*
* @tc.name: LNN_INIT_DEVICE_NAME_TEST_001
* @tc.desc: LnnInitDevicename test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNDeviceNameInfoTest, LNN_INIT_DEVICE_NAME_TEST_001, TestSize.Level1)
{
    NiceMock<LnnSyncInfoInterfaceMock> lnnSyncInfoMock;
    EXPECT_CALL(lnnSyncInfoMock, LnnRegSyncInfoHandler)
        .WillOnce(Return(SOFTBUS_LOCK_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = LnnInitDevicename();
    EXPECT_NE(ret, SOFTBUS_LOCK_ERR);
    ret = LnnInitDevicename();
    EXPECT_EQ(ret, SOFTBUS_OK);
}


/*
* @tc.name: LNN_SET_LOCAL_DEVICE_NAME_TEST_001
* @tc.desc: LnnSetLocalDeviceName test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNDeviceNameInfoTest, LNN_SET_LOCAL_DEVICE_NAME_TEST_001, TestSize.Level1)
{
    NiceMock<LnnServicetInterfaceMock> serviceMock;
    EXPECT_CALL(serviceMock, LnnNotifyLocalNetworkIdChanged).WillRepeatedly(Return());
    EXPECT_CALL(serviceMock, LnnNotifyDeviceInfoChanged).WillRepeatedly(Return());
    int32_t ret = LnnSetLocalDeviceName(DEVICE_NAME1);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnSetLocalDeviceName(DEVICE_NAME3);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    EXPECT_CALL(ledgerMock, LnnGetLocalStrInfo).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    ret = LnnSetLocalDeviceName(DEVICE_NAME2);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_GET_NODE_INFO_ERR);
    const char* info = "ABCDEFG";
    EXPECT_CALL(ledgerMock, LnnGetLocalStrInfo).WillOnce(DoAll(SetArgPointee<1>(*info), Return(SOFTBUS_OK)));
    ret = LnnSetLocalDeviceName(DEVICE_NAME2);
    EXPECT_EQ(ret, SOFTBUS_OK);
    const char* info1 = "ABCDEFGHIGKL";
    EXPECT_CALL(ledgerMock, LnnGetLocalStrInfo).WillRepeatedly(DoAll(SetArgPointee<1>(*info1), Return(SOFTBUS_OK)));
    EXPECT_CALL(ledgerMock, LnnSetLocalStrInfo).WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    ret = LnnSetLocalDeviceName(DEVICE_NAME2);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_SET_NODE_INFO_ERR);
    EXPECT_CALL(ledgerMock, LnnGetAllOnlineNodeInfo).WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(DoAll(SetArgPointee<1>(1), Return(SOFTBUS_OK)));
    ret = LnnSetLocalDeviceName(DEVICE_NAME2);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_GET_ALL_NODE_INFO_ERR);
    EXPECT_CALL(ledgerMock, LnnIsLSANode).WillRepeatedly(Return(true));
    ret = LnnSetLocalDeviceName(DEVICE_NAME2);
    EXPECT_EQ(ret, SOFTBUS_OK);
}
} // namespace OHOS
