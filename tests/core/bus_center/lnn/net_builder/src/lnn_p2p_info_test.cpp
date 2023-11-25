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

#include "bus_center_event.h"
#include "bus_center_manager.h"
#include "cJSON.h"
#include "common_list.h"
#include "lnn_log.h"
#include "lnn_net_builder.h"
#include "lnn_net_ledger_mock.h"
#include "lnn_node_info.h"
#include "lnn_p2p_info.h"
#include "lnn_p2p_info.c"
#include "lnn_service_mock.h"
#include "lnn_sync_info_manager.h"
#include "lnn_trans_mock.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_common.h"
#include "softbus_errcode.h"
#include "message_handler.h"
#include "softbus_json_utils.h"

#define JSON_KEY_P2P_ROLE "P2P_ROLE"
#define JSON_KEY_P2P_MAC "P2P_MAC"
#define JSON_KEY_GO_MAC "GO_MAC"
#define JSON_KEY_WIFIDIRECT_ADDR "WIFIDIRECT_ADDR"

namespace OHOS {
using namespace testing::ext;
using namespace testing;

constexpr int32_t CHANNELID = 0;
constexpr int32_t CHANNELID1 = 1;
constexpr int32_t CHANNELID2 = 2;
constexpr uint32_t LEN = 65;
constexpr char UUID[65] = "abc";
constexpr char NETWORKID[NETWORK_ID_BUF_LEN] = "345678BNHFCF";
constexpr int32_t ERR_MSG_LEN = 0;
constexpr int32_t OK_MSG_LEN = 13;
constexpr uint8_t MSG[] = "123456BNHFCF";
constexpr int32_t PARSE_P2P_INFO_MSG_LEN = 256;

static char *GetP2pInfoMsgTest(const P2pInfo *info)
{
    cJSON *json = cJSON_CreateObject();
    if (json == NULL) {
        LNN_LOGE(LNN_TEST, "create p2p info json fail");
        return NULL;
    }
    if (!AddNumberToJsonObject(json, JSON_KEY_P2P_ROLE, info->p2pRole)) {
        LNN_LOGE(LNN_TEST, "add p2p role fail");
        cJSON_Delete(json);
        return NULL;
    }
    if (!AddStringToJsonObject(json, JSON_KEY_P2P_MAC, info->p2pMac)) {
        LNN_LOGE(LNN_TEST, "add p2p mac fail");
        cJSON_Delete(json);
        return NULL;
    }
    if (!AddStringToJsonObject(json, JSON_KEY_GO_MAC, info->goMac)) {
        LNN_LOGE(LNN_TEST, "add go mac fail");
        cJSON_Delete(json);
        return NULL;
    }
    char *msg = cJSON_PrintUnformatted(json);
    if (msg == NULL) {
        LNN_LOGE(LNN_TEST, "unformat p2p info fail");
    }
    cJSON_Delete(json);
    return msg;
}

class LNNP2pInfoTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void LNNP2pInfoTest::SetUpTestCase()
{
    LooperInit();
    NiceMock<LnnTransInterfaceMock> transMock;
    NiceMock<LnnServicetInterfaceMock> serviceMock;
    EXPECT_CALL(transMock, TransRegisterNetworkingChannelListener).WillRepeatedly(
        DoAll(LnnTransInterfaceMock::ActionOfTransRegister, Return(SOFTBUS_OK)));
    LnnInitSyncInfoManager();
    LnnInitP2p();
    LnnInitWifiDirect();
}

void LNNP2pInfoTest::TearDownTestCase()
{
    NiceMock<LnnServicetInterfaceMock> serviceMock;
    LooperDeinit();
    LnnDeinitSyncInfoManager();
    LnnDeinitP2p();
    LnnDeinitWifiDirect();
}

void LNNP2pInfoTest::SetUp()
{
}

void LNNP2pInfoTest::TearDown()
{
}

/*
 * @tc.name: P2P_INFO_MOCK_TEST_001
 * @tc.desc: test LnnInitLocalP2pInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNP2pInfoTest, P2P_INFO_MOCK_TEST_001, TestSize.Level1)
{
    NiceMock<LnnNetLedgertInterfaceMock> netLedgerMock;
    ON_CALL(netLedgerMock, LnnSetP2pRole).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(netLedgerMock, LnnSetP2pMac).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(netLedgerMock, LnnSetP2pGoMac).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(netLedgerMock, LnnSetWifiDirectAddr).WillByDefault(Return(SOFTBUS_OK));
    NodeInfo info;
    (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));

    int32_t ret = LnnInitLocalP2pInfo(&info);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    ret = LnnInitLocalP2pInfo(nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);

    EXPECT_CALL(netLedgerMock, LnnSetP2pRole(_, _)).WillRepeatedly(Return(SOFTBUS_ERR));
    ret = LnnInitLocalP2pInfo(&info);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    EXPECT_CALL(netLedgerMock, LnnSetP2pMac(_, _)).WillRepeatedly(Return(SOFTBUS_ERR));
    ret = LnnInitLocalP2pInfo(&info);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    EXPECT_CALL(netLedgerMock, LnnSetP2pGoMac(_, _)).WillRepeatedly(Return(SOFTBUS_ERR));
    ret = LnnInitLocalP2pInfo(&info);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    EXPECT_CALL(netLedgerMock, LnnSetWifiDirectAddr(_, _)).WillRepeatedly(Return(SOFTBUS_ERR));
    ret = LnnInitLocalP2pInfo(&info);
    EXPECT_TRUE(ret != SOFTBUS_OK);
}

/*
 * @tc.name: P2P_INFO_MOCK_TEST_002
 * @tc.desc: test LnnSyncP2pInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNP2pInfoTest, P2P_INFO_MOCK_TEST_002, TestSize.Level1)
{
    NiceMock<LnnNetLedgertInterfaceMock> netLedgerMock;
    NiceMock<LnnTransInterfaceMock> transMock;
    NodeInfo info = {
        .p2pInfo.p2pRole = 1,
        .p2pInfo.p2pMac = "abc",
        .p2pInfo.goMac = "abc",
    };
    ON_CALL(netLedgerMock, LnnGetAllOnlineAndMetaNodeInfo).WillByDefault(
        LnnNetLedgertInterfaceMock::ActionOfLnnGetAllOnline);
    ON_CALL(netLedgerMock, LnnGetLocalNodeInfo).WillByDefault(Return(&info));
    ON_CALL(transMock, TransOpenNetWorkingChannel).WillByDefault(Return(CHANNELID));
    ON_CALL(transMock, TransSendNetworkingMessage).WillByDefault(Return(SOFTBUS_OK));
    int32_t ret = LnnSyncP2pInfo();
    SoftBusSleepMs(50);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ON_CALL(netLedgerMock, LnnConvertDlId).WillByDefault(LnnNetLedgertInterfaceMock::
        ActionOfLnnConvertDlId);
    int ret1 = LnnTransInterfaceMock::g_networkListener->onChannelOpened(CHANNELID, UUID, false);
    EXPECT_TRUE(ret1 == SOFTBUS_OK);

    P2pInfo p2pInfo = {
        .p2pRole = 1,
        .p2pMac = "abcd",
        .goMac = "abcd",
    };
    char *p2pMsg = GetP2pInfoMsgTest(&p2pInfo);
    EXPECT_TRUE(p2pMsg != NULL);
    char msg[65] = {0};
    *(int32_t *)msg = 6;
    if (memcpy_s(msg + sizeof(int32_t), LEN - sizeof(int32_t), p2pMsg, strlen(p2pMsg) + 1) != EOK) {
        LNN_LOGE(LNN_TEST, "copy sync info msg for type:");
    }
    cJSON_free(p2pMsg);
    LnnTransInterfaceMock::g_networkListener->onChannelOpenFailed(CHANNELID, UUID);
    LnnTransInterfaceMock::g_networkListener->onChannelClosed(CHANNELID);
    LnnTransInterfaceMock::g_networkListener->onChannelOpened(CHANNELID2, UUID, true);
    LnnTransInterfaceMock::g_networkListener->onMessageReceived(CHANNELID2, msg, LEN);
}

/*
 * @tc.name: P2P_INFO_MOCK_TEST_003
 * @tc.desc: test LnnSyncP2pInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNP2pInfoTest, P2P_INFO_MOCK_TEST_003, TestSize.Level1)
{
    NiceMock<LnnNetLedgertInterfaceMock> netLedgerMock;
    NiceMock<LnnTransInterfaceMock> transMock;
    NodeInfo info = {
        .p2pInfo.p2pRole = 1,
        .p2pInfo.p2pMac = "abc",
        .p2pInfo.goMac = "abc",
    };
    ON_CALL(netLedgerMock, LnnGetLocalNodeInfo).WillByDefault(Return(&info));
    ON_CALL(transMock, TransOpenNetWorkingChannel).WillByDefault(Return(CHANNELID));
    ON_CALL(transMock, TransSendNetworkingMessage).WillByDefault(Return(SOFTBUS_OK));

    EXPECT_CALL(netLedgerMock, LnnGetAllOnlineAndMetaNodeInfo).WillOnce(
        Return(SOFTBUS_OK)).WillRepeatedly(LnnNetLedgertInterfaceMock::ActionOfLnnGetAllOnline);
    int32_t ret = LnnSyncP2pInfo();
    SoftBusSleepMs(2);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    EXPECT_CALL(netLedgerMock, LnnGetLocalNodeInfo).WillOnce(Return(nullptr))
        .WillRepeatedly(Return(&info));
    ret = LnnSyncP2pInfo();
    SoftBusSleepMs(50);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    EXPECT_CALL(transMock, TransOpenNetWorkingChannel).WillOnce(Return(CHANNELID1))
        .WillRepeatedly(Return(CHANNELID));
    ret = LnnSyncP2pInfo();
    SoftBusSleepMs(50);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: P2P_INFO_MOCK_TEST_004
 * @tc.desc: test LnnSyncWifiDirectAddr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNP2pInfoTest, P2P_INFO_MOCK_TEST_004, TestSize.Level1)
{
    NiceMock<LnnNetLedgertInterfaceMock> netLedgerMock;
    NiceMock<LnnTransInterfaceMock> transMock;
    NodeInfo info = {
        .wifiDirectAddr = "abc",
    };
    ON_CALL(netLedgerMock, LnnGetAllOnlineAndMetaNodeInfo).WillByDefault(
        LnnNetLedgertInterfaceMock::ActionOfLnnGetAllOnline);
    ON_CALL(netLedgerMock, LnnGetLocalNodeInfo).WillByDefault(Return(&info));
    ON_CALL(transMock, TransOpenNetWorkingChannel).WillByDefault(Return(CHANNELID));
    ON_CALL(transMock, TransSendNetworkingMessage).WillByDefault(Return(SOFTBUS_OK));
    int32_t ret = LnnSyncWifiDirectAddr();
    SoftBusSleepMs(50);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ON_CALL(netLedgerMock, LnnConvertDlId).WillByDefault(LnnNetLedgertInterfaceMock::
        ActionOfLnnConvertDlId);
    int ret1 = LnnTransInterfaceMock::g_networkListener->onChannelOpened(CHANNELID, UUID, false);
    EXPECT_TRUE(ret1 == SOFTBUS_OK);

    LnnTransInterfaceMock::g_networkListener->onChannelOpenFailed(CHANNELID, UUID);
    LnnTransInterfaceMock::g_networkListener->onChannelClosed(CHANNELID);
    LnnTransInterfaceMock::g_networkListener->onChannelOpened(CHANNELID2, UUID, true);
}

/*
 * @tc.name: P2P_INFO_MOCK_TEST_005
 * @tc.desc: test LnnSyncWifiDirectAddr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNP2pInfoTest, P2P_INFO_MOCK_TEST_005, TestSize.Level1)
{
    NiceMock<LnnNetLedgertInterfaceMock> netLedgerMock;
    NiceMock<LnnTransInterfaceMock> transMock;
    NodeInfo info = {
        .wifiDirectAddr = "abc",
    };
    ON_CALL(netLedgerMock, LnnGetLocalNodeInfo).WillByDefault(Return(&info));
    ON_CALL(transMock, TransOpenNetWorkingChannel).WillByDefault(Return(CHANNELID));
    ON_CALL(transMock, TransSendNetworkingMessage).WillByDefault(Return(SOFTBUS_OK));

    EXPECT_CALL(netLedgerMock, LnnGetAllOnlineAndMetaNodeInfo).WillOnce(
        Return(SOFTBUS_OK)).WillRepeatedly(LnnNetLedgertInterfaceMock::ActionOfLnnGetAllOnline);
    int32_t ret = LnnSyncWifiDirectAddr();
    SoftBusSleepMs(2);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    EXPECT_CALL(netLedgerMock, LnnGetLocalNodeInfo).WillOnce(Return(nullptr))
        .WillRepeatedly(Return(&info));
    ret = LnnSyncWifiDirectAddr();
    SoftBusSleepMs(50);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: LNN_PARSE_P2P_INFO_MSG_TEST_001
 * @tc.desc: test LnnParseP2pInfoMsg
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNP2pInfoTest, LNN_PARSE_P2P_INFO_MSG_TEST_001, TestSize.Level1)
{
    char msg[PARSE_P2P_INFO_MSG_LEN] = "{\"P2P_ROLE\":1234}";
    P2pInfo info = {};
    int32_t ret = LnnParseP2pInfoMsg(msg, &info, 0);
    EXPECT_TRUE(ret == SOFTBUS_PARSE_JSON_ERR);

    (void)strcpy_s(msg, sizeof(msg), "{\"WIFI_CFG\":1234}");
    ret = LnnParseP2pInfoMsg(msg, &info, strlen(msg) + 1);
    EXPECT_TRUE(ret == SOFTBUS_ERR);

    (void)strcpy_s(msg, sizeof(msg), "{\"P2P_ROLE\":1234}");
    ret = LnnParseP2pInfoMsg(msg, &info, strlen(msg) + 1);
    EXPECT_TRUE(ret == SOFTBUS_ERR);

    (void)strcpy_s(msg, sizeof(msg), "{\"P2P_ROLE\":1234, \"WIFI_CFG\":\"wifi_cgf\"}");
    ret = LnnParseP2pInfoMsg(msg, &info, strlen(msg) + 1);
    EXPECT_TRUE(ret == SOFTBUS_ERR);

    (void)strcpy_s(msg, sizeof(msg), "{\"P2P_ROLE\":1234, \"WIFI_CFG\":\"wifi_cgf\", "\
    "\"CHAN_LIST_5G\":\"CHAN_LIST_5G\"}");
    ret = LnnParseP2pInfoMsg(msg, &info, strlen(msg) + 1);
    EXPECT_TRUE(ret == SOFTBUS_ERR);

    (void)strcpy_s(msg, sizeof(msg), "{\"P2P_ROLE\":1234, \"WIFI_CFG\":\"wifi_cgf\", "\
        "\"CHAN_LIST_5G\":\"CHAN_LIST_5G\", \"STA_FREQUENCY\":2008}");
    ret = LnnParseP2pInfoMsg(msg, &info, strlen(msg) + 1);
    EXPECT_TRUE(ret == SOFTBUS_ERR);

    (void)strcpy_s(msg, sizeof(msg), "{\"P2P_ROLE\":1234, \"WIFI_CFG\":\"wifi_cgf\", "\
        "\"CHAN_LIST_5G\":\"CHAN_LIST_5G\", \"STA_FREQUENCY\":2008, \"P2P_MAC\":\"P2P_MAC\"}");
    ret = LnnParseP2pInfoMsg(msg, &info, strlen(msg) + 1);
    EXPECT_TRUE(ret == SOFTBUS_ERR);

    (void)strcpy_s(msg, sizeof(msg),  "{\"P2P_ROLE\":1234, \"WIFI_CFG\":\"wifi_cgf\", "\
        "\"CHAN_LIST_5G\":\"CHAN_LIST_5G\",\"STA_FREQUENCY\":2008, \"P2P_MAC\":\"P2P_MAC\", \"GO_MAC\":\"GO_MAC\"}");
    ret = LnnParseP2pInfoMsg(msg, &info, strlen(msg) + 1);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: ON_RECEIVE_P2P_SYNC_INFO_MSG_TEST_001
 * @tc.desc: test OnReceiveP2pSyncInfoMsg
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNP2pInfoTest, ON_RECEIVE_P2P_SYNC_INFO_MSG_TEST_001, TestSize.Level1)
{
    OnReceiveP2pSyncInfoMsg(LNN_INFO_TYPE_OFFLINE, NETWORKID, MSG, ERR_MSG_LEN);
    OnReceiveP2pSyncInfoMsg(LNN_INFO_TYPE_P2P_INFO, NETWORKID, nullptr, ERR_MSG_LEN);
    OnReceiveP2pSyncInfoMsg(LNN_INFO_TYPE_P2P_INFO, NETWORKID, MSG, ERR_MSG_LEN);
    OnReceiveP2pSyncInfoMsg(LNN_INFO_TYPE_P2P_INFO, nullptr, MSG, OK_MSG_LEN);
}
} // namespace OHOS
