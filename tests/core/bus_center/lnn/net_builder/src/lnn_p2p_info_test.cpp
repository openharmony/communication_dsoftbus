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

#include "lnn_net_ledger_mock.h"
#include "lnn_p2p_info.c"
#include "lnn_p2p_info.h"
#include "lnn_service_mock.h"
#include "lnn_sync_info_mock.h"

#define JSON_KEY_P2P_ROLE        "P2P_ROLE"
#define JSON_KEY_P2P_MAC         "P2P_MAC"
#define JSON_KEY_GO_MAC          "GO_MAC"
#define JSON_KEY_WIFIDIRECT_ADDR "WIFIDIRECT_ADDR"
#define OH_OS_TYPE               10
#define HO_OS_TYPE               11

namespace OHOS {
using namespace testing::ext;
using namespace testing;

constexpr char NETWORKID[NETWORK_ID_BUF_LEN] = "345678BNHFCF";
constexpr int32_t ERR_MSG_LEN = 0;
constexpr int32_t OK_MSG_LEN = 13;
constexpr uint8_t MSG[] = "123456BNHFCF";
constexpr int32_t PARSE_P2P_INFO_MSG_LEN = 256;

class LNNP2pInfoTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void LNNP2pInfoTest::SetUpTestCase() { }

void LNNP2pInfoTest::TearDownTestCase() { }

void LNNP2pInfoTest::SetUp() { }

void LNNP2pInfoTest::TearDown() { }

/*
 * @tc.name: LNN_GET_P2P_INFO_MSG_TEST_001
 * @tc.desc: test LnnGetP2pInfoMsg
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNP2pInfoTest, LNN_GET_P2P_INFO_MSG_TEST_001, TestSize.Level1)
{
    P2pInfo info = {
        .p2pRole = 1234,
        .wifiCfg = "wifi_cgf",
        .chanList5g = "chanList5g",
        .staFrequency = 500,
        .p2pMac = "p2pMac",
        .goMac = "goMac",
    };
    char *ret = LnnGetP2pInfoMsg(&info);
    EXPECT_NE(ret, nullptr);
}

/*
 * @tc.name: LNN_GET_WIFI_DIRECT_ADDR_MSG_TEST_001
 * @tc.desc: test LnnGetWifiDirectAddrMsg
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNP2pInfoTest, LNN_GET_WIFI_DIRECT_ADDR_MSG_TEST_001, TestSize.Level1)
{
    NodeInfo info = {
        .wifiDirectAddr = "wifiDirectAddr",
    };
    char *ret = LnnGetWifiDirectAddrMsg(&info);
    EXPECT_NE(ret, nullptr);
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
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = LnnInitLocalP2pInfo(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    EXPECT_CALL(netLedgerMock, LnnSetP2pRole(_, _)).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    ret = LnnInitLocalP2pInfo(&info);
    EXPECT_NE(ret, SOFTBUS_OK);

    EXPECT_CALL(netLedgerMock, LnnSetP2pMac(_, _)).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    ret = LnnInitLocalP2pInfo(&info);
    EXPECT_NE(ret, SOFTBUS_OK);

    EXPECT_CALL(netLedgerMock, LnnSetP2pGoMac(_, _)).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    ret = LnnInitLocalP2pInfo(&info);
    EXPECT_NE(ret, SOFTBUS_OK);

    EXPECT_CALL(netLedgerMock, LnnSetWifiDirectAddr(_, _)).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    ret = LnnInitLocalP2pInfo(&info);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_PARSE_WIFI_DIRECT_ADDR_MSG_TEST_001
 * @tc.desc: test LnnParseWifiDirectAddrMsg
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNP2pInfoTest, LNN_PARSE_WIFI_DIRECT_ADDR_MSG_TEST_001, TestSize.Level1)
{
    char wifiDirectAddr[MAC_LEN] = { 0 };
    char msg[PARSE_P2P_INFO_MSG_LEN] = "{\"WIFIDIRECT_ADDR\":\"192.168.12.12\"}";
    int32_t ret = LnnParseWifiDirectAddrMsg(msg, wifiDirectAddr, strlen(msg));
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = LnnParseWifiDirectAddrMsg(nullptr, wifiDirectAddr, 0);
    EXPECT_EQ(ret, SOFTBUS_PARSE_JSON_ERR);
    char msg1[PARSE_P2P_INFO_MSG_LEN] = "{\"test\":\"192.168.12.12\"}";
    ret = LnnParseWifiDirectAddrMsg(msg1, wifiDirectAddr, strlen(msg1));
    EXPECT_EQ(ret, SOFTBUS_GET_INFO_FROM_JSON_FAIL);
}

/*
 * @tc.name: IS_NEED_SYNC_P2P_INFO_TEST_001
 * @tc.desc: test IsNeedSyncP2pInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNP2pInfoTest, IS_NEED_SYNC_P2P_INFO_TEST_001, TestSize.Level1)
{
    NiceMock<LnnServicetInterfaceMock> lnnServiceMock;
    EXPECT_CALL(lnnServiceMock, IsFeatureSupport).WillOnce(Return(false));
    NodeInfo localInfo;
    (void)memset_s(&localInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    NodeBasicInfo info;
    (void)memset_s(&info, sizeof(NodeBasicInfo), 0, sizeof(NodeBasicInfo));
    bool ret = IsNeedSyncP2pInfo(&localInfo, &info);
    EXPECT_EQ(ret, true);
    EXPECT_CALL(lnnServiceMock, IsFeatureSupport).WillRepeatedly(Return(true));
    int32_t osType = HO_OS_TYPE;
    NiceMock<LnnNetLedgertInterfaceMock> netLedgerMock;
    EXPECT_CALL(netLedgerMock, LnnGetOsTypeByNetworkId)
        .WillOnce(DoAll(SetArgPointee<1>(osType), Return(SOFTBUS_INVALID_PARAM)));
    ret = IsNeedSyncP2pInfo(&localInfo, &info);
    EXPECT_EQ(ret, true);
}

/*
 * @tc.name: PROCESS_SYNC_P2P_INFO_TEST_001
 * @tc.desc: test ProcessSyncP2pInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNP2pInfoTest, PROCESS_SYNC_P2P_INFO_TEST_001, TestSize.Level1)
{
    NodeInfo info = {
        .p2pInfo.p2pRole = 1234,
        .p2pInfo.wifiCfg = "wifi_cgf",
        .p2pInfo.chanList5g = "chanList5g",
        .p2pInfo.staFrequency = 500,
        .p2pInfo.p2pMac = "p2pMac",
        .p2pInfo.goMac = "goMac",
        .wifiDirectAddr = "wifiDirectAddr",
    };
    NiceMock<LnnNetLedgertInterfaceMock> netLedgerMock;
    EXPECT_CALL(netLedgerMock, LnnGetAllOnlineAndMetaNodeInfo)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillOnce(Return(SOFTBUS_INVALID_PARAM));
    ProcessSyncP2pInfo(nullptr);
    ProcessSyncWifiDirectAddr(nullptr);
    int32_t infoNum = 0;
    EXPECT_CALL(netLedgerMock, LnnGetAllOnlineAndMetaNodeInfo)
        .WillOnce(DoAll(SetArgPointee<1>(infoNum), Return(SOFTBUS_OK)))
        .WillOnce(DoAll(SetArgPointee<1>(infoNum), Return(SOFTBUS_OK)));
    ProcessSyncP2pInfo(nullptr);
    ProcessSyncWifiDirectAddr(nullptr);
    EXPECT_CALL(netLedgerMock, LnnGetAllOnlineAndMetaNodeInfo)
        .WillRepeatedly(LnnNetLedgertInterfaceMock::ActionOfLnnGetAllOnline);
    EXPECT_CALL(netLedgerMock, LnnGetLocalNodeInfo).WillRepeatedly(Return(nullptr));
    ProcessSyncP2pInfo(nullptr);
    ProcessSyncWifiDirectAddr(nullptr);
    EXPECT_CALL(netLedgerMock, LnnGetLocalNodeInfo).WillRepeatedly(Return(&info));
    EXPECT_CALL(netLedgerMock, LnnIsLSANode).WillRepeatedly(Return(false));
    EXPECT_CALL(netLedgerMock, LnnGetOsTypeByNetworkId)
        .WillRepeatedly(DoAll(SetArgPointee<1>(HO_OS_TYPE), Return(SOFTBUS_INVALID_PARAM)));
    NiceMock<LnnServicetInterfaceMock> lnnServiceMock;
    EXPECT_CALL(lnnServiceMock, IsFeatureSupport).WillRepeatedly(Return(false));
    NiceMock<LnnSyncInfoInterfaceMock> lnnSyncInfoMock;
    EXPECT_CALL(lnnSyncInfoMock, LnnSendSyncInfoMsg).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    ProcessSyncP2pInfo(nullptr);
    ProcessSyncWifiDirectAddr(nullptr);
}

/*
 * @tc.name: PROCESS_SYNC_P2P_INFO_TEST_002
 * @tc.desc: test ProcessSyncP2pInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNP2pInfoTest, PROCESS_SYNC_P2P_INFO_TEST_002, TestSize.Level1)
{
    NodeInfo info = {
        .p2pInfo.p2pRole = 1234,
        .p2pInfo.wifiCfg = "wifi_cgf",
        .p2pInfo.chanList5g = "chanList5g",
        .p2pInfo.staFrequency = 500,
        .p2pInfo.p2pMac = "p2pMac",
        .p2pInfo.goMac = "goMac",
        .wifiDirectAddr = "wifiDirectAddr",
    };
    NiceMock<LnnNetLedgertInterfaceMock> netLedgerMock;
    EXPECT_CALL(netLedgerMock, LnnGetAllOnlineAndMetaNodeInfo)
        .WillRepeatedly(LnnNetLedgertInterfaceMock::ActionOfLnnGetAllOnline);
    EXPECT_CALL(netLedgerMock, LnnGetLocalNodeInfo).WillRepeatedly(Return(&info));
    EXPECT_CALL(netLedgerMock, LnnIsLSANode).WillRepeatedly(Return(true));
    ProcessSyncP2pInfo(nullptr);
    ProcessSyncWifiDirectAddr(nullptr);
    EXPECT_CALL(netLedgerMock, LnnGetOsTypeByNetworkId)
        .WillRepeatedly(DoAll(SetArgPointee<1>(OH_OS_TYPE), Return(SOFTBUS_OK)));
    NiceMock<LnnServicetInterfaceMock> lnnServiceMock;
    EXPECT_CALL(lnnServiceMock, IsFeatureSupport).WillRepeatedly(Return(false));
    NiceMock<LnnSyncInfoInterfaceMock> lnnSyncInfoMock;
    EXPECT_CALL(lnnSyncInfoMock, LnnSendSyncInfoMsg).WillRepeatedly(Return(SOFTBUS_OK));
    ProcessSyncP2pInfo(nullptr);
    ProcessSyncWifiDirectAddr(nullptr);
    EXPECT_CALL(netLedgerMock, LnnGetOsTypeByNetworkId)
        .WillRepeatedly(DoAll(SetArgPointee<1>(HO_OS_TYPE), Return(SOFTBUS_OK)));
    ProcessSyncWifiDirectAddr(nullptr);
}

/*
 * @tc.name: ON_RECEIVE_WIFI_DIRECT_SYNC_ADDR_TEST_001
 * @tc.desc: test OnReceiveWifiDirectSyncAddr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNP2pInfoTest, ON_RECEIVE_WIFI_DIRECT_SYNC_ADDR_TEST_001, TestSize.Level1)
{
    NodeInfo info = {
        .wifiDirectAddr = "wifiDirectAddr",
    };
    char *msg = LnnGetWifiDirectAddrMsg(&info);
    EXPECT_NE(msg, nullptr);
    OnReceiveWifiDirectSyncAddr(LNN_INFO_TYPE_OFFLINE, NETWORKID, MSG, ERR_MSG_LEN);
    OnReceiveWifiDirectSyncAddr(LNN_INFO_TYPE_WIFI_DIRECT, NETWORKID, nullptr, ERR_MSG_LEN);
    OnReceiveWifiDirectSyncAddr(LNN_INFO_TYPE_WIFI_DIRECT, NETWORKID, MSG, ERR_MSG_LEN);
    OnReceiveWifiDirectSyncAddr(LNN_INFO_TYPE_WIFI_DIRECT, nullptr, MSG, OK_MSG_LEN);
    NiceMock<LnnNetLedgertInterfaceMock> netLedgerMock;
    EXPECT_CALL(netLedgerMock, LnnSetDLWifiDirectAddr)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    OnReceiveWifiDirectSyncAddr(
        LNN_INFO_TYPE_WIFI_DIRECT, NETWORKID, reinterpret_cast<const uint8_t *>(msg), strlen(msg));
    OnReceiveWifiDirectSyncAddr(
        LNN_INFO_TYPE_WIFI_DIRECT, NETWORKID, reinterpret_cast<const uint8_t *>(msg), strlen(msg));
}

/*
 * @tc.name: LNN_SYNC_P2P_INFO_TEST_001
 * @tc.desc: test LnnSyncP2pInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNP2pInfoTest, LNN_SYNC_P2P_INFO_TEST_001, TestSize.Level1)
{
    NiceMock<LnnServicetInterfaceMock> lnnServiceMock;
    EXPECT_CALL(lnnServiceMock, LnnAsyncCallbackHelper)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = LnnSyncP2pInfo();
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnSyncP2pInfo();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_SYNC_WIFI_DIRECT_ADDR_TEST_001
 * @tc.desc: test LnnSyncWifiDirectAddr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNP2pInfoTest, LNN_SYNC_WIFI_DIRECT_ADDR_TEST_001, TestSize.Level1)
{
    NiceMock<LnnServicetInterfaceMock> lnnServiceMock;
    EXPECT_CALL(lnnServiceMock, LnnAsyncCallbackHelper)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = LnnSyncWifiDirectAddr();
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnSyncWifiDirectAddr();
    EXPECT_EQ(ret, SOFTBUS_OK);
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
    EXPECT_TRUE(ret == SOFTBUS_GET_INFO_FROM_JSON_FAIL);

    (void)strcpy_s(msg, sizeof(msg), "{\"P2P_ROLE\":1234}");
    ret = LnnParseP2pInfoMsg(msg, &info, strlen(msg) + 1);
    EXPECT_TRUE(ret == SOFTBUS_GET_INFO_FROM_JSON_FAIL);

    (void)strcpy_s(msg, sizeof(msg), "{\"P2P_ROLE\":1234, \"WIFI_CFG\":\"wifi_cgf\"}");
    ret = LnnParseP2pInfoMsg(msg, &info, strlen(msg) + 1);
    EXPECT_TRUE(ret == SOFTBUS_GET_INFO_FROM_JSON_FAIL);

    (void)strcpy_s(msg, sizeof(msg),
        "{\"P2P_ROLE\":1234, \"WIFI_CFG\":\"wifi_cgf\", "
        "\"CHAN_LIST_5G\":\"CHAN_LIST_5G\"}");
    ret = LnnParseP2pInfoMsg(msg, &info, strlen(msg) + 1);
    EXPECT_TRUE(ret == SOFTBUS_GET_INFO_FROM_JSON_FAIL);

    (void)strcpy_s(msg, sizeof(msg),
        "{\"P2P_ROLE\":1234, \"WIFI_CFG\":\"wifi_cgf\", "
        "\"CHAN_LIST_5G\":\"CHAN_LIST_5G\", \"STA_FREQUENCY\":2008}");
    ret = LnnParseP2pInfoMsg(msg, &info, strlen(msg) + 1);
    EXPECT_TRUE(ret == SOFTBUS_GET_INFO_FROM_JSON_FAIL);

    (void)strcpy_s(msg, sizeof(msg),
        "{\"P2P_ROLE\":1234, \"WIFI_CFG\":\"wifi_cgf\", "
        "\"CHAN_LIST_5G\":\"CHAN_LIST_5G\", \"STA_FREQUENCY\":2008, \"P2P_MAC\":\"P2P_MAC\"}");
    ret = LnnParseP2pInfoMsg(msg, &info, strlen(msg) + 1);
    EXPECT_TRUE(ret == SOFTBUS_GET_INFO_FROM_JSON_FAIL);

    (void)strcpy_s(msg, sizeof(msg),
        "{\"P2P_ROLE\":1234, \"WIFI_CFG\":\"wifi_cgf\", "
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
    P2pInfo info = {
        .p2pRole = 1234,
        .wifiCfg = "wifi_cgf",
        .chanList5g = "chanList5g",
        .staFrequency = 500,
        .p2pMac = "p2pMac",
        .goMac = "goMac",
    };
    char *msg = LnnGetP2pInfoMsg(&info);
    EXPECT_NE(msg, nullptr);
    OnReceiveP2pSyncInfoMsg(LNN_INFO_TYPE_OFFLINE, NETWORKID, MSG, ERR_MSG_LEN);
    OnReceiveP2pSyncInfoMsg(LNN_INFO_TYPE_P2P_INFO, NETWORKID, nullptr, ERR_MSG_LEN);
    OnReceiveP2pSyncInfoMsg(LNN_INFO_TYPE_P2P_INFO, NETWORKID, MSG, ERR_MSG_LEN);
    OnReceiveP2pSyncInfoMsg(LNN_INFO_TYPE_P2P_INFO, nullptr, MSG, OK_MSG_LEN);
    NiceMock<LnnNetLedgertInterfaceMock> netLedgerMock;
    EXPECT_CALL(netLedgerMock, LnnSetDLP2pInfo).WillOnce(Return(false)).WillRepeatedly(Return(true));
    OnReceiveP2pSyncInfoMsg(LNN_INFO_TYPE_P2P_INFO, NETWORKID, reinterpret_cast<const uint8_t *>(msg), strlen(msg));
    OnReceiveP2pSyncInfoMsg(LNN_INFO_TYPE_P2P_INFO, NETWORKID, reinterpret_cast<const uint8_t *>(msg), strlen(msg));
}
} // namespace OHOS
