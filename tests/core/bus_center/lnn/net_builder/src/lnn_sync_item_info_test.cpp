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

#include "lnn_net_builder_mock.h"
#include "lnn_net_ledger_mock.h"
#include "lnn_service_mock.h"
#include "lnn_sync_info_mock.h"
#include "lnn_sync_item_info.c"
#include "lnn_sync_item_info.h"
#include "softbus_adapter_mem.h"
#include "softbus_common.h"
#include "softbus_error_code.h"

#define TEST_VALID_PEER_NETWORKID    "12345678"
#define TEST_VALID_PEER_NETWORKID1   "123456"
#define TEST_VALID_PEER_NETWORKID2   "1234"
#define TEST_VALID_UDID_LEN          32
#define TEST_TARGET_BSSID            "targetBssid"
#define TEST_SSID                    "ssid"
#define TEST_PRE_SHARED_KEY          "preSharedKey"
#define TEST_INT_VALUE               1
#define INVALID_WIFI_MAX_CONFIG_SIZE 11
namespace OHOS {
using namespace testing;
using namespace testing::ext;

class LNNSyncInfoItemTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void LNNSyncInfoItemTest::SetUpTestCase() { }

void LNNSyncInfoItemTest::TearDownTestCase() { }

void LNNSyncInfoItemTest::SetUp() { }

void LNNSyncInfoItemTest::TearDown() { }

/*
 * @tc.name: WIFI_CONNECT_TO_TARGET_AP_TEST_001
 * @tc.desc: test WifiConnectToTargetAp
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNSyncInfoItemTest, WIFI_CONNECT_TO_TARGET_AP_TEST_001, TestSize.Level1)
{
    SoftBusWifiDevConf *result1 = static_cast<SoftBusWifiDevConf *>(SoftBusCalloc(sizeof(SoftBusWifiDevConf)));
    EXPECT_TRUE(result1 != nullptr);
    EXPECT_EQ(EOK, strcpy_s(result1->ssid, WIFI_MAX_SSID_LEN, TEST_SSID));
    SoftBusWifiDevConf *result2 = static_cast<SoftBusWifiDevConf *>(SoftBusCalloc(sizeof(SoftBusWifiDevConf)));
    EXPECT_TRUE(result2 != nullptr);
    EXPECT_EQ(EOK, strcpy_s(result2->ssid, WIFI_MAX_SSID_LEN, TEST_SSID));
    SoftBusWifiDevConf *result3 = static_cast<SoftBusWifiDevConf *>(SoftBusCalloc(sizeof(SoftBusWifiDevConf)));
    EXPECT_TRUE(result3 != nullptr);
    EXPECT_EQ(EOK, strcpy_s(result3->ssid, WIFI_MAX_SSID_LEN, TEST_SSID));
    SoftBusWifiDevConf *result4 = static_cast<SoftBusWifiDevConf *>(SoftBusCalloc(sizeof(SoftBusWifiDevConf)));
    EXPECT_TRUE(result4 != nullptr);
    EXPECT_EQ(EOK, strcpy_s(result4->ssid, WIFI_MAX_SSID_LEN, TEST_SSID));
    SoftBusWifiDevConf *result5 = static_cast<SoftBusWifiDevConf *>(SoftBusCalloc(sizeof(SoftBusWifiDevConf)));
    EXPECT_TRUE(result5 != nullptr);
    EXPECT_EQ(EOK, strcpy_s(result5->ssid, WIFI_MAX_SSID_LEN, TEST_SSID));
    NiceMock<LnnServicetInterfaceMock> LnnServiceMock;
    EXPECT_CALL(LnnServiceMock, SoftBusGetWifiDeviceConfig)
        .WillOnce(DoAll(
            SetArgPointee<0>(*result1), SetArgPointee<1>(INVALID_WIFI_MAX_CONFIG_SIZE), Return(SOFTBUS_INVALID_PARAM)))
        .WillOnce(DoAll(SetArgPointee<0>(*result2), SetArgPointee<1>(INVALID_WIFI_MAX_CONFIG_SIZE), Return(SOFTBUS_OK)))
        .WillOnce(DoAll(SetArgPointee<0>(*result3), SetArgPointee<1>(WIFI_MAX_CONFIG_SIZE), Return(SOFTBUS_OK)))
        .WillOnce(DoAll(SetArgPointee<0>(*result4), SetArgPointee<1>(WIFI_MAX_CONFIG_SIZE), Return(SOFTBUS_OK)))
        .WillOnce(DoAll(SetArgPointee<0>(*result5), SetArgPointee<1>(WIFI_MAX_CONFIG_SIZE), Return(SOFTBUS_OK)));
    const unsigned char targetBssid[] = "123456";
    int32_t ret = WifiConnectToTargetAp(targetBssid, TEST_VALID_PEER_NETWORKID1);
    EXPECT_EQ(ret, SOFTBUS_GET_WIFI_DEVICE_CONFIG_FAIL);
    ret = WifiConnectToTargetAp(targetBssid, TEST_VALID_PEER_NETWORKID1);
    EXPECT_EQ(ret, SOFTBUS_GET_WIFI_DEVICE_CONFIG_FAIL);
    EXPECT_CALL(LnnServiceMock, SoftBusDisconnectDevice)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(LnnServiceMock, SoftBusConnectToDevice)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    ret = WifiConnectToTargetAp(targetBssid, TEST_VALID_PEER_NETWORKID1);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = WifiConnectToTargetAp(targetBssid, TEST_VALID_PEER_NETWORKID1);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = WifiConnectToTargetAp(targetBssid, TEST_VALID_PEER_NETWORKID1);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_SEND_TRANS_REQ_TEST_001
 * @tc.desc: test LnnSendTransReq
 * @tc.type: FUNC
 * @tc.require:I5PRUD
 */
HWTEST_F(LNNSyncInfoItemTest, LNN_SEND_TRANS_REQ_TEST_001, TestSize.Level1)
{
    NiceMock<LnnNetLedgertInterfaceMock> LedgerMock;
    EXPECT_CALL(LedgerMock, LnnSetDLBssTransInfo)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    NiceMock<LnnSyncInfoInterfaceMock> SyncInfoMock;
    EXPECT_CALL(SyncInfoMock, LnnSendSyncInfoMsg)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    BssTransInfo transInfo;
    (void)memset_s(&transInfo, sizeof(BssTransInfo), 0, sizeof(BssTransInfo));
    EXPECT_EQ(EOK, strcpy_s(transInfo.ssid, WIFI_SSID_LEN, TEST_VALID_PEER_NETWORKID1));
    EXPECT_EQ(EOK, strcpy_s((char *)transInfo.targetBssid, WIFI_MAC_LEN, TEST_VALID_PEER_NETWORKID2));
    int32_t ret = LnnSendTransReq(TEST_VALID_PEER_NETWORKID, &transInfo);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnSendTransReq(TEST_VALID_PEER_NETWORKID, &transInfo);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnSendTransReq(TEST_VALID_PEER_NETWORKID, &transInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = LnnSendTransReq(nullptr, &transInfo);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnSendTransReq(TEST_VALID_PEER_NETWORKID, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LNN_ONRECEIVE_DEVICE_NAME_TEST_001
 * @tc.desc: test OnReceiveDeviceName
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNSyncInfoItemTest, LNN_ONRECEIVE_DEVICE_NAME_TEST_001, TestSize.Level1)
{
    NiceMock<LnnNetLedgertInterfaceMock> LedgerMock;
    NiceMock<LnnSyncInfoInterfaceMock> SyncInfoMock;
    EXPECT_CALL(LedgerMock, LnnConvertDlId).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(SyncInfoMock, LnnRegSyncInfoHandler).WillRepeatedly(Return(SOFTBUS_OK));
    OnReceiveDeviceName(LNN_INFO_TYPE_DEVICE_NAME, nullptr, nullptr, TEST_VALID_UDID_LEN);
    uint8_t msg[WIFI_SSID_LEN] = { 1, 2, 3, 4, 5 };
    OnReceiveDeviceName(LNN_INFO_TYPE_BATTERY_INFO, nullptr, msg, TEST_VALID_UDID_LEN);
    OnReceiveDeviceName(LNN_INFO_TYPE_DEVICE_NAME, nullptr, msg, TEST_VALID_UDID_LEN);
    int32_t ret = LnnInitOffline();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_ONRECEIVE_TRANS_REQ_MSG_TEST_001
 * @tc.desc: test OnReceiveTransReqMsg
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNSyncInfoItemTest, LNN_ONRECEIVE_TRANS_REQ_MSG_TEST_001, TestSize.Level1)
{
    NiceMock<LnnNetLedgertInterfaceMock> LedgerMock;
    NiceMock<LnnSyncInfoInterfaceMock> SyncInfoMock;
    EXPECT_CALL(LedgerMock, LnnConvertDlId).WillOnce(Return(SOFTBUS_INVALID_PARAM)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(LedgerMock, LnnSetDLDeviceInfoName)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(SyncInfoMock, LnnRegSyncInfoHandler).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    OnReceiveTransReqMsg(LNN_INFO_TYPE_TOPO_UPDATE, nullptr, nullptr, TEST_VALID_UDID_LEN);
    OnReceiveTransReqMsg(LNN_INFO_TYPE_BSS_TRANS, nullptr, nullptr, TEST_VALID_UDID_LEN);
    OnReceiveTransReqMsg(LNN_INFO_TYPE_BSS_TRANS, nullptr, nullptr, TEST_VALID_UDID_LEN);
    OnReceiveTransReqMsg(LNN_INFO_TYPE_BSS_TRANS, nullptr, nullptr, TEST_VALID_UDID_LEN);
    int32_t ret = LnnInitOffline();
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LNN_ONRECEIVE_BR_OFFLINE_TEST_001
 * @tc.desc: test OnReceiveBrOffline
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNSyncInfoItemTest, LNN_ONRECEIVE_BR_OFFLINE_TEST_001, TestSize.Level1)
{
    NiceMock<LnnNetLedgertInterfaceMock> LedgerMock;
    EXPECT_CALL(LedgerMock, LnnConvertDlId).WillOnce(Return(SOFTBUS_INVALID_PARAM)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(LedgerMock, LnnGetCnnCode)
        .WillOnce(Return(INVALID_CONNECTION_CODE_VALUE))
        .WillRepeatedly(Return(SOFTBUS_OK));
    uint32_t len = sizeof(int32_t);
    uint32_t tmpMsg;
    const uint8_t *msg = reinterpret_cast<const uint8_t *>(&tmpMsg);
    OnReceiveBrOffline(LNN_INFO_TYPE_P2P_INFO, nullptr, nullptr, len);
    OnReceiveBrOffline(LNN_INFO_TYPE_OFFLINE, nullptr, nullptr, len);
    OnReceiveBrOffline(LNN_INFO_TYPE_OFFLINE, nullptr, msg, len + 1);
    OnReceiveBrOffline(LNN_INFO_TYPE_OFFLINE, nullptr, msg, len);
    OnReceiveBrOffline(LNN_INFO_TYPE_OFFLINE, nullptr, msg, len);
    OnReceiveBrOffline(LNN_INFO_TYPE_OFFLINE, nullptr, msg, len);
}

/*
 * @tc.name: FILL_TARGET_WIFI_CONFIG_TEST_001
 * @tc.desc: test FillTargetWifiConfig
 * @tc.type: FUNC
 * @tc.require:I5PRUD
 */
HWTEST_F(LNNSyncInfoItemTest, FILL_TARGET_WIFI_CONFIG_TEST_001, TestSize.Level1)
{
    SoftBusWifiDevConf conWifiConf = {
        .securityType = TEST_INT_VALUE,
        .isHiddenSsid = TEST_INT_VALUE,
    };
    EXPECT_EQ(EOK, strcpy_s(conWifiConf.preSharedKey, WIFI_MAX_KEY_LEN, TEST_PRE_SHARED_KEY));
    SoftBusWifiDevConf targetWifiConf;
    (void)memset_s(&targetWifiConf, sizeof(SoftBusWifiDevConf), 0, sizeof(SoftBusWifiDevConf));
    const unsigned char *targetBssid = reinterpret_cast<const unsigned char *>(const_cast<char *>(TEST_PRE_SHARED_KEY));
    int32_t ret = FillTargetWifiConfig(targetBssid, TEST_SSID, &conWifiConf, &targetWifiConf);
    EXPECT_EQ(ret, SOFTBUS_OK);
}
} // namespace OHOS
