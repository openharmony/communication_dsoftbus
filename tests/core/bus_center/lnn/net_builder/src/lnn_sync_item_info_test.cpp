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

#include "lnn_auth_mock.h"
#include "lnn_connection_fsm.h"
#include "lnn_devicename_info.h"
#include "lnn_net_builder.h"
#include "lnn_service_mock.h"
#include "message_handler.h"
#include "softbus_adapter_mem.h"
#include "softbus_common.h"
#include "softbus_errcode.h"
#include "lnn_sync_item_info.h"
#include "lnn_sync_item_info.c"

#define TEST_VALID_PEER_NETWORKID "12345678"
#define TEST_VALID_PEER_NETWORKID1 "123456"
#define TEST_VALID_PEER_NETWORKID2 "1234"
#define TEST_VALID_UDID_LEN 32

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

void LNNSyncInfoItemTest::SetUpTestCase()
{
    LooperInit();
}

void LNNSyncInfoItemTest::TearDownTestCase()
{
    LooperDeinit();
}

void LNNSyncInfoItemTest::SetUp()
{
}

void LNNSyncInfoItemTest::TearDown()
{
}

/*
* @tc.name: LNN_SEND_TRANS_REQ_TEST_001
* @tc.desc: test LnnSendTransReq
* @tc.type: FUNC
* @tc.require:I5PRUD
*/
HWTEST_F(LNNSyncInfoItemTest, LNN_SEND_TRANS_REQ_TEST_001, TestSize.Level1)
{
    BssTransInfo *transInfo = nullptr;
    transInfo = reinterpret_cast<BssTransInfo *>(SoftBusMalloc(sizeof(BssTransInfo)));
    EXPECT_TRUE(transInfo != nullptr);
    memset_s(transInfo, sizeof(BssTransInfo), 0, sizeof(BssTransInfo));

    (void)strcpy_s(transInfo->ssid, WIFI_SSID_LEN, TEST_VALID_PEER_NETWORKID1);
    (void)strcpy_s((char *)transInfo->targetBssid, WIFI_MAC_LEN, TEST_VALID_PEER_NETWORKID2);

    int32_t ret = LnnSendTransReq(nullptr, transInfo);
    EXPECT_TRUE(ret == SOFTBUS_ERR);

    ret = LnnSendTransReq(TEST_VALID_PEER_NETWORKID, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_ERR);

    ret = LnnSendTransReq(TEST_VALID_PEER_NETWORKID, transInfo);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
}

/*
* @tc.name: LNN_ONRECEIVE_DEVICE_NAME_TEST_001
* @tc.desc: test OnReceiveDeviceName
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNSyncInfoItemTest, LNN_ONRECEIVE_DEVICE_NAME_TEST_001, TestSize.Level1)
{
    OnReceiveDeviceName(LNN_INFO_TYPE_DEVICE_NAME, nullptr, nullptr, TEST_VALID_UDID_LEN);
    uint8_t msg[WIFI_SSID_LEN] = {1, 2, 3, 4, 5};
    OnReceiveDeviceName(LNN_INFO_TYPE_BATTERY_INFO, nullptr, msg, TEST_VALID_UDID_LEN);
}

/*
* @tc.name: LNN_ONRECEIVE_TRANS_REQ_MSG_TEST_001
* @tc.desc: test OnReceiveTransReqMsg
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNSyncInfoItemTest, LNN_ONRECEIVE_TRANS_REQ_MSG_TEST_001, TestSize.Level1)
{
    OnReceiveTransReqMsg(LNN_INFO_TYPE_TOPO_UPDATE, nullptr, nullptr, TEST_VALID_UDID_LEN);
}

/*
* @tc.name: LNN_ONRECEIVE_BR_OFFLINE_TEST_001
* @tc.desc: test OnReceiveBrOffline
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNSyncInfoItemTest, LNN_ONRECEIVE_BR_OFFLINE_TEST_001, TestSize.Level1)
{
    OnReceiveBrOffline(LNN_INFO_TYPE_P2P_INFO, nullptr, nullptr, TEST_VALID_UDID_LEN);
    OnReceiveBrOffline(LNN_INFO_TYPE_OFFLINE, nullptr, nullptr, TEST_VALID_UDID_LEN);
    OnReceiveBrOffline(LNN_INFO_TYPE_OFFLINE, nullptr, nullptr, TEST_VALID_UDID_LEN);
}

/*
* @tc.name: FILL_TARGET_WIIFI_CONFIG_TEST_001
* @tc.desc: test FillTargetWifiConfig
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNSyncInfoItemTest, FILL_TARGET_WIIFI_CONFIG_TEST_001, TestSize.Level1)
{
    SoftBusWifiDevConf conWifiConf;
    SoftBusWifiDevConf targetWifiConf;
    const unsigned char targetBssid[] = "123456";
    int32_t ret = FillTargetWifiConfig(targetBssid, TEST_VALID_PEER_NETWORKID1, &conWifiConf, &targetWifiConf);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
* @tc.name: WIFI_CONNECT_TO_TARGET_AP_TEST_001
* @tc.desc: test WifiConnectToTargetAp
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNSyncInfoItemTest, WIFI_CONNECT_TO_TARGET_AP_TEST_001, TestSize.Level1)
{
    const unsigned char targetBssid[] = "123456";
    int32_t ret = WifiConnectToTargetAp(targetBssid, TEST_VALID_PEER_NETWORKID1);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
}
} // namespace OHOS
