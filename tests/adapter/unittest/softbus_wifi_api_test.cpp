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
#include "gtest/gtest.h"
#include <securec.h>

#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_wifi_api_adapter.h"
#include "wifi_mock.h"

namespace OHOS {
using namespace testing::ext;
using namespace testing;
#define TEST_SSID           "321654761321465"
#define TEST_BSSID          "67251"
#define TEST_SHAREKEY       "468721652"
#define TEST_SER_TYPE       2
#define TEST_IS_HIDDEN_SSID 0
#define TEST_CONFIG_SIZE    1
class AdapterDsoftbusWifiTest : public testing::Test {
protected:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};
void AdapterDsoftbusWifiTest::SetUpTestCase(void) { }
void AdapterDsoftbusWifiTest::TearDownTestCase(void) { }
void AdapterDsoftbusWifiTest::SetUp() { }
void AdapterDsoftbusWifiTest::TearDown() { }
void OnSoftBusWifiScanResult(int32_t state, int32_t size) { }
/*
 * @tc.name: SoftBusGetWifiDeviceConfig
 * @tc.desc: softbus wifi test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdapterDsoftbusWifiTest, SoftBusGetWifiDeviceConfigTest001, TestSize.Level1)
{
    SoftBusWifiDevConf configList;
    NiceMock<WifiInterfaceMock> wifiMock;
    ON_CALL(wifiMock, GetDeviceConfigs).WillByDefault(Return(WIFI_SUCCESS));
    (void)memset_s(&configList, sizeof(SoftBusWifiDevConf), 0, sizeof(SoftBusWifiDevConf));
    (void)strcpy_s(configList.ssid, sizeof(TEST_SSID), TEST_SSID);
    (void)memcpy_s(configList.bssid, sizeof(TEST_BSSID), TEST_BSSID, sizeof(TEST_BSSID));
    (void)strcpy_s(configList.preSharedKey, sizeof(TEST_SHAREKEY), TEST_SHAREKEY);
    configList.securityType = TEST_SER_TYPE;
    configList.isHiddenSsid = TEST_IS_HIDDEN_SSID;
    uint32_t num;
    int32_t ret = SoftBusGetWifiDeviceConfig(&configList, &num);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    EXPECT_CALL(wifiMock, GetDeviceConfigs)
        .WillOnce(DoAll(SetArgPointee<1>(WIFI_MAX_CONFIG_SIZE + 1), Return(WIFI_SUCCESS)));

    ret = SoftBusGetWifiDeviceConfig(&configList, &num);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    EXPECT_CALL(wifiMock, GetDeviceConfigs)
        .WillOnce(DoAll(SetArgPointee<1>(TEST_CONFIG_SIZE), Return(ERROR_WIFI_INVALID_ARGS)));
    ret = SoftBusGetWifiDeviceConfig(&configList, &num);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    ret = SoftBusGetWifiDeviceConfig(nullptr, &num);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
}

/*
 * @tc.name: SoftBusConnectToDevice
 * @tc.desc: softbus wifi test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdapterDsoftbusWifiTest, SoftBusConnectToDeviceTest001, TestSize.Level1)
{
    SoftBusWifiDevConf configList;
    NiceMock<WifiInterfaceMock> wifiMock;
    ON_CALL(wifiMock, ConnectToDevice).WillByDefault(Return(WIFI_SUCCESS));
    (void)memset_s(&configList, sizeof(SoftBusWifiDevConf), 0, sizeof(SoftBusWifiDevConf));
    (void)strcpy_s(configList.ssid, sizeof(TEST_SSID), TEST_SSID);
    (void)memcpy_s(configList.bssid, sizeof(TEST_BSSID), TEST_BSSID, sizeof(TEST_BSSID));
    (void)strcpy_s(configList.preSharedKey, sizeof(TEST_SHAREKEY), TEST_SHAREKEY);
    configList.securityType = TEST_SER_TYPE;
    configList.isHiddenSsid = TEST_IS_HIDDEN_SSID;

    int32_t ret = SoftBusConnectToDevice(&configList);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    EXPECT_CALL(wifiMock, GetDeviceConfigs).WillRepeatedly(Return(ERROR_WIFI_INVALID_ARGS));
    ret = SoftBusConnectToDevice(&configList);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = SoftBusConnectToDevice(nullptr);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
}

/*
 * @tc.name: SoftBusStartWifiScan
 * @tc.desc: softbus wifi test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdapterDsoftbusWifiTest, SoftBusStartWifiScanTest001, TestSize.Level1)
{
    NiceMock<WifiInterfaceMock> wifiMock;
    EXPECT_CALL(wifiMock, Scan).WillOnce(Return(WIFI_SUCCESS)).WillRepeatedly(Return(ERROR_WIFI_INVALID_ARGS));
    int32_t ret = SoftBusStartWifiScan();
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = SoftBusStartWifiScan();
    EXPECT_TRUE(ret == SOFTBUS_ERR);
}

/*
 * @tc.name: ScanResultCb
 * @tc.desc: softbus wifi test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdapterDsoftbusWifiTest, ScanResultCbTest001, TestSize.Level1)
{
    NiceMock<WifiInterfaceMock> wifiMock;
    ISoftBusScanResult cb = {
        .onSoftBusWifiScanResult = OnSoftBusWifiScanResult,
    };
    EXPECT_CALL(wifiMock, RegisterWifiEvent)
        .WillOnce(Return(WIFI_SUCCESS))
        .WillRepeatedly(Return(ERROR_WIFI_INVALID_ARGS));
    int32_t ret = SoftBusRegisterWifiEvent(&cb);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = SoftBusRegisterWifiEvent(nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: SoftBusGetWifiScanList
 * @tc.desc: softbus wifi test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdapterDsoftbusWifiTest, SoftBusGetWifiScanListTest001, TestSize.Level1)
{
    NiceMock<WifiInterfaceMock> wifiMock;
    ON_CALL(wifiMock, GetScanInfoList).WillByDefault(Return(WIFI_SUCCESS));
    SoftBusWifiScanInfo *result = nullptr;
    uint32_t size;
    int32_t ret = SoftBusGetWifiScanList(nullptr, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    ret = SoftBusGetWifiScanList(&result, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    ret = SoftBusGetWifiScanList(&result, &size);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    EXPECT_CALL(wifiMock, GetScanInfoList).WillRepeatedly(Return(ERROR_WIFI_INVALID_ARGS));
    ret = SoftBusGetWifiScanList(&result, &size);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
}

/*
 * @tc.name: SoftBusUnRegisterWifiEvent
 * @tc.desc: softbus wifi test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdapterDsoftbusWifiTest, SoftBusUnRegisterWifiEventTest001, TestSize.Level1)
{
    NiceMock<WifiInterfaceMock> wifiMock;

    ISoftBusScanResult cb = {
        .onSoftBusWifiScanResult = OnSoftBusWifiScanResult,
    };
    EXPECT_CALL(wifiMock, UnRegisterWifiEvent)
        .WillOnce(Return(WIFI_SUCCESS))
        .WillRepeatedly(Return(ERROR_WIFI_INVALID_ARGS));
    int32_t ret = SoftBusUnRegisterWifiEvent(&cb);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = SoftBusUnRegisterWifiEvent(nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: SoftBusGetChannelListFor5G
 * @tc.desc: softbus wifi test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdapterDsoftbusWifiTest, SoftBusGetChannelListFor5GTest001, TestSize.Level1)
{
    NiceMock<WifiInterfaceMock> wifiMock;
    int32_t channelList = TEST_CONFIG_SIZE;
    int32_t num = TEST_CONFIG_SIZE;
    EXPECT_CALL(wifiMock, Hid2dGetChannelListFor5G)
        .WillOnce(Return(WIFI_SUCCESS))
        .WillRepeatedly(Return(ERROR_WIFI_INVALID_ARGS));
    int32_t ret = SoftBusGetChannelListFor5G(&channelList, num);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = SoftBusGetChannelListFor5G(&channelList, num);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    ret = SoftBusGetChannelListFor5G(nullptr, num);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
}

/*
 * @tc.name: SoftBusGetLinkBand
 * @tc.desc: softbus wifi test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdapterDsoftbusWifiTest, SoftBusGetLinkBandTest001, TestSize.Level1)
{
    NiceMock<WifiInterfaceMock> wifiMock;
    WifiLinkedInfo result = {
        .band = BAND_24G,
    };
    WifiLinkedInfo result2 = {
        .band = BAND_5G,
    };
    WifiLinkedInfo result3 = {
        .band = BAND_UNKNOWN,
    };
    EXPECT_CALL(wifiMock, GetLinkedInfo)
        .WillRepeatedly(DoAll(SetArgPointee<0>(result), Return(ERROR_WIFI_INVALID_ARGS)));
    int32_t ret = SoftBusGetLinkBand();
    EXPECT_TRUE(ret == BAND_UNKNOWN);
    EXPECT_CALL(wifiMock, GetLinkedInfo).WillRepeatedly(DoAll(SetArgPointee<0>(result), Return(WIFI_SUCCESS)));
    ret = SoftBusGetLinkBand();
    EXPECT_TRUE(ret == BAND_24G);
    EXPECT_CALL(wifiMock, GetLinkedInfo).WillRepeatedly(DoAll(SetArgPointee<0>(result2), Return(WIFI_SUCCESS)));
    ret = SoftBusGetLinkBand();
    EXPECT_TRUE(ret == BAND_5G);
    EXPECT_CALL(wifiMock, GetLinkedInfo).WillRepeatedly(DoAll(SetArgPointee<0>(result3), Return(WIFI_SUCCESS)));
    ret = SoftBusGetLinkBand();
    EXPECT_TRUE(ret == BAND_UNKNOWN);
}

/*
 * @tc.name: SoftBusGetLinkedInfo
 * @tc.desc: softbus wifi test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdapterDsoftbusWifiTest, SoftBusGetLinkedInfoTest001, TestSize.Level1)
{
    NiceMock<WifiInterfaceMock> wifiMock;
    SoftBusWifiLinkedInfo info;
    EXPECT_CALL(wifiMock, GetLinkedInfo).WillOnce(Return(WIFI_SUCCESS)).WillRepeatedly(Return(ERROR_WIFI_INVALID_ARGS));
    int32_t ret = SoftBusGetLinkedInfo(&info);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = SoftBusGetLinkedInfo(&info);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
}

/*
 * @tc.name: SoftBusGetCurrentGroup
 * @tc.desc: softbus wifi test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdapterDsoftbusWifiTest, SoftBusGetCurrentGroupTest001, TestSize.Level1)
{
    NiceMock<WifiInterfaceMock> wifiMock;
    SoftBusWifiP2pGroupInfo groupInfo;
    EXPECT_CALL(wifiMock, GetCurrentGroup)
        .WillOnce(Return(WIFI_SUCCESS))
        .WillRepeatedly(Return(ERROR_WIFI_INVALID_ARGS));
    int32_t ret = SoftBusGetCurrentGroup(&groupInfo);
    EXPECT_TRUE(ret != SOFTBUS_OK);
}

/*
 * @tc.name: SoftBusIsWifiActive
 * @tc.desc: softbus wifi test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdapterDsoftbusWifiTest, SoftBusIsWifiActiveTest001, TestSize.Level1)
{
    NiceMock<WifiInterfaceMock> wifiMock;
    EXPECT_CALL(wifiMock, IsWifiActive).WillOnce(Return(WIFI_STA_ACTIVE)).WillRepeatedly(Return(WIFI_STA_NOT_ACTIVE));
    bool ret = SoftBusIsWifiActive();
    EXPECT_TRUE(ret == true);
    ret = SoftBusIsWifiActive();
    EXPECT_TRUE(ret == false);
}

/*
 * @tc.name: SoftBusGetWifiState
 * @tc.desc: softbus wifi test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdapterDsoftbusWifiTest, SoftBusGetWifiStateTest001, TestSize.Level1)
{
    WifiDetailState wifiState = STATE_INACTIVE;
    NiceMock<WifiInterfaceMock> wifiMock;
    EXPECT_CALL(wifiMock, GetWifiDetailState)
        .WillOnce(DoAll(SetArgPointee<0>(wifiState), Return(ERROR_WIFI_INVALID_ARGS)));
    SoftBusWifiDetailState ret = SoftBusGetWifiState();
    EXPECT_TRUE(ret == SOFTBUS_WIFI_STATE_UNKNOWN);

    EXPECT_CALL(wifiMock, GetWifiDetailState).WillOnce(DoAll(SetArgPointee<0>(wifiState), Return(WIFI_SUCCESS)));
    ret = SoftBusGetWifiState();
    EXPECT_TRUE(ret == SOFTBUS_WIFI_STATE_INACTIVE);

    wifiState = STATE_ACTIVATED;
    EXPECT_CALL(wifiMock, GetWifiDetailState).WillOnce(DoAll(SetArgPointee<0>(wifiState), Return(WIFI_SUCCESS)));
    ret = SoftBusGetWifiState();
    EXPECT_TRUE(ret == SOFTBUS_WIFI_STATE_ACTIVED);

    wifiState = STATE_SEMI_ACTIVE;
    EXPECT_CALL(wifiMock, GetWifiDetailState).WillOnce(DoAll(SetArgPointee<0>(wifiState), Return(WIFI_SUCCESS)));
    ret = SoftBusGetWifiState();
    EXPECT_TRUE(ret == SOFTBUS_WIFI_STATE_SEMIACTIVE);
}

/*
 * @tc.name: SoftBusIsWifiP2pEnabled
 * @tc.desc: softbus wifi test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdapterDsoftbusWifiTest, SoftBusIsWifiP2pEnabledTest001, TestSize.Level1)
{
    P2pState stateEnable = P2P_STATE_STARTED;
    P2pState stateDisable = P2P_STATE_CLOSING;
    NiceMock<WifiInterfaceMock> wifiMock;
    EXPECT_CALL(wifiMock, GetP2pEnableStatus)
        .WillRepeatedly(DoAll(SetArgPointee<0>(stateEnable), Return(ERROR_WIFI_INVALID_ARGS)));
    bool ret = SoftBusIsWifiP2pEnabled();
    EXPECT_TRUE(ret == false);

    EXPECT_CALL(wifiMock, GetP2pEnableStatus)
        .WillRepeatedly(DoAll(SetArgPointee<0>(stateDisable), Return(WIFI_SUCCESS)));
    ret = SoftBusIsWifiP2pEnabled();
    EXPECT_TRUE(ret == false);

    EXPECT_CALL(wifiMock, GetP2pEnableStatus)
        .WillRepeatedly(DoAll(SetArgPointee<0>(stateEnable), Return(WIFI_SUCCESS)));
    ret = SoftBusIsWifiP2pEnabled();
    EXPECT_TRUE(ret == true);
}
} // namespace OHOS