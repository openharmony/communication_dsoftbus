/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <string>
#include <gtest/gtest.h>

#include "softbus_error_code.h"
#include "softbus_adapter_mem.h"
#include "softbus_common.h"
#include "legacy/softbus_hisysevt_bus_center.h"
#include "securec.h"
#include "legacy/softbus_hisysevt_discreporter.h"
#include "legacy/softbus_hisysevt_connreporter.h"
#include "legacy/softbus_adapter_hisysevent.h"
#include "legacy/softbus_hisysevt_common.h"

using namespace std;
using namespace testing::ext;

static const char *g_businessName = "music";
static const char *g_callerPackName = "kuwo";
static const char *g_remoteBizUuid = "adafafaffafaga";
static const char *g_softBusVer = "1.00.01";
static const char *g_devName = "OpenHarmony";
static const char *g_udid = "12345678";
static const char *g_appName1 = "testApp1";
static const char *g_appName2 = "testApp2";

namespace OHOS {
class LnnDfxTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void LnnDfxTest::SetUpTestCase(void)
{
    InitSoftbusSysEvt();
}

void LnnDfxTest::TearDownTestCase(void)
{
}

void LnnDfxTest::SetUp(void)
{
}

void LnnDfxTest::TearDown(void)
{
}

/**
 * @tc.name: SoftBusRecordDiscoveryResult
 * @tc.desc: Verify SoftBus Record Discovery Result function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnDfxTest, LnnDfxTest_SoftBusRecordDiscoveryResult_001, TestSize.Level0)
{
    int32_t ret = SOFTBUS_ERR;
    ret = SoftBusRecordDiscoveryResult(START_DISCOVERY, NULL);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SoftBusRecordDiscoveryResult(SEND_BROADCAST, NULL);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SoftBusRecordDiscoveryResult(RECV_BROADCAST, NULL);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SoftBusRecordDiscoveryResult(DEVICE_FOUND, NULL);
    EXPECT_EQ(SOFTBUS_OK, ret);
    AppDiscNode node1 = {0};
    node1.appDiscCnt = 1;
    ret = memcpy_s(node1.appName, SOFTBUS_HISYSEVT_NAME_LEN, g_appName1, strlen(g_appName1));
    EXPECT_EQ(EOK, ret);
    ret = SoftBusRecordDiscoveryResult(BUSINESS_DISCOVERY, &node1);
    EXPECT_EQ(SOFTBUS_OK, ret);
    AppDiscNode node2 = {0};
    node2.appDiscCnt = 2;
    ret = memcpy_s(node2.appName, SOFTBUS_HISYSEVT_NAME_LEN, g_appName2, strlen(g_appName2));
    EXPECT_EQ(EOK, ret);
    ret = SoftBusRecordDiscoveryResult(BUSINESS_DISCOVERY, &node2);
    EXPECT_EQ(SOFTBUS_OK, ret);
    StatisticEvtReportFunc reportFunc = GetStatisticEvtReportFunc(SOFTBUS_STATISTIC_EVT_DEV_DISCOVERY);
    ret = reportFunc();
    EXPECT_EQ(SOFTBUS_OK, ret);

    reportFunc = GetStatisticEvtReportFunc(SOFTBUS_STATISTIC_EVT_APP_DISCOVERY);
    ret = reportFunc();
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: SoftBusRecordDevOnlineDurResult001
 * @tc.desc: Verify SoftBusRecordDevOnlineDurResult function.
 * @tc.type: FUNC
 * @tc.require:
 */

HWTEST_F(LnnDfxTest, SoftBusRecordDevOnlineDurResult001, TestSize.Level0)
{
    int32_t ret = SOFTBUS_ERR;
    ret = SoftBusRecordDevOnlineDurResult(11);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SoftBusRecordDevOnlineDurResult(31);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SoftBusRecordDevOnlineDurResult(301);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SoftBusRecordDevOnlineDurResult(601);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SoftBusRecordDevOnlineDurResult(901);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SoftBusRecordDevOnlineDurResult(901);
    EXPECT_EQ(SOFTBUS_OK, ret);
    StatisticEvtReportFunc reportFunc = GetStatisticEvtReportFunc(SOFTBUS_STATISTIC_EVT_ONLINE_DURATION);
    ret = reportFunc();
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: SoftBusRecordBusCenterResult001
 * @tc.desc: Verify SoftBusRecordBusCenterResult function.
 * @tc.type: FUNC
 * @tc.require:
 */

HWTEST_F(LnnDfxTest, SoftBusRecordBusCenterResult001, TestSize.Level0)
{
    int32_t ret = SOFTBUS_ERR;
    ret = SoftBusRecordBusCenterResult(SOFTBUS_HISYSEVT_LINK_TYPE_BR, 900);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SoftBusRecordBusCenterResult(SOFTBUS_HISYSEVT_LINK_TYPE_BLE, 1100);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SoftBusRecordBusCenterResult(SOFTBUS_HISYSEVT_LINK_TYPE_WLAN, 1300);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SoftBusRecordBusCenterResult(SOFTBUS_HISYSEVT_LINK_TYPE_P2P, 1600);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SoftBusRecordBusCenterResult(SOFTBUS_HISYSEVT_LINK_TYPE_HML, 1900);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SoftBusRecordBusCenterResult(SOFTBUS_HISYSEVT_LINK_TYPE_HML, 900);
    EXPECT_EQ(SOFTBUS_OK, ret);
    StatisticEvtReportFunc reportFunc = GetStatisticEvtReportFunc(SOFTBUS_STATISTIC_EVT_LNN_DURATION);
    ret = reportFunc();
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: SoftBusRecordAuthResult001
 * @tc.desc: Verify SoftBusRecordAuthResult function.
 * @tc.type: FUNC
 * @tc.require:
 */

HWTEST_F(LnnDfxTest, SoftBusRecordAuthResult001, TestSize.Level0)
{
    int32_t ret = SOFTBUS_ERR;
    ret = SoftBusRecordAuthResult(SOFTBUS_HISYSEVT_LINK_TYPE_BR, 0, 2100, AUTH_STAGE_BUTT);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SoftBusRecordAuthResult(SOFTBUS_HISYSEVT_LINK_TYPE_BLE, 1, 2100, AUTH_CONNECT_STAGE);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SoftBusRecordAuthResult(SOFTBUS_HISYSEVT_LINK_TYPE_WLAN, 0, 2600, AUTH_STAGE_BUTT);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SoftBusRecordAuthResult(SOFTBUS_HISYSEVT_LINK_TYPE_P2P, 0, 2100, AUTH_STAGE_BUTT);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SoftBusRecordAuthResult(SOFTBUS_HISYSEVT_LINK_TYPE_P2P, 1, 3600, AUTH_VERIFY_STAGE);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SoftBusRecordAuthResult(SOFTBUS_HISYSEVT_LINK_TYPE_HML, 0, 2100, AUTH_STAGE_BUTT);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SoftBusRecordAuthResult(SOFTBUS_HISYSEVT_LINK_TYPE_HML, 1, 4100, AUTH_EXCHANGE_STAGE);
    EXPECT_EQ(SOFTBUS_OK, ret);
    StatisticEvtReportFunc reportFunc = GetStatisticEvtReportFunc(SOFTBUS_STATISTIC_EVT_AUTH_KPI);
    ret = reportFunc();
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: SoftBusReportBusCenterFaultEvt001
 * @tc.desc: Verify SoftBusReportBusCenterFaultEvt function.
 * @tc.type: FUNC
 * @tc.require:
 */

HWTEST_F(LnnDfxTest, SoftBusReportBusCenterFaultEvt001, TestSize.Level0)
{
    int32_t ret = SOFTBUS_ERR;
    SoftBusFaultEvtInfo info = {0};
    info.moduleType = MODULE_TYPE_DISCOVERY;
    info.linkType = SOFTBUS_HISYSEVT_LINK_TYPE_BLE;
    info.channelQuality = 1.2;
    info.errorCode = -1;
    info.peerDevType = 11;
    info.onLineDevNum = 5;
    info.connNum = 4;
    info.nightMode = 0;
    info.wifiStatue = 1;
    info.bleStatue = 1;
    info.callerAppMode = 1;
    info.subErrCode = 2;
    info.connBrNum = 1;
    info.connBleNum = 2;
    info.bleBradStatus = true;
    info.bleScanStatus = false;
    ret = memcpy_s(info.businessName, SOFTBUS_HISYSEVT_NAME_LEN, g_businessName, strlen(g_businessName));
    EXPECT_EQ(EOK, ret);
    ret = memcpy_s(info.callerPackName, SOFTBUS_HISYSEVT_NAME_LEN, g_callerPackName, strlen(g_callerPackName));
    EXPECT_EQ(EOK, ret);
    ret = memcpy_s(info.remoteBizUuid, SOFTBUS_HISYSEVT_NAME_LEN, g_remoteBizUuid, strlen(g_remoteBizUuid));
    EXPECT_EQ(EOK, ret);
    ret = SoftBusReportBusCenterFaultEvt(&info);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: SoftBusReportDevOnlineEvt001
 * @tc.desc: Verify SoftBusReportDevOnlineEvt function.
 * @tc.type: FUNC
 * @tc.require:
 */

HWTEST_F(LnnDfxTest, SoftBusReportDevOnlineEvt001, TestSize.Level0)
{
    int32_t ret = SOFTBUS_ERR;
    OnlineDeviceInfo devInfo = {0};
    devInfo.onlineDevNum = 10;
    devInfo.btOnlineDevNum = 10;
    devInfo.wifiOnlineDevNum = 3;
    devInfo.peerDevType = 3;
    devInfo.insertFileResult = 1;
    ret = memcpy_s(devInfo.peerSoftBusVer, SOFTBUS_HISYSEVT_NAME_LEN, g_softBusVer, strlen(g_softBusVer));
    EXPECT_EQ(EOK, ret);
    ret = memcpy_s(devInfo.peerDevName, SOFTBUS_HISYSEVT_NAME_LEN, g_devName, strlen(g_devName));
    EXPECT_EQ(EOK, ret);
    ret = memcpy_s(devInfo.localSoftBusVer, SOFTBUS_HISYSEVT_NAME_LEN, g_softBusVer, strlen(g_softBusVer));
    EXPECT_EQ(EOK, ret);
    ret = memcpy_s(devInfo.peerPackVer, SOFTBUS_HISYSEVT_NAME_LEN, g_softBusVer, strlen(g_softBusVer));
    EXPECT_EQ(EOK, ret);
    ret = memcpy_s(devInfo.localPackVer, SOFTBUS_HISYSEVT_NAME_LEN, g_softBusVer, strlen(g_softBusVer));
    EXPECT_EQ(EOK, ret);
    ret = SoftBusReportDevOnlineEvt(&devInfo, g_udid);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: InitBusCenterDfx001
 * @tc.desc: Verify InitBusCenterDfx function.
 * @tc.type: FUNC
 * @tc.require:
 */

HWTEST_F(LnnDfxTest, InitBusCenterDfx001, TestSize.Level0)
{
    int32_t ret = InitBusCenterDfx();
    EXPECT_EQ(SOFTBUS_OK, ret);
    DeinitBusCenterDfx();
}
} // namespace OHOS