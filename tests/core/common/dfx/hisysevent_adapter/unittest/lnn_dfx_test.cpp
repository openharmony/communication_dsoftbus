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
#include "softbus_log.h"
#include "softbus_common.h"
#include "softbus_hisysevt_bus_center.h"
#include "securec.h"
#include "softbus_hisysevt_discreporter.h"
#include "softbus_hisysevt_connreporter.h"
#include "softbus_adapter_hisysevent.h"
#include "softbus_hisysevt_common.h"

using namespace std;
using namespace testing::ext;

static const StatisticEvtType g_testType = (StatisticEvtType)(-1);
static const int32_t SOFTBUS_HISYSEVT_COMMON_ERR_ERRCODE = -1;
static const char *g_errBusCenterEvt = "BUS_CENTER_FAULT_EVT_TEST";

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

static int32_t TestReportCommonFaultEvt()
{
    return SOFTBUS_OK;
}
/**
 * @tc.name: CreateBusCenterFaultEvtTest001
 * @tc.desc: Verify CreateBusCenterFaultEvt function, use the normal parameter.
 * @tc.type: FUNC
 * @tc.require: I5JQ1E
 */
HWTEST_F(LnnDfxTest, CreateBusCenterFaultEvtTest001, TestSize.Level0)
{
    SoftBusEvtReportMsg msg;
    memset_s(&msg, sizeof(msg), 0, sizeof(msg));
    int32_t errorCode = SOFTBUS_NETWORK_AUTH_TCP_ERR;
    ConnectionAddr addr;
    addr.type = CONNECTION_ADDR_WLAN;
    int32_t ret = CreateBusCenterFaultEvt(&msg, errorCode, &addr);
    ASSERT_EQ(SOFTBUS_OK, ret);
    ASSERT_NE(nullptr, msg.paramArray);
}

/**
 * @tc.name: CreateBusCenterFaultEvtTest002
 * @tc.desc: Verify CreateBusCenterFaultEvt function, use the normal parameter.
 * @tc.type: FUNC
 * @tc.require: I5JQ1E
 */
HWTEST_F(LnnDfxTest, CreateBusCenterFaultEvtTest002, TestSize.Level0)
{
    SoftBusEvtReportMsg msg;
    memset_s(&msg, sizeof(msg), 0, sizeof(msg));
    int32_t errorCode = SOFTBUS_NETWORK_GET_META_NODE_INFO_ERR + 1;
    ConnectionAddr addr;
    addr.type = CONNECTION_ADDR_WLAN;
    int32_t ret = CreateBusCenterFaultEvt(&msg, errorCode, &addr);
    ASSERT_EQ(SOFTBUS_OK, ret);
    ASSERT_EQ(nullptr, msg.paramArray);

    ret = CreateBusCenterFaultEvt(nullptr, errorCode, &addr);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    ret = CreateBusCenterFaultEvt(&msg, errorCode, nullptr);
    EXPECT_EQ(SOFTBUS_ERR, ret);
}

/**
 * @tc.name: ReportBusCenterFaultEvtTest001
 * @tc.desc: Verify ReportBusCenterFaultEvt function, use the normal parameter.
 * @tc.type: FUNC
 * @tc.require: I5JQ1E
 */
HWTEST_F(LnnDfxTest, ReportBusCenterFaultEvtTest001, TestSize.Level0)
{
    SoftBusEvtReportMsg msg;
    memset_s(&msg, sizeof(msg), 0, sizeof(msg));
    int32_t errorCode = SOFTBUS_NETWORK_AUTH_TCP_ERR;
    ConnectionAddr addr;
    addr.type = CONNECTION_ADDR_WLAN;
    int32_t ret = CreateBusCenterFaultEvt(&msg, errorCode, &addr);
    ASSERT_EQ(SOFTBUS_OK, ret);
    ASSERT_NE(nullptr, msg.paramArray);

    ret = ReportBusCenterFaultEvt(&msg);
    ASSERT_EQ(SOFTBUS_OK, ret);

    ret = ReportBusCenterFaultEvt(nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = memcpy_s(msg.evtName, SOFTBUS_HISYSEVT_NAME_LEN, g_errBusCenterEvt, strlen(g_errBusCenterEvt));
    ASSERT_EQ(EOK, ret);
    ret = ReportBusCenterFaultEvt(&msg);
    EXPECT_EQ(SOFTBUS_ERR, ret);
}

/**
 * @tc.name: ReportBusCenterFaultEvtTest002
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnDfxTest, ReportBusCenterFaultEvtTest002, TestSize.Level1)
{
    SoftBusEvtReportMsg msg;
    memset_s(&msg, sizeof(msg), 0, sizeof(msg));
    int32_t errorCode = SOFTBUS_NETWORK_AUTH_TCP_ERR;
    ConnectionAddr addr;
    addr.type = CONNECTION_ADDR_WLAN;
    int32_t ret = CreateBusCenterFaultEvt(&msg, errorCode, &addr);
    ASSERT_EQ(SOFTBUS_OK, ret);
    ASSERT_NE(nullptr, msg.paramArray);

    ret = ReportBusCenterFaultEvt(&msg);
    ASSERT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: InitBusCenterDfxTest001
 * @tc.desc: Verify InitBusCenterDfx function, use the normal parameter.
 * @tc.type: FUNC
 * @tc.require: I5JQ1E
 */
HWTEST_F(LnnDfxTest, InitBusCenterDfxTest001, TestSize.Level0)
{
    int32_t ret = InitBusCenterDfx();
    ASSERT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: AddStatisticDurationTest001
 * @tc.desc: Verify AddStatisticDuration function, use the normal parameter.
 * @tc.type: FUNC
 * @tc.require: I5JQ1E
 */
HWTEST_F(LnnDfxTest, AddStatisticDurationTest001, TestSize.Level0)
{
    LnnStatisticData *data = NULL;
    int32_t ret = AddStatisticDuration(data);
    ASSERT_EQ(SOFTBUS_ERR, ret);
}

/**
 * @tc.name: AddStatisticDurationTest002
 * @tc.desc: Verify AddStatisticDuration function, use the normal parameter.
 * @tc.type: FUNC
 * @tc.require: I5JQ1E
 */
HWTEST_F(LnnDfxTest, AddStatisticDurationTest002, TestSize.Level0)
{
    LnnStatisticData data;
    data.endTime = 202207301230;
    data.beginTime = 202207301235;
    int32_t ret = AddStatisticDuration(&data);
    ASSERT_EQ(SOFTBUS_ERR, ret);
}

/**
 * @tc.name: AddStatisticDurationTest003
 * @tc.desc: Verify AddStatisticDuration function, use the normal parameter.
 * @tc.type: FUNC
 * @tc.require: I5JQ1E
 */
HWTEST_F(LnnDfxTest, AddStatisticDurationTest003, TestSize.Level0)
{
    LnnStatisticData data;
    data.type = CONNECTION_ADDR_ETH;
    int32_t ret = AddStatisticDuration(&data);
    ASSERT_EQ(SOFTBUS_ERR, ret);

    data.retCode = SOFTBUS_ERR;
    ret = AddStatisticDuration(&data);
    EXPECT_EQ(SOFTBUS_ERR, ret);
}

/**
 * @tc.name: AddStatisticDurationTest004
 * @tc.desc: Verify AddStatisticDuration function, add the time to the statistics with the correct parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnDfxTest, AddStatisticDurationTest004, TestSize.Level1)
{
    LnnStatisticData data = {
        .beginTime = 202207301230,
        .authTime = 202207301233,
        .endTime = 202207301235,
        .retCode = SOFTBUS_OK,
        .type = CONNECTION_ADDR_BLE,
    };
    int32_t ret = AddStatisticDuration(&data);
    EXPECT_EQ(SOFTBUS_OK, ret);

    data.type = CONNECTION_ADDR_WLAN;
    ret = AddStatisticDuration(&data);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: AddStatisticRateOfSuccessTest001
 * @tc.desc: Verify AddStatisticRateOfSuccess function, use the normal parameter.
 * @tc.type: FUNC
 * @tc.require: I5JQ1E
 */
HWTEST_F(LnnDfxTest, AddStatisticRateOfSuccessTest001, TestSize.Level0)
{
    LnnStatisticData *data = NULL;
    int32_t ret = AddStatisticRateOfSuccess(data);
    ASSERT_EQ(SOFTBUS_ERR, ret);
}

/**
 * @tc.name: AddStatisticRateOfSuccessTest002
 * @tc.desc: Verify AddStatisticRateOfSuccess function, use the normal parameter.
 * @tc.type: FUNC
 * @tc.require: I5JQ1E
 */
HWTEST_F(LnnDfxTest, AddStatisticRateOfSuccessTest002, TestSize.Level0)
{
    LnnStatisticData data;
    data.type = CONNECTION_ADDR_ETH;
    int32_t ret = AddStatisticRateOfSuccess(&data);
    ASSERT_EQ(SOFTBUS_ERR, ret);
}

/**
 * @tc.name: AddStatisticRateOfSuccessTest003
 * @tc.desc: use the correct parameters to transfer records to calculate the success rate.
 * @tc.type: FUNC
 * @tc.require: I5JQ1E
 */
HWTEST_F(LnnDfxTest, AddStatisticRateOfSuccessTest003, TestSize.Level0)
{
    LnnStatisticData data;
    data.beginTime = 202207301245;
    data.authTime = 202207301230;
    data.endTime = 202207301248;
    data.retCode = SOFTBUS_OK;
    data.type = CONNECTION_ADDR_WLAN;
    int32_t ret = AddStatisticRateOfSuccess(&data);
    ASSERT_EQ(SOFTBUS_OK, ret);

    data.type = CONNECTION_ADDR_BLE;
    ret = AddStatisticRateOfSuccess(&data);
    ASSERT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: LnnDfxTest_SoftBusReportConnFaultEvt_001
 * @tc.desc: report error events generated by different media.
 * @tc.type: FUNC
 * @tc.require: SR000H04L1
 */
HWTEST_F(LnnDfxTest, LnnDfxTest_SoftBusReportConnFaultEvt_001, TestSize.Level1)
{
    int ret = SoftBusReportConnFaultEvt(SOFTBUS_HISYSEVT_CONN_MEDIUM_BLE, SOFTBUS_HISYSEVT_BLE_GATTSERVER_INIT_FAIL);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = SoftBusReportConnFaultEvt(SOFTBUS_HISYSEVT_CONN_MEDIUM_BR, SOFTBUS_HISYSEVT_CONN_MANAGER_OP_NOT_SUPPORT);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = SoftBusReportConnFaultEvt(SOFTBUS_HISYSEVT_CONN_MEDIUM_TCP, SOFTBUS_HISYSEVT_TCP_CONNECTION_SOCKET_ERR);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = SoftBusReportConnFaultEvt(SOFTBUS_HISYSEVT_CONN_MEDIUM_P2P, SOFTBUS_MEM_ERR);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**
 * @tc.name: SoftBusReportConnFaultEvt_002
 * @tc.desc: report the wrong branch of the failed event in the connection with the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnDfxTest, LnnDfxTest_SoftBusReportConnFaultEvt_002, TestSize.Level1)
{
    SoftBusConnMedium testMedium = SOFTBUS_HISYSEVT_CONN_MEDIUM_BUTT;
    SoftBusConnErrCode testErrCode = SOFTBUS_HISYSEVT_BLE_NOT_INIT;

    int32_t ret = SoftBusReportConnFaultEvt(testMedium, testErrCode);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    testMedium = SOFTBUS_HISYSEVT_CONN_MEDIUM_BLE;

    testErrCode = (SoftBusConnErrCode)SOFTBUS_HISYSEVT_COMMON_ERR_ERRCODE;
    ret = SoftBusReportConnFaultEvt(testMedium, testErrCode);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    testErrCode = SOFTBUS_HISYSEVT_CONN_ERRCODE_BUTT;
    ret = SoftBusReportConnFaultEvt(testMedium, testErrCode);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}
/**
 * @tc.name: LnnDfxTest_SoftbusRecordConnInfo_001
 * @tc.desc: send behavior msg to hiview system, we can see the result in log.
 * @tc.type: FUNC
 * @tc.require: SR000H04L1
 */
HWTEST_F(LnnDfxTest, LnnDfxTest_SoftbusRecordConnInfo_001, TestSize.Level1)
{
    int ret = SOFTBUS_ERR;
    int32_t time = 10;
    ret = SoftbusRecordConnInfo(SOFTBUS_HISYSEVT_CONN_MEDIUM_BR, SOFTBUS_EVT_CONN_SUCC, time);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = SoftbusRecordConnInfo(SOFTBUS_HISYSEVT_CONN_MEDIUM_BR, SOFTBUS_EVT_CONN_FAIL, time);
    EXPECT_EQ(SOFTBUS_OK, ret);

    time = 15;
    ret = SoftbusRecordConnInfo(SOFTBUS_HISYSEVT_CONN_MEDIUM_BR, SOFTBUS_EVT_CONN_SUCC, time);
    EXPECT_EQ(SOFTBUS_OK, ret);

    time = 12;
    ret = SoftbusRecordConnInfo(SOFTBUS_HISYSEVT_CONN_MEDIUM_BR, SOFTBUS_EVT_CONN_SUCC, time);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = SoftbusRecordConnInfo(SOFTBUS_HISYSEVT_CONN_MEDIUM_BUTT, SOFTBUS_EVT_CONN_SUCC, time);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**
 * @tc.name: LnnDfxTest_SoftBusReportDiscStartupEvt_001
 * @tc.desc: Error register timeout callback test.
 * @tc.type: FUNC
 * @tc.require: SR000H04L1
 */
HWTEST_F(LnnDfxTest, LnnDfxTest_SoftBusReportDiscStartupEvt_001, TestSize.Level1)
{
    int32_t ret = SOFTBUS_ERR;
    char pkgName[] = "testPackage";
    ret = SoftBusReportDiscStartupEvt(pkgName);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = SoftBusReportDiscStartupEvt(nullptr);
    EXPECT_EQ(ret, SOFTBUS_ERR);
}

/**
 * @tc.name: LnnDfxTest_SoftbusRecordDiscScanTimes_001
 * @tc.desc: Error register timeout callback test.
 * @tc.type: FUNC
 * @tc.require: SR000H04L1
 */
HWTEST_F(LnnDfxTest, LnnDfxTest_SoftbusRecordDiscScanTimes_001, TestSize.Level1)
{
    int ret = SOFTBUS_ERR;
    SoftBusDiscMedium testMedium = SOFTBUS_HISYSEVT_DISC_MEDIUM_BLE;
    ret = SoftbusRecordDiscScanTimes((uint8_t)testMedium);
    EXPECT_EQ(SOFTBUS_OK, ret);

    testMedium = SOFTBUS_HISYSEVT_DISC_MEDIUM_BUTT;
    ret = SoftbusRecordDiscScanTimes((uint8_t)testMedium);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**
 * @tc.name: LnnDfxTest_SoftbusRecordFirstDiscTime_001
 * @tc.desc: Error register timeout callback test.
 * @tc.type: FUNC
 * @tc.require: SR000H04L1
 */
HWTEST_F(LnnDfxTest, LnnDfxTest_SoftbusRecordFirstDiscTime_001, TestSize.Level1)
{
    int32_t ret = SOFTBUS_ERR;
    uint32_t time = 10;
    SoftBusDiscMedium testMedium = SOFTBUS_HISYSEVT_DISC_MEDIUM_BUTT;

    ret = SoftbusRecordFirstDiscTime((uint8_t)testMedium, time);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    testMedium = SOFTBUS_HISYSEVT_DISC_MEDIUM_BLE;
    ret = SoftbusRecordFirstDiscTime((uint8_t)testMedium, time);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: LnnDfxTest_SoftbusRecordDiscFault_001
 * @tc.desc: Error register timeout callback test.
 * @tc.type: FUNC
 * @tc.require:SR000H04L1
 */
HWTEST_F(LnnDfxTest, LnnDfxTest_SoftbusRecordDiscFault_001, TestSize.Level1)
{
    int ret = SOFTBUS_ERR;
    uint32_t errCode = SOFTBUS_HISYSEVT_DISC_ERRCODE_TIMEOUT;
    ret = SoftbusRecordDiscFault(SOFTBUS_HISYSEVT_DISC_MEDIUM_BLE, errCode);
    EXPECT_EQ(SOFTBUS_OK, ret);

    errCode = SOFTBUS_HISYSEVT_DISCOVER_COAP_REGISTER_CAP_FAIL;
    ret = SoftbusRecordDiscFault(SOFTBUS_HISYSEVT_DISC_MEDIUM_COAP, errCode);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: LnnDfxTest_SoftbusRecordDiscFault_002
 * @tc.desc: failures during discovery are logged with different parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnDfxTest, LnnDfxTest_SoftbusRecordDiscFault_002, TestSize.Level1)
{
    int32_t ret = SOFTBUS_ERR;
    uint32_t errCode = SOFTBUS_HISYSEVT_DISC_ERRCODE_TIMEOUT;
    SoftBusDiscMedium testMedium = SOFTBUS_HISYSEVT_DISC_MEDIUM_COAP;

    ret = SoftbusRecordDiscFault(testMedium, errCode);
    EXPECT_EQ(SOFTBUS_OK, ret);

    testMedium = SOFTBUS_HISYSEVT_DISC_MEDIUM_BUTT;
    ret = SoftbusRecordDiscFault(testMedium, errCode);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**
 * @tc.name: GetStatisticEvtReportFunc_001
 * @tc.desc: use the different event type parameters to get the event function for statistics.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnDfxTest, LnnDfxTest_GetStatisticEvtReportFunc_001, TestSize.Level1)
{
    InitSoftbusSysEvt();
    StatisticEvtType testType = g_testType;
    StatisticEvtReportFunc ret = GetStatisticEvtReportFunc(testType);
    EXPECT_TRUE(ret == nullptr);

    testType = SOFTBUS_STATISTIC_EVT_BUTT;
    ret = GetStatisticEvtReportFunc(testType);
    EXPECT_EQ(nullptr, ret);

    testType = SOFTBUS_STATISTIC_EVT_DISC_FAULT;
    int32_t res = SetStatisticEvtReportFunc(testType, TestReportCommonFaultEvt);
    EXPECT_EQ(SOFTBUS_OK, res);

    ret = GetStatisticEvtReportFunc(testType);
    EXPECT_EQ(ret, TestReportCommonFaultEvt);
}

/**
 * @tc.name: SetStatisticEvtReportFunc_001
 * @tc.desc: Use different event type parameters to set the event function corresponding to the statistics.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnDfxTest, LnnDfxTest_SetStatisticEvtReportFunc_001, TestSize.Level1)
{
    InitSoftbusSysEvt();
    StatisticEvtType testType = g_testType;
    int32_t ret = SetStatisticEvtReportFunc(testType, TestReportCommonFaultEvt);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    testType = SOFTBUS_STATISTIC_EVT_BUTT;
    ret = SetStatisticEvtReportFunc(testType, TestReportCommonFaultEvt);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    testType = SOFTBUS_STATISTIC_EVT_DISC_FAULT;
    ret = SetStatisticEvtReportFunc(testType, nullptr);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    testType = SOFTBUS_STATISTIC_EVT_DISC_FAULT;
    ret = SetStatisticEvtReportFunc(testType, TestReportCommonFaultEvt);
    EXPECT_EQ(SOFTBUS_OK, ret);
}
} // namespace OHOS