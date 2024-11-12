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

static const char *g_moduleNameOne = "testModule1";
static const char *g_moduleNameTwo = "testModule2";

namespace OHOS {
class DiscConnDfxTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void DiscConnDfxTest::SetUpTestCase(void)
{
    InitSoftbusSysEvt();
}

void DiscConnDfxTest::TearDownTestCase(void)
{
}

void DiscConnDfxTest::SetUp(void)
{
}

void DiscConnDfxTest::TearDown(void)
{
}

/**
 * @tc.name: SoftbusRecordFirstDiscTime
 * @tc.desc: Verify SoftBus Record first Discovery time function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscConnDfxTest, SoftbusRecordFirstDiscTime_001, TestSize.Level0)
{
    int32_t ret = SOFTBUS_ERR;

    ret = SoftbusRecordFirstDiscTime(SOFTBUS_HISYSEVT_DISC_MEDIUM_BLE, 1000);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SoftbusRecordFirstDiscTime(SOFTBUS_HISYSEVT_DISC_MEDIUM_BLE, 2000);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SoftbusRecordFirstDiscTime(SOFTBUS_HISYSEVT_DISC_MEDIUM_BLE, 3000);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SoftbusRecordFirstDiscTime(SOFTBUS_HISYSEVT_DISC_MEDIUM_BLE, UINT64_MAX - 1);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = SoftbusRecordFirstDiscTime(SOFTBUS_HISYSEVT_DISC_MEDIUM_COAP, 1000);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SoftbusRecordFirstDiscTime(SOFTBUS_HISYSEVT_DISC_MEDIUM_COAP, 2000);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SoftbusRecordFirstDiscTime(SOFTBUS_HISYSEVT_DISC_MEDIUM_COAP, 3000);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SoftbusRecordFirstDiscTime(SOFTBUS_HISYSEVT_DISC_MEDIUM_COAP, UINT64_MAX - 1);
    EXPECT_EQ(SOFTBUS_OK, ret);

    StatisticEvtReportFunc reportFunc = GetStatisticEvtReportFunc(SOFTBUS_STATISTIC_EVT_FIRST_DISC_DURATION);
    ret = reportFunc();
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: SoftbusRecordBleDiscDetails001
 * @tc.desc: Verify SoftbusRecordBleDiscDetails function.
 * @tc.type: FUNC
 * @tc.require:
 */

HWTEST_F(DiscConnDfxTest, SoftbusRecordBleDiscDetails_001, TestSize.Level0)
{
    int32_t ret = SOFTBUS_ERR;

    ret = SoftbusRecordBleDiscDetails(const_cast<char *>(g_moduleNameOne), 1000, 3, 2, 1);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SoftbusRecordBleDiscDetails(const_cast<char *>(g_moduleNameOne), 2000, 3, 2, 1);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SoftbusRecordBleDiscDetails(const_cast<char *>(g_moduleNameOne), 3000, 3, 2, 1);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = SoftbusRecordBleDiscDetails(const_cast<char *>(g_moduleNameTwo), 1000, 3, 2, 1);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SoftbusRecordBleDiscDetails(const_cast<char *>(g_moduleNameTwo), 2000, 3, 2, 1);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SoftbusRecordBleDiscDetails(const_cast<char *>(g_moduleNameTwo), 3000, 3, 2, 1);
    EXPECT_EQ(SOFTBUS_OK, ret);

    StatisticEvtReportFunc reportFunc = GetStatisticEvtReportFunc(SOFTBUS_STATISTIC_EVT_DISC_DETAILS);
    ret = reportFunc();
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: SoftbusRecordDiscBleRssi001
 * @tc.desc: Verify SoftbusRecordDiscBleRssi function.
 * @tc.type: FUNC
 * @tc.require:
 */

HWTEST_F(DiscConnDfxTest, SoftbusRecordDiscBleRssi_001, TestSize.Level0)
{
    int32_t ret = SOFTBUS_ERR;

    ret = SoftbusRecordDiscBleRssi(-30);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SoftbusRecordDiscBleRssi(-20);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SoftbusRecordDiscBleRssi(20);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SoftbusRecordDiscBleRssi(30);
    EXPECT_EQ(SOFTBUS_OK, ret);

    StatisticEvtReportFunc reportFunc = GetStatisticEvtReportFunc(SOFTBUS_STATISTIC_EVT_DISC_BLE_RSSI);
    ret = reportFunc();
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: SoftbusRecordConnResult_001
 * @tc.desc: Verify SoftbusRecordConnResult function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscConnDfxTest, SoftbusRecordConnResult_001, TestSize.Level0)
{
    int32_t ret = SOFTBUS_ERR;

    ret = SoftbusRecordConnResult(DEFAULT_PID, SOFTBUS_HISYSEVT_CONN_TYPE_BR, SOFTBUS_EVT_CONN_SUCC,
                            1000, SOFTBUS_HISYSEVT_CONN_OK);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SoftbusRecordConnResult(DEFAULT_PID, SOFTBUS_HISYSEVT_CONN_TYPE_BR, SOFTBUS_EVT_CONN_SUCC,
                            2000, SOFTBUS_HISYSEVT_CONN_OK);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SoftbusRecordConnResult(DEFAULT_PID, SOFTBUS_HISYSEVT_CONN_TYPE_BR, SOFTBUS_EVT_CONN_SUCC,
                            3000, SOFTBUS_HISYSEVT_CONN_OK);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SoftbusRecordConnResult(DEFAULT_PID, SOFTBUS_HISYSEVT_CONN_TYPE_BLE, SOFTBUS_EVT_CONN_SUCC,
                            3000, SOFTBUS_HISYSEVT_CONN_OK);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SoftbusRecordConnResult(DEFAULT_PID, SOFTBUS_HISYSEVT_CONN_TYPE_TCP, SOFTBUS_EVT_CONN_SUCC,
                            3000, SOFTBUS_HISYSEVT_CONN_OK);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SoftbusRecordConnResult(DEFAULT_PID, SOFTBUS_HISYSEVT_CONN_TYPE_P2P, SOFTBUS_EVT_CONN_SUCC,
                            3000, SOFTBUS_HISYSEVT_CONN_OK);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SoftbusRecordConnResult(DEFAULT_PID, SOFTBUS_HISYSEVT_CONN_TYPE_BR, SOFTBUS_EVT_CONN_FAIL,
                            3000, SOFTBUS_ERR);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SoftbusRecordConnResult(DEFAULT_PID, SOFTBUS_HISYSEVT_CONN_TYPE_BR, SOFTBUS_EVT_CONN_FAIL,
                            2000, SOFTBUS_ERR);
    EXPECT_EQ(SOFTBUS_OK, ret);
    StatisticEvtReportFunc reportFunc = GetStatisticEvtReportFunc(SOFTBUS_STATISTIC_EVT_CONN_DURATION);
    ret = reportFunc();
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: SoftbusRecordConnResult_001
 * @tc.desc: Verify SoftbusRecordConnResult function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscConnDfxTest, SoftbusRecordProccessDuration_001, TestSize.Level0)
{
    int32_t ret = SOFTBUS_ERR;
    ProcessStepTime processStepTime = {
        .totalTime = 3000,
        .negotiationTime = 1000,
        .groupCreateTime = 1000,
        .connGroupTime = 1000,
    };
    ret = SoftbusRecordProccessDuration(DEFAULT_PID, SOFTBUS_HISYSEVT_CONN_TYPE_P2P, SOFTBUS_EVT_CONN_SUCC,
                                        &processStepTime, SOFTBUS_HISYSEVT_CONN_OK);
    EXPECT_EQ(SOFTBUS_OK, ret);

    StatisticEvtReportFunc reportFunc = GetStatisticEvtReportFunc(SOFTBUS_STATISTIC_EVT_PROCESS_STEP_DURATION);
    ret = reportFunc();
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: SoftbusReportDiscFault_001
 * @tc.desc: Verify SoftbusReportDiscFault function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscConnDfxTest, SoftbusReportDiscFault_001, TestSize.Level0)
{
    int32_t ret = SOFTBUS_ERR;
    ret = SoftbusReportDiscFault(SOFTBUS_HISYSEVT_DISC_MEDIUM_BLE, -100);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = SoftbusReportDiscFault(SOFTBUS_HISYSEVT_DISC_MEDIUM_COAP, -100);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: InitBusCenterDfx001
 * @tc.desc: Verify InitBusCenterDfx function.
 * @tc.type: FUNC
 * @tc.require:
 */

HWTEST_F(DiscConnDfxTest, InitDiscConnDfx001, TestSize.Level0)
{
    int32_t ret = InitConnStatisticSysEvt();
    EXPECT_EQ(SOFTBUS_OK, ret);
    DeinitConnStatisticSysEvt();

    ret = InitDiscStatisticSysEvt();
    EXPECT_EQ(SOFTBUS_OK, ret);
    DeinitDiscStatisticSysEvt();
}
} // namespace OHOS
