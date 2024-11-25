/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "legacy/softbus_adapter_hisysevent.h"
#include "softbus_error_code.h"

using namespace testing::ext;

namespace OHOS {

class AdapterDsoftbusDfxTest : public testing::Test {
protected:
    static void SetUpTestCase() { }
    static void TearDownTestCase() { }
    void SetUp() override { }
    void TearDown() override { }
};

/*
 * @tc.name: SoftbusWriteHisEvtTest001
 * @tc.desc: ParamType is SOFTBUS_EVT_PARAMTYPE_BOOL
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterDsoftbusDfxTest, SoftbusWriteHisEvtTest001, TestSize.Level1)
{
    SoftBusEvtParam evtParam;
    strcpy_s(evtParam.paramName, sizeof(evtParam.paramName), "testParamName");
    evtParam.paramType = SOFTBUS_EVT_PARAMTYPE_BOOL;
    evtParam.paramValue.b = false;

    SoftBusEvtReportMsg reportMsg;
    reportMsg.evtType = SOFTBUS_EVT_TYPE_FAULT;
    reportMsg.paramArray = &evtParam;
    reportMsg.paramNum = 1;
    strcpy_s(reportMsg.evtName, sizeof(evtParam.paramName), "testEvent");
    int32_t ret = SoftbusWriteHisEvt(&reportMsg);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: SoftbusWriteHisEvtTest002
 * @tc.desc: ParamType is SOFTBUS_EVT_PARAMTYPE_UINT8
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterDsoftbusDfxTest, SoftbusWriteHisEvtTest002, TestSize.Level1)
{
    SoftBusEvtParam evtParam;
    strcpy_s(evtParam.paramName, sizeof(evtParam.paramName), "testParamName");
    evtParam.paramType = SOFTBUS_EVT_PARAMTYPE_UINT8;
    evtParam.paramValue.u8v = UINT8_MAX;

    SoftBusEvtReportMsg reportMsg;
    reportMsg.evtType = SOFTBUS_EVT_TYPE_FAULT;
    reportMsg.paramArray = &evtParam;
    reportMsg.paramNum = 1;
    strcpy_s(reportMsg.evtName, sizeof(evtParam.paramName), "testEvent");
    int32_t ret = SoftbusWriteHisEvt(&reportMsg);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: SoftbusWriteHisEvtTest003
 * @tc.desc: ParamType is SOFTBUS_EVT_PARAMTYPE_UINT16
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterDsoftbusDfxTest, SoftbusWriteHisEvtTest003, TestSize.Level1)
{
    SoftBusEvtParam evtParam;
    strcpy_s(evtParam.paramName, sizeof(evtParam.paramName), "testParamName");
    evtParam.paramType = SOFTBUS_EVT_PARAMTYPE_UINT16;
    evtParam.paramValue.u16v = UINT16_MAX;

    SoftBusEvtReportMsg reportMsg;
    reportMsg.evtType = SOFTBUS_EVT_TYPE_FAULT;
    reportMsg.paramArray = &evtParam;
    reportMsg.paramNum = 1;
    strcpy_s(reportMsg.evtName, sizeof(evtParam.paramName), "testEvent");
    int32_t ret = SoftbusWriteHisEvt(&reportMsg);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: SoftbusWriteHisEvtTest004
 * @tc.desc: ParamType is SOFTBUS_EVT_PARAMTYPE_INT32
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterDsoftbusDfxTest, SoftbusWriteHisEvtTest004, TestSize.Level1)
{
    SoftBusEvtParam evtParam;
    strcpy_s(evtParam.paramName, sizeof(evtParam.paramName), "testParamName");
    evtParam.paramType = SOFTBUS_EVT_PARAMTYPE_INT32;
    evtParam.paramValue.i32v = INT32_MAX;

    SoftBusEvtReportMsg reportMsg;
    reportMsg.evtType = SOFTBUS_EVT_TYPE_FAULT;
    reportMsg.paramArray = &evtParam;
    reportMsg.paramNum = 1;
    strcpy_s(reportMsg.evtName, sizeof(evtParam.paramName), "testEvent");
    int32_t ret = SoftbusWriteHisEvt(&reportMsg);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: SoftbusWriteHisEvtTest005
 * @tc.desc: ParamType is SOFTBUS_EVT_PARAMTYPE_UINT32
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterDsoftbusDfxTest, SoftbusWriteHisEvtTest005, TestSize.Level1)
{
    SoftBusEvtParam evtParam;
    strcpy_s(evtParam.paramName, sizeof(evtParam.paramName), "testParamName");
    evtParam.paramType = SOFTBUS_EVT_PARAMTYPE_UINT32;
    evtParam.paramValue.u32v = UINT32_MAX;

    SoftBusEvtReportMsg reportMsg;
    reportMsg.evtType = SOFTBUS_EVT_TYPE_FAULT;
    reportMsg.paramArray = &evtParam;
    reportMsg.paramNum = 1;
    strcpy_s(reportMsg.evtName, sizeof(evtParam.paramName), "testEvent");
    int32_t ret = SoftbusWriteHisEvt(&reportMsg);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: SoftbusWriteHisEvtTest006
 * @tc.desc: ParamType is SOFTBUS_EVT_PARAMTYPE_UINT64
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterDsoftbusDfxTest, SoftbusWriteHisEvtTest006, TestSize.Level1)
{
    SoftBusEvtParam evtParam;
    strcpy_s(evtParam.paramName, sizeof(evtParam.paramName), "testParamName");
    evtParam.paramType = SOFTBUS_EVT_PARAMTYPE_UINT64;
    evtParam.paramValue.u64v = UINT64_MAX;

    SoftBusEvtReportMsg reportMsg;
    reportMsg.evtType = SOFTBUS_EVT_TYPE_FAULT;
    reportMsg.paramArray = &evtParam;
    reportMsg.paramNum = 1;
    strcpy_s(reportMsg.evtName, sizeof(evtParam.paramName), "testEvent");
    int32_t ret = SoftbusWriteHisEvt(&reportMsg);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: SoftbusWriteHisEvtTest007
 * @tc.desc: ParamType is SOFTBUS_EVT_PARAMTYPE_FLOAT
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterDsoftbusDfxTest, SoftbusWriteHisEvtTest007, TestSize.Level1)
{
    SoftBusEvtParam evtParam;
    strcpy_s(evtParam.paramName, sizeof(evtParam.paramName), "testParamName");
    evtParam.paramType = SOFTBUS_EVT_PARAMTYPE_FLOAT;
    evtParam.paramValue.f = 0.1f;

    SoftBusEvtReportMsg reportMsg;
    reportMsg.evtType = SOFTBUS_EVT_TYPE_FAULT;
    reportMsg.paramArray = &evtParam;
    reportMsg.paramNum = 1;
    strcpy_s(reportMsg.evtName, sizeof(evtParam.paramName), "testEvent");
    int32_t ret = SoftbusWriteHisEvt(&reportMsg);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: SoftbusWriteHisEvtTest008
 * @tc.desc: ParamType is SOFTBUS_EVT_PARAMTYPE_DOUBLE
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterDsoftbusDfxTest, SoftbusWriteHisEvtTest008, TestSize.Level1)
{
    SoftBusEvtParam evtParam;
    strcpy_s(evtParam.paramName, sizeof(evtParam.paramName), "testParamName");
    evtParam.paramType = SOFTBUS_EVT_PARAMTYPE_DOUBLE;
    evtParam.paramValue.d = 0.2;

    SoftBusEvtReportMsg reportMsg;
    reportMsg.evtType = SOFTBUS_EVT_TYPE_FAULT;
    reportMsg.paramArray = &evtParam;
    reportMsg.paramNum = 1;
    strcpy_s(reportMsg.evtName, sizeof(evtParam.paramName), "testEvent");
    int32_t ret = SoftbusWriteHisEvt(&reportMsg);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: SoftbusWriteHisEvtTest009
 * @tc.desc: ParamType is SOFTBUS_EVT_PARAMTYPE_STRING
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterDsoftbusDfxTest, SoftbusWriteHisEvtTest009, TestSize.Level1)
{
    SoftBusEvtParam evtParam;
    strcpy_s(evtParam.paramName, sizeof(evtParam.paramName), "testParamName");
    evtParam.paramType = SOFTBUS_EVT_PARAMTYPE_STRING;
    strcpy_s(evtParam.paramValue.str, sizeof(evtParam.paramValue.str), "testParamValue");

    SoftBusEvtReportMsg reportMsg;
    reportMsg.evtType = SOFTBUS_EVT_TYPE_FAULT;
    reportMsg.paramArray = &evtParam;
    reportMsg.paramNum = 1;
    strcpy_s(reportMsg.evtName, sizeof(evtParam.paramName), "testevent");
    int32_t ret = SoftbusWriteHisEvt(&reportMsg);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: SoftbusWriteHisEvtTest010
 * @tc.desc: ParamType is SOFTBUS_EVT_PARAMTYPE_BUTT
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterDsoftbusDfxTest, SoftbusWriteHisEvtTest010, TestSize.Level1)
{
    SoftBusEvtParam evtParam;
    strcpy_s(evtParam.paramName, sizeof(evtParam.paramName), "testParamName");
    evtParam.paramType = SOFTBUS_EVT_PARAMTYPE_BUTT;
    strcpy_s(evtParam.paramValue.str, sizeof(evtParam.paramValue.str), "testParamValue");

    SoftBusEvtReportMsg reportMsg;
    reportMsg.evtType = SOFTBUS_EVT_TYPE_FAULT;
    reportMsg.paramArray = &evtParam;
    reportMsg.paramNum = 1;
    strcpy_s(reportMsg.evtName, sizeof(evtParam.paramName), "testevent");
    int32_t ret = SoftbusWriteHisEvt(&reportMsg);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: SoftbusWriteHisEvtTest021
 * @tc.desc: evtType is SOFTBUS_EVT_TYPE_STATISTIC
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterDsoftbusDfxTest, SoftbusWriteHisEvtTest021, TestSize.Level1)
{
    SoftBusEvtParam evtParam;
    strcpy_s(evtParam.paramName, sizeof(evtParam.paramName), "testParamName");
    evtParam.paramType = SOFTBUS_EVT_PARAMTYPE_STRING;
    strcpy_s(evtParam.paramValue.str, sizeof(evtParam.paramValue.str), "testParamValue");

    SoftBusEvtReportMsg reportMsg;
    reportMsg.evtType = SOFTBUS_EVT_TYPE_STATISTIC;
    reportMsg.paramArray = &evtParam;
    reportMsg.paramNum = 1;
    strcpy_s(reportMsg.evtName, sizeof(evtParam.paramName), "testevent");
    int32_t ret = SoftbusWriteHisEvt(&reportMsg);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: SoftbusWriteHisEvtTest022
 * @tc.desc: evtType is SOFTBUS_EVT_TYPE_SECURITY
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterDsoftbusDfxTest, SoftbusWriteHisEvtTest022, TestSize.Level1)
{
    SoftBusEvtParam evtParam;
    strcpy_s(evtParam.paramName, sizeof(evtParam.paramName), "testParamName");
    evtParam.paramType = SOFTBUS_EVT_PARAMTYPE_STRING;
    strcpy_s(evtParam.paramValue.str, sizeof(evtParam.paramValue.str), "testParamValue");

    SoftBusEvtReportMsg reportMsg;
    reportMsg.evtType = SOFTBUS_EVT_TYPE_SECURITY;
    reportMsg.paramArray = &evtParam;
    reportMsg.paramNum = 1;
    strcpy_s(reportMsg.evtName, sizeof(evtParam.paramName), "testevent");
    int32_t ret = SoftbusWriteHisEvt(&reportMsg);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: SoftbusWriteHisEvtTest023
 * @tc.desc: evtType is SOFTBUS_EVT_TYPE_BEHAVIOR
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterDsoftbusDfxTest, SoftbusWriteHisEvtTest023, TestSize.Level1)
{
    SoftBusEvtParam evtParam;
    strcpy_s(evtParam.paramName, sizeof(evtParam.paramName), "testParamName");
    evtParam.paramType = SOFTBUS_EVT_PARAMTYPE_STRING;
    strcpy_s(evtParam.paramValue.str, sizeof(evtParam.paramValue.str), "testParamValue");

    SoftBusEvtReportMsg reportMsg;
    reportMsg.evtType = SOFTBUS_EVT_TYPE_BEHAVIOR;
    reportMsg.paramArray = &evtParam;
    reportMsg.paramNum = 1;
    strcpy_s(reportMsg.evtName, sizeof(evtParam.paramName), "testevent");
    int32_t ret = SoftbusWriteHisEvt(&reportMsg);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: SoftbusWriteHisEvtTest024
 * @tc.desc: evtType is SOFTBUS_EVT_TYPE_BUTT
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterDsoftbusDfxTest, SoftbusWriteHisEvtTest024, TestSize.Level1)
{
    SoftBusEvtParam evtParam;
    strcpy_s(evtParam.paramName, sizeof(evtParam.paramName), "testParamName");
    evtParam.paramType = SOFTBUS_EVT_PARAMTYPE_STRING;
    strcpy_s(evtParam.paramValue.str, sizeof(evtParam.paramValue.str), "testParamValue");

    SoftBusEvtReportMsg reportMsg;
    reportMsg.evtType = SOFTBUS_EVT_TYPE_BUTT;
    reportMsg.paramArray = &evtParam;
    reportMsg.paramNum = 1;
    strcpy_s(reportMsg.evtName, sizeof(evtParam.paramName), "testevent");
    int32_t ret = SoftbusWriteHisEvt(&reportMsg);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: SoftbusWriteHisEvtTest031
 * @tc.desc: paramNum is -1
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterDsoftbusDfxTest, SoftbusWriteHisEvtTest031, TestSize.Level1)
{
    int32_t paramNum = -1;
    SoftBusEvtReportMsg *msg = SoftbusCreateEvtReportMsg(paramNum);
    int32_t ret = SoftbusWriteHisEvt(msg);
    EXPECT_EQ(SOFTBUS_ERR, ret);
    SoftbusFreeEvtReportMsg(msg);
}

/*
 * @tc.name: SoftbusCreateEvtReportMsgTest001
 * @tc.desc: Create softbus event report message nllptr
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterDsoftbusDfxTest, SoftbusCreateEvtReportMsgTest001, TestSize.Level1)
{
    int32_t paramNum = -1;
    SoftBusEvtReportMsg *msg = SoftbusCreateEvtReportMsg(paramNum);
    EXPECT_EQ(nullptr, msg);
    SoftbusFreeEvtReportMsg(msg);
}

/*
 * @tc.name: SoftbusCreateEvtReportMsgTest002
 * @tc.desc: Create softbus event report message nllptr
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterDsoftbusDfxTest, SoftbusCreateEvtReportMsgTest002, TestSize.Level1)
{
    int32_t paramNum = SOFTBUS_EVT_PARAM_ZERO;
    SoftBusEvtReportMsg *msg = SoftbusCreateEvtReportMsg(paramNum);
    EXPECT_EQ(nullptr, msg);
    SoftbusFreeEvtReportMsg(msg);
}

/*
 * @tc.name: SoftbusCreateEvtReportMsgTest003
 * @tc.desc: Create softbus event report message nllptr
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterDsoftbusDfxTest, SoftbusCreateEvtReportMsgTest003, TestSize.Level1)
{
    int32_t paramNum = INT32_MAX;
    SoftBusEvtReportMsg *msg = SoftbusCreateEvtReportMsg(paramNum);
    EXPECT_EQ(nullptr, msg);
    SoftbusFreeEvtReportMsg(msg);
}

/*
 * @tc.name: SoftbusCreateEvtReportMsgTest004
 * @tc.desc: Create softbus event report message nllptr
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterDsoftbusDfxTest, SoftbusCreateEvtReportMsgTest004, TestSize.Level1)
{
    int32_t paramNum = SOFTBUS_EVT_PARAM_BUTT;
    SoftBusEvtReportMsg *msg = SoftbusCreateEvtReportMsg(paramNum);
    EXPECT_EQ(nullptr, msg);
    // free nullptr message
    SoftbusFreeEvtReportMsg(msg);
}

/*
 * @tc.name: SoftbusCreateEvtReportMsgTest005
 * @tc.desc: Create softbus event report message
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterDsoftbusDfxTest, SoftbusCreateEvtReportMsgTest005, TestSize.Level1)
{
    int32_t paramNum = SOFTBUS_EVT_PARAM_ONE;
    SoftBusEvtReportMsg *msg = SoftbusCreateEvtReportMsg(paramNum);
    EXPECT_NE(nullptr, msg);
    SoftbusFreeEvtReportMsg(msg);
}

} // namespace OHOS