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
#include "softbus_adapter_hisysevent.h"
#include "softbus_hisysevt_common.h"

using namespace std;
using namespace testing::ext;

namespace OHOS {
class LnnDfxTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void LnnDfxTest::SetUpTestCase(void) {}

void LnnDfxTest::TearDownTestCase(void) {}

void LnnDfxTest::SetUp(void) {}

void LnnDfxTest::TearDown(void) {}

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
 * @tc.desc: Verify AddStatisticRateOfSuccess function, use the normal parameter.
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
}
}; // namespace OHOS