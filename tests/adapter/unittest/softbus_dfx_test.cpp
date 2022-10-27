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
#include "softbus_errcode.h"
#include "softbus_adapter_hisysevent.h"

using namespace testing::ext;
namespace OHOS {
class DsoftbusDfxTest : public testing::Test {
protected:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() override {}
    void TearDown() override {}
};

/*
* @tc.name: HiSysEventParamDeInitTest001
* @tc.desc: paramType is SOFTBUS_EVT_PARAMTYPE_STRING
* @tc.type: FUNC
* @tc.require: 1
*/
HWTEST_F(DsoftbusDfxTest, HiSysEventParamDeInitTest001, TestSize.Level1)
{
    SoftBusEvtParam evtParam;
    strcpy_s(evtParam.paramName, sizeof(evtParam.paramName), "test");
    evtParam.paramType = SOFTBUS_EVT_PARAMTYPE_STRING;
    strcpy_s(evtParam.paramValue.str, sizeof(evtParam.paramValue.str), "test");

    SoftBusEvtReportMsg reportMsg;
    reportMsg.paramArray = &evtParam;
    reportMsg.paramNum = 1;
    int32_t ret = SoftbusWriteHisEvt(&reportMsg);
    EXPECT_EQ(SOFTBUS_OK, ret);
}
}