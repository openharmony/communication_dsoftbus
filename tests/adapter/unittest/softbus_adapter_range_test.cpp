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
#include <securec.h>
#include "gtest/gtest.h"

#include "softbus_errcode.h"
#include "softbus_adapter_range.h"

using namespace std;
using namespace testing::ext;

namespace OHOS {
class AdapterDsoftbusRangeTest : public testing::Test {
protected:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};
void AdapterDsoftbusRangeTest::SetUpTestCase(void)
{
}
void AdapterDsoftbusRangeTest::TearDownTestCase(void)
{
}
void AdapterDsoftbusRangeTest::SetUp()
{
}
void AdapterDsoftbusRangeTest::TearDown()
{
}
/*
* @tc.name: SoftBusBleRange001
* @tc.desc: parameters is Legal and illegal
* @tc.type: FUNC
* @tc.require: I5OHDE
*/
HWTEST_F(AdapterDsoftbusRangeTest, SoftBusBleRange001, TestSize.Level0)
{
    int32_t range = -1;
    SoftBusRangeParam param = {
        .rssi = 5,
        .power = 1,
        .identity = {"test"}
    };
    int32_t ret = SoftBusBleRange(NULL, NULL);
    EXPECT_EQ(-1, ret);
    ret = SoftBusBleRange(NULL, &range);
    EXPECT_EQ(-1, ret);
    ret = SoftBusBleRange(&param, NULL);
    EXPECT_EQ(-1, ret);
    ret = SoftBusBleRange(&param, &range);
    EXPECT_EQ(0, ret);
}

/*
* @tc.name: SoftBusGetBlePower001
* @tc.desc: parameter is Legal and illegal
* @tc.type: FUNC
* @tc.require: I5OHDE
*/
HWTEST_F(AdapterDsoftbusRangeTest, SoftBusGetBlePower001, TestSize.Level0)
{
    int8_t power = 0;
    int ret = SoftBusGetBlePower(NULL);
    EXPECT_EQ(-1, ret);
    ret = SoftBusGetBlePower(&power);
    EXPECT_EQ(0, ret);
}
}