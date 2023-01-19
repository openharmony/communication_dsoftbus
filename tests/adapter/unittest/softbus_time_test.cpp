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
#include <securec.h>
#include "gtest/gtest.h"

#include "softbus_adapter_timer.h"
#include "softbus_def.h"
#include "softbus_errcode.h"

using namespace std;
using namespace testing::ext;

namespace OHOS {
const int32_t TIMER_TIMEOUT = 1000;

class SoftbusTimeTest : public testing::Test {
protected:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};
void SoftbusTimeTest::SetUpTestCase(void)
{
}
void SoftbusTimeTest::TearDownTestCase(void)
{
}
void SoftbusTimeTest::SetUp()
{
}
void SoftbusTimeTest::TearDown()
{
}
/*
* @tc.name: SoftBusTimerTest001
* @tc.desc: soft bus timer test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftbusTimeTest, SoftBusTimerTest001, TestSize.Level1)
{
    void *timerId = NULL;
    SoftBusSysTime times = {0};
    int32_t ret;

    ret = SoftBusStartTimer(NULL, TIMER_TIMEOUT);
    EXPECT_EQ(SOFTBUS_ERR, ret);
    SoftBusCreateTimer(NULL, TIMER_TYPE_ONCE);
    SoftBusCreateTimer(&timerId, TIMER_TYPE_ONCE);
    ret = SoftBusStartTimer(timerId, TIMER_TIMEOUT);
    EXPECT_NE(SOFTBUS_ERR, ret);
    ret = SoftBusDeleteTimer(NULL);
    EXPECT_EQ(SOFTBUS_ERR, ret);
    ret = SoftBusDeleteTimer(timerId);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SoftBusGetTime(NULL);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = SoftBusGetTime(&times);
    EXPECT_EQ(SOFTBUS_OK, ret);
}
}