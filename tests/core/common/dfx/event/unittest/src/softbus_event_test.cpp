/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "hisysevent_mock.h"
#include "softbus_hisysevent_matcher.h"
#include "gtest/gtest.h"

using namespace std;
using namespace testing;
using namespace testing::ext;

namespace OHOS {
class SoftbusEventTest : public testing::Test { };

/**
 * @tc.name: SoftbusEventTest001
 * @tc.desc: Test event names
 * @tc.type: FUNC
 * @tc.require: I8HA59
 */
HWTEST_F(SoftbusEventTest, SoftbusEventTest001, TestSize.Level0)
{
    EXPECT_STREQ(CONN_EVENT_NAME, "CONNECTION_BEHAVIOR");
    EXPECT_STREQ(DISC_EVENT_NAME, "DISCOVER_BEHAVIOR");
    EXPECT_STREQ(LNN_EVENT_NAME, "BUSCENTER_BEHAVIOR");
    EXPECT_STREQ(TRANS_EVENT_NAME, "TRANSPORT_BEHAVIOR");
}

/**
 * @tc.name: SoftbusEventTest002
 * @tc.desc: Test softbus event form
 * @tc.type: FUNC
 * @tc.require: I8HA59
 */
HWTEST_F(SoftbusEventTest, SoftbusEventTest002, TestSize.Level0)
{
    SoftbusEventForm form = {
        .scene = EVENT_SCENE_OPEN_CHANNEL,
        .stage = EVENT_STAGE_START_CONNECT,
        .line = 233,
        .func = "TestFunc",
    };
    constexpr int32_t VALID_FORM_SIZE = SOFTBUS_ASSIGNER_SIZE;

    HiSysEventMock mock;
    EXPECT_CALL(mock,
        HiSysEvent_Write(StrEq(form.func), Eq(form.line), StrEq(SOFTBUS_EVENT_DOMAIN), _,
            Eq(SOFTBUS_EVENT_TYPE_BEHAVIOR), SoftbusParamArrayMatcher(form, VALID_FORM_SIZE), _))
        .Times(1);
    SoftbusEventInner(EVENT_MODULE_CONN, &form);
}

} // namespace OHOS