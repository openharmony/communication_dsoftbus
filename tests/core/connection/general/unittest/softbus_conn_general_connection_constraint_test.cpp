/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "general_connection_mock.h"
#include "softbus_conn_general_connection.c"
#include "softbus_conn_general_connection.h"

using namespace std;

namespace OHOS {
using namespace testing::ext;
using namespace testing;
using testing::Return;

class GeneralConnectionConstraintTest : public testing::Test {
public:
    GeneralConnectionConstraintTest() { }
    ~GeneralConnectionConstraintTest() { }
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void GeneralConnectionConstraintTest::SetUpTestCase(void) { }

void GeneralConnectionConstraintTest::TearDownTestCase(void) { }

void GeneralConnectionConstraintTest::SetUp(void) { }

void GeneralConnectionConstraintTest::TearDown(void) { }

/*
 * @tc.name: ConstraintStateChangeHandlerTest001
 * @tc.desc: use abnormal parameter
 *           Test whether the function ConstraintStateChangeHandler correctly handles
 *           null pointer and wrong event type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GeneralConnectionConstraintTest, ConstraintStateChangeHandlerTest001, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(ConstraintStateChangeHandler(nullptr));
 
    LnnConstraintChangeEvent *event =
        reinterpret_cast<LnnConstraintChangeEvent *>(SoftBusCalloc(sizeof(LnnConstraintChangeEvent)));
    ASSERT_TRUE(event != nullptr);
    event->basic.event = LNN_EVENT_TYPE_MAX;
    event->isConstraint = true;
    EXPECT_NO_FATAL_FAILURE(ConstraintStateChangeHandler(&event->basic));
    SoftBusFree(event);
}

/*
 * @tc.name: ConstraintStateChangeHandlerTest002
 * @tc.desc: Test constraint disabled does not trigger ClearAllGeneralInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GeneralConnectionConstraintTest, ConstraintStateChangeHandlerTest002, TestSize.Level1)
{
    LnnConstraintChangeEvent *event =
        reinterpret_cast<LnnConstraintChangeEvent *>(SoftBusCalloc(sizeof(LnnConstraintChangeEvent)));
    ASSERT_TRUE(event != nullptr);
 
    event->basic.event = LNN_EVENT_CONSTRAINT_ENABLE;
    event->isConstraint = false;
    EXPECT_NO_FATAL_FAILURE(ConstraintStateChangeHandler(&event->basic));
 
    SoftBusFree(event);
}

/*
 * @tc.name: ConstraintStateChangeHandlerTest003
 * @tc.desc: Test constraint enabled with successful ClearAllGeneralInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GeneralConnectionConstraintTest, ConstraintStateChangeHandlerTest003, TestSize.Level1)
{
    LnnConstraintChangeEvent *event =
        reinterpret_cast<LnnConstraintChangeEvent *>(SoftBusCalloc(sizeof(LnnConstraintChangeEvent)));
    ASSERT_TRUE(event != nullptr);
 
    event->basic.event = LNN_EVENT_CONSTRAINT_ENABLE;
    event->isConstraint = true;
    EXPECT_NO_FATAL_FAILURE(ConstraintStateChangeHandler(&event->basic));
 
    SoftBusFree(event);
}

/*
 * @tc.name: ConnConstraintEventInitTest001
 * @tc.desc: Test ConnConstraintEventInit
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GeneralConnectionConstraintTest, ConnConstraintEventInitTest001, TestSize.Level1)
{
    GeneralConnectionInterfaceMock conMock;
    EXPECT_CALL(conMock, LnnRegisterEventHandler(testing::_, testing::_))
        .WillOnce(Return(SOFTBUS_NOT_IMPLEMENT));
    EXPECT_NE(ConnConstraintEventInit(), SOFTBUS_OK);
    EXPECT_CALL(conMock, LnnRegisterEventHandler(testing::_, testing::_))
        .WillOnce(Return(SOFTBUS_OK));
    EXPECT_EQ(ConnConstraintEventInit(), SOFTBUS_OK);
}
} // namespace OHOS
