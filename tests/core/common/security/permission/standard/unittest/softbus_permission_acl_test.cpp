/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include <securec.h>

#include "access_control.h"
#include "session.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "softbus_error_code.h"

using namespace std;
using namespace testing::ext;

namespace OHOS {
const int32_t HAP_TOKENID = 123456;
const int32_t NATIVE_TOKENID = 134341184;
class SoftbusPermissionACLTest : public testing::Test {
public:
    SoftbusPermissionACLTest() { }
    ~SoftbusPermissionACLTest() { }
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override { }
    void TearDown() override { }
};

void SoftbusPermissionACLTest::SetUpTestCase(void) { }
void SoftbusPermissionACLTest::TearDownTestCase(void) { }

/**
 * @tc.name: TransCheckClientAccessControl001
 * @tc.desc: test function TransCheckClientAccessControl parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusPermissionACLTest, TransCheckClientAccessControl001, TestSize.Level0)
{
    int32_t ret = TransCheckClientAccessControl(nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = TransCheckClientAccessControl("test");
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransCheckServerAccessControl001
 * @tc.desc: test function TransCheckServerAccessControl parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusPermissionACLTest, TransCheckServerAccessControl001, TestSize.Level0)
{
    int32_t ret = TransCheckServerAccessControl(TOKENID_NOT_SET);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = TransCheckServerAccessControl(NATIVE_TOKENID);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = TransCheckServerAccessControl(HAP_TOKENID);
    EXPECT_NE(SOFTBUS_OK, ret);
}
} // namespace OHOS