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

#include "securec.h"
#include <gtest/gtest.h>

#include "permission_entry.h"
#include "permission_utils.h"
#include "session.h"
#include "softbus_access_token_adapter.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_permission.h"

using namespace std;
using namespace testing::ext;

namespace OHOS {
const char *g_pkgName = "dms";
const char *g_sessionName = "ohos.distributedschedule.dms.test";

class SoftbusPermissionTest : public testing::Test {
public:
    SoftbusPermissionTest() { }
    ~SoftbusPermissionTest() { }
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override { }
    void TearDown() override { }
};

void SoftbusPermissionTest::SetUpTestCase(void) { }
void SoftbusPermissionTest::TearDownTestCase(void) { }

/**
 * @tc.name: IsValidPkgNameTest001
 * @tc.desc: is valid pkgname test, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusPermissionTest, IsValidPkgNameTest001, TestSize.Level0)
{
    int32_t ret;

    ret = IsValidPkgName(0, NULL);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = IsValidPkgName(0, g_pkgName);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: CheckTransPermissionTest001
 * @tc.desc: check trans permission test, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusPermissionTest, CheckTransPermissionTest001, TestSize.Level0)
{
    int32_t ret;

    ret = CheckTransPermission(0, 0, nullptr, g_sessionName, 0);
    EXPECT_EQ(SOFTBUS_PERMISSION_DENIED, ret);

    ret = CheckTransPermission(0, 0, g_pkgName, nullptr, 0);
    EXPECT_EQ(SOFTBUS_PERMISSION_DENIED, ret);
}

/**
 * @tc.name: CheckTransSecLevelTest001
 * @tc.desc: check trans sec level test, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusPermissionTest, CheckTransSecLevelTest001, TestSize.Level0)
{
    int32_t ret;
    ret = CheckTransSecLevel(nullptr, g_sessionName);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = CheckTransSecLevel(g_sessionName, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = CheckTransSecLevel(g_sessionName, g_sessionName);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: CheckDiscPermissionTest001
 * @tc.desc: check disc permission test, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusPermissionTest, CheckDiscPermissionTest001, TestSize.Level0)
{
#define SYSTEM_UID 1000
    bool ret;

    ret = CheckDiscPermission(0, nullptr);
    EXPECT_TRUE(ret == false);

    ret = CheckDiscPermission(SYSTEM_UID, g_pkgName);
    EXPECT_TRUE(ret == true);

    ret = CheckDiscPermission(0, g_pkgName);
    EXPECT_TRUE(ret == false);
}

/**
 * @tc.name: GrantTransPermissionTest001
 * @tc.desc: grant trans permission test, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusPermissionTest, GrantTransPermissionTest001, TestSize.Level0)
{
    int32_t ret;
    InitDynamicPermission();
    ret = GrantTransPermission(0, 0, NULL);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**
 * @tc.name: RemoveTransPermissionTest001
 * @tc.desc: remove trans permission test, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusPermissionTest, RemoveTransPermissionTest001, TestSize.Level0)
{
    int32_t ret;

    ret = RemoveTransPermission(g_sessionName);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
}

/**
 * @tc.name: CheckDynamicPermissionTest001
 * @tc.desc: check dynamic permission test, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusPermissionTest, CheckDynamicPermissionTest001, TestSize.Level0)
{
    int32_t invalidTokenId = -1;
    int32_t ret = SoftBusCheckDynamicPermission(invalidTokenId);
    EXPECT_EQ(SOFTBUS_PERMISSION_DENIED, ret);
}

/**
 * @tc.name:CheckDmsServerPermissionTest001
 * @tc.desc: check dms server permission test, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusPermissionTest, CheckDmsServerPermissionTest001, TestSize.Level0)
{
    uint64_t invalidTokenId = 0;
    int32_t ret = SoftBusCheckDmsServerPermission(invalidTokenId);
    EXPECT_EQ(SOFTBUS_PERMISSION_DENIED, ret);
}
} // namespace OHOS