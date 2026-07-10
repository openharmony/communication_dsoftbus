/*
 * Copyright (c) 2022-2026 Huawei Device Co., Ltd.
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

#include "permission_entry.h"
#include "softbus_error_code.h"
#include "softbus_permission.h"

using namespace testing::ext;

namespace OHOS {
int32_t g_permUid = 0;
int32_t g_permPid = 0;
std::string g_permSessionName;

class TransDynamicPermissionTest : public testing::Test {
public:
    TransDynamicPermissionTest() { }
    ~TransDynamicPermissionTest() { }
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override { }
    void TearDown() override { }
};

void TransDynamicPermissionTest::SetUpTestCase(void)
{
    g_permUid = static_cast<int32_t>(getuid());
    ASSERT_TRUE(g_permUid >= 0);
    g_permPid = static_cast<int32_t>(getpid());
    ASSERT_TRUE(g_permPid > 0);
    g_permSessionName = "DBinder" + std::to_string(g_permUid) + std::string("_") + std::to_string(g_permPid);
    ASSERT_EQ(TransPermissionInit(), SOFTBUS_OK);
}

void TransDynamicPermissionTest::TearDownTestCase(void)
{
    TransPermissionDeinit();
}

/**
 * @tc.name: AddAndDeleteDynamicPermissionTest001
 * @tc.desc: AddDynamicPermission and DeleteDynamicPermission with valid params return SOFTBUS_OK.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransDynamicPermissionTest, AddAndDeleteDynamicPermissionTest001, TestSize.Level1)
{
    int32_t ret = AddDynamicPermission(g_permUid, g_permPid, g_permSessionName.c_str());
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = DeleteDynamicPermission(g_permSessionName.c_str());
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = AddDynamicPermission(g_permUid, g_permPid, g_permSessionName.c_str());
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = DeleteDynamicPermission(g_permSessionName.c_str());
    ASSERT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: AddDynamicPermissionTest002
 * @tc.desc: AddDynamicPermission reach upper limit returns SOFTBUS_NO_ENOUGH_DATA.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransDynamicPermissionTest, AddDynamicPermissionTest002, TestSize.Level1)
{
    int32_t testPid = 10000;
    int32_t ret = 0;
    int32_t testNum = 99;

    std::string sessionName = "DBinder" + std::to_string(g_permUid) + std::string("_") + std::to_string(g_permPid);
    ret = AddDynamicPermission(g_permUid, g_permPid, sessionName.c_str());
    ASSERT_EQ(ret, SOFTBUS_OK);

    for (int32_t i = 0; i < testNum; i++) {
        sessionName = "DBinder" + std::to_string(g_permUid) + std::string("_") + std::to_string(testPid);
        ret = AddDynamicPermission(g_permUid, testPid, sessionName.c_str());
        ASSERT_EQ(ret, SOFTBUS_OK);
        testPid++;
    }

    for (int32_t i = 0; i < testNum; i++) {
        sessionName = "DBinder" + std::to_string(g_permUid) + std::string("_") + std::to_string(testPid);
        ret = AddDynamicPermission(g_permUid, testPid, sessionName.c_str());
        ASSERT_EQ(ret, SOFTBUS_NO_ENOUGH_DATA);
    }

    sessionName = "DBinder" + std::to_string(g_permUid) + std::string("_") + std::to_string(g_permPid);
    ret = DeleteDynamicPermission(sessionName.c_str());
    ASSERT_EQ(ret, SOFTBUS_OK);
    testPid--;
    for (int32_t i = 0; i < testNum; i++) {
        sessionName = "DBinder" + std::to_string(g_permUid) + std::string("_") + std::to_string(testPid);
        testPid--;
        ret = DeleteDynamicPermission(sessionName.c_str());
        ASSERT_EQ(ret, SOFTBUS_OK) << sessionName;
    }
}

/**
 * @tc.name: CheckTransPermissionTest001
 * @tc.desc: CheckTransPermission without dynamic permission returns not SOFTBUS_OK for both open and create actions.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransDynamicPermissionTest, CheckTransPermissionTest001, TestSize.Level1)
{
    int32_t testPid = 20000;
    std::string sessionName = "DBinder" + std::to_string(g_permUid) + std::string("_") + std::to_string(testPid);
    int32_t ret = CheckTransPermission(g_permUid, testPid, "DBinderBus", sessionName.c_str(), ACTION_OPEN);
    ASSERT_NE(ret, SOFTBUS_OK);
    ret = CheckTransPermission(g_permUid, testPid, "DBinderBus", sessionName.c_str(), ACTION_CREATE);
    ASSERT_NE(ret, SOFTBUS_OK);
}

/**
 * @tc.name: CheckTransPermissionTest002
 * @tc.desc: CheckTransPermission with dynamic permission returns SOFTBUS_OK.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransDynamicPermissionTest, CheckTransPermissionTest002, TestSize.Level1)
{
    int32_t testPid = 20001;
    std::string sessionName = "DBinder" + std::to_string(g_permUid) + std::string("_") + std::to_string(testPid);
    int32_t ret = AddDynamicPermission(g_permUid, testPid, sessionName.c_str());
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = CheckTransPermission(g_permUid, testPid, "DBinderBus", sessionName.c_str(), ACTION_OPEN);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = DeleteDynamicPermission(sessionName.c_str());
    ASSERT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: CheckTransSecLevelTest001
 * @tc.desc: CheckTransSecLevel with same session names returns SOFTBUS_OK.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransDynamicPermissionTest, CheckTransSecLevelTest001, TestSize.Level1)
{
    int32_t testPid = 20002;
    std::string sessionName = "DBinder" + std::to_string(g_permUid) + std::string("_") + std::to_string(testPid);
    int32_t ret = AddDynamicPermission(g_permUid, testPid, sessionName.c_str());
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = CheckTransSecLevel(sessionName.c_str(), sessionName.c_str());
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = DeleteDynamicPermission(sessionName.c_str());
    ASSERT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: CheckTransPermissionTest003
 * @tc.desc: CheckTransPermission after delete returns not SOFTBUS_OK.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransDynamicPermissionTest, CheckTransPermissionTest003, TestSize.Level1)
{
    int32_t testPid = 20003;
    std::string sessionName = "DBinder" + std::to_string(g_permUid) + std::string("_") + std::to_string(testPid);
    int32_t ret = AddDynamicPermission(g_permUid, testPid, sessionName.c_str());
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = DeleteDynamicPermission(sessionName.c_str());
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = CheckTransPermission(g_permUid, testPid, "DBinderBus", sessionName.c_str(), ACTION_OPEN);
    ASSERT_NE(ret, SOFTBUS_OK);
}

/**
 * @tc.name: DynamicPermissionAddDeleteCycleTest001
 * @tc.desc: Repeated add delete and check dynamic permission cycle.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransDynamicPermissionTest, DynamicPermissionAddDeleteCycleTest001, TestSize.Level1)
{
    int32_t testPid = 17258;
    int32_t ret = 0;
    int32_t testNum = 100;
    std::string sessionName = "DBinder" + std::to_string(g_permUid) + std::string("_") + std::to_string(testPid);

    for (int32_t i = 0; i < testNum; i++) {
        ret = CheckTransPermission(g_permUid, testPid, "DBinderBus", sessionName.c_str(), ACTION_OPEN);
        ASSERT_NE(ret, SOFTBUS_OK);
        ret = AddDynamicPermission(g_permUid, testPid, sessionName.c_str());
        ASSERT_EQ(ret, SOFTBUS_OK);

        ret = CheckTransPermission(g_permUid, testPid, "DBinderBus", sessionName.c_str(), ACTION_OPEN);
        ASSERT_EQ(ret, SOFTBUS_OK) << "sessionName: " << sessionName.c_str();
        ret = CheckTransSecLevel(sessionName.c_str(), sessionName.c_str());
        ASSERT_EQ(ret, SOFTBUS_OK);

        ret = DeleteDynamicPermission(sessionName.c_str());
        ASSERT_EQ(ret, SOFTBUS_OK);

        ret = CheckTransPermission(g_permUid, testPid, "DBinderBus", sessionName.c_str(), ACTION_OPEN);
        ASSERT_NE(ret, SOFTBUS_OK);
    }
    TransPermissionDeinit();
    ASSERT_EQ(TransPermissionInit(), SOFTBUS_OK);
}
} // namespace OHOS
