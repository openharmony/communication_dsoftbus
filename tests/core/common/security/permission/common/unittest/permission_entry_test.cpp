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

#include <gtest/gtest.h>
#include <securec.h>

#include "permission_entry.h"
#include "session.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "softbus_error_code.h"

using namespace std;
using namespace testing::ext;
#define NUM                     50
#define DBINDER_SERVICE_NAME    "DBinderService"
#define DBINDER_BUS_NAME_PREFIX "DBinder"

namespace OHOS {

const char *g_pkgName = "dms";
const char *g_sessionName = "ohos.distributedschedule.dms.test";
const char *g_errPkgName = "abc";

class PermissionEntryTest : public testing::Test {
public:
    PermissionEntryTest() { }
    ~PermissionEntryTest() { }
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override { }
    void TearDown() override { }
};

void PermissionEntryTest::SetUpTestCase(void) { }
void PermissionEntryTest::TearDownTestCase(void) { }

/**
 * @tc.name: StrIsEmptyTest001
 * @tc.desc: str is empty test, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionEntryTest, StrIsEmptyTest001, TestSize.Level0)
{
    int32_t ret;
    const char *sessionName = "";
    SoftBusPermissionItem *pItem = (SoftBusPermissionItem *)SoftBusCalloc(sizeof(SoftBusPermissionItem));
    ASSERT_TRUE(pItem != NULL);
    ret = CheckPermissionEntry(sessionName, pItem);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**
 * @tc.name: LoadPermissionJsonTest001
 * @tc.desc: load permission json test, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionEntryTest, LoadPermissionJsonTest001, TestSize.Level0)
{
    int32_t ret;

    ret = LoadPermissionJson(NULL);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**
 * @tc.name: CheckPermissionEntryTest001
 * @tc.desc: check permission entry test, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionEntryTest, CheckPermissionEntryTest001, TestSize.Level0)
{
    int32_t ret;
    char sessionName[NUM] = "ABC";
    char sessionNameNormal[NUM] = "bbb";
    SoftBusPermissionItem *pItem = (SoftBusPermissionItem *)SoftBusCalloc(sizeof(SoftBusPermissionItem));
    ASSERT_TRUE(pItem != NULL);

    ret = CheckPermissionEntry(NULL, pItem);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = CheckPermissionEntry(g_sessionName, NULL);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    pItem->permType = NATIVE_APP;
    ret = CheckPermissionEntry(sessionName, NULL);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    pItem->permType = NORMAL_APP;
    pItem->actions = ACTION_CREATE;
    pItem->pkgName = NULL;

    ret = CheckPermissionEntry(sessionName, pItem);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    pItem->pkgName = sessionName;
    ret = CheckPermissionEntry(sessionNameNormal, pItem);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**
 * @tc.name: PermIsSecLevelPublicTest001
 * @tc.desc: perm is sec level public test, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionEntryTest, PermIsSecLevelPublicTest001, TestSize.Level0)
{
    bool ret;
    const char sessionName[NUM] = "";

    ret = PermIsSecLevelPublic(NULL);
    EXPECT_TRUE(ret == false);

    ret = PermIsSecLevelPublic(DBINDER_SERVICE_NAME);
    EXPECT_TRUE(ret == true);

    ret = PermIsSecLevelPublic(sessionName);
    EXPECT_TRUE(ret == false);
}

/**
 * @tc.name: AddDynamicPermissionTest001
 * @tc.desc: add dynamic permission test, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionEntryTest, AddDynamicPermissionTest001, TestSize.Level0)
{
    int32_t ret;
    int32_t callingUid = 0;
    int32_t callingPid = 0;
    char sessionNameWrong[SESSION_NAME_SIZE_MAX * 2] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                                                       "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                                                       "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                                                       "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                                                       "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    InitDynamicPermission();
    ret = AddDynamicPermission(callingUid, callingPid, DBINDER_BUS_NAME_PREFIX);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = AddDynamicPermission(callingUid, callingPid, DBINDER_SERVICE_NAME);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = AddDynamicPermission(callingUid, callingPid, sessionNameWrong);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**
 * @tc.name: DeleteDynamicPermissionTest001
 * @tc.desc: delete dynamic permission test, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionEntryTest, DeleteDynamicPermissionTest001, TestSize.Level0)
{
    int32_t ret;
    const char sessionName[NUM] = "bbb";

    InitDynamicPermission();
    ret = DeleteDynamicPermission(sessionName);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
}
} // namespace OHOS