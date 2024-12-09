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

#include "permission_entry.c"
#include "session.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "softbus_error_code.h"

using namespace std;
using namespace testing::ext;

#define NUM 50
namespace OHOS {

const char *g_pkgName = "dms";
const char *g_sessionName = "ohos.distributedschedule.dms.test";
const char *g_errPkgName = "abc";

class PermissionEntrystaticTest : public testing::Test {
public:
    PermissionEntrystaticTest() { }
    ~PermissionEntrystaticTest() { }
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override { }
    void TearDown() override { }
};

void PermissionEntrystaticTest::SetUpTestCase(void) { }
void PermissionEntrystaticTest::TearDownTestCase(void) { }

/**
 * @tc.name: GetPeMapValueTest001
 * @tc.desc: get pe map value test, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionEntrystaticTest, GetPeMapValue001, TestSize.Level0)
{
    int32_t ret;
    const char *tmpString = "";
    ret = GetPeMapValue(tmpString);
    EXPECT_EQ(UNKNOWN_VALUE, ret);
}

/**
 * @tc.name: StrStartWithTest001
 * @tc.desc: str start with test, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionEntrystaticTest, StrStartWithTest001, TestSize.Level0)
{
    bool ret;
    const char tmpString[NUM] = "";
    const char tmpStringNormal[NUM] = "hfg";
    const char target[NUM] = "abc";
    ret = StrStartWith(tmpString, target);
    EXPECT_TRUE(ret == false);

    ret = StrStartWith(NULL, NULL);
    EXPECT_TRUE(ret == false);

    ret = StrStartWith(tmpStringNormal, target);
    EXPECT_TRUE(ret == false);
}

/**
 * @tc.name: ProcessAppInfoTest001
 * @tc.desc: process app info test, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionEntrystaticTest, ProcessAppInfoTest001, TestSize.Level0)
{
    SoftBusAppInfo *pRet = NULL;

    pRet = ProcessAppInfo(NULL);
    EXPECT_TRUE(pRet == NULL);
}

/**
 * @tc.name: ProcessPermissionEntryTest001
 * @tc.desc: process permission entry test, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionEntrystaticTest, ProcessPermissionEntryTest001, TestSize.Level0)
{
    SoftBusPermissionEntry *pRet = NULL;
    cJSON object;

    pRet = ProcessPermissionEntry(NULL);
    EXPECT_TRUE(pRet == NULL);

    pRet = ProcessPermissionEntry(&object);
    EXPECT_TRUE(pRet == NULL);
}

/**
 * @tc.name: CompareStringTest001
 * @tc.desc: compare string test, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionEntrystaticTest, CompareStringTest001, TestSize.Level0)
{
    int32_t ret;

    ret = CompareString(NULL, NULL, true);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = CompareString(g_pkgName, g_pkgName, true);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: GetPermTypeTest001
 * @tc.desc: get perm type test, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionEntrystaticTest, GetPermTypeTest001, TestSize.Level0)
{
    int32_t ret;
    ret = GetPermType(NULL, NULL);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    SoftBusPermissionItem *pItem = (SoftBusPermissionItem *)SoftBusCalloc(sizeof(SoftBusPermissionItem));
    ASSERT_TRUE(pItem != NULL);
    SoftBusAppInfo *appInfo = (SoftBusAppInfo *)SoftBusCalloc(sizeof(SoftBusAppInfo));
    ASSERT_TRUE(appInfo != NULL);
    ListInit(&appInfo->node);
    appInfo->type = NATIVE_APP;
    appInfo->uid = UNKNOWN_VALUE;
    appInfo->pid = UNKNOWN_VALUE;
    appInfo->actions = 0;

    pItem->permType = SYSTEM_APP;
    ret = GetPermType(appInfo, pItem);
    EXPECT_EQ(SYSTEM_APP, ret);

    pItem->permType = NATIVE_APP;
    ret = GetPermType(appInfo, pItem);
    EXPECT_EQ(NATIVE_APP, ret);

    appInfo->type = SYSTEM_APP;
    pItem->permType = SYSTEM_APP;
    ret = GetPermType(appInfo, pItem);
    EXPECT_EQ(SYSTEM_APP, ret);

    pItem->permType = NATIVE_APP;
    ret = GetPermType(appInfo, pItem);
    EXPECT_EQ(NATIVE_APP, ret);

    appInfo->type = GRANTED_APP;
    pItem->actions = ACTION_CREATE;
    pItem->permType = SYSTEM_APP;
    ret = GetPermType(appInfo, pItem);
    EXPECT_EQ(SYSTEM_APP, ret);

    pItem->permType = NATIVE_APP;
    ret = GetPermType(appInfo, pItem);
    EXPECT_EQ(NATIVE_APP, ret);

    pItem->permType = NORMAL_APP;
    ret = GetPermType(appInfo, pItem);
    EXPECT_EQ(NORMAL_APP, ret);
}

/**
 * @tc.name: GetPermTypeTest002
 * @tc.desc: get perm type test, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionEntrystaticTest, GetPermTypeTest002, TestSize.Level0)
{
    int32_t ret;
    ret = GetPermType(NULL, NULL);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    SoftBusPermissionItem *pItem = (SoftBusPermissionItem *)SoftBusCalloc(sizeof(SoftBusPermissionItem));
    ASSERT_TRUE(pItem != NULL);
    SoftBusAppInfo *appInfo = (SoftBusAppInfo *)SoftBusCalloc(sizeof(SoftBusAppInfo));
    ASSERT_TRUE(appInfo != NULL);
    ListInit(&appInfo->node);
    appInfo->type = GRANTED_APP;
    appInfo->uid = UNKNOWN_VALUE;
    appInfo->pid = UNKNOWN_VALUE;
    appInfo->actions = 0;

    pItem->actions = ACTION_OPEN;
    pItem->permType = GRANTED_APP;
    ret = GetPermType(appInfo, pItem);
    EXPECT_EQ(GRANTED_APP, ret);

    appInfo->type = NORMAL_APP;
    pItem->permType = SYSTEM_APP;
    ret = GetPermType(appInfo, pItem);
    EXPECT_EQ(SYSTEM_APP, ret);

    pItem->permType = NATIVE_APP;
    ret = GetPermType(appInfo, pItem);
    EXPECT_EQ(NATIVE_APP, ret);

    pItem->permType = NORMAL_APP;
    ret = GetPermType(appInfo, pItem);
    EXPECT_EQ(NORMAL_APP, ret);

    appInfo->type = SELF_APP;
    pItem->permType = SELF_APP;
    ret = GetPermType(appInfo, pItem);
    EXPECT_EQ(SELF_APP, ret);

    appInfo->type = NUM;
    ret = GetPermType(appInfo, pItem);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    appInfo->type = NUM;
    pItem->permType = NUM;
    ret = GetPermType(appInfo, pItem);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**
 * @tc.name: CheckPermissionAppInfoTest001
 * @tc.desc: check permission appinfo test, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionEntrystaticTest, CheckPermissionAppInfoTest001, TestSize.Level0)
{
    int32_t ret;
    SoftBusPermissionEntry *pe = NULL;

    SoftBusPermissionItem *pItem = (SoftBusPermissionItem *)SoftBusCalloc(sizeof(SoftBusPermissionItem));
    ASSERT_TRUE(pItem != NULL);

    ret = CheckPermissionAppInfo(NULL, NULL);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    pItem->actions = 0;
    ret = CheckPermissionAppInfo(pe, pItem);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    SoftBusPermissionEntry *permissionEntry = (SoftBusPermissionEntry *)SoftBusCalloc(sizeof(SoftBusPermissionEntry));
    ASSERT_TRUE(permissionEntry != NULL);
    ListInit(&permissionEntry->node);
    ListInit(&permissionEntry->appInfo);
    permissionEntry->regexp = false;
    permissionEntry->devId = UNKNOWN_VALUE;
    permissionEntry->secLevel = UNKNOWN_VALUE;

    ret = CheckPermissionAppInfo(pe, pItem);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**
 * @tc.name: CheckDBinderTest001
 * @tc.desc: check dbinder test, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionEntrystaticTest, CheckDBinderTest001, TestSize.Level0)
{
    bool ret;
    char sessionName[NUM] = "";
    char sessionNameWrong[NUM] = "abc";

    ret = CheckDBinder(sessionName);
    EXPECT_TRUE(ret == false);

    ret = CheckDBinder(DBINDER_SERVICE_NAME);
    EXPECT_TRUE(ret == true);

    ret = CheckDBinder(DBINDER_BUS_NAME_PREFIX);
    EXPECT_TRUE(ret == true);

    ret = CheckDBinder(sessionNameWrong);
    EXPECT_TRUE(ret == false);
}

/**
 * @tc.name: HaveGrantedPermissionTest001
 * @tc.desc: have graned permission test, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionEntrystaticTest, HaveGrantedPermissionTest001, TestSize.Level0)
{
    bool ret;

    ret = HaveGrantedPermission(NULL);
    EXPECT_TRUE(ret == false);

    ret = HaveGrantedPermission(DBINDER_SERVICE_NAME);
    EXPECT_TRUE(ret == false);

    ret = HaveGrantedPermission(DBINDER_BUS_NAME_PREFIX);
    EXPECT_TRUE(ret == false);
}

/**
 * @tc.name: NewDynamicPermissionEntryTest001
 * @tc.desc: have graned permission test, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionEntrystaticTest, NewDynamicPermissionEntryTest001, TestSize.Level0)
{
    bool ret;
    char sessionName[NUM] = "";
    char sessionNameWrong[SESSION_NAME_SIZE_MAX * 2] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                                                       "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                                                       "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                                                       "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                                                       "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    int32_t callingUid = 0;
    int32_t callingPid = 0;
    SoftBusPermissionEntry *permissionEntry = (SoftBusPermissionEntry *)SoftBusCalloc(sizeof(SoftBusPermissionEntry));
    ASSERT_TRUE(permissionEntry != NULL);

    ret = NewDynamicPermissionEntry(NULL, sessionName, callingUid, callingPid);
    EXPECT_TRUE(ret == true);

    ret = NewDynamicPermissionEntry(permissionEntry, NULL, callingUid, callingPid);
    EXPECT_TRUE(ret == true);

    ret = NewDynamicPermissionEntry(permissionEntry, sessionNameWrong, callingUid, callingPid);
    EXPECT_TRUE(ret == true);

    ret = NewDynamicPermissionEntry(permissionEntry, DBINDER_SERVICE_NAME, callingUid, callingPid);
    EXPECT_TRUE(ret == false);
}
} // namespace OHOS