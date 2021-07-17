/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#include <pthread.h>
#include <vector>

#include "permission/permission.h"
#include "permission/permission_kit.h"
#include "permission_entry.h"
#include "permission_utils.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_permission.h"
#include "softbus_utils.h"

using namespace testing::ext;
using namespace OHOS::Security::Permission;

namespace OHOS {
const char *JSON_FILE = "/system/etc/communication/softbus/softbus_permission_test.json";
const std::string SYSTEM_APP_PERMISSION = "com.huawei.permission.MANAGE_DISTRIBUTED_PERMISSION";
const std::string DANGER_APP_PERMISSION = "ohos.permission.DISTRIBUTED_DATASYNC";
const std::string BIND_DISCOVER_SERVICE = "com.huawei.hwddmp.permission.BIND_DISCOVER_SERVICE";

const std::string TEST_LABEL = "test label";
const std::string TEST_DESCRIPTION = "test description";
const int TEST_LABEL_ID = 9527;
const int TEST_DESCRIPTION_ID = 9528;

class SoftbusPermissionTest : public testing::Test {
public:
    SoftbusPermissionTest()
    {}
    ~SoftbusPermissionTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void SoftbusPermissionTest::SetUpTestCase(void)
{
    TransPermissionInit(JSON_FILE);
}

void SoftbusPermissionTest::TearDownTestCase(void)
{
    TransPermissionDeinit();
}

void SoftbusPermissionTest::SetUp(void)
{}

void SoftbusPermissionTest::TearDown(void)
{}

void AddPermission(const string &pkgName)
{
    std::vector<PermissionDef> permDefList;
    PermissionDef permissionDefAlpha = {
        .permissionName = SYSTEM_APP_PERMISSION,
        .bundleName = pkgName,
        .grantMode = GrantMode::SYSTEM_GRANT,
        .availableScope = AVAILABLE_SCOPE_ALL,
        .label = TEST_LABEL,
        .labelId = TEST_LABEL_ID,
        .description = TEST_DESCRIPTION,
        .descriptionId = TEST_DESCRIPTION_ID
    };
    PermissionDef permissionDefBeta = {
        .permissionName = DANGER_APP_PERMISSION,
        .bundleName = pkgName,
        .grantMode = GrantMode::SYSTEM_GRANT,
        .availableScope = AVAILABLE_SCOPE_ALL,
        .label = TEST_LABEL,
        .labelId = TEST_LABEL_ID,
        .description = TEST_DESCRIPTION,
        .descriptionId = TEST_DESCRIPTION_ID
    };
    PermissionDef permissionDefGamma = {
        .permissionName = BIND_DISCOVER_SERVICE,
        .bundleName = pkgName,
        .grantMode = GrantMode::SYSTEM_GRANT,
        .availableScope = AVAILABLE_SCOPE_ALL,
        .label = TEST_LABEL,
        .labelId = TEST_LABEL_ID,
        .description = TEST_DESCRIPTION,
        .descriptionId = TEST_DESCRIPTION_ID
    };
    permDefList.emplace_back(permissionDefAlpha);
    permDefList.emplace_back(permissionDefBeta);
    permDefList.emplace_back(permissionDefGamma);
    PermissionKit::AddDefPermissions(permDefList);
    std::vector<std::string> permList;
    permList.push_back(SYSTEM_APP_PERMISSION);
    permList.push_back(DANGER_APP_PERMISSION);
    permList.push_back(BIND_DISCOVER_SERVICE);
    PermissionKit::AddSystemGrantedReqPermissions(pkgName, permList);
    PermissionKit::GrantSystemGrantedPermission(pkgName, SYSTEM_APP_PERMISSION);
    PermissionKit::GrantSystemGrantedPermission(pkgName, DANGER_APP_PERMISSION);
    PermissionKit::GrantSystemGrantedPermission(pkgName, BIND_DISCOVER_SERVICE);
}

void RemovePermission(const string &pkgName)
{
    int ret = PermissionKit::RemoveDefPermissions(pkgName);
    ret = PermissionKit::RemoveSystemGrantedReqPermissions(pkgName);
}

static std::vector<int32_t> g_action = {
    0,
    ACTION_CREATE,
    ACTION_OPEN,
    ACTION_CREATE | ACTION_OPEN
};

/*
* @tc.name: testPermission001
* @tc.desc: test no uid permission
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftbusPermissionTest, testPermission001, TestSize.Level1)
{
    int32_t ret;
    uint32_t trueAction = ACTION_CREATE | ACTION_OPEN;
    const char *sessionName = "com.devicegroupmanage";
    const char *pkgName = "com.devicegroupmanage";
    AddPermission(std::string(pkgName));
    for (size_t i = 0; i < g_action.size(); i++) {
        ret = CheckTransPermission(sessionName, pkgName, g_action[i]);
        if (((uint32_t)(g_action[i]) & trueAction) == (uint32_t)(g_action[i]) && g_action[i] != 0) {
            EXPECT_EQ(ret, SYSTEM_APP);
        } else {
            EXPECT_EQ(ret, SOFTBUS_PERMISSION_DENIED);
        }
    }
    RemovePermission(std::string(pkgName));
}

/*
* @tc.name: testPermission002
* @tc.desc: test right uid permission
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftbusPermissionTest, testPermission002, TestSize.Level1)
{
    int32_t ret;
    uint32_t trueAction = ACTION_CREATE | ACTION_OPEN;
    const char *sessionName = "com.systemserver_CHANNEL_DPMS";
    const char *pkgName = "com.systemserver";
    AddPermission(std::string(pkgName));
    for (size_t i = 0; i < g_action.size(); i++) {
        ret = CheckTransPermission(sessionName, pkgName, g_action[i]);
        if (((uint32_t)(g_action[i]) & trueAction) == (uint32_t)(g_action[i]) && g_action[i] != 0) {
            EXPECT_EQ(ret, SYSTEM_APP);
        } else {
            EXPECT_EQ(ret, SOFTBUS_PERMISSION_DENIED);
        }
    }
    RemovePermission(std::string(pkgName));
}

/*
* @tc.name: testPermission003
* @tc.desc: test wrong uid permission
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftbusPermissionTest, testPermission003, TestSize.Level1)
{
    int32_t ret;
    const char *sessionName = "hiview_distributed_network_softbus";
    const char *pkgName = "hiview_distributed_network_softbus";
    AddPermission(std::string(pkgName));
    for (size_t i = 0; i < g_action.size(); i++) {
        ret = CheckTransPermission(sessionName, pkgName, g_action[i]);
        EXPECT_EQ(ret, SOFTBUS_PERMISSION_DENIED);
    }
    RemovePermission(std::string(pkgName));
}

/*
* @tc.name: testPermission004
* @tc.desc: test reg true match
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftbusPermissionTest, testPermission004, TestSize.Level1)
{
    int32_t ret;
    uint32_t trueAction = ACTION_CREATE | ACTION_OPEN;
    vector<const char*> sessionName = {
        "distributeddata.test1",
        "distributeddata.test123",
        "distributeddata.test",
        "distributeddata.",
    };
    const char *pkgName = "com.hwddmp";
    AddPermission(std::string(pkgName));
    for (size_t i = 0; i < g_action.size(); i++) {
        for (size_t j = 0; j < sessionName.size(); j++) {
            ret = CheckTransPermission(sessionName[j], pkgName, g_action[i]);
            if (((uint32_t)(g_action[i]) & trueAction) == (uint32_t)(g_action[i]) && g_action[i] != 0) {
                EXPECT_EQ(ret, SYSTEM_APP);
            } else {
                EXPECT_EQ(ret, SOFTBUS_PERMISSION_DENIED);
            }
        }
    }
    RemovePermission(std::string(pkgName));
}

/*
* @tc.name: testPermission005
* @tc.desc: test name dismatch
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftbusPermissionTest, testPermission005, TestSize.Level1)
{
    int32_t ret;
    int32_t trueAction = ACTION_CREATE | ACTION_OPEN;
    const char *validSessionName = "com.devicegroupmanage";
    const char *invalidSessionName = "com.wrongsessionname";
    const char *validPkgName = "com.devicegroupmanage";
    const char *invalidPkgName = "com.wrongpkgname";
    AddPermission(std::string(validPkgName));
    AddPermission(std::string(invalidPkgName));
    ret = CheckTransPermission(invalidSessionName, validPkgName, trueAction);
    EXPECT_EQ(ret, SOFTBUS_PERMISSION_DENIED);
    ret = CheckTransPermission(validSessionName, invalidPkgName, trueAction);
    EXPECT_EQ(ret, SOFTBUS_PERMISSION_DENIED);
    ret = CheckTransPermission(invalidSessionName, invalidPkgName, trueAction);
    EXPECT_EQ(ret, SOFTBUS_PERMISSION_DENIED);
    RemovePermission(std::string(validPkgName));
    RemovePermission(std::string(invalidPkgName));
}

/*
* @tc.name: testPermission006
* @tc.desc: test invalid input param
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftbusPermissionTest, testPermission006, TestSize.Level1)
{
    const char *sessionName = "com.devicegroupmanage";
    const char *pkgName = "com.devicegroupmanage";
    AddPermission(std::string(pkgName));
    EXPECT_EQ(NATIVE_APP, CheckTransPermission(NULL, NULL, 0));
    EXPECT_EQ(SYSTEM_APP, CheckTransPermission(NULL, pkgName, g_action[3]));
    EXPECT_EQ(NATIVE_APP, CheckTransPermission(sessionName, NULL, g_action[3]));
    RemovePermission(std::string(pkgName));
}

/*
* @tc.name: testPermission007
* @tc.desc: test system app -> appInfo self app
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftbusPermissionTest, testPermission007, TestSize.Level1)
{
    const char *sessionName = "SPE";
    const char *pkgName = "com.nearby";
    int32_t trueAction = ACTION_CREATE | ACTION_OPEN;
    AddPermission(std::string(pkgName));
    EXPECT_EQ(SOFTBUS_PERMISSION_DENIED, CheckTransPermission(sessionName, pkgName, trueAction));
    RemovePermission(std::string(pkgName));
}

/*
* @tc.name: testPermission008
* @tc.desc: test system app -> appInfo native app
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftbusPermissionTest, testPermission008, TestSize.Level1)
{
    const char *sessionName = "SystemAbilityManager_DDC.test";
    const char *pkgName = "test";
    int32_t trueAction = ACTION_CREATE | ACTION_OPEN;
    AddPermission(std::string(pkgName));
    EXPECT_EQ(SYSTEM_APP, CheckTransPermission(sessionName, pkgName, trueAction));
    RemovePermission(std::string(pkgName));
}

/*
* @tc.name: testPermission009
* @tc.desc: test system app -> appInfo granted app
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftbusPermissionTest, testPermission009, TestSize.Level1)
{
    const char *sessionName = "DBinder.test";
    const char *pkgName = "DBinderBus";
    int32_t trueAction = ACTION_OPEN;
    AddPermission(std::string(pkgName));
    EXPECT_EQ(GRANTED_APP, CheckTransPermission(sessionName, pkgName, trueAction));
    RemovePermission(std::string(pkgName));
}

/*
* @tc.name: testPermission010
* @tc.desc: test discovery permission
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftbusPermissionTest, testPermission010, TestSize.Level1)
{
    const char *pkgName = "com.profile";
    AddPermission(std::string(pkgName));
    EXPECT_EQ(true, CheckDiscPermission(pkgName));
    EXPECT_EQ(false, CheckDiscPermission(nullptr));
    RemovePermission(std::string(pkgName));
}
}