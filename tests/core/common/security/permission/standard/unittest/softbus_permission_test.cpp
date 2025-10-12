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

#include "ipc_skeleton.h"
#include "permission_entry.h"
#include "permission_utils.h"
#include "session.h"
#include "session_ipc_adapter.h"
#include "softbus_access_token_adapter.cpp"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_permission.h"
#include "trans_client_proxy.h"

using namespace std;
using namespace testing::ext;
class SoftBusAccessTokenAdapter;

#define INVALID_TEST_PID 1066

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

/*
 * @tc.name: IsValidPkgNameTest001
 * @tc.desc: is valid pkgname test, use the wrong or normal parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusPermissionTest, IsValidPkgNameTest001, TestSize.Level0)
{
    int32_t ret;

    ret = IsValidPkgName(0, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = IsValidPkgName(0, g_pkgName);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: CheckTransPermissionTest001
 * @tc.desc: check trans permission test, use the wrong parameter
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

/*
 * @tc.name: CheckTransSecLevelTest001
 * @tc.desc: check trans sec level test, use the wrong or normal parameter
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

/*
 * @tc.name: CheckDiscPermissionTest001
 * @tc.desc: check disc permission test, use the wrong or normal parameter
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

/*
 * @tc.name: GrantTransPermissionTest001
 * @tc.desc: grant trans permission test, use the wrong parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusPermissionTest, GrantTransPermissionTest001, TestSize.Level0)
{
    int32_t ret;
    InitDynamicPermission();
    ret = GrantTransPermission(0, 0, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: RemoveTransPermissionTest001
 * @tc.desc: remove trans permission test, use the wrong parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusPermissionTest, RemoveTransPermissionTest001, TestSize.Level0)
{
    int32_t ret;

    ret = RemoveTransPermission(g_sessionName);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
}

/*
 * @tc.name: CheckDynamicPermissionTest001
 * @tc.desc: check dynamic permission test, use the wrong parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusPermissionTest, CheckDynamicPermissionTest001, TestSize.Level0)
{
    int32_t invalidTokenId = -1;
    int32_t ret = SoftBusCheckDynamicPermission(invalidTokenId);
    EXPECT_EQ(SOFTBUS_PERMISSION_DENIED, ret);
}

/*
 * @tc.name:CheckDmsServerPermissionTest001
 * @tc.desc: check dms server permission test, use the wrong parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusPermissionTest, CheckDmsServerPermissionTest001, TestSize.Level0)
{
    uint64_t invalidTokenId = 0;
    int32_t ret = SoftBusCheckDmsServerPermission(invalidTokenId);
    EXPECT_EQ(SOFTBUS_PERMISSION_DENIED, ret);
}

/*
 * @tc.name:SoftBusCheckIsSystemService001
 * @tc.desc: SoftBusCheckIsSystemService test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusPermissionTest, SoftBusCheckIsSystemService001, TestSize.Level0)
{
    uint32_t tokenCaller;
    int32_t ret = SoftBusGetCallingTokenId(&tokenCaller);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = SoftBusCheckDmsServerPermission(tokenCaller);
    EXPECT_TRUE(ret);
}

/*
 * @tc.name:SoftBusCheckIsNormalApp001
 * @tc.desc: SoftBusCheckIsNormalApp test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusPermissionTest, SoftBusCheckIsNormalApp001, TestSize.Level0)
{
    char *sessionName = nullptr;
    uint64_t fullTokenId = 0;
    int32_t ret = SoftBusCheckIsNormalApp(fullTokenId, sessionName);
    EXPECT_FALSE(ret);
}

/*
 * @tc.name:SoftBusCheckIsNormalApp002
 * @tc.desc: SoftBusCheckIsNormalApp test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusPermissionTest, SoftBusCheckIsNormalApp002, TestSize.Level0)
{
    const char *sessionName = "DBinder";
    uint64_t fullTokenId = 0;
    int32_t ret = SoftBusCheckIsNormalApp(fullTokenId, sessionName);
    EXPECT_FALSE(ret);
}

/*
 * @tc.name:SoftBusCheckIsNormalApp003
 * @tc.desc: SoftBusCheckIsNormalApp test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusPermissionTest, SoftBusCheckIsNormalApp003, TestSize.Level0)
{
    const char *sessionName = "ohos.dtbcollab.dms";
    uint64_t fullTokenId = 0;
    int32_t ret = SoftBusCheckIsNormalApp(fullTokenId, sessionName);
    EXPECT_FALSE(ret);
}

/*
 * @tc.name:SoftBusCheckIsNormalApp004
 * @tc.desc: SoftBusCheckIsNormalApp test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusPermissionTest, SoftBusCheckIsNormalApp004, TestSize.Level0)
{
    uint32_t fullTokenId;
    const char *sessionName = "com.aijowiaow.cn";
    int32_t ret = SoftBusGetCallingTokenId(&fullTokenId);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = SoftBusCheckIsNormalApp(fullTokenId, sessionName);
    EXPECT_FALSE(ret);
}

/*
 * @tc.name:SoftBusCheckIsAccessAndRecordAccessToken001
 * @tc.desc: SoftBusCheckIsAccessAndRecordAccessToken test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusPermissionTest, SoftBusCheckIsAccessAndRecordAccessToken001, TestSize.Level0)
{
    uint64_t tokenId = 0;
    const char *permission = nullptr;
    int32_t ret = SoftBusCheckIsAccessAndRecordAccessToken(tokenId, permission);
    EXPECT_FALSE(ret);
}

/*
 * @tc.name:SoftBusCalcPermType001
 * @tc.desc: SoftBusCalcPermType test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusPermissionTest, SoftBusCalcPermType001, TestSize.Level0)
{
    uint64_t fullTokenId = 0;
    pid_t callingUid = OHOS::IPCSkeleton::GetCallingUid();
    pid_t callingPid = OHOS::IPCSkeleton::GetCallingPid();

    int32_t ret = SoftBusCalcPermType(fullTokenId, callingUid, callingPid);
    EXPECT_EQ(ret, SELF_APP);
}

/*
 * @tc.name:SoftBusCalcPermType002
 * @tc.desc: SoftBusCalcPermType test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusPermissionTest, SoftBusCalcPermType002, TestSize.Level0)
{
    uint64_t fullTokenId = 1;
    pid_t callingUid = 1024;
    pid_t callingPid = OHOS::IPCSkeleton::GetCallingPid();

    int32_t ret = SoftBusCalcPermType(fullTokenId, callingUid, callingPid);
    EXPECT_EQ(ret, ATokenTypeEnum::TOKEN_TYPE_BUTT);
}

/*
 * @tc.name:PermStateChangeCallback001
 * @tc.desc: PermStateChangeCallback test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusPermissionTest, PermStateChangeCallback001, TestSize.Level0)
{
    PermStateChangeInfo result;
    result.permissionName = "noTestPermission";
    PermissionChangeCb permissionChanCb = nullptr;
    EXPECT_NO_FATAL_FAILURE(SoftBusRegisterPermissionChangeCb(permissionChanCb));

    std::string pkgaName = "check.AccessToken";
    PermStateChangeScope permStateObj;
    OHOS::SoftBusAccessTokenAdapter accessTokenAdapterObj(permStateObj, pkgaName, INVALID_TEST_PID);
    EXPECT_NO_FATAL_FAILURE(accessTokenAdapterObj.PermStateChangeCallback(result));
    std::cout << "g_permissionChangeCb is empty." << std::endl;
}

/*
 * @tc.name:PermStateChangeCallback002
 * @tc.desc: PermStateChangeCallback test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusPermissionTest, PermStateChangeCallback002, TestSize.Level0)
{
    PermStateChangeInfo result;
    result.permissionName = "noTestPermission";
    result.permStateChangeType = STATE_CHANGE_GRANTED;
    PermissionChangeCb permissionChanCb = InformPermissionChange;
    EXPECT_NO_FATAL_FAILURE(SoftBusRegisterPermissionChangeCb(permissionChanCb));

    std::string pkgaName = "check.AccessToken";
    PermStateChangeScope permStateObj;
    OHOS::SoftBusAccessTokenAdapter accessTokenAdapterObj(permStateObj, pkgaName, INVALID_TEST_PID);
    EXPECT_NO_FATAL_FAILURE(accessTokenAdapterObj.PermStateChangeCallback(result));
    std::cout << "g_permissionChangeCb is not empty." << std::endl;
}

/*
 * @tc.name:SoftBusRegisterDataSyncPermission001
 * @tc.desc: SoftBusRegisterDataSyncPermission test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusPermissionTest, SoftBusRegisterDataSyncPermission001, TestSize.Level0)
{
    uint64_t tonkenId = 0;
    EXPECT_NO_FATAL_FAILURE(SoftBusRegisterDataSyncPermission(tonkenId, nullptr, nullptr, INVALID_TEST_PID));
}

/*
 * @tc.name:SoftBusUnRegisterDataSyncPermission001
 * @tc.desc: SoftBusUnRegisterDataSyncPermission test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusPermissionTest, SoftBusUnRegisterDataSyncPermission001, TestSize.Level0)
{
    EXPECT_NO_FATAL_FAILURE(SoftBusUnRegisterDataSyncPermission(INVALID_TEST_PID));
}

/*
 * @tc.name:SoftBusGetTokenNameByTokenType001
 * @tc.desc: SoftBusGetTokenNameByTokenType test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusPermissionTest, SoftBusGetTokenNameByTokenType001, TestSize.Level0)
{
    int32_t nameLen = 1;
    EXPECT_NO_FATAL_FAILURE(SoftBusGetTokenNameByTokenType(nullptr, nameLen, TOKEN_HAP, ACEESS_TOKEN_TYPE_INVALID));
}

/*
 * @tc.name:SoftBusGetTokenNameByTokenType002
 * @tc.desc: SoftBusGetTokenNameByTokenType test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusPermissionTest, SoftBusGetTokenNameByTokenType002, TestSize.Level0)
{
    char tokenName[32] = "softbus_token_test_name";
    int32_t nameLen = strlen(tokenName);
    EXPECT_EQ(nameLen, 23);
    EXPECT_NO_FATAL_FAILURE(
        SoftBusGetTokenNameByTokenType(tokenName, nameLen, TOKEN_NATIVE, ACEESS_TOKEN_TYPE_INVALID));
}

/*
 * @tc.name:SoftBusGetTokenNameByTokenType003
 * @tc.desc: SoftBusGetTokenNameByTokenType test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusPermissionTest, SoftBusGetTokenNameByTokenType003, TestSize.Level0)
{
    char tokenName[32] = "softbus_token_test_name";
    int32_t nameLen = strlen(tokenName);
    EXPECT_EQ(nameLen, 23);
    EXPECT_NO_FATAL_FAILURE(
        SoftBusGetTokenNameByTokenType(tokenName, nameLen, TOKEN_SHELL, ACEESS_TOKEN_TYPE_INVALID));
}

/*
 * @tc.name:SoftBusCheckIsCollabApp001
 * @tc.desc: SoftBusCheckIsCollabApp test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusPermissionTest, SoftBusCheckIsCollabApp001, TestSize.Level0)
{
    uint64_t fullTokenId = 66;
    bool ret = SoftBusCheckIsCollabApp(fullTokenId, nullptr);
    EXPECT_FALSE(ret);
}

/*
 * @tc.name:SoftBusCheckIsCollabApp002
 * @tc.desc: SoftBusCheckIsCollabApp test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusPermissionTest, SoftBusCheckIsCollabApp002, TestSize.Level0)
{
    uint32_t fullTokenId;
    const char *sessionName = "com.woaiwojia.cn";
    int32_t ret = SoftBusGetCallingTokenId(&fullTokenId);
    EXPECT_EQ(ret, SOFTBUS_OK);

    bool result = SoftBusCheckIsCollabApp(fullTokenId, sessionName);
    EXPECT_FALSE(result);
}

/*
 * @tc.name:SoftBusCheckIsCollabApp003
 * @tc.desc: SoftBusCheckIsCollabApp test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusPermissionTest, SoftBusCheckIsCollabApp003, TestSize.Level0)
{
    uint32_t fullTokenId;
    const char *sessionName = "ohos.dtbcollab.dms";
    int32_t ret = SoftBusGetCallingTokenId(&fullTokenId);
    EXPECT_EQ(ret, SOFTBUS_OK);

    bool result = SoftBusCheckIsCollabApp(fullTokenId, sessionName);
    EXPECT_FALSE(result);
}

/*
 * @tc.name:CheckLnnPermissionTest001
 * @tc.desc: CheckLnnPermission param error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusPermissionTest, CheckLnnPermissionTest001, TestSize.Level1)
{
    const char interfaceName[] = "SERVER_GET_NODE_KEY_INFO";
    const char processName[] = "device_manager";
    int32_t ret = CheckLnnPermission(nullptr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = CheckLnnPermission(interfaceName, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = CheckLnnPermission(nullptr, processName);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = CheckLnnPermission(interfaceName, processName);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    LnnDeinitPermission();
}

/*
 * @tc.name:LnnInitPermissionTest001
 * @tc.desc: LnnInitPermission func test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusPermissionTest, LnnInitPermissionTest001, TestSize.Level1)
{
    int32_t ret = LnnInitPermission();
    EXPECT_EQ(ret, SOFTBUS_OK);
}
} // namespace OHOS