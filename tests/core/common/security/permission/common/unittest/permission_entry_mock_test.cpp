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

#include "comm_log.h"
#include "permission_entry.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"

using namespace testing::ext;

namespace {
constexpr int32_t TEST_UID = 4321;

struct PermissionParam {
    int32_t permType;
    int32_t uid;
    int32_t pid;
    const char *pkgName;
    uint32_t actions;
    const char *sessionName;
};

static int32_t TestCheckPermissionEntry(const PermissionParam &param)
{
    SoftBusPermissionItem *permItem =
        CreatePermissionItem(param.permType, param.uid, param.pid, param.pkgName, param.actions);
    COMM_CHECK_AND_RETURN_RET_LOGE(permItem != nullptr, SOFTBUS_MALLOC_ERR, COMM_TEST, "create perm item failed");

    int32_t ret = CheckPermissionEntry(param.sessionName, permItem, false);
    SoftBusFree(permItem);
    return ret;
}
} // anonymous namespace

extern "C" {
int32_t SoftBusReadFullFile(const char *fileName, char *readBuf, uint32_t maxLen)
{
    errno_t ret = memset_s(readBuf, maxLen, 0, maxLen);
    COMM_CHECK_AND_RETURN_RET_LOGE(ret == EOK, SOFTBUS_MEM_ERR, COMM_TEST, "memset failed");

    ret = strcpy_s(readBuf, maxLen, fileName);
    COMM_CHECK_AND_RETURN_RET_LOGE(ret == EOK, SOFTBUS_STRCPY_ERR, COMM_TEST, "strcpy failed");
    return SOFTBUS_OK;
}
} // extern "C"

namespace OHOS {
class PermissionEntryMockTest : public testing::Test {
public:
    PermissionEntryMockTest() { }

    ~PermissionEntryMockTest() { }

    static void SetUpTestCase(void) { }

    static void TearDownTestCase(void) { }

    void SetUp() override { }

    void TearDown() override { }
};

/*
 * @tc.name: TestCheckPermissionEntry001
 * @tc.desc: Verify TestCheckPermissionEntry returns NATIVE_APP for valid permission TestCheckPermissionEntry test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionEntryMockTest, TestCheckPermissionEntry001, TestSize.Level0)
{
    const char *permConfig = R"([{
        "SESSION_NAME": "DistributedFileService.*",
        "REGEXP": "true",
        "DEVID": "UUID",
        "APP_INFO": [{
            "TYPE": "native_app",
            "UID": "1009",
            "ACTIONS": "create"
        }]
    }])";
    int32_t ret = LoadPermissionJson(permConfig);
    EXPECT_EQ(ret, SOFTBUS_OK);

    PermissionParam validParam = {
        .permType = NATIVE_APP,
        .uid = 1009,
        .pid = 1,
        .pkgName = "111",
        .actions = ACTION_CREATE,
        .sessionName = "DistributedFileService.111",
    };
    ret = TestCheckPermissionEntry(validParam);
    EXPECT_EQ(ret, NATIVE_APP);

    PermissionParam validParam2 = validParam;
    validParam2.permType = SYSTEM_APP;
    ret = TestCheckPermissionEntry(validParam);
    EXPECT_EQ(ret, NATIVE_APP);

    PermissionParam invalidUid = validParam;
    invalidUid.uid = 1;
    ret = TestCheckPermissionEntry(invalidUid);
    EXPECT_EQ(ret, SOFTBUS_PERMISSION_DENIED);

    PermissionParam invalidActions = validParam;
    invalidActions.actions = ACTION_OPEN;
    ret = TestCheckPermissionEntry(invalidActions);
    EXPECT_EQ(ret, SOFTBUS_PERMISSION_DENIED);

    PermissionParam invalidSessionName = validParam;
    invalidSessionName.sessionName = "DistributedFileServicf";
    ret = TestCheckPermissionEntry(invalidSessionName);
    EXPECT_EQ(ret, SOFTBUS_PERMISSION_DENIED);

    DeinitPermissionJson();
}

/*
 * @tc.name: TestCheckPermissionEntry002
 * @tc.desc: Verify TestCheckPermissionEntry returns SYSTEM_APP for valid permission TestCheckPermissionEntry test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionEntryMockTest, TestCheckPermissionEntry002, TestSize.Level0)
{
    const char *permConfig = R"([{
        "SESSION_NAME": "distributeddata-default*",
        "REGEXP": "true",
        "DEVID": "UUID",
        "SEC_LEVEL": "public",
        "APP_INFO": [{
            "TYPE": "system_app",
            "PKG_NAME": "ohos.distributeddata",
            "ACTIONS": "open"
        }]
    }])";
    int32_t ret = LoadPermissionJson(permConfig);
    EXPECT_EQ(ret, SOFTBUS_OK);

    PermissionParam validParam = {
        .permType = SYSTEM_APP,
        .uid = 1,
        .pid = 1,
        .pkgName = "ohos.distributeddata",
        .actions = ACTION_OPEN,
        .sessionName = "distributeddata-default111",
    };
    ret = TestCheckPermissionEntry(validParam);
    EXPECT_EQ(ret, SYSTEM_APP);

    PermissionParam validParam2 = validParam;
    validParam2.permType = NATIVE_APP;
    ret = TestCheckPermissionEntry(validParam);
    EXPECT_EQ(ret, SYSTEM_APP);

    PermissionParam invalidPkgName = validParam;
    invalidPkgName.pkgName = "111";
    ret = TestCheckPermissionEntry(invalidPkgName);
    EXPECT_EQ(ret, SOFTBUS_PERMISSION_DENIED);

    PermissionParam invalidActions = validParam;
    invalidActions.actions = ACTION_CREATE;
    ret = TestCheckPermissionEntry(invalidActions);
    EXPECT_EQ(ret, SOFTBUS_PERMISSION_DENIED);

    PermissionParam invalidSessionName = validParam;
    invalidSessionName.sessionName = "DistributedFileService.111";
    ret = TestCheckPermissionEntry(invalidSessionName);
    EXPECT_EQ(ret, SOFTBUS_PERMISSION_DENIED);

    DeinitPermissionJson();
}

/*
 * @tc.name: LoadRpcPermissionJson001
 * @tc.desc: Verify LoadRpcPermissionJson returns SOFTBUS_INVALID_PARAM for
 *           nullptr json LoadRpcPermissionJson test invalid param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionEntryMockTest, LoadRpcPermissionJson001, TestSize.Level0)
{
    DeinitRpcSaPermissionJson();
    int32_t ret = SOFTBUS_OK;
    ret = LoadRpcPermissionJson(nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    DeinitRpcSaPermissionJson();
}

/*
 * @tc.name: LoadRpcPermissionJson002
 * @tc.desc: Verify LoadRpcPermissionJson returns SOFTBUS_OK for valid json LoadRpcPermissionJson test valid param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionEntryMockTest, LoadRpcPermissionJson002, TestSize.Level0)
{
    const char *permConfig = R"([{
        "PROCESS_NAME": "testProcessName",
        "SA_ID": "1234",
        "SA_UID": "4321"
    }])";
    int32_t ret = LoadRpcPermissionJson(permConfig);
    EXPECT_EQ(ret, SOFTBUS_OK);
    DeinitRpcSaPermissionJson();
}

/*
 * @tc.name: LoadRpcPermissionJson003
 * @tc.desc: Verify LoadRpcPermissionJson returns SOFTBUS_PARSE_JSON_ERR for invalid SA_UID
 *           LoadRpcPermissionJson test invalid SA_UID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionEntryMockTest, LoadRpcPermissionJson003, TestSize.Level0)
{
    const char *permConfig = R"([{
        "PROCESS_NAME": "testProcessName",
        "SA_ID": "1234",
    }])";
    int32_t ret = LoadRpcPermissionJson(permConfig);
    EXPECT_EQ(ret, SOFTBUS_PARSE_JSON_ERR);
    DeinitRpcSaPermissionJson();
}

/*
 * @tc.name: LoadRpcPermissionJson004
 * @tc.desc: Verify LoadRpcPermissionJson returns SOFTBUS_PARSE_JSON_ERR for invalid format
 *           LoadRpcPermissionJson test invalid format
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionEntryMockTest, LoadRpcPermissionJson004, TestSize.Level0)
{
    const char *permConfig = R"([{
        "PROCESS_NAME": "testProcessName",
        "SA_ID": "1234",
    )";
    int32_t ret = LoadRpcPermissionJson(permConfig);
    EXPECT_EQ(ret, SOFTBUS_PARSE_JSON_ERR);
    DeinitRpcSaPermissionJson();
}

/*
 * @tc.name: CheckRpcPermissionEntryTest001
 * @tc.desc: Verify CheckRpcPermissionEntry returns SOFTBUS_INVALID_PARAM for invalid param
 *           CheckRpcPermissionEntry test invalid param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionEntryMockTest, CheckRpcPermissionEntryTest001, TestSize.Level1)
{
    int32_t ret = CheckRpcPermissionEntry(0, nullptr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    char testSessionName[] = "testSessionName";
    ret = CheckRpcPermissionEntry(0, testSessionName, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: CheckRpcPermissionEntryTest002
 * @tc.desc: Verify CheckRpcPermissionEntry returns SOFTBUS_OK for valid param
 *           CheckRpcPermissionEntry test valid param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionEntryMockTest, CheckRpcPermissionEntryTest002, TestSize.Level1)
{
    const char *permConfig = R"([{
        "PROCESS_NAME": "testProcessName",
        "SA_ID": "1234",
        "SA_UID": "4321"
    }])";
    int32_t ret = LoadRpcPermissionJson(permConfig);
    EXPECT_EQ(ret, SOFTBUS_OK);

    char testSessionName[] = "testSessionName";
    char testProcessName[] = "testProcessName";
    ret = CheckRpcPermissionEntry(TEST_UID, testSessionName, testProcessName);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = CheckRpcPermissionEntry(0, testSessionName, testProcessName);
    EXPECT_EQ(ret, SOFTBUS_PERMISSION_DENIED);

    ret = CheckRpcPermissionEntry(TEST_UID, testProcessName, testSessionName);
    EXPECT_EQ(ret, SOFTBUS_PERMISSION_DENIED);
    DeinitRpcSaPermissionJson();
}
} // namespace OHOS
