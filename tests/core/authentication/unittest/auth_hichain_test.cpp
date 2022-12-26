/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <cinttypes>
#include <gtest/gtest.h>
#include <securec.h>
#include <sys/time.h>

#include "auth_hichain.h"
#include "auth_hichain.c"
#include "softbus_app_info.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_socket.h"

namespace OHOS {
using namespace testing;
using namespace testing::ext;

class AuthHichainTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void AuthHichainTest::SetUpTestCase()
{
}

void AuthHichainTest::TearDownTestCase() {}

void AuthHichainTest::SetUp()
{
    LOG_INFO("AuthHichainTest start.");
}

void AuthHichainTest::TearDown() {}

void OnDeviceNotTrustedTest(const char *peerUdid)
{
    (void)peerUdid;
}

void OnGroupCreatedTest(const char *groupId, int32_t groupType)
{
    (void)groupId;
    (void)groupType;
}

void OnGroupDeletedTest(const char *groupId)
{
    (void)groupId;
}
/*
 * @tc.name: ON_DEVICE_NOT_TRUSTED_TEST_001
 * @tc.desc: on device not trusted test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthHichainTest, ON_DEVICE_NOT_TRUSTED_TEST_001, TestSize.Level1)
{
    const char *groupInfo = "testdata";
    const char *groupInfoStr = "{\"groupId\":\"1111\", \"groupType\":1}";
    const char *udid = "000";
    GroupInfo info;

    OnGroupCreated(nullptr);
    OnGroupCreated(groupInfo);
    g_dataChangeListener.onGroupCreated = nullptr;
    OnGroupCreated(groupInfoStr);
    g_dataChangeListener.onGroupCreated = OnGroupCreatedTest;
    OnGroupCreated(groupInfoStr);

    OnGroupDeleted(nullptr);
    OnGroupDeleted(groupInfo);
    g_dataChangeListener.onGroupDeleted = nullptr;
    OnGroupDeleted(groupInfoStr);
    g_dataChangeListener.onGroupDeleted = OnGroupDeletedTest;
    OnGroupDeleted(groupInfoStr);

    OnDeviceNotTrusted(nullptr);
    g_dataChangeListener.onDeviceNotTrusted = nullptr;
    OnDeviceNotTrusted(udid);
    g_dataChangeListener.onDeviceNotTrusted = OnDeviceNotTrustedTest;
    OnDeviceNotTrusted(udid);

    (void)memset_s(&info, sizeof(GroupInfo), 0, sizeof(GroupInfo));
    int32_t ret = ParseGroupInfo(nullptr, &info);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    ret = ParseGroupInfo(groupInfoStr, &info);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: ON_REQUEST_TEST_001
 * @tc.desc: on request test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthHichainTest, ON_REQUEST_TEST_001, TestSize.Level1)
{
    int64_t authSeq = 0;
    int operationCode = 0;
    const char *reqParams = "testdata";

    char *msgStr = OnRequest(authSeq, operationCode, reqParams);
    EXPECT_TRUE(msgStr == nullptr);
}
} // namespace OHOS
