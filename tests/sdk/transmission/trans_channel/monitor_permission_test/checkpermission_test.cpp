/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include "session.h"
#include "softbus_errcode.h"
#include "softbus_def.h"
#include "client_trans_session_manager.h"
#include "softbus_feature_config.h"
#include "client_trans_session_service.h"
#include <string>

using namespace testing::ext;

namespace OHOS {
const char *g_pkgName = "com.huawei.plrdtest.dsoftbus";
const char *g_sessionName = "com.huawei.plrdtest.dsoftbus.test";
const char *g_networkid = "ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00";
const char *g_groupid = "TEST_GROUP_ID";
static SessionAttribute g_sessionAttr = {
    .dataType = TYPE_BYTES,
};
const int FILE_NUM = 4;
static int32_t g_sessionId = INVALID_SESSION_ID;

static int OnSessionOpened(int sessionId, int result)
{
    return SOFTBUS_OK;
}

static ISessionListener g_sessionlistener = {
    .OnSessionOpened = OnSessionOpened,
};

class CheckPermissionTest : public testing::Test {
public:
    CheckPermissionTest()
    {}
    ~CheckPermissionTest()
    {}
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp()
    {}
    void TearDown()
    {}
};

void CheckPermissionTest::SetUpTestCase()
{
    (void)TransClientInit();
    SoftbusConfigInit();
    int ret = ClientAddSessionServer(SEC_TYPE_CIPHERTEXT, g_pkgName, g_sessionName, &g_sessionlistener);
    EXPECT_EQ(SOFTBUS_OK, ret);

    SessionParam param = {
        .sessionName = g_sessionName,
        .peerSessionName = g_sessionName,
        .peerDeviceId = g_networkid,
        .groupId = g_groupid,
        .attr = &g_sessionAttr,
    };
    bool isEnabled = false;
    ret = ClientAddSession(&param, &g_sessionId, &isEnabled);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

void CheckPermissionTest::TearDownTestCase()
{
}


/**
 * @tc.name: CheckPermissionTest001
 * @tc.desc: CheckpermissionAPI.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CheckPermissionTest, CheckPermissionTest001, TestSize.Level0)
{
    const char *data = "testdata";
    uint32_t len = strlen(data);

    int ret = SendBytes(g_sessionId, data, len);
    EXPECT_NE(SOFTBUS_OK, ret);

    ret = SendBytes(INVALID_SESSION_ID, data, len);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**
 * @tc.name: CheckPermissionTest002
 * @tc.desc: CheckpermissionAPI.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CheckPermissionTest, CheckPermissionTest002, TestSize.Level0)
{
    const char *data = "testdata";
    uint32_t len = strlen(data);

    int ret = SendMessage(g_sessionId, data, len);
    EXPECT_NE(SOFTBUS_OK, ret);

    ret = SendMessage(INVALID_SESSION_ID, data, len);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**
 * @tc.name: CheckPermissionTest003
 * @tc.desc: CheckpermissionAPI.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CheckPermissionTest, CheckPermissionTest003, TestSize.Level0)
{
    const StreamData streamData = {0};
    const StreamData ext = {0};
    const StreamFrameInfo param = {0};

    int ret = SendStream(g_sessionId, &streamData, &ext, &param);
    EXPECT_NE(SOFTBUS_OK, ret);

    ret = SendStream(INVALID_SESSION_ID, &streamData, &ext, &param);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**
 * @tc.name: CheckPermissionTest004
 * @tc.desc: CheckpermissionAPI.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CheckPermissionTest, CheckPermissionTest004, TestSize.Level0)
{
    const char *sfileList[] = {
        "/data/big.tar",
        "/data/richu.jpg",
        "/data/richu-002.jpg",
        "/data/richu-003.jpg",
    };
    int ret = SendFile(g_sessionId, sfileList, nullptr, FILE_NUM);
    EXPECT_NE(SOFTBUS_OK, ret);

    ret = SendFile(INVALID_SESSION_ID, sfileList, nullptr, FILE_NUM);
    EXPECT_NE(SOFTBUS_OK, ret);
}
} // namespace OHOS