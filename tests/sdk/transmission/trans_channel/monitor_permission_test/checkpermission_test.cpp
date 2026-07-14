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
#include <string>

#include "client_trans_session_manager.h"
#include "client_trans_session_service.h"
#include "client_trans_socket_manager.h"
#include "session.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_feature_config.h"

using namespace testing::ext;

namespace OHOS {
const char *g_pkgName = "com.plrdtest.dsoftbus";
const char *g_sessionName = "com.plrdtest.dsoftbus.test";
const char *g_networkid = "ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00";
const char *g_groupid = "TEST_GROUP_ID";
static SessionAttribute g_sessionAttr = {
    .dataType = TYPE_BYTES,
};
const int32_t FILE_NUM = 4;
static int32_t g_sessionId = INVALID_SESSION_ID;

static int32_t OnSessionOpened(int32_t sessionId, int32_t result)
{
    return SOFTBUS_OK;
}

static ISessionListener g_sessionlistener = {
    .OnSessionOpened = OnSessionOpened,
};

class CheckPermissionTest : public testing::Test {
public:
    CheckPermissionTest() { }
    ~CheckPermissionTest() { }
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) { }
    void TearDown(void) { }
};

void CheckPermissionTest::SetUpTestCase(void)
{
    (void)TransClientInit();
    SoftbusConfigInit();
    uint64_t timestamp = 0;
    int32_t ret = ClientAddSessionServer(SEC_TYPE_CIPHERTEXT, g_pkgName, g_sessionName, &g_sessionlistener, &timestamp);
    EXPECT_EQ(SOFTBUS_OK, ret);

    SessionParam param = {
        .sessionName = g_sessionName,
        .peerSessionName = g_sessionName,
        .peerDeviceId = g_networkid,
        .groupId = g_groupid,
        .attr = &g_sessionAttr,
    };
    SessionEnableStatus isEnabled = ENABLE_STATUS_INIT;
    ret = ClientAddSession(&param, &g_sessionId, &isEnabled);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

void CheckPermissionTest::TearDownTestCase(void) { }

/**
 * @tc.name: SendBytesPermissionTest001
 * @tc.desc: SendBytes permission check with valid session id
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CheckPermissionTest, SendBytesPermissionTest001, TestSize.Level0)
{
    const char *data = "testdata";
    uint32_t len = strlen(data);

    int32_t ret = SendBytes(g_sessionId, data, len);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**
 * @tc.name: SendBytesPermissionTest002
 * @tc.desc: SendBytes permission check with invalid session id
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CheckPermissionTest, SendBytesPermissionTest002, TestSize.Level0)
{
    const char *data = "testdata";
    uint32_t len = strlen(data);

    int32_t ret = SendBytes(INVALID_SESSION_ID, data, len);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**
 * @tc.name: SendMessagePermissionTest001
 * @tc.desc: SendMessage permission check with valid session id
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CheckPermissionTest, SendMessagePermissionTest001, TestSize.Level0)
{
    const char *data = "testdata";
    uint32_t len = strlen(data);

    int32_t ret = SendMessage(g_sessionId, data, len);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**
 * @tc.name: SendMessagePermissionTest002
 * @tc.desc: SendMessage permission check with invalid session id
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CheckPermissionTest, SendMessagePermissionTest002, TestSize.Level0)
{
    const char *data = "testdata";
    uint32_t len = strlen(data);

    int32_t ret = SendMessage(INVALID_SESSION_ID, data, len);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**
 * @tc.name: SendStreamPermissionTest001
 * @tc.desc: SendStream permission check with valid session id
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CheckPermissionTest, SendStreamPermissionTest001, TestSize.Level0)
{
    const StreamData streamData = { 0 };
    const StreamData ext = { 0 };
    const StreamFrameInfo param = { 0 };

    int32_t ret = SendStream(g_sessionId, &streamData, &ext, &param);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**
 * @tc.name: SendStreamPermissionTest002
 * @tc.desc: SendStream permission check with invalid session id
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CheckPermissionTest, SendStreamPermissionTest002, TestSize.Level0)
{
    const StreamData streamData = { 0 };
    const StreamData ext = { 0 };
    const StreamFrameInfo param = { 0 };

    int32_t ret = SendStream(INVALID_SESSION_ID, &streamData, &ext, &param);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**
 * @tc.name: SendFilePermissionTest001
 * @tc.desc: SendFile permission check with valid session id
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CheckPermissionTest, SendFilePermissionTest001, TestSize.Level0)
{
    const char *sfileList[] = {
        "/data/big.tar",
        "/data/richu.jpg",
        "/data/richu-002.jpg",
        "/data/richu-003.jpg",
    };
    int32_t ret = SendFile(g_sessionId, sfileList, nullptr, FILE_NUM);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/**
 * @tc.name: SendFilePermissionTest002
 * @tc.desc: SendFile permission check with invalid session id
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CheckPermissionTest, SendFilePermissionTest002, TestSize.Level0)
{
    const char *sfileList[] = {
        "/data/big.tar",
        "/data/richu.jpg",
        "/data/richu-002.jpg",
        "/data/richu-003.jpg",
    };
    int32_t ret = SendFile(INVALID_SESSION_ID, sfileList, nullptr, FILE_NUM);
    EXPECT_NE(SOFTBUS_OK, ret);
}
} // namespace OHOS
