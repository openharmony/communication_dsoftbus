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

#include <securec.h>

#include "gtest/gtest.h"
#include "message_handler.h"
#include "softbus_errcode.h"
#include "softbus_feature_config.h"
#include "trans_auth_negotiation.c"
#include "trans_auth_negotiation.h"
#include "trans_session_service.h"

using namespace testing::ext;
namespace OHOS {
#define TRANS_TEST_INVALID_AUTH_REQUEST_ID (0)
#define TRANS_TEST_AUTH_REQUEST_ID (1)

class TransAuthNegotiateTest : public testing::Test {
public:
    TransAuthNegotiateTest()
    {}
    ~TransAuthNegotiateTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void TransAuthNegotiateTest::SetUpTestCase(void)
{
    SoftbusConfigInit();
    (void)LooperInit();
    (void)ConnServerInit();
    (void)TransProxyTransInit();
    (void)TransServerInit();
    (void)TransReqAuthPendingInit();
}

void TransAuthNegotiateTest::TearDownTestCase(void)
{
    LooperDeinit();
    ConnServerDeinit();
    TransServerDeinit();
    TransReqAuthPendingDeinit();
}

/**
 * @tc.name: TransAuthPendingTest001
 * @tc.desc: Use the wrong parameter and legal parameter to test TransAddAuthReqToPendingList.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthNegotiateTest, TransAuthPendingTest001, TestSize.Level1)
{
    int32_t ret = TransAddAuthReqToPendingList(TRANS_TEST_INVALID_AUTH_REQUEST_ID);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransAddAuthReqToPendingList(TRANS_TEST_AUTH_REQUEST_ID);
    EXPECT_EQ(SOFTBUS_OK, ret);
    TransDelAuthReqFromPendingList(TRANS_TEST_AUTH_REQUEST_ID);
}

/**
 * @tc.name: TransAuthPendingTest002
 * @tc.desc: Use the wrong parameter and legal parameter to test TransUpdateAuthInfo.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthNegotiateTest, TransAuthPendingTest002, TestSize.Level1)
{
    int32_t errCode = SOFTBUS_INVALID_PARAM;
    int32_t ret = TransUpdateAuthInfo(TRANS_TEST_INVALID_AUTH_REQUEST_ID, errCode);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransUpdateAuthInfo(TRANS_TEST_AUTH_REQUEST_ID, errCode);
    EXPECT_EQ(SOFTBUS_TRANS_AUTH_REQUEST_NOT_FOUND, ret);

    ret = TransAddAuthReqToPendingList(TRANS_TEST_AUTH_REQUEST_ID);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransUpdateAuthInfo(TRANS_TEST_AUTH_REQUEST_ID, errCode);
    EXPECT_EQ(SOFTBUS_OK, ret);
    TransDelAuthReqFromPendingList(TRANS_TEST_AUTH_REQUEST_ID);
}

/**
 * @tc.name: TransAuthPendingTest003
 * @tc.desc: Use the wrong parameter and legal parameter to test TransCheckAuthNegoStatusByReqId.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthNegotiateTest, TransAuthPendingTest003, TestSize.Level1)
{
    bool isFinished = false;
    int32_t errCode = SOFTBUS_INVALID_PARAM;
    int32_t cnt = 0;
    int32_t ret = TransCheckAuthNegoStatusByReqId(TRANS_TEST_AUTH_REQUEST_ID, &isFinished, &errCode, &cnt);
    EXPECT_EQ(SOFTBUS_TRANS_AUTH_REQUEST_NOT_FOUND, ret);

    errCode = SOFTBUS_OK;
    ret = TransAddAuthReqToPendingList(TRANS_TEST_AUTH_REQUEST_ID);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransUpdateAuthInfo(TRANS_TEST_AUTH_REQUEST_ID, errCode);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransCheckAuthNegoStatusByReqId(TRANS_TEST_AUTH_REQUEST_ID, &isFinished, &errCode, &cnt);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_EQ(true, isFinished);
    EXPECT_EQ(SOFTBUS_OK, errCode);
    EXPECT_EQ(1, cnt);
    TransDelAuthReqFromPendingList(TRANS_TEST_AUTH_REQUEST_ID);
}

/**
 * @tc.name: TransAuthPendingTest004
 * @tc.desc: Use the wrong parameter and legal parameter to test WaitingForAuthNegoToBeDone.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthNegotiateTest, TransAuthPendingTest004, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t ret = WaitingForAuthNegoToBeDone(TRANS_TEST_INVALID_AUTH_REQUEST_ID, channelId);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = WaitingForAuthNegoToBeDone(TRANS_TEST_AUTH_REQUEST_ID, channelId);
    EXPECT_EQ(SOFTBUS_OK, ret);
    TransDelAuthReqFromPendingList(TRANS_TEST_AUTH_REQUEST_ID);
}

/**
 * @tc.name: TransAuthPendingTest005
 * @tc.desc: Use the wrong parameter to test TransNegotiateSessionKey and TransReNegotiateSessionKey.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthNegotiateTest, TransAuthPendingTest005, TestSize.Level1)
{
    AuthConnInfo authConnInfo;
    (void)memset_s(&authConnInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    int32_t channelId = 1;
    char peerNetworkId[DEVICE_ID_SIZE_MAX] = { 0 };
    int32_t ret = TransNegotiateSessionKey(nullptr, channelId, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransNegotiateSessionKey(&authConnInfo, channelId, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransNegotiateSessionKey(nullptr, channelId, peerNetworkId);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = TransReNegotiateSessionKey(nullptr, channelId);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**
 * @tc.name: TransAuthPendingTest006
 * @tc.desc: Use the wrong parameter to test GetAuthConnInfoByConnId.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthNegotiateTest, TransAuthPendingTest006, TestSize.Level1)
{
    uint32_t connectionId = 1;
    AuthConnInfo authConnInfo;
    (void)memset_s(&authConnInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    int32_t ret = GetAuthConnInfoByConnId(connectionId, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}
} // OHOS
