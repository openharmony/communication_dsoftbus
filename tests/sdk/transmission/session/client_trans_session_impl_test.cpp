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

#include "session_impl.h"
#include "softbus_error_code.h"

using namespace testing::ext;

namespace Communication {
namespace SoftBus {

static constexpr int32_t TEST_EXPEXT_CHANNELD_ID = 123456789;
static constexpr int32_t TEST_MAX_BYTES_LENGTH = 128 * 1024 * 1024;
static constexpr int32_t TEST_INVALID_BUF_LEN = 0;
static constexpr int32_t TEST_SEND_BUF_LENGTYH = 10;
static constexpr pid_t TEST_EXPEXTED_PEERPID = 38356;
static constexpr int32_t TEST_SESSIONID_003 = 1234;
static constexpr int32_t TEST_SESSIONID_004 = -123;
static constexpr int32_t TEST_SESSIONID_005 = 0;

class TransClientSessionImplTest : public testing::Test {
public:
    TransClientSessionImplTest() {}
    ~TransClientSessionImplTest() {};
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}

protected:
    SessionImpl sessionImpl_;
};

void TransClientSessionImplTest::SetUpTestCase(void) {}

void TransClientSessionImplTest::TearDownTestCase(void) {}

/**
 * @tc.name: TransClientSessionImplTest001
 * @tc.desc: Transmission sdk session impl initialization parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionImplTest, TransClientSessionImplTest001, TestSize.Level0)
{
    EXPECT_EQ(-1, sessionImpl_.GetSessionId());
    EXPECT_FALSE(sessionImpl_.IsServerSide());
    EXPECT_EQ(-1, sessionImpl_.GetPeerUid());
    EXPECT_EQ(-1, sessionImpl_.GetPeerPid());
}

/**
 * @tc.name: TransClientSessionImplTest002
 * @tc.desc: Transmission sdk test GetChannelId method.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionImplTest, TransClientSessionImplTest002, TestSize.Level0)
{
    sessionImpl_.SetSessionId(TEST_EXPEXT_CHANNELD_ID);
    EXPECT_EQ(sessionImpl_.GetChannelId(), TEST_EXPEXT_CHANNELD_ID);
}

/**
 * @tc.name: TransClientSessionImplTest003
 * @tc.desc: Transmission sdk test SetSessionId method.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionImplTest, TransClientSessionImplTest003, TestSize.Level0)
{
    int32_t sessionId = TEST_SESSIONID_003;
    sessionImpl_.SetSessionId(sessionId);
    EXPECT_EQ(sessionImpl_.GetSessionId(), sessionId);
}


/**
 * @tc.name: TransClientSessionImplTest004
 * @tc.desc: Transmission sdk test SetSessionId method.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionImplTest, TransClientSessionImplTest004, TestSize.Level0)
{
    int32_t sessionId = TEST_SESSIONID_004;
    sessionImpl_.SetSessionId(sessionId);
    EXPECT_EQ(sessionImpl_.GetSessionId(), sessionId);
}

/**
 * @tc.name: TransClientSessionImplTest005
 * @tc.desc: Transmission sdk test SetSessionId method.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionImplTest, TransClientSessionImplTest005, TestSize.Level0)
{
    int32_t sessionId = TEST_SESSIONID_005;
    sessionImpl_.SetSessionId(sessionId);
    EXPECT_EQ(sessionImpl_.GetSessionId(), sessionId);
}

/**
 * @tc.name: TransClientSessionImplTest006
 * @tc.desc: Test when GetMySessionName is called then it returns the correct session name.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionImplTest, TransClientSessionImplTest006, TestSize.Level0)
{
    std::string expectedSessionName = "trans.client.session.test";
    sessionImpl_.SetMySessionName(expectedSessionName);
    const std::string &actualSessionName = sessionImpl_.GetMySessionName();
    EXPECT_EQ(expectedSessionName, actualSessionName);
}

/**
 * @tc.name: TransClientSessionImplTest007
 * @tc.desc: Test when GetMySessionName is called then it returns an empty string if no session name is set.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionImplTest, TransClientSessionImplTest007, TestSize.Level0)
{
    const std::string &actualSessionName = sessionImpl_.GetMySessionName();
    EXPECT_EQ("", actualSessionName);
}

/**
 * @tc.name: TransClientSessionImplTest008
 * @tc.desc: Test SetPeerDeviceId when name is empty.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionImplTest, TransClientSessionImplTest008, TestSize.Level0)
{
    std::string name = "";
    sessionImpl_.SetPeerDeviceId(name);
    EXPECT_EQ(sessionImpl_.GetPeerDeviceId(), name);
}

/**
 * @tc.name: TransClientSessionImplTest009
 * @tc.desc: Test SetPeerDeviceId when name is not empty.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionImplTest, TransClientSessionImplTest009, TestSize.Level0)
{
    std::string name = "1111222223333333333333test";
    sessionImpl_.SetPeerDeviceId(name);
    EXPECT_EQ(sessionImpl_.GetPeerDeviceId(), name);
}

/**
 * @tc.name: TransClientSessionImplTest010
 * @tc.desc: Test when isServer is true.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionImplTest, TransClientSessionImplTest010, TestSize.Level0)
{
    sessionImpl_.SetIsServer(true);
    EXPECT_TRUE(sessionImpl_.IsServerSide());
}

/**
 * @tc.name: TransClientSessionImplTest011
 * @tc.desc: Test when isServer is false.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionImplTest, TransClientSessionImplTest011, TestSize.Level0)
{
    sessionImpl_.SetIsServer(false);
    EXPECT_FALSE(sessionImpl_.IsServerSide());
}

/**
 * @tc.name: TransClientSessionImplTest012
 * @tc.desc: Test when GetDeviceId is called then return deviceId_.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionImplTest, TransClientSessionImplTest012, TestSize.Level0)
{
    std::string deviceId = "11111111111111222222222222test";
    sessionImpl_.SetDeviceId(deviceId);
    const std::string &result = sessionImpl_.GetDeviceId();
    EXPECT_EQ(result, deviceId);
}

/**
 * @tc.name: TransClientSessionImplTest013
 * @tc.desc: Test when GetPeerUid is called then it returns the correct peerUid.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionImplTest, TransClientSessionImplTest013, TestSize.Level0)
{
    uid_t expectedPeerUid = TEST_EXPEXTED_PEERPID;
    sessionImpl_.SetPeerUid(expectedPeerUid);
    uid_t actualPeerUid = sessionImpl_.GetPeerUid();
    EXPECT_EQ(actualPeerUid, expectedPeerUid);
}

/**
 * @tc.name: TransClientSessionImplTest014
 * @tc.desc: Test GetPeerPid method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionImplTest, TransClientSessionImplTest014, TestSize.Level0)
{
    pid_t expectedPeerPid = TEST_EXPEXTED_PEERPID;
    sessionImpl_.SetPeerPid(expectedPeerPid);
    EXPECT_EQ(sessionImpl_.GetPeerPid(), expectedPeerPid);
}

/**
 * @tc.name: TransClientSessionImplTest015
 * @tc.desc: Test when isServer_ is true then IsServerSide returns true.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionImplTest, TransClientSessionImplTest015, TestSize.Level0)
{
    sessionImpl_.SetIsServer(true);
    ASSERT_EQ(sessionImpl_.IsServerSide(), true);
}

/**
 * @tc.name: TransClientSessionImplTest016
 * @tc.desc:Test when isServer_ is false then IsServerSide returns false.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionImplTest, TransClientSessionImplTest016, TestSize.Level0)
{
    sessionImpl_.SetIsServer(false);
    ASSERT_EQ(sessionImpl_.IsServerSide(), false);
}

/**
 * @tc.name: TransClientSessionImplTest017
 * @tc.desc: Test when buf is nullptr then SendBytes returns SOFTBUS_INVALID_PARAM.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionImplTest, TransClientSessionImplTest017, TestSize.Level0)
{
    const void *buf = nullptr;
    int32_t ret = sessionImpl_.SendBytes(buf, TEST_SEND_BUF_LENGTYH);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/**
 * @tc.name: TransClientSessionImplTest018
 * @tc.desc: Test when len is less than or equal to 0 then SendBytes returns SOFTBUS_INVALID_PARAM.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionImplTest, TransClientSessionImplTest018, TestSize.Level0)
{
    const void *buf = "sessionimpltestbuf";
    int32_t ret = sessionImpl_.SendBytes(buf, TEST_INVALID_BUF_LEN);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/**
 * @tc.name: TransClientSessionImplTest019
 * @tc.desc: Test when len is greater than TEST_MAX_BYTES_LENGTH then SendBytes returns SOFTBUS_INVALID_PARAM.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientSessionImplTest, TransClientSessionImplTest019, TestSize.Level0)
{
    const void *buf = "sessionimpltestbuf";
    ssize_t len = TEST_MAX_BYTES_LENGTH + 1;
    int32_t ret = sessionImpl_.SendBytes(buf, len);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}
} // SoftBus
} // Communication
