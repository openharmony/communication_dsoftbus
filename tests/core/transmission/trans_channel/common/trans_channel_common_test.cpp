/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "trans_channel_common.h"
#include "trans_channel_common_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
class TransChannelCommonTest : public testing::Test {
public:
    TransChannelCommonTest() { }
    ~TransChannelCommonTest() { }
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override { }
    void TearDown() override { }
};

void TransChannelCommonTest::SetUpTestCase(void) { }

void TransChannelCommonTest::TearDownTestCase(void) { }

/*
 * @tc.name: TransSetWakeUpInfoTest001
 * @tc.desc: TransSetWakeUpInfo with TCP_DIRECT channel passes through TransTdcSetWakeUpInfo return value.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelCommonTest, TransSetWakeUpInfoTest001, TestSize.Level1)
{
    TransChannelCommonMock mock;
    int32_t channelId = 0;
    bool needFastWakeUp = true;
    EXPECT_CALL(mock, TransTdcSetWakeUpInfo).WillOnce(Return(SOFTBUS_OK));
    int32_t ret = TransSetWakeUpInfo(CHANNEL_TYPE_TCP_DIRECT, channelId, needFastWakeUp);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_CALL(mock, TransTdcSetWakeUpInfo).WillOnce(Return(SOFTBUS_ERR));
    ret = TransSetWakeUpInfo(CHANNEL_TYPE_TCP_DIRECT, channelId, needFastWakeUp);
    EXPECT_EQ(SOFTBUS_ERR, ret);
}

/*
 * @tc.name: TransSetWakeUpInfoTest002
 * @tc.desc: TransSetWakeUpInfo with UDP channel passes through TransUdpSetWakeUpInfo return value.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelCommonTest, TransSetWakeUpInfoTest002, TestSize.Level1)
{
    TransChannelCommonMock mock;
    int32_t channelId = 0;
    bool needFastWakeUp = true;
    EXPECT_CALL(mock, TransUdpSetWakeUpInfo).WillOnce(Return(SOFTBUS_OK));
    int32_t ret = TransSetWakeUpInfo(CHANNEL_TYPE_UDP, channelId, needFastWakeUp);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_CALL(mock, TransUdpSetWakeUpInfo).WillOnce(Return(SOFTBUS_ERR));
    ret = TransSetWakeUpInfo(CHANNEL_TYPE_UDP, channelId, needFastWakeUp);
    EXPECT_EQ(SOFTBUS_ERR, ret);
}

/*
 * @tc.name: TransSetWakeUpInfoTest003
 * @tc.desc: TransSetWakeUpInfo with unsupported channel type returns SOFTBUS_TRANS_FUNC_NOT_SUPPORT.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelCommonTest, TransSetWakeUpInfoTest003, TestSize.Level1)
{
    int32_t channelId = 0;
    bool needFastWakeUp = true;
    int32_t ret = TransSetWakeUpInfo(CHANNEL_TYPE_UNDEFINED, channelId, needFastWakeUp);
    EXPECT_EQ(SOFTBUS_TRANS_FUNC_NOT_SUPPORT, ret);
    ret = TransSetWakeUpInfo(CHANNEL_TYPE_PROXY, channelId, needFastWakeUp);
    EXPECT_EQ(SOFTBUS_TRANS_FUNC_NOT_SUPPORT, ret);
}

/*
 * @tc.name: TransGetWakeUpInfoTest001
 * @tc.desc: TransGetWakeUpInfo with TCP_DIRECT channel passes through TransTdcGetWakeUpInfo return value.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelCommonTest, TransGetWakeUpInfoTest001, TestSize.Level1)
{
    TransChannelCommonMock mock;
    int32_t channelId = 0;
    char *uuid = nullptr;
    int32_t uuidLen = 0;
    bool *needFastWakeUp = nullptr;
    EXPECT_CALL(mock, TransTdcGetWakeUpInfo).WillOnce(Return(SOFTBUS_OK));
    int32_t ret = TransGetWakeUpInfo(CHANNEL_TYPE_TCP_DIRECT, channelId, uuid, uuidLen, needFastWakeUp);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_CALL(mock, TransTdcGetWakeUpInfo).WillOnce(Return(SOFTBUS_ERR));
    ret = TransGetWakeUpInfo(CHANNEL_TYPE_TCP_DIRECT, channelId, uuid, uuidLen, needFastWakeUp);
    EXPECT_EQ(SOFTBUS_ERR, ret);
}

/*
 * @tc.name: TransGetWakeUpInfoTest002
 * @tc.desc: TransGetWakeUpInfo with UDP channel passes through TransUdpGetWakeUpInfo return value.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelCommonTest, TransGetWakeUpInfoTest002, TestSize.Level1)
{
    TransChannelCommonMock mock;
    int32_t channelId = 0;
    char *uuid = nullptr;
    int32_t uuidLen = 0;
    bool *needFastWakeUp = nullptr;
    EXPECT_CALL(mock, TransUdpGetWakeUpInfo).WillOnce(Return(SOFTBUS_OK));
    int32_t ret = TransGetWakeUpInfo(CHANNEL_TYPE_UDP, channelId, uuid, uuidLen, needFastWakeUp);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_CALL(mock, TransUdpGetWakeUpInfo).WillOnce(Return(SOFTBUS_ERR));
    ret = TransGetWakeUpInfo(CHANNEL_TYPE_UDP, channelId, uuid, uuidLen, needFastWakeUp);
    EXPECT_EQ(SOFTBUS_ERR, ret);
}

/*
 * @tc.name: TransGetWakeUpInfoTest003
 * @tc.desc: TransGetWakeUpInfo with unsupported channel type returns SOFTBUS_TRANS_FUNC_NOT_SUPPORT.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelCommonTest, TransGetWakeUpInfoTest003, TestSize.Level1)
{
    int32_t channelId = 0;
    char *uuid = nullptr;
    int32_t uuidLen = 0;
    bool *needFastWakeUp = nullptr;
    int32_t ret = TransGetWakeUpInfo(CHANNEL_TYPE_UNDEFINED, channelId, uuid, uuidLen, needFastWakeUp);
    EXPECT_EQ(SOFTBUS_TRANS_FUNC_NOT_SUPPORT, ret);
    ret = TransGetWakeUpInfo(CHANNEL_TYPE_PROXY, channelId, uuid, uuidLen, needFastWakeUp);
    EXPECT_EQ(SOFTBUS_TRANS_FUNC_NOT_SUPPORT, ret);
}
} // namespace OHOS
