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

/**
 * @tc.name: TransChannelTest001SetWakeUpInfo
 * @tc.desc: Check channelType with right return value.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelCommonTest, TransChannelTest001SetWakeUpInfo, TestSize.Level1)
{
    TransChannelCommonMock mock;
    int32_t channelType = 0;
    int32_t channelId = 0;
    bool needFastWakeUp = true;
    int32_t expectRes = SOFTBUS_OK;
    int32_t ret = SOFTBUS_OK;

    channelType = CHANNEL_TYPE_TCP_DIRECT;
    expectRes = SOFTBUS_OK;
    EXPECT_CALL(mock, TransTdcSetWakeUpInfo).WillOnce(testing::Return(expectRes));
    ret = TransSetWakeUpInfo(channelType, channelId, needFastWakeUp);
    EXPECT_EQ(expectRes, ret);
    expectRes = SOFTBUS_ERR;
    EXPECT_CALL(mock, TransTdcSetWakeUpInfo).WillOnce(testing::Return(expectRes));
    ret = TransSetWakeUpInfo(channelType, channelId, needFastWakeUp);
    EXPECT_EQ(expectRes, ret);

    channelType = CHANNEL_TYPE_UDP;
    expectRes = SOFTBUS_OK;
    EXPECT_CALL(mock, TransUdpSetWakeUpInfo).WillOnce(testing::Return(expectRes));
    ret = TransSetWakeUpInfo(channelType, channelId, needFastWakeUp);
    EXPECT_EQ(expectRes, ret);
    expectRes = SOFTBUS_ERR;
    EXPECT_CALL(mock, TransUdpSetWakeUpInfo).WillOnce(testing::Return(expectRes));
    ret = TransSetWakeUpInfo(channelType, channelId, needFastWakeUp);
    EXPECT_EQ(expectRes, ret);

    channelType = CHANNEL_TYPE_UNDEFINED;
    expectRes = SOFTBUS_TRANS_FUNC_NOT_SUPPORT;
    ret = TransSetWakeUpInfo(channelType, channelId, needFastWakeUp);
    EXPECT_EQ(expectRes, ret);
}

/**
 * @tc.name: TransChannelTest002GetWakeUpInfo
 * @tc.desc: Check channelType with right return value.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelCommonTest, TransChannelTest002GetWakeUpInfo, TestSize.Level1)
{
    TransChannelCommonMock mock;
    int32_t channelType = 0;
    int32_t channelId = 0;
    char *uuid = NULL;
    int32_t uuidLen = 0;
    bool *needFastWakeUp = NULL;
    int32_t expectRes = SOFTBUS_OK;
    int32_t ret = SOFTBUS_OK;

    channelType = CHANNEL_TYPE_TCP_DIRECT;
    expectRes = SOFTBUS_OK;
    EXPECT_CALL(mock, TransTdcGetWakeUpInfo).WillOnce(testing::Return(expectRes));
    ret = TransGetWakeUpInfo(channelType, channelId, uuid, uuidLen, needFastWakeUp);
    EXPECT_EQ(expectRes, ret);
    expectRes = SOFTBUS_ERR;
    EXPECT_CALL(mock, TransTdcGetWakeUpInfo).WillOnce(testing::Return(expectRes));
    ret = TransGetWakeUpInfo(channelType, channelId, uuid, uuidLen, needFastWakeUp);
    EXPECT_EQ(expectRes, ret);

    channelType = CHANNEL_TYPE_UDP;
    expectRes = SOFTBUS_OK;
    EXPECT_CALL(mock, TransUdpGetWakeUpInfo).WillOnce(testing::Return(expectRes));
    ret = TransGetWakeUpInfo(channelType, channelId, uuid, uuidLen, needFastWakeUp);
    EXPECT_EQ(expectRes, ret);
    expectRes = SOFTBUS_ERR;
    EXPECT_CALL(mock, TransUdpGetWakeUpInfo).WillOnce(testing::Return(expectRes));
    ret = TransGetWakeUpInfo(channelType, channelId, uuid, uuidLen, needFastWakeUp);
    EXPECT_EQ(expectRes, ret);

    channelType = CHANNEL_TYPE_UNDEFINED;
    expectRes = SOFTBUS_TRANS_FUNC_NOT_SUPPORT;
    ret = TransGetWakeUpInfo(channelType, channelId, uuid, uuidLen, needFastWakeUp);
    EXPECT_EQ(expectRes, ret);
}
}
