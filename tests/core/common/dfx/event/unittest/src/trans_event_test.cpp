/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "hisysevent_mock.h"
#include "softbus_hisysevent_matcher.h"
#include "trans_event.h"
#include "trans_hisysevent_matcher.h"
#include "gtest/gtest.h"

using namespace std;
using namespace testing;
using namespace testing::ext;

namespace OHOS {
class TransEventTest : public testing::Test { };

/**
 * @tc.name: TransEventTest001
 * @tc.desc: Test trans event form size
 * @tc.type: FUNC
 * @tc.require: I8HA59
 */
HWTEST_F(TransEventTest, TransEventTest001, TestSize.Level0)
{
    TransEventExtra extra = {
        .result = 1,
        .errcode = 2233,
        .socketName = "testSocket",
        .dataType = 0, // invalid
    };
    constexpr int32_t VALID_EXTRA_SIZE = 3;

    HiSysEventMock mock;
    EXPECT_CALL(mock,
        HiSysEvent_Write(_, _, StrEq(SOFTBUS_EVENT_DOMAIN), StrEq(TRANS_EVENT_NAME), Eq(SOFTBUS_EVENT_TYPE_BEHAVIOR), _,
            ParamArraySizeMatcher(VALID_EXTRA_SIZE)))
        .Times(1);
    TRANS_EVENT(SCENE_OPEN_CHANNEL, STAGE_OPEN_CHANNEL_START, extra);
}

/**
 * @tc.name: TransEventTest002
 * @tc.desc: Test all valid trans event form items
 * @tc.type: FUNC
 * @tc.require: I8HA59
 */
HWTEST_F(TransEventTest, TransEventTest002, TestSize.Level0)
{
    TransEventExtra validExtra = {
        .result = 1,
        .errcode = 2,
        .socketName = "testSocketName",
        .dataType = 3,
        .channelType = 4,
        .laneId = 5,
        .preferLinkType = 6,
        .laneTransType = 7,
        .channelId = 8,
        .requestId = 9,
        .connectionId = 10,
        .linkType = 11,
        .authId = 12,
        .socketFd = 13,
        .costTime = 14,
        .channelScore = 15,
        .peerChannelId = 16,
        .peerNetworkId = "testNetworkId",
        .callerPkg = "testCallerPkg",
        .calleePkg = "testCalleePkg",
    };
    constexpr int32_t VALID_EXTRA_SIZE = TRANS_ASSIGNER_SIZE;

    HiSysEventMock mock;
    EXPECT_CALL(mock,
        HiSysEvent_Write(_, _, StrEq(SOFTBUS_EVENT_DOMAIN), StrEq(TRANS_EVENT_NAME), Eq(SOFTBUS_EVENT_TYPE_BEHAVIOR),
            TransValidParamArrayMatcher(validExtra, VALID_EXTRA_SIZE), ParamArraySizeMatcher(VALID_EXTRA_SIZE)))
        .Times(1);
    TRANS_EVENT(SCENE_OPEN_CHANNEL, STAGE_OPEN_CHANNEL_END, validExtra);
}

/**
 * @tc.name: TransEventTest003
 * @tc.desc: Test all invalid trans event form items
 * @tc.type: FUNC
 * @tc.require: I8HA59
 */
HWTEST_F(TransEventTest, TransEventTest003, TestSize.Level0)
{
    TransEventExtra invalidExtra = {
        .result = -1,
        .errcode = -2,
        .socketName = "",
        .dataType = -3,
        .channelType = -4,
        .laneId = -5,
        .preferLinkType = -6,
        .laneTransType = -7,
        .channelId = -8,
        .requestId = -9,
        .connectionId = -10,
        .linkType = -11,
        .authId = -12,
        .socketFd = -13,
        .costTime = -14,
        .channelScore = -15,
        .peerChannelId = -16,
        .peerNetworkId = "",
        .callerPkg = "\0",
        .calleePkg = nullptr,
    };
    constexpr int32_t VALID_EXTRA_SIZE = 1; // errcode is valid

    HiSysEventMock mock;
    EXPECT_CALL(mock,
        HiSysEvent_Write(_, _, StrEq(SOFTBUS_EVENT_DOMAIN), StrEq(TRANS_EVENT_NAME), Eq(SOFTBUS_EVENT_TYPE_BEHAVIOR),
            TransInvalidParamArrayMatcher(invalidExtra, VALID_EXTRA_SIZE), ParamArraySizeMatcher(VALID_EXTRA_SIZE)))
        .Times(1);
    TRANS_EVENT(SCENE_CLOSE_CHANNEL_ACTIVE, STAGE_CLOSE_CHANNEL, invalidExtra);
}

/**
 * @tc.name: TransEventTest004
 * @tc.desc: Test empty trans event form
 * @tc.type: FUNC
 * @tc.require: I8HA59
 */
HWTEST_F(TransEventTest, TransEventTest004, TestSize.Level0)
{
    TransEventExtra emptyExtra = { 0 };
    constexpr int32_t VALID_EXTRA_SIZE = 1; // errcode is valid

    HiSysEventMock mock;
    EXPECT_CALL(mock,
        HiSysEvent_Write(_, _, StrEq(SOFTBUS_EVENT_DOMAIN), StrEq(TRANS_EVENT_NAME), Eq(SOFTBUS_EVENT_TYPE_BEHAVIOR),
            TransInvalidParamArrayMatcher(emptyExtra, VALID_EXTRA_SIZE), ParamArraySizeMatcher(VALID_EXTRA_SIZE)))
        .Times(1);
    TRANS_EVENT(SCENE_CLOSE_CHANNEL_PASSIVE, STAGE_CLOSE_CHANNEL, emptyExtra);
}
} // namespace OHOS
