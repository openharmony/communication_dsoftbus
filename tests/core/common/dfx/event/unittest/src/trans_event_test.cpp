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
    TRANS_EVENT(EVENT_SCENE_OPEN_CHANNEL, EVENT_STAGE_OPEN_CHANNEL_START, extra);
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
        .btFlow = 17,
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
    TRANS_EVENT(EVENT_SCENE_OPEN_CHANNEL, EVENT_STAGE_OPEN_CHANNEL_END, validExtra);
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
        .result = -1,  // valid
        .errcode = -2, // valid
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
        .btFlow = -17,
        .peerNetworkId = "",
        .callerPkg = "\0",
        .calleePkg = nullptr,
    };
    constexpr int32_t VALID_EXTRA_SIZE = 2; // result, errcode is valid

    HiSysEventMock mock;
    EXPECT_CALL(mock,
        HiSysEvent_Write(_, _, StrEq(SOFTBUS_EVENT_DOMAIN), StrEq(TRANS_EVENT_NAME), Eq(SOFTBUS_EVENT_TYPE_BEHAVIOR),
            TransInvalidParamArrayMatcher(invalidExtra, VALID_EXTRA_SIZE), ParamArraySizeMatcher(VALID_EXTRA_SIZE)))
        .Times(1);
    TRANS_EVENT(EVENT_SCENE_CLOSE_CHANNEL_ACTIVE, EVENT_STAGE_CLOSE_CHANNEL, invalidExtra);
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
    constexpr int32_t VALID_EXTRA_SIZE = 2; // result, errcode is valid

    HiSysEventMock mock;
    EXPECT_CALL(mock,
        HiSysEvent_Write(_, _, StrEq(SOFTBUS_EVENT_DOMAIN), StrEq(TRANS_EVENT_NAME), Eq(SOFTBUS_EVENT_TYPE_BEHAVIOR),
            TransInvalidParamArrayMatcher(emptyExtra, VALID_EXTRA_SIZE), ParamArraySizeMatcher(VALID_EXTRA_SIZE)))
        .Times(1);
    TRANS_EVENT(EVENT_SCENE_CLOSE_CHANNEL_PASSIVE, EVENT_STAGE_CLOSE_CHANNEL, emptyExtra);
}

/**
 * @tc.name: TransEventTest005
 * @tc.desc: Test trans event form size
 * @tc.type: FUNC
 * @tc.require: I8HA59
 */
HWTEST_F(TransEventTest, TransEventTest005, TestSize.Level0)
{
    TransAlarmExtra extra = {
        .result = 1,
        .errcode = 2233,
        .minBw = 32,
        .linkType = 0, // invalid
    };
    constexpr int32_t VALID_EXTRA_SIZE = 3;

    HiSysEventMock mock;
    EXPECT_CALL(mock,
        HiSysEvent_Write(_, _, StrEq(SOFTBUS_EVENT_DOMAIN), StrEq(CONTROL_ALARM_EVENT_NAME),
            Eq(SOFTBUS_EVENT_TYPE_BEHAVIOR), _, ParamArraySizeMatcher(VALID_EXTRA_SIZE)))
        .Times(1);
    TRANS_ALARM(BANDWIDTH_INSUFFICIANT_ALARM, CONTROL_ALARM_TYPE, extra);
}

/**
 * @tc.name: TransEventTest006
 * @tc.desc: Test all valid trans event form items
 * @tc.type: FUNC
 * @tc.require: I8HA59
 */
HWTEST_F(TransEventTest, TransEventTest006, TestSize.Level0)
{
    TransAlarmExtra validExtra = {
        .result = 1,
        .errcode = 2,
        .callerPid = 3,
        .linkType = 4,
        .minBw = 5,
        .methodId = 6,
        .duration = 7,
        .curFlow = 8,
        .limitFlow = 9,
        .limitTime = 10,
        .occupyRes = 11,
        .syncType = 12,
        .syncData = 13,
        .retryCount = 14,
        .retryReason = 15,
        .conflictName = "conflictName",
        .conflictedName = "conflictedName",
        .occupyedName = "testOccupyName",
        .permissionName = "testPermissionName",
        .sessionName = "testSessionName",
    };
    constexpr int32_t VALID_EXTRA_SIZE = TRANS_ALARM_ASSIGNER_SIZE;

    HiSysEventMock mock;
    EXPECT_CALL(mock,
        HiSysEvent_Write(_, _, StrEq(SOFTBUS_EVENT_DOMAIN), StrEq(MANAGE_ALARM_EVENT_NAME),
            Eq(SOFTBUS_EVENT_TYPE_BEHAVIOR), TransAlarmValidParamArrayMatcher(validExtra, VALID_EXTRA_SIZE),
            ParamArraySizeMatcher(VALID_EXTRA_SIZE)))
        .Times(1);
    TRANS_ALARM(BANDWIDTH_INSUFFICIANT_ALARM, MANAGE_ALARM_TYPE, validExtra);
}

/**
 * @tc.name: TransEventTest007
 * @tc.desc: Test speed limit alarm
 * @tc.type: FUNC
 * @tc.require: I8HA59
 */
HWTEST_F(TransEventTest, TransEventTest007, TestSize.Level0)
{
    TransEventExtra validExtra = {
        .result = 1,
        .errcode = 2,
        .socketName = "testSocketName",
        .peerChannelId = 16,
        .btFlow = 17,
        .peerNetworkId = "testNetworkId",
        .callerPkg = "testCallerPkg",
        .calleePkg = "testCalleePkg",
    };
    TRANS_EVENT(EVENT_SCENE_BT_FLOW, SOFTBUS_DEFAULT_STAGE, validExtra);

    TransEventExtra validExtra1 = {
        .result = 1,
        .errcode = 2,
        .socketName = "testSocketName",
        .channelScore = 15,
        .peerChannelId = 16,
        .peerNetworkId = "testNetworkId",
        .callerPkg = "testCallerPkg",
        .calleePkg = "testCalleePkg",
    };
    TRANS_EVENT(EVENT_SCENE_LANE_SCORE, SOFTBUS_DEFAULT_STAGE, validExtra1);

    TransEventExtra validExtra2 = {
        .result = 1,
        .errcode = 2,
        .peerChannelId = 16,
        .peerNetworkId = "testNetworkId",
        .callerPkg = "testCallerPkg",
        .calleePkg = "testCalleePkg",
    };
    TRANS_EVENT(EVENT_SCENE_DETECTION, SOFTBUS_DEFAULT_STAGE, validExtra2);

    TransEventExtra validExtra3 = {
        .result = 1,
        .errcode = 2,
        .peerChannelId = 16,
        .peerNetworkId = "testNetworkId",
        .callerPkg = "testCallerPkg",
        .calleePkg = "testCalleePkg",
    };
    TRANS_EVENT(EVENT_SCENE_ACTIVATION, SOFTBUS_DEFAULT_STAGE, validExtra3);

    TransAlarmExtra validExtra4 = {
        .result = 11,
        .errcode = 22,
        .duration = 7,
        .curFlow = 100,
        .limitFlow = 90,
        .limitTime = 10,
        .occupyRes = 11,
        .syncType = 12,
        .syncData = 13,
        .retryCount = 14,
        .retryReason = 15,
        .occupyedName = "testOccupyName",
        .permissionName = "testPermissionName",
        .sessionName = "testSessionName",
    };

    TRANS_ALARM(SPEED_LIMIT_ALARM, CONTROL_ALARM_TYPE, validExtra4);

}
} // namespace OHOS
