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
#include "lnn_event.h"
#include "lnn_hisysevent_matcher.h"
#include "softbus_hisysevent_matcher.h"
#include "gtest/gtest.h"

using namespace std;
using namespace testing;
using namespace testing::ext;

namespace OHOS {
class LnnEventTest : public testing::Test { };

/**
 * @tc.name: LnnEventTest001
 * @tc.desc: Test lnn event form size
 * @tc.type: FUNC
 * @tc.require: I8HA59
 */
HWTEST_F(LnnEventTest, LnnEventTest001, TestSize.Level0)
{
    LnnEventExtra extra = {
        .result = 1,
        .errcode = 2233,
        .onlineNum = -1, // invalid
        .peerPort = "9000",
    };
    constexpr int32_t VALID_EXTRA_SIZE = 3;

    HiSysEventMock mock;
    EXPECT_CALL(mock,
        HiSysEvent_Write(_, _, StrEq(SOFTBUS_EVENT_DOMAIN), StrEq(LNN_EVENT_NAME), Eq(SOFTBUS_EVENT_TYPE_BEHAVIOR), _,
            ParamArraySizeMatcher(VALID_EXTRA_SIZE)))
        .Times(1);
    LNN_EVENT(SCENE_JION_LNN, STAGE_JOIN_LNN_START, extra);
}

/**
 * @tc.name: LnnEventTest002
 * @tc.desc: Test all valid lnn event form items
 * @tc.type: FUNC
 * @tc.require: I8HA59
 */
HWTEST_F(LnnEventTest, LnnEventTest002, TestSize.Level0)
{
    LnnEventExtra validExtra = {
        .result = 1,
        .errcode = 2,
        .connectionId = 3,
        .authType = 4,
        .authId = 5,
        .lnnType = 6,
        .onlineNum = 7,
        .peerDeviceAbility = 8,
        .peerDeviceInfo = "testPeerDeviceInfo",
        .peerIp = "testPeerIp",
        .peerBrMac = "testPeerBrMac",
        .peerBleMac = "testPeerBleMac",
        .peerWifiMac = "testPeerWifiMac",
        .peerPort = "testPeerPort",
        .peerUdid = "testPeerUdid",
        .peerNetworkId = "testPeerNetworkId",
        .peerDeviceType = "testPeerDeviceType",
        .callerPkg = "testCallerPkg",
        .calleePkg = "testCalleePkg",
    };
    constexpr int32_t VALID_EXTRA_SIZE = LNN_ASSIGNER_SIZE;

    HiSysEventMock mock;
    EXPECT_CALL(mock,
        HiSysEvent_Write(_, _, StrEq(SOFTBUS_EVENT_DOMAIN), StrEq(LNN_EVENT_NAME), Eq(SOFTBUS_EVENT_TYPE_BEHAVIOR),
            LnnValidParamArrayMatcher(validExtra, VALID_EXTRA_SIZE), ParamArraySizeMatcher(VALID_EXTRA_SIZE)))
        .Times(1);
    LNN_EVENT(SCENE_JION_LNN, STAGE_JOIN_LNN_END, validExtra);
}

/**
 * @tc.name: LnnEventTest003
 * @tc.desc: Test all invalid lnn event form items
 * @tc.type: FUNC
 * @tc.require: I8HA59
 */
HWTEST_F(LnnEventTest, LnnEventTest003, TestSize.Level0)
{
    LnnEventExtra invalidExtra = {
        .result = -1,
        .errcode = -2, // valid
        .connectionId = -3,
        .authType = -4,
        .authId = -5,
        .lnnType = -6,
        .onlineNum = -7,
        .peerDeviceAbility = -8,
        .peerDeviceInfo = "",
        .peerIp = "",
        .peerBrMac = "",
        .peerBleMac = "",
        .peerWifiMac = "",
        .peerPort = "",
        .peerUdid = "",
        .peerNetworkId = "",
        .peerDeviceType = "",
        .callerPkg = "\0",
        .calleePkg = nullptr,
    };
    constexpr int32_t VALID_EXTRA_SIZE = 1; // errcode is valid

    HiSysEventMock mock;
    EXPECT_CALL(mock,
        HiSysEvent_Write(_, _, StrEq(SOFTBUS_EVENT_DOMAIN), StrEq(LNN_EVENT_NAME), Eq(SOFTBUS_EVENT_TYPE_BEHAVIOR),
            LnnInvalidParamArrayMatcher(invalidExtra, VALID_EXTRA_SIZE), ParamArraySizeMatcher(VALID_EXTRA_SIZE)))
        .Times(1);
    LNN_EVENT(SCENE_LEAVE_LNN, STAGE_LEAVE_LNN_START, invalidExtra);
}

/**
 * @tc.name: LnnEventTest004
 * @tc.desc: Test empty lnn event form
 * @tc.type: FUNC
 * @tc.require: I8HA59
 */
HWTEST_F(LnnEventTest, LnnEventTest004, TestSize.Level0)
{
    LnnEventExtra emptyExtra = { 0 };
    constexpr int32_t VALID_EXTRA_SIZE = 1; // errcode is valid

    HiSysEventMock mock;
    EXPECT_CALL(mock,
        HiSysEvent_Write(_, _, StrEq(SOFTBUS_EVENT_DOMAIN), StrEq(LNN_EVENT_NAME), Eq(SOFTBUS_EVENT_TYPE_BEHAVIOR),
            LnnInvalidParamArrayMatcher(emptyExtra, VALID_EXTRA_SIZE), ParamArraySizeMatcher(VALID_EXTRA_SIZE)))
        .Times(1);
    LNN_EVENT(SCENE_LEAVE_LNN, STAGE_LEAVE_LNN_END, emptyExtra);
}
} // namespace OHOS
