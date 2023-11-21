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

#include "disc_event.h"
#include "disc_hisysevent_matcher.h"
#include "hisysevent_mock.h"
#include "softbus_hisysevent_matcher.h"
#include "gtest/gtest.h"

using namespace std;
using namespace testing;
using namespace testing::ext;

namespace OHOS {
class DiscEventTest : public testing::Test { };

/**
 * @tc.name: DiscEventTest001
 * @tc.desc: Test disc event form size
 * @tc.type: FUNC
 * @tc.require: I8HA59
 */
HWTEST_F(DiscEventTest, DiscEventTest001, TestSize.Level0)
{
    DiscEventExtra extra = {
        .broadcastType = 0,  // invalid
        .peerNetworkId = -1, // invalid
        .result = 1,
        .errcode = 2233,
        .peerPort = "9000",
    };
    constexpr int32_t VALID_EXTRA_SIZE = 3;

    HiSysEventMock mock;
    EXPECT_CALL(mock,
        HiSysEvent_Write(_, _, StrEq(SOFTBUS_EVENT_DOMAIN), StrEq(DISC_EVENT_NAME), Eq(SOFTBUS_EVENT_TYPE_BEHAVIOR), _,
            ParamArraySizeMatcher(VALID_EXTRA_SIZE)))
        .Times(1);
    DISC_EVENT(SCENE_BROADCAST, STAGE_BROADCAST, extra);
}

/**
 * @tc.name: DiscEventTest002
 * @tc.desc: Test all valid disc event form items
 * @tc.type: FUNC
 * @tc.require: I8HA59
 */
HWTEST_F(DiscEventTest, DiscEventTest002, TestSize.Level0)
{
    DiscEventExtra validExtra = {
        .broadcastType = 1,
        .broadcastFreq = 2,
        .scanType = 3,
        .discMode = 4,
        .discType = 5,
        .localNetworkId = 6,
        .localDeviceType = 7,
        .costTime = 8,
        .peerNetworkId = 9,
        .peerDeviceType = 10,
        .result = 11,
        .errcode = 12,
        .callerPkg = "testCallerPkg",
        .scanCycle = "testScanCycle",
        .peerBrMac = "testPeerBrMac",
        .peerBleMac = "testPeerBleMac",
        .peerWifiMac = "testPeerWifiMac",
        .peerIp = "testPeerIp",
        .peerPort = "testPeerPort",
    };
    constexpr int32_t VALID_EXTRA_SIZE = DISC_ASSIGNER_SIZE;

    HiSysEventMock mock;
    EXPECT_CALL(mock,
        HiSysEvent_Write(_, _, StrEq(SOFTBUS_EVENT_DOMAIN), StrEq(DISC_EVENT_NAME), Eq(SOFTBUS_EVENT_TYPE_BEHAVIOR),
            DiscValidParamArrayMatcher(validExtra, VALID_EXTRA_SIZE), ParamArraySizeMatcher(VALID_EXTRA_SIZE)))
        .Times(1);
    DISC_EVENT(SCENE_SCAN, STAGE_SCAN_START, validExtra);
}

/**
 * @tc.name: DiscEventTest003
 * @tc.desc: Test all invalid disc event form items
 * @tc.type: FUNC
 * @tc.require: I8HA59
 */
HWTEST_F(DiscEventTest, DiscEventTest003, TestSize.Level0)
{
    DiscEventExtra invalidExtra = {
        .broadcastType = -1,
        .broadcastFreq = -2,
        .scanType = -3,
        .discMode = -4,
        .discType = -5,
        .localNetworkId = -6,
        .localDeviceType = -7,
        .costTime = -8,
        .peerNetworkId = -9,
        .peerDeviceType = -10,
        .result = -11,
        .errcode = -12, // valid
        .callerPkg = nullptr,
        .scanCycle = "\0",
        .peerBrMac = "",
        .peerBleMac = nullptr,
        .peerWifiMac = nullptr,
        .peerIp = nullptr,
        .peerPort = nullptr,
    };
    constexpr int32_t VALID_EXTRA_SIZE = 1; // errcode is valid

    HiSysEventMock mock;
    EXPECT_CALL(mock,
        HiSysEvent_Write(_, _, StrEq(SOFTBUS_EVENT_DOMAIN), StrEq(DISC_EVENT_NAME), Eq(SOFTBUS_EVENT_TYPE_BEHAVIOR),
            DiscInvalidParamArrayMatcher(invalidExtra, VALID_EXTRA_SIZE), ParamArraySizeMatcher(VALID_EXTRA_SIZE)))
        .Times(1);
    DISC_EVENT(SCENE_SCAN, STAGE_SCAN_END, invalidExtra);
}

/**
 * @tc.name: DiscEventTest004
 * @tc.desc: Test empty disc event form
 * @tc.type: FUNC
 * @tc.require: I8HA59
 */
HWTEST_F(DiscEventTest, DiscEventTest004, TestSize.Level0)
{
    DiscEventExtra emptyExtra = { 0 };
    constexpr int32_t VALID_EXTRA_SIZE = 1; // errcode is valid

    HiSysEventMock mock;
    EXPECT_CALL(mock,
        HiSysEvent_Write(_, _, StrEq(SOFTBUS_EVENT_DOMAIN), StrEq(DISC_EVENT_NAME), Eq(SOFTBUS_EVENT_TYPE_BEHAVIOR),
            DiscInvalidParamArrayMatcher(emptyExtra, VALID_EXTRA_SIZE), ParamArraySizeMatcher(VALID_EXTRA_SIZE)))
        .Times(1);
    DISC_EVENT(SCENE_BROADCAST, STAGE_BROADCAST, emptyExtra);
}
} // namespace OHOS
