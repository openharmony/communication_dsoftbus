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
        .result = 1,
        .errcode = 2233,
        .broadcastType = 0, // invalid
        .peerPort = "9000",
    };
    constexpr int32_t VALID_EXTRA_SIZE = 3;

    HiSysEventMock mock;
    EXPECT_CALL(mock,
        HiSysEvent_Write(_, _, StrEq(SOFTBUS_EVENT_DOMAIN), StrEq(DISC_EVENT_NAME), Eq(SOFTBUS_EVENT_TYPE_BEHAVIOR), _,
            ParamArraySizeMatcher(VALID_EXTRA_SIZE)))
        .Times(1);
    DISC_EVENT(EVENT_SCENE_BLE, EVENT_STAGE_BROADCAST, extra);
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
        .result = 1,
        .errcode = 2,
        .initType = 3,
        .serverType = "4",
        .advHandle = 5,
        .bcOverMaxCnt = 6,
        .interFuncType = 7,
        .capabilityBit = 8,
        .capabilityData = "testCapabilityData",
        .bleTurnState = 10,
        .ipLinkStatus = 11,
        .coapChangeType = 12,
        .broadcastType = 13,
        .broadcastFreq = 14,
        .minInterval = 15,
        .maxInterval = 16,
        .currentNum = 17,
        .scanType = 18,
        .scanCount = 19,
        .scanCycle = "testScanCycle",
        .discType = 21,
        .discMode = 22,
        .successCnt = 23,
        .failCnt = 24,
        .startTime = 25,
        .costTime = 26,
        .localNetworkId = "a8ynvpdaihw1f6nknjd2hkfhxljxypkr6kvjsbhnhpp16974uo4fvsrpfa6t50fm",
        .peerIp = "10.11.12.1",
        .peerBrMac = "dd:15:bc:b9:f2:05",
        .peerBleMac = "dd:15:bc:b9:f2:04",
        .peerWifiMac = "dd:15:bc:b9:f2:04",
        .peerPort = "testPeerPort",
        .peerNetworkId = "a8ynvpdaihw1f6nknjd2hkfhxljxypkr6kvjsbhnhpp16974uo4fvsrpfa6t50fm",
        .peerDeviceType = "a8ynvpdaihw1f6nknjd2hkfhxljxypkr6kvjsbhnhpp16974uo4fvsrpfa6t50fm",
        .callerPkg = "testCallerPkg",
    };
    constexpr int32_t VALID_EXTRA_SIZE = DISC_ASSIGNER_SIZE;

    HiSysEventMock mock;
    EXPECT_CALL(mock,
        HiSysEvent_Write(_, _, StrEq(SOFTBUS_EVENT_DOMAIN), StrEq(DISC_EVENT_NAME), Eq(SOFTBUS_EVENT_TYPE_BEHAVIOR),
            DiscValidParamArrayMatcher(validExtra, VALID_EXTRA_SIZE), ParamArraySizeMatcher(VALID_EXTRA_SIZE)))
        .Times(1);
    DISC_EVENT(EVENT_SCENE_BLE, EVENT_STAGE_SCAN, validExtra);
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
        .result = -1,  // valid
        .errcode = -2, // valid
        .initType = -3,
        .serverType = "",
        .interFuncType = -5,
        .capabilityBit = -6,
        .capabilityData = "",
        .bleTurnState = -8,
        .ipLinkStatus = -9,
        .coapChangeType = -10,
        .broadcastType = -11,
        .broadcastFreq = -12,
        .scanType = -13,
        .scanCycle = "",
        .discType = -15,
        .discMode = -16,
        .costTime = -17,
        .localNetworkId = "",
        .peerIp = "",
        .peerBrMac = "",
        .peerBleMac = "",
        .peerWifiMac = "",
        .peerPort = "",
        .peerNetworkId = "",
        .peerDeviceType = "\0",
        .callerPkg = nullptr,
    };
    constexpr int32_t VALID_EXTRA_SIZE = 2; // result, errcode is valid

    HiSysEventMock mock;
    EXPECT_CALL(mock,
        HiSysEvent_Write(_, _, StrEq(SOFTBUS_EVENT_DOMAIN), StrEq(DISC_EVENT_NAME), Eq(SOFTBUS_EVENT_TYPE_BEHAVIOR),
            DiscInvalidParamArrayMatcher(invalidExtra, VALID_EXTRA_SIZE), ParamArraySizeMatcher(VALID_EXTRA_SIZE)))
        .Times(1);
    DISC_EVENT(EVENT_SCENE_BLE, EVENT_STAGE_SCAN, invalidExtra);
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
    constexpr int32_t VALID_EXTRA_SIZE = 2; // result, errcode is valid

    HiSysEventMock mock;
    EXPECT_CALL(mock,
        HiSysEvent_Write(_, _, StrEq(SOFTBUS_EVENT_DOMAIN), StrEq(DISC_EVENT_NAME), Eq(SOFTBUS_EVENT_TYPE_BEHAVIOR),
            DiscInvalidParamArrayMatcher(emptyExtra, VALID_EXTRA_SIZE), ParamArraySizeMatcher(VALID_EXTRA_SIZE)))
        .Times(1);
    DISC_EVENT(EVENT_SCENE_BLE, EVENT_STAGE_BROADCAST, emptyExtra);
}
} // namespace OHOS
