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
    DISC_EVENT(EVENT_SCENE_BROADCAST, EVENT_STAGE_BROADCAST, extra);
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
        .broadcastType = 3,
        .broadcastFreq = 4,
        .scanType = 5,
        .scanCycle = "testScanCycle",
        .discType = 7,
        .discMode = 8,
        .costTime = 9,
        .localNetworkId = "testLocalNetworkId",
        .localUdid = "testLocalUdid",
        .localDeviceType = "testLocalDeviceType",
        .peerIp = "testPeerIp",
        .peerBrMac = "testPeerBrMac",
        .peerBleMac = "testPeerBleMac",
        .peerWifiMac = "testPeerWifiMac",
        .peerPort = "testPeerPort",
        .peerUdid = "testPeerUdid",
        .peerNetworkId = "testPeerNetworkId",
        .peerDeviceType = "testPeerDeviceType",
        .callerPkg = "testCallerPkg",
    };
    constexpr int32_t VALID_EXTRA_SIZE = DISC_ASSIGNER_SIZE;

    HiSysEventMock mock;
    EXPECT_CALL(mock,
        HiSysEvent_Write(_, _, StrEq(SOFTBUS_EVENT_DOMAIN), StrEq(DISC_EVENT_NAME), Eq(SOFTBUS_EVENT_TYPE_BEHAVIOR),
            DiscValidParamArrayMatcher(validExtra, VALID_EXTRA_SIZE), ParamArraySizeMatcher(VALID_EXTRA_SIZE)))
        .Times(1);
    DISC_EVENT(EVENT_SCENE_SCAN, EVENT_STAGE_SCAN_START, validExtra);
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
        .broadcastType = -3,
        .broadcastFreq = -4,
        .scanType = -5,
        .scanCycle = "",
        .discType = -7,
        .discMode = -8,
        .costTime = -9,
        .localNetworkId = "",
        .localUdid = "",
        .localDeviceType = "",
        .peerIp = "",
        .peerBrMac = "",
        .peerBleMac = "",
        .peerWifiMac = "",
        .peerPort = "",
        .peerUdid = "",
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
    DISC_EVENT(EVENT_SCENE_SCAN, EVENT_STAGE_SCAN_END, invalidExtra);
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
    DISC_EVENT(EVENT_SCENE_BROADCAST, EVENT_STAGE_BROADCAST, emptyExtra);
}
} // namespace OHOS
