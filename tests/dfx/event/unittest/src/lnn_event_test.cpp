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

static LnnEventExtra validExtra = {
    .result = 1,
    .errcode = 2,
    .authId = 3,
    .discServerType = 4,
    .gearCycle = 5,
    .gearDuration = 6,
    .connectionId = 7,
    .authLinkType = 8,
    .authRequestId = 9,
    .authCostTime = 10,
    .lnnType = 11,
    .onlineNum = 12,
    .peerDeviceAbility = 13,
    .onlineType = 14,
    .osType = 15,
    .connOnlineReason = 16,
    .laneId = 17,
    .chanReqId = 18,
    .connReqId = 19,
    .strategy = 20,
    .timeLatency = 21,
    .triggerReason = 22,
    .authSeq = 23,
    .onlineDevCnt = 24,
    .interval = 25,
    .laneLinkType = 26,
    .hmlChannelId = 27,
    .p2pChannelId = 28,
    .staChannelId = 29,
    .apChannelId = 30,
    .laneReqId = 31,
    .minBW = 32,
    .maxLaneLatency = 33,
    .minLaneLatency = 34,
    .isWifiDirectReuse = 35,
    .bandWidth = 36,
    .guideType = 37,
    .peerDeviceInfo = "testPeerDeviceInfo",
    .peerIp = "10.11.12.1",
    .peerBrMac = "dd:15:bc:b9:f2:04",
    .peerBleMac = "dd:15:bc:b9:f2:04",
    .peerWifiMac = "dd:15:bc:b9:f2:04",
    .peerPort = "testPeerPort",
    .peerUdid = "a8ynvpdaihw1f6nknjd2hkfhxljxypkr6kvjsbhnhpp16974uo4fvsrpfa6t50fm",
    .peerNetworkId = "a8ynvpdaihw1f6nknjd2hkfhxljxypkr6kvjsbhnhpp16974uo4fvsrpfa6t50fm",
    .localDeviceType = "testLocalDeviceType",
    .peerDeviceType = "testPeerDeviceType",
    .localUdidHash = "8f37c149495d2a45",
    .peerUdidHash = "9ada389cd0898797",
    .callerPkg = "testCallerPkg",
    .calleePkg = "testCalleePkg",
};

static LnnEventExtra invalidExtra = {
    .result = -1,  // vaild
    .errcode = -2, // valid
    .authId = -3,  // vaild
    .discServerType = -4,
    .gearCycle = -5,
    .gearDuration = -6,
    .connectionId = -7,
    .authLinkType = -8,
    .authRequestId = -9,
    .authCostTime = -10,
    .lnnType = -11,
    .onlineNum = -12,
    .peerDeviceAbility = -13,
    .onlineType = -14,
    .osType = -15,
    .connOnlineReason = 0,
    .laneId = -17,
    .chanReqId = -18,
    .connReqId = -19,
    .strategy = -20,
    .timeLatency = -21,
    .triggerReason = -22,
    .authSeq = -23,
    .onlineDevCnt = -24,
    .interval = -25,
    .laneLinkType = -26,
    .hmlChannelId = -27,
    .p2pChannelId = -28,
    .staChannelId = -29,
    .apChannelId = -30,
    .laneReqId = -31,
    .minBW = -32,
    .maxLaneLatency = -33,
    .minLaneLatency = -34,
    .isWifiDirectReuse = -35,
    .bandWidth = -36,
    .guideType = -37,
    .peerDeviceInfo = "",
    .peerIp = "",
    .peerBrMac = "",
    .peerBleMac = "",
    .peerWifiMac = "",
    .peerPort = "",
    .peerUdid = "",
    .peerNetworkId = "",
    .localDeviceType = "",
    .peerDeviceType = "",
    .localUdidHash = "",
    .peerUdidHash = "",
    .callerPkg = "\0",
    .calleePkg = nullptr,
};

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
        .authId = 112233,
        .onlineNum = -1, // invalid
        .peerPort = "9000",
    };
    constexpr int32_t VALID_EXTRA_SIZE = 14;

    HiSysEventMock mock;
    EXPECT_CALL(mock,
        HiSysEvent_Write(_, _, StrEq(SOFTBUS_EVENT_DOMAIN), StrEq(LNN_EVENT_NAME), Eq(SOFTBUS_EVENT_TYPE_BEHAVIOR), _,
            ParamArraySizeMatcher(VALID_EXTRA_SIZE)))
        .Times(1);
    LNN_EVENT(EVENT_SCENE_JOIN_LNN, EVENT_STAGE_JOIN_LNN_START, extra);
}

/**
 * @tc.name: LnnEventTest002
 * @tc.desc: Test all valid lnn event form items
 * @tc.type: FUNC
 * @tc.require: I8HA59
 */
HWTEST_F(LnnEventTest, LnnEventTest002, TestSize.Level0)
{
    constexpr int32_t VALID_EXTRA_SIZE = LNN_ASSIGNER_SIZE;

    HiSysEventMock mock;
    EXPECT_CALL(mock,
        HiSysEvent_Write(_, _, StrEq(SOFTBUS_EVENT_DOMAIN), StrEq(LNN_EVENT_NAME), Eq(SOFTBUS_EVENT_TYPE_BEHAVIOR),
            LnnValidParamArrayMatcher(validExtra, VALID_EXTRA_SIZE), ParamArraySizeMatcher(VALID_EXTRA_SIZE)))
        .Times(1);
    LNN_EVENT(EVENT_SCENE_JOIN_LNN, EVENT_STAGE_JOIN_LNN_END, validExtra);
}

/**
 * @tc.name: LnnEventTest003
 * @tc.desc: Test all invalid lnn event form items
 * @tc.type: FUNC
 * @tc.require: I8HA59
 */
HWTEST_F(LnnEventTest, LnnEventTest003, TestSize.Level0)
{
    constexpr int32_t VALID_EXTRA_SIZE = 3; // result, errcode, authId is valid
    constexpr int32_t VALID_EXTRA_MATCHER_SIZE = 13;
    HiSysEventMock mock;
    EXPECT_CALL(mock, HiSysEvent_Write(_, _, StrEq(SOFTBUS_EVENT_DOMAIN), StrEq(LNN_EVENT_NAME),
        Eq(SOFTBUS_EVENT_TYPE_BEHAVIOR), LnnInvalidParamArrayMatcher(invalidExtra, VALID_EXTRA_SIZE),
        ParamArraySizeMatcher(VALID_EXTRA_MATCHER_SIZE))).Times(1);
    LNN_EVENT(EVENT_SCENE_LEAVE_LNN, EVENT_STAGE_LEAVE_LNN, invalidExtra);
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
    constexpr int32_t VALID_EXTRA_SIZE = 3; // result, errcode, authId is valid
    constexpr int32_t VALID_EXTRA_MATCHER_SIZE = 13;

    HiSysEventMock mock;
    EXPECT_CALL(mock,
        HiSysEvent_Write(_, _, StrEq(SOFTBUS_EVENT_DOMAIN), StrEq(LNN_EVENT_NAME), Eq(SOFTBUS_EVENT_TYPE_BEHAVIOR),
            LnnInvalidParamArrayMatcher(emptyExtra, VALID_EXTRA_SIZE), ParamArraySizeMatcher(VALID_EXTRA_MATCHER_SIZE)))
        .Times(1);
    LNN_EVENT(EVENT_SCENE_LEAVE_LNN, EVENT_STAGE_LEAVE_LNN, emptyExtra);
}

/**
 * @tc.name: LnnAuditTest001
 * @tc.desc: Test lnn audit form size
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnEventTest, LnnAuditTest001, TestSize.Level0)
{
    LnnAuditExtra extra = {
        .result = AUDIT_DECRYPT_FAIL_END_AUTH,
        .errCode = 2233,
        .auditType = AUDIT_EVENT_MSG_ERROR,
        .connId = 123,
        .authLinkType = 2,
        .authRequestId = 10,
        .onlineNum = 2,
        .hostPkg = "testHostPkg",
        .localIp = "127.0.0.0",
        .localBrMac = "12:22:23:33:33:91",
        .localBleMac = "91:33:33:23:22:12",
        .localUdid = "aassddffgghhhh",
        .localNetworkId = "aassddffgghhhh",
        .localDevName = "Openharmony001",
        .peerIp = "127.1.1.1",
        .peerBrMac = "22:33:44:55:66:77",
        .peerBleMac = "77:66:55:44:33:22",
        .peerUdid = "aassddffgghhhh",
        .peerNetworkId = "aassddffgghhhh",
        .peerDevName = "Openharmony002",
        .localAuthPort = 1,
        .localProxyPort = 2,
        .localSessionPort = 3,
        .localDevType = 127,
        .peerAuthPort = 4,
        .peerProxyPort = 5,
        .peerSessionPort = 6,
        .peerDevType = 128,
        .attackTimes = 10000,
        .beAttackedPort = 25,
    };
    constexpr int32_t VALID_EXTRA_SIZE = 30; // result, errcode is valid

    HiSysEventMock mock;
    EXPECT_CALL(mock,
        HiSysEvent_Write(_, _, StrEq(SOFTBUS_EVENT_DOMAIN), StrEq(LNN_AUDIT_NAME), Eq(SOFTBUS_EVENT_TYPE_SECURITY),
            LnnAuditValidParamArrayMatcher(extra, VALID_EXTRA_SIZE), ParamArraySizeMatcher(VALID_EXTRA_SIZE - 1)))
        .Times(1);
    LNN_AUDIT(AUDIT_SCENE_DECRYPT_CONN_DATA, extra);
}
} // namespace OHOS
