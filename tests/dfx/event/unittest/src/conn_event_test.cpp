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

#include "conn_event.h"
#include "conn_hisysevent_matcher.h"
#include "hisysevent_mock.h"
#include "softbus_hisysevent_matcher.h"
#include "gtest/gtest.h"

using namespace std;
using namespace testing;
using namespace testing::ext;

namespace OHOS {
class ConnEventTest : public testing::Test { };
static ConnEventExtra g_validExtra = {
    .result = 1,
    .errcode = 2,
    .connectionId = 3,
    .requestId = 4,
    .linkType = 5,
    .authType = 6,
    .authId = 7,
    .lnnType = "testLnnType",
    .expectRole = 8,
    .costTime = 9,
    .rssi = 10,
    .load = 11,
    .frequency = 12,
    .connProtocol = 13,
    .connRole = 14,
    .connRcDelta = 15,
    .connRc = 16,
    .supportFeature = 17,
    .moduleId = 18,
    .proType = 19,
    .fd = 20,
    .cfd = 21,
    .challengeCode = "2024",
    .peerIp = "10.11.12.1",
    .peerBrMac = "dd-15-bc-b9-f2-04",
    .peerBleMac = "dd-15-bc-b9-f2-04",
    .peerWifiMac = "dd-15-bc-b9-f2-04",
    .peerPort = "testPeerPort",
    .peerNetworkId = "a8ynvpdaihw1f6nknjd2hkfhxljxypkr6kvjsbhnhpp16974uo4fvsrpfa6t50fm",
    .peerUdid = "testPeerUdid",
    .peerDeviceType = "testPeerDeviceType",
    .localNetworkId = "a8ynvpdaihw1f6nknjd2hkfhxljxypkr6kvjsbhnhpp16974uo4fvsrpfa6t50fm",
    .callerPkg = "testCallerPkg",
    .calleePkg = "testCalleePkg",
    .bootLinkType = 13,
    .isRenegotiate = 14,
    .isReuse = 15,
    .negotiateTime = 16,
    .linkTime = 17,
    .osType = 18,
    .localDeviceType = "loc********Type",
    .remoteDeviceType = "remo********Type",
    .p2pChannel = 19,
    .hmlChannel = 20,
    .staChannel = 21,
    .apChannel = 22,
    .peerDevVer = "peerDevVer",
    .remoteScreenStatus = 1,
    .businessType = 1,
    .businessId = 1,
    .timeout = 1,
    .fastestConnectEnable = 1,
    .coapDataChannel = 1,
    .enableWideBandwidth = 1,
    .p2pRole = 1,
    .needHmlConnect = 1,
    .businessTag = "test",
};

/**
 * @tc.name: ConnEventTest001
 * @tc.desc: Test conn event form size
 * @tc.type: FUNC
 * @tc.require: I8HA59
 */
HWTEST_F(ConnEventTest, ConnEventTest001, TestSize.Level0)
{
    constexpr int32_t VALID_EXTRA_SIZE = CONN_ASSIGNER_SIZE;

    HiSysEventMock mock;
    EXPECT_CALL(mock,
        HiSysEvent_Write(_, _, StrEq(SOFTBUS_EVENT_DOMAIN), StrEq(CONN_EVENT_NAME), Eq(SOFTBUS_EVENT_TYPE_BEHAVIOR), _,
            ParamArraySizeMatcher(VALID_EXTRA_SIZE)))
        .Times(1);
    CONN_EVENT(EVENT_SCENE_OPEN_CHANNEL, EVENT_STAGE_START_CONNECT, g_validExtra);
}

/**
 * @tc.name: ConnEventTest002
 * @tc.desc: Test all valid conn event form items
 * @tc.type: FUNC
 * @tc.require: I8HA59
 */
HWTEST_F(ConnEventTest, ConnEventTest002, TestSize.Level0)
{
    constexpr int32_t VALID_EXTRA_SIZE = CONN_ASSIGNER_SIZE;

    HiSysEventMock mock;
    EXPECT_CALL(mock,
        HiSysEvent_Write(_, _, StrEq(SOFTBUS_EVENT_DOMAIN), StrEq(CONN_EVENT_NAME), Eq(SOFTBUS_EVENT_TYPE_BEHAVIOR),
            ConnValidParamArrayMatcher(g_validExtra, VALID_EXTRA_SIZE), ParamArraySizeMatcher(VALID_EXTRA_SIZE)))
        .Times(1);
    CONN_EVENT(EVENT_SCENE_OPEN_CHANNEL, EVENT_STAGE_CONNECT_INVOKE_PROTOCOL, g_validExtra);
}

static ConnEventExtra g_invalidExtra = {
    .result = -1,  // valid
    .errcode = -2, // valid
    .connectionId = -3,
    .requestId = -4,
    .linkType = -5,
    .authType = -6,
    .authId = -7,
    .lnnType = "",
    .expectRole = -8,
    .costTime = -9,
    .rssi = -10,
    .load = -11,
    .frequency = -12,
    .connProtocol = -13,
    .connRole = -14,
    .connRcDelta = -15,
    .connRc = -16,
    .supportFeature = -17,
    .moduleId = -18,
    .proType = 19,
    .fd = -20,
    .cfd = -21,
    .challengeCode = "",
    .peerIp = "",
    .peerBrMac = "",
    .peerBleMac = "",
    .peerWifiMac = "\0",
    .peerPort = nullptr,
    .peerNetworkId = "",
    .peerUdid = "\0",
    .peerDeviceType = "\0",
    .localNetworkId = "",
    .callerPkg = "\0",
    .calleePkg = nullptr,
    .bootLinkType = -13,
    .isRenegotiate = -14,
    .isReuse = -15,
    .negotiateTime = 0,
    .linkTime = 0,
};

/**
 * @tc.name: ConnEventTest003
 * @tc.desc: Test all invalid conn event form items
 * @tc.type: FUNC
 * @tc.require: I8HA59
 */
HWTEST_F(ConnEventTest, ConnEventTest003, TestSize.Level0)
{
    constexpr int32_t TWO_VALID_EXTRA_SIZE = 2; // result, errcode is valid
    constexpr int32_t VALID_EXTRA_SIZE = 22;

    HiSysEventMock mock;
    EXPECT_CALL(mock,
        HiSysEvent_Write(_, _, StrEq(SOFTBUS_EVENT_DOMAIN), StrEq(CONN_EVENT_NAME), Eq(SOFTBUS_EVENT_TYPE_BEHAVIOR),
        ConnInvalidParamArrayMatcher(g_invalidExtra, TWO_VALID_EXTRA_SIZE), ParamArraySizeMatcher(VALID_EXTRA_SIZE)))
        .Times(1);
    CONN_EVENT(EVENT_SCENE_CONNECT, EVENT_STAGE_CONNECT_END, g_invalidExtra);
}

/**
 * @tc.name: ConnEventTest004
 * @tc.desc: Test empty conn event form
 * @tc.type: FUNC
 * @tc.require: I8HA59
 */
HWTEST_F(ConnEventTest, ConnEventTest004, TestSize.Level0)
{
    ConnEventExtra emptyExtra = { 0 };
    constexpr int32_t TWO_VALID_EXTRA_SIZE = 2; // result, errcode is valid
    constexpr int32_t VALID_EXTRA_SIZE = 22;

    HiSysEventMock mock;
    EXPECT_CALL(mock,
        HiSysEvent_Write(_, _, StrEq(SOFTBUS_EVENT_DOMAIN), StrEq(CONN_EVENT_NAME), Eq(SOFTBUS_EVENT_TYPE_BEHAVIOR),
            ConnInvalidParamArrayMatcher(emptyExtra, TWO_VALID_EXTRA_SIZE), ParamArraySizeMatcher(VALID_EXTRA_SIZE)))
        .Times(1);
    CONN_EVENT(EVENT_SCENE_CONNECT, EVENT_STAGE_CONNECT_START, emptyExtra);
}

static ConnAuditExtra g_extra = {
    .errcode = 1000,
    .auditType = AUDIT_EVENT_MSG_ERROR,
    .connectionId = 222,
    .requestId = 101,
    .linkType = 1,
    .expectRole = 9,
    .costTime = 999,
    .connectTimes = 3,
    .frequency = "3999",
    .challengeCode = "1",
    .peerBrMac = "11:22:33:44:55:66",
    .localBrMac = "12:22:23:33:33:91",
    .peerBleMac = "22:66:55:44:33:22",
    .localBleMac = "91:33:33:23:22:12",
    .peerDeviceType = "phone",
    .peerUdid = "aassddffggh565",
    .localUdid = "sqqqddffggh565",
    .connPayload = "100/3/14/588",
    .localDeviceName = "test_connection",
    .peerIp = "127.1.1.1",
    .localIp = "127.0.0.0",
    .callerPkg = "nearby",
    .calleePkg = "test_name",
    .peerPort = "3512",
    .localPort = "2484",
};

/**
 * @tc.name: ConnEventTest001
 * @tc.desc: Test conn event form size
 * @tc.type: FUNC
 * @tc.require: I8HA59
 */
HWTEST_F(ConnEventTest, ConnEventTest005, TestSize.Level0)
{
    constexpr int32_t VALID_EXTRA_SIZE = 25;

    HiSysEventMock mock;
    EXPECT_CALL(mock,
        HiSysEvent_Write(_, _, StrEq(SOFTBUS_EVENT_DOMAIN), StrEq(CONN_AUDIT_NAME), Eq(SOFTBUS_EVENT_TYPE_SECURITY),
            ConnAuditValidParamArrayMatcher(g_extra, VALID_EXTRA_SIZE), ParamArraySizeMatcher(VALID_EXTRA_SIZE)))
    .Times(1);
    CONN_AUDIT(AUDIT_SCENE_CONN_HML_GROUP_TIMEOUT, g_extra);
}

} // namespace OHOS
