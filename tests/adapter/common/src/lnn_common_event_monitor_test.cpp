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
 
#include <securec.h>
 
#include "bus_center_client_proxy.h"
#include "common_event_data.h"
#include "lnn_common_event_mock.h"
#include "lnn_common_event_monitor.cpp"
#include "lnn_wifiservice_monitor_mock.cpp"
#include "softbus_error_code.h"
#include "gtest/gtest.h"
 
namespace OHOS {
using namespace testing;
using namespace testing::ext;
static const std::string EVENT_DSOFTBUS_D2D_STATE_CHANGE = "usual.event.DSOFTBUS_D2D_STATE_CHANGE";
static const std::string EVENT_NEARLINK_HOST_DATA_TRANSFER_UPDATE = "usual.event.nearlink.host.DATA_TRANSFER_UPDATE";
static const std::string EVENT_NEARLINK_HOST_RANGING_UPDATE = "usual.event.nearlink.host.RANGING_UPDATE";
static const std::string SLE_D2D_PAGING_ADV_STATE = "d2d.paging.advertise";
static const std::string SLE_D2D_GROUP_ADV_STATE = "d2d.group.advertise";
static const std::string KEY_PARAM_STATE = "state";
static const std::string EVENT_INVALID_STATE = "invalid.event";
 
class LnnCommonEventMonitorTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};
 
void LnnCommonEventMonitorTest::SetUpTestCase()
{
    GTEST_LOG_(INFO) << "LnnCommonEventMonitorTest start";
}
 
void LnnCommonEventMonitorTest::TearDownTestCase()
{
    GTEST_LOG_(INFO) << "LnnCommonEventMonitorTest end";
}
 
void LnnCommonEventMonitorTest::SetUp() { }
 
void LnnCommonEventMonitorTest::TearDown() { }
 
/*
 * @tc.name: LNN_OnReceiveSleEvent_001
 * @tc.desc: check sle common event D2D
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LnnCommonEventMonitorTest, LNN_OnReceiveSleEvent_001, TestSize.Level1)
{
    OHOS::AAFwk::Want want;
    want.SetAction(EVENT_DSOFTBUS_D2D_STATE_CHANGE);
    want.SetParam(SLE_D2D_PAGING_ADV_STATE, OPEN_D2D);
    EventFwk::CommonEventData data;
    data.SetWant(want);
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EVENT_DSOFTBUS_D2D_STATE_CHANGE);
    EventFwk::CommonEventSubscribeInfo subscriberInfo(matchingSkills);
    EventFwk::CommonEventMonitor eventSubscriber(subscriberInfo);
    EXPECT_NO_FATAL_FAILURE(eventSubscriber.OnReceiveEvent(data));
}
 
/*
 * @tc.name: LNN_OnReceiveSleEvent_002
 * @tc.desc: check sle common event
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LnnCommonEventMonitorTest, LNN_OnReceiveSleEvent_002, TestSize.Level1)
{
    OHOS::AAFwk::Want want;
    want.SetAction(EVENT_DSOFTBUS_D2D_STATE_CHANGE);
    want.SetParam(SLE_D2D_PAGING_ADV_STATE, 0);
    want.SetParam(SLE_D2D_GROUP_ADV_STATE, OPEN_D2D);
    EventFwk::CommonEventData data;
    data.SetWant(want);
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EVENT_DSOFTBUS_D2D_STATE_CHANGE);
    EventFwk::CommonEventSubscribeInfo subscriberInfo(matchingSkills);
    EventFwk::CommonEventMonitor eventSubscriber(subscriberInfo);
    EXPECT_NO_FATAL_FAILURE(eventSubscriber.OnReceiveEvent(data));
}
 
/*
 * @tc.name: LNN_OnReceiveSleEvent_003
 * @tc.desc: check sle common event
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LnnCommonEventMonitorTest, LNN_OnReceiveSleEvent_003, TestSize.Level1)
{
    OHOS::AAFwk::Want want;
    want.SetAction(EVENT_NEARLINK_HOST_DATA_TRANSFER_UPDATE);
    want.SetParam(KEY_PARAM_STATE, 1);
 
    EventFwk::CommonEventData data;
    data.SetWant(want);
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EVENT_NEARLINK_HOST_DATA_TRANSFER_UPDATE);
    EventFwk::CommonEventSubscribeInfo subscriberInfo(matchingSkills);
    EventFwk::CommonEventMonitor eventSubscriber(subscriberInfo);
    EXPECT_NO_FATAL_FAILURE(eventSubscriber.OnReceiveEvent(data));
}
 
/*
 * @tc.name: LNN_OnReceiveSleEvent_004
 * @tc.desc: check sle common event
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LnnCommonEventMonitorTest, LNN_OnReceiveSleEvent_004, TestSize.Level1)
{
    OHOS::AAFwk::Want want;
    want.SetAction(EVENT_NEARLINK_HOST_RANGING_UPDATE);
    want.SetParam(KEY_PARAM_STATE, 1);
 
    EventFwk::CommonEventData data;
    data.SetWant(want);
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EVENT_NEARLINK_HOST_RANGING_UPDATE);
    EventFwk::CommonEventSubscribeInfo subscriberInfo(matchingSkills);
    EventFwk::CommonEventMonitor eventSubscriber(subscriberInfo);
    EXPECT_NO_FATAL_FAILURE(eventSubscriber.OnReceiveEvent(data));
}
 
/*
 * @tc.name: LNN_OnReceiveSleEvent_005
 * @tc.desc: check sle common event
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LnnCommonEventMonitorTest, LNN_OnReceiveSleEvent_005, TestSize.Level1)
{
    OHOS::AAFwk::Want want;
    want.SetAction(EVENT_INVALID_STATE);
 
    EventFwk::CommonEventData data;
    data.SetWant(want);
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EVENT_INVALID_STATE);
    EventFwk::CommonEventSubscribeInfo subscriberInfo(matchingSkills);
    EventFwk::CommonEventMonitor eventSubscriber(subscriberInfo);
    EXPECT_NO_FATAL_FAILURE(eventSubscriber.OnReceiveEvent(data));
}
} // namespace OHOS