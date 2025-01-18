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

#include <gmock/gmock-matchers.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <string>

#include "lnn_log.h"
#include "hilog_mock.h"
#include "softbus_log_test_utils.h"

using namespace std;
using namespace testing;
using namespace testing::ext;

namespace OHOS {
class LnnLogTest : public testing::Test { };

/**
 * @tc.name: LnnLogTest001
 * @tc.desc: Test SoftBusLogLabel is consistent with TransLogLabelEnum
 * @tc.type: FUNC
 * @tc.require: I8DW1W
 */
HWTEST_F(LnnLogTest, LnnLogTest001, TestSize.Level0)
{
    int32_t index = 0;
    int32_t lnnDomainBase = 0xd005780;

    EXPECT_NO_FATAL_FAILURE(
        ExpectMatchSoftBusLogAttrs(LNN_LABELS[index], LNN_INIT, lnnDomainBase, "LnnInit"));
    EXPECT_NO_FATAL_FAILURE(
        ExpectMatchSoftBusLogAttrs(LNN_LABELS[++index], LNN_HEART_BEAT, ++lnnDomainBase, "LnnHeartBeat"));
    EXPECT_NO_FATAL_FAILURE(
        ExpectMatchSoftBusLogAttrs(LNN_LABELS[++index], LNN_LEDGER, ++lnnDomainBase, "LnnLedger"));
    EXPECT_NO_FATAL_FAILURE(
        ExpectMatchSoftBusLogAttrs(LNN_LABELS[++index], LNN_BUILDER, ++lnnDomainBase, "LnnBuilder"));
    EXPECT_NO_FATAL_FAILURE(
        ExpectMatchSoftBusLogAttrs(LNN_LABELS[++index], LNN_LANE, ++lnnDomainBase, "LnnLane"));
    EXPECT_NO_FATAL_FAILURE(
        ExpectMatchSoftBusLogAttrs(LNN_LABELS[++index], LNN_QOS, ++lnnDomainBase, "LnnQos"));
    EXPECT_NO_FATAL_FAILURE(
        ExpectMatchSoftBusLogAttrs(LNN_LABELS[++index], LNN_EVENT, ++lnnDomainBase, "LnnEvent"));
    EXPECT_NO_FATAL_FAILURE(
        ExpectMatchSoftBusLogAttrs(LNN_LABELS[++index], LNN_STATE, ++lnnDomainBase, "LnnState"));
    EXPECT_NO_FATAL_FAILURE(
        ExpectMatchSoftBusLogAttrs(LNN_LABELS[++index], LNN_META_NODE, ++lnnDomainBase, "LnnMetaNode"));
    EXPECT_NO_FATAL_FAILURE(
        ExpectMatchSoftBusLogAttrs(LNN_LABELS[++index], LNN_CLOCK, ++lnnDomainBase, "LnnClock"));
    EXPECT_NO_FATAL_FAILURE(
        ExpectMatchSoftBusLogAttrs(LNN_LABELS[++index], LNN_TEST, DOMAIN_ID_TEST, "LnnTest"));
}

/**
 * @tc.name: LnnLogTest002
 * @tc.desc: Test LNN_LOGD
 * @tc.type: FUNC
 * @tc.require: I8DW1W
 */
HWTEST_F(LnnLogTest, LnnLogTest002, TestSize.Level0)
{
    SoftBusLogLabel label = LNN_LABELS[LNN_TEST];
    HilogMock mock;
    EXPECT_CALL(mock, HiLogPrint(Eq(LOG_CORE), Eq(LOG_DEBUG), Eq(label.domain), StrEq(label.tag), _, _))
        .Times(1);
    LNN_LOGD(LNN_TEST, "test log");
}

/**
 * @tc.name: LnnLogTest003
 * @tc.desc: Test LNN_LOGI
 * @tc.type: FUNC
 * @tc.require: I8DW1W
 */
HWTEST_F(LnnLogTest, LnnLogTest003, TestSize.Level0)
{
    SoftBusLogLabel label = LNN_LABELS[LNN_TEST];
    HilogMock mock;
    EXPECT_CALL(mock, HiLogPrint(Eq(LOG_CORE), Eq(LOG_INFO), Eq(label.domain), StrEq(label.tag), _, _))
        .Times(1);
    LNN_LOGI(LNN_TEST, "test log");
}

/**
 * @tc.name: LnnLogTest004
 * @tc.desc: Test LNN_LOGW
 * @tc.type: FUNC
 * @tc.require: I8DW1W
 */
HWTEST_F(LnnLogTest, LnnLogTest004, TestSize.Level0)
{
    SoftBusLogLabel label = LNN_LABELS[LNN_TEST];
    HilogMock mock;
    EXPECT_CALL(mock, HiLogPrint(Eq(LOG_CORE), Eq(LOG_WARN), Eq(label.domain), StrEq(label.tag), _, _))
        .Times(1);
    LNN_LOGW(LNN_TEST, "test log");
}

/**
 * @tc.name: LnnLogTest005
 * @tc.desc: Test LNN_LOGE
 * @tc.type: FUNC
 * @tc.require: I8DW1W
 */
HWTEST_F(LnnLogTest, LnnLogTest005, TestSize.Level0)
{
    SoftBusLogLabel label = LNN_LABELS[LNN_TEST];
    HilogMock mock;
    EXPECT_CALL(mock, HiLogPrint(Eq(LOG_CORE), Eq(LOG_ERROR), Eq(label.domain), StrEq(label.tag), _, _))
        .Times(1);
    LNN_LOGE(LNN_TEST, "test log");
}

/**
 * @tc.name: LnnLogTest006
 * @tc.desc: Test LNN_LOGF
 * @tc.type: FUNC
 * @tc.require: I8DW1W
 */
HWTEST_F(LnnLogTest, LnnLogTest006, TestSize.Level0)
{
    SoftBusLogLabel label = LNN_LABELS[LNN_TEST];
    HilogMock mock;
    EXPECT_CALL(mock, HiLogPrint(Eq(LOG_CORE), Eq(LOG_FATAL), Eq(label.domain), StrEq(label.tag), _, _))
        .Times(1);
    LNN_LOGF(LNN_TEST, "test log");
}
} // namespace OHOS
