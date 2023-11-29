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

    EXPECT_EQ(index, LNN_INIT);
    auto label = LNN_LABELS[LNN_INIT];
    EXPECT_EQ(LNN_INIT, label.label);
    EXPECT_EQ(lnnDomainBase, label.domain);
    EXPECT_STREQ("LnnInit", label.tag);

    EXPECT_EQ(++index, LNN_HEART_BEAT);
    label = LNN_LABELS[LNN_HEART_BEAT];
    EXPECT_EQ(LNN_HEART_BEAT, label.label);
    EXPECT_EQ(++lnnDomainBase, label.domain);
    EXPECT_STREQ("LnnHeartBeat", label.tag);

    EXPECT_EQ(++index, LNN_LEDGER);
    label = LNN_LABELS[LNN_LEDGER];
    EXPECT_EQ(LNN_LEDGER, label.label);
    EXPECT_EQ(++lnnDomainBase, label.domain);
    EXPECT_STREQ("LnnLedger", label.tag);

    EXPECT_EQ(++index, LNN_BUILDER);
    label = LNN_LABELS[LNN_BUILDER];
    EXPECT_EQ(LNN_BUILDER, label.label);
    EXPECT_EQ(++lnnDomainBase, label.domain);
    EXPECT_STREQ("LnnBuilder", label.tag);

    EXPECT_EQ(++index, LNN_LANE);
    label = LNN_LABELS[LNN_LANE];
    EXPECT_EQ(LNN_LANE, label.label);
    EXPECT_EQ(++lnnDomainBase, label.domain);
    EXPECT_STREQ("LnnLane", label.tag);

    EXPECT_EQ(++index, LNN_QOS);
    label = LNN_LABELS[LNN_QOS];
    EXPECT_EQ(LNN_QOS, label.label);
    EXPECT_EQ(++lnnDomainBase, label.domain);
    EXPECT_STREQ("LnnQos", label.tag);

    EXPECT_EQ(++index, LNN_EVENT);
    label = LNN_LABELS[LNN_EVENT];
    EXPECT_EQ(LNN_EVENT, label.label);
    EXPECT_EQ(++lnnDomainBase, label.domain);
    EXPECT_STREQ("LnnEvent", label.tag);

    EXPECT_EQ(++index, LNN_STATE);
    label = LNN_LABELS[LNN_STATE];
    EXPECT_EQ(LNN_STATE, label.label);
    EXPECT_EQ(++lnnDomainBase, label.domain);
    EXPECT_STREQ("LnnState", label.tag);

    EXPECT_EQ(++index, LNN_META_NODE);
    label = LNN_LABELS[LNN_META_NODE];
    EXPECT_EQ(LNN_META_NODE, label.label);
    EXPECT_EQ(++lnnDomainBase, label.domain);
    EXPECT_STREQ("LnnMetaNode", label.tag);

    EXPECT_EQ(++index, LNN_CLOCK);
    label = LNN_LABELS[LNN_CLOCK];
    EXPECT_EQ(LNN_CLOCK, label.label);
    EXPECT_EQ(++lnnDomainBase, label.domain);
    EXPECT_STREQ("LnnClock", label.tag);

    EXPECT_EQ(++index, LNN_TEST);
    label = LNN_LABELS[LNN_TEST];
    EXPECT_EQ(LNN_TEST, label.label);
    EXPECT_EQ(DOMAIN_ID_TEST, label.domain);
    EXPECT_STREQ("LnnTest", label.tag);
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