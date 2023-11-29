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

#include "hilog_mock.h"
#include "trans_log.h"

using namespace std;
using namespace testing;
using namespace testing::ext;

namespace OHOS {
class TransLogTest : public testing::Test { };

/**
 * @tc.name: TransLogTest001
 * @tc.desc: Test SoftBusLogLabel is consistent with TransLogLabelEnum
 * @tc.type: FUNC
 * @tc.require: I8DW1W
 */
HWTEST_F(TransLogTest, TransLogTest001, TestSize.Level0)
{
    int32_t index = 0;
    int32_t transDomainBase = 0xd005740;

    EXPECT_EQ(index, TRANS_SDK);
    auto label = TRANS_LABELS[TRANS_SDK];
    EXPECT_EQ(index, TRANS_SDK);
    label = TRANS_LABELS[TRANS_SDK];
    EXPECT_EQ(TRANS_SDK, label.label);
    EXPECT_EQ(transDomainBase, label.domain);
    EXPECT_STREQ("TransSdk", label.tag);

    EXPECT_EQ(++index, TRANS_SVC);
    label = TRANS_LABELS[TRANS_SVC];
    EXPECT_EQ(TRANS_SVC, label.label);
    EXPECT_EQ(++transDomainBase, label.domain);
    EXPECT_STREQ("TransSvc", label.tag);

    EXPECT_EQ(++index, TRANS_INIT);
    label = TRANS_LABELS[TRANS_INIT];
    EXPECT_EQ(TRANS_INIT, label.label);
    EXPECT_EQ(++transDomainBase, label.domain);
    EXPECT_STREQ("TransInit", label.tag);

    EXPECT_EQ(++index, TRANS_CTRL);
    label = TRANS_LABELS[TRANS_CTRL];
    EXPECT_EQ(TRANS_CTRL, label.label);
    EXPECT_EQ(++transDomainBase, label.domain);
    EXPECT_STREQ("TransCtrl", label.tag);

    EXPECT_EQ(++index, TRANS_BYTES);
    label = TRANS_LABELS[TRANS_BYTES];
    EXPECT_EQ(TRANS_BYTES, label.label);
    EXPECT_EQ(++transDomainBase, label.domain);
    EXPECT_STREQ("TransBytes", label.tag);

    EXPECT_EQ(++index, TRANS_FILE);
    label = TRANS_LABELS[TRANS_FILE];
    EXPECT_EQ(TRANS_FILE, label.label);
    EXPECT_EQ(++transDomainBase, label.domain);
    EXPECT_STREQ("TransFile", label.tag);

    EXPECT_EQ(++index, TRANS_MSG);
    label = TRANS_LABELS[TRANS_MSG];
    EXPECT_EQ(TRANS_MSG, label.label);
    EXPECT_EQ(++transDomainBase, label.domain);
    EXPECT_STREQ("TransMsg", label.tag);

    EXPECT_EQ(++index, TRANS_STREAM);
    label = TRANS_LABELS[TRANS_STREAM];
    EXPECT_EQ(TRANS_STREAM, label.label);
    EXPECT_EQ(++transDomainBase, label.domain);
    EXPECT_STREQ("TransStream", label.tag);

    EXPECT_EQ(++index, TRANS_QOS);
    label = TRANS_LABELS[TRANS_QOS];
    EXPECT_EQ(TRANS_QOS, label.label);
    EXPECT_EQ(++transDomainBase, label.domain);
    EXPECT_STREQ("TransQos", label.tag);

    EXPECT_EQ(++index, TRANS_TEST);
    label = TRANS_LABELS[TRANS_TEST];
    EXPECT_EQ(TRANS_TEST, label.label);
    EXPECT_EQ(DOMAIN_ID_TEST, label.domain);
    EXPECT_STREQ("TransTest", label.tag);
}

/**
 * @tc.name: TransLogTest002
 * @tc.desc: Test TRANS_LOGD
 * @tc.type: FUNC
 * @tc.require: I8DW1W
 */
HWTEST_F(TransLogTest, TransLogTest002, TestSize.Level0)
{
    SoftBusLogLabel label = TRANS_LABELS[TRANS_TEST];
    HilogMock mock;
    EXPECT_CALL(mock, HiLogPrint(Eq(LOG_CORE), Eq(LOG_DEBUG), Eq(label.domain), StrEq(label.tag), _, _)).Times(1);
    TRANS_LOGD(TRANS_TEST, "test log");
}

/**
 * @tc.name: TransLogTest003
 * @tc.desc: Test TRANS_LOGI
 * @tc.type: FUNC
 * @tc.require: I8DW1W
 */
HWTEST_F(TransLogTest, TransLogTest003, TestSize.Level0)
{
    SoftBusLogLabel label = TRANS_LABELS[TRANS_TEST];
    HilogMock mock;
    EXPECT_CALL(mock, HiLogPrint(Eq(LOG_CORE), Eq(LOG_INFO), Eq(label.domain), StrEq(label.tag), _, _)).Times(1);
    TRANS_LOGI(TRANS_TEST, "test log");
}

/**
 * @tc.name: TransLogTest004
 * @tc.desc: Test TRANS_LOGW
 * @tc.type: FUNC
 * @tc.require: I8DW1W
 */
HWTEST_F(TransLogTest, TransLogTest004, TestSize.Level0)
{
    SoftBusLogLabel label = TRANS_LABELS[TRANS_TEST];
    HilogMock mock;
    EXPECT_CALL(mock, HiLogPrint(Eq(LOG_CORE), Eq(LOG_WARN), Eq(label.domain), StrEq(label.tag), _, _)).Times(1);
    TRANS_LOGW(TRANS_TEST, "test log");
}

/**
 * @tc.name: TransLogTest005
 * @tc.desc: Test TRANS_LOGE
 * @tc.type: FUNC
 * @tc.require: I8DW1W
 */
HWTEST_F(TransLogTest, TransLogTest005, TestSize.Level0)
{
    SoftBusLogLabel label = TRANS_LABELS[TRANS_TEST];
    HilogMock mock;
    EXPECT_CALL(mock, HiLogPrint(Eq(LOG_CORE), Eq(LOG_ERROR), Eq(label.domain), StrEq(label.tag), _, _)).Times(1);
    TRANS_LOGE(TRANS_TEST, "test log");
}

/**
 * @tc.name: TransLogTest006
 * @tc.desc: Test TRANS_LOGF
 * @tc.type: FUNC
 * @tc.require: I8DW1W
 */
HWTEST_F(TransLogTest, TransLogTest006, TestSize.Level0)
{
    SoftBusLogLabel label = TRANS_LABELS[TRANS_TEST];
    HilogMock mock;
    EXPECT_CALL(mock, HiLogPrint(Eq(LOG_CORE), Eq(LOG_FATAL), Eq(label.domain), StrEq(label.tag), _, _)).Times(1);
    TRANS_LOGF(TRANS_TEST, "test log");
}
} // namespace OHOS