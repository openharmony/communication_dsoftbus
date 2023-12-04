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

#include "comm_log.h"
#include "hilog_mock.h"

using namespace std;
using namespace testing;
using namespace testing::ext;

namespace OHOS {
class CommLogTest : public testing::Test { };

/**
 * @tc.name: CommLogTest001
 * @tc.desc: Test SoftBusLogLabel is consistent with CommLogLabelEnum
 * @tc.type: FUNC
 * @tc.require: I8DW1W
 */
HWTEST_F(CommLogTest, CommLogTest001, TestSize.Level0)
{
    int32_t index = 0;
    int32_t authDomainBase = 0xd005700;

    EXPECT_EQ(index, COMM_SDK);
    auto label = COMM_LABELS[COMM_SDK];
    EXPECT_EQ(COMM_SDK, label.label);
    EXPECT_EQ(authDomainBase, label.domain);
    EXPECT_STREQ("CommSdk", label.tag);

    EXPECT_EQ(++index, COMM_SVC);
    label = COMM_LABELS[COMM_SVC];
    EXPECT_EQ(COMM_SVC, label.label);
    EXPECT_EQ(++authDomainBase, label.domain);
    EXPECT_STREQ("CommSvc", label.tag);

    EXPECT_EQ(++index, COMM_INIT);
    label = COMM_LABELS[COMM_INIT];
    EXPECT_EQ(COMM_INIT, label.label);
    EXPECT_EQ(++authDomainBase, label.domain);
    EXPECT_STREQ("CommInit", label.tag);

    EXPECT_EQ(++index, COMM_DFX);
    label = COMM_LABELS[COMM_DFX];
    EXPECT_EQ(COMM_DFX, label.label);
    EXPECT_EQ(++authDomainBase, label.domain);
    EXPECT_STREQ("CommDfx", label.tag);

    EXPECT_EQ(++index, COMM_EVENT);
    label = COMM_LABELS[COMM_EVENT];
    EXPECT_EQ(COMM_EVENT, label.label);
    EXPECT_EQ(++authDomainBase, label.domain);
    EXPECT_STREQ("CommEvent", label.tag);

    EXPECT_EQ(++index, COMM_VERIFY);
    label = COMM_LABELS[COMM_VERIFY];
    EXPECT_EQ(COMM_VERIFY, label.label);
    EXPECT_EQ(++authDomainBase, label.domain);
    EXPECT_STREQ("CommVerify", label.tag);

    EXPECT_EQ(++index, COMM_PERM);
    label = COMM_LABELS[COMM_PERM];
    EXPECT_EQ(COMM_PERM, label.label);
    EXPECT_EQ(++authDomainBase, label.domain);
    EXPECT_STREQ("CommPerm", label.tag);

    EXPECT_EQ(++index, COMM_UTILS);
    label = COMM_LABELS[COMM_UTILS];
    EXPECT_EQ(COMM_UTILS, label.label);
    EXPECT_EQ(++authDomainBase, label.domain);
    EXPECT_STREQ("CommUtils", label.tag);

    EXPECT_EQ(++index, COMM_ADAPTER);
    label = COMM_LABELS[COMM_ADAPTER];
    EXPECT_EQ(COMM_ADAPTER, label.label);
    EXPECT_EQ(++authDomainBase, label.domain);
    EXPECT_STREQ("CommAdapter", label.tag);

    EXPECT_EQ(++index, COMM_TEST);
    label = COMM_LABELS[COMM_TEST];
    EXPECT_EQ(COMM_TEST, label.label);
    EXPECT_EQ(DOMAIN_ID_TEST, label.domain);
    EXPECT_STREQ("CommTest", label.tag);
}

/**
 * @tc.name: CommLogTest002
 * @tc.desc: Test COMM_LOGD
 * @tc.type: FUNC
 * @tc.require: I8DW1W
 */
HWTEST_F(CommLogTest, CommLogTest002, TestSize.Level0)
{
    SoftBusLogLabel label = COMM_LABELS[COMM_TEST];
    HilogMock mock;
    EXPECT_CALL(mock, HiLogPrint(Eq(LOG_CORE), Eq(LOG_DEBUG), Eq(label.domain), StrEq(label.tag), _, _)).Times(1);
    COMM_LOGD(COMM_TEST, "test log");
}

/**
 * @tc.name: CommLogTest003
 * @tc.desc: Test COMM_LOGI
 * @tc.type: FUNC
 * @tc.require: I8DW1W
 */
HWTEST_F(CommLogTest, CommLogTest003, TestSize.Level0)
{
    SoftBusLogLabel label = COMM_LABELS[COMM_TEST];
    HilogMock mock;
    EXPECT_CALL(mock, HiLogPrint(Eq(LOG_CORE), Eq(LOG_INFO), Eq(label.domain), StrEq(label.tag), _, _)).Times(1);
    COMM_LOGI(COMM_TEST, "test log");
}

/**
 * @tc.name: CommLogTest004
 * @tc.desc: Test COMM_LOGW
 * @tc.type: FUNC
 * @tc.require: I8DW1W
 */
HWTEST_F(CommLogTest, CommLogTest004, TestSize.Level0)
{
    SoftBusLogLabel label = COMM_LABELS[COMM_TEST];
    HilogMock mock;
    EXPECT_CALL(mock, HiLogPrint(Eq(LOG_CORE), Eq(LOG_WARN), Eq(label.domain), StrEq(label.tag), _, _)).Times(1);
    COMM_LOGW(COMM_TEST, "test log");
}

/**
 * @tc.name: CommLogTest005
 * @tc.desc: Test COMM_LOGE
 * @tc.type: FUNC
 * @tc.require: I8DW1W
 */
HWTEST_F(CommLogTest, CommLogTest005, TestSize.Level0)
{
    SoftBusLogLabel label = COMM_LABELS[COMM_TEST];
    HilogMock mock;
    EXPECT_CALL(mock, HiLogPrint(Eq(LOG_CORE), Eq(LOG_ERROR), Eq(label.domain), StrEq(label.tag), _, _)).Times(1);
    COMM_LOGE(COMM_TEST, "test log");
}

/**
 * @tc.name: CommLogTest006
 * @tc.desc: Test COMM_LOGF
 * @tc.type: FUNC
 * @tc.require: I8DW1W
 */
HWTEST_F(CommLogTest, CommLogTest006, TestSize.Level0)
{
    SoftBusLogLabel label = COMM_LABELS[COMM_TEST];
    HilogMock mock;
    EXPECT_CALL(mock, HiLogPrint(Eq(LOG_CORE), Eq(LOG_FATAL), Eq(label.domain), StrEq(label.tag), _, _)).Times(1);
    COMM_LOGF(COMM_TEST, "test log");
}
} // namespace OHOS