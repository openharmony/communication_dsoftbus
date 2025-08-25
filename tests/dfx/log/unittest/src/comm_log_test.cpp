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
#include "softbus_log_test_utils.h"

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
    int32_t commDomainBase = 0xd005700;

    EXPECT_NO_FATAL_FAILURE(ExpectMatchSoftBusLogAttrs(COMM_LABELS[index], COMM_SDK, commDomainBase, "CommSdk"));
    EXPECT_NO_FATAL_FAILURE(ExpectMatchSoftBusLogAttrs(COMM_LABELS[++index], COMM_SVC, ++commDomainBase, "CommSvc"));
    EXPECT_NO_FATAL_FAILURE(ExpectMatchSoftBusLogAttrs(COMM_LABELS[++index], COMM_INIT, ++commDomainBase, "CommInit"));
    EXPECT_NO_FATAL_FAILURE(ExpectMatchSoftBusLogAttrs(COMM_LABELS[++index], COMM_DFX, ++commDomainBase, "CommDfx"));
    EXPECT_NO_FATAL_FAILURE(ExpectMatchSoftBusLogAttrs(COMM_LABELS[++index],
        COMM_EVENT, ++commDomainBase, "CommEvent"));
    EXPECT_NO_FATAL_FAILURE(ExpectMatchSoftBusLogAttrs(COMM_LABELS[++index],
        COMM_VERIFY, ++commDomainBase, "CommVerify"));
    EXPECT_NO_FATAL_FAILURE(ExpectMatchSoftBusLogAttrs(COMM_LABELS[++index], COMM_PERM, ++commDomainBase, "CommPerm"));
    EXPECT_NO_FATAL_FAILURE(ExpectMatchSoftBusLogAttrs(COMM_LABELS[++index],
        COMM_UTILS, ++commDomainBase, "CommUtils"));
    EXPECT_NO_FATAL_FAILURE(ExpectMatchSoftBusLogAttrs(COMM_LABELS[++index],
        COMM_ADAPTER, ++commDomainBase, "CommAdapter"));
    EXPECT_NO_FATAL_FAILURE(ExpectMatchSoftBusLogAttrs(COMM_LABELS[++index], COMM_TEST, DOMAIN_ID_TEST, "CommTest"));
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
