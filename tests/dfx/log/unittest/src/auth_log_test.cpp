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

#include "auth_log.h"
#include "hilog_mock.h"
#include "softbus_log_test_utils.h"

using namespace std;
using namespace testing;
using namespace testing::ext;

namespace OHOS {
class AuthLogTest : public testing::Test { };

/**
 * @tc.name: AuthLogTest001
 * @tc.desc: Test SoftBusLogLabel is consistent with TransLogLabel
 * @tc.type: FUNC
 * @tc.require: I8DW1W
 */
HWTEST_F(AuthLogTest, AuthLogTest001, TestSize.Level0)
{
    int32_t index = 0;
    int32_t authDomainBase = 0xd005720;

    EXPECT_NO_FATAL_FAILURE(ExpectMatchSoftBusLogAttrs(AUTH_LABELS[index], AUTH_INIT, authDomainBase, "AuthInit"));
    EXPECT_NO_FATAL_FAILURE(ExpectMatchSoftBusLogAttrs(AUTH_LABELS[++index], AUTH_HICHAIN, ++authDomainBase,
        "AuthHiChain"));
    EXPECT_NO_FATAL_FAILURE(ExpectMatchSoftBusLogAttrs(AUTH_LABELS[++index], AUTH_CONN, ++authDomainBase, "AuthConn"));
    EXPECT_NO_FATAL_FAILURE(ExpectMatchSoftBusLogAttrs(AUTH_LABELS[++index], AUTH_FSM, ++authDomainBase, "AuthFsm"));
    EXPECT_NO_FATAL_FAILURE(ExpectMatchSoftBusLogAttrs(AUTH_LABELS[++index], AUTH_KEY, ++authDomainBase, "AuthKey"));
    EXPECT_NO_FATAL_FAILURE(ExpectMatchSoftBusLogAttrs(AUTH_LABELS[++index], AUTH_TEST, DOMAIN_ID_TEST, "AuthTest"));
}

/**
 * @tc.name: AuthLogTest002
 * @tc.desc: Test AUTH_LOGD
 * @tc.type: FUNC
 * @tc.require: I8DW1W
 */
HWTEST_F(AuthLogTest, AuthLogTest002, TestSize.Level0)
{
    SoftBusLogLabel label = AUTH_LABELS[AUTH_TEST];
    HilogMock mock;
    EXPECT_CALL(mock, HiLogPrint(Eq(LOG_CORE), Eq(LOG_DEBUG), Eq(label.domain), StrEq(label.tag), _, _))
        .Times(1);
    AUTH_LOGD(AUTH_TEST, "test log");
}

/**
 * @tc.name: AuthLogTest003
 * @tc.desc: Test AUTH_LOGI
 * @tc.type: FUNC
 * @tc.require: I8DW1W
 */
HWTEST_F(AuthLogTest, AuthLogTest003, TestSize.Level0)
{
    SoftBusLogLabel label = AUTH_LABELS[AUTH_TEST];
    HilogMock mock;
    EXPECT_CALL(mock, HiLogPrint(Eq(LOG_CORE), Eq(LOG_INFO), Eq(label.domain), StrEq(label.tag), _, _))
        .Times(1);
    AUTH_LOGI(AUTH_TEST, "test log");
}

/**
 * @tc.name: AuthLogTest004
 * @tc.desc: Test AUTH_LOGW
 * @tc.type: FUNC
 * @tc.require: I8DW1W
 */
HWTEST_F(AuthLogTest, AuthLogTest004, TestSize.Level0)
{
    SoftBusLogLabel label = AUTH_LABELS[AUTH_TEST];
    HilogMock mock;
    EXPECT_CALL(mock, HiLogPrint(Eq(LOG_CORE), Eq(LOG_WARN), Eq(label.domain), StrEq(label.tag), _, _))
        .Times(1);
    AUTH_LOGW(AUTH_TEST, "test log");
}

/**
 * @tc.name: AuthLogTest005
 * @tc.desc: Test AUTH_LOGE
 * @tc.type: FUNC
 * @tc.require: I8DW1W
 */
HWTEST_F(AuthLogTest, AuthLogTest005, TestSize.Level0)
{
    SoftBusLogLabel label = AUTH_LABELS[AUTH_TEST];
    HilogMock mock;
    EXPECT_CALL(mock, HiLogPrint(Eq(LOG_CORE), Eq(LOG_ERROR), Eq(label.domain), StrEq(label.tag), _, _))
        .Times(1);
    AUTH_LOGE(AUTH_TEST, "test log");
}

/**
 * @tc.name: AuthLogTest006
 * @tc.desc: Test AUTH_LOGF
 * @tc.type: FUNC
 * @tc.require: I8DW1W
 */
HWTEST_F(AuthLogTest, AuthLogTest006, TestSize.Level0)
{
    SoftBusLogLabel label = AUTH_LABELS[AUTH_TEST];
    HilogMock mock;
    EXPECT_CALL(mock, HiLogPrint(Eq(LOG_CORE), Eq(LOG_FATAL), Eq(label.domain), StrEq(label.tag), _, _))
        .Times(1);
    AUTH_LOGF(AUTH_TEST, "test log");
}
} // namespace OHOS
