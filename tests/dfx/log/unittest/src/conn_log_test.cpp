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

#include "conn_log.h"
#include "hilog_mock.h"
#include "softbus_log_test_utils.h"

using namespace std;
using namespace testing;
using namespace testing::ext;

namespace OHOS {
class ConnLogTest : public testing::Test { };

/**
 * @tc.name: ConnLogTest001
 * @tc.desc: Test SoftBusLogLabel is consistent with ConnLogLabelEnum
 * @tc.type: FUNC
 * @tc.require: I8DW1W
 */
HWTEST_F(ConnLogTest, ConnLogTest001, TestSize.Level0)
{
    int32_t index = 0;
    int32_t connDomainBase = 0xd005760;

    EXPECT_NO_FATAL_FAILURE(ExpectMatchSoftBusLogAttrs(CONN_LABELS[index], CONN_INIT, connDomainBase, "ConnInit"));
    EXPECT_NO_FATAL_FAILURE(ExpectMatchSoftBusLogAttrs(CONN_LABELS[++index], CONN_BLE, ++connDomainBase, "ConnBle"));
    EXPECT_NO_FATAL_FAILURE(ExpectMatchSoftBusLogAttrs(CONN_LABELS[++index], CONN_BR, ++connDomainBase, "ConnBr"));
    EXPECT_NO_FATAL_FAILURE(ExpectMatchSoftBusLogAttrs(CONN_LABELS[++index], CONN_COMMON, ++connDomainBase,
        "ConnCommon"));
    EXPECT_NO_FATAL_FAILURE(ExpectMatchSoftBusLogAttrs(CONN_LABELS[++index], CONN_WIFI_DIRECT, ++connDomainBase,
        "ConnWD"));
    EXPECT_NO_FATAL_FAILURE(ExpectMatchSoftBusLogAttrs(CONN_LABELS[++index], CONN_NEARBY, ++connDomainBase,
        "ConnNearby"));
    EXPECT_NO_FATAL_FAILURE(ExpectMatchSoftBusLogAttrs(CONN_LABELS[++index], CONN_BLE_DIRECT, ++connDomainBase,
        "ConnBD"));
    EXPECT_NO_FATAL_FAILURE(ExpectMatchSoftBusLogAttrs(CONN_LABELS[++index], CONN_BROADCAST, ++connDomainBase,
        "ConnBC"));
    EXPECT_NO_FATAL_FAILURE(ExpectMatchSoftBusLogAttrs(CONN_LABELS[++index], CONN_NEWIP, ++connDomainBase,
        "ConnNewIp"));
    EXPECT_NO_FATAL_FAILURE(ExpectMatchSoftBusLogAttrs(CONN_LABELS[++index], CONN_ACTION, ++connDomainBase,
        "ConnAction"));
    EXPECT_NO_FATAL_FAILURE(ExpectMatchSoftBusLogAttrs(CONN_LABELS[++index], CONN_TEST, DOMAIN_ID_TEST, "ConnTest"));
}

/**
 * @tc.name: ConnLogTest002
 * @tc.desc: Test CONN_LOGD
 * @tc.type: FUNC
 * @tc.require: I8DW1W
 */
HWTEST_F(ConnLogTest, ConnLogTest002, TestSize.Level0)
{
    SoftBusLogLabel label = CONN_LABELS[CONN_TEST];
    HilogMock mock;
    EXPECT_CALL(mock, HiLogPrint(Eq(LOG_CORE), Eq(LOG_DEBUG), Eq(label.domain), StrEq(label.tag), _, _))
        .Times(1);
    CONN_LOGD(CONN_TEST, "test log");
}

/**
 * @tc.name: ConnLogTest003
 * @tc.desc: Test CONN_LOGI
 * @tc.type: FUNC
 * @tc.require: I8DW1W
 */
HWTEST_F(ConnLogTest, ConnLogTest003, TestSize.Level0)
{
    SoftBusLogLabel label = CONN_LABELS[CONN_TEST];
    HilogMock mock;
    EXPECT_CALL(mock, HiLogPrint(Eq(LOG_CORE), Eq(LOG_INFO), Eq(label.domain), StrEq(label.tag), _, _))
        .Times(1);
    CONN_LOGI(CONN_TEST, "test log");
}

/**
 * @tc.name: ConnLogTest004
 * @tc.desc: Test CONN_LOGW
 * @tc.type: FUNC
 * @tc.require: I8DW1W
 */
HWTEST_F(ConnLogTest, ConnLogTest004, TestSize.Level0)
{
    SoftBusLogLabel label = CONN_LABELS[CONN_TEST];
    HilogMock mock;
    EXPECT_CALL(mock, HiLogPrint(Eq(LOG_CORE), Eq(LOG_WARN), Eq(label.domain), StrEq(label.tag), _, _))
        .Times(1);
    CONN_LOGW(CONN_TEST, "test log");
}

/**
 * @tc.name: ConnLogTest005
 * @tc.desc: Test CONN_LOGE
 * @tc.type: FUNC
 * @tc.require: I8DW1W
 */
HWTEST_F(ConnLogTest, ConnLogTest005, TestSize.Level0)
{
    SoftBusLogLabel label = CONN_LABELS[CONN_TEST];
    HilogMock mock;
    EXPECT_CALL(mock, HiLogPrint(Eq(LOG_CORE), Eq(LOG_ERROR), Eq(label.domain), StrEq(label.tag), _, _))
        .Times(1);
    CONN_LOGE(CONN_TEST, "test log");
}

/**
 * @tc.name: ConnLogTest006
 * @tc.desc: Test CONN_LOGF
 * @tc.type: FUNC
 * @tc.require: I8DW1W
 */
HWTEST_F(ConnLogTest, ConnLogTest006, TestSize.Level0)
{
    SoftBusLogLabel label = CONN_LABELS[CONN_TEST];
    HilogMock mock;
    EXPECT_CALL(mock, HiLogPrint(Eq(LOG_CORE), Eq(LOG_FATAL), Eq(label.domain), StrEq(label.tag), _, _))
        .Times(1);
    CONN_LOGF(CONN_TEST, "test log");
}
} // namespace OHOS
