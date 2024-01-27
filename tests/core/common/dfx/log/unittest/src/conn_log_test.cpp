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

    EXPECT_EQ(index, CONN_INIT);
    auto label = CONN_LABELS[CONN_INIT];
    EXPECT_EQ(CONN_INIT, label.label);
    EXPECT_EQ(connDomainBase, label.domain);
    EXPECT_STREQ("ConnInit", label.tag);

    EXPECT_EQ(++index, CONN_BLE);
    label = CONN_LABELS[CONN_BLE];
    EXPECT_EQ(CONN_BLE, label.label);
    EXPECT_EQ(++connDomainBase, label.domain);
    EXPECT_STREQ("ConnBle", label.tag);

    EXPECT_EQ(++index, CONN_BR);
    label = CONN_LABELS[CONN_BR];
    EXPECT_EQ(CONN_BR, label.label);
    EXPECT_EQ(++connDomainBase, label.domain);
    EXPECT_STREQ("ConnBr", label.tag);

    EXPECT_EQ(++index, CONN_COMMON);
    label = CONN_LABELS[CONN_COMMON];
    EXPECT_EQ(CONN_COMMON, label.label);
    EXPECT_EQ(++connDomainBase, label.domain);
    EXPECT_STREQ("ConnCommon", label.tag);

    EXPECT_EQ(++index, CONN_WIFI_DIRECT);
    label = CONN_LABELS[CONN_WIFI_DIRECT];
    EXPECT_EQ(CONN_WIFI_DIRECT, label.label);
    EXPECT_EQ(++connDomainBase, label.domain);
    EXPECT_STREQ("ConnWD", label.tag);

    EXPECT_EQ(++index, CONN_NEARBY);
    label = CONN_LABELS[CONN_NEARBY];
    EXPECT_EQ(CONN_NEARBY, label.label);
    EXPECT_EQ(++connDomainBase, label.domain);
    EXPECT_STREQ("ConnNearby", label.tag);

    EXPECT_EQ(++index, CONN_BLE_DIRECT);
    label = CONN_LABELS[CONN_BLE_DIRECT];
    EXPECT_EQ(CONN_BLE_DIRECT, label.label);
    EXPECT_EQ(++connDomainBase, label.domain);
    EXPECT_STREQ("ConnBD", label.tag);

    EXPECT_EQ(++index, CONN_BROADCAST);
    label = CONN_LABELS[CONN_BROADCAST];
    EXPECT_EQ(CONN_BROADCAST, label.label);
    EXPECT_EQ(++connDomainBase, label.domain);
    EXPECT_STREQ("ConnBC", label.tag);

    EXPECT_EQ(++index, CONN_BLE_DIRECT);
    label = CONN_LABELS[CONN_BLE_DIRECT];
    EXPECT_EQ(CONN_BLE_DIRECT, label.label);
    EXPECT_EQ(++connDomainBase, label.domain);
    EXPECT_STREQ("ConnBD", label.tag);

    EXPECT_EQ(++index, CONN_BROADCAST);
    label = CONN_LABELS[CONN_BROADCAST];
    EXPECT_EQ(CONN_BROADCAST, label.label);
    EXPECT_EQ(++connDomainBase, label.domain);
    EXPECT_STREQ("ConnBC", label.tag);

    EXPECT_EQ(++index, CONN_NEWIP);
    label = CONN_LABELS[CONN_NEWIP];
    EXPECT_EQ(CONN_NEWIP, label.label);
    EXPECT_EQ(++connDomainBase, label.domain);
    EXPECT_STREQ("ConnNewIp", label.tag);

    EXPECT_EQ(++index, CONN_TEST);
    label = CONN_LABELS[CONN_TEST];
    EXPECT_EQ(CONN_TEST, label.label);
    EXPECT_EQ(DOMAIN_ID_TEST, label.domain);
    EXPECT_STREQ("ConnTest", label.tag);
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