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
#include "softbus_log_test_utils.h"

using namespace std;
using namespace testing;
using namespace testing::ext;

namespace OHOS {
class TransLogTest : public testing::Test { };

/**
 * @tc.name: TransLogTest001
 * @tc.desc: Test TRANS_LOGD
 * @tc.type: FUNC
 * @tc.require: I8DW1W
 */
HWTEST_F(TransLogTest, TransLogTest001, TestSize.Level0)
{
    int32_t index = 0;
    int32_t transDomainBase = 0xd005740;

    ExpectMatchSoftBusLogAttrs(TRANS_LABELS[index], TRANS_SDK, transDomainBase, "TransSdk");
    ExpectMatchSoftBusLogAttrs(TRANS_LABELS[++index], TRANS_SVC, ++transDomainBase, "TransSvc");
    ExpectMatchSoftBusLogAttrs(TRANS_LABELS[++index], TRANS_INIT, ++transDomainBase, "TransInit");
    ExpectMatchSoftBusLogAttrs(TRANS_LABELS[++index], TRANS_CTRL, ++transDomainBase, "TransCtrl");
    ExpectMatchSoftBusLogAttrs(TRANS_LABELS[++index], TRANS_BYTES, ++transDomainBase, "TransBytes");
    ExpectMatchSoftBusLogAttrs(TRANS_LABELS[++index], TRANS_FILE, ++transDomainBase, "TransFile");
    ExpectMatchSoftBusLogAttrs(TRANS_LABELS[++index], TRANS_MSG, ++transDomainBase, "TransMsg");
    ExpectMatchSoftBusLogAttrs(TRANS_LABELS[++index], TRANS_STREAM, ++transDomainBase, "TransStream");
    ExpectMatchSoftBusLogAttrs(TRANS_LABELS[++index], TRANS_QOS, ++transDomainBase, "TransQos");
    ExpectMatchSoftBusLogAttrs(TRANS_LABELS[++index], TRANS_TEST, DOMAIN_ID_TEST, "TransTest");
    SoftBusLogLabel label = TRANS_LABELS[TRANS_TEST];
    HilogMock mock;
    EXPECT_CALL(mock, HiLogPrint(Eq(LOG_CORE), Eq(LOG_DEBUG), Eq(label.domain), StrEq(label.tag), _, _)).Times(1);
    TRANS_LOGD(TRANS_TEST, "test log");
}

/**
 * @tc.name: TransLogTest002
 * @tc.desc: Test TRANS_LOGI
 * @tc.type: FUNC
 * @tc.require: I8DW1W
 */
HWTEST_F(TransLogTest, TransLogTest002, TestSize.Level0)
{
    SoftBusLogLabel label = TRANS_LABELS[TRANS_TEST];
    HilogMock mock;
    EXPECT_CALL(mock, HiLogPrint(Eq(LOG_CORE), Eq(LOG_INFO), Eq(label.domain), StrEq(label.tag), _, _)).Times(1);
    TRANS_LOGI(TRANS_TEST, "test log");
}

/**
 * @tc.name: TransLogTest003
 * @tc.desc: Test TRANS_LOGW
 * @tc.type: FUNC
 * @tc.require: I8DW1W
 */
HWTEST_F(TransLogTest, TransLogTest003, TestSize.Level0)
{
    SoftBusLogLabel label = TRANS_LABELS[TRANS_TEST];
    HilogMock mock;
    EXPECT_CALL(mock, HiLogPrint(Eq(LOG_CORE), Eq(LOG_WARN), Eq(label.domain), StrEq(label.tag), _, _)).Times(1);
    TRANS_LOGW(TRANS_TEST, "test log");
}

/**
 * @tc.name: TransLogTest004
 * @tc.desc: Test TRANS_LOGE
 * @tc.type: FUNC
 * @tc.require: I8DW1W
 */
HWTEST_F(TransLogTest, TransLogTest004, TestSize.Level0)
{
    SoftBusLogLabel label = TRANS_LABELS[TRANS_TEST];
    HilogMock mock;
    EXPECT_CALL(mock, HiLogPrint(Eq(LOG_CORE), Eq(LOG_ERROR), Eq(label.domain), StrEq(label.tag), _, _)).Times(1);
    TRANS_LOGE(TRANS_TEST, "test log");
}

/**
 * @tc.name: TransLogTest005
 * @tc.desc: Test TRANS_LOGF
 * @tc.type: FUNC
 * @tc.require: I8DW1W
 */
HWTEST_F(TransLogTest, TransLogTest005, TestSize.Level0)
{
    SoftBusLogLabel label = TRANS_LABELS[TRANS_TEST];
    HilogMock mock;
    EXPECT_CALL(mock, HiLogPrint(Eq(LOG_CORE), Eq(LOG_FATAL), Eq(label.domain), StrEq(label.tag), _, _)).Times(1);
    TRANS_LOGF(TRANS_TEST, "test log");
}
} // namespace OHOS
