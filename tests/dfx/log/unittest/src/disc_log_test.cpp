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

#include "disc_log.h"
#include "hilog_mock.h"
#include "softbus_log_test_utils.h"

using namespace std;
using namespace testing;
using namespace testing::ext;

namespace OHOS {
class DiscLogTest : public testing::Test { };

/**
 * @tc.name: DiscLogTest001
 * @tc.desc: Test SoftBusLogLabel is consistent with DiscLogLabelEnum
 * @tc.type: FUNC
 * @tc.require: I8DW1W
 */
HWTEST_F(DiscLogTest, DiscLogTest001, TestSize.Level0)
{
    int32_t index = 0;
    int32_t discDomainBase = 0xd0057a0;

    ExpectMatchSoftBusLogAttrs(DISC_LABELS[index], DISC_INIT, discDomainBase, "DiscInit");
    ExpectMatchSoftBusLogAttrs(DISC_LABELS[++index], DISC_CONTROL, ++discDomainBase, "DiscControl");
    ExpectMatchSoftBusLogAttrs(DISC_LABELS[++index], DISC_LNN, ++discDomainBase, "DiscLnn");
    ExpectMatchSoftBusLogAttrs(DISC_LABELS[++index], DISC_BLE, ++discDomainBase, "DiscBle");
    ExpectMatchSoftBusLogAttrs(DISC_LABELS[++index], DISC_BLE_ADAPTER, ++discDomainBase, "DiscBleAdapter");
    ExpectMatchSoftBusLogAttrs(DISC_LABELS[++index], DISC_COAP, ++discDomainBase, "DiscCoap");
    ExpectMatchSoftBusLogAttrs(DISC_LABELS[++index], DISC_DFINDER, ++discDomainBase, "DiscDfinder");
    ExpectMatchSoftBusLogAttrs(DISC_LABELS[++index], DISC_ABILITY, ++discDomainBase, "DiscAbility");
    ExpectMatchSoftBusLogAttrs(DISC_LABELS[++index], DISC_USB, ++discDomainBase, "DiscUsb");
    ExpectMatchSoftBusLogAttrs(DISC_LABELS[++index], DISC_USB_ADAPTER, ++discDomainBase, "DiscUsbAdapter");
    ExpectMatchSoftBusLogAttrs(DISC_LABELS[++index], DISC_SDK, ++discDomainBase, "DiscSdk");
    ExpectMatchSoftBusLogAttrs(DISC_LABELS[++index], DISC_BROADCAST, ++discDomainBase, "DiscBroadcast");
    ExpectMatchSoftBusLogAttrs(DISC_LABELS[++index], DISC_TEST, DOMAIN_ID_TEST, "DiscTest");
}

/**
 * @tc.name: DiscLogTest002
 * @tc.desc: Test DISC_LOGD
 * @tc.type: FUNC
 * @tc.require: I8DW1W
 */
HWTEST_F(DiscLogTest, DiscLogTest002, TestSize.Level0)
{
    SoftBusLogLabel label = DISC_LABELS[DISC_INIT];
    HilogMock mock;
    EXPECT_CALL(mock, HiLogPrint(Eq(LOG_CORE), Eq(LOG_DEBUG), Eq(label.domain), StrEq(label.tag), _, _))
        .Times(1);
    DISC_LOGD(DISC_INIT, "test log");
}

/**
 * @tc.name: DiscLogTest003
 * @tc.desc: Test DISC_LOGI
 * @tc.type: FUNC
 * @tc.require: I8DW1W
 */
HWTEST_F(DiscLogTest, DiscLogTest003, TestSize.Level0)
{
    SoftBusLogLabel label = DISC_LABELS[DISC_INIT];
    HilogMock mock;
    EXPECT_CALL(mock, HiLogPrint(Eq(LOG_CORE), Eq(LOG_INFO), Eq(label.domain), StrEq(label.tag), _, _))
        .Times(1);
    DISC_LOGI(DISC_INIT, "test log");
}

/**
 * @tc.name: DiscLogTest004
 * @tc.desc: Test DISC_LOGW
 * @tc.type: FUNC
 * @tc.require: I8DW1W
 */
HWTEST_F(DiscLogTest, DiscLogTest004, TestSize.Level0)
{
    SoftBusLogLabel label = DISC_LABELS[DISC_INIT];
    HilogMock mock;
    EXPECT_CALL(mock, HiLogPrint(Eq(LOG_CORE), Eq(LOG_WARN), Eq(label.domain), StrEq(label.tag), _, _))
        .Times(1);
    DISC_LOGW(DISC_INIT, "test log");
}

/**
 * @tc.name: DiscLogTest005
 * @tc.desc: Test DISC_LOGE
 * @tc.type: FUNC
 * @tc.require: I8DW1W
 */
HWTEST_F(DiscLogTest, DiscLogTest005, TestSize.Level0)
{
    SoftBusLogLabel label = DISC_LABELS[DISC_INIT];
    HilogMock mock;
    EXPECT_CALL(mock, HiLogPrint(Eq(LOG_CORE), Eq(LOG_ERROR), Eq(label.domain), StrEq(label.tag), _, _))
        .Times(1);
    DISC_LOGE(DISC_INIT, "test log");
}

/**
 * @tc.name: DiscLogTest006
 * @tc.desc: Test DISC_LOGF
 * @tc.type: FUNC
 * @tc.require: I8DW1W
 */
HWTEST_F(DiscLogTest, DiscLogTest006, TestSize.Level0)
{
    SoftBusLogLabel label = DISC_LABELS[DISC_INIT];
    HilogMock mock;
    EXPECT_CALL(mock, HiLogPrint(Eq(LOG_CORE), Eq(LOG_FATAL), Eq(label.domain), StrEq(label.tag), _, _))
        .Times(1);
    DISC_LOGF(DISC_INIT, "test log");
}
} // namespace OHOS
