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
    int32_t authDomainBase = 0xd0057a0;

    EXPECT_EQ(index, DISC_INIT);
    auto label = DISC_LABELS[DISC_INIT];
    EXPECT_EQ(DISC_INIT, label.label);
    EXPECT_EQ(authDomainBase, label.domain);
    EXPECT_STREQ("DiscInit", label.tag);

    EXPECT_EQ(++index, DISC_CONTROL);
    label = DISC_LABELS[DISC_CONTROL];
    EXPECT_EQ(DISC_CONTROL, label.label);
    EXPECT_EQ(++authDomainBase, label.domain);
    EXPECT_STREQ("DiscControl", label.tag);

    EXPECT_EQ(++index, DISC_LNN);
    label = DISC_LABELS[DISC_LNN];
    EXPECT_EQ(DISC_LNN, label.label);
    EXPECT_EQ(++authDomainBase, label.domain);
    EXPECT_STREQ("DiscLnn", label.tag);

    EXPECT_EQ(++index, DISC_BLE);
    label = DISC_LABELS[DISC_BLE];
    EXPECT_EQ(DISC_BLE, label.label);
    EXPECT_EQ(++authDomainBase, label.domain);
    EXPECT_STREQ("DiscBle", label.tag);

    EXPECT_EQ(++index, DISC_BLE_ADAPTER);
    label = DISC_LABELS[DISC_BLE_ADAPTER];
    EXPECT_EQ(DISC_BLE_ADAPTER, label.label);
    EXPECT_EQ(++authDomainBase, label.domain);
    EXPECT_STREQ("DiscBleAdapter", label.tag);

    EXPECT_EQ(++index, DISC_COAP);
    label = DISC_LABELS[DISC_COAP];
    EXPECT_EQ(DISC_COAP, label.label);
    EXPECT_EQ(++authDomainBase, label.domain);
    EXPECT_STREQ("DiscCoap", label.tag);

    EXPECT_EQ(++index, DISC_DFINDER);
    label = DISC_LABELS[DISC_DFINDER];
    EXPECT_EQ(DISC_DFINDER, label.label);
    EXPECT_EQ(++authDomainBase, label.domain);
    EXPECT_STREQ("DiscDfinder", label.tag);

    EXPECT_EQ(++index, DISC_ABILITY);
    label = DISC_LABELS[DISC_ABILITY];
    EXPECT_EQ(DISC_ABILITY, label.label);
    EXPECT_EQ(++authDomainBase, label.domain);
    EXPECT_STREQ("DiscAbility", label.tag);

    EXPECT_EQ(++index, DISC_USB);
    label = DISC_LABELS[DISC_USB];
    EXPECT_EQ(DISC_USB, label.label);
    EXPECT_EQ(++authDomainBase, label.domain);
    EXPECT_STREQ("DiscUsb", label.tag);

    EXPECT_EQ(++index, DISC_USB_ADAPTER);
    label = DISC_LABELS[DISC_USB_ADAPTER];
    EXPECT_EQ(DISC_USB_ADAPTER, label.label);
    EXPECT_EQ(++authDomainBase, label.domain);
    EXPECT_STREQ("DiscUsbAdapter", label.tag);

    EXPECT_EQ(++index, DISC_SDK);
    label = DISC_LABELS[DISC_SDK];
    EXPECT_EQ(DISC_SDK, label.label);
    EXPECT_EQ(++authDomainBase, label.domain);
    EXPECT_STREQ("DiscSdk", label.tag);

    EXPECT_EQ(++index, DISC_TEST);
    label = DISC_LABELS[DISC_TEST];
    EXPECT_EQ(DISC_TEST, label.label);
    EXPECT_EQ(DOMAIN_ID_TEST, label.domain);
    EXPECT_STREQ("DiscTest", label.tag);
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