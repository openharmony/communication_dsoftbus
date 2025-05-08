/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>
#include <string>

#include "lnn_usb_adapter.h"
#include "softbus_common.h"
#include "softbus_error_code.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"

using namespace std;
using namespace testing;
using namespace testing::ext;
using ::testing::Return;

namespace OHOS {
class LnnUsbAdapterTest : public testing::Test {
protected:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void LnnUsbAdapterTest::SetUpTestCase(void) { }

void LnnUsbAdapterTest::TearDownTestCase(void) { }

void LnnUsbAdapterTest::SetUp() { }

void LnnUsbAdapterTest::TearDown() { }

/**
 * @tc.name: LnnUsbAdapterTest_001
 * @tc.desc: StartUsbNcmAdapter
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LnnUsbAdapterTest, LnnUsbAdapterTest_001, TestSize.Level1)
{
    int32_t mode = 0;
    EXPECT_EQ(StartUsbNcmAdapter(mode), SOFTBUS_OK);
    mode = 1;
    EXPECT_EQ(StartUsbNcmAdapter(mode), SOFTBUS_OK);
    mode = 100;
    EXPECT_EQ(StartUsbNcmAdapter(mode), SOFTBUS_NETWORK_USB_MODE_INVALID);
}
}