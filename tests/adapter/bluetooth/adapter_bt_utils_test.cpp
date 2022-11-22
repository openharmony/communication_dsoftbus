/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "gtest/gtest.h"

#include "adapter_bt_utils.h"

// negative numbers to make sure it's illegal
#define ILLEGAL_OHOS_BT_STATUS (-1)

using namespace testing::ext;

namespace OHOS {

/**
 * @tc.name: AdapterBtUtilsTest_ConvertStatus
 * @tc.desc: test bt status convert to dsoftbu status
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST(AdapterBtUtilsTest, ConvertStatus, TestSize.Level3)
{
    auto status = BleOhosStatusToSoftBus(OHOS_BT_STATUS_SUCCESS);
    EXPECT_EQ(status, SOFTBUS_BT_STATUS_SUCCESS);

    status = BleOhosStatusToSoftBus(OHOS_BT_STATUS_FAIL);
    EXPECT_EQ(status, SOFTBUS_BT_STATUS_FAIL);

    status = BleOhosStatusToSoftBus(OHOS_BT_STATUS_NOT_READY);
    EXPECT_EQ(status, SOFTBUS_BT_STATUS_NOT_READY);

    status = BleOhosStatusToSoftBus(OHOS_BT_STATUS_NOMEM);
    EXPECT_EQ(status, SOFTBUS_BT_STATUS_NOMEM);

    status = BleOhosStatusToSoftBus(OHOS_BT_STATUS_BUSY);
    EXPECT_EQ(status, SOFTBUS_BT_STATUS_BUSY);

    status = BleOhosStatusToSoftBus(OHOS_BT_STATUS_DONE);
    EXPECT_EQ(status, SOFTBUS_BT_STATUS_DONE);

    status = BleOhosStatusToSoftBus(OHOS_BT_STATUS_UNSUPPORTED);
    EXPECT_EQ(status, SOFTBUS_BT_STATUS_UNSUPPORTED);

    status = BleOhosStatusToSoftBus(OHOS_BT_STATUS_PARM_INVALID);
    EXPECT_EQ(status, SOFTBUS_BT_STATUS_PARM_INVALID);

    status = BleOhosStatusToSoftBus(OHOS_BT_STATUS_UNHANDLED);
    EXPECT_EQ(status, SOFTBUS_BT_STATUS_UNHANDLED);

    status = BleOhosStatusToSoftBus(OHOS_BT_STATUS_AUTH_FAILURE);
    EXPECT_EQ(status, SOFTBUS_BT_STATUS_AUTH_FAILURE);

    status = BleOhosStatusToSoftBus(OHOS_BT_STATUS_RMT_DEV_DOWN);
    EXPECT_EQ(status, SOFTBUS_BT_STATUS_RMT_DEV_DOWN);

    status = BleOhosStatusToSoftBus(OHOS_BT_STATUS_AUTH_REJECTED);
    EXPECT_EQ(status, SOFTBUS_BT_STATUS_AUTH_REJECTED);

    status = BleOhosStatusToSoftBus((BtStatus)ILLEGAL_OHOS_BT_STATUS);
    EXPECT_EQ(status, SOFTBUS_BT_STATUS_FAIL);
}

} // namespace OHOS