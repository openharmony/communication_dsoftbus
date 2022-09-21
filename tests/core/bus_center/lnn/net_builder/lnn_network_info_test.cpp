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

#include <gtest/gtest.h>
#include <securec.h>

#include "bus_center_event.h"
#include "lnn_devicename_info.h"
#include "lnn_net_builder.h"
#include "lnn_network_info.h"
#include "lnn_local_net_ledger.h"
#include "message_handler.h"
#include "softbus_bus_center.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "lnn_sync_info_manager.h"

namespace OHOS {
using namespace testing::ext;

class LnnNetworkInfoTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void LnnNetworkInfoTest::SetUpTestCase()
{
    EXPECT_EQ(LnnInitBusCenterEvent(), SOFTBUS_OK);
    EXPECT_EQ(LnnInitSyncInfoManager(), SOFTBUS_OK);
}

void LnnNetworkInfoTest::TearDownTestCase()
{
    LnnDeinitSyncInfoManager();
}

void LnnNetworkInfoTest::SetUp()
{
}

void LnnNetworkInfoTest::TearDown()
{
}

/*
* @tc.name: LNN_INIT_NETWORK_INFO_TEST_001
* @tc.desc: test LnnInitNetworkInfo
* @tc.type: FUNC
* @tc.require: I5PRUD
*/
HWTEST_F(LnnNetworkInfoTest, LNN_INIT_NETWORK_INFO_TEST_001, TestSize.Level0)
{
    EXPECT_EQ(LnnInitNetworkInfo(), SOFTBUS_OK);
}

/*
* @tc.name: LNN_INIT_NETWORK_INFO_TEST_002
* @tc.desc: test LnnInitDevicename
* @tc.type: FUNC
* @tc.require: I5PRUD
*/
HWTEST_F(LnnNetworkInfoTest, LNN_INIT_DEVICENAME_INFO_TEST_001, TestSize.Level0)
{
    EXPECT_EQ(LnnInitDevicename(), SOFTBUS_OK);
}
}
