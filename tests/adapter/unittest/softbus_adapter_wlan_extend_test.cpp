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

#include "gtest/gtest.h"
#include <securec.h>

#include "softbus_adapter_wlan_extend.h"
#include "lnn_async_callback_utils.h"
#include "securec.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "softbus_errcode.h"

#define WLAN_SERVICE_NAME "wlan_interface_service"
#define WLAN_IFNAME "wlan0"
#define MEAS_TIME_PER_CHAN_MS (15)
#define GET_MEAS_RESULT_DELAY_MS (1000)
static struct IWlanInterface *g_wlanObj = NULL;
static WlanChannelInfoCb *g_wlanChannelInfoCb = NULL;

namespace OHOS {
using namespace testing::ext;

class AdapterWlanExtendTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void AdapterWlanExtendTest::SetUpTestCase()
{
}

void AdapterWlanExtendTest::TearDownTestCase()
{
}

void AdapterWlanExtendTest::SetUp()
{
}

void AdapterWlanExtendTest::TearDown()
{
}

/*
* @tc.name: Wlan_Extend_Test_001
* @tc.desc: apply SoftBusRegWlanChannelInfoCb test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AdapterWlanExtendTest, Wlan_Extend_Test_001, TestSize.Level0)
{
    g_wlanChannelInfoCb = NULL;
    WlanChannelInfoCb *g_wlanChannelInfoCbInit = new WlanChannelInfoCb();
    int32_t laneId = 0;

    laneId = SoftBusRegWlanChannelInfoCb(g_wlanChannelInfoCb);
    EXPECT_TRUE(laneId == SOFTBUS_INVALID_PARAM);
    laneId = SoftBusRegWlanChannelInfoCb(g_wlanChannelInfoCbInit);
    delete g_wlanChannelInfoCbInit;
    EXPECT_TRUE(laneId == SOFTBUS_OK);
}

/*
* @tc.name: Wlan_Extend_Test_002
* @tc.desc: apply SoftBusRequestWlanChannelInfo test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AdapterWlanExtendTest, Wlan_Extend_Test_002, TestSize.Level0)
{
    int32_t *channelId = nullptr;
    int32_t value = 1;
    uint32_t num = 0;
    int32_t laneId = 0;

    laneId = SoftBusRequestWlanChannelInfo(channelId, num);
    EXPECT_TRUE(laneId == SOFTBUS_INVALID_PARAM);
    channelId = &value;
    laneId = SoftBusRequestWlanChannelInfo(channelId, num);
    EXPECT_TRUE(laneId == SOFTBUS_INVALID_PARAM);
    num = 1;
    g_wlanObj = NULL;
    laneId = SoftBusRequestWlanChannelInfo(channelId, num);
    EXPECT_TRUE(laneId == SOFTBUS_OK);
}

} // namespace OHOS
