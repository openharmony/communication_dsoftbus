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
 
#include <securec.h>

#include <gtest/gtest.h>
#include <unistd.h>
#include "disc_nstackx_adapter.h"
#include "nstackx.h"
#include "bus_center_info_key.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"
#include "nstackx_error.h"
#include "disc_manager.h"
#include "lnn_local_net_ledger.h"

using namespace testing::ext;
namespace OHOS {

class DiscNstackxAdapterTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() override {}
    void TearDown() override {}
};

/*
* @tc.name: testDiscCoapRegisterCb001
* @tc.desc: test DiscCoapRegisterCb NULL
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscNstackxAdapterTest, TestDiscCoapRegisterCb001, TestSize.Level1)
{
    int32_t ret;
   
    ret = DiscMgrInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
   
    ret = DiscCoapRegisterCb(NULL);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
* @tc.name: testDiscCoapRegisterCapability001
* @tc.desc: test DiscCoapRegisterCapability
* @tc.type: FUNC
* @tc.require:

*/
HWTEST_F(DiscNstackxAdapterTest, TestDiscCoapRegisterCapability001, TestSize.Level1)
{
    int32_t ret;
    uint32_t mapNum = 3;
    NSTACKX_Parameter g_parameter;
  
    NSTACKX_Init(&g_parameter);
    ret = DiscCoapRegisterCapability(0, 0);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
   
    ret = DiscCoapRegisterCapability(mapNum, 0);
    EXPECT_EQ(ret, SOFTBUS_DISCOVER_COAP_REGISTER_CAP_FAIL);
   
    NSTACKX_Deinit();
}

/*
* @tc.name: testDiscCoapSetFilterCapability001
* @tc.desc: test DiscCoapSetFilterCapability
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscNstackxAdapterTest, TestDiscCoapSetFilterCapability001, TestSize.Level1)
{
    int32_t ret;
   
    uint32_t capabilityBitmap[] = {1, 2, 3, 4, 5};
    uint32_t capabilityBitmapNum = 1;
   
    ret = DiscCoapSetFilterCapability(0, capabilityBitmap);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
   
    ret = DiscCoapSetFilterCapability(capabilityBitmapNum, capabilityBitmap);
    EXPECT_EQ(ret, SOFTBUS_DISCOVER_COAP_SET_FILTER_CAP_FAIL);
}

/*
* @tc.name: testDiscCoapStartDiscovery001
* @tc.desc: test DiscCoapStartDiscovery
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscNstackxAdapterTest, TestDiscCoapStartDiscovery001, TestSize.Level1)
{
    int32_t ret;
   
    ret = DiscCoapStartDiscovery(NULL);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
   
    DiscCoapOption *option = (DiscCoapOption*)SoftBusMalloc(sizeof(DiscCoapOption));
    ASSERT_TRUE(option != nullptr);
    memset_s(option, sizeof(DiscCoapOption), 0, sizeof(DiscCoapOption));
    option->mode = INVALID_MODE;
   
    ret = DiscCoapStartDiscovery(option);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    SoftBusFree(option);
}

/*
* @tc.name: testDiscCoapUpdateLocalIp
* @tc.desc: test DiscCoapUpdateLocalIp
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscNstackxAdapterTest, TestDiscCoapUpdateLocalIp, TestSize.Level1)
{
    int32_t ret = DiscNstackxInit();
    EXPECT_EQ(ret, SOFTBUS_OK);

    LinkStatus status = LINK_STATUS_UP;
    DiscCoapUpdateLocalIp(status);

    status = LINK_STATUS_DOWN;
    DiscCoapUpdateLocalIp(status);

    status = (LinkStatus)(-1);
    DiscCoapUpdateLocalIp(status);

    DiscNstackxDeinit();
}

/*
* @tc.name: testDiscCoapRegisterServiceData
* @tc.desc: test DiscCoapRegisterServiceData
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscNstackxAdapterTest, TestDiscCoapRegisterServiceData001, TestSize.Level1)
{
    uint32_t dataLen = 1;
    int32_t ret = DiscCoapRegisterServiceData(nullptr, dataLen);
    EXPECT_EQ(ret, SOFTBUS_DISCOVER_COAP_INIT_FAIL);
}

/*
* @tc.name: testDiscCoapStopDiscovery
* @tc.desc: test DiscCoapStopDiscovery
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscNstackxAdapterTest, testDiscCoapStopDiscovery001, TestSize.Level1)
{
    int32_t ret = DiscCoapStopDiscovery();
    EXPECT_EQ(ret, SOFTBUS_DISCOVER_COAP_STOP_DISCOVER_FAIL);
    
    DiscCoapUpdateDevName();
}
}
