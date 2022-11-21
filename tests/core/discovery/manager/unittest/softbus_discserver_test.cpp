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
 
#include <cstdio>
#include <ctime>
#include <gtest/gtest.h>
#include <sys/time.h>
#include <unistd.h>
#include <securec.h>
#include <cstdint>

#include "disc_manager.h"
#include "softbus_log.h"
#include "nstackx.h"
#include "disc_coap.h"
#include "softbus_errcode.h"
#include "softbus_error_code.h"
#include "softbus_disc_server.h"
#include "disc_client_proxy.h"
#include "softbus_hisysevt_discreporter.h"

#define TEST_PACKAGE_NAME "com.test.trans.demopackagename"

using namespace testing::ext;


namespace OHOS {

const char *g_pkgName = "pkgpkgpkgpkg";
const char *g_packageName = "packpackpack";
const int32_t TEST_PUBLISH_ID = 2;
const int32_t TEST_SUBSCRIBE_ID = 4;

class SoftbusDiscServerTest : public testing::Test {
public:
    SoftbusDiscServerTest()
    {}
    ~SoftbusDiscServerTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override {}
    void TearDown() override {}
};

void SoftbusDiscServerTest::SetUpTestCase(void)
{}

void SoftbusDiscServerTest::TearDownTestCase(void)
{}

static PublishInfo g_pInfo = {
    .publishId = TEST_PUBLISH_ID,
    .mode = DISCOVER_MODE_ACTIVE,
    .medium = COAP,
    .freq = MID,
    .capability = "dvKit",
    .capabilityData = NULL,
    .dataLen = 0
};


static SubscribeInfo g_sInfo = {
    .subscribeId = TEST_SUBSCRIBE_ID,
    .mode = DISCOVER_MODE_ACTIVE,
    .medium = COAP,
    .freq = MID,
    .isSameAccount = true,
    .isWakeRemote = false,
    .capability = "hicall",
    .capabilityData = NULL,
    .dataLen = 0
};

/*
* @tc.name: testDiscServerInit
* @tc.desc: test DiscServerInit
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftbusDiscServerTest, testDiscServerInit001, TestSize.Level1)
{
    int32_t ret = DiscServerInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
   
    DiscServerDeinit();
}


/*
* @tc.name: testDiscServerDeathCallback
* @tc.desc: test DiscServerDeathCallback
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftbusDiscServerTest, testDiscServerDeathCallback001, TestSize.Level1)
{
    DiscServerDeathCallback(g_pkgName);
   
    DiscServerDeathCallback(nullptr);
}

/*
* @tc.name: testDiscIpcPublishService001
* @tc.desc: test DiscIpcPublishService faild
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftbusDiscServerTest, testDiscIpcPublishService001, TestSize.Level1)
{
    int32_t ret;
   
    ret = DiscIpcPublishService(g_packageName, &g_pInfo);
   
    EXPECT_EQ(ret, SOFTBUS_DISCOVER_MANAGER_NOT_INIT);
}


/*
* @tc.name: testDiscIpcUnPublishService001
* @tc.desc: test DiscIpcUnPublishService faild
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftbusDiscServerTest, testDiscIpcUnPublishService001, TestSize.Level1)
{
    int32_t ret;
   
    ret = DiscUnPublishService(NULL, NULL);
   
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
* @tc.name: testDiscIpcStartDiscovery001
* @tc.desc: test DiscIpcStartDiscovery success
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftbusDiscServerTest, testDiscIpcStartDiscovery001, TestSize.Level1)
{
    int32_t ret;
   
    ret = DiscIpcStartDiscovery(g_packageName, &g_sInfo);
   
    EXPECT_EQ(ret, SOFTBUS_DISCOVER_MANAGER_NOT_INIT);
}

/*
* @tc.name: testDiscIpcStopDiscovery001
* @tc.desc: test DiscIpcStopDiscovery faild
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftbusDiscServerTest, testDiscIpcStopDiscovery001, TestSize.Level1)
{
    int32_t ret;
   
    ret = DiscIpcStopDiscovery(NULL, NULL);
   
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
* @tc.name: testSetCallLnnStatus
* @tc.desc: test SetCallLnnStatus Pass in the wrong parameter
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftbusDiscServerTest, testSetCallLnnStatus001, TestSize.Level1)
{
    bool flag = true;
    SetCallLnnStatus(flag);
   
    bool ret = GetCallLnnStatus();
   
    EXPECT_EQ(ret, true);
}
}