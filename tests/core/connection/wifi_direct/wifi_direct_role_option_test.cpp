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

#include <arpa/inet.h>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <gtest/gtest.h>
#include <netinet/in.h>
#include <pthread.h>
#include <securec.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "common_list.h"
#include "softbus_adapter_mem.h"
#include "softbus_base_listener.h"
#include "softbus_conn_interface.h"
#include "softbus_conn_manager.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_feature_config.h"
#include "softbus_utils.h"
#include "wifi_direct_role_option.h"

using namespace testing::ext;
namespace OHOS {

class WifiDirectRoleTest : public testing::Test {
public:
    WifiDirectRoleTest()
    {}
    ~WifiDirectRoleTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void WifiDirectRoleTest::SetUpTestCase(void)
{}

void WifiDirectRoleTest::TearDownTestCase(void)
{}

void WifiDirectRoleTest::SetUp(void)
{}

void WifiDirectRoleTest::TearDown(void)
{}

/*
* @tc.name: WifiDirectRoleOption001
* @tc.desc: test getExpectedRole with different value
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectRoleTest, WifiDirectRoleOption001, TestSize.Level1)
{
    struct WifiDirectRoleOption *self = GetWifiDirectRoleOption();
    const char *networkId = "192.168.0.1";
    enum WifiDirectConnectType type = WIFI_DIRECT_CONNECT_TYPE_P2P;
    uint32_t value = 0xff;
    uint32_t *expectdRole = &value;
    bool flagValue = true;
    bool *isStrict = &flagValue;
    int32_t ret = self->getExpectedRole(networkId, type, expectdRole, isStrict);
    EXPECT_EQ(ret, SOFTBUS_OK);
};

/*
* @tc.name: WifiDirectRoleOption002
* @tc.desc: test getExpectedRole with different value
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectRoleTest, WifiDirectRoleOption002, TestSize.Level1)
{
    struct WifiDirectRoleOption *self = GetWifiDirectRoleOption();
    const char *networkId = "192.168.0.1";
    enum WifiDirectConnectType type = WIFI_DIRECT_CONNECT_TYPE_HML;
    uint32_t value = 0x01;
    uint32_t *expectdRole = &value;
    bool flagValue = true;
    bool *isStrict = &flagValue;
    int32_t ret = self->getExpectedRole(networkId, type, expectdRole, isStrict);
    EXPECT_EQ(ret, SOFTBUS_OK);
};

/*
* @tc.name: WifiDirectRoleOption003
* @tc.desc: test getExpectedRole with different value
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectRoleTest, WifiDirectRoleOption003, TestSize.Level1)
{
    struct WifiDirectRoleOption *self = GetWifiDirectRoleOption();
    const char *networkId = "192.168.0.1";
    enum WifiDirectConnectType type = WIFI_DIRECT_CONNECT_TYPE_WIFI_DIRECT;
    uint32_t value = 0x10;
    uint32_t *expectdRole = &value;
    bool flagValue = true;
    bool *isStrict = &flagValue;
    int32_t ret = self->getExpectedRole(networkId, type, expectdRole, isStrict);
    EXPECT_EQ(ret, SOFTBUS_OK);
};

/*
* @tc.name: WifiDirectRoleOption004
* @tc.desc: test getExpectedRole with different value
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectRoleTest, WifiDirectRoleOption004, TestSize.Level1)
{
    struct WifiDirectRoleOption *self = GetWifiDirectRoleOption();
    const char *networkId = "192.168.0.1";
    enum WifiDirectConnectType type = WIFI_DIRECT_CONNECT_TYPE_INVALID;
    uint32_t value = 0x10;
    uint32_t *expectdRole = &value;
    bool flagValue = true;
    bool *isStrict = &flagValue;
    int32_t ret = self->getExpectedRole(networkId, type, expectdRole, isStrict);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
};

/*
* @tc.name: WifiDirectRoleOption005
* @tc.desc: test getExpectedRole with different value
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WifiDirectRoleTest, WifiDirectRoleOption005, TestSize.Level1)
{
    struct WifiDirectRoleOption *self = GetWifiDirectRoleOption();
    const char *networkId = "192.168.0.1";
    enum WifiDirectConnectType type = WIFI_DIRECT_CONNECT_TYPE_MAX;
    uint32_t value = 0x10;
    uint32_t *expectdRole = &value;
    bool flagValue = true;
    bool *isStrict = &flagValue;
    int32_t ret = self->getExpectedRole(networkId, type, expectdRole, isStrict);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
};
}