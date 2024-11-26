/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "bus_center_info_key.h"
#include "lnn_connection_addr_utils.h"
#include "lnn_network_id.h"
#include "softbus_bus_center.h"
#include "softbus_error_code.h"

namespace OHOS {
using namespace testing::ext;

constexpr char BT_MAC[] = "12:34:56:78";
constexpr char WLAN_IP[] = "10.146.181.134";

class NetBuilderTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void NetBuilderTest::SetUpTestCase() { }

void NetBuilderTest::TearDownTestCase() { }

void NetBuilderTest::SetUp() { }

void NetBuilderTest::TearDown() { }

/*
 * @tc.name: NET_BUILDER_GEN_ID_Test_001
 * @tc.desc: generate network id interface test
 * @tc.type: FUNC
 * @tc.require: AR000FK6J3
 */
HWTEST_F(NetBuilderTest, NET_BUILDER_GEN_ID_Test_001, TestSize.Level0)
{
    char networkIdFirst[NETWORK_ID_BUF_LEN] = { 0 };
    char networkIdSecond[NETWORK_ID_BUF_LEN] = { 0 };

    EXPECT_TRUE(LnnGenLocalNetworkId(networkIdFirst, NETWORK_ID_BUF_LEN) == SOFTBUS_OK);
    EXPECT_TRUE(LnnGenLocalNetworkId(networkIdSecond, NETWORK_ID_BUF_LEN) == SOFTBUS_OK);
    EXPECT_TRUE(strncmp(networkIdFirst, networkIdSecond, NETWORK_ID_BUF_LEN) != 0);
}

/*
 * @tc.name: NET_BUILDER_GEN_ID_Test_002
 * @tc.desc: generate uuid interface test
 * @tc.type: FUNC
 * @tc.require: AR000FK6J3
 */
HWTEST_F(NetBuilderTest, NET_BUILDER_GEN_ID_Test_002, TestSize.Level0)
{
    char uuidFirst[UUID_BUF_LEN] = { 0 };
    char uuidSecond[UUID_BUF_LEN] = { 0 };

    EXPECT_TRUE(LnnGenLocalUuid(uuidFirst, UUID_BUF_LEN) == SOFTBUS_OK);
    EXPECT_TRUE(LnnGenLocalUuid(uuidSecond, UUID_BUF_LEN) == SOFTBUS_OK);
    EXPECT_TRUE(strncmp(uuidFirst, uuidSecond, UUID_BUF_LEN) == 0);
}

/*
 * @tc.name: NET_BUILDER_GEN_ID_Test_003
 * @tc.desc: generate irk interface test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NetBuilderTest, NET_BUILDER_GEN_ID_Test_003, TestSize.Level0)
{
    unsigned char irkFirst[LFINDER_IRK_LEN] = { 0 };
    unsigned char irkSecond[LFINDER_IRK_LEN] = { 0 };

    EXPECT_TRUE(LnnGenLocalIrk(irkFirst, LFINDER_IRK_LEN) == SOFTBUS_OK);
    EXPECT_TRUE(LnnGenLocalIrk(irkSecond, LFINDER_IRK_LEN) == SOFTBUS_OK);
    EXPECT_EQ(memcmp(irkFirst, irkSecond, LFINDER_IRK_LEN), 0);
}

/*
 * @tc.name: NET_BUILDER_CONNECTION_ADDR_Test_001
 * @tc.desc: connection address compare interface test
 * @tc.type: FUNC
 * @tc.require: AR000FK6J2
 */
HWTEST_F(NetBuilderTest, NET_BUILDER_CONNECTION_ADDR_Test_001, TestSize.Level0)
{
    ConnectionAddr bleAddr = {
        .type = CONNECTION_ADDR_BR,
    };
    ConnectionAddr ethAddr = {
        .type = CONNECTION_ADDR_ETH,
    };

    EXPECT_TRUE(strncpy_s(bleAddr.info.br.brMac, BT_MAC_LEN, BT_MAC, strlen(BT_MAC)) == EOK);
    EXPECT_TRUE(strncpy_s(bleAddr.info.ip.ip, IP_STR_MAX_LEN, WLAN_IP, strlen(WLAN_IP)) == EOK);
    EXPECT_TRUE(LnnIsSameConnectionAddr(&bleAddr, &bleAddr, true));
    EXPECT_TRUE(LnnIsSameConnectionAddr(&ethAddr, &ethAddr, true));
    EXPECT_FALSE(LnnIsSameConnectionAddr(&bleAddr, &ethAddr, false));
}
} // namespace OHOS
