/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include <gmock/gmock.h>

#include "lnn_network_manager.h"
#include "lnn_physical_subnet_manager.h"

namespace OHOS {
using namespace testing::ext;
using namespace testing;
static VisitNextChoice visitCb = CHOICE_VISIT_NEXT;
static VisitNextChoice LnnVisitPhysicalSubnetCallback(const LnnPhysicalSubnet *subnet, void *priv)
{
    return visitCb;
}

class LNNPhysicalSubnetManagerTest : public testing::Test {
public:
    void SetUp();
    void TearDown();
};

void LNNPhysicalSubnetManagerTest::SetUp()
{
    int32_t ret = LnnInitPhysicalSubnetManager();
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

void LNNPhysicalSubnetManagerTest::TearDown()
{
    LnnDeinitPhysicalSubnetManager();
}

/*
* @tc.name: LNN_REGIST_PHYSICAL_SUBNET_001
* @tc.desc: test subnet null or subnet->protocol null
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNPhysicalSubnetManagerTest, LNN_REGIST_PHYSICAL_SUBNET_001, TestSize.Level1)
{
    int32_t ret = SOFTBUS_OK;
    ret = LnnRegistPhysicalSubnet(nullptr);
    EXPECT_NE(ret, SOFTBUS_OK);

    LnnPhysicalSubnet subnet = {
            .protocol = NULL,
            .status = LNN_SUBNET_RUNNING,
        };
    ret = LnnRegistPhysicalSubnet(&subnet);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
* @tc.name: LNN_REGIST_PHYSICAL_SUBNET_002
* @tc.desc: test subnet is full
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNPhysicalSubnetManagerTest, LNN_REGIST_PHYSICAL_SUBNET_002, TestSize.Level1)
{
    int32_t ret = SOFTBUS_OK;
    for (int i = 0; i <= 6; i++)
    {
        LnnProtocolManager lnnProtocolManager = {
        .id = LNN_PROTOCOL_IP,
        };
        LnnPhysicalSubnet subnet = {
            .protocol = &lnnProtocolManager,
            .status = LNN_SUBNET_RUNNING,
        };
        ret += LnnRegistPhysicalSubnet(&subnet);
    }
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
* @tc.name: LNN_UNREGIST_PHYSICAL_SUBNET_BY_TYPE
* @tc.desc: test LnnUnregistPhysicalSubnetByType
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNPhysicalSubnetManagerTest, LNN_UNREGIST_PHYSICAL_SUBNET_BY_TYPE, TestSize.Level1)
{
    int32_t ret = SOFTBUS_OK;
    LnnProtocolManager lnnProtocolManager = {
        .id = LNN_PROTOCOL_IP,
        };
    LnnPhysicalSubnet subnet = {
            .protocol = &lnnProtocolManager,
            .status = LNN_SUBNET_RUNNING,
        };
    ret = LnnRegistPhysicalSubnet(&subnet);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = LnnUnregistPhysicalSubnetByType(LNN_PROTOCOL_IP);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: LNN_VISIT_PHYSICAL_SUBNET
* @tc.desc: test LnnVisitPhysicalSubnet
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNPhysicalSubnetManagerTest, LNN_VISIT_PHYSICAL_SUBNET, TestSize.Level1)
{
    int32_t ret = SOFTBUS_OK;

    LnnProtocolManager lnnProtocolManager = {
        .id = LNN_PROTOCOL_IP,
        };
    LnnPhysicalSubnet subnet = {
            .protocol = &lnnProtocolManager,
            .status = LNN_SUBNET_RUNNING,
        };
    ret = LnnRegistPhysicalSubnet(&subnet);
    EXPECT_EQ(ret, SOFTBUS_OK);

    visitCb = CHOICE_FINISH_VISITING;
    bool visit = LnnVisitPhysicalSubnet(LnnVisitPhysicalSubnetCallback, NULL);
    EXPECT_FALSE(visit);

    visitCb = CHOICE_VISIT_NEXT;
    visit = LnnVisitPhysicalSubnet(LnnVisitPhysicalSubnetCallback, NULL);
    EXPECT_TRUE(visit);

    ret = LnnUnregistPhysicalSubnetByType(LNN_PROTOCOL_IP);
    EXPECT_EQ(ret, SOFTBUS_OK);
}
}