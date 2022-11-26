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

#include "lnn_topo_manager.h"
#include "softbus_adapter_mem.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "lnn_service_mock.h"

namespace OHOS {
using namespace testing::ext;
using namespace testing;

constexpr char UDID[] = "123456789";
constexpr char PEER1_UDID[] = "123456789";
constexpr uint32_t LEN = CONNECTION_ADDR_MAX + 1;
constexpr uint32_t LEN2 = CONNECTION_ADDR_MAX;

class LnnTopoManagerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void LnnTopoManagerTest::SetUpTestCase()
{
    NiceMock<LnnServicetInterfaceMock> serviceMock;
    ON_CALL(serviceMock, LnnRegisterEventHandler(_, _)).WillByDefault
        (LnnServicetInterfaceMock::ActionOfLnnRegisterEventHandler);
    LnnInitTopoManager();
}

void LnnTopoManagerTest::TearDownTestCase()
{
    LnnDeinitTopoManager();
}

void LnnTopoManagerTest::SetUp()
{
}

void LnnTopoManagerTest::TearDown()
{
}

/*
* @tc.name: LNN_GET_RELATION_TEST_001
* @tc.desc: len is not CONNECTION_ADDR_MAX return SOFTBUS_INVALID_PARAM
* @tc.type: FUNC
* @tc.require: I5OMIK
*/
HWTEST_F(LnnTopoManagerTest, LNN_GET_RELATION_TEST_001, TestSize.Level0)
{
    uint8_t num = 0;
    int ret = LnnGetRelation(UDID, PEER1_UDID, &num, LEN);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
}

/*
* @tc.name: LNN_GET_RELATION_TEST_002
* @tc.desc: Udid and PeerUdid not find return SOFTBUS_NOT_FIND
* @tc.type: FUNC
* @tc.require: I5OMIK
*/
HWTEST_F(LnnTopoManagerTest, LNN_GET_RELATION_TEST_002, TestSize.Level0)
{
    uint8_t num = 0;
    int ret = LnnGetRelation(UDID, PEER1_UDID, &num, LEN2);
    EXPECT_TRUE(ret == SOFTBUS_NOT_FIND);
}

/*
* @tc.name: LNN_GET_ALL_RELATION_TEST_001
* @tc.desc: relationNum is NULL return SOFTBUS_INVALID_PARAM
* @tc.type: FUNC
* @tc.require: I5OMIK
*/
HWTEST_F(LnnTopoManagerTest, LNN_GET_ALL_RELATION_TEST_001, TestSize.Level0)
{
    uint32_t *relationNum = nullptr;
    LnnRelation *relation = nullptr;
    int ret = LnnGetAllRelation(&relation, relationNum);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
}

/*
* @tc.name: LNN_GET_RELATION_TEST_002
* @tc.desc: *invalid parameter
* @tc.type: FUNC
* @tc.require: I5OMIK
*/
HWTEST_F(LnnTopoManagerTest, LNN_GET_ALL_RELATION_TEST_002, TestSize.Level0)
{
    uint32_t num = 0;
    LnnRelation *relation = nullptr;
    int ret = LnnGetAllRelation(&relation, &num);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    num = 1;
    ret = LnnGetAllRelation(&relation, &num);
    SoftBusFree(relation);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}
} // namespace OHOS
