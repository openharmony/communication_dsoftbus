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
#include <cstring>
#include <gtest/gtest.h>
#include <securec.h>

#include "client_bus_center_manager.c"
#include "softbus_common.h"

namespace OHOS {
using namespace testing::ext;

class ClientBusMangerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void ClientBusMangerTest::SetUpTestCase() { }

void ClientBusMangerTest::TearDownTestCase() { }

void ClientBusMangerTest::SetUp()
{
    BusCenterClientInit();
}

void ClientBusMangerTest::TearDown() { }

/*
 * @tc.name: IS_SAME_CONNECTION_ADDR_Test_001
 * @tc.desc: PreLink lane test
 * @tc.type: FUNC
 * @tc.require: AR000FN5VC
 */
HWTEST_F(ClientBusMangerTest, IS_SAME_CONNECTION_ADDR_Test_001, TestSize.Level1)
{
    const ConnectionAddr addr1 = {
        .type = CONNECTION_ADDR_MAX,
        .info.session.sessionId = 1,
    };
    const ConnectionAddr addr2 = {
        .type = CONNECTION_ADDR_SESSION,
        .info.session.sessionId = 2,
    };
    int32_t ret = IsSameConnectionAddr(&addr1, &addr2);
    EXPECT_EQ(ret, false);
}

/*
 * @tc.name: IS_SAME_CONNECTION_ADDR_Test_002
 * @tc.desc: PreLink lane test
 * @tc.type: FUNC
 * @tc.require: AR000FN5VC
 */
HWTEST_F(ClientBusMangerTest, IS_SAME_CONNECTION_ADDR_Test_002, TestSize.Level1)
{
    const ConnectionAddr addr1 = {
        .type = CONNECTION_ADDR_SESSION,
        .info.session.sessionId = 1,
    };
    const ConnectionAddr addr2 = {
        .type = CONNECTION_ADDR_SESSION,
        .info.session.sessionId = 2,
    };
    int32_t ret = IsSameConnectionAddr(&addr1, &addr2);
    EXPECT_EQ(ret, false);
}

/*
 * @tc.name: IS_SAME_CONNECTION_ADDR_Test_003
 * @tc.desc: PreLink lane test
 * @tc.type: FUNC
 * @tc.require: AR000FN5VC
 */
HWTEST_F(ClientBusMangerTest, IS_SAME_CONNECTION_ADDR_Test_003, TestSize.Level1)
{
    const ConnectionAddr addr1 = {
        .type = CONNECTION_ADDR_BR,
        .info.br.brMac = 1,
    };
    const ConnectionAddr addr2 = {
        .type = CONNECTION_ADDR_BR,
        .info.br.brMac = 2,
    };
    int32_t ret = IsSameConnectionAddr(&addr1, &addr2);
    EXPECT_EQ(ret, false);
}

/*
 * @tc.name: IS_SAME_CONNECTION_ADDR_Test_004
 * @tc.desc: PreLink lane test
 * @tc.type: FUNC
 * @tc.require: AR000FN5VC
 */
HWTEST_F(ClientBusMangerTest, IS_SAME_CONNECTION_ADDR_Test_004, TestSize.Level1)
{
    const ConnectionAddr addr1 = {
        .type = CONNECTION_ADDR_WLAN,
        .info.ip.port = 1,
    };
    const ConnectionAddr addr2 = {
        .type = CONNECTION_ADDR_WLAN,
        .info.ip.port = 2,
    };
    int32_t ret = IsSameConnectionAddr(&addr1, &addr2);
    EXPECT_EQ(ret, false);
}
} // namespace OHOS
