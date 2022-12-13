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

#include "lnn_auth_mock.h"
#include "lnn_net_ledger_mock.h"
#include "lnn_network_manager.h"
#include "lnn_network_manager.c"
#include "lnn_network_manager_mock.h"
#include "lnn_physical_subnet_manager.h"
#include "lnn_trans_mock.h"
#include "message_handler.h"
#include "softbus_adapter_mem.h"
#include "softbus_common.h"
#include "softbus_errcode.h"
#include "softbus_log.h"

namespace OHOS {
using namespace testing::ext;
using namespace testing;

class LnnNetworkManagerImplTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void LnnNetworkManagerImplTest::SetUpTestCase()
{
    LooperInit();
}

void LnnNetworkManagerImplTest::TearDownTestCase()
{
    LooperDeinit();
}

void LnnNetworkManagerImplTest::SetUp()
{
}

void LnnNetworkManagerImplTest::TearDown()
{
}

/*
* @tc.name: LNN_NETWORK_MANAGER_TEST_001
* @tc.desc: len is not CONNECTION_ADDR_MAX return SOFTBUS_INVALID_PARAM
* @tc.type: FUNC
* @tc.require: I5OMIK
*/
HWTEST_F(LnnNetworkManagerImplTest, LNN_NETWORK_MANAGER_TEST_001, TestSize.Level1)
{
    NiceMock<LnnNetworkManagerInterfaceMock> managerMock;
    NiceMock<LnnAuthtInterfaceMock> authMock;
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    EXPECT_CALL(managerMock, RegistIPProtocolManager).WillOnce(Return(SOFTBUS_ERR)).
        WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(authMock, RegGroupChangeListener).WillOnce(Return(SOFTBUS_ERR)).
        WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(managerMock, LnnInitPhysicalSubnetManager).WillOnce(Return(SOFTBUS_ERR)).
        WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ledgerMock, LnnSetLocalNum64Info).WillOnce(Return(SOFTBUS_ERR)).
        WillRepeatedly(Return(SOFTBUS_OK));
    int ret = LnnInitNetworkManager();
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    ret = LnnInitNetworkManager();
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    ret = LnnInitNetworkManager();
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    ret = LnnInitNetworkManager();
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    ret = LnnInitNetworkManager();
    EXPECT_TRUE(ret == SOFTBUS_OK);
}
}