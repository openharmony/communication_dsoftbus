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
#include <cstddef>
#include <cstdlib>
#include <cstring>

#include "bus_center_info_key.h"
#include "bus_center_manager.h"
#include "lnn_local_net_ledger.h"
#include "lnn_node_info.h"
#include "lnn_local_ledger_deps_mock.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"
#include "softbus_common.h"
#include "softbus_log.h"

namespace OHOS {
using namespace testing::ext;
constexpr uint32_t CAPABILTY = 17;
using namespace testing;
class LNNLedgerMockTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void LNNLedgerMockTest::SetUpTestCase()
{
}

void LNNLedgerMockTest::TearDownTestCase()
{
}

void LNNLedgerMockTest::SetUp()
{
    LOG_INFO("LNNLedgerMockTest start.");
}

void LNNLedgerMockTest::TearDown()
{
}

/*
* @tc.name: LOCAL_LEDGER_MOCK_Test_001
* @tc.desc: local ledger init test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLedgerMockTest, LOCAL_LEDGER_MOCK_Test_001, TestSize.Level1)
{
    LocalLedgerDepsInterfaceMock localLedgerMock;
    EXPECT_CALL(localLedgerMock, LnnGetNetCapabilty()).WillRepeatedly(Return(CAPABILTY));
    EXPECT_CALL(localLedgerMock, SoftBusGenerateRandomArray(_, _)).WillRepeatedly(Return(SOFTBUS_ERR));
    EXPECT_TRUE(LnnInitLocalLedger() == SOFTBUS_ERR);
}

/*
* @tc.name: LOCAL_LEDGER_MOCK_Test_002
* @tc.desc: local ledger init and deinit test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLedgerMockTest, LOCAL_LEDGER_MOCK_Test_002, TestSize.Level1)
{
    LocalLedgerDepsInterfaceMock localLedgerMock;
    EXPECT_CALL(localLedgerMock, LnnGetNetCapabilty()).WillRepeatedly(Return(CAPABILTY));
    EXPECT_CALL(localLedgerMock, SoftBusGenerateRandomArray(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock,
        GetCommonDevInfo(_, NotNull(), _)).WillRepeatedly(localLedgerMock.LedgerGetCommonDevInfo);
    EXPECT_CALL(localLedgerMock, LnnInitLocalP2pInfo(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock,
        SoftBusRegBusCenterVarDump(_, _)).WillRepeatedly(localLedgerMock.LedgerSoftBusRegBusCenterVarDump);
    int32_t ret = LnnInitLocalLedger();
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnInitLocalLedger();
    EXPECT_TRUE(ret == SOFTBUS_OK);
    LnnDeinitLocalLedger();
}

/*
* @tc.name: LOCAL_LEDGER_MOCK_Test_003
* @tc.desc: local ledger delay init test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLedgerMockTest, LOCAL_LEDGER_MOCK_Test_003, TestSize.Level1)
{
    LocalLedgerDepsInterfaceMock localLedgerMock;
    EXPECT_CALL(localLedgerMock, GetCommonDevInfo(_, _, _)).WillRepeatedly(Return(SOFTBUS_ERR));
    EXPECT_CALL(localLedgerMock, LnnInitOhosAccount()).WillRepeatedly(Return(SOFTBUS_ERR));
    EXPECT_TRUE(LnnInitLocalLedgerDelay() == SOFTBUS_ERR);
}

/*
* @tc.name: LOCAL_LEDGER_MOCK_Test_004
* @tc.desc: local ledger init test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLedgerMockTest, LOCAL_LEDGER_MOCK_Test_004, TestSize.Level1)
{
    LocalLedgerDepsInterfaceMock localLedgerMock;
    EXPECT_CALL(localLedgerMock, LnnGetNetCapabilty()).WillRepeatedly(Return(CAPABILTY));
    EXPECT_CALL(localLedgerMock, SoftBusGenerateRandomArray(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock, GetCommonDevInfo(_, _, _)).WillRepeatedly(Return(SOFTBUS_ERR));
    EXPECT_CALL(localLedgerMock, LnnInitLocalP2pInfo(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock, SoftBusRegBusCenterVarDump(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_TRUE(LnnInitLocalLedger() == SOFTBUS_ERR);
}

/*
* @tc.name: LOCAL_LEDGER_MOCK_Test_005
* @tc.desc: local ledger init test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLedgerMockTest, LOCAL_LEDGER_MOCK_Test_005, TestSize.Level1)
{
    LocalLedgerDepsInterfaceMock localLedgerMock;
    EXPECT_CALL(localLedgerMock, LnnGetNetCapabilty()).WillRepeatedly(Return(CAPABILTY));
    EXPECT_CALL(localLedgerMock, SoftBusGenerateRandomArray(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock, GetCommonDevInfo(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock, LnnInitLocalP2pInfo(_)).WillRepeatedly(Return(SOFTBUS_ERR));
    EXPECT_TRUE(LnnInitLocalLedger() == SOFTBUS_ERR);
}

/*
* @tc.name: LOCAL_LEDGER_MOCK_Test_006
* @tc.desc: local ledger init test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLedgerMockTest, LOCAL_LEDGER_MOCK_Test_006, TestSize.Level1)
{
    LocalLedgerDepsInterfaceMock localLedgerMock;
    EXPECT_CALL(localLedgerMock, LnnGetNetCapabilty()).WillRepeatedly(Return(CAPABILTY));
    EXPECT_CALL(localLedgerMock, SoftBusGenerateRandomArray(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock, GetCommonDevInfo(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock, LnnInitLocalP2pInfo(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock, SoftBusRegBusCenterVarDump(_, _)).WillRepeatedly(Return(SOFTBUS_ERR));
    EXPECT_TRUE(LnnInitLocalLedger() == SOFTBUS_ERR);
}

/*
* @tc.name: LOCAL_LEDGER_MOCK_Test_007
* @tc.desc: local ledger init test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLedgerMockTest, LOCAL_LEDGER_MOCK_Test_007, TestSize.Level1)
{
    LocalLedgerDepsInterfaceMock localLedgerMock;
    EXPECT_CALL(localLedgerMock, LnnGetNetCapabilty()).WillRepeatedly(Return(CAPABILTY));
    EXPECT_CALL(localLedgerMock, SoftBusGenerateRandomArray(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock, GetCommonDevInfo(_, _, _))
        .WillOnce(Return(SOFTBUS_OK)).WillRepeatedly(Return(SOFTBUS_ERR));
    EXPECT_CALL(localLedgerMock, LnnInitLocalP2pInfo(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock, SoftBusRegBusCenterVarDump(_, _)).WillRepeatedly(Return(SOFTBUS_ERR));
    EXPECT_TRUE(LnnInitLocalLedger() == SOFTBUS_ERR);
}

/*
* @tc.name: LOCAL_LEDGER_MOCK_Test_008
* @tc.desc: local ledger init test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLedgerMockTest, LOCAL_LEDGER_MOCK_Test_008, TestSize.Level1)
{
    LocalLedgerDepsInterfaceMock localLedgerMock;
    EXPECT_CALL(localLedgerMock, GetCommonDevInfo(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock, LnnInitOhosAccount()).WillRepeatedly(Return(SOFTBUS_ERR));
    EXPECT_TRUE(LnnInitLocalLedgerDelay() == SOFTBUS_ERR);
}

/*
* @tc.name: LOCAL_LEDGER_MOCK_Test_009
* @tc.desc: local ledger init test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLedgerMockTest, LOCAL_LEDGER_MOCK_Test_009, TestSize.Level1)
{
    LocalLedgerDepsInterfaceMock localLedgerMock;
    EXPECT_CALL(localLedgerMock, GetCommonDevInfo(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock, LnnInitOhosAccount()).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_TRUE(LnnInitLocalLedgerDelay() == SOFTBUS_OK);
}
} // namespace OHOS
