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

#include <gtest/gtest.h>
#include <securec.h>
#include <cstddef>
#include <cstdlib>
#include <cstring>

#include "bus_center_info_key.h"
#include "bus_center_manager.h"
#include "lnn_local_net_ledger.h"
#include "lnn_local_net_ledger.c"
#include "lnn_log.h"
#include "lnn_node_info.h"
#include "lnn_local_ledger_deps_mock.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"
#include "softbus_common.h"

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
    LNN_LOGI(LNN_TEST, "LNNLedgerMockTest start");
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

/*
* @tc.name: Local_Ledger_Key_Test_001
* @tc.desc: local ledger key test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLedgerMockTest, Local_Ledger_Key_Test_001, TestSize.Level1)
{
    char infoTmp[] = "";
    char *infoMinsize = infoTmp;
    char *infoCharNull = nullptr;
    uint32_t len = 0;

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
    for (uint32_t i = 0; i < sizeof(g_localKeyTable) / sizeof(LocalLedgerKey); i++) {
        if (g_localKeyTable[i].getInfo != NULL) {
            EXPECT_EQ(g_localKeyTable[i].getInfo((void *)infoCharNull, len), SOFTBUS_INVALID_PARAM);
        }
    }
    EXPECT_EQ(g_localKeyTable[0].getInfo(infoMinsize, len), SOFTBUS_MEM_ERR);
    EXPECT_EQ(g_localKeyTable[1].getInfo(infoMinsize, len), SOFTBUS_MEM_ERR);
    EXPECT_EQ(g_localKeyTable[2].getInfo(infoMinsize, len), SOFTBUS_MEM_ERR);
    EXPECT_EQ(g_localKeyTable[3].getInfo(infoMinsize, len), SOFTBUS_MEM_ERR);
    EXPECT_EQ(g_localKeyTable[4].getInfo(infoMinsize, len), SOFTBUS_MEM_ERR);
    EXPECT_EQ(g_localKeyTable[5].getInfo(infoMinsize, len), SOFTBUS_MEM_ERR);
    EXPECT_EQ(g_localKeyTable[6].getInfo(infoMinsize, len), SOFTBUS_MEM_ERR);
    EXPECT_EQ(g_localKeyTable[7].getInfo(infoMinsize, len), SOFTBUS_MEM_ERR);
    EXPECT_EQ(g_localKeyTable[8].getInfo(infoMinsize, len), SOFTBUS_MEM_ERR);
    EXPECT_EQ(g_localKeyTable[9].getInfo(infoMinsize, len), SOFTBUS_MEM_ERR);
    EXPECT_EQ(g_localKeyTable[10].getInfo(infoMinsize, len), SOFTBUS_MEM_ERR);
    EXPECT_EQ(g_localKeyTable[11].getInfo(infoMinsize, len), SOFTBUS_MEM_ERR);
    EXPECT_EQ(g_localKeyTable[18].getInfo(infoMinsize, len), SOFTBUS_MEM_ERR);
    EXPECT_EQ(g_localKeyTable[19].getInfo(infoMinsize, len), SOFTBUS_MEM_ERR);
    EXPECT_EQ(g_localKeyTable[35].getInfo(infoMinsize, len), SOFTBUS_INVALID_PARAM);
    LnnDeinitLocalLedger();
}

/*
* @tc.name: Local_Ledger_Key_Test_002
* @tc.desc: local ledger key test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLedgerMockTest, Local_Ledger_Key_Test_002, TestSize.Level1)
{
    char infoTmp[] = "";
    char *infoMinsize = infoTmp;
    uint32_t len = 0;

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
    EXPECT_EQ(g_localKeyTable[12].getInfo(infoMinsize, len), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(g_localKeyTable[13].getInfo(infoMinsize, len), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(g_localKeyTable[14].getInfo(infoMinsize, len), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(g_localKeyTable[15].getInfo(infoMinsize, len), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(g_localKeyTable[16].getInfo(infoMinsize, len), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(g_localKeyTable[17].getInfo(infoMinsize, len), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(g_localKeyTable[20].getInfo(infoMinsize, len), SOFTBUS_MEM_ERR);
    EXPECT_EQ(g_localKeyTable[21].getInfo(infoMinsize, len), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(g_localKeyTable[22].getInfo(infoMinsize, len), SOFTBUS_MEM_ERR);
    EXPECT_EQ(g_localKeyTable[23].getInfo(infoMinsize, len), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(g_localKeyTable[24].getInfo(infoMinsize, len), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(g_localKeyTable[25].getInfo(infoMinsize, len), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(g_localKeyTable[26].getInfo(infoMinsize, len), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(g_localKeyTable[27].getInfo(infoMinsize, len), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(g_localKeyTable[28].getInfo(infoMinsize, len), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(g_localKeyTable[29].getInfo(infoMinsize, len), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(g_localKeyTable[30].getInfo(infoMinsize, len), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(g_localKeyTable[31].getInfo(infoMinsize, len), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(g_localKeyTable[32].getInfo(infoMinsize, len), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(g_localKeyTable[33].getInfo(infoMinsize, len), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(g_localKeyTable[34].getInfo(infoMinsize, len), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(g_localKeyTable[35].getInfo(infoMinsize, len), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(g_localKeyTable[41].getInfo(infoMinsize, len), SOFTBUS_INVALID_PARAM);
    LnnDeinitLocalLedger();
}

/*
* @tc.name: Local_Ledger_Key_Test_003
* @tc.desc: local ledger key test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLedgerMockTest, Local_Ledger_Key_Test_003, TestSize.Level1)
{
    char *infoCharNull = nullptr;
    void *infoVoidNull = nullptr;
    uint32_t len = 0;

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
    for (uint32_t i = 0; i < sizeof(g_localKeyTable) / sizeof(LocalLedgerKey); i++) {
        if (g_localKeyTable[i].getInfo != NULL) {
            EXPECT_EQ(g_localKeyTable[i].getInfo((void *)infoCharNull, len), SOFTBUS_INVALID_PARAM);
        }
    }
    EXPECT_EQ(g_localKeyTable[1].setInfo(infoVoidNull), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(g_localKeyTable[2].setInfo(infoVoidNull), SOFTBUS_ERR);
    EXPECT_EQ(g_localKeyTable[4].setInfo(infoVoidNull), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(g_localKeyTable[5].setInfo(infoVoidNull), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(g_localKeyTable[6].setInfo(infoVoidNull), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(g_localKeyTable[7].setInfo(infoVoidNull), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(g_localKeyTable[8].setInfo(infoVoidNull), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(g_localKeyTable[9].setInfo(infoVoidNull), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(g_localKeyTable[10].setInfo(infoVoidNull), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(g_localKeyTable[11].setInfo(infoVoidNull), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(g_localKeyTable[13].setInfo(infoVoidNull), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(g_localKeyTable[14].setInfo(infoVoidNull), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(g_localKeyTable[15].setInfo(infoVoidNull), SOFTBUS_INVALID_PARAM);
    LnnDeinitLocalLedger();
}

/*
* @tc.name: Local_Ledger_Key_Test_004
* @tc.desc: local ledger key test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLedgerMockTest, Local_Ledger_Key_Test_004, TestSize.Level1)
{
    char *infoCharNull = nullptr;
    void *infoVoidNull = nullptr;
    uint32_t len = 0;

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
    for (uint32_t i = 0; i < sizeof(g_localKeyTable) / sizeof(LocalLedgerKey); i++) {
        if (g_localKeyTable[i].getInfo != NULL) {
            EXPECT_EQ(g_localKeyTable[i].getInfo((void *)infoCharNull, len), SOFTBUS_INVALID_PARAM);
        }
    }
    EXPECT_EQ(g_localKeyTable[16].setInfo(infoVoidNull), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(g_localKeyTable[17].setInfo(infoVoidNull), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(g_localKeyTable[18].setInfo(infoVoidNull), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(g_localKeyTable[19].setInfo(infoVoidNull), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(g_localKeyTable[20].setInfo(infoVoidNull), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(g_localKeyTable[21].setInfo(infoVoidNull), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(g_localKeyTable[22].setInfo(infoVoidNull), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(g_localKeyTable[23].setInfo(infoVoidNull), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(g_localKeyTable[24].setInfo(infoVoidNull), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(g_localKeyTable[27].setInfo(infoVoidNull), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(g_localKeyTable[30].setInfo(infoVoidNull), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(g_localKeyTable[32].setInfo(infoVoidNull), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(g_localKeyTable[33].setInfo(infoVoidNull), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(g_localKeyTable[35].setInfo(infoVoidNull), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(g_localKeyTable[41].setInfo(infoVoidNull), SOFTBUS_INVALID_PARAM);
    LnnDeinitLocalLedger();
}
} // namespace OHOS
