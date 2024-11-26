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

#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <gtest/gtest.h>
#include <securec.h>

#include "bus_center_info_key.h"
#include "bus_center_manager.h"
#include "lnn_local_ledger_deps_mock.h"
#include "lnn_local_net_ledger.c"
#include "lnn_local_net_ledger.h"
#include "lnn_log.h"
#include "lnn_node_info.h"
#include "softbus_adapter_mem.h"
#include "softbus_common.h"
#include "softbus_error_code.h"

namespace OHOS {
using namespace testing::ext;
constexpr uint32_t CAPABILTY = 17;
constexpr uint64_t FEATURE = 1;
using namespace testing;
class LNNLedgerMockTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void LNNLedgerMockTest::SetUpTestCase() { }

void LNNLedgerMockTest::TearDownTestCase() { }

void LNNLedgerMockTest::SetUp()
{
    LNN_LOGI(LNN_TEST, "LNNLedgerMockTest start");
}

void LNNLedgerMockTest::TearDown() { }

static void LocalLedgerKeyTestPackaged(void)
{
    EXPECT_EQ(UpdateLocalDeviceUdid(nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(UpdateLocalNetworkId(nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(UpdateLocalUuid(nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(UpdateLocalDeviceType(nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(UpdateLocalDeviceName(nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(UpdateUnifiedName(nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(UpdateUnifiedDefaultName(nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(UpdateNickName(nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(UpdateLocalBtMac(nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(UpdateLocalDeviceIp(nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(UpdateLocalNetIfName(nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(LlUpdateNodeAddr(nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(UpdateP2pMac(nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(UpdateWifiCfg(nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(UpdateChanList5g(nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(UpdateP2pGoMac(nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(LlUpdateLocalOffLineCode(nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(LlUpdateLocalExtData(nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(UpdateWifiDirectAddr(nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(LlUpdateLocalP2pIp(nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(UpdateLocalSessionPort(nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(UpdateLocalAuthPort(nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(UpdateLocalProxyPort(nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(UpdateLocalNetCapability(nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(UpdateLocalFeatureCapability(nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(UpdateLocalCipherInfoKey(nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(UpdateLocalCipherInfoIv(nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(LlUpdateStaticCapLen(nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(LlUpdateAccount(nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(LlUpdateStaticCapability(nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(LnnUpdateLocalScreenStatus(true), SOFTBUS_OK);
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
    EXPECT_CALL(localLedgerMock, SoftBusGenerateRandomArray(_, _))
        .WillRepeatedly(Return(SOFTBUS_GENERATE_RANDOM_ARRAY_FAIL));
    EXPECT_CALL(localLedgerMock, LnnGetFeatureCapabilty()).WillRepeatedly(Return(FEATURE));
    EXPECT_TRUE(LnnInitLocalLedger() == SOFTBUS_NETWORK_LEDGER_INIT_FAILED);
}

/*
 * @tc.name: LOCAL_LEDGER_MOCK_Test_002
 * @tc.desc: local ledger init and deinit test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNLedgerMockTest, LOCAL_LEDGER_MOCK_Test_002, TestSize.Level1)
{
    NiceMock<LocalLedgerDepsInterfaceMock> localLedgerMock;
    EXPECT_CALL(localLedgerMock, LnnGetNetCapabilty()).WillRepeatedly(Return(CAPABILTY));
    EXPECT_CALL(localLedgerMock, SoftBusGenerateRandomArray(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock, LnnGetFeatureCapabilty()).WillRepeatedly(Return(FEATURE));
    ON_CALL(localLedgerMock, GetCommonOsType).WillByDefault(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock, GetCommonDevInfo(_, NotNull(), _))
        .WillRepeatedly(localLedgerMock.LedgerGetCommonDevInfo);
    EXPECT_CALL(localLedgerMock, LnnInitLocalP2pInfo(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock, SoftBusRegBusCenterVarDump(_, _))
        .WillRepeatedly(localLedgerMock.LedgerSoftBusRegBusCenterVarDump);
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
    EXPECT_CALL(localLedgerMock, GetCommonDevInfo(_, _, _)).WillRepeatedly(Return(SOFTBUS_NETWORK_GET_DEVICE_INFO_ERR));
    EXPECT_CALL(localLedgerMock, LnnInitOhosAccount()).WillRepeatedly(Return(SOFTBUS_NETWORK_SET_LEDGER_INFO_ERR));
    EXPECT_TRUE(LnnInitLocalLedgerDelay() == SOFTBUS_NETWORK_GET_DEVICE_INFO_ERR);
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
    EXPECT_CALL(localLedgerMock, LnnGetFeatureCapabilty()).WillRepeatedly(Return(FEATURE));
    EXPECT_CALL(localLedgerMock, GetCommonDevInfo(_, _, _)).WillRepeatedly(Return(SOFTBUS_NETWORK_GET_DEVICE_INFO_ERR));
    EXPECT_CALL(localLedgerMock, LnnInitLocalP2pInfo(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock, SoftBusRegBusCenterVarDump(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_TRUE(LnnInitLocalLedger() == SOFTBUS_NETWORK_LEDGER_INIT_FAILED);
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
    EXPECT_CALL(localLedgerMock, LnnGetFeatureCapabilty()).WillRepeatedly(Return(FEATURE));
    EXPECT_CALL(localLedgerMock, GetCommonOsType(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock, GetCommonOsVersion(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock, GetCommonDevInfo(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock, LnnInitLocalP2pInfo(_)).WillRepeatedly(Return(SOFTBUS_SET_P2P_INFO_FAIL));
    EXPECT_TRUE(LnnInitLocalLedger() == SOFTBUS_NETWORK_LEDGER_INIT_FAILED);
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
    EXPECT_CALL(localLedgerMock, LnnGetFeatureCapabilty()).WillRepeatedly(Return(FEATURE));
    EXPECT_CALL(localLedgerMock, GetCommonOsType(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock, GetCommonOsVersion(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock, GetCommonDevInfo(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock, LnnInitLocalP2pInfo(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock, SoftBusRegBusCenterVarDump(_, _)).WillRepeatedly(Return(SOFTBUS_MEM_ERR));
    EXPECT_TRUE(LnnInitLocalLedger() == SOFTBUS_MEM_ERR);
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
    EXPECT_CALL(localLedgerMock, LnnGetFeatureCapabilty()).WillRepeatedly(Return(FEATURE));
    EXPECT_CALL(localLedgerMock, GetCommonOsType(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock, GetCommonOsVersion(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock, GetCommonDevInfo(_, _, _))
        .WillOnce(Return(SOFTBUS_OK))
        .WillRepeatedly(Return(SOFTBUS_NETWORK_GET_DEVICE_INFO_ERR));
    EXPECT_CALL(localLedgerMock, LnnInitLocalP2pInfo(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock, SoftBusRegBusCenterVarDump(_, _)).WillRepeatedly(Return(SOFTBUS_MEM_ERR));
    EXPECT_TRUE(LnnInitLocalLedger() == SOFTBUS_NETWORK_LEDGER_INIT_FAILED);
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
    EXPECT_CALL(localLedgerMock, LnnInitOhosAccount()).WillRepeatedly(Return(SOFTBUS_NETWORK_SET_LEDGER_INFO_ERR));
    EXPECT_TRUE(LnnInitLocalLedgerDelay() == SOFTBUS_NETWORK_SET_LEDGER_INFO_ERR);
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
    EXPECT_CALL(localLedgerMock, LnnGetFeatureCapabilty()).WillRepeatedly(Return(FEATURE));
    EXPECT_CALL(localLedgerMock, GetCommonOsType(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock, GetCommonOsVersion(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
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
    EXPECT_CALL(localLedgerMock, LnnGetFeatureCapabilty()).WillRepeatedly(Return(FEATURE));
    EXPECT_CALL(localLedgerMock, GetCommonOsType(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock, GetCommonOsVersion(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock, GetCommonDevInfo(_, NotNull(), _))
        .WillRepeatedly(localLedgerMock.LedgerGetCommonDevInfo);
    EXPECT_CALL(localLedgerMock, LnnInitLocalP2pInfo(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock, SoftBusRegBusCenterVarDump(_, _))
        .WillRepeatedly(localLedgerMock.LedgerSoftBusRegBusCenterVarDump);
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
    EXPECT_EQ(g_localKeyTable[18].getInfo(infoMinsize, len), SOFTBUS_INVALID_PARAM);
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
    EXPECT_CALL(localLedgerMock, LnnGetFeatureCapabilty()).WillRepeatedly(Return(FEATURE));
    EXPECT_CALL(localLedgerMock, GetCommonOsType(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock, GetCommonOsVersion(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock, GetCommonDevInfo(_, NotNull(), _))
        .WillRepeatedly(localLedgerMock.LedgerGetCommonDevInfo);
    EXPECT_CALL(localLedgerMock, LnnInitLocalP2pInfo(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock, SoftBusRegBusCenterVarDump(_, _))
        .WillRepeatedly(localLedgerMock.LedgerSoftBusRegBusCenterVarDump);
    int32_t ret = LnnInitLocalLedger();
    EXPECT_TRUE(ret == SOFTBUS_OK);
    EXPECT_EQ(g_localKeyTable[12].getInfo(infoMinsize, len), SOFTBUS_MEM_ERR);
    EXPECT_EQ(g_localKeyTable[13].getInfo(infoMinsize, len), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(g_localKeyTable[14].getInfo(infoMinsize, len), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(g_localKeyTable[15].getInfo(infoMinsize, len), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(g_localKeyTable[16].getInfo(infoMinsize, len), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(g_localKeyTable[17].getInfo(infoMinsize, len), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(g_localKeyTable[20].getInfo(infoMinsize, len), SOFTBUS_MEM_ERR);
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
    LocalLedgerDepsInterfaceMock localLedgerMock;
    EXPECT_CALL(localLedgerMock, LnnGetNetCapabilty()).WillRepeatedly(Return(CAPABILTY));
    EXPECT_CALL(localLedgerMock, SoftBusGenerateRandomArray(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock, LnnGetFeatureCapabilty()).WillRepeatedly(Return(FEATURE));
    EXPECT_CALL(localLedgerMock, GetCommonOsType(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock, GetCommonOsVersion(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock, GetCommonDevInfo(_, NotNull(), _))
        .WillRepeatedly(localLedgerMock.LedgerGetCommonDevInfo);
    EXPECT_CALL(localLedgerMock, LnnInitLocalP2pInfo(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock, SoftBusRegBusCenterVarDump(_, _))
        .WillRepeatedly(localLedgerMock.LedgerSoftBusRegBusCenterVarDump);
    EXPECT_TRUE(LnnInitLocalLedger() == SOFTBUS_OK);
    for (uint32_t i = 0; i < sizeof(g_localKeyTable) / sizeof(LocalLedgerKey); i++) {
        if (g_localKeyTable[i].getInfo != NULL) {
            EXPECT_EQ(g_localKeyTable[i].getInfo(nullptr, 0), SOFTBUS_INVALID_PARAM);
        }
    }
    LocalLedgerKeyTestPackaged();
    LnnDeinitLocalLedger();
}

/*
 * @tc.name: Local_Ledger_Key_Test_005
 * @tc.desc: local ledger key test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNLedgerMockTest, Local_Ledger_Key_Test_005, TestSize.Level1)
{
    NodeInfo *info = nullptr;
    int32_t ret = LnnInitLocalNodeInfo(info);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    NodeInfo *nodeInfo = (NodeInfo *)SoftBusMalloc(sizeof(NodeInfo));
    ASSERT_TRUE(nodeInfo != nullptr);
    (void)memset_s(nodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));

    LocalLedgerDepsInterfaceMock localLedgerMock;
    EXPECT_CALL(localLedgerMock, LnnGetNetCapabilty()).WillRepeatedly(Return(CAPABILTY));
    EXPECT_CALL(localLedgerMock, SoftBusGenerateRandomArray(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock, LnnGetFeatureCapabilty()).WillRepeatedly(Return(FEATURE));
    EXPECT_CALL(localLedgerMock, GetCommonOsType(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock, GetCommonOsVersion(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock, GetCommonDevInfo(_, NotNull(), _))
        .WillRepeatedly(localLedgerMock.LedgerGetCommonDevInfo);
    EXPECT_CALL(localLedgerMock, LnnInitLocalP2pInfo(_))
        .WillOnce(Return(SOFTBUS_OK))
        .WillRepeatedly(Return(SOFTBUS_SET_P2P_INFO_FAIL));
    ret = LnnInitLocalNodeInfo(nodeInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = LnnInitLocalNodeInfo(nodeInfo);
    EXPECT_EQ(ret, SOFTBUS_SET_P2P_INFO_FAIL);
    ret = LnnInitLocalNodeInfo(nodeInfo);
    EXPECT_EQ(ret, SOFTBUS_SET_P2P_INFO_FAIL);
    if (nodeInfo != NULL) {
        SoftBusFree(nodeInfo);
    }
}

/*
 * @tc.name: Local_Ledger_Key_Test_006
 * @tc.desc: local ledger key test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNLedgerMockTest, Local_Ledger_Key_Test_006, TestSize.Level1)
{
    int32_t ret = LnnSetLocalUnifiedName(NULL);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    const char *unifiedName = "testJohn";
    ret = LnnSetLocalUnifiedName(unifiedName);
    EXPECT_EQ(ret, SOFTBUS_LOCK_ERR);

    ret = UpdateLocalPubMac(NULL);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    const void *testId = "testId";
    ret = UpdateLocalPubMac(testId);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = LlUpdateStaticCapability(NULL);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = LlUpdateStaticCapability(testId);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: Local_Ledger_Key_Test_007
 * @tc.desc: local ledger key test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNLedgerMockTest, Local_Ledger_Key_Test_007, TestSize.Level1)
{
    uint32_t len = 101;
    int32_t ret = LlGetStaticCapability(NULL, 1);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LlGetIrk(NULL, len);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LlGetPubMac(NULL, len);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LlGetCipherInfoKey(NULL, len);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    void *buf = SoftBusCalloc(100);
    ASSERT_TRUE(buf != nullptr);
    ret = LlGetStaticCapability(buf, len);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LlGetIrk(buf, 0);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LlGetPubMac(buf, 0);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LlGetCipherInfoKey(buf, 0);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = LlGetStaticCapability(buf, 100);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = LlGetIrk(buf, len);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = LlGetPubMac(buf, len);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = LlGetCipherInfoKey(buf, 0);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    SoftBusFree(buf);
}

/*
 * @tc.name: Local_Ledger_Key_Test_008
 * @tc.desc: local ledger key test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNLedgerMockTest, Local_Ledger_Key_Test_008, TestSize.Level1)
{
    LocalLedgerDepsInterfaceMock localLedgerMock;
    EXPECT_CALL(localLedgerMock, LnnGetNetCapabilty()).WillRepeatedly(Return(CAPABILTY));
    EXPECT_CALL(localLedgerMock, SoftBusGenerateRandomArray(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock, LnnGetFeatureCapabilty()).WillRepeatedly(Return(FEATURE));
    EXPECT_CALL(localLedgerMock, GetCommonOsType(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock, GetCommonOsVersion(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock, GetCommonDevInfo(_, NotNull(), _))
        .WillRepeatedly(localLedgerMock.LedgerGetCommonDevInfo);
    EXPECT_CALL(localLedgerMock, LnnInitLocalP2pInfo(_))
        .WillOnce(Return(SOFTBUS_OK))
        .WillRepeatedly(Return(SOFTBUS_SET_P2P_INFO_FAIL));
    EXPECT_EQ(LnnInitLocalLedger(), SOFTBUS_OK);
    EXPECT_EQ(LnnUpdateLocalScreenStatus(true), SOFTBUS_OK);
    EXPECT_EQ(LnnUpdateLocalScreenStatus(false), SOFTBUS_OK);
    LnnDeinitLocalLedger();
}
} // namespace OHOS
