/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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
    EXPECT_EQ(UpdateLocalDeviceIp(nullptr, 0), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(UpdateLocalNetIfName(nullptr, 0), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(LlUpdateNodeAddr(nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(UpdateP2pMac(nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(UpdateWifiCfg(nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(UpdateChanList5g(nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(UpdateP2pGoMac(nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(LlUpdateLocalOffLineCode(nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(LlUpdateLocalExtData(nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(UpdateWifiDirectAddr(nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(LlUpdateLocalP2pIp(nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(UpdateLocalSessionPort(nullptr, 0), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(UpdateLocalAuthPort(nullptr, 0), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(UpdateLocalProxyPort(nullptr, 0), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(UpdateLocalNetCapability(nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(UpdateLocalFeatureCapability(nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(UpdateLocalCipherInfoKey(nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(UpdateLocalCipherInfoIv(nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(LlUpdateStaticCapLen(nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(LlUpdateAccount(nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(LlUpdateStaticCapability(nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(LnnUpdateLocalScreenStatus(true), SOFTBUS_OK);
    EXPECT_EQ(UpdateHuksKeyTime(nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(UpdateLocalSparkCheck(nullptr), SOFTBUS_INVALID_PARAM);
}

static void MockForInitLocalLedger(LocalLedgerDepsInterfaceMock &localLedgerMock)
{
    EXPECT_CALL(localLedgerMock, LnnGetNetCapabilty()).WillRepeatedly(Return(CAPABILTY));
    EXPECT_CALL(localLedgerMock, SoftBusGenerateRandomArray(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock, LnnGetFeatureCapabilty()).WillRepeatedly(Return(FEATURE));
    ON_CALL(localLedgerMock, GetCommonOsType).WillByDefault(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock, GetCommonDevInfo(_, NotNull(), _))
        .WillRepeatedly(localLedgerMock.LedgerGetCommonDevInfo);
    EXPECT_CALL(localLedgerMock, LnnInitLocalP2pInfo(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock, SoftBusRegBusCenterVarDump(_, _))
        .WillRepeatedly(localLedgerMock.LedgerSoftBusRegBusCenterVarDump);
}

/*
 * @tc.name: LOCAL_LEDGER_MOCK_Test_001
 * @tc.desc: local ledger init test
 * @tc.type: FUNC
 * @tc.level: Level1
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
 * @tc.level: Level1
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
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNLedgerMockTest, LOCAL_LEDGER_MOCK_Test_003, TestSize.Level1)
{
    SoftBusMutexInit(&g_localNetLedger.lock, NULL);
    LocalLedgerDepsInterfaceMock localLedgerMock;
    EXPECT_CALL(localLedgerMock, GetCommonDevInfo(_, _, _)).WillRepeatedly(Return(SOFTBUS_NETWORK_GET_DEVICE_INFO_ERR));
    EXPECT_CALL(localLedgerMock, LnnInitOhosAccount()).WillRepeatedly(Return(SOFTBUS_NETWORK_SET_LEDGER_INFO_ERR));
    EXPECT_TRUE(LnnInitLocalLedgerDelay() == SOFTBUS_NETWORK_GET_DEVICE_INFO_ERR);
}

/*
 * @tc.name: LOCAL_LEDGER_MOCK_Test_004
 * @tc.desc: local ledger init test
 * @tc.type: FUNC
 * @tc.level: Level1
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
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNLedgerMockTest, LOCAL_LEDGER_MOCK_Test_005, TestSize.Level1)
{
    LocalLedgerDepsInterfaceMock localLedgerMock;
    EXPECT_CALL(localLedgerMock, GetCommonDeviceVersion(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock, GetDeviceSecurityLevel(_)).WillRepeatedly(Return(SOFTBUS_OK));
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
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNLedgerMockTest, LOCAL_LEDGER_MOCK_Test_006, TestSize.Level1)
{
    LocalLedgerDepsInterfaceMock localLedgerMock;
    EXPECT_CALL(localLedgerMock, GetCommonDeviceVersion(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock, GetDeviceSecurityLevel(_)).WillRepeatedly(Return(SOFTBUS_OK));
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
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNLedgerMockTest, LOCAL_LEDGER_MOCK_Test_007, TestSize.Level1)
{
    LocalLedgerDepsInterfaceMock localLedgerMock;
    EXPECT_CALL(localLedgerMock, GetCommonDeviceVersion(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
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
 * @tc.level: Level1
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
 * @tc.level: Level1
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
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNLedgerMockTest, Local_Ledger_Key_Test_001, TestSize.Level1)
{
    char infoTmp[] = "";
    char *infoMinsize = infoTmp;
    char *infoCharNull = nullptr;
    uint32_t len = 0;

    LocalLedgerDepsInterfaceMock localLedgerMock;
    EXPECT_CALL(localLedgerMock, GetCommonDeviceVersion(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock, GetDeviceSecurityLevel(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock, SoftBusGetBtState()).WillRepeatedly(Return(BLE_DISABLE));
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
        if (g_localKeyTable[i].getInfo != nullptr) {
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
    EXPECT_EQ(g_localKeyTable[11].getInfo(infoMinsize, len), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(g_localKeyTable[18].getInfo(infoMinsize, len), SOFTBUS_MEM_ERR);
    EXPECT_EQ(g_localKeyTable[19].getInfo(infoMinsize, len), SOFTBUS_MEM_ERR);
    EXPECT_EQ(g_localKeyTable[35].getInfo(infoMinsize, len), SOFTBUS_INVALID_PARAM);
    LnnDeinitLocalLedger();
}

/*
 * @tc.name: Local_Ledger_Key_Test_002
 * @tc.desc: local ledger key test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNLedgerMockTest, Local_Ledger_Key_Test_002, TestSize.Level1)
{
    char infoTmp[] = "";
    char *infoMinsize = infoTmp;
    uint32_t len = 0;
    LocalLedgerDepsInterfaceMock localLedgerMock;
    EXPECT_CALL(localLedgerMock, GetCommonDeviceVersion(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock, GetDeviceSecurityLevel(_)).WillRepeatedly(Return(SOFTBUS_OK));
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
    EXPECT_EQ(g_localKeyTable[12].getInfo(infoMinsize, len), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(g_localKeyTable[13].getInfo(infoMinsize, len), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(g_localKeyTable[14].getInfo(infoMinsize, len), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(g_localKeyTable[15].getInfo(infoMinsize, len), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(g_localKeyTable[16].getInfo(infoMinsize, len), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(g_localKeyTable[17].getInfo(infoMinsize, len), SOFTBUS_MEM_ERR);
    EXPECT_EQ(g_localKeyTable[20].getInfo(infoMinsize, len), SOFTBUS_INVALID_PARAM);
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
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNLedgerMockTest, Local_Ledger_Key_Test_003, TestSize.Level1)
{
    LocalLedgerDepsInterfaceMock localLedgerMock;
    EXPECT_CALL(localLedgerMock, GetCommonDeviceVersion(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock, GetDeviceSecurityLevel(_)).WillRepeatedly(Return(SOFTBUS_OK));
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
        if (g_localKeyTable[i].getInfo != nullptr) {
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
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNLedgerMockTest, Local_Ledger_Key_Test_005, TestSize.Level1)
{
    NodeInfo *info = nullptr;
    int32_t ret = LnnInitLocalNodeInfo(info);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    NodeInfo *nodeInfo = &g_localNetLedger.localInfo;
    (void)memset_s(nodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    nodeInfo->authCapacity |= (1 << (uint32_t)BIT_SUPPORT_BR_DUP_BLE);
    LocalLedgerDepsInterfaceMock localLedgerMock;
    EXPECT_CALL(localLedgerMock, GetCommonDeviceVersion(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock, GetDeviceSecurityLevel(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock, LnnGetNetCapabilty()).WillRepeatedly(Return(CAPABILTY));
    EXPECT_CALL(localLedgerMock, SoftBusGenerateRandomArray(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock, LnnGetFeatureCapabilty()).WillRepeatedly(Return(FEATURE));
    EXPECT_CALL(localLedgerMock, GetCommonOsType(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock, GetCommonOsVersion(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock, GetCommonDevInfo(_, NotNull(), _))
        .WillRepeatedly(localLedgerMock.LedgerGetCommonDevInfoGlass);
    EXPECT_CALL(localLedgerMock, LnnInitLocalP2pInfo(_))
        .WillOnce(Return(SOFTBUS_OK))
        .WillRepeatedly(Return(SOFTBUS_SET_P2P_INFO_FAIL));
    ret = LnnInitLocalNodeInfo(nodeInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(nodeInfo->authCapacity, 0);
    ret = LnnInitLocalNodeInfo(nodeInfo);
    EXPECT_EQ(ret, SOFTBUS_SET_P2P_INFO_FAIL);
    ret = LnnInitLocalNodeInfo(nodeInfo);
    EXPECT_EQ(ret, SOFTBUS_SET_P2P_INFO_FAIL);
}

/*
 * @tc.name: Local_Ledger_Key_Test_006
 * @tc.desc: local ledger key test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNLedgerMockTest, Local_Ledger_Key_Test_006, TestSize.Level1)
{
    int32_t ret = LnnSetLocalUnifiedName(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    const char *unifiedName = "testJohn";
    ret = LnnSetLocalUnifiedName(unifiedName);
    EXPECT_EQ(ret, SOFTBUS_LOCK_ERR);

    ret = UpdateLocalPubMac(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    const void *testId = "testId";
    ret = UpdateLocalPubMac(testId);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = LlUpdateStaticCapability(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = LlUpdateStaticCapability(testId);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: Local_Ledger_Key_Test_007
 * @tc.desc: local ledger key test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNLedgerMockTest, Local_Ledger_Key_Test_007, TestSize.Level1)
{
    uint32_t len = 101;
    int32_t ret = LlGetStaticCapability(nullptr, 1);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LlGetIrk(nullptr, len);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LlGetPubMac(nullptr, len);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LlGetCipherInfoKey(nullptr, len);
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
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNLedgerMockTest, Local_Ledger_Key_Test_008, TestSize.Level1)
{
    LocalLedgerDepsInterfaceMock localLedgerMock;
    EXPECT_CALL(localLedgerMock, GetCommonDeviceVersion(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock, GetDeviceSecurityLevel(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock, LnnGetNetCapabilty()).WillRepeatedly(Return(CAPABILTY));
    EXPECT_CALL(localLedgerMock, SoftBusGenerateRandomArray(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock, LnnGetFeatureCapabilty()).WillRepeatedly(Return(FEATURE));
    EXPECT_CALL(localLedgerMock, GetCommonOsType(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock, GetCommonOsVersion(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock, SoftBusRegBusCenterVarDump(_, _))
        .WillRepeatedly(localLedgerMock.LedgerSoftBusRegBusCenterVarDump);
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

/*
 * @tc.name: UPDATE_STATE_VERSION_Test_001
 * @tc.desc: UpdateStateVersion test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNLedgerMockTest, UPDATE_STATE_VERSION_Test_001, TestSize.Level1)
{
    LocalLedgerDepsInterfaceMock localLedgerMock;
    EXPECT_CALL(localLedgerMock, GetCommonDeviceVersion(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock, GetDeviceSecurityLevel(_)).WillRepeatedly(Return(SOFTBUS_OK));
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
    EXPECT_EQ(LnnInitLocalLedger(), SOFTBUS_OK);
    EXPECT_EQ(UpdateStateVersion(nullptr), SOFTBUS_INVALID_PARAM);
    int32_t version = 100;
    EXPECT_EQ(UpdateStateVersion(reinterpret_cast<const void *>(&version)), SOFTBUS_OK);
}

/*
 * @tc.name: L1_GET_CONN_SUB_FEATURE_CAPA_Test_001
 * @tc.desc: L1GetConnSubFeatureCapa test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNLedgerMockTest, L1_GET_CONN_SUB_FEATURE_CAPA_Test_001, TestSize.Level1)
{
    uint64_t feature = 100;
    uint32_t len = sizeof(uint64_t) + 1;
    EXPECT_EQ(L1GetConnSubFeatureCapa(nullptr, len), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(L1GetConnSubFeatureCapa(reinterpret_cast<void *>(&feature), len), SOFTBUS_INVALID_PARAM);
    len = sizeof(uint64_t);
    EXPECT_EQ(L1GetConnSubFeatureCapa(reinterpret_cast<void *>(&feature), len), SOFTBUS_OK);
}

/*
 * @tc.name: L1_GET_WIFI_CFG_Test_001
 * @tc.desc: L1GetWifiCfg test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNLedgerMockTest, L1_GET_WIFI_CFG_Test_001, TestSize.Level1)
{
    const char *wifiCfg = "wifiCfgTest";
    uint32_t len = WIFI_CFG_INFO_MAX_LEN - 1;
    EXPECT_EQ(L1GetWifiCfg(nullptr, len), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(L1GetWifiCfg(reinterpret_cast<void *>(const_cast<char *>(wifiCfg)), len), SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: L1_GET_CHAN_LIST_5G_Test_001
 * @tc.desc: L1GetChanList5g test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNLedgerMockTest, L1_GET_CHAN_LIST_5G_Test_001, TestSize.Level1)
{
    char *chanList5g = (char *)SoftBusCalloc(WIFI_CFG_INFO_MAX_LEN);
    if (chanList5g == nullptr) {
        return;
    }
    uint32_t len = WIFI_CFG_INFO_MAX_LEN - 1;
    EXPECT_EQ(L1GetChanList5g(nullptr, len), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(L1GetChanList5g(reinterpret_cast<void *>(chanList5g), len), SOFTBUS_INVALID_PARAM);
    len = WIFI_CFG_INFO_MAX_LEN;
    EXPECT_EQ(L1GetChanList5g(reinterpret_cast<void *>(chanList5g), len), SOFTBUS_OK);
    SoftBusFree(chanList5g);
}

/*
 * @tc.name: L1_GET_STA_FREQUENCY_Test_001
 * @tc.desc: L1GetStaFrequency test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNLedgerMockTest, L1_GET_STA_FREQUENCY_Test_001, TestSize.Level1)
{
    int32_t frequency = 0;
    uint32_t len = LNN_COMMON_LEN - 1;
    EXPECT_EQ(L1GetStaFrequency(nullptr, len), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(L1GetStaFrequency(reinterpret_cast<void *>(&frequency), len), SOFTBUS_INVALID_PARAM);
    len = LNN_COMMON_LEN;
    EXPECT_EQ(L1GetStaFrequency(reinterpret_cast<void *>(&frequency), len), SOFTBUS_OK);
}

/*
 * @tc.name: L1_GET_NODE_DATA_CHANGE_FLAG_Test_001
 * @tc.desc: L1GetNodeDataChangeFlag test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNLedgerMockTest, L1_GET_NODE_DATA_CHANGE_FLAG_Test_001, TestSize.Level1)
{
    int16_t flag = 0;
    uint32_t len = DATA_CHANGE_FLAG_BUF_LEN - 1;
    EXPECT_EQ(L1GetNodeDataChangeFlag(nullptr, len), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(L1GetNodeDataChangeFlag(reinterpret_cast<void *>(&flag), len), SOFTBUS_INVALID_PARAM);
    len = DATA_CHANGE_FLAG_BUF_LEN;
    EXPECT_EQ(L1GetNodeDataChangeFlag(reinterpret_cast<void *>(&flag), len), SOFTBUS_OK);
}

/*
 * @tc.name: L1_GET_DATA_DYNAMIC_LEVEL_Test_001
 * @tc.desc: L1GetDataDynamicLevel test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNLedgerMockTest, L1_GET_DATA_DYNAMIC_LEVEL_Test_001, TestSize.Level1)
{
    uint16_t level = 0;
    uint32_t len = DATA_DYNAMIC_LEVEL_BUF_LEN - 1;
    EXPECT_EQ(L1GetDataDynamicLevel(nullptr, len), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(L1GetDataDynamicLevel(reinterpret_cast<void *>(&level), len), SOFTBUS_INVALID_PARAM);
    len = DATA_DYNAMIC_LEVEL_BUF_LEN;
    EXPECT_EQ(L1GetDataDynamicLevel(reinterpret_cast<void *>(&level), len), SOFTBUS_OK);
    EXPECT_EQ(UpdateDataDynamicLevel(nullptr), SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: L1_GET_DATA_STATIC_LEVEL_Test_001
 * @tc.desc: L1GetDataStaticLevel test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNLedgerMockTest, L1_GET_DATA_STATIC_LEVEL_Test_001, TestSize.Level1)
{
    uint16_t level = 0;
    uint32_t len = DATA_STATIC_LEVEL_BUF_LEN - 1;
    EXPECT_EQ(L1GetDataStaticLevel(nullptr, len), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(L1GetDataStaticLevel(reinterpret_cast<void *>(&level), len), SOFTBUS_INVALID_PARAM);
    len = DATA_STATIC_LEVEL_BUF_LEN;
    EXPECT_EQ(L1GetDataStaticLevel(reinterpret_cast<void *>(&level), len), SOFTBUS_OK);
    EXPECT_EQ(UpdateDataStaticLevel(nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(UpdateDataSwitchLevel(nullptr), SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: L1_GET_DATA_SWITCH_LENGTH_Test_001
 * @tc.desc: L1GetDataSwitchLength test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNLedgerMockTest, L1_GET_DATA_SWITCH_LENGTH_Test_001, TestSize.Level1)
{
    uint16_t length = 0;
    uint32_t len = DATA_SWITCH_LENGTH_BUF_LEN - 1;
    EXPECT_EQ(L1GetDataSwitchLength(nullptr, len), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(L1GetDataSwitchLength(reinterpret_cast<void *>(&length), len), SOFTBUS_INVALID_PARAM);
    len = DATA_SWITCH_LENGTH_BUF_LEN;
    EXPECT_EQ(L1GetDataSwitchLength(reinterpret_cast<void *>(&length), len), SOFTBUS_OK);
    EXPECT_EQ(UpdateDataSwitchLength(nullptr), SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LOCAL_GET_NODE_BLE_START_TIME_Test_001
 * @tc.desc: LocalGetNodeBleStartTime test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNLedgerMockTest, LOCAL_GET_NODE_BLE_START_TIME_Test_001, TestSize.Level1)
{
    int64_t timeStamp = 0;
    uint32_t len = sizeof(int64_t) - 1;
    EXPECT_EQ(LocalGetNodeBleStartTime(nullptr, len), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(LocalGetNodeBleStartTime(reinterpret_cast<void *>(&timeStamp), len), SOFTBUS_INVALID_PARAM);
    len = sizeof(int64_t);
    EXPECT_EQ(LocalGetNodeBleStartTime(reinterpret_cast<void *>(&timeStamp), len), SOFTBUS_OK);
}

/*
 * @tc.name: LOCAL_GET_NETWORK_ID_TIME_STAMP_Test_001
 * @tc.desc: LocalGetNetworkIdTimeStamp test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNLedgerMockTest, LOCAL_GET_NETWORK_ID_TIME_STAMP_Test_001, TestSize.Level1)
{
    int64_t timeStamp = 0;
    uint32_t len = sizeof(int64_t) - 1;
    EXPECT_EQ(LocalGetNetworkIdTimeStamp(nullptr, len), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(LocalGetNetworkIdTimeStamp(reinterpret_cast<void *>(&timeStamp), len), SOFTBUS_INVALID_PARAM);
    len = sizeof(int64_t);
    EXPECT_EQ(LocalGetNetworkIdTimeStamp(reinterpret_cast<void *>(&timeStamp), len), SOFTBUS_OK);
    EXPECT_EQ(InitLocalVersionType(nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(InitConnectInfo(nullptr), SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: UPDATE_UNIFIED_NAME_Test_001
 * @tc.desc: UpdateUnifiedName test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNLedgerMockTest, UPDATE_UNIFIED_NAME_Test_001, TestSize.Level1)
{
    LocalLedgerDepsInterfaceMock localLedgerMock;
    EXPECT_CALL(localLedgerMock, LnnGetLocalDevInfoPacked).WillRepeatedly(Return(SOFTBUS_OK));
    const char *unifiedName = "unifiedNameTest";
    EXPECT_EQ(UpdateUnifiedName(nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(UpdateUnifiedName(reinterpret_cast<const void *>(const_cast<char *>(unifiedName))), SOFTBUS_OK);
}

/*
 * @tc.name: UPDATE_UNIFIED_DEFAULT_NAME_Test_001
 * @tc.desc: UpdateUnifiedDefaultName test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNLedgerMockTest, UPDATE_UNIFIED_DEFAULT_NAME_Test_001, TestSize.Level1)
{
    LocalLedgerDepsInterfaceMock localLedgerMock;
    EXPECT_CALL(localLedgerMock, LnnGetLocalDevInfoPacked).WillRepeatedly(Return(SOFTBUS_OK));
    const char *unifiedDefaultName = "unifiedDefaultNameTest";
    EXPECT_EQ(UpdateUnifiedDefaultName(nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(
        UpdateUnifiedDefaultName(reinterpret_cast<const void *>(const_cast<char *>(unifiedDefaultName))), SOFTBUS_OK);
}

/*
 * @tc.name: UPDATE_NICK_NAME_Test_001
 * @tc.desc: UpdateNickName test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNLedgerMockTest, UPDATE_NICK_NAME_Test_001, TestSize.Level1)
{
    LocalLedgerDepsInterfaceMock localLedgerMock;
    EXPECT_CALL(localLedgerMock, LnnGetLocalDevInfoPacked).WillRepeatedly(Return(SOFTBUS_OK));
    const char *nickName = "nickNameTest";
    EXPECT_EQ(UpdateNickName(nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(UpdateNickName(reinterpret_cast<const void *>(const_cast<char *>(nickName))), SOFTBUS_OK);
}

/*
 * @tc.name: UPDATEL_1OCAL_CONN_SUB_FEATURE_CAPABILITY_Test_001
 * @tc.desc: UpdateLocalConnSubFeatureCapability test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNLedgerMockTest, UPDATEL_1OCAL_CONN_SUB_FEATURE_CAPABILITY_Test_001, TestSize.Level1)
{
    int32_t capability = 0;
    EXPECT_EQ(UpdateLocalConnSubFeatureCapability(nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(UpdateLocalConnSubFeatureCapability(reinterpret_cast<const void *>(&capability)), SOFTBUS_OK);
}

/*
 * @tc.name: UPDATE_MASGER_NODE_WEIGHT_Test_001
 * @tc.desc: UpdateMasgerNodeWeight test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNLedgerMockTest, UPDATE_MASGER_NODE_WEIGHT_Test_001, TestSize.Level1)
{
    int32_t weight = 100;
    EXPECT_EQ(UpdateMasgerNodeWeight(nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(UpdateMasgerNodeWeight(reinterpret_cast<const void *>(&weight)), SOFTBUS_OK);
}

/*
 * @tc.name: UPDATE_P2P_ROLE_Test_001
 * @tc.desc: UpdateP2pRole test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNLedgerMockTest, UPDATE_P2P_ROLE_Test_001, TestSize.Level1)
{
    int32_t role = 1;
    EXPECT_EQ(UpdateP2pRole(nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(UpdateP2pRole(reinterpret_cast<const void *>(&role)), SOFTBUS_OK);
}

/*
 * @tc.name: UPDATE_STA_FREQUENCY_Test_001
 * @tc.desc: UpdateStaFrequency test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNLedgerMockTest, UPDATE_STA_FREQUENCY_Test_001, TestSize.Level1)
{
    int32_t staFrequency = 1;
    EXPECT_EQ(UpdateStaFrequency(nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(UpdateStaFrequency(reinterpret_cast<const void *>(&staFrequency)), SOFTBUS_OK);
    EXPECT_EQ(LnnUpdateLocalDeviceName(nullptr), SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LL_GET_DEVICE_SECURITY_LEVEL_Test_001
 * @tc.desc: LlGetDeviceSecurityLevel test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNLedgerMockTest, LL_GET_DEVICE_SECURITY_LEVEL_Test_001, TestSize.Level1)
{
    int32_t level = 1;
    uint32_t len = sizeof(int32_t) - 1;
    EXPECT_EQ(LlGetDeviceSecurityLevel(nullptr, len), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(LlGetDeviceSecurityLevel(reinterpret_cast<void *>(&level), len), SOFTBUS_INVALID_PARAM);
    len = sizeof(int32_t);
    EXPECT_EQ(LlGetDeviceSecurityLevel(reinterpret_cast<void *>(&level), len), SOFTBUS_OK);
}

/*
 * @tc.name: LL_UPDATE_DEVICE_SECURITY_LEVEL_Test_001
 * @tc.desc: LlUpdateDeviceSecurityLevel test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNLedgerMockTest, LL_UPDATE_DEVICE_SECURITY_LEVEL_Test_001, TestSize.Level1)
{
    int32_t level = 1;
    EXPECT_EQ(LlUpdateDeviceSecurityLevel(nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(LlUpdateDeviceSecurityLevel(reinterpret_cast<const void *>(&level)), SOFTBUS_OK);
}

/*
 * @tc.name: LL_GET_USER_ID_CHECK_SUM_Test_001
 * @tc.desc: LlGetUserIdCheckSum test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNLedgerMockTest, LL_GET_USER_ID_CHECK_SUM_Test_001, TestSize.Level1)
{
    int32_t checkSum = 0;
    uint32_t len = USERID_CHECKSUM_LEN + 1;
    EXPECT_EQ(LlGetUserIdCheckSum(nullptr, len), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(LlGetUserIdCheckSum(reinterpret_cast<void *>(&checkSum), len), SOFTBUS_INVALID_PARAM);
    len = USERID_CHECKSUM_LEN;
    EXPECT_EQ(LlGetUserIdCheckSum(reinterpret_cast<void *>(&checkSum), len), SOFTBUS_OK);
}

/*
 * @tc.name: LL_GET_P2P_IP_Test_001
 * @tc.desc: LlGetP2pIp test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNLedgerMockTest, LL_GET_P2P_IP_Test_001, TestSize.Level1)
{
    char *p2pIp = (char *)SoftBusCalloc(IP_LEN);
    if (p2pIp == nullptr) {
        return;
    }
    uint32_t len = IP_LEN;
    EXPECT_EQ(LlGetP2pIp(nullptr, len), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(LlGetP2pIp(reinterpret_cast<void *>(p2pIp), len), SOFTBUS_OK);
    EXPECT_EQ(UpdateLocalIrk(nullptr), SOFTBUS_INVALID_PARAM);
    SoftBusFree(p2pIp);
}

/*
 * @tc.name: LL_UPDATE_LOCAL_P2P_IP_Test_001
 * @tc.desc: LlUpdateLocalP2pIp test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNLedgerMockTest, LL_UPDATE_LOCAL_P2P_IP_Test_001, TestSize.Level1)
{
    const char *p2pIp = "127.0.0.0";
    EXPECT_EQ(LlUpdateLocalP2pIp(nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(LlUpdateLocalP2pIp(reinterpret_cast<const void *>(const_cast<char *>(p2pIp))), SOFTBUS_OK);
}

/*
 * @tc.name: L1_GET_USER_ID_Test_001
 * @tc.desc: L1GetUserId test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNLedgerMockTest, L1_GET_USER_ID_Test_001, TestSize.Level1)
{
    LocalLedgerDepsInterfaceMock localLedgerMock;
    int32_t userId = 0;
    uint32_t len = sizeof(int32_t) - 1;
    EXPECT_EQ(L1GetUserId(nullptr, len), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(L1GetUserId(reinterpret_cast<void *>(&userId), len), SOFTBUS_INVALID_PARAM);
    len = sizeof(int32_t);
    EXPECT_EQ(L1GetUserId(reinterpret_cast<void *>(&userId), len), SOFTBUS_OK);
    LnnDeinitLocalLedger();
}

/*
 * @tc.name: LL_SLE_CAP_Test_001
 * @tc.desc: LL_SLE_CAP_Test_001
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNLedgerMockTest, LL_SLE_CAP_Test_001, TestSize.Level1)
{
    int32_t mockSleRangeCap = 1;
    int32_t sleRangeCapRet = -1;
    int32_t sleRangeCap = 0;
    char sleAddrRet[MAC_LEN] = { 0 };
    LocalLedgerDepsInterfaceMock localLedgerMock;
    EXPECT_CALL(localLedgerMock, IsSleEnabled()).WillRepeatedly(Return(true));
    EXPECT_CALL(localLedgerMock, SoftBusAddSleStateListener(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock, GetSleRangeCapacity()).WillRepeatedly(Return(mockSleRangeCap));
    EXPECT_CALL(localLedgerMock, GetLocalSleAddr(_, _)).WillRepeatedly(localLedgerMock.MockGetLocalSleAddrFunc);
    EXPECT_CALL(localLedgerMock, LnnGetNetCapabilty()).WillRepeatedly(Return(CAPABILTY));
    EXPECT_CALL(localLedgerMock, LnnGetFeatureCapabilty()).WillRepeatedly(Return(FEATURE));
    EXPECT_CALL(localLedgerMock, SoftBusGenerateRandomArray(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock, GetCommonDevInfo(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock, GetCommonOsType(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock, GetCommonOsVersion(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock, GetCommonDeviceVersion(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock, GetDeviceSecurityLevel(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock, LnnInitLocalP2pInfo(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock, SoftBusRegBusCenterVarDump(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_TRUE(LnnInitLocalLedger() == SOFTBUS_OK);
    EXPECT_TRUE(LnnGetLocalNumInfo(NUM_KEY_SLE_RANGE_CAP, &sleRangeCapRet) == SOFTBUS_OK);
    EXPECT_EQ(sleRangeCapRet, sleRangeCap);
    EXPECT_TRUE(LnnGetLocalStrInfo(STRING_KEY_SLE_ADDR, sleAddrRet, MAC_LEN) == SOFTBUS_OK);
    EXPECT_NE(sleAddrRet, nullptr);
    LnnDeinitLocalLedger();
}
/*
 * @tc.name: L1_GET_HUKS_KEY_TIME_Test_001
 * @tc.desc: L1 get huks key time test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNLedgerMockTest, L1_GET_HUKS_KEY_TIME_Test_001, TestSize.Level1)
{
    int64_t hukTime = 0;
    uint32_t len = sizeof(uint64_t);
    EXPECT_EQ(L1GetHuksKeyTime(nullptr, len), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(L1GetHuksKeyTime(reinterpret_cast<void *>(&hukTime), len), SOFTBUS_OK);
}

/*
 * @tc.name: HANDLE_DEVICE_INFOIF_UDID_CHANGED_001
 * @tc.desc: HandleDeviceInfoIfUdidChanged test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNLedgerMockTest, HANDLE_DEVICE_INFOIF_UDID_CHANGED_001, TestSize.Level1)
{
    LocalLedgerDepsInterfaceMock localLedgerMock;
    EXPECT_CALL(localLedgerMock, GetCommonDevInfo).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = HandleDeviceInfoIfUdidChanged();
    EXPECT_EQ(ret, SOFTBUS_NETWORK_GET_DEVICE_INFO_ERR);
    NodeInfo localNodeInfo;
    (void)memset_s(&localNodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    localNodeInfo.deviceInfo.deviceUdid[0] = 4;
    EXPECT_CALL(localLedgerMock, LnnGetLocalDevInfoPacked)
        .WillRepeatedly(DoAll(SetArgPointee<0>(localNodeInfo), Return(SOFTBUS_OK)));
    EXPECT_CALL(localLedgerMock, GetCommonDevInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock, LnnRemoveStorageConfigPath)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    ret = HandleDeviceInfoIfUdidChanged();
    EXPECT_EQ(ret, SOFTBUS_FILE_ERR);
    EXPECT_CALL(localLedgerMock, InitTrustedDevInfoTable)
        .WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    ret = HandleDeviceInfoIfUdidChanged();
    EXPECT_EQ(ret, SOFTBUS_NETWORK_INVALID_DEV_INFO);
}

/*
 * @tc.name: HANDLE_DEVICE_INFOIF_UDID_CHANGED_002
 * @tc.desc: HandleDeviceInfoIfUdidChanged test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNLedgerMockTest, HANDLE_DEVICE_INFOIF_UDID_CHANGED_002, TestSize.Level1)
{
    LocalLedgerDepsInterfaceMock localLedgerMock;
    NodeInfo localNodeInfo;
    (void)memset_s(&localNodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    localNodeInfo.deviceInfo.deviceUdid[0] = 4;
    EXPECT_CALL(localLedgerMock, LnnGetLocalDevInfoPacked)
        .WillRepeatedly(DoAll(SetArgPointee<0>(localNodeInfo), Return(SOFTBUS_OK)));
    EXPECT_CALL(localLedgerMock, GetCommonDevInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock, LnnRemoveStorageConfigPath).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock, InitTrustedDevInfoTable).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = HandleDeviceInfoIfUdidChanged();
    EXPECT_EQ(ret, SOFTBUS_NETWORK_INVALID_DEV_INFO);
}

/*
 * @tc.name: LNN_INIT_LOCAL_NODE_INFO_001
 * @tc.desc: LnnInitLocalNodeInfo test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNLedgerMockTest, LNN_INIT_LOCAL_NODE_INFO_001, TestSize.Level1)
{
    LocalLedgerDepsInterfaceMock localLedgerMock;
    NodeInfo nodeInfo;
    (void)memset_s(&nodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    nodeInfo.deviceInfo.deviceTypeId = TYPE_WATCH_ID;
    EXPECT_CALL(localLedgerMock, GetCommonDevInfo(Eq(COMM_DEVICE_KEY_BLE_MAC), _, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock, GetCommonDevInfo(Eq(COMM_DEVICE_KEY_DEVNAME), _, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock, GetCommonDevInfo(Eq(COMM_DEVICE_KEY_DEVTYPE), _, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock, GetCommonDevInfo(Eq(COMM_DEVICE_KEY_VERSION_TYPE), _, _))
        .WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = LnnInitLocalNodeInfo(&nodeInfo);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_GET_DEVICE_INFO_ERR);
    EXPECT_CALL(localLedgerMock, GetDeviceSecurityLevel)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock, GetCommonDevInfo(Eq(COMM_DEVICE_KEY_VERSION_TYPE), _, _))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock, GetCommonDevInfo(Eq(COMM_DEVICE_KEY_BT_MAC), _, _))
        .WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    ret = LnnInitLocalNodeInfo(&nodeInfo);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LNN_GET_LOCAL_HUM_U16_INFO_001
 * @tc.desc: LnnGetLocalNumU16Info test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNLedgerMockTest, LNN_GET_LOCAL_HUM_U16_INFO_001, TestSize.Level1)
{
    int32_t ret = LnnGetLocalNumU16Info(NUM_KEY_DATA_SWITCH_LENGTH, NULL);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    uint16_t info = 0;
    ret = LnnGetLocalNumU16Info(NUM_KEY_DATA_SWITCH_LENGTH, &info);
    EXPECT_EQ(ret, SOFTBUS_LOCK_ERR);
}

/*
 * @tc.name: LNN_GEN_BROAD_CAST_CIPHER_INFO_001
 * @tc.desc: LnnGenBroadcastCipherInfo test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNLedgerMockTest, LNN_GEN_BROAD_CAST_CIPHER_INFO_001, TestSize.Level1)
{
    LocalLedgerDepsInterfaceMock localLedgerMock;
    EXPECT_CALL(localLedgerMock, LnnLoadLocalBroadcastCipherKeyPacked).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = LnnGenBroadcastCipherInfo();
    EXPECT_EQ(ret, SOFTBUS_NETWORK_GENERATE_CIPHER_INFO_FAILED);
}

/*
 * @tc.name: LNN_GEN_BROAD_CAST_CIPHER_INFO_002
 * @tc.desc: LnnGenBroadcastCipherInfo test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNLedgerMockTest, LNN_GEN_BROAD_CAST_CIPHER_INFO_002, TestSize.Level1)
{
    LocalLedgerDepsInterfaceMock localLedgerMock;
    EXPECT_CALL(localLedgerMock, LnnLoadLocalBroadcastCipherKeyPacked).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(localLedgerMock, SoftBusGenerateRandomArray(_, Eq(SESSION_KEY_LENGTH)))
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = LnnGenBroadcastCipherInfo();
    EXPECT_EQ(ret, SOFTBUS_NETWORK_GENERATE_CIPHER_INFO_FAILED);
    EXPECT_CALL(localLedgerMock, SoftBusGenerateRandomArray(_, Eq(BROADCAST_IV_LEN)))
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    ret = LnnGenBroadcastCipherInfo();
    EXPECT_EQ(ret, SOFTBUS_NETWORK_GENERATE_CIPHER_INFO_FAILED);
}

/*
 * @tc.name: LNN_GEN_BROAD_CAST_CIPHER_INFO_003
 * @tc.desc: LnnGenBroadcastCipherInfo test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNLedgerMockTest, LNN_GEN_BROAD_CAST_CIPHER_INFO_003, TestSize.Level1)
{
    LocalLedgerDepsInterfaceMock localLedgerMock;
    EXPECT_CALL(localLedgerMock, LnnLoadLocalBroadcastCipherKeyPacked).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(localLedgerMock, SoftBusGenerateRandomArray).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock, LnnUpdateLocalBroadcastCipherKeyPacked).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = LnnGenBroadcastCipherInfo();
    EXPECT_EQ(ret, SOFTBUS_NETWORK_GENERATE_CIPHER_INFO_FAILED);
}

/*
 * @tc.name: LNN_GEN_BROAD_CAST_CIPHER_INFO_004
 * @tc.desc: LnnGenBroadcastCipherInfo test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNLedgerMockTest, LNN_GEN_BROAD_CAST_CIPHER_INFO_004, TestSize.Level1)
{
    NiceMock<LocalLedgerDepsInterfaceMock> localLedgerMock;
    MockForInitLocalLedger(localLedgerMock);
    EXPECT_EQ(LnnInitLocalLedger(), SOFTBUS_OK);
    EXPECT_CALL(localLedgerMock, LnnLoadLocalBroadcastCipherKeyPacked).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(localLedgerMock, SoftBusGenerateRandomArray).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock, LnnUpdateLocalBroadcastCipherKeyPacked).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_EQ(SOFTBUS_NETWORK_GENERATE_CIPHER_INFO_FAILED, LnnGenBroadcastCipherInfo());
    EXPECT_CALL(localLedgerMock, SoftBusGenerateRandomArray).WillOnce(Return(SOFTBUS_OK)).WillOnce(Return(SOFTBUS_OK))
        .WillOnce(Return(SOFTBUS_INVALID_PARAM)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_EQ(SOFTBUS_NETWORK_GENERATE_CIPHER_INFO_FAILED, LnnGenBroadcastCipherInfo());
    EXPECT_NO_FATAL_FAILURE(LnnDeinitLocalLedger());
}

/*
 * @tc.name: LlGetSparkCheck_001
 * @tc.desc: LlGetSparkCheck test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNLedgerMockTest, LlGetSparkCheck_001, TestSize.Level1)
{
    unsigned char sparkCheck[SPARK_CHECK_LENGTH] = {0};
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, LlGetSparkCheck(nullptr, 0));
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, LlGetSparkCheck(sparkCheck, 0));
    EXPECT_EQ(SOFTBUS_OK, LlGetSparkCheck(sparkCheck, SPARK_CHECK_LENGTH));
}

/*
 * @tc.name: UpdateLocalSparkCheck_001
 * @tc.desc: UpdateLocalSparkCheck test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNLedgerMockTest, UpdateLocalSparkCheck_001, TestSize.Level1)
{
    unsigned char sparkCheck2[SPARK_CHECK_LENGTH] = {0};
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, UpdateLocalSparkCheck(nullptr));
    EXPECT_EQ(SOFTBUS_OK, UpdateLocalSparkCheck(sparkCheck2));
}

/*
 * @tc.name: LnnGenSparkCheck_001
 * @tc.desc: LnnGenSparkCheck test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNLedgerMockTest, LnnGenSparkCheck_001, TestSize.Level1)
{
    NiceMock<LocalLedgerDepsInterfaceMock> localLedgerMock;
    MockForInitLocalLedger(localLedgerMock);
    EXPECT_EQ(LnnInitLocalLedger(), SOFTBUS_OK);
    EXPECT_CALL(localLedgerMock, SoftBusGenerateRandomArray).WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    unsigned char sparkCheck[SPARK_CHECK_LENGTH] = {0};
    EXPECT_EQ(SOFTBUS_ENCRYPT_ERR, LnnGenSparkCheck(sparkCheck));
    EXPECT_EQ(SOFTBUS_OK, LnnGenSparkCheck(sparkCheck));
    EXPECT_NO_FATAL_FAILURE(LnnDeinitLocalLedger());
}

/*
 * @tc.name: LNN_LOAD_BROADCAST_CIPHER_INFO_001
 * @tc.desc: LnnLoadBroadcastCipherInfo param error
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNLedgerMockTest, LNN_LOAD_BROADCAST_CIPHER_INFO_001, TestSize.Level1)
{
    LocalLedgerDepsInterfaceMock localLedgerMock;
    BroadcastCipherKey broadcastKey;
    (void)memset_s(&broadcastKey, sizeof(BroadcastCipherKey), 0, sizeof(BroadcastCipherKey));
    int32_t ret = LnnLoadBroadcastCipherInfo(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    EXPECT_CALL(localLedgerMock, LnnGetLocalBroadcastCipherKeyPacked)
        .WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    ret = LnnLoadBroadcastCipherInfo(&broadcastKey);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_NODE_KEY_INFO_ERR);
}

/*
 * @tc.name: LNN_LOAD_BROADCAST_CIPHER_INFO_002
 * @tc.desc: LnnLoadBroadcastCipherInfo process sparkCheck
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNLedgerMockTest, LNN_LOAD_BROADCAST_CIPHER_INFO_002, TestSize.Level1)
{
    NiceMock<LocalLedgerDepsInterfaceMock> localLedgerMock;
    MockForInitLocalLedger(localLedgerMock);
    EXPECT_EQ(LnnInitLocalLedger(), SOFTBUS_OK);
    BroadcastCipherKey broadcastKey;
    (void)memset_s(&broadcastKey, sizeof(BroadcastCipherKey), 0, sizeof(BroadcastCipherKey));
    EXPECT_CALL(localLedgerMock, LnnGetLocalBroadcastCipherKeyPacked).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock, SoftBusGenerateRandomArray).WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock, LnnUpdateLocalBroadcastCipherKeyPacked).WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    broadcastKey.sparkCheck[0] = 1;
    EXPECT_EQ(LnnLoadBroadcastCipherInfo(&broadcastKey), SOFTBUS_OK);
    broadcastKey.sparkCheck[0] = 0;
    EXPECT_EQ(LnnLoadBroadcastCipherInfo(&broadcastKey), SOFTBUS_OK);
    EXPECT_EQ(LnnLoadBroadcastCipherInfo(&broadcastKey), SOFTBUS_OK);
    EXPECT_EQ(LnnLoadBroadcastCipherInfo(&broadcastKey), SOFTBUS_OK);
    EXPECT_NO_FATAL_FAILURE(LnnDeinitLocalLedger());
}

/*
 * @tc.name: LNN_FIRST_GET_UDID_001
 * @tc.desc: LnnFirstGetUdid get device info error
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNLedgerMockTest, LNN_FIRST_GET_UDID_001, TestSize.Level1)
{
    LocalLedgerDepsInterfaceMock localLedgerMock;
    EXPECT_CALL(localLedgerMock, GetCommonDevInfo).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = LnnFirstGetUdid();
    EXPECT_EQ(ret, SOFTBUS_NETWORK_GET_DEVICE_INFO_ERR);
}

/*
 * @tc.name: LNN_SET_LOCAL_INFO_BY_IFNMAEIDX_001
 * @tc.desc: LnnSetLocalInfoByIfnameIdx param error
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNLedgerMockTest, LNN_SET_LOCAL_INFO_BY_IFNMAEIDX_001, TestSize.Level1)
{
    int32_t ret = LnnSetLocalInfoByIfnameIdx(INFO_KEY_MAX, nullptr, INFO_KEY_MAX);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnSetLocalInfoByIfnameIdx(BYTE_KEY_BROADCAST_CIPHER_KEY, nullptr, BYTE_KEY_BROADCAST_CIPHER_KEY);
    EXPECT_EQ(ret, SOFTBUS_LOCK_ERR);
}

/*
 * @tc.name: LNN_SET_LOCAL_INFO_001
 * @tc.desc: LnnSetLocalInfo param error
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNLedgerMockTest, LNN_SET_LOCAL_INFO_001, TestSize.Level1)
{
    int32_t ret = LnnSetLocalInfo(INFO_KEY_MAX, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LNN_SET_LOCAL_STR_INFO_BY_IFNAMEIDX_001
 * @tc.desc: LnnSetLocalStrInfoByIfnameIdx param error
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNLedgerMockTest, LNN_SET_LOCAL_STR_INFO_BY_IFNAMEIDX_001, TestSize.Level1)
{
    char info[] = "test";
    int32_t ret = LnnSetLocalStrInfoByIfnameIdx(STRING_KEY_IP6_WITH_IF, nullptr, USB_IF);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnSetLocalStrInfoByIfnameIdx(STRING_KEY_END, info, USB_IF);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnSetLocalStrInfoByIfnameIdx(STRING_KEY_ACCOUNT_UID, info, CAPABILTY);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnSetLocalStrInfoByIfnameIdx(STRING_KEY_IP6_WITH_IF, info, USB_IF);
    EXPECT_EQ(ret, SOFTBUS_LOCK_ERR);
}

/*
 * @tc.name: LNN_GET_LOCAL_BOOL_INFO_001
 * @tc.desc: LnnGetLocalBoolInfo param error
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNLedgerMockTest, LNN_GET_LOCAL_BOOL_INFO_001, TestSize.Level1)
{
    int32_t ret = LnnGetLocalBoolInfo(BOOL_KEY_END, nullptr, 0);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnGetLocalBoolInfo(BOOL_KEY_SCREEN_STATUS, nullptr, 0);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LNN_GET_LOCAL_BOOL_INFO_002
 * @tc.desc: LnnGetLocalBoolInfo not found
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNLedgerMockTest, LNN_GET_LOCAL_BOOL_INFO_002, TestSize.Level1)
{
    bool info = false;
    int32_t ret = LnnGetLocalBoolInfo(STRING_KEY_IP, &info, 0);
    EXPECT_EQ(ret, SOFTBUS_LOCK_ERR);
}

/*
 * @tc.name: LNN_GET_LOCAL_INFO_BY_IFNAME_IDX_001
 * @tc.desc: LnnGetLocalInfoByIfnameIdx param error
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNLedgerMockTest, LNN_GET_LOCAL_INFO_BY_IFNAME_IDX_001, TestSize.Level1)
{
    uint32_t infoSize = 0;
    int32_t ifIdx = 0;
    int32_t info = 0;
    int32_t ret = LnnGetLocalInfoByIfnameIdx(STRING_KEY_IP, nullptr, infoSize, ifIdx);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnGetLocalInfoByIfnameIdx(INFO_KEY_MAX, (void*)&info, infoSize, ifIdx);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnGetLocalInfoByIfnameIdx(STRING_KEY_END, (void*)&info, infoSize, ifIdx);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnGetLocalInfoByIfnameIdx(NUM_KEY_END, (void*)&info, infoSize, ifIdx);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LNN_GET_LOCAL_INFO_BY_IFNAME_IDX_002
 * @tc.desc: LnnGetLocalInfoByIfnameIdx not found
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNLedgerMockTest, LNN_GET_LOCAL_INFO_BY_IFNAME_IDX_002, TestSize.Level1)
{
    uint32_t infoSize = 0;
    int32_t info = 0;
    int32_t ifIdx = 0;
    int32_t ret = LnnGetLocalInfoByIfnameIdx(NUM_KEY_META_NODE, (void*)&info, infoSize, ifIdx);
    EXPECT_EQ(ret, SOFTBUS_LOCK_ERR);
}

/*
 * @tc.name: LNN_GET_LOCAL_INFO_001
 * @tc.desc: LnnGetLocalInfo param error
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNLedgerMockTest, LNN_GET_LOCAL_INFO_001, TestSize.Level1)
{
    uint32_t infoSize = 0;
    int32_t info = 0;
    int32_t ret = LnnGetLocalInfo(INFO_KEY_MAX, (void*)&info, infoSize);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnGetLocalInfo(STRING_KEY_END, (void*)&info, infoSize);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnGetLocalInfo(NUM_KEY_END, (void*)&info, infoSize);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LNN_GET_LOCAL_STR_INFO_BY_IFNAME_FIX_001
 * @tc.desc: LnnGetLocalStrInfoByIfnameIdx param error
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNLedgerMockTest, LNN_GET_LOCAL_STR_INFO_BY_IFNAME_FIX_001, TestSize.Level1)
{
    int32_t ifIdx = 0;
    char info[MAX_ADDR_LEN] = {0};
    int32_t ret = LnnGetLocalStrInfoByIfnameIdx(STRING_KEY_END, info, MAX_ADDR_LEN, ifIdx);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ifIdx = 2;
    ret = LnnGetLocalStrInfoByIfnameIdx(STRING_KEY_ACCOUNT_UID, info, MAX_ADDR_LEN, ifIdx);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LNN_GET_LOCAL_STR_INFO_BY_IFNAME_FIX_002
 * @tc.desc: LnnGetLocalStrInfoByIfnameIdx not found
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNLedgerMockTest, LNN_GET_LOCAL_STR_INFO_BY_IFNAME_FIX_002, TestSize.Level1)
{
    char info[MAX_ADDR_LEN] = {0};
    int32_t ret = LnnGetLocalStrInfoByIfnameIdx(STRING_KEY_ACCOUNT_UID, info, MAX_ADDR_LEN, MIN_IF);
    EXPECT_EQ(ret, SOFTBUS_LOCK_ERR);
}

/*
 * @tc.name: LL_SET_LOCAL_SLE_RANGE_CAPACITY_001
 * @tc.desc: LlSetLocalSleRangeCapacity param error
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNLedgerMockTest, LL_SET_LOCAL_SLE_RANGE_CAPACITY_001, TestSize.Level1)
{
    int32_t ret = LlSetLocalSleRangeCapacity(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: UPDATE_STATIC_NET_CAP_001
 * @tc.desc: UpdateStaticNetCap param error
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNLedgerMockTest, UPDATE_STATIC_NET_CAP_001, TestSize.Level1)
{
    int32_t ret = UpdateStaticNetCap(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: UPDATE_LOCAL_USER_ID_001
 * @tc.desc: UpdateLocalUserId param error
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNLedgerMockTest, UPDATE_LOCAL_USER_ID_001, TestSize.Level1)
{
    int32_t ret = UpdateLocalUserId(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LL_GET_UDID_HASH_001
 * @tc.desc: LlGetUdidHash param error
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNLedgerMockTest, LL_GET_UDID_HASH_001, TestSize.Level1)
{
    LocalLedgerDepsInterfaceMock localLedgerMock;
    EXPECT_CALL(localLedgerMock, SoftBusGenerateStrHash).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    uint8_t localUdidHash[UDID_HASH_LEN] = { 0 };
    int32_t ret = LlGetUdidHash((void *)localUdidHash, UDID_HASH_LEN);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_GENERATE_STR_HASH_ERR);
}

/*
 * @tc.name: LL_GET_USER_ID_CHECK_SUM_001
 * @tc.desc: LlGetUserIdCheckSum get user id fail
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNLedgerMockTest, LL_GET_USER_ID_CHECK_SUM_001, TestSize.Level1)
{
    uint8_t localUdidHash[UDID_HASH_LEN - 1] = { 0 };
    int32_t ret = LlGetUserIdCheckSum((void *)localUdidHash, UDID_HASH_LEN - 1);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LL_UPDATE_USER_ID_CHECK_SUM_001
 * @tc.desc: LlUpdateUserIdCheckSum param error
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNLedgerMockTest, LL_UPDATE_USER_ID_CHECK_SUM_001, TestSize.Level1)
{
    int32_t ret = LlUpdateUserIdCheckSum(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LNN_ANONYMIZE_CIPHER_INFO_INVALID_PARAM_001
 * @tc.desc: LnnAnonymizeDeviceStr invalid param check
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNLedgerMockTest, LNN_ANONYMIZE_CIPHER_INFO_INVALID_PARAM_001, TestSize.Level1)
{
    char cipherStr[PTK_STR_LEN] = {0};
    char *anonyCipher = nullptr;
    EXPECT_NO_FATAL_FAILURE(LnnAnonymizeDeviceStr(nullptr, 0, 0, nullptr));
    AnonymizeFree(anonyCipher);
    anonyCipher = nullptr;
    EXPECT_NO_FATAL_FAILURE(LnnAnonymizeDeviceStr(cipherStr, 0, 0, nullptr));
    AnonymizeFree(anonyCipher);
    anonyCipher = nullptr;
    EXPECT_NO_FATAL_FAILURE(LnnAnonymizeDeviceStr(cipherStr, PTK_STR_LEN, 0, nullptr));
    AnonymizeFree(anonyCipher);
    anonyCipher = nullptr;
    EXPECT_NO_FATAL_FAILURE(LnnAnonymizeDeviceStr(cipherStr, LFINDER_IRK_STR_LEN, PTK_DEFAULT_LEN, nullptr));
    AnonymizeFree(anonyCipher);
    anonyCipher = nullptr;
    EXPECT_NO_FATAL_FAILURE(LnnAnonymizeDeviceStr(cipherStr, PTK_STR_LEN, PTK_DEFAULT_LEN, nullptr));
    AnonymizeFree(anonyCipher);
    anonyCipher = nullptr;
}

/*
 * @tc.name: LNN_ANONYMIZE_PTK_TEST_001
 * @tc.desc: LnnAnonymizeDeviceStr ptk
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNLedgerMockTest, LNN_ANONYMIZE_PTK_TEST_001, TestSize.Level1)
{
    char ptkStr[PTK_STR_LEN] = {0};
    char *anonyPtk = nullptr;
    LocalLedgerDepsInterfaceMock localLedgerMock;
    EXPECT_CALL(localLedgerMock, ConvertBytesToHexString).WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock, SoftBusGenerateStrHash).WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_NO_FATAL_FAILURE(LnnAnonymizeDeviceStr(ptkStr, PTK_STR_LEN, PTK_DEFAULT_LEN, &anonyPtk));
    AnonymizeFree(anonyPtk);
    anonyPtk = nullptr;
    EXPECT_NO_FATAL_FAILURE(LnnAnonymizeDeviceStr(ptkStr, PTK_STR_LEN, PTK_DEFAULT_LEN, &anonyPtk));
    AnonymizeFree(anonyPtk);
    anonyPtk = nullptr;
    ptkStr[0] = 1;
    EXPECT_NO_FATAL_FAILURE(LnnAnonymizeDeviceStr(ptkStr, PTK_STR_LEN, PTK_DEFAULT_LEN, &anonyPtk));
    AnonymizeFree(anonyPtk);
    anonyPtk = nullptr;
    EXPECT_NO_FATAL_FAILURE(LnnAnonymizeDeviceStr(ptkStr, PTK_STR_LEN, PTK_DEFAULT_LEN, &anonyPtk));
    AnonymizeFree(anonyPtk);
    anonyPtk = nullptr;
    EXPECT_CALL(localLedgerMock, ConvertBytesToHexString).WillOnce(Return(SOFTBUS_OK))
        .WillOnce(Return(SOFTBUS_INVALID_PARAM)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_NO_FATAL_FAILURE(LnnAnonymizeDeviceStr(ptkStr, PTK_STR_LEN, PTK_DEFAULT_LEN, &anonyPtk));
    AnonymizeFree(anonyPtk);
    anonyPtk = nullptr;
    EXPECT_NO_FATAL_FAILURE(LnnAnonymizeDeviceStr(ptkStr, PTK_STR_LEN, PTK_DEFAULT_LEN, &anonyPtk));
    AnonymizeFree(anonyPtk);
    anonyPtk = nullptr;
}

/*
 * @tc.name: LNN_ANONYMIZE_IRK_TEST_001
 * @tc.desc: LnnAnonymizeDeviceStr irk
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNLedgerMockTest, LNN_ANONYMIZE_IRK_TEST_001, TestSize.Level1)
{
    char irkStr[LFINDER_IRK_STR_LEN] = {0};
    char *anonyIrk = nullptr;
    LocalLedgerDepsInterfaceMock localLedgerMock;
    EXPECT_CALL(localLedgerMock, ConvertBytesToHexString).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock, SoftBusGenerateStrHash).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_NO_FATAL_FAILURE(LnnAnonymizeDeviceStr(irkStr, LFINDER_IRK_STR_LEN, LFINDER_IRK_LEN, &anonyIrk));
    AnonymizeFree(anonyIrk);
    anonyIrk = nullptr;
    irkStr[0] = 1;
    EXPECT_NO_FATAL_FAILURE(LnnAnonymizeDeviceStr(irkStr, LFINDER_IRK_STR_LEN, LFINDER_IRK_LEN, &anonyIrk));
    AnonymizeFree(anonyIrk);
    anonyIrk = nullptr;
}

/*
 * @tc.name: LNN_ANONYMIZE_BROADCAST_KEY_TEST_001
 * @tc.desc: LnnAnonymizeDeviceStr broadcast key
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNLedgerMockTest, LNN_ANONYMIZE_BROADCAST_KEY_TEST_001, TestSize.Level1)
{
    char broadCastKeyStr[SESSION_KEY_STR_LEN] = {0};
    char *anonyBroadCastKey = nullptr;
    LocalLedgerDepsInterfaceMock localLedgerMock;
    EXPECT_CALL(localLedgerMock, ConvertBytesToHexString).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock, SoftBusGenerateStrHash).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_NO_FATAL_FAILURE(LnnAnonymizeDeviceStr(broadCastKeyStr, SESSION_KEY_STR_LEN, SESSION_KEY_LENGTH,
        &anonyBroadCastKey));
    AnonymizeFree(anonyBroadCastKey);
    anonyBroadCastKey = nullptr;
    broadCastKeyStr[0] = 1;
    EXPECT_NO_FATAL_FAILURE(LnnAnonymizeDeviceStr(broadCastKeyStr, SESSION_KEY_STR_LEN, SESSION_KEY_LENGTH,
        &anonyBroadCastKey));
    AnonymizeFree(anonyBroadCastKey);
    anonyBroadCastKey = nullptr;
}

/*
 * @tc.name: LNN_ANONYMIZE_SPARK_CHECK_TEST_001
 * @tc.desc: LnnAnonymizeDeviceStr sparkCheck
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNLedgerMockTest, LNN_ANONYMIZE_SPARK_CHECK_TEST_001, TestSize.Level1)
{
    char sparkCheckStr[SPARK_CHECK_STR_LEN] = {0};
    char *anonySparkCheck = nullptr;
    LocalLedgerDepsInterfaceMock localLedgerMock;
    EXPECT_CALL(localLedgerMock, ConvertBytesToHexString).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock, SoftBusGenerateStrHash).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_NO_FATAL_FAILURE(LnnAnonymizeDeviceStr(sparkCheckStr, SPARK_CHECK_STR_LEN, SPARK_CHECK_LENGTH,
        &anonySparkCheck));
    AnonymizeFree(anonySparkCheck);
    anonySparkCheck = nullptr;
    sparkCheckStr[0] = 1;
    EXPECT_NO_FATAL_FAILURE(LnnAnonymizeDeviceStr(sparkCheckStr, SPARK_CHECK_STR_LEN, SPARK_CHECK_LENGTH,
        &anonySparkCheck));
    AnonymizeFree(anonySparkCheck);
    anonySparkCheck = nullptr;
}
} // namespace OHOS
