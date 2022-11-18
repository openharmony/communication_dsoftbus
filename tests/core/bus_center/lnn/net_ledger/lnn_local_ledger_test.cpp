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
constexpr char NODE_MASTER_WEIGHT[] = "10";
constexpr char NODE_UDID[] = "123456ABCDEF";
using namespace testing;
class LocalLedgerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void LocalLedgerTest::SetUpTestCase()
{
}

void LocalLedgerTest::TearDownTestCase()
{
}

void LocalLedgerTest::SetUp()
{
    LOG_INFO("LocalLedgerTest start.");
}

void LocalLedgerTest::TearDown()
{
}

/*
* @tc.name: LOCAL_LEDGER_MOCK_Test_001
* @tc.desc: local ledger init test
* @tc.type: FUNC
* @tc.require:
*/
#define CAPABILTY 17
HWTEST_F(LocalLedgerTest, LOCAL_LEDGER_MOCK_Test_001, TestSize.Level1)
{
    LocalLedgerDepsInterfaceMock localLedgerMock;
    EXPECT_CALL(localLedgerMock, LnnGetNetCapabilty()).WillRepeatedly(Return(CAPABILTY));
    EXPECT_CALL(localLedgerMock, SoftBusGenerateRandomArray(_,_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock,
        GetCommonDevInfo(_,NotNull(),_)).WillRepeatedly(localLedgerMock.LedgerGetCommonDevInfo);
    EXPECT_CALL(localLedgerMock, LnnInitLocalP2pInfo(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock, LnnConvertDeviceTypeToId(_,_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(localLedgerMock,
        SoftBusRegBusCenterVarDump(_,_)).WillRepeatedly(localLedgerMock.LedgerSoftBusRegBusCenterVarDump);
    int32_t ret = LnnInitLocalLedger();
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnInitLocalLedger();
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
* @tc.name: LOCAL_LEDGER_MOCK_Test_002
* @tc.desc: local ledger delay init test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LocalLedgerTest, LOCAL_LEDGER_MOCK_Test_002, TestSize.Level1)
{
    LocalLedgerDepsInterfaceMock localLedgerMock;
    EXPECT_CALL(localLedgerMock,
        GetCommonDevInfo(_,NotNull(),_)).WillRepeatedly(localLedgerMock.LedgerGetCommonDevInfo);
    EXPECT_CALL(localLedgerMock, LnnInitOhosAccount()).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = LnnInitLocalLedgerDelay();
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
* @tc.name: LOCAL_LEDGER_MOCK_Test_003
* @tc.desc: lnn local key table test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LocalLedgerTest, LOCAL_LEDGER_MOCK_Test_003, TestSize.Level1)
{
    static InfoKey getLocalKeyTestTableString[] = {
        STRING_KEY_HICE_VERSION,
        STRING_KEY_NET_IF_NAME,
        STRING_KEY_MASTER_NODE_UDID,
        STRING_KEY_P2P_MAC,
        STRING_KEY_P2P_GO_MAC,
        STRING_KEY_OFFLINE_CODE
    };
    char buf[UDID_BUF_LEN] = {0};
    int32_t ret;
    uint32_t i;
    for (i = 0; i < sizeof(getLocalKeyTestTableString) / sizeof(InfoKey); i++) {
        (void)memset_s(buf, UDID_BUF_LEN, 0, UDID_BUF_LEN);
        ret = LnnGetLocalStrInfo(getLocalKeyTestTableString[i], buf, UDID_BUF_LEN);
        EXPECT_TRUE(ret == SOFTBUS_OK);
    }
    for (i = 0; i < sizeof(getLocalKeyTestTableString) / sizeof(InfoKey); i++) {
        ret = LnnGetLocalStrInfo(getLocalKeyTestTableString[i], nullptr, UDID_BUF_LEN);
        EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    }
}

/*
* @tc.name: LOCAL_LEDGER_MOCK_Test_004
* @tc.desc: lnn local key table test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LocalLedgerTest, LOCAL_LEDGER_MOCK_Test_004, TestSize.Level1)
{
    static InfoKey getLocalKeyTestTableNum[] = {
        NUM_KEY_DEV_TYPE_ID,
        NUM_KEY_MASTER_NODE_WEIGHT,
        NUM_KEY_P2P_ROLE,
        NUM_KEY_TRANS_PROTOCOLS,
        NUM_KEY_DATA_CHANGE_FLAG
    };
    static uint32_t bufLen[] = {
        LNN_COMMON_LEN,
        LNN_COMMON_LEN,
        LNN_COMMON_LEN,
        sizeof(int64_t),
        DATA_CHANGE_FLAG_BUF_LEN
    };
    char buf[UDID_BUF_LEN] = {0};
    int32_t ret;
    for (uint32_t i = 0; i < sizeof(getLocalKeyTestTableNum) / sizeof(InfoKey); i++) {
        (void)memset_s(buf, UDID_BUF_LEN, 0, UDID_BUF_LEN);
        ret = LnnGetLocalStrInfo(getLocalKeyTestTableNum[i], buf, bufLen[i]);
        EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);  
    }
}

/*
* @tc.name: LOCAL_LEDGER_MOCK_Test_005
* @tc.desc: lnn set local strInfo test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LocalLedgerTest, LOCAL_LEDGER_MOCK_Test_005, TestSize.Level1)
{
    int32_t ret = LnnSetLocalStrInfo(STRING_KEY_MASTER_NODE_UDID, NODE_UDID);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnSetLocalStrInfo(NUM_KEY_MASTER_NODE_WEIGHT, NODE_MASTER_WEIGHT);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    LnnDeinitLocalLedger();
}
} // namespace OHOS
