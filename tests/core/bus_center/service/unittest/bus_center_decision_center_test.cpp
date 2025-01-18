/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "common_list.h"
#include "bus_center_decision_center.h"
#include "bus_center_decision_center_deps_mock.h"
#include "message_handler.h"
#include "softbus_conn_interface.h"
#include "bus_center_manager.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_net_builder.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_error_code.h"
#include "softbus_utils.h"
#include "softbus_bus_center.h"
#include "bus_center_event.h"

using namespace testing;
using namespace testing::ext;
#define NETWORK_ID_BUF_LEN 65
#define NODE_NETWORK_ID "ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF0"

namespace OHOS {

class BusCenterDecisionTest : public testing::Test {
protected:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void BusCenterDecisionTest::SetUpTestCase(void)
{
}

void BusCenterDecisionTest::TearDownTestCase(void)
{
}

void BusCenterDecisionTest::SetUp(void)
{
}

void BusCenterDecisionTest::TearDown(void)
{
}

/*
* @tc.name: BusCenterDecisionTest001
* @tc.desc:
* @tc.type: FUNC
* @tc.require: 1
*/
HWTEST_F(BusCenterDecisionTest, BusCenterDecisionTest001, TestSize.Level1)
{
    ConnectOption option;
    memset_s(&option, sizeof(ConnectOption), 0, sizeof(ConnectOption));
    option.type = CONNECT_BR;
    EXPECT_NO_FATAL_FAILURE(LnnDCReportConnectException(&option, 1));
    option.type = CONNECT_P2P;
    EXPECT_NO_FATAL_FAILURE(LnnDCReportConnectException(&option, 1));
}

/*
* @tc.name: BusCenterDecisionTest002
* @tc.desc:bus center decision test
* @tc.type: FUNC
* @tc.require: 1
*/
HWTEST_F(BusCenterDecisionTest, BusCenterDecisionTest002, TestSize.Level1)
{
    ConnectOption option;
    memset_s(&option, sizeof(ConnectOption), 0, sizeof(ConnectOption));
    option.type = CONNECT_BR;
    EXPECT_NO_FATAL_FAILURE(LnnDCClearConnectException(&option));
    option.type = CONNECT_P2P;
    EXPECT_NO_FATAL_FAILURE(LnnDCClearConnectException(&option));
}

/*
* @tc.name: BusCenterDecisionTest003
* @tc.desc:bus center decision test
* @tc.type: FUNC
* @tc.require: 1
*/
HWTEST_F(BusCenterDecisionTest, BusCenterDecisionTest003, TestSize.Level1)
{
    NodeBasicInfo info;
    (void)memset_s(&info, sizeof(info), 0, sizeof(info));
    bool isOnline = true;
    EXPECT_NO_FATAL_FAILURE(LnnDCProcessOnlineState(isOnline, &info));
    isOnline = false;
    EXPECT_NO_FATAL_FAILURE(LnnDCProcessOnlineState(isOnline, &info));
    (void)strncpy_s(info.networkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID, strlen(NODE_NETWORK_ID));
    EXPECT_NO_FATAL_FAILURE(LnnDCProcessOnlineState(isOnline, &info));
}

/*
* @tc.name: BusCenterDecisionTest004
* @tc.desc:bus center decision test
* @tc.type: FUNC
* @tc.require: 1
*/
HWTEST_F(BusCenterDecisionTest, BusCenterDecisionTest004, TestSize.Level1)
{
    NiceMock<BusCenterDecisionCenterDepsInterfaceMock> BusCenterDecisionMock;
    EXPECT_CALL(BusCenterDecisionMock, CreateSoftBusList).WillOnce(Return(nullptr));
    int32_t ret = InitDecisionCenter();
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
* @tc.name: BusCenterDecisionTest005
* @tc.desc:bus center decision test
* @tc.type: FUNC
* @tc.require: 1
*/
HWTEST_F(BusCenterDecisionTest, BusCenterDecisionTest005, TestSize.Level1)
{
    // list will free when go to TransSrvDataListDeinit
    SoftBusList *list = (SoftBusList *)SoftBusCalloc(sizeof(SoftBusList));
    SoftBusMutexAttr mutexAttr;
    mutexAttr.type = SOFTBUS_MUTEX_RECURSIVE;
    SoftBusMutexInit(&list->lock, &mutexAttr);
    ListInit(&list->list);
    NiceMock<BusCenterDecisionCenterDepsInterfaceMock> BusCenterDecisionMock;
    EXPECT_CALL(BusCenterDecisionMock, CreateSoftBusList).WillOnce(Return(list));
    int32_t ret = InitDecisionCenter();
    EXPECT_EQ(SOFTBUS_OK, ret);
    DeinitDecisionCenter();
}
}
       
