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


#include "bus_center_decision_center.h"
#include "message_handler.h"
#include "softbus_conn_interface.h"
#include <stdbool.h>
#include "bus_center_manager.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_net_builder.h"
#include "softbus_adapter_mem.h"
#include "softbus_errcode.h"
#include "softbus_utils.h"
#include "softbus_bus_center.h"
#include "bus_center_event.h"

using namespace testing;
using namespace testing::ext;

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
HWTEST_F(BusCenterDecisionTest, BusCenterDecisionTest001, TestSize.Level0)
{
    ConnectOption option;
    memset_s(&option, sizeof(ConnectOption), 0, sizeof(ConnectOption));
    option.type = CONNECT_BR;
    LnnDCReportConnectException(&option,1);
    option.type = CONNECT_P2P;
    LnnDCReportConnectException(&option,1);
}
}
       