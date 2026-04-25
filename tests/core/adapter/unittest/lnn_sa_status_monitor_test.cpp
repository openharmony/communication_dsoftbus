/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include <string>

#include "lnn_sa_status_monitor.h"
#include "lnn_sa_status_monitor_mock.h"
#include "lnn_ohos_account_adapter.h"
#include "softbus_common.h"
#include "softbus_error_code.h"
#include "system_ability_definition.h"

#define private   public
#include "lnn_sa_status_monitor.cpp"

using namespace std;
using namespace testing;
using namespace testing::ext;
using ::testing::Return;

namespace OHOS {
static const int32_t TEST_ACCOUNT_SA_ID = SUBSYS_ACCOUNT_SYS_ABILITY_ID_BEGIN;

class LnnSaStatusMonitorTest : public testing::Test {
protected:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void LnnSaStatusMonitorTest::SetUpTestCase(void) { }

void LnnSaStatusMonitorTest::TearDownTestCase(void) { }

void LnnSaStatusMonitorTest::SetUp() { }

void LnnSaStatusMonitorTest::TearDown() { }

/*
 * @tc.name: LNN_INIT_SA_STATUS_MONITOR_001
 * @tc.desc: Execute LnnInitSaStatusMonitor and LnnDeInitSaStatusMonitor normally
 *           without fatal errors when LnnAsyncCallbackDelayHelper returns SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnSaStatusMonitorTest, LNN_INIT_SA_STATUS_MONITOR_001, TestSize.Level1)
{
    LnnSaStatusMonitorInterfaceMock mocker;
    EXPECT_CALL(mocker, LnnAsyncCallbackDelayHelper).WillOnce(Return(SOFTBUS_OK));
    EXPECT_NO_FATAL_FAILURE(LnnInitSaStatusMonitor());
    EXPECT_NO_FATAL_FAILURE(LnnDeInitSaStatusMonitor());
}

/*
 * @tc.name: LNN_INIT_SA_STATUS_MONITOR_002
 * @tc.desc: Execute LnnInitSaStatusMonitor and LnnDeInitSaStatusMonitor normally without
 *           fatal errors when LnnAsyncCallbackDelayHelper returns SOFTBUS_ERR
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnSaStatusMonitorTest, LNN_INIT_SA_STATUS_MONITOR_002, TestSize.Level1)
{
    LnnSaStatusMonitorInterfaceMock mocker;
    EXPECT_CALL(mocker, LnnAsyncCallbackDelayHelper).WillOnce(Return(SOFTBUS_ERR));
    EXPECT_NO_FATAL_FAILURE(LnnInitSaStatusMonitor());
    EXPECT_NO_FATAL_FAILURE(LnnDeInitSaStatusMonitor());
}

/*
 * @tc.name: LNN_ON_REMOVE_SYSTEM_ABILITY_001
 * @tc.desc: Verify OnRemoveSystemAbility calls LnnClearOsAccountAdapterStatus for ACCOUNT_SA_ID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnSaStatusMonitorTest, LNN_ON_REMOVE_SYSTEM_ABILITY_001, TestSize.Level1)
{
    sptr<ServiceStatusMonitorManager::SaStatusListener> listener =
        new ServiceStatusMonitorManager::SaStatusListener();
    ASSERT_NE(listener, nullptr);
    EXPECT_NO_FATAL_FAILURE(listener->OnRemoveSystemAbility(TEST_ACCOUNT_SA_ID, ""));
}

/*
 * @tc.name: LNN_ON_REMOVE_SYSTEM_ABILITY_002
 * @tc.desc: Verify OnRemoveSystemAbility handles unknown saId without crash
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnSaStatusMonitorTest, LNN_ON_REMOVE_SYSTEM_ABILITY_002, TestSize.Level1)
{
    sptr<ServiceStatusMonitorManager::SaStatusListener> listener =
        new ServiceStatusMonitorManager::SaStatusListener();
    ASSERT_NE(listener, nullptr);
    EXPECT_NO_FATAL_FAILURE(listener->OnRemoveSystemAbility(99999, ""));
    EXPECT_NO_FATAL_FAILURE(listener->OnRemoveSystemAbility(0, ""));
}

/*
 * @tc.name: LNN_ON_ADD_SYSTEM_ABILITY_001
 * @tc.desc: Verify OnAddSystemAbility handles ACCOUNT_SA_ID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnSaStatusMonitorTest, LNN_ON_ADD_SYSTEM_ABILITY_001, TestSize.Level1)
{
    LnnSaStatusMonitorInterfaceMock mocker;
    EXPECT_CALL(mocker, LnnAsyncCallbackDelayHelper).WillRepeatedly(Return(SOFTBUS_OK));
    sptr<ServiceStatusMonitorManager::SaStatusListener> listener =
        new ServiceStatusMonitorManager::SaStatusListener();
    ASSERT_NE(listener, nullptr);
    EXPECT_NO_FATAL_FAILURE(listener->OnAddSystemAbility(TEST_ACCOUNT_SA_ID, ""));
}

/*
 * @tc.name: LNN_ON_ADD_SYSTEM_ABILITY_002
 * @tc.desc: Verify OnAddSystemAbility handles unknown saId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnSaStatusMonitorTest, LNN_ON_ADD_SYSTEM_ABILITY_002, TestSize.Level1)
{
    sptr<ServiceStatusMonitorManager::SaStatusListener> listener =
        new ServiceStatusMonitorManager::SaStatusListener();
    ASSERT_NE(listener, nullptr);
    EXPECT_NO_FATAL_FAILURE(listener->OnAddSystemAbility(99999, ""));
}
} // namespace OHOS
