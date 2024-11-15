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
#include "gtest/gtest.h"
#include <string>
#include "lnn_kv_store_launch_listener_mock.h"
#include "lnn_kv_store_launch_listener.h"
#include "lnn_settingdata_event_monitor.h"
#include "system_ability_definition.h"
#include "softbus_error_code.h"
#include "lnn_log.h"

using namespace std;
using namespace testing::ext;
OHOS::KvStoreStatusChangeListener *listener;
namespace OHOS {
class LNNKvStoreLaunchListenerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void LNNKvStoreLaunchListenerTest::SetUpTestCase(void)
{
    listener = new (std::nothrow) KvStoreStatusChangeListener();
    ASSERT_TRUE(listener != nullptr);
}

void LNNKvStoreLaunchListenerTest::TearDownTestCase(void)
{
    delete(listener);
    listener = nullptr;
}
void LNNKvStoreLaunchListenerTest::SetUp(void)
{
}
void LNNKvStoreLaunchListenerTest::TearDown(void)
{
}

/**
 * @tc.name: OnAddSystemAbility
 * @tc.desc: check DISTRIBUTED_KV_DATA_SERVICE_ABILITY_ID.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNKvStoreLaunchListenerTest, ON_ADD_SYSTEM_ABILITY_001, TestSize.Level1)
{
    LnnKvStoreLaunchListenerInterfaceMock mocker;
    EXPECT_CALL(mocker, LnnInitCloudSyncModule()).Times(1);
    EXPECT_NE(listener, nullptr);
    listener->OnAddSystemAbility(DISTRIBUTED_KV_DATA_SERVICE_ABILITY_ID, "");
    listener->OnRemoveSystemAbility(DISTRIBUTED_KV_DATA_SERVICE_ABILITY_ID, "");
}

/**
 * @tc.name: OnAddSystemAbility
 * @tc.desc: check not DISTRIBUTED_KV_DATA_SERVICE_ABILITY_ID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNKvStoreLaunchListenerTest, ON_ADD_SYSTEM_ABILITY_002, TestSize.Level1)
{
    LnnKvStoreLaunchListenerInterfaceMock mocker;
    EXPECT_CALL(mocker, LnnInitCloudSyncModule).Times(0);
    EXPECT_NE(listener, nullptr);
    listener->OnAddSystemAbility(DISTRIBUTED_KV_DATA_SERVICE_ABILITY_ID + 1, "");
    listener->OnRemoveSystemAbility(DISTRIBUTED_KV_DATA_SERVICE_ABILITY_ID + 1, "");
}
} //OHOS
