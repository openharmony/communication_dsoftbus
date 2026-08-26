 /*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include <securec.h>

#include "gtest/gtest.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"
#include "softbus_proxychannel_manager.h"
#include "softbus_proxychannel_manager.c"
#include "bus_center_event.h"

using namespace testing::ext;

namespace OHOS {

#define TEST_PID 1000
#define TEST_SERVICE_ID_1 1001
#define TEST_SERVICE_ID_2 1002
#define TEST_SERVICE_ID_COUNT 2
#define TEST_INVALID_COUNT_0 0

class SoftbusProxyProfileDeletedTest : public testing::Test {
public:
    SoftbusProxyProfileDeletedTest()
    {}
    ~SoftbusProxyProfileDeletedTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override {}
    void TearDown() override {}
};

void SoftbusProxyProfileDeletedTest::SetUpTestCase(void) {}

void SoftbusProxyProfileDeletedTest::TearDownTestCase(void) {}

/*
 * @tc.name: TransNotifyProfileDeletedTest001
 * @tc.desc: TransNotifyProfileDeleted with null info returns early without crash
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyProfileDeletedTest, TransNotifyProfileDeletedTest001, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(TransNotifyProfileDeleted(nullptr));
}

/*
 * @tc.name: TransNotifyProfileDeletedTest002
 * @tc.desc: TransNotifyProfileDeleted with invalid event type returns early without crash
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyProfileDeletedTest, TransNotifyProfileDeletedTest002, TestSize.Level1)
{
    LnnEventBasicInfo info = {
        .event = LNN_EVENT_NODE_ONLINE_STATE_CHANGED,
    };
    EXPECT_NO_FATAL_FAILURE(TransNotifyProfileDeleted(&info));
}

/*
 * @tc.name: TransNotifyProfileDeletedTest003
 * @tc.desc: TransNotifyProfileDeleted with valid event type processes profile deletion
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyProfileDeletedTest, TransNotifyProfileDeletedTest003, TestSize.Level1)
{
    LnnAccountAclChangeEvent profileEvent;
    (void)memset_s(&profileEvent, sizeof(profileEvent), 0, sizeof(profileEvent));
    profileEvent.basic.event = LNN_EVENT_ACCOUNT_ACL_CHANGE;
    int64_t serviceIds[] = {TEST_SERVICE_ID_1, TEST_SERVICE_ID_2};
    profileEvent.serviceIdCount = TEST_SERVICE_ID_COUNT;
    (void)memcpy_s(profileEvent.serviceIdList, sizeof(serviceIds), serviceIds, sizeof(serviceIds));
    EXPECT_NO_FATAL_FAILURE(TransNotifyProfileDeleted(reinterpret_cast<LnnEventBasicInfo *>(&profileEvent)));
}

/*
 * @tc.name: TransNotifyProfileDeletedTest004
 * @tc.desc: TransNotifyProfileDeleted with zero serviceIdCount returns early without crash
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyProfileDeletedTest, TransNotifyProfileDeletedTest004, TestSize.Level1)
{
    LnnAccountAclChangeEvent profileEvent;
    (void)memset_s(&profileEvent, sizeof(profileEvent), 0, sizeof(profileEvent));
    profileEvent.basic.event = LNN_EVENT_ACCOUNT_ACL_CHANGE;
    profileEvent.serviceIdCount = TEST_INVALID_COUNT_0;
    EXPECT_NO_FATAL_FAILURE(TransNotifyProfileDeleted(reinterpret_cast<LnnEventBasicInfo *>(&profileEvent)));
}
} // namespace OHOS