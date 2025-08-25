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
#include "gtest/gtest.h"
#include <securec.h>

#include "bus_center_event.h"
#include "g_enhance_adapter_func.h"
#include "lnn_sle_monitor.c"
#include "lnn_event_monitor_impl.h"
#include "network_mock.h"
#include "softbus_error_code.h"

namespace OHOS {
using namespace testing::ext;
using namespace testing;
class SoftbusSleMonitorTest : public testing::Test {
protected:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};
void SoftbusSleMonitorTest::SetUpTestCase(void)
{
    AdapterEnhanceFuncList *pfnAdapterFuncList = AdapterEnhanceFuncListGet();
    pfnAdapterFuncList->softBusAddSleStateListener = SoftBusAddSleStateListener;
    pfnAdapterFuncList->isSleEnabled = IsSleEnabled;
    pfnAdapterFuncList->softBusRemoveSleStateListener = SoftBusRemoveSleStateListener;
}
void SoftbusSleMonitorTest::TearDownTestCase(void) { }
void SoftbusSleMonitorTest::SetUp() { }
void SoftbusSleMonitorTest::TearDown() { }

/*
 * @tc.name: LnnInitSle
 * @tc.desc: softbus network test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusSleMonitorTest, LnnInitSleTest001, TestSize.Level1)
{
    NiceMock<NetworkInterfaceMock> networkMock;
    EXPECT_CALL(networkMock, LnnAsyncCallbackHelper).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(networkMock, SoftBusAddSleStateListener)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(DoAll(SetArgPointee<1>(1), Return(SOFTBUS_OK)));

    int32_t ret = LnnInitSle();
    EXPECT_TRUE(ret != SOFTBUS_OK);
    EXPECT_CALL(networkMock, IsSleEnabled).WillOnce(Return(false)).WillRepeatedly(Return(true));
    ret = LnnInitSle();
    EXPECT_TRUE(ret == SOFTBUS_OK);
    EXPECT_CALL(networkMock, SoftBusRemoveSleStateListener) .WillOnce(Return());
    EXPECT_NO_FATAL_FAILURE(LnnDeinitSle());
    EXPECT_NO_FATAL_FAILURE(LnnOnSleStateChanged(SOFTBUS_SLE_UNKNOWN));
}

} // namespace OHOS