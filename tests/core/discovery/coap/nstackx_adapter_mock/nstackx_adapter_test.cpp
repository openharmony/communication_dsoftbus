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
#include "disc_log.h"
#include "nstackx_adapter_mock.h"

#include "lnn_local_net_ledger.h"
#include "nstackx_error.h"
#include "softbus_error_code.h"

#include "disc_nstackx_adapter.h"

using namespace testing::ext;
using testing::_;
using testing::NotNull;
using testing::Return;

namespace OHOS {
class NstackxAdapterTest : public testing::Test {
public:
    static void SetUpTestCase() { }
    static void TearDownTestCase() { }

    void SetUp() override { }
    void TearDown() override { }
};

/*
 * @tc.name: DiscCoapRegisterServiceData002
 * @tc.desc: Test DiscCoapRegisterServiceData use mock NSTACKX_RegisterServiceData to return error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NstackxAdapterTest, DiscCoapRegisterServiceData002, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscCoapRegisterServiceData002 begin ----");
    DiscNstackxInit();
    int32_t ret = LnnInitLocalLedger();
    DISC_LOGI(DISC_TEST, "LnnInitLocalLedger called  ret=%{public}d", ret);

    AdapterMock adapterMock;
    PublishOption option = {
        .freq = LOW,
    };
    EXPECT_CALL(adapterMock, NSTACKX_RegisterServiceData(NotNull()))
        .WillRepeatedly(Return(SOFTBUS_DISCOVER_COAP_REGISTER_CAP_FAIL));

    EXPECT_EQ(DiscCoapRegisterServiceData(&option, 0), SOFTBUS_DISCOVER_COAP_REGISTER_CAP_FAIL);
    DISC_LOGI(DISC_TEST, "DiscCoapRegisterServiceData002 end ----");
}
} // namespace OHOS
