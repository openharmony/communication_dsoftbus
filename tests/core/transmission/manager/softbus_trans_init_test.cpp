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
#include <securec.h>

#include "softbus_trans_init.h"
#include "softbus_trans_init_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
class SoftbusTransInitTest : public testing::Test {
public:
    SoftbusTransInitTest() {}
    ~SoftbusTransInitTest() {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override {}
    void TearDown() override {}
};

void SoftbusTransInitTest::SetUpTestCase(void)
{}

void SoftbusTransInitTest::TearDownTestCase(void)
{}

static int32_t TransRegisterOpenfuncTemp(void)
{
    return SOFTBUS_NETWORK_DLOPEN_FAILED;
}

/**
 * @tc.name: TransOpenFuncInit001
 * @tc.desc: Use the wrong parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusTransInitTest, TransOpenFuncInit001, TestSize.Level1)
{
    int32_t ret = TransOpenFuncInit(nullptr);
    EXPECT_EQ(SOFTBUS_NETWORK_DLOPEN_FAILED, ret);
}

/**
 * @tc.name: TransOpenFuncInit002
 * @tc.desc: Use the wrong parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusTransInitTest, TransOpenFuncInit002, TestSize.Level1)
{
    void *pluginServerSoHandle = nullptr;
    (void)SoftBusDlopen(SOFTBUS_HANDLE_SERVER_PLUGIN, &pluginServerSoHandle);
    if (pluginServerSoHandle == nullptr) {
        return;
    }
    SoftbusTransInitInterfaceMock mock;
    EXPECT_CALL(mock, SoftBusDlsym).WillOnce(Return(SOFTBUS_NETWORK_DLSYM_FAILED));
    int32_t ret = TransOpenFuncInit(pluginServerSoHandle);
    EXPECT_EQ(SOFTBUS_NETWORK_DLSYM_FAILED, ret);
}

/**
 * @tc.name: TransOpenFuncInit003
 * @tc.desc: Use the wrong parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusTransInitTest, TransOpenFuncInit003, TestSize.Level1)
{
    SoftbusTransInitInterfaceMock mock;
    int32_t (*transRegisterOpenfunc)(void);
    void *pluginServerSoHandle = nullptr;
    (void)SoftBusDlopen(SOFTBUS_HANDLE_SERVER_PLUGIN, &pluginServerSoHandle);
    if (pluginServerSoHandle == nullptr) {
        return;
    }
    transRegisterOpenfunc = &TransRegisterOpenfuncTemp;
    void *funcHandle = reinterpret_cast<void *>(transRegisterOpenfunc);
    EXPECT_CALL(mock, SoftBusDlsym).WillOnce(DoAll(SetArgPointee<2>(funcHandle), Return(SOFTBUS_OK)));
    int32_t ret = TransOpenFuncInit(pluginServerSoHandle);
    EXPECT_EQ(SOFTBUS_NETWORK_TRANS_OPEN_FUNC_INIT_FAILED, ret);
}
} // namespace OHOS
