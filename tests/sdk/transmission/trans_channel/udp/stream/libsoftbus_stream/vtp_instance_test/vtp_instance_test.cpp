/*
 * Copyright (c) 2022-2026 Huawei Device Co., Ltd.
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

#define private public
#include "vtp_instance.cpp"
#include "vtp_instance.h"
#undef private

using namespace testing::ext;
namespace OHOS {
#define DEVICE_ID "DEVICE_ID"

class VtpInstanceTest : public testing::Test {
public:
    VtpInstanceTest() { }
    ~VtpInstanceTest() { }
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override { }
    void TearDown() override { }
};

void VtpInstanceTest::SetUpTestCase(void) { }

void VtpInstanceTest::TearDownTestCase(void) { }

/*
 * @tc.name: UpdateVtpLogLevel001
 * @tc.desc: test UpdateVtpLogLevel returns FILLP_DBG_LVL_DEBUG
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(VtpInstanceTest, UpdateVtpLogLevel001, TestSize.Level1)
{
    int32_t ret = Communication::SoftBus::UpdateVtpLogLevel();
    EXPECT_EQ(FILLP_DBG_LVL_DEBUG, ret);
}

/*
 * @tc.name: GetVersion001
 * @tc.desc: test GetVersion returns VTP_V1.0
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(VtpInstanceTest, GetVersion001, TestSize.Level1)
{
    std::shared_ptr<Communication::SoftBus::VtpInstance> vtpInstance =
        std::make_shared<Communication::SoftBus::VtpInstance>();
    std::string tmpStr = vtpInstance->GetVersion();

    EXPECT_TRUE(tmpStr == "VTP_V1.0");
}

/*
 * @tc.name: CryptoRand001
 * @tc.desc: test CryptoRand returns non-zero value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(VtpInstanceTest, CryptoRand001, TestSize.Level1)
{
    std::shared_ptr<Communication::SoftBus::VtpInstance> vtpInstance =
        std::make_shared<Communication::SoftBus::VtpInstance>();

    int32_t res = (int)vtpInstance->CryptoRand();
    EXPECT_NE(0, res);
}

/*
 * @tc.name: PreSetFillpCoreParams001
 * @tc.desc: test PreSetFillpCoreParams and InitVtp succeeds
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(VtpInstanceTest, PreSetFillpCoreParams001, TestSize.Level1)
{
    std::shared_ptr<Communication::SoftBus::VtpInstance> vtpInstance =
        std::make_shared<Communication::SoftBus::VtpInstance>();

    vtpInstance->PreSetFillpCoreParams();

    std::string pkgName = "CryptoRandTest";
    bool ret = vtpInstance->InitVtp(pkgName);
    EXPECT_EQ(true, ret);
    vtpInstance->DestroyVtp(pkgName);
}

/*
 * @tc.name: WaitForDestroy001
 * @tc.desc: test WaitForDestroy sets isDestroyed_ to true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(VtpInstanceTest, WaitForDestroy001, TestSize.Level1)
{
    std::shared_ptr<Communication::SoftBus::VtpInstance> vtpInstance =
        std::make_shared<Communication::SoftBus::VtpInstance>();
    vtpInstance->PreSetFillpCoreParams();
    const int32_t delayTimes = 1;
    vtpInstance->WaitForDestroy(delayTimes);
    EXPECT_TRUE(vtpInstance->isDestroyed_);
}

/*
 * @tc.name: InitVtp001
 * @tc.desc: test InitVtp succeeds when isDestroyed_ is true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(VtpInstanceTest, InitVtp001, TestSize.Level1)
{
    std::shared_ptr<Communication::SoftBus::VtpInstance> vtpInstance =
        std::make_shared<Communication::SoftBus::VtpInstance>();
    vtpInstance->PreSetFillpCoreParams();
    vtpInstance->isDestroyed_ = true;
    std::string pkgName = "InitVtp001";
    bool res = vtpInstance->InitVtp(pkgName);
    EXPECT_TRUE(res);
    vtpInstance->DestroyVtp(pkgName);
}

/*
 * @tc.name: InitVtp002
 * @tc.desc: test InitVtp succeeds when isDestroyed_ is false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(VtpInstanceTest, InitVtp002, TestSize.Level1)
{
    std::shared_ptr<Communication::SoftBus::VtpInstance> vtpInstance =
        std::make_shared<Communication::SoftBus::VtpInstance>();
    vtpInstance->PreSetFillpCoreParams();
    vtpInstance->isDestroyed_ = false;
    std::string pkgName = "InitVtp002";
    bool res = vtpInstance->InitVtp(pkgName);
    EXPECT_TRUE(res);
    vtpInstance->DestroyVtp(pkgName);
}

/*
 * @tc.name: UpdateSocketStreamCount001
 * @tc.desc: test UpdateSocketStreamCount increments count when add is true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(VtpInstanceTest, UpdateSocketStreamCount001, TestSize.Level1)
{
    std::shared_ptr<Communication::SoftBus::VtpInstance> vtpInstance =
        std::make_shared<Communication::SoftBus::VtpInstance>();
    vtpInstance->PreSetFillpCoreParams();
    std::string pkgName = "UpdateSocketStreamCount001";
    bool res = vtpInstance->InitVtp(pkgName);
    ASSERT_TRUE(res);
    bool add = true;
    vtpInstance->UpdateSocketStreamCount(add);
    EXPECT_EQ(1, vtpInstance->socketStreamCount_);
    vtpInstance->DestroyVtp(pkgName);
}

/*
 * @tc.name: UpdateSocketStreamCount002
 * @tc.desc: test UpdateSocketStreamCount does not decrement when count is 0 and add is false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(VtpInstanceTest, UpdateSocketStreamCount002, TestSize.Level1)
{
    std::shared_ptr<Communication::SoftBus::VtpInstance> vtpInstance =
        std::make_shared<Communication::SoftBus::VtpInstance>();
    vtpInstance->PreSetFillpCoreParams();
    std::string pkgName = "UpdateSocketStreamCount002";
    bool res = vtpInstance->InitVtp(pkgName);
    ASSERT_TRUE(res);
    vtpInstance->socketStreamCount_ = 0;
    bool add = false;
    vtpInstance->UpdateSocketStreamCount(add);
    EXPECT_EQ(0, vtpInstance->socketStreamCount_);
    vtpInstance->DestroyVtp(pkgName);
}

/*
 * @tc.name: UpdateSocketStreamCount003
 * @tc.desc: test UpdateSocketStreamCount decrements count when count is 1 and add is false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(VtpInstanceTest, UpdateSocketStreamCount003, TestSize.Level1)
{
    std::shared_ptr<Communication::SoftBus::VtpInstance> vtpInstance =
        std::make_shared<Communication::SoftBus::VtpInstance>();
    vtpInstance->PreSetFillpCoreParams();
    std::string pkgName = "UpdateSocketStreamCount003";
    bool res = vtpInstance->InitVtp(pkgName);
    ASSERT_TRUE(res);
    vtpInstance->socketStreamCount_ = 1;
    bool add = false;
    vtpInstance->UpdateSocketStreamCount(add);
    EXPECT_EQ(0, vtpInstance->socketStreamCount_);
    vtpInstance->DestroyVtp(pkgName);
}
} // namespace OHOS
