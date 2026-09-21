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

#include <gtest/gtest.h>
#include <memory>

#include "lnn_device_info_struct.h"
#include "perception_deps_mock.h"
#include "perception_manager.h"
#include "softbus_error_code.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;

namespace {
constexpr char VALID_PKG[] = "perception_test_pkg";
constexpr PerceptionType VALID_TYPE = PERCEPTION_TYPE_COLLABORATIVE_WAKE;
constexpr PerceptionCycle VALID_CYCLE = PERCEPTION_CYCLE_LOW;
} // namespace

class PerceptionManagerTest : public testing::Test {
public:
    static void SetUpTestSuite() {}
    static void TearDownTestSuite() {}
    void SetUp() override
    {
        mock_ = std::make_unique<PerceptionDepsMock>();
        ON_CALL(*mock_, LnnIsLocalSupportBurstFeature).WillByDefault(Return(true));
        ON_CALL(*mock_, IsSupportLpFeaturePacked).WillByDefault(Return(true));
        ON_CALL(*mock_, LnnGetLocalNumInfo).WillByDefault([](InfoKey, int32_t *info) {
            *info = (int32_t)TYPE_PHONE_ID;
            return SOFTBUS_OK;
        });
        ON_CALL(*mock_, PerceptionAdvertiserInit).WillByDefault(Return(SOFTBUS_OK));
        ON_CALL(*mock_, PerceptionScannerInit).WillByDefault(Return(SOFTBUS_OK));
        ON_CALL(*mock_, LnnRegisterEventHandler).WillByDefault(Return(SOFTBUS_OK));
        ON_CALL(*mock_, PerceptionEnhanceInitPacked).WillByDefault(Return(SOFTBUS_NOT_IMPLEMENT));
        ON_CALL(*mock_, PerceptionEnhanceDeinitPacked).WillByDefault(Return());
        ON_CALL(*mock_, PerceptionAdvertiserDeinit).WillByDefault(Return());
        ON_CALL(*mock_, PerceptionScannerDeinit).WillByDefault(Return());
        ON_CALL(*mock_, LnnUnregisterEventHandler).WillByDefault(Return());
        EXPECT_EQ(PerceptionManagerInit(), SOFTBUS_OK);
    }
    void TearDown() override
    {
        PerceptionManagerDeinit();
        mock_.reset();
    }

protected:
    static PerceptionAdvParam MakeParam(uint32_t len)
    {
        PerceptionAdvParam p{};
        p.customDataLen = len;
        return p;
    }
    std::unique_ptr<PerceptionDepsMock> mock_;
};

HWTEST_F(PerceptionManagerTest, StartAdv_NullPkgName, TestSize.Level1)
{
    auto param = MakeParam(0);
    EXPECT_EQ(LnnStartPerceptionAdv(nullptr, VALID_TYPE, &param), SOFTBUS_INVALID_PKGNAME);
}

HWTEST_F(PerceptionManagerTest, StartAdv_InvalidType, TestSize.Level1)
{
    auto param = MakeParam(0);
    EXPECT_EQ(LnnStartPerceptionAdv(VALID_PKG, PERCEPTION_TYPE_BUTT, &param), SOFTBUS_INVALID_PARAM);
}

HWTEST_F(PerceptionManagerTest, StartAdv_NullParam, TestSize.Level1)
{
    EXPECT_EQ(LnnStartPerceptionAdv(VALID_PKG, VALID_TYPE, nullptr), SOFTBUS_INVALID_PARAM);
}

HWTEST_F(PerceptionManagerTest, StartAdv_OversizedCustomData, TestSize.Level1)
{
    auto param = MakeParam(PERCEPTION_CUSTOM_DATA_MAX_LEN + 1);
    EXPECT_EQ(LnnStartPerceptionAdv(VALID_PKG, VALID_TYPE, &param), SOFTBUS_INVALID_PARAM);
}

HWTEST_F(PerceptionManagerTest, StartAdv_NotInited, TestSize.Level1)
{
    PerceptionManagerDeinit();
    auto param = MakeParam(0);
    EXPECT_CALL(*mock_, PerceptionAdvStart).Times(0);
    EXPECT_EQ(LnnStartPerceptionAdv(VALID_PKG, VALID_TYPE, &param), SOFTBUS_NO_INIT);
}

HWTEST_F(PerceptionManagerTest, StartAdv_Success, TestSize.Level1)
{
    auto param = MakeParam(0);
    EXPECT_CALL(*mock_, PerceptionAdvStart(VALID_TYPE, _)).WillOnce(Return(SOFTBUS_OK));
    EXPECT_EQ(LnnStartPerceptionAdv(VALID_PKG, VALID_TYPE, &param), SOFTBUS_OK);
}

HWTEST_F(PerceptionManagerTest, SetHighFreq_NullParam, TestSize.Level1)
{
    EXPECT_EQ(LnnSetPerceptionAdvHighFreq(VALID_PKG, VALID_TYPE, nullptr), SOFTBUS_INVALID_PARAM);
}

HWTEST_F(PerceptionManagerTest, SetHighFreq_NotInited, TestSize.Level1)
{
    PerceptionManagerDeinit();
    auto param = MakeParam(0);
    EXPECT_CALL(*mock_, PerceptionAdvSetHighFreq).Times(0);
    EXPECT_EQ(LnnSetPerceptionAdvHighFreq(VALID_PKG, VALID_TYPE, &param), SOFTBUS_NO_INIT);
}

HWTEST_F(PerceptionManagerTest, SetHighFreq_Success, TestSize.Level1)
{
    auto param = MakeParam(0);
    EXPECT_CALL(*mock_, PerceptionAdvSetHighFreq(VALID_TYPE, _)).WillOnce(Return(SOFTBUS_OK));
    EXPECT_EQ(LnnSetPerceptionAdvHighFreq(VALID_PKG, VALID_TYPE, &param), SOFTBUS_OK);
}

HWTEST_F(PerceptionManagerTest, StopAdv_InvalidType, TestSize.Level1)
{
    EXPECT_CALL(*mock_, PerceptionAdvStop).Times(0);
    EXPECT_EQ(LnnStopPerceptionAdv(VALID_PKG, PERCEPTION_TYPE_BUTT), SOFTBUS_INVALID_PARAM);
}

HWTEST_F(PerceptionManagerTest, StopAdv_Success, TestSize.Level1)
{
    EXPECT_CALL(*mock_, PerceptionAdvStop()).WillOnce(Return(SOFTBUS_OK));
    EXPECT_EQ(LnnStopPerceptionAdv(VALID_PKG, VALID_TYPE), SOFTBUS_OK);
}

HWTEST_F(PerceptionManagerTest, StartScan_InvalidCycle, TestSize.Level1)
{
    EXPECT_CALL(*mock_, PerceptionScanStart).Times(0);
    EXPECT_EQ(LnnStartPerceptionScan(VALID_PKG, VALID_TYPE, PERCEPTION_CYCLE_BUTT), SOFTBUS_INVALID_PARAM);
}

HWTEST_F(PerceptionManagerTest, StartScan_BurstNotSupported, TestSize.Level1)
{
    ON_CALL(*mock_, LnnIsLocalSupportBurstFeature).WillByDefault(Return(false));
    ON_CALL(*mock_, IsSupportLpFeaturePacked).WillByDefault(Return(false));
    EXPECT_CALL(*mock_, PerceptionScanStart).Times(0);
    EXPECT_EQ(LnnStartPerceptionScan(VALID_PKG, VALID_TYPE, VALID_CYCLE), SOFTBUS_FUNC_NOT_SUPPORT);
}

HWTEST_F(PerceptionManagerTest, StartScan_DevTypeNotSupported, TestSize.Level1)
{
    ON_CALL(*mock_, LnnGetLocalNumInfo).WillByDefault([](InfoKey, int32_t *info) {
        *info = (int32_t)TYPE_WATCH_ID;
        return SOFTBUS_OK;
    });
    EXPECT_CALL(*mock_, PerceptionScanStart).Times(0);
    EXPECT_EQ(LnnStartPerceptionScan(VALID_PKG, VALID_TYPE, VALID_CYCLE), SOFTBUS_FUNC_NOT_SUPPORT);
}

HWTEST_F(PerceptionManagerTest, StartScan_NotInited, TestSize.Level1)
{
    PerceptionManagerDeinit();
    EXPECT_CALL(*mock_, PerceptionScanStart).Times(0);
    EXPECT_EQ(LnnStartPerceptionScan(VALID_PKG, VALID_TYPE, VALID_CYCLE), SOFTBUS_NO_INIT);
}

HWTEST_F(PerceptionManagerTest, StartScan_Success, TestSize.Level1)
{
    EXPECT_CALL(*mock_, PerceptionScanStart(VALID_TYPE, VALID_CYCLE)).WillOnce(Return(SOFTBUS_OK));
    EXPECT_EQ(LnnStartPerceptionScan(VALID_PKG, VALID_TYPE, VALID_CYCLE), SOFTBUS_OK);
}

HWTEST_F(PerceptionManagerTest, StopScan_InvalidType, TestSize.Level1)
{
    EXPECT_CALL(*mock_, PerceptionScanStop).Times(0);
    EXPECT_EQ(LnnStopPerceptionScan(VALID_PKG, PERCEPTION_TYPE_BUTT), SOFTBUS_INVALID_PARAM);
}

HWTEST_F(PerceptionManagerTest, StopScan_Success, TestSize.Level1)
{
    EXPECT_CALL(*mock_, PerceptionScanStop()).WillOnce(Return(SOFTBUS_OK));
    EXPECT_EQ(LnnStopPerceptionScan(VALID_PKG, VALID_TYPE), SOFTBUS_OK);
}

HWTEST_F(PerceptionManagerTest, GetDeviceList_NullOut, TestSize.Level1)
{
    EXPECT_CALL(*mock_, PerceptionScanGetDeviceList).Times(0);
    EXPECT_EQ(LnnGetPerceptionDeviceList(VALID_PKG, VALID_TYPE, nullptr, nullptr), SOFTBUS_INVALID_PARAM);
}

HWTEST_F(PerceptionManagerTest, GetDeviceList_BurstNotSupported, TestSize.Level1)
{
    ON_CALL(*mock_, LnnIsLocalSupportBurstFeature).WillByDefault(Return(false));
    ON_CALL(*mock_, IsSupportLpFeaturePacked).WillByDefault(Return(false));
    PerceptionDeviceInfo *list = nullptr;
    uint32_t count = 0;
    EXPECT_CALL(*mock_, PerceptionScanGetDeviceList).Times(0);
    EXPECT_EQ(LnnGetPerceptionDeviceList(VALID_PKG, VALID_TYPE, &list, &count), SOFTBUS_FUNC_NOT_SUPPORT);
}

HWTEST_F(PerceptionManagerTest, GetDeviceList_DevTypeNotSupported, TestSize.Level1)
{
    ON_CALL(*mock_, LnnGetLocalNumInfo).WillByDefault([](InfoKey, int32_t *info) {
        *info = (int32_t)TYPE_WATCH_ID;
        return SOFTBUS_OK;
    });
    PerceptionDeviceInfo *list = nullptr;
    uint32_t count = 0;
    EXPECT_CALL(*mock_, PerceptionScanGetDeviceList).Times(0);
    EXPECT_EQ(LnnGetPerceptionDeviceList(VALID_PKG, VALID_TYPE, &list, &count), SOFTBUS_FUNC_NOT_SUPPORT);
}

HWTEST_F(PerceptionManagerTest, GetDeviceList_NotInited, TestSize.Level1)
{
    PerceptionManagerDeinit();
    PerceptionDeviceInfo *list = nullptr;
    uint32_t count = 0;
    EXPECT_CALL(*mock_, PerceptionScanGetDeviceList).Times(0);
    EXPECT_EQ(LnnGetPerceptionDeviceList(VALID_PKG, VALID_TYPE, &list, &count), SOFTBUS_NO_INIT);
}

HWTEST_F(PerceptionManagerTest, GetDeviceList_Success, TestSize.Level1)
{
    PerceptionDeviceInfo *list = nullptr;
    uint32_t count = 0;
    EXPECT_CALL(*mock_, PerceptionScanGetDeviceList(VALID_TYPE, _, _)).WillOnce(Return(SOFTBUS_OK));
    EXPECT_EQ(LnnGetPerceptionDeviceList(VALID_PKG, VALID_TYPE, &list, &count), SOFTBUS_OK);
}
