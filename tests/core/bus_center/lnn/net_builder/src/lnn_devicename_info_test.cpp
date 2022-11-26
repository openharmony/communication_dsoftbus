/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "lnn_devicename_info.h"
#include "lnn_net_builder_deps_mock.h"
#include "lnn_p2p_info.h"
#include "message_handler.h"
#include "softbus_common.h"
#include "softbus_errcode.h"
#include "bus_center_info_key.h"
#include "lnn_net_ledger_mock.h"
#include "lnn_node_info.h"

NodeInfo *info = {0};
constexpr char *DEVICE_NAME1 = nullptr;
constexpr char DEVICE_NAME2[] = "ABCDEFG";

namespace OHOS {
using namespace testing;
using namespace testing::ext;

class LnnDeviceNameInfoTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void LnnDeviceNameInfoTest::SetUpTestCase()
{
}

void LnnDeviceNameInfoTest::TearDownTestCase()
{
}

void LnnDeviceNameInfoTest::SetUp()
{
}

void LnnDeviceNameInfoTest::TearDown()
{
}

/*
* @tc.name: LNN_UPDATE_DEVICE_NAME_TEST_001
* @tc.desc: no retry
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LnnDeviceNameInfoTest, LNN_UPDATE_DEVICE_NAME_TEST_001, TestSize.Level1)
{
    NiceMock<NetBuilderDepsInterfaceMock> netbuilderMock;
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    char name[DEVICE_NAME_BUF_LEN] = {0};
    LooperInit();
    EXPECT_CALL(netbuilderMock, LnnGetSettingDeviceName(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ledgerMock, LnnSetLocalStrInfo(STRING_KEY_DEV_NAME, name)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ledgerMock, LnnGetAllOnlineAndMetaNodeInfo(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ledgerMock, LnnGetLocalNodeInfo()).WillRepeatedly(Return(info));
    EXPECT_CALL(ledgerMock, LnnGetDeviceName(_)).WillRepeatedly(Return(DEVICE_NAME1));
    EXPECT_CALL(ledgerMock, LnnGetDeviceName(_)).WillRepeatedly(Return(DEVICE_NAME2));
    UpdateDeviceName(nullptr);
    LooperDeinit();
}

/*
* @tc.name: LNN_UPDATE_DEVICE_NAME_TEST_002
* @tc.desc: looper is null
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LnnDeviceNameInfoTest, LNN_UPDATE_DEVICE_NAME_TEST_002, TestSize.Level1)
{
    NiceMock<NetBuilderDepsInterfaceMock> netbuilderMock;
    EXPECT_CALL(netbuilderMock, LnnGetSettingDeviceName(_, _)).WillRepeatedly(Return(SOFTBUS_ERR));
    UpdateDeviceName(nullptr);
}
} // namespace OHOS
