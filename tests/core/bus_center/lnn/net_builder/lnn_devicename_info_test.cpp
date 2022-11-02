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
#include "lnn_p2p_info.c"
#include "message_handler.h"
#include "softbus_common.h"
#include "softbus_errcode.h"

namespace OHOS {
using namespace testing::ext;
using namespace testing;
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
    NetBuilderDepsInterfaceMock deviceNameMock;
    EXPECT_CALL(deviceNameMock, LnnGetSettingDeviceName(_,_)).WillRepeatedly(Return(SOFTBUS_ERR));
    LooperInit();
    UpdateDeviceName(nullptr);
    LooperDeinit();
}

/*
* @tc.name: LNN_UPDATE_DEVICE_NAME_TEST_001
* @tc.desc: looper is null
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LnnDeviceNameInfoTest, LNN_UPDATE_DEVICE_NAME_TEST_003, TestSize.Level1)
{
    NetBuilderDepsInterfaceMock deviceNameMock;
    EXPECT_CALL(deviceNameMock, LnnGetSettingDeviceName(_,_)).WillRepeatedly(Return(SOFTBUS_ERR));
    UpdateDeviceName(nullptr);
}

/*
* @tc.name: LNN_P2P_INFO_TEST_001
* @tc.desc: GetAllOnlineAndMetaNode success
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LnnDeviceNameInfoTest, LNN_P2P_INFO_TEST_001, TestSize.Level1)
{
    NetBuilderDepsInterfaceMock deviceNameMock;
    EXPECT_CALL(deviceNameMock, LnnGetAllOnlineAndMetaNodeInfo(_,_)).WillRepeatedly(Return(SOFTBUS_OK));
    ProcessSyncP2pInfo(nullptr);
}

/*
* @tc.name: LNN_P2P_INFO_TEST_001
* @tc.desc: GetAllOnlineAndMetaNode fail
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LnnDeviceNameInfoTest, LNN_P2P_INFO_TEST_002, TestSize.Level1)
{
    NetBuilderDepsInterfaceMock deviceNameMock;
    EXPECT_CALL(deviceNameMock, LnnGetAllOnlineAndMetaNodeInfo(_,_)).WillRepeatedly(Return(SOFTBUS_ERR));
    ProcessSyncP2pInfo(nullptr);
}

} // namespace OHOS
