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
#include "softbus_conn_interface.h"
#include "softbus_conn_manager.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_feature_config.h"
#include "softbus_log.h"
#include "br_connection_manager.c"

using namespace testing::ext;
namespace OHOS {
class ConnectionBrManagerTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() override {}
    void TearDown() override {}
};

/*
* @tc.name: HasDiffMacDeviceExit
* @tc.desc:  br mac match
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnectionBrManagerTest, HasDiffMacDeviceExit, TestSize.Level1)
{
    BrConnectionInfo *info = CreateBrconnectionNode(true);
    char mac[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 };
    memcpy_s(info->mac, sizeof(info->mac), mac, sizeof(mac));
    ListAdd(&g_connection_list, &info->node);

    ConnectOption option;
    int32_t ret = HasDiffMacDeviceExit(&option);
    EXPECT_EQ(ret, true);

    ListDelete(&info->node);
    SoftBusFree(info);
}

/*
* @tc.name: GetBrConnStateByConnectionId
* @tc.desc:  find by connection Id
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnectionBrManagerTest, GetBrConnStateByConnectionId, TestSize.Level1)
{
    BrConnectionInfo *info = CreateBrconnectionNode(true);
    info->state = BR_CONNECTION_STATE_CLOSED;
    ListAdd(&g_connection_list, &info->node);

    int32_t ret = GetBrConnStateByConnectionId(info->connectionId);
    EXPECT_EQ(ret, BR_CONNECTION_STATE_CLOSED);

    ListDelete(&info->node);
    SoftBusFree(info);
}

/*
* @tc.name: BrClosingByConnOption
* @tc.desc:  br mac match
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnectionBrManagerTest, BrClosingByConnOption, TestSize.Level1)
{
    char mac[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 };
    BrConnectionInfo *info = CreateBrconnectionNode(true);
    memcpy_s(info->mac, sizeof(info->mac), mac, sizeof(mac));
    info->state = BR_CONNECTION_STATE_CLOSED;
    ListAdd(&g_connection_list, &info->node);

    ConnectOption option;
    memcpy_s(option.brOption.brMac, sizeof(option.brOption.brMac), mac, sizeof(mac));

    int32_t socketFd;
    int32_t sideType;
    int32_t ret = BrClosingByConnOption(&option, &socketFd, &sideType);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ListDelete(&info->node);
    SoftBusFree(info);
}

/*
* @tc.name: BrCheckActiveConnection
* @tc.desc:  br mac match and state
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnectionBrManagerTest, BrCheckActiveConnection, TestSize.Level1)
{
    char mac[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 };
    BrConnectionInfo *info = CreateBrconnectionNode(true);
    memcpy_s(info->mac, sizeof(info->mac), mac, sizeof(mac));
    info->state = BR_CONNECTION_STATE_CONNECTED;
    ListAdd(&g_connection_list, &info->node);

    ConnectOption option;
    memcpy_s(option.brOption.brMac, sizeof(option.brOption.brMac), mac, sizeof(mac));

    int32_t ret = BrCheckActiveConnection(&option);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ListDelete(&info->node);
    SoftBusFree(info);
}
}