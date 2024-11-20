/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <gtest/gtest.h>

#include "comm_log.h"
#include "securec.h"
#include "softbus_adapter_mem.h"
#include "softbus_app_info.h"
#include "softbus_common.h"
#include "softbus_error_code.h"
#include "legacy/softbus_hidumper_alarm.h"
#include "legacy/softbus_hidumper_broadcast.h"
#include "legacy/softbus_hidumper_buscenter.h"
#include "legacy/softbus_hidumper_conn.h"
#include "legacy/softbus_hidumper_disc.h"
#include "legacy/softbus_hidumper_interface.h"
#include "legacy/softbus_hidumper_nstack.h"
#include "legacy/softbus_hidumper_stats.h"
#include "legacy/softbus_hidumper_trans.h"
#include "legacy/softbus_hidumper_util.h"
#include "legacy/softbus_hidumper.h"
#include "trans_network_statistics.c"
#include "trans_network_statistics.h"

using namespace std;
using namespace testing::ext;

namespace OHOS {
class TransNetworkStatisticsTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void TransNetworkStatisticsTest::SetUpTestCase(void) {}

void TransNetworkStatisticsTest::TearDownTestCase(void) {}

void TransNetworkStatisticsTest::SetUp(void) {}

void TransNetworkStatisticsTest::TearDown(void) {}

/* *
 * @tc.name: IsChannelDfxInfoValid001
 * @tc.desc: Test IsChannelDfxInfoValid when channelId is less than 0.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransNetworkStatisticsTest, IsChannelDfxInfoValid001, TestSize.Level1)
{
    int32_t channelId = -1;
    int32_t channelType = 1;
    EXPECT_FALSE(IsChannelDfxInfoValid(channelId, channelType));
}

/* *
 * @tc.name: IsChannelDfxInfoValid002
 * @tc.desc: Test IsChannelDfxInfoValid when g_channelDfxInfoList is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransNetworkStatisticsTest, IsChannelDfxInfoValid002, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t channelType = 1;
    TransNetworkStatisticsDeinit();
    EXPECT_FALSE(IsChannelDfxInfoValid(channelId, channelType));
}

/* *
 * @tc.name: IsChannelDfxInfoValid003
 * @tc.desc: Test IsChannelDfxInfoValid when channelType is invalid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransNetworkStatisticsTest, IsChannelDfxInfoValid003, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t channelType = -1;
    EXPECT_EQ(TransNetworkStatisticsInit(), SOFTBUS_OK);
    EXPECT_FALSE(IsChannelDfxInfoValid(channelId, channelType));
    TransNetworkStatisticsDeinit();
}

/* *
 * @tc.name: ChannelStatisticsInfoInit001
 * @tc.desc: Test ChannelStatisticsInfoInit when info is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransNetworkStatisticsTest, ChannelStatisticsInfoInit001, TestSize.Level1)
{
    int32_t channelId = 1;
    const void *dataInfo = "testData";
    uint32_t len = 8;
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ChannelStatisticsInfoInit(nullptr, channelId, dataInfo, len));
}

/* *
 * @tc.name: ChannelStatisticsInfoInit002
 * @tc.desc: Test ChannelStatisticsInfoInit when dataInfo is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransNetworkStatisticsTest, ChannelStatisticsInfoInit002, TestSize.Level1)
{
    int32_t channelId = 1;
    ChannelStatisticsInfo info;
    uint32_t len = 8;
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ChannelStatisticsInfoInit(&info, channelId, nullptr, len));
}

/* *
 * @tc.name: ChannelStatisticsInfoInit003
 * @tc.desc: Test ChannelStatisticsInfoInit when len is greater than MAX_SOCKET_RESOURCE_LEN.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransNetworkStatisticsTest, ChannelStatisticsInfoInit003, TestSize.Level1)
{
    int32_t channelId = 1;
    ChannelStatisticsInfo info;
    const void *dataInfo = "testData";
    uint32_t len = MAX_SOCKET_RESOURCE_LEN + 1;
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ChannelStatisticsInfoInit(&info, channelId, dataInfo, len));
}

/* *
 * @tc.name: ChannelStatisticsInfoInit004
 * @tc.desc: Test ChannelStatisticsInfoInit when all parameters are valid.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransNetworkStatisticsTest, ChannelStatisticsInfoInit004, TestSize.Level1)
{
    int32_t channelId = 1;
    ChannelStatisticsInfo info;
    const void *dataInfo = "testData";
    uint32_t len = 8;
    EXPECT_EQ(SOFTBUS_OK, ChannelStatisticsInfoInit(&info, channelId, dataInfo, len));
    SoftBusFree(info.channelInfo);
}

/* *
 * @tc.name: PackNetworkStatistics001
 * @tc.desc: Test PackNetworkStatistics when json is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransNetworkStatisticsTest, PackNetworkStatistics001, TestSize.Level1)
{
    NetworkStatisticsInfo info;
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, PackNetworkStatistics(nullptr, &info));
}

/* *
 * @tc.name: PackNetworkStatistics002
 * @tc.desc: Test PackNetworkStatistics when info is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransNetworkStatisticsTest, PackNetworkStatistics002, TestSize.Level1)
{
    cJSON *json = cJSON_CreateObject();
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, PackNetworkStatistics(json, nullptr));
    cJSON_Delete(json);
}

/* *
 * @tc.name: PackNetworkStatistics003
 * @tc.desc: Test PackNetworkStatistics when all parameters are valid.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransNetworkStatisticsTest, PackNetworkStatistics003, TestSize.Level1)
{
    cJSON *json = cJSON_CreateObject();
    NetworkStatisticsInfo info;
    info.resource.laneId = 1234567890;
    EXPECT_EQ(EOK, strcpy_s(info.resource.localUdid, sizeof(info.resource.localUdid), "localUdid"));
    EXPECT_EQ(EOK, strcpy_s(info.resource.peerUdid, sizeof(info.resource.peerUdid), "peerUdid"));
    info.resource.laneLinkType = 1;
    info.startTime = 1234567890;
    info.endTime = 1234567890;

    EXPECT_EQ(SOFTBUS_OK, PackNetworkStatistics(json, &info));
    cJSON_Delete(json);
}

/* *
 * @tc.name: AddChannelStatisticsInfo001
 * @tc.desc: Test AddChannelStatisticsInfo when channelId is less than 0.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransNetworkStatisticsTest, AddChannelStatisticsInfo001, TestSize.Level1)
{
    int32_t channelId = -1;
    int32_t channelType = 1;
    AddChannelStatisticsInfo(channelId, channelType);
    EXPECT_NO_FATAL_FAILURE(AddChannelStatisticsInfo(channelId, channelType));
}

/* *
 * @tc.name: AddChannelStatisticsInfo002
 * @tc.desc: Test AddChannelStatisticsInfo when g_channelDfxInfoList is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransNetworkStatisticsTest, AddChannelStatisticsInfo002, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t channelType = 1;
    TransNetworkStatisticsDeinit();
    AddChannelStatisticsInfo(channelId, channelType);
    EXPECT_NO_FATAL_FAILURE(AddChannelStatisticsInfo(channelId, channelType));
}

/* *
 * @tc.name: AddNetworkResource001
 * @tc.desc: Test AddNetworkResource when networkResource is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransNetworkStatisticsTest, AddNetworkResource001, TestSize.Level1)
{
    NetworkResource *networkResource = nullptr;
    AddNetworkResource(networkResource);
    EXPECT_NO_FATAL_FAILURE(AddNetworkResource(networkResource));
}

/* *
 * @tc.name: AddNetworkResource002
 * @tc.desc: Test AddNetworkResource when g_networkResourceList is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransNetworkStatisticsTest, AddNetworkResource002, TestSize.Level1)
{
    NetworkResource networkResource;
    TransNetworkStatisticsDeinit();
    AddNetworkResource(&networkResource);
    EXPECT_NO_FATAL_FAILURE(AddNetworkResource(&networkResource));
}

/* *
 * @tc.name: UpdateNetworkResourceByLaneId001
 * @tc.desc: Test UpdateNetworkResourceByLaneId when dataInfo is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransNetworkStatisticsTest, UpdateNetworkResourceByLaneId001, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t channelType = 1;
    uint64_t laneId = 1234567890;
    const void *dataInfo = nullptr;
    uint32_t len = 8;
    UpdateNetworkResourceByLaneId(channelId, channelType, laneId, dataInfo, len);
    EXPECT_NO_FATAL_FAILURE(UpdateNetworkResourceByLaneId(channelId, channelType, laneId, dataInfo, len));
}
} // namespace OHOS