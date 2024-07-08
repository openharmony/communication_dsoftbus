/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#define private   public
#define protected public
#include "processor/p2p_v1_processor.h"
#undef protected
#undef private

#include <gtest/gtest.h>

#include "kits/c/wifi_device.h"

#include "wifi_direct_mock.h"

using namespace testing::ext;
using namespace testing;
using ::testing::_;
using ::testing::Invoke;

namespace OHOS::SoftBus {
class P2pV1ProcessorTest : public testing::Test {
public:
    static void SetUpTestCase() { }
    static void TearDownTestCase() { }
    void SetUp() override { }
    void TearDown() override { }
};

/*
 * @tc.name: GetStateName
 * @tc.desc: static method test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pV1ProcessorTest, GetStateName, TestSize.Level1)
{
    auto value = P2pV1Processor::GetStateName(&P2pV1Processor::AvailableState);
    EXPECT_EQ(value, "AvailableState");

    value = P2pV1Processor::GetStateName(&P2pV1Processor::OnWaitReqResponseTimeoutEvent);
    EXPECT_EQ(value, "UNKNOWN_STATE");
}

/*
 * @tc.name: IsNeedDhcp
 * @tc.desc: static method test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pV1ProcessorTest, IsNeedDhcp, TestSize.Level1)
{
    std::string enableDhcpGroupCfg = "DIRECT-XXX\n11:22:33:44:55:66\n12345678\n5170\n1";
    auto value = P2pV1Processor::IsNeedDhcp("", enableDhcpGroupCfg);
    EXPECT_EQ(value, true);

    value = P2pV1Processor::IsNeedDhcp("192.168.1.1", enableDhcpGroupCfg);
    EXPECT_EQ(value, true);

    std::string disableDhcpGroupCfg = "DIRECT-XXX\n11:22:33:44:55:66\n12345678\n5170\n0";
    value = P2pV1Processor::IsNeedDhcp("192.168.1.1", disableDhcpGroupCfg);
    EXPECT_EQ(value, false);
}

/*
 * @tc.name: ChooseFrequency
 * @tc.desc: static method test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pV1ProcessorTest, ChooseFrequency, TestSize.Level1)
{
    WifiDirectInterfaceMock mock;
    auto doMock = [&mock](int stationFreq, int recommendFreq, std::vector<int> channels) {
        EXPECT_CALL(mock, GetLinkedInfo(_)).WillRepeatedly([stationFreq](WifiLinkedInfo *result) {
            result->frequency = stationFreq;
            return WIFI_SUCCESS;
        });
        EXPECT_CALL(mock, Hid2dGetRecommendChannel(_, _))
            .WillRepeatedly(
                [recommendFreq](const RecommendChannelRequest *request, RecommendChannelResponse *response) {
                    response->centerFreq = recommendFreq;
                    return WIFI_SUCCESS;
                });
        EXPECT_CALL(mock, Hid2dGetChannelListFor5G(_, _)).WillRepeatedly([channels](int *chanList, int len) {
            for (int i = 0; i < channels.size() && i < len; ++i) {
                chanList[i] = channels[i];
            }
            return WIFI_SUCCESS;
        });
    };
    std::vector<int> gcChannels;

    doMock(2412, 2412, std::vector<int>());
    auto value = P2pV1Processor::ChooseFrequency(-1, gcChannels);
    EXPECT_EQ(value, 2412);

    doMock(-1, 2417, std::vector<int>());
    value = P2pV1Processor::ChooseFrequency(2417, gcChannels);
    EXPECT_EQ(value, 2417);

    doMock(-1, -1, std::vector<int> { 2, 13 });
    gcChannels.push_back(1);
    gcChannels.push_back(2);
    value = P2pV1Processor::ChooseFrequency(-1, gcChannels);
    EXPECT_EQ(value, 2417);

    doMock(2412, -1, std::vector<int>());
    gcChannels.clear();
    value = P2pV1Processor::ChooseFrequency(-1, gcChannels);
    EXPECT_EQ(value, 2412);

    doMock(-1, -1, std::vector<int>());
    value = P2pV1Processor::ChooseFrequency(2417, gcChannels);
    EXPECT_EQ(value, 2417);

    doMock(-1, -1, std::vector<int>());
    value = P2pV1Processor::ChooseFrequency(-1, gcChannels);
    EXPECT_EQ(value, 2412);

    doMock(-1, -1, std::vector<int>());
    EXPECT_CALL(mock, Hid2dGetChannelListFor5G(_, _)).WillRepeatedly([](int *chanList, int len) {
        return ERROR_WIFI_IFACE_INVALID;
    });
    value = P2pV1Processor::ChooseFrequency(-1, gcChannels);
    EXPECT_EQ(value, ToSoftBusErrorCode(ERROR_WIFI_IFACE_INVALID));
}

} // namespace OHOS::SoftBus
