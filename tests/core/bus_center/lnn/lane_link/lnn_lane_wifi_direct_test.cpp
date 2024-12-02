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

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <thread>

#include "lnn_lane_link_deps_mock.h"
#include "lnn_lane_wifi_direct_link.h"

namespace OHOS {
using namespace testing::ext;
using namespace testing;

class LNNLaneWifiDirectTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void LNNLaneWifiDirectTest::SetUpTestCase()
{
    GTEST_LOG_(INFO) << "LNNLaneWifiDirectTest start";
}

void LNNLaneWifiDirectTest::TearDownTestCase()
{
    GTEST_LOG_(INFO) << "LNNLaneWifiDirectTest end";
}

void LNNLaneWifiDirectTest::SetUp()
{
}

void LNNLaneWifiDirectTest::TearDown()
{
}

static void OnLaneLinkSuccess(uint32_t reqId, LaneLinkType linkType, const LaneLinkInfo *linkInfo)
{
    (void)reqId;
    (void)linkType;
    (void)linkInfo;
    GTEST_LOG_(INFO) << "link success";
}

static void OnLaneLinkFail(uint32_t reqId, int32_t reason, LaneLinkType linkType)
{
    (void)reqId;
    (void)reason;
    (void)linkType;
    GTEST_LOG_(INFO) << "link fail";
}

static LaneLinkCb g_linkCb = {
    .onLaneLinkSuccess = OnLaneLinkSuccess,
    .onLaneLinkFail = OnLaneLinkFail,
};

/*
* @tc.name: LNN_LANE_WIFI_DIRECT_CONN_TEST_001
* @tc.desc: test lane wifi direct link
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneWifiDirectTest, LNN_LANE_WIFI_DIRECT_CONN_TEST_001, TestSize.Level1)
{
    LnnWDRequestInfo request;
    request.linkType = LANE_HML;
    request.isNetworkDelegate = false;
    request.bandWidth = LANE_BW_20M;
    request.timeout = 1;
    int32_t ret = LnnWifiDirectConnect(0, &request, nullptr);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
* @tc.name: LNN_LANE_WIFI_DIRECT_CONN_TEST_002
* @tc.desc: test lane wifi direct link
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneWifiDirectTest, LNN_LANE_WIFI_DIRECT_CONN_TEST_002, TestSize.Level1)
{
    LnnWDRequestInfo request;
    request.linkType = LANE_HML;
    request.isNetworkDelegate = false;
    request.bandWidth = LANE_BW_20M;
    request.timeout = 1;
    int32_t ret = LnnWifiDirectConnect(0, &request, &g_linkCb);
    EXPECT_NE(ret, SOFTBUS_OK);
}
} // namespace OHOS