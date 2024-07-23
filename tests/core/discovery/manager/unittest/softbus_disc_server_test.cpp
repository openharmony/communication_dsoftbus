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

#include <securec.h>

#include "disc_log.h"
#include "softbus_common.h"
#include "softbus_disc_server.h"
#include "softbus_disc_server_mock.h"
#include "softbus_errcode.h"

using namespace testing;
using namespace testing::ext;
using testing::Return;

namespace OHOS {
class DiscManagerServerTest : public testing::Test {
public:
    static void SetUpTestCase()
    {}
    static void TearDownTestCase()
    {}

    void SetUp()
    {}
    void TearDown()
    {}
};


/*
 * @tc.name: DiscIpcPublishServiceTest
 * @tc.desc: Test the invalid parameter input and normal flow of the DiscIpcPublishService function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscManagerServerTest, DiscIpcPublishServiceTest, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscIpcPublishServiceTest start");
    PublishInfo publishInfo;
    (void)memset_s(&publishInfo, sizeof(PublishInfo), 0, sizeof(PublishInfo));
    const char *packageName = "packageName";
    EXPECT_EQ(DiscIpcPublishService(nullptr, &publishInfo), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(DiscIpcPublishService(packageName, nullptr), SOFTBUS_INVALID_PARAM);
    DiscMock discMock;
    EXPECT_CALL(discMock, ClientIpcOnPublishFail).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(discMock, ClientIpcOnPublishSuccess).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(discMock, SoftbusReportDiscFault).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(discMock, DiscPublishService).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_EQ(DiscIpcPublishService(packageName, &publishInfo), SOFTBUS_INVALID_PARAM);
    EXPECT_CALL(discMock, DiscPublishService).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_EQ(DiscIpcPublishService(packageName, &publishInfo), SOFTBUS_OK);
    DISC_LOGI(DISC_TEST, "DiscIpcPublishServiceTest end");
}

/*
 * @tc.name: DiscIpcUnPublishServiceTest
 * @tc.desc: Test the invalid parameter input and normal flow of the DiscIpcUnPublishService function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscManagerServerTest, DiscIpcUnPublishServiceTest, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscIpcUnPublishServiceTest start");
    DiscMock discMock;
    EXPECT_CALL(discMock, DiscUnPublishService).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_EQ(DiscIpcUnPublishService(nullptr, 0), SOFTBUS_INVALID_PARAM);
    EXPECT_CALL(discMock, DiscUnPublishService).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_EQ(DiscIpcUnPublishService(nullptr, 0), SOFTBUS_OK);
    DISC_LOGI(DISC_TEST, "DiscIpcUnPublishServiceTest end");
}

/*
 * @tc.name: DiscIpcStartDiscoveryTest
 * @tc.desc: Test the invalid parameter input and normal flow of the DiscIpcStartDiscovery function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscManagerServerTest, DiscIpcStartDiscoveryTest, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscIpcStartDiscoveryTest start");
    SubscribeInfo subscribeInfo;
    (void)memset_s(&subscribeInfo, sizeof(subscribeInfo), 0, sizeof(subscribeInfo));
    const char *packageName = "packageName";
    DiscMock discMock;
    EXPECT_EQ(DiscIpcStartDiscovery(nullptr, &subscribeInfo), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(DiscIpcStartDiscovery(packageName, nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_CALL(discMock, ClientIpcOnDiscoverFailed).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(discMock, ClientIpcDiscoverySuccess).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(discMock, SoftbusReportDiscFault).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(discMock, ClientIpcOnDeviceFound).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(discMock, DiscStartDiscovery).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_EQ(DiscIpcStartDiscovery(packageName, &subscribeInfo), SOFTBUS_OK);
    EXPECT_CALL(discMock, DiscStartDiscovery).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_EQ(DiscIpcStartDiscovery(packageName, &subscribeInfo), SOFTBUS_OK);
    DISC_LOGI(DISC_TEST, "DiscIpcStartDiscoveryTest end");
}

/*
 * @tc.name: DiscIpcStopDiscoveryTest
 * @tc.desc: Test the invalid parameter input and normal flow of the DiscIpcStopDiscovery function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscManagerServerTest, DiscIpcStopDiscoveryTest, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscIpcStopDiscoveryTest start");
    DiscMock discMock;
    EXPECT_CALL(discMock, DiscStopDiscovery).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_EQ(DiscIpcStopDiscovery(nullptr, 0), SOFTBUS_INVALID_PARAM);
    EXPECT_CALL(discMock, DiscStopDiscovery).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_EQ(DiscIpcStopDiscovery(nullptr, 0), SOFTBUS_OK);
    DISC_LOGI(DISC_TEST, "DiscIpcStopDiscoveryTest end");
}

/*
 * @tc.name: PublishErroCodeProcessTest
 * @tc.desc: Test the PublishErroCodeProcess function by run DiscIpcPublishService function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscManagerServerTest, PublishErroCodeProcessTest, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "PublishErroCodeProcessTest start");
    PublishInfo publishInfo;
    (void)memset_s(&publishInfo, sizeof(PublishInfo), 0, sizeof(PublishInfo));
    const char *packageName = "packageName";
    DiscMock discMock;
    EXPECT_CALL(discMock, ClientIpcOnPublishFail).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(discMock, ClientIpcOnPublishSuccess).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(discMock, SoftbusReportDiscFault).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(discMock, DiscPublishService).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_EQ(DiscIpcPublishService(packageName, &publishInfo), SOFTBUS_INVALID_PARAM);
    EXPECT_CALL(discMock,
                DiscPublishService).WillRepeatedly(Return(SOFTBUS_DISCOVER_MANAGER_INVALID_MEDIUM));
    EXPECT_EQ(DiscIpcPublishService(packageName, &publishInfo), SOFTBUS_DISCOVER_MANAGER_INVALID_MEDIUM);
    DISC_LOGI(DISC_TEST, "PublishErroCodeProcessTest end");
}

/*
 * @tc.name: DiscoveryErroCodeProcessTest
 * @tc.desc: Test the DiscoveryErroCodeProcess function by run DiscIpcStartDiscovery function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscManagerServerTest, DiscoveryErroCodeProcessTest, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscoveryErroCodeProcessTest start");
    SubscribeInfo subscribeInfo;
    (void)memset_s(&subscribeInfo, sizeof(subscribeInfo), 0, sizeof(subscribeInfo));
    const char *packageName = "packageName";
    DiscMock discMock;
    EXPECT_CALL(discMock, ClientIpcOnDiscoverFailed).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(discMock, ClientIpcDiscoverySuccess).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(discMock, SoftbusReportDiscFault).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(discMock, ClientIpcOnDeviceFound).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(discMock, DiscStartDiscovery).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_EQ(DiscIpcStartDiscovery(packageName, &subscribeInfo), SOFTBUS_INVALID_PARAM);
    EXPECT_CALL(discMock,
                DiscStartDiscovery).WillRepeatedly(Return(SOFTBUS_DISCOVER_MANAGER_INVALID_MEDIUM));
    EXPECT_EQ(DiscIpcStartDiscovery(packageName, &subscribeInfo), DISCOVERY_FAIL_REASON_NOT_SUPPORT_MEDIUM);
    DISC_LOGI(DISC_TEST, "DiscoveryErroCodeProcessTest end");
}

/*
 * @tc.name: ConvertDiscTypeTest
 * @tc.desc: Test the ConvertDiscTypeTest function by run DiscIpcPublishService function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscManagerServerTest, ConvertDiscTypeTest, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "ConvertDiscTypeTest start");
    PublishInfo deviceinfo1 {
        .medium = COAP,
        .publishId = 0,
    };
    PublishInfo deviceinfo2 {
        .medium = BLE,
        .publishId = 0,
    };
    PublishInfo deviceinfo3 {
        .medium = USB,
        .publishId = 0,
    };
    const char *packageName = "packageName";
    DiscMock discMock;
    EXPECT_CALL(discMock, ClientIpcOnPublishFail).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(discMock, ClientIpcOnPublishSuccess).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(discMock, SoftbusReportDiscFault).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(discMock, DiscPublishService).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_EQ(DiscIpcPublishService(packageName, &deviceinfo1), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(DiscIpcPublishService(packageName, &deviceinfo2), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(DiscIpcPublishService(packageName, &deviceinfo3), SOFTBUS_INVALID_PARAM);
    DISC_LOGI(DISC_TEST, "ConvertDiscTypeTest end");
}
} // namespace OHOS