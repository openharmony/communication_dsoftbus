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

#include "gtest/gtest.h"
#include <securec.h>

#include "softbus_app_info.h"
#include "trans_bus_center_manager_mock.h"
#include "trans_udp_negotiation_exchange.c"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
#define INVALID_META_TYPE 999

class TransUdpNegotiationExchangeMockTest : public testing::Test {
public:
    TransUdpNegotiationExchangeMockTest() { }
    ~TransUdpNegotiationExchangeMockTest() { }
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override { }
    void TearDown() override { }
};

void TransUdpNegotiationExchangeMockTest::SetUpTestCase(void) { }

void TransUdpNegotiationExchangeMockTest::TearDownTestCase(void) { }

/**
 * @tc.name: TransUnpackMetaTypeSpecificData001
 * @tc.desc: Test the normal process of obtaining the META_SDK type.
 * @tc.type: FUNC
 * @tc.require: Simulate LnnGetRemoteNumInfo to set metaType to META_SDK and return success.
 */
HWTEST_F(TransUdpNegotiationExchangeMockTest, TransUnpackMetaTypeSpecificData001, TestSize.Level1)
{
    cJSON *msg = cJSON_CreateObject();
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));

    NiceMock<TransBusCenterManagerInterfaceMock> TransBusCenterManagerMock;
    EXPECT_CALL(TransBusCenterManagerMock, LnnGetRemoteNumInfo)
        .WillOnce(DoAll(SetArgPointee<2>(META_SDK), Return(SOFTBUS_OK)));
    int32_t ret = TransUnpackMetaTypeSpecificData(msg, &appInfo);
    EXPECT_EQ(META_SDK, appInfo.metaType);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    cJSON_Delete(msg);
}

/**
 * @tc.name: TransUnpackMetaTypeSpecificData002
 * @tc.desc: Test the normal process of obtaining the META_HA type.
 * @tc.type: FUNC
 * @tc.require: Simulate LnnGetRemoteNumInfo to set metaType to META_HA and return success.
 */
HWTEST_F(TransUdpNegotiationExchangeMockTest, TransUnpackMetaTypeSpecificData002, TestSize.Level1)
{
    cJSON *msg = cJSON_CreateObject();
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));

    NiceMock<TransBusCenterManagerInterfaceMock> TransBusCenterManagerMock;
    EXPECT_CALL(TransBusCenterManagerMock, LnnGetRemoteNumInfo)
        .WillOnce(DoAll(SetArgPointee<2>(META_HA), Return(SOFTBUS_OK)));
    int32_t ret = TransUnpackMetaTypeSpecificData(msg, &appInfo);
    EXPECT_EQ(META_HA, appInfo.metaType);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    cJSON_Delete(msg);
}

/**
 * @tc.name: TransUnpackMetaTypeSpecificData003
 * @tc.desc: Test the default process after obtaining the META_HA type.
 * @tc.type: FUNC
 * @tc.require: Simulate LnnGetRemoteNumInfo to setting unknown metaType and returning failure.
 */
HWTEST_F(TransUdpNegotiationExchangeMockTest, TransUnpackMetaTypeSpecificData003, TestSize.Level1)
{
    cJSON *msg = cJSON_CreateObject();
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));

    NiceMock<TransBusCenterManagerInterfaceMock> TransBusCenterManagerMock;
    EXPECT_CALL(TransBusCenterManagerMock, LnnGetRemoteNumInfo)
        .WillOnce(DoAll(SetArgPointee<2>(INVALID_META_TYPE), Return(SOFTBUS_INVALID_PARAM)));
    int32_t ret = TransUnpackMetaTypeSpecificData(msg, &appInfo);
    EXPECT_EQ(META_HA, appInfo.metaType);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    cJSON_Delete(msg);
}
} /* namespace OHOS */
