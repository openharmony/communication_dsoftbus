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

#include "iservice_registry.h"
#include "softbus_common.h"
#include "softbus_error_code.h"
#include "softbus_server.h"
#include "softbus_server_test_mock.h"
#include "system_ability_definition.h"
#include <gtest/gtest.h>

using namespace testing;
using namespace testing::ext;

namespace OHOS {

#define TEST_SESSION_NAME_SIZE_MAX 256

class SoftbusServerTest : public testing::Test {
public:
    SoftbusServerTest()
    {}
    ~SoftbusServerTest()
    {}
    static void SetUpTestCase()
    {}
    static void TearDownTestCase()
    {}
    void SetUp() override
    {}
    void TearDown() override
    {}
};

static sptr<IRemoteObject> GenerateRemoteObject(void)
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr != nullptr) {
        return samgr->GetSystemAbility(SOFTBUS_SERVER_SA_ID);
    }
    return nullptr;
}

/**
 * @tc.name: SoftbusServerTest001
 * @tc.desc: Verify the SoftbusRegisterService function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusServerTest, SoftbusServerTest001, TestSize.Level1)
{
    sptr<OHOS::SoftBusServer> softBusServer = new OHOS::SoftBusServer(SOFTBUS_SERVER_SA_ID, true);
    ASSERT_NE(nullptr, softBusServer);
    
    int32_t ret = softBusServer->SoftbusRegisterService("test", nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    sptr<IRemoteObject> obj = GenerateRemoteObject();
    ret = softBusServer->SoftbusRegisterService("test", obj);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: SoftbusServerTest002
 * @tc.desc: Verify the OpenAuthSession function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusServerTest, SoftbusServerTest002, TestSize.Level1)
{
    sptr<OHOS::SoftBusServer> softBusServer = new OHOS::SoftBusServer(SOFTBUS_SERVER_SA_ID, true);
    ASSERT_NE(nullptr, softBusServer);
    ConnectionAddr addr;
    addr.type = CONNECTION_ADDR_MAX;
    
    int32_t ret = softBusServer->OpenAuthSession("test", nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = softBusServer->OpenAuthSession("test", &addr);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_CONNECT_TYPE, ret);
}

/**
 * @tc.name: SoftbusServerTest003
 * @tc.desc: Verify the Dump function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusServerTest, SoftbusServerTest003, TestSize.Level1)
{
    sptr<OHOS::SoftBusServer> softBusServer = new OHOS::SoftBusServer(SOFTBUS_SERVER_SA_ID, true);
    ASSERT_NE(nullptr, softBusServer);
    int32_t fd = -1;
    std::vector<std::u16string> args;

    int32_t ret = softBusServer->Dump(fd, args);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    fd = 0;
    ret = softBusServer->Dump(fd, args);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: SoftbusServerTest004
 * @tc.desc: Verify the GetSoftbusSpecObject function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusServerTest, SoftbusServerTest004, TestSize.Level1)
{
    sptr<OHOS::SoftBusServer> softBusServer = new OHOS::SoftBusServer(SOFTBUS_SERVER_SA_ID, true);
    ASSERT_NE(nullptr, softBusServer);
    sptr<IRemoteObject> object = nullptr;
    int32_t ret = softBusServer->GetSoftbusSpecObject(object);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: SoftbusServerTest005
 * @tc.desc: Verify the GetBusCenterExObj function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusServerTest, SoftbusServerTest005, TestSize.Level1)
{
    sptr<OHOS::SoftBusServer> softBusServer = new OHOS::SoftBusServer(SOFTBUS_SERVER_SA_ID, true);
    ASSERT_NE(nullptr, softBusServer);
    sptr<IRemoteObject> object = nullptr;
    int32_t ret = softBusServer->GetBusCenterExObj(object);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: SoftbusServerTest006
 * @tc.desc: Verify the EvaluateQos function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusServerTest, SoftbusServerTest006, TestSize.Level1)
{
    sptr<OHOS::SoftBusServer> softBusServer = new OHOS::SoftBusServer(SOFTBUS_SERVER_SA_ID, true);
    ASSERT_NE(nullptr, softBusServer);
    NiceMock<SoftbusServerTestInterfaceMock> softbusServerMock;
    char networkId[NETWORK_ID_BUF_LEN] = "test";
    TransDataType dataType = DATA_TYPE_BYTES;

    EXPECT_CALL(softbusServerMock, IsValidString(_, _))
        .WillRepeatedly(Return(false));
    int32_t ret = softBusServer->EvaluateQos(networkId, dataType, nullptr, 0);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    EXPECT_CALL(softbusServerMock, IsValidString(_, _))
        .WillRepeatedly(Return(true));
    ret = softBusServer->EvaluateQos(networkId, dataType, nullptr, 0);
    EXPECT_EQ(SOFTBUS_NETWORK_NODE_OFFLINE, ret);
}
}