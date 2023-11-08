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
#include <gmock/gmock.h>

#include "discovery_service.h"
#include "disc_client_proxy.h"
#include "disc_log.h"
#include "softbus_error_code.h"
#include "softbus_server_ipc_interface_code.h"
#include "remote_object_mock.h"
#include "client_info_manager_mock.h"
#include "exception_branch_checker.h"

using namespace testing::ext;
using testing::Return;

namespace OHOS {
class DiscClientProxyTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() override {}
    void TearDown() override {}

    static inline std::string pkgName = "TestPackage";
    static constexpr int SUBSCRIBE_ID = 8;
    static constexpr int PUBLISH_ID = 16;
};

/*
* @tc.name: OnDeviceFound001
* @tc.desc: both fail and success case
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscClientProxyTest, OnDeviceFound001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "OnDeviceFound001 begin ----");
    const DeviceInfo device {};
    const InnerDeviceInfoAddtions addition{};

    {
        sptr<RemoteObjectMock> objectMock = new (std::nothrow) RemoteObjectMock();
        RemoteObjectMock::SetupStub(objectMock);
        EXPECT_CALL(*objectMock, SendRequest).WillRepeatedly(Return(SOFTBUS_ERR));
        ClientInfoManagerMock managerMock;
        managerMock.SetupStub();
        ExceptionBranchChecker checker("send request failed");

        EXPECT_EQ(ClientIpcOnDeviceFound(pkgName.c_str(), &device, &addition), SOFTBUS_OK);
        EXPECT_EQ(checker.GetResult(), true);
    }
    {
        sptr<RemoteObjectMock> objectMock = new (std::nothrow) RemoteObjectMock();
        RemoteObjectMock::SetupStub(objectMock);
        ClientInfoManagerMock managerMock;
        managerMock.SetupStub();

        EXPECT_EQ(ClientIpcOnDeviceFound(pkgName.c_str(), &device, &addition), SOFTBUS_OK);
        EXPECT_EQ(objectMock->GetResult(CLIENT_DISCOVERY_DEVICE_FOUND, &device), true);
    }

    RemoteObjectMock::Destroy();
    DISC_LOGI(DISC_TEST, "OnDeviceFound001 end ----");
}

/*
* @tc.name: OnDiscoverFailed001
* @tc.desc: both fail and success case
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscClientProxyTest, OnDiscoverFailed001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "OnDiscoverFailed001 begin ----");
    {
        sptr<RemoteObjectMock> objectMock = new (std::nothrow) RemoteObjectMock();
        RemoteObjectMock::SetupStub(objectMock);
        EXPECT_CALL(*objectMock, SendRequest).WillRepeatedly(Return(SOFTBUS_ERR));
        ClientInfoManagerMock managerMock;
        managerMock.SetupStub();
        ExceptionBranchChecker checker("send request failed");

        EXPECT_EQ(ClientIpcOnDiscoverFailed(pkgName.c_str(), SUBSCRIBE_ID, DISCOVERY_FAIL_REASON_NOT_SUPPORT_MEDIUM),
                  SOFTBUS_OK);
        EXPECT_EQ(checker.GetResult(), true);
    }
    {
        sptr<RemoteObjectMock> objectMock = new (std::nothrow) RemoteObjectMock();
        RemoteObjectMock::SetupStub(objectMock);
        ClientInfoManagerMock managerMock;
        managerMock.SetupStub();

        EXPECT_EQ(ClientIpcOnDiscoverFailed(pkgName.c_str(), SUBSCRIBE_ID, DISCOVERY_FAIL_REASON_NOT_SUPPORT_MEDIUM),
                  SOFTBUS_OK);
        EXPECT_EQ(objectMock->GetResult(CLIENT_DISCOVERY_FAIL, nullptr, 0, SUBSCRIBE_ID,
                                        DISCOVERY_FAIL_REASON_NOT_SUPPORT_MEDIUM), true);
    }

    RemoteObjectMock::Destroy();
    DISC_LOGI(DISC_TEST, "OnDiscoverFailed001 end ----");
}

/*
* @tc.name: DiscoverySuccess001
* @tc.desc: both fail and success case
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscClientProxyTest, DiscoverySuccess001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscoverySuccess001 begin ----");
    {
        sptr<RemoteObjectMock> objectMock = new (std::nothrow) RemoteObjectMock();
        RemoteObjectMock::SetupStub(objectMock);
        EXPECT_CALL(*objectMock, SendRequest).WillRepeatedly(Return(SOFTBUS_ERR));
        ClientInfoManagerMock managerMock;
        managerMock.SetupStub();
        ExceptionBranchChecker checker("send request failed");

        EXPECT_EQ(ClientIpcDiscoverySuccess(pkgName.c_str(), SUBSCRIBE_ID), SOFTBUS_OK);
        EXPECT_EQ(checker.GetResult(), true);
    }
    {
        sptr<RemoteObjectMock> objectMock = new (std::nothrow) RemoteObjectMock();
        RemoteObjectMock::SetupStub(objectMock);
        ClientInfoManagerMock managerMock;
        managerMock.SetupStub();

        EXPECT_EQ(ClientIpcDiscoverySuccess(pkgName.c_str(), SUBSCRIBE_ID), SOFTBUS_OK);
        EXPECT_EQ(objectMock->GetResult(CLIENT_DISCOVERY_SUCC, nullptr, 0, SUBSCRIBE_ID), true);
    }

    RemoteObjectMock::Destroy();
    DISC_LOGI(DISC_TEST, "DiscoverySuccess001 end ----");
}

/*
* @tc.name: OnPublishSuccess001
* @tc.desc: both fail and success case
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscClientProxyTest, OnPublishSuccess001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscoverySuccess001 begin ----");
    {
        sptr<RemoteObjectMock> objectMock = new (std::nothrow) RemoteObjectMock();
        RemoteObjectMock::SetupStub(objectMock);
        EXPECT_CALL(*objectMock, SendRequest).WillRepeatedly(Return(SOFTBUS_ERR));
        ClientInfoManagerMock managerMock;
        managerMock.SetupStub();
        ExceptionBranchChecker checker("send request failed");

        EXPECT_EQ(ClientIpcOnPublishSuccess(pkgName.c_str(), PUBLISH_ID), SOFTBUS_OK);
        EXPECT_EQ(checker.GetResult(), true);
    }
    {
        sptr<RemoteObjectMock> objectMock = new (std::nothrow) RemoteObjectMock();
        RemoteObjectMock::SetupStub(objectMock);
        ClientInfoManagerMock managerMock;
        managerMock.SetupStub();

        EXPECT_EQ(ClientIpcOnPublishSuccess(pkgName.c_str(), PUBLISH_ID), SOFTBUS_OK);
        EXPECT_EQ(objectMock->GetResult(CLIENT_PUBLISH_SUCC, nullptr, PUBLISH_ID), true);
    }

    RemoteObjectMock::Destroy();
    DISC_LOGI(DISC_TEST, "OnPublishSuccess001 end ----");
}

/*
* @tc.name: OnPublishFail001
* @tc.desc: both fail and success case
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscClientProxyTest, OnPublishFail001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "OnPublishFail001 begin ----");
    {
        sptr<RemoteObjectMock> objectMock = new (std::nothrow) RemoteObjectMock();
        RemoteObjectMock::SetupStub(objectMock);
        EXPECT_CALL(*objectMock, SendRequest).WillRepeatedly(Return(SOFTBUS_ERR));
        ClientInfoManagerMock managerMock;
        managerMock.SetupStub();
        ExceptionBranchChecker checker("send request failed");

        EXPECT_EQ(ClientIpcOnPublishFail(pkgName.c_str(), PUBLISH_ID, PUBLISH_FAIL_REASON_NOT_SUPPORT_MEDIUM),
                  SOFTBUS_OK);
        EXPECT_EQ(checker.GetResult(), true);
    }
    {
        sptr<RemoteObjectMock> objectMock = new (std::nothrow) RemoteObjectMock();
        RemoteObjectMock::SetupStub(objectMock);
        ClientInfoManagerMock managerMock;
        managerMock.SetupStub();

        EXPECT_EQ(ClientIpcOnPublishFail(pkgName.c_str(), PUBLISH_ID, PUBLISH_FAIL_REASON_NOT_SUPPORT_MEDIUM),
                  SOFTBUS_OK);
        EXPECT_EQ(objectMock->GetResult(CLIENT_PUBLISH_FAIL, nullptr, PUBLISH_ID, 0,
                                        PUBLISH_FAIL_REASON_NOT_SUPPORT_MEDIUM), true);
    }

    RemoteObjectMock::Destroy();
    DISC_LOGI(DISC_TEST, "OnPublishFail001 end ----");
}
}