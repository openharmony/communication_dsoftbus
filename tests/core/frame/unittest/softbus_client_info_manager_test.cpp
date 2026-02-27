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

#include <gtest/gtest.h>

#include "softbus_client_info_manager.h"
#include "softbus_error_code.h"

#define TEST_PID 100

using namespace testing::ext;

namespace OHOS {
class SoftbusClientInfoManagerTest : public testing::Test {
public:
    SoftbusClientInfoManagerTest()
    {}
    ~SoftbusClientInfoManagerTest()
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

/*
 * @tc.name: SoftbusClientInfoManagerTest001
 * @tc.desc: SoftbusAddService function test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(SoftbusClientInfoManagerTest, SoftbusClientInfoManagerTest001, TestSize.Level1)
{
    int32_t pidTest = TEST_PID;
    std::string pkgName = "testPkgName";
    const sptr<IRemoteObject> object = nullptr;
    const sptr<IRemoteObject::DeathRecipient> abilityDeath = nullptr;
    int32_t ret = SoftbusClientInfoManager::GetInstance().SoftbusAddService(pkgName,
        object, abilityDeath, pidTest);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = SoftbusClientInfoManager::GetInstance().SoftbusAddServiceInner(pkgName,
        nullptr, pidTest);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: SoftbusClientInfoManagerTest002
 * @tc.desc: SoftbusRemoveServiceInner function test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(SoftbusClientInfoManagerTest, SoftbusClientInfoManagerTest002, TestSize.Level1)
{
    std::string pkgName;
    int32_t ret = SoftbusClientInfoManager::GetInstance().SoftbusRemoveServiceInner(pkgName);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    const char *sessionName = "ohos.distributedschedule.dms.test";
    ret = SoftbusClientInfoManager::GetInstance().SoftbusRemoveServiceInner(sessionName);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: SoftbusClientInfoManagerTest003
 * @tc.desc: SoftbusRemoveService function test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(SoftbusClientInfoManagerTest, SoftbusClientInfoManagerTest003, TestSize.Level1)
{
    std::string pkgName;
    int32_t ret = SoftbusClientInfoManager::GetInstance().SoftbusRemoveService(
        nullptr, pkgName, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: SoftbusClientInfoManagerTest004
 * @tc.desc: GetSoftbusInnerObject function test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(SoftbusClientInfoManagerTest, SoftbusClientInfoManagerTest004, TestSize.Level1)
{
    std::string pkgName;
    int32_t ret = SoftbusClientInfoManager::GetInstance().GetSoftbusInnerObject(
        pkgName, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ISessionListenerInner object;
    const char *sessionName = "ohos.distributedschedule.dms.test";
    ret = SoftbusClientInfoManager::GetInstance().GetSoftbusInnerObject(
        sessionName, &object);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
}

/*
 * @tc.name: SoftbusClientInfoManagerTest005
 * @tc.desc: GetSoftbusClientProxy function test
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(SoftbusClientInfoManagerTest, SoftbusClientInfoManagerTest005, TestSize.Level1)
{
    const char *sessionName = "ohos.distributedschedule.dms.test";
    sptr<IRemoteObject> clientObject =
        SoftbusClientInfoManager::GetInstance().GetSoftbusClientProxy(sessionName);
    EXPECT_EQ(clientObject, nullptr);
}
}
