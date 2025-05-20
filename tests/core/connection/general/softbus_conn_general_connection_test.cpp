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

#include "general_connection_mock.h"
#include "softbus_conn_general_connection.h"
#include "softbus_conn_ipc.h"
#include "softbus_feature_config.h"

using namespace testing::ext;
using namespace testing;
using namespace std;

#define GENERAL_PKGNAME_MAX_COUNT          (10)

namespace OHOS {
class GeneralConnectionTest : public testing::Test {
public:
    GeneralConnectionTest() { }
    ~GeneralConnectionTest() { }
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void GeneralConnectionTest::SetUpTestCase(void) { }

void GeneralConnectionTest::TearDownTestCase(void) { }

void GeneralConnectionTest::SetUp(void) { }

void GeneralConnectionTest::TearDown(void) { }

/*
* @tc.name: TestInit
* @tc.desc: test init general connection
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(GeneralConnectionTest, TestInit, TestSize.Level1)
{
    CONN_LOGI(CONN_BLE, "test init start");
    const char *pkgName = "testName";
    ClearGeneralConnection(pkgName, 0);
    int32_t ret = InitGeneralConnection();
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);

    ret = InitGeneralConnection();
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);
    ConnUnSetConnectCallback(MODULE_BLE_GENERAL);

    LooperInit();
    SoftbusConfigInit();
    ret = ConnServerInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ClearGeneralConnection(pkgName, 0);
    GeneralConnectionManager *manager = GetGeneralConnectionManager();
    EXPECT_NE(manager, nullptr);
    GeneralConnectionParam param = {0};
    manager->closeServer(&param);
    CONN_LOGI(CONN_BLE, "test init end");
}

/*
* @tc.name: TestCreateServerMax
* @tc.desc: test create server include max count(10) and normal case
* @tc.type: FUNC
* @tc.require:AR000GIRGE
*/
HWTEST_F(GeneralConnectionTest, TestCreateServer, TestSize.Level1)
{
    CONN_LOGI(CONN_BLE, "test createServer start");
    GeneralConnectionManager *manager = GetGeneralConnectionManager();
    EXPECT_NE(manager, nullptr);
    GeneralConnectionParam param = {0};

    const char *name = "test";
    int32_t ret = strcpy_s(param.name, GENERAL_NAME_LEN, "test");
    EXPECT_EQ(ret, EOK);
    const char *pkgName = "testPkgName";
    ret = strcpy_s(param.pkgName, PKG_NAME_SIZE_MAX, pkgName);
    EXPECT_EQ(ret, EOK);
    
    ret = strcpy_s(param.bundleName, BUNDLE_NAME_MAX, "testBundleName");
    EXPECT_EQ(ret, EOK);

    ret = manager->createServer(&param);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = manager->createServer(&param);
    EXPECT_EQ(ret, SOFTBUS_CONN_GENERAL_DUPLICATE_SERVER);
    for (uint32_t i = 0; i < GENERAL_PKGNAME_MAX_COUNT; ++i) { 
        string nameTemp = name + to_string(i);
        ret = strcpy_s(param.name, GENERAL_NAME_LEN, nameTemp.c_str());
        EXPECT_EQ(ret, EOK);
        manager->createServer(&param);
        EXPECT_EQ(ret, SOFTBUS_OK);
    }
    
    ret = strcpy_s(param.name, GENERAL_NAME_LEN, "test10");
    EXPECT_EQ(ret, EOK);
    ret = manager->createServer(&param);
    EXPECT_EQ(ret, SOFTBUS_CONN_GENERAL_CREATE_SERVER_MAX);
    manager->closeServer(&param);
    ret = strcpy_s(param.name, GENERAL_NAME_LEN, "test9");
    EXPECT_EQ(ret, EOK);
    manager->closeServer(&param);

    ret = strcpy_s(param.name, GENERAL_NAME_LEN, "test8");
    EXPECT_EQ(ret, EOK);
    ret = strcpy_s(param.bundleName, GENERAL_NAME_LEN, "testBundleName0");
    EXPECT_EQ(ret, EOK);
    manager->closeServer(&param);
    CONN_LOGI(CONN_BLE, "test createServer end");
}

/*
* @tc.name: TestConnect
* @tc.desc: test connect include to max count(10) and normal case
* @tc.type: FUNC
* @tc.require:AR000GIRGE
*/
HWTEST_F(GeneralConnectionTest, TestConnect, TestSize.Level1)
{
    CONN_LOGI(CONN_BLE, "test connect start");
    GeneralConnectionManager *manager = GetGeneralConnectionManager();
    EXPECT_NE(manager, nullptr);
    GeneralConnectionParam param = {0};

    const char *pkgName = "testPkgName";
    int32_t ret = strcpy_s(param.pkgName, PKG_NAME_SIZE_MAX, pkgName);
    EXPECT_EQ(ret, EOK);
    
    ret = strcpy_s(param.bundleName, BUNDLE_NAME_MAX, "testBundleName");
    EXPECT_EQ(ret, EOK);
    const char *name = "test";
    const char *addr = "11:22:33:44:55:66";
    param.pid = 0;
    GeneralConnectionInterfaceMock mock;
    EXPECT_CALL(mock, BleConnectDeviceMock).WillRepeatedly(Return(SOFTBUS_OK));
    for (uint32_t i = 0; i < GENERAL_PKGNAME_MAX_COUNT; ++i) { 
        string nameTemp = name + to_string(i);
        ret = strcpy_s(param.name, GENERAL_NAME_LEN, nameTemp.c_str());
        EXPECT_EQ(ret, EOK);
        ret = manager->connect(&param, addr);
        EXPECT_EQ(ret > 0, true);
    }
    ret = strcpy_s(param.name, GENERAL_NAME_LEN, "test10");
    EXPECT_EQ(ret, EOK);
    ret = manager->connect(&param, addr);
    EXPECT_EQ(ret, SOFTBUS_CONN_GENERAL_CREATE_CLIENT_MAX);
    manager->cleanupGeneralConnection(param.pkgName, param.pid);

    ret = strcpy_s(param.name, GENERAL_NAME_LEN, "test9");
    EXPECT_EQ(ret, EOK);
    EXPECT_CALL(mock, BleConnectDeviceMock).WillRepeatedly(Return(SOFTBUS_STRCPY_ERR));
    ret = manager->connect(&param, addr);
    EXPECT_EQ(ret, SOFTBUS_CONN_GENERAL_CONNECT_FAILED);
    CONN_LOGI(CONN_BLE, "test connect end");
}
}