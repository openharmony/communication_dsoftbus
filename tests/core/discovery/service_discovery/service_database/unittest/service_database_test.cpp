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

#include <cstdint>
#include <cstdio>
#include <gtest/gtest.h>
#include <securec.h>
#include <unistd.h>

#include "disc_log.h"
#include "softbus_adapter_mem.h"
#include "service_database.h"
#include "softbus_error_code.h"

using namespace testing::ext;

namespace OHOS {
static int64_t g_serviceId = 1000000;
static const char *g_serviceType = "castplus";

static ServiceInfo g_serviceInfo0 = {
    .serviceId = 1000000,
    .serviceType = "serviceType",
    .serviceName = "serviceName",
    .serviceDisplayName = "serviceDisplayName",
    .customData = "customData",
    .dataLen = strlen("customData")
};

static ServiceInfo g_serviceInfo1 = {
    .serviceId = 1111111111111111111,
    .serviceType = "serviceType1",
    .serviceName = "serviceName1",
    .serviceDisplayName = "serviceDisplayName1",
    .customData = "customData1",
    .dataLen = strlen("customData1")
};

const int32_t MAX_SERVICE_INFO_CNT = 10;

class ServiceDatabaseTest : public testing::Test {
public:
    ServiceDatabaseTest() { }
    ~ServiceDatabaseTest() { }
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override { }
    void TearDown() override { }
};

void ServiceDatabaseTest::SetUpTestCase(void) { }

void ServiceDatabaseTest::TearDownTestCase(void) { }

/*
 * @tc.name: ServiceDatabaseInitTest001
 * @tc.desc: Test ServiceDatabaseInit
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServiceDatabaseTest, ServiceDatabaseInitTest001, TestSize.Level1)
{
    DISC_LOGI(DISC_INIT, "ServiceDatabaseInitTest001 begin");

    EXPECT_EQ(ServiceDatabaseInit(), SOFTBUS_OK);

    // Return SOFTBUS_OK when ServiceDatabaseInit is called multiple times
    EXPECT_EQ(ServiceDatabaseInit(), SOFTBUS_OK);

    ServiceDatabaseDeinit();
    // Return SOFTBUS_OK when ServiceDatabaseDeinit is called multiple times
    ServiceDatabaseDeinit();

    DISC_LOGI(DISC_INIT, "ServiceDatabaseInitTest001 end");
}

/*
 * @tc.name: ServiceDatabaseDeinitTest001
 * @tc.desc: Test ServiceDatabaseDeinit when softbus_server is dead
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServiceDatabaseTest, ServiceDatabaseDeinitTest001, TestSize.Level1)
{
    DISC_LOGI(DISC_INIT, "ServiceDatabaseDeinitTest001 begin");

    EXPECT_EQ(ServiceDatabaseInit(), SOFTBUS_OK);

    ServiceInfo info = {};
    info.serviceId = g_serviceId;
    (void)strcpy_s((char *)info.serviceType, DISC_SERVICE_TYPE_MAX_LEN - 1, g_serviceType);
    EXPECT_EQ(AddServiceInfo(&info), SOFTBUS_OK);

    // serviceInfo is released in ServiceDatabaseDeinit
    ServiceDatabaseDeinit();

    DISC_LOGI(DISC_INIT, "ServiceDatabaseDeinitTest001 end");
}

/*
 * @tc.name: AddServiceInfoTest001
 * @tc.desc: Test AddServiceInfo when ServiceInfo is invalid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServiceDatabaseTest, AddServiceInfoTest001, TestSize.Level1)
{
    DISC_LOGI(DISC_INIT, "AddServiceInfoTest001 begin");

    EXPECT_EQ(AddServiceInfo(nullptr), SOFTBUS_INVALID_PARAM);

    ServiceInfo info = {};
    EXPECT_EQ(AddServiceInfo(&info), SOFTBUS_INVALID_PARAM);

    DISC_LOGI(DISC_INIT, "AddServiceInfoTest001 end");
}

/*
 * @tc.name: AddServiceInfoTest002
 * @tc.desc: Test AddServiceInfo when ServiceInfo is valid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServiceDatabaseTest, AddServiceInfoTest002, TestSize.Level1)
{
    DISC_LOGI(DISC_INIT, "AddServiceInfoTest002 begin");

    EXPECT_EQ(ServiceDatabaseInit(), SOFTBUS_OK);

    ServiceInfo info = {};
    info.serviceId = g_serviceId;
    (void)strcpy_s((char *)info.serviceType, DISC_SERVICE_TYPE_MAX_LEN - 1, g_serviceType);
    EXPECT_EQ(AddServiceInfo(&info), SOFTBUS_OK);
    EXPECT_EQ(RemoveServiceInfo(g_serviceId), SOFTBUS_OK);

    ServiceDatabaseDeinit();

    DISC_LOGI(DISC_INIT, "AddServiceInfoTest002 end");
}

/*
 * @tc.name: AddServiceInfoTest003
 * @tc.desc: Test AddServiceInfo when customData is invalid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServiceDatabaseTest, AddServiceInfoTest003, TestSize.Level1)
{
    DISC_LOGI(DISC_INIT, "AddServiceInfoTest003 begin");

    ServiceInfo info = {};
    info.serviceId = g_serviceId;
    (void)strcpy_s((char *)info.serviceType, DISC_SERVICE_TYPE_MAX_LEN - 1, g_serviceType);
    info.dataLen = 1;
    EXPECT_EQ(AddServiceInfo(&info), SOFTBUS_INVALID_PARAM);

    (void)memcpy_s(info.customData, DISC_SERVICE_CUSTOMDATA_MAX_LEN - 1, "customData", strlen("customData"));
    info.dataLen = 0;
    EXPECT_EQ(AddServiceInfo(&info), SOFTBUS_INVALID_PARAM);

    info.dataLen = DISC_SERVICE_CUSTOMDATA_MAX_LEN;
    EXPECT_EQ(AddServiceInfo(&info), SOFTBUS_INVALID_PARAM);

    info.dataLen = 1;
    EXPECT_EQ(AddServiceInfo(&info), SOFTBUS_INVALID_PARAM);

    DISC_LOGI(DISC_INIT, "AddServiceInfoTest003 end");
}

/*
 * @tc.name: GetServiceInfoTest001
 * @tc.desc: Test GetServiceInfo when input param is invalid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServiceDatabaseTest, GetServiceInfoTest001, TestSize.Level1)
{
    DISC_LOGI(DISC_INIT, "GetServiceInfoTest001 begin");

    EXPECT_EQ(ServiceDatabaseInit(), SOFTBUS_OK);

    ServiceInfo info = {};
    EXPECT_EQ(GetServiceInfo(0, nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(GetServiceInfo(g_serviceId, nullptr), SOFTBUS_INVALID_PARAM);

    // Return SOFTBUS_DISCOVER_SD_SERVICE_ID_NOT_EXISTED when serviceId is not existed
    EXPECT_EQ(GetServiceInfo(g_serviceId, &info), SOFTBUS_DISCOVER_SD_SERVICE_ID_NOT_EXISTED);

    ServiceDatabaseDeinit();

    DISC_LOGI(DISC_INIT, "GetServiceInfoTest001 end");
}

/*
 * @tc.name: GetServiceInfoTest002
 * @tc.desc: Test AddServiceInfo and GetServiceInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServiceDatabaseTest, GetServiceInfoTest002, TestSize.Level1)
{
    DISC_LOGI(DISC_INIT, "GetServiceInfoTest002 begin");

    EXPECT_EQ(ServiceDatabaseInit(), SOFTBUS_OK);

    EXPECT_EQ(AddServiceInfo(&g_serviceInfo0), SOFTBUS_OK);

    ServiceInfo srvInfo = {};
    EXPECT_EQ(GetServiceInfo(g_serviceInfo0.serviceId, &srvInfo), SOFTBUS_OK);

    EXPECT_EQ(srvInfo.serviceId, g_serviceInfo0.serviceId);
    EXPECT_EQ(strcmp(srvInfo.serviceType, g_serviceInfo0.serviceType), SOFTBUS_OK);
    EXPECT_EQ(strcmp(srvInfo.serviceName, g_serviceInfo0.serviceName), SOFTBUS_OK);
    EXPECT_EQ(strcmp(srvInfo.serviceDisplayName, g_serviceInfo0.serviceDisplayName), SOFTBUS_OK);
    EXPECT_EQ(strcmp((const char *)srvInfo.customData, (const char *)g_serviceInfo0.customData), SOFTBUS_OK);
    EXPECT_EQ(srvInfo.dataLen, g_serviceInfo0.dataLen);

    EXPECT_EQ(RemoveServiceInfo(g_serviceInfo0.serviceId), SOFTBUS_OK);

    ServiceDatabaseDeinit();

    DISC_LOGI(DISC_INIT, "GetServiceInfoTest002 end");
}

/*
 * @tc.name: GetAllServiceInfosTest001
 * @tc.desc: Test GetAllServiceInfos when input param is invalid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServiceDatabaseTest, GetAllServiceInfosTest001, TestSize.Level1)
{
    DISC_LOGI(DISC_INIT, "GetAllServiceInfosTest001 begin");

    EXPECT_EQ(ServiceDatabaseInit(), SOFTBUS_OK);

    uint32_t infoCnt = 0;
    EXPECT_EQ(GetAllServiceInfos(nullptr, &infoCnt), SOFTBUS_INVALID_PARAM);

    ServiceDatabaseDeinit();

    DISC_LOGI(DISC_INIT, "GetAllServiceInfosTest001 end");
}

/*
 * @tc.name: GetAllServiceInfosTest002
 * @tc.desc: Test AddServiceInfo and GetAllServiceInfos
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServiceDatabaseTest, GetAllServiceInfosTest002, TestSize.Level1)
{
    DISC_LOGI(DISC_INIT, "GetAllServiceInfosTest002 begin");

    EXPECT_EQ(ServiceDatabaseInit(), SOFTBUS_OK);

    uint32_t infoCnt = MAX_SERVICE_INFO_CNT;
    ServiceInfo infos[MAX_SERVICE_INFO_CNT] = {};
    EXPECT_EQ(GetAllServiceInfos(infos, &infoCnt), SOFTBUS_OK);
    EXPECT_TRUE(infoCnt == 0);

    EXPECT_EQ(AddServiceInfo(&g_serviceInfo0), SOFTBUS_OK);
    infoCnt = MAX_SERVICE_INFO_CNT;
    EXPECT_EQ(GetAllServiceInfos(infos, &infoCnt), SOFTBUS_OK);
    EXPECT_TRUE(infoCnt == 1);
    EXPECT_EQ(infos[0].serviceId, g_serviceInfo0.serviceId);
    EXPECT_EQ(strcmp(infos[0].serviceType, g_serviceInfo0.serviceType), SOFTBUS_OK);
    EXPECT_EQ(strcmp(infos[0].serviceName, g_serviceInfo0.serviceName), SOFTBUS_OK);
    EXPECT_EQ(strcmp(infos[0].serviceDisplayName, g_serviceInfo0.serviceDisplayName), SOFTBUS_OK);
    EXPECT_EQ(strcmp((const char *)infos[0].customData, (const char *)g_serviceInfo0.customData), SOFTBUS_OK);
    EXPECT_EQ(infos[0].dataLen, g_serviceInfo0.dataLen);

    EXPECT_EQ(RemoveServiceInfo(g_serviceInfo0.serviceId), SOFTBUS_OK);
    infoCnt = MAX_SERVICE_INFO_CNT;
    ServiceInfo infos1[MAX_SERVICE_INFO_CNT] = {};
    EXPECT_EQ(GetAllServiceInfos(infos1, &infoCnt), SOFTBUS_OK);
    EXPECT_TRUE(infoCnt == 0);

    ServiceDatabaseDeinit();

    DISC_LOGI(DISC_INIT, "GetAllServiceInfosTest002 end");
}

/*
 * @tc.name: GetAllServiceInfosTest003
 * @tc.desc: Test GetAllServiceInfos when input param is invalid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServiceDatabaseTest, GetAllServiceInfosTest003, TestSize.Level1)
{
    DISC_LOGI(DISC_INIT, "GetAllServiceInfosTest003 begin");

    EXPECT_EQ(ServiceDatabaseInit(), SOFTBUS_OK);

    uint32_t infoCnt = MAX_SERVICE_INFO_CNT;
    ServiceInfo infos[MAX_SERVICE_INFO_CNT] = {};
    EXPECT_EQ(GetAllServiceInfos(infos, &infoCnt), SOFTBUS_OK);
    EXPECT_TRUE(infoCnt == 0);
    EXPECT_EQ(strlen(infos[0].serviceType), 0);
    EXPECT_EQ(strlen(infos[0].serviceName), 0);
    EXPECT_EQ(strlen(infos[0].serviceDisplayName), 0);
    EXPECT_EQ(strlen((char *)infos[0].customData), 0);
    EXPECT_EQ(infos[0].dataLen, 0);

    ServiceDatabaseDeinit();

    DISC_LOGI(DISC_INIT, "GetAllServiceInfosTest003 end");
}

/*
 * @tc.name: RemoveServiceInfoTest001
 * @tc.desc: Test RemoveServiceInfo when input param is invalid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServiceDatabaseTest, RemoveServiceInfoTest001, TestSize.Level1)
{
    DISC_LOGI(DISC_INIT, "RemoveServiceInfoTest001 begin");

    EXPECT_EQ(ServiceDatabaseInit(), SOFTBUS_OK);

    EXPECT_EQ(RemoveServiceInfo(g_serviceId), SOFTBUS_OK);

    ServiceDatabaseDeinit();

    DISC_LOGI(DISC_INIT, "RemoveServiceInfoTest001 end");
}

/*
 * @tc.name: RemoveServiceInfoTest002
 * @tc.desc: Test RemoveServiceInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServiceDatabaseTest, RemoveServiceInfoTest002, TestSize.Level1)
{
    DISC_LOGI(DISC_INIT, "RemoveServiceInfoTest002 begin");

    EXPECT_EQ(ServiceDatabaseInit(), SOFTBUS_OK);

    uint32_t infoCnt = MAX_SERVICE_INFO_CNT;
    ServiceInfo infos[MAX_SERVICE_INFO_CNT] = {};

    EXPECT_EQ(AddServiceInfo(&g_serviceInfo0), SOFTBUS_OK);
    EXPECT_EQ(AddServiceInfo(&g_serviceInfo1), SOFTBUS_OK);

    EXPECT_EQ(GetAllServiceInfos(infos, &infoCnt), SOFTBUS_OK);
    EXPECT_TRUE(infoCnt == 2);
    EXPECT_EQ(infos[0].serviceId, g_serviceInfo0.serviceId);
    EXPECT_EQ(strcmp(infos[0].serviceType, g_serviceInfo0.serviceType), SOFTBUS_OK);
    EXPECT_EQ(strcmp(infos[0].serviceName, g_serviceInfo0.serviceName), SOFTBUS_OK);
    EXPECT_EQ(strcmp(infos[0].serviceDisplayName, g_serviceInfo0.serviceDisplayName), SOFTBUS_OK);
    EXPECT_EQ(strcmp((const char *)infos[0].customData, (const char *)g_serviceInfo0.customData), SOFTBUS_OK);
    EXPECT_EQ(infos[0].dataLen, g_serviceInfo0.dataLen);
    EXPECT_EQ(infos[1].serviceId, g_serviceInfo1.serviceId);
    EXPECT_EQ(strcmp(infos[1].serviceType, g_serviceInfo1.serviceType), SOFTBUS_OK);
    EXPECT_EQ(strcmp(infos[1].serviceName, g_serviceInfo1.serviceName), SOFTBUS_OK);
    EXPECT_EQ(strcmp(infos[1].serviceDisplayName, g_serviceInfo1.serviceDisplayName), SOFTBUS_OK);
    EXPECT_EQ(strcmp((const char *)infos[1].customData, (const char *)g_serviceInfo1.customData), SOFTBUS_OK);
    EXPECT_EQ(infos[1].dataLen, g_serviceInfo1.dataLen);

    EXPECT_EQ(RemoveServiceInfo(g_serviceInfo0.serviceId), SOFTBUS_OK);
    ServiceInfo infos1[MAX_SERVICE_INFO_CNT] = {};
    EXPECT_EQ(GetAllServiceInfos(infos1, &infoCnt), SOFTBUS_OK);
    EXPECT_TRUE(infoCnt == 1);
    EXPECT_EQ(infos1[0].serviceId, g_serviceInfo1.serviceId);
    EXPECT_EQ(strcmp(infos1[0].serviceType, g_serviceInfo1.serviceType), SOFTBUS_OK);
    EXPECT_EQ(strcmp(infos1[0].serviceName, g_serviceInfo1.serviceName), SOFTBUS_OK);
    EXPECT_EQ(strcmp(infos1[0].serviceDisplayName, g_serviceInfo1.serviceDisplayName), SOFTBUS_OK);
    EXPECT_EQ(strcmp((const char *)infos1[0].customData, (const char *)g_serviceInfo1.customData), SOFTBUS_OK);
    EXPECT_EQ(infos1[0].dataLen, g_serviceInfo1.dataLen);
    EXPECT_EQ(strlen(infos1[1].serviceType), 0);
    EXPECT_EQ(strlen(infos1[1].serviceName), 0);
    EXPECT_EQ(strlen(infos1[1].serviceDisplayName), 0);
    EXPECT_EQ(strlen((char *)infos1[1].customData), 0);
    EXPECT_EQ(infos1[1].dataLen, 0);
    EXPECT_EQ(RemoveServiceInfo(g_serviceInfo1.serviceId), SOFTBUS_OK);

    ServiceDatabaseDeinit();

    DISC_LOGI(DISC_INIT, "RemoveServiceInfoTest002 end");
}

/*
 * @tc.name: UpdateServiceInfoTest001
 * @tc.desc: Test UpdateServiceInfo when input param is invalid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServiceDatabaseTest, UpdateServiceInfoTest001, TestSize.Level1)
{
    DISC_LOGI(DISC_INIT, "UpdateServiceInfoTest001 begin");

    EXPECT_EQ(ServiceDatabaseInit(), SOFTBUS_OK);

    EXPECT_EQ(UpdateServiceInfo(nullptr), SOFTBUS_INVALID_PARAM);

    ServiceDatabaseDeinit();

    DISC_LOGI(DISC_INIT, "UpdateServiceInfoTest001 end");
}

/*
 * @tc.name: UpdateServiceInfoTest002
 * @tc.desc: Test UpdateServiceInfo when input param is invalid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServiceDatabaseTest, UpdateServiceInfoTest002, TestSize.Level1)
{
    DISC_LOGI(DISC_INIT, "UpdateServiceInfoTest002 begin");

    EXPECT_EQ(ServiceDatabaseInit(), SOFTBUS_OK);

    EXPECT_EQ(UpdateServiceInfo(&g_serviceInfo1), SOFTBUS_OK);

    ServiceDatabaseDeinit();

    DISC_LOGI(DISC_INIT, "UpdateServiceInfoTest002 end");
}

/*
 * @tc.name: UpdateServiceInfoTest003
 * @tc.desc: Test UpdateServiceInfo and GetServiceInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServiceDatabaseTest, UpdateServiceInfoTest003, TestSize.Level1)
{
    DISC_LOGI(DISC_INIT, "UpdateServiceInfoTest003 begin");

    EXPECT_EQ(ServiceDatabaseInit(), SOFTBUS_OK);

    EXPECT_EQ(AddServiceInfo(&g_serviceInfo0), SOFTBUS_OK);

    ServiceInfo srvInfo = {};
    EXPECT_EQ(GetServiceInfo(g_serviceInfo0.serviceId, &srvInfo), SOFTBUS_OK);

    EXPECT_EQ(srvInfo.serviceId, g_serviceInfo0.serviceId);
    EXPECT_EQ(strcmp(srvInfo.serviceType, g_serviceInfo0.serviceType), SOFTBUS_OK);
    EXPECT_EQ(strcmp(srvInfo.serviceName, g_serviceInfo0.serviceName), SOFTBUS_OK);
    EXPECT_EQ(strcmp(srvInfo.serviceDisplayName, g_serviceInfo0.serviceDisplayName), SOFTBUS_OK);
    EXPECT_EQ(strcmp((const char *)srvInfo.customData, (const char *)g_serviceInfo0.customData), SOFTBUS_OK);
    EXPECT_EQ(srvInfo.dataLen, g_serviceInfo0.dataLen);

    static ServiceInfo srvInfo1 = {
        .serviceId = 1000000,
        .serviceType = "serviceType1",
        .serviceName = "serviceName1",
        .serviceDisplayName = "serviceDisplayName1",
        .dataLen = strlen("customData1")
    };
    (void)memcpy_s(srvInfo1.customData, DISC_SERVICE_CUSTOMDATA_MAX_LEN - 1, "customData1", strlen("customData1"));

    EXPECT_EQ(UpdateServiceInfo(&srvInfo1), SOFTBUS_OK);

    ServiceInfo srvInfo2 = {};
    EXPECT_EQ(GetServiceInfo(g_serviceInfo0.serviceId, &srvInfo2), SOFTBUS_OK);

    EXPECT_EQ(srvInfo2.serviceId, srvInfo1.serviceId);
    EXPECT_EQ(strcmp(srvInfo2.serviceType, srvInfo1.serviceType), SOFTBUS_OK);
    EXPECT_EQ(strcmp(srvInfo2.serviceName, srvInfo1.serviceName), SOFTBUS_OK);
    EXPECT_EQ(strcmp(srvInfo2.serviceDisplayName, srvInfo1.serviceDisplayName), SOFTBUS_OK);
    EXPECT_EQ(strcmp((const char *)srvInfo2.customData, (const char *)srvInfo1.customData), SOFTBUS_OK);
    EXPECT_EQ(srvInfo2.dataLen, srvInfo1.dataLen);

    EXPECT_EQ(RemoveServiceInfo(g_serviceInfo0.serviceId), SOFTBUS_OK);

    ServiceDatabaseDeinit();

    DISC_LOGI(DISC_INIT, "UpdateServiceInfoTest003 end");
}

} // namespace OHOS
