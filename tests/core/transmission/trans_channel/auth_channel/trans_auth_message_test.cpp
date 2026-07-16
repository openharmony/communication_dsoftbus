/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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
#include <securec.h>

#include "softbus_adapter_mem.h"
#include "trans_auth_message.h"

using namespace testing::ext;

#define TEST_AUTH_DATA "test auth message data"
#define CODE_OPEN_AUTH_MSG_CHANNEL 4

namespace OHOS {
const char *g_pkgName = "dms";
const char *g_sessionName = "ohos.distributedschedule.dms.test";
const char *g_deviceId = "ABCDEF00ABCDEF00ABCDEF00";
const char *g_errMsg = "errormessage";
const char *g_reqId = "test reqId";

class TransAuthMessageTest : public testing::Test {
public:
    TransAuthMessageTest(void)
    {}
    ~TransAuthMessageTest(void)
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void TransAuthMessageTest::SetUpTestCase(void)
{}

void TransAuthMessageTest::TearDownTestCase(void)
{}

/*
 * @tc.name: TransAuthChannelMsgPackTest001
 * @tc.desc: TransAuthChannelMsgPack with null params returns SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthMessageTest, TransAuthChannelMsgPackTest001, TestSize.Level1)
{
    AppInfo *appInfo = reinterpret_cast<AppInfo *>(SoftBusMalloc(sizeof(AppInfo)));
    ASSERT_TRUE(appInfo != nullptr);
    (void)memset_s(appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    cJSON *msg = cJSON_CreateObject();

    int32_t ret = TransAuthChannelMsgPack(nullptr, appInfo);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = TransAuthChannelMsgPack(msg, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    cJSON_Delete(msg);
    SoftBusFree(appInfo);
}

/*
 * @tc.name: TransAuthChannelMsgUnpackTest001
 * @tc.desc: TransAuthChannelMsgUnpack with null params returns SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthMessageTest, TransAuthChannelMsgUnpackTest001, TestSize.Level1)
{
    AppInfo *appInfo = reinterpret_cast<AppInfo *>(SoftBusMalloc(sizeof(AppInfo)));
    ASSERT_TRUE(appInfo != nullptr);
    (void)memset_s(appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));

    int32_t ret = TransAuthChannelMsgUnpack(nullptr, appInfo, 0);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = TransAuthChannelMsgUnpack(TEST_AUTH_DATA, nullptr, 0);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    SoftBusFree(appInfo);
}

/*
 * @tc.name: TransAuthChannelInvalidParamTest001
 * @tc.desc: TransAuthChannelMsgUnpack with len=0 and TransAuthChannelErrorPack with null params return error codes
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthMessageTest, TransAuthChannelInvalidParamTest001, TestSize.Level1)
{
    AppInfo *appInfo = reinterpret_cast<AppInfo *>(SoftBusMalloc(sizeof(AppInfo)));
    ASSERT_TRUE(appInfo != nullptr);
    (void)memset_s(appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));

    int32_t ret = TransAuthChannelMsgUnpack(TEST_AUTH_DATA, appInfo, 0);
    EXPECT_EQ(ret, SOFTBUS_PARSE_JSON_ERR);

    char cJsonStr[ERR_MSG_MAX_LEN] = {0};
    ret = TransAuthChannelErrorPack(SOFTBUS_INVALID_PARAM, nullptr, cJsonStr, ERR_MSG_MAX_LEN);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = TransAuthChannelErrorPack(SOFTBUS_INVALID_PARAM, g_errMsg, nullptr, ERR_MSG_MAX_LEN);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    SoftBusFree(appInfo);
}

/*
 * @tc.name: TransAuthChannelMsgUnpackTest003
 * @tc.desc: TransAuthChannelMsgUnpack with progressively added JSON fields returns SOFTBUS_PARSE_JSON_ERR
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthMessageTest, TransAuthChannelMsgUnpackTest003, TestSize.Level1)
{
    AppInfo *appInfo = reinterpret_cast<AppInfo *>(SoftBusMalloc(sizeof(AppInfo)));
    ASSERT_TRUE(appInfo != nullptr);
    (void)memset_s(appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    cJSON *msg = cJSON_CreateObject();

    bool res = AddNumberToJsonObject(msg, "CODE", CODE_OPEN_AUTH_MSG_CHANNEL);
    EXPECT_TRUE(res);

    char *data = cJSON_PrintUnformatted(msg);
    int32_t ret = TransAuthChannelMsgUnpack(data, appInfo, strlen(data));
    EXPECT_EQ(ret, SOFTBUS_PARSE_JSON_ERR);
    cJSON_free(data);

    res = AddStringToJsonObject(msg, "DEVICE_ID", g_deviceId);
    ASSERT_TRUE(res);

    data = cJSON_PrintUnformatted(msg);
    ret = TransAuthChannelMsgUnpack(data, appInfo, strlen(data));
    EXPECT_EQ(ret, SOFTBUS_PARSE_JSON_ERR);
    cJSON_free(data);

    res = AddStringToJsonObject(msg, "PKG_NAME", g_pkgName);
    ASSERT_TRUE(res);
    data = cJSON_PrintUnformatted(msg);
    ret = TransAuthChannelMsgUnpack(data, appInfo, strlen(data));
    EXPECT_EQ(ret, SOFTBUS_PARSE_JSON_ERR);
    cJSON_free(data);

    res = AddStringToJsonObject(msg, "SRC_BUS_NAME", g_sessionName);
    ASSERT_TRUE(res);
    data = cJSON_PrintUnformatted(msg);
    ret = TransAuthChannelMsgUnpack(data, appInfo, strlen(data));
    EXPECT_EQ(ret, SOFTBUS_PARSE_JSON_ERR);
    cJSON_free(data);

    res = AddStringToJsonObject(msg, "DST_BUS_NAME", g_sessionName);
    EXPECT_TRUE(res);

    data = cJSON_PrintUnformatted(msg);
    ret = TransAuthChannelMsgUnpack(data, appInfo, strlen(data));
    EXPECT_EQ(ret, SOFTBUS_PARSE_JSON_ERR);
    cJSON_free(data);

    res = AddStringToJsonObject(msg, "REQ_ID", g_reqId);
    EXPECT_TRUE(res);

    data = cJSON_PrintUnformatted(msg);
    ret = TransAuthChannelMsgUnpack(data, appInfo, strlen(data));
    EXPECT_EQ(ret, SOFTBUS_OK);
 
    cJSON_free(data);
    cJSON_Delete(msg);
    SoftBusFree(appInfo);
}

/*
 * @tc.name: TransAuthChannelMsgUnpackTest004
 * @tc.desc: TransAuthChannelMsgUnpack with ERR_CODE and ERR_DESC fields returns SOFTBUS_PARSE_JSON_ERR
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthMessageTest, TransAuthChannelMsgUnpackTest004, TestSize.Level1)
{
    AppInfo *appInfo = reinterpret_cast<AppInfo *>(SoftBusMalloc(sizeof(AppInfo)));
    ASSERT_TRUE(appInfo != nullptr);
    (void)memset_s(appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    cJSON *msg = cJSON_CreateObject();

    int32_t errorCode = 1;
    bool res = AddNumberToJsonObject(msg, "ERR_CODE", errorCode);
    EXPECT_TRUE(res);

    res = AddStringToJsonObject(msg, "ERR_DESC", g_errMsg);
    EXPECT_TRUE(res);

    char *data = cJSON_PrintUnformatted(msg);
    int32_t ret = TransAuthChannelMsgUnpack(data, appInfo, strlen(data));
    EXPECT_EQ(ret, errorCode);

    cJSON_free(data);
    cJSON_Delete(msg);
    SoftBusFree(appInfo);
}
} // namespace OHOS
