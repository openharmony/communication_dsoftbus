/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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
#include "softbus_json_utils.h"
// This file needs to be placed after gtest.h (atomic), otherwise will compile error (stdatomic.h)
#include "softbus_message_open_channel.c"
#include "trans_auth_message.h"

using namespace testing::ext;
namespace OHOS {
#define SESSION_NAME_MAX_LEN 256
#define PKG_NAME_SIZE_MAX_LEN 65
#define TEST_SESSION_KEY "session key"

const char *g_sessionKey = "www.huaweitest.com";
const char *g_groupid = "TEST_GROUP_ID";
static const char *g_sessionName = "com.test.trans.auth.demo";
static const char *g_pkgName = "dms";
constexpr uint16_t fastTransDataSize = 64;

class SoftBusMessageOpenChannelTest : public testing::Test {
public:
    SoftBusMessageOpenChannelTest()
    {}
    ~SoftBusMessageOpenChannelTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void SoftBusMessageOpenChannelTest::SetUpTestCase(void)
{}

void SoftBusMessageOpenChannelTest::TearDownTestCase(void)
{}

char *TestGetMsgPack(ApiVersion apiVersion)
{
    cJSON *msg = cJSON_CreateObject();
    if (msg == nullptr) {
        cJSON_Delete(msg);
        return nullptr;
    }
    AppInfo *appInfo = (AppInfo *)SoftBusCalloc(sizeof(AppInfo));
    if (appInfo == nullptr) {
        cJSON_Delete(msg);
        return nullptr;
    }
    appInfo->appType = APP_TYPE_NOT_CARE;
    appInfo->businessType = BUSINESS_TYPE_BYTE;
    appInfo->myData.channelId = 1;
    appInfo->myData.apiVersion = apiVersion;
    appInfo->peerData.apiVersion = apiVersion;
    (void)memcpy_s(appInfo->myData.sessionName, SESSION_NAME_MAX_LEN, g_sessionName, (strlen(g_sessionName)+1));
    (void)memcpy_s(appInfo->myData.pkgName, PKG_NAME_SIZE_MAX_LEN, g_pkgName, (strlen(g_pkgName)+1));
    if (TransAuthChannelMsgPack(msg, appInfo) != SOFTBUS_OK) {
        cJSON_Delete(msg);
        return nullptr;
    }
    if (!AddStringToJsonObject(msg, AUTH_STATE, g_sessionKey)) {
        cJSON_Delete(msg);
        return nullptr;
    }
    char *data = cJSON_PrintUnformatted(msg);
    cJSON_Delete(msg);

    if (appInfo != nullptr) {
        SoftBusFree(appInfo);
    }
    return data;
}

int32_t TestTransAuthChannelMsgPack(cJSON *msg, const AppInfo *appInfo)
{
    if (appInfo == NULL || msg == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (!AddStringToJsonObject(msg, "DEVICE_ID", appInfo->myData.deviceId) ||
        !AddStringToJsonObject(msg, "PKG_NAME", appInfo->myData.pkgName) ||
        !AddStringToJsonObject(msg, "SRC_BUS_NAME", appInfo->myData.sessionName) ||
        !AddNumber16ToJsonObject(msg, "FIRST_DATA_SIZE", appInfo->fastTransDataSize) ||
        !AddStringToJsonObject(msg, "DST_BUS_NAME", appInfo->peerData.sessionName) ||
        !AddStringToJsonObject(msg, "FIRST_DATA", reinterpret_cast<const char *>(appInfo->fastTransData)) ||
        !AddNumberToJsonObject(msg, "MTU_SIZE", appInfo->myData.dataConfig)) {
        return SOFTBUS_PARSE_JSON_ERR;
    }
    return SOFTBUS_OK;
}

/**
 * @tc.name: PackError001
 * @tc.desc: PackError001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusMessageOpenChannelTest, PackError001, TestSize.Level1)
{
    int32_t errCode = SOFTBUS_INVALID_PARAM;
    char *msg = PackError(errCode, NULL);
    EXPECT_EQ(NULL, msg);

    errCode = CODE_OPEN_CHANNEL;
    msg = PackError(errCode, NULL);
    EXPECT_EQ(NULL, msg);

    const char *errDesc = "test";
    errCode = -1;
    msg = PackError(errCode, errDesc);
    EXPECT_NE(msg, NULL);
}

/**
 * @tc.name: PackRequest001
 * @tc.desc: PackRequest001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusMessageOpenChannelTest, PackRequest001, TestSize.Level1)
{
    AppInfo *appInfo = (AppInfo *)SoftBusCalloc(sizeof(AppInfo));
    ASSERT_TRUE(appInfo != nullptr);
    (void)memset_s(appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));

    char *msg = PackRequest(NULL);
    EXPECT_EQ(NULL, msg);

    int32_t res = strcpy_s(appInfo->myData.pkgName, sizeof(appInfo->myData.pkgName), g_sessionName);
    EXPECT_EQ(EOK, res);
    res = strcpy_s(appInfo->myData.sessionName, sizeof(appInfo->myData.sessionName), g_sessionName);
    EXPECT_EQ(EOK, res);
    res = strcpy_s(appInfo->myData.authState, sizeof(appInfo->myData.authState), g_sessionName);
    EXPECT_EQ(EOK, res);

    msg = PackRequest(appInfo);
    // return data
    EXPECT_NE(msg, nullptr);

    if (appInfo != NULL) {
        SoftBusFree(appInfo);
    }
}

/**
 * @tc.name: UnpackRequest001
 * @tc.desc: UnpackRequest001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusMessageOpenChannelTest, UnpackRequest001, TestSize.Level1)
{
    int32_t ret = UnpackRequest(NULL, NULL);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    char *mag = TestGetMsgPack(API_V2);
    cJSON *json = cJSON_Parse(mag);
    EXPECT_NE(json, nullptr);
    ret = UnpackRequest(json, NULL);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    AppInfo *appInfo = (AppInfo *)SoftBusCalloc(sizeof(AppInfo));
    ASSERT_TRUE(appInfo != nullptr);
    (void)memset_s(appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    ret = UnpackRequest(NULL, appInfo);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    int32_t res = strcpy_s(appInfo->groupId, sizeof(appInfo->groupId), g_groupid);
    EXPECT_EQ(EOK, res);
    ret = UnpackRequest(json, appInfo);
    EXPECT_EQ(SOFTBUS_PARSE_JSON_ERR, ret);
    char *msg = TestGetMsgPack(API_V1);
    cJSON *json1 = cJSON_Parse(msg);
    EXPECT_NE(json1, nullptr);
    ret = UnpackRequest(json1, appInfo);
    EXPECT_EQ(SOFTBUS_PARSE_JSON_ERR, ret);
    if (appInfo != NULL) {
        SoftBusFree(appInfo);
    }
    cJSON_Delete(json);
    cJSON_Delete(json1);
}

/**
 * @tc.name: UnpackRequest002
 * @tc.desc: UnpackRequest001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusMessageOpenChannelTest, UnpackRequest002, TestSize.Level1)
{
    cJSON *msg = cJSON_CreateObject();
    cJSON_AddStringToObject(msg, BUS_NAME, "BUS_NAME");
    cJSON_AddStringToObject(msg, GROUP_ID, "GROUP_ID");
    cJSON_AddStringToObject(msg, SESSION_KEY, "SESSION_KEY");
    cJSON_AddNumberToObject(msg, MTU_SIZE, 1000);
    cJSON_AddNumberToObject(msg, UID, 100);
    cJSON_AddNumberToObject(msg, PID, 200);
    cJSON_AddNumberToObject(msg, MY_HANDLE_ID, 1);
    cJSON_AddNumberToObject(msg, PEER_HANDLE_ID, 2);
    AppInfo *appInfo = (AppInfo *)SoftBusCalloc(sizeof(AppInfo));
    ASSERT_TRUE(appInfo != nullptr);
    int32_t ret = UnpackRequest(msg, appInfo);
    EXPECT_EQ(ret, SOFTBUS_PARSE_JSON_ERR);
    EXPECT_STREQ(appInfo->myData.sessionName, "BUS_NAME");
    EXPECT_STREQ(appInfo->groupId, "GROUP_ID");
    EXPECT_STREQ(appInfo->sessionKey, "");
    EXPECT_EQ(appInfo->peerData.dataConfig, 1000);
    EXPECT_EQ(appInfo->peerData.uid, 100);
    EXPECT_EQ(appInfo->peerData.pid, 200);
    EXPECT_EQ(appInfo->myHandleId, 2);
    EXPECT_EQ(appInfo->peerHandleId, 1);
    cJSON_Delete(msg);
    SoftBusFree(appInfo);
}
/**
 * @tc.name: PackReply001
 * @tc.desc: PackReply001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusMessageOpenChannelTest, PackReply001, TestSize.Level1)
{
    char *msg = PackReply(NULL);
    EXPECT_EQ(NULL, msg);

    AppInfo *appInfo = (AppInfo *)SoftBusCalloc(sizeof(AppInfo));
    ASSERT_TRUE(appInfo != nullptr);
    (void)memset_s(appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    appInfo->myData.apiVersion = API_V1;
    appInfo->myData.uid = -1;
    appInfo->myData.pid = -1;
    msg = PackReply(appInfo);
    // return data
    EXPECT_NE(msg, nullptr);

    (void)memset_s(appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    appInfo->myData.apiVersion = API_V2;
    appInfo->myData.uid = -1;
    appInfo->myData.pid = -1;
    msg = PackReply(appInfo);
    EXPECT_TRUE(msg != nullptr);

    if (appInfo != NULL) {
        SoftBusFree(appInfo);
    }
}

/**
 * @tc.name: UnpackReply001
 * @tc.desc: UnpackReply001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusMessageOpenChannelTest, UnpackReply001, TestSize.Level1)
{
    int32_t ret = UnpackReply(NULL, NULL, NULL);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    char *mag = TestGetMsgPack(API_V2);
    cJSON *json = cJSON_Parse(mag);
    ret = UnpackReply(json, NULL, NULL);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    AppInfo *appInfo = (AppInfo *)SoftBusCalloc(sizeof(AppInfo));
    ASSERT_TRUE(appInfo != nullptr);
    (void)memset_s(appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    ret = UnpackReply(NULL, appInfo, NULL);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    uint16_t fastDataSize = 1;
    ret = UnpackReply(json, appInfo, &fastDataSize);
    EXPECT_EQ(SOFTBUS_OK, ret);

    if (appInfo != NULL) {
        SoftBusFree(appInfo);
    }
    cJSON_Delete(json);
}

/**
 * @tc.name: UnpackReplyErrCode001
 * @tc.desc: UnpackReplyErrCode001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusMessageOpenChannelTest, UnpackReplyErrCode001, TestSize.Level1)
{
    int32_t errCode = -12345;
    int32_t ret = UnpackReplyErrCode(NULL, NULL);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    char *mag = TestGetMsgPack(API_V2);
    cJSON *json = cJSON_Parse(mag);
    ret = UnpackReplyErrCode(json, NULL);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = UnpackReplyErrCode(NULL, &errCode);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    errCode = 1;
    ret = UnpackReplyErrCode(json, &errCode);
    EXPECT_EQ(SOFTBUS_PARSE_JSON_ERR, ret);
    cJSON_Delete(json);
}

/**
 * @tc.name: PackFirstData001
 * @tc.desc: test PackFirstData.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusMessageOpenChannelTest, PackFirstData001, TestSize.Level1)
{
    AppInfo *appInfo = (AppInfo *)SoftBusCalloc(sizeof(AppInfo));
    ASSERT_TRUE(appInfo != nullptr);

    char *mag = TestGetMsgPack(API_V2);
    cJSON *json = cJSON_Parse(mag);
    EXPECT_NE(json, nullptr);

    int32_t ret = PackFirstData(appInfo, json);
    EXPECT_EQ(SOFTBUS_ENCRYPT_ERR, ret);

    appInfo->fastTransDataSize = fastTransDataSize;
    appInfo->fastTransData = (uint8_t*)"abcdef@ghabcdefghabcdefghfgdabc";

    int32_t res = strcpy_s(appInfo->sessionKey, sizeof(appInfo->sessionKey), TEST_SESSION_KEY);
    EXPECT_EQ(EOK, res);

    ret = PackFirstData(appInfo, json);
    EXPECT_EQ(EOK, ret);
    if (appInfo != NULL) {
        SoftBusFree(appInfo);
    }
    cJSON_Delete(json);
}

/**
 * @tc.name: UnpackFirstData001
 * @tc.desc: test UnpackFirstData.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusMessageOpenChannelTest, UnpackFirstData001, TestSize.Level1)
{
    cJSON *msg = cJSON_CreateObject();
    AppInfo *appInfo = (AppInfo *)SoftBusCalloc(sizeof(AppInfo));
    ASSERT_TRUE(appInfo != nullptr);

    appInfo->appType = APP_TYPE_NOT_CARE;
    appInfo->businessType = BUSINESS_TYPE_BYTE;
    appInfo->myData.channelId = 1;
    appInfo->myData.apiVersion = API_V2;
    appInfo->peerData.apiVersion = API_V2;
    appInfo->fastTransDataSize = fastTransDataSize;
    appInfo->fastTransData = (uint8_t*)"abcdef@ghabcdefghabcdefghfgdabc";

    (void)memcpy_s(appInfo->myData.sessionName, SESSION_NAME_MAX_LEN, g_sessionName, (strlen(g_sessionName)+1));
    (void)memcpy_s(appInfo->myData.pkgName, PKG_NAME_SIZE_MAX_LEN, g_pkgName, (strlen(g_pkgName)+1));
    int32_t res = TestTransAuthChannelMsgPack(msg, appInfo);
    EXPECT_EQ(SOFTBUS_OK, res);
    char *data = cJSON_PrintUnformatted(msg);
    cJSON_Delete(msg);

    cJSON *json = cJSON_Parse(data);
    EXPECT_NE(json, nullptr);

    int32_t ret = UnpackFirstData(appInfo, nullptr);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = UnpackFirstData(appInfo, json);
    EXPECT_EQ(SOFTBUS_DECRYPT_ERR, ret);

    char *mag = TestGetMsgPack(API_V2);
    cJSON *json1 = cJSON_Parse(mag);
    EXPECT_NE(json, nullptr);
    ret = UnpackFirstData(appInfo, json1);
    EXPECT_EQ(SOFTBUS_OK, ret);

    if (appInfo != nullptr) {
        SoftBusFree(appInfo);
    }
    cJSON_Delete(json);
    cJSON_Delete(json1);
}
} // OHOS
