/*
 * Copyright (c) 2025-2026 Huawei Device Co., Ltd.
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
#include "softbus_message_open_channel.c"
#include "trans_auth_message.h"
#include "softbus_message_open_channel_mock.h"

using namespace std;
using namespace testing;
using namespace testing::ext;
namespace OHOS {
#define TEMP_NUM 1
class SoftBusMessageOpenChannelMockTest : public testing::Test {
public:
    SoftBusMessageOpenChannelMockTest()
    {}
    ~SoftBusMessageOpenChannelMockTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void SoftBusMessageOpenChannelMockTest::SetUpTestCase(void)
{}

void SoftBusMessageOpenChannelMockTest::TearDownTestCase(void)
{}


/*
 * @tc.name: PackError001
 * @tc.desc: PackError001 test
 *           use the wrong parameter or normal parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusMessageOpenChannelMockTest, PackError001, TestSize.Level1)
{
    int32_t errCode = SOFTBUS_INVALID_PARAM;
    const char *errDesc = "test";
    OHOS::SoftbusMessageOpenChannelInterfaceMock softbusMOpenChannelMock;

    EXPECT_CALL(softbusMOpenChannelMock, cJSON_CreateObject).WillOnce(Return(nullptr));
    EXPECT_CALL(softbusMOpenChannelMock, AddStringToJsonObject).WillRepeatedly(Return(true));
    char *ret = PackError(errCode, errDesc);
    EXPECT_EQ(nullptr, ret);
}

/*
 * @tc.name: PackError002
 * @tc.desc: PackError002 test
 *           use the wrong parameter or normal parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusMessageOpenChannelMockTest, PackError002, TestSize.Level1)
{
    int32_t errCode = SOFTBUS_INVALID_PARAM;
    const char *errDesc = "test";
    cJSON json = {0};
    OHOS::SoftbusMessageOpenChannelInterfaceMock softbusMOpenChannelMock;
    EXPECT_CALL(softbusMOpenChannelMock, AddStringToJsonObject).WillRepeatedly(Return(true));
    EXPECT_CALL(softbusMOpenChannelMock, cJSON_CreateObject).WillOnce(Return(&json));
    EXPECT_CALL(softbusMOpenChannelMock, AddNumberToJsonObject).WillRepeatedly(Return(false));
    char *ret = PackError(errCode, errDesc);
    EXPECT_EQ(nullptr, ret);
}

/*
 * @tc.name: PackError003
 * @tc.desc: PackError003 test
 *           use the wrong parameter or normal parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusMessageOpenChannelMockTest, PackError003, TestSize.Level1)
{
    int32_t errCode = SOFTBUS_INVALID_PARAM;
    const char *errDesc = "test";
    cJSON json = {0};
    OHOS::SoftbusMessageOpenChannelInterfaceMock softbusMOpenChannelMock;
    EXPECT_CALL(softbusMOpenChannelMock, AddStringToJsonObject).WillRepeatedly(Return(true));
    EXPECT_CALL(softbusMOpenChannelMock, cJSON_CreateObject).WillRepeatedly(Return(&json));
    EXPECT_CALL(softbusMOpenChannelMock, AddNumberToJsonObject).WillRepeatedly(Return(true));
    EXPECT_CALL(softbusMOpenChannelMock, cJSON_PrintUnformatted).WillRepeatedly(Return(nullptr));
    char *ret = PackError(errCode, errDesc);
    EXPECT_EQ(nullptr, ret);
}

/*
 * @tc.name: PackRequest001
 * @tc.desc: PackRequest001 test
 *           use the wrong parameter or normal parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusMessageOpenChannelMockTest, PackRequest001, TestSize.Level3)
{
    AppInfo *appInfo = reinterpret_cast<AppInfo *>(SoftBusMalloc(sizeof(AppInfo)));
    ASSERT_NE(nullptr, appInfo);
    (void)memset_s(appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    OHOS::SoftbusMessageOpenChannelInterfaceMock softbusMOpenChannelMock;
    EXPECT_CALL(softbusMOpenChannelMock, cJSON_CreateObject).WillOnce(Return(nullptr));
    char *ret = PackRequest(appInfo, 0);
    EXPECT_EQ(nullptr, ret);

    if (appInfo != nullptr) {
        SoftBusFree(appInfo);
    }
}

/*
 * @tc.name: PackRequest002
 * @tc.desc: PackRequest002 test
 *           use the wrong parameter or normal parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusMessageOpenChannelMockTest, PackRequest002, TestSize.Level3)
{
    AppInfo *appInfo = reinterpret_cast<AppInfo *>(SoftBusMalloc(sizeof(AppInfo)));
    ASSERT_NE(nullptr, appInfo);
    (void)memset_s(appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    cJSON json = {0};
    OHOS::SoftbusMessageOpenChannelInterfaceMock softbusMOpenChannelMock;
    EXPECT_CALL(softbusMOpenChannelMock, cJSON_CreateObject).WillOnce(Return(&json));
    EXPECT_CALL(softbusMOpenChannelMock, AddNumber16ToJsonObject).WillOnce(Return(false));
    char *ret = PackRequest(appInfo, 0);
    EXPECT_EQ(nullptr, ret);

    if (appInfo != nullptr) {
        SoftBusFree(appInfo);
    }
}

/*
 * @tc.name: PackRequest003
 * @tc.desc: PackRequest003 test
 *           use the wrong parameter or normal parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusMessageOpenChannelMockTest, PackRequest003, TestSize.Level3)
{
    AppInfo *appInfo = reinterpret_cast<AppInfo *>(SoftBusMalloc(sizeof(AppInfo)));
    ASSERT_NE(nullptr, appInfo);
    (void)memset_s(appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    cJSON json = {0};
    OHOS::SoftbusMessageOpenChannelInterfaceMock softbusMOpenChannelMock;
    EXPECT_CALL(softbusMOpenChannelMock, cJSON_CreateObject).WillRepeatedly(Return(&json));
    EXPECT_CALL(softbusMOpenChannelMock, AddNumber16ToJsonObject).WillRepeatedly(Return(true));
    EXPECT_CALL(softbusMOpenChannelMock, AddNumberToJsonObject).WillRepeatedly(Return(true));
    EXPECT_CALL(softbusMOpenChannelMock, AddStringToJsonObject).WillRepeatedly(Return(true));
    EXPECT_CALL(softbusMOpenChannelMock, cJSON_PrintUnformatted).WillRepeatedly(Return(nullptr));
    EXPECT_CALL(softbusMOpenChannelMock, SoftBusBase64Encode).WillOnce(Return(TEMP_NUM));

    char *ret = PackRequest(appInfo, 0);
    EXPECT_EQ(nullptr, ret);

    if (appInfo != nullptr) {
        SoftBusFree(appInfo);
    }
}

/*
 * @tc.name: PackRequest004
 * @tc.desc: PackRequest004 test
 *           use the wrong parameter or normal parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusMessageOpenChannelMockTest, PackRequest004, TestSize.Level3)
{
    AppInfo *appInfo = reinterpret_cast<AppInfo *>(SoftBusMalloc(sizeof(AppInfo)));
    ASSERT_NE(nullptr, appInfo);
    (void)memset_s(appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    cJSON json = {0};
    OHOS::SoftbusMessageOpenChannelInterfaceMock softbusMOpenChannelMock;
    EXPECT_CALL(softbusMOpenChannelMock, cJSON_CreateObject).WillRepeatedly(Return(&json));
    EXPECT_CALL(softbusMOpenChannelMock, AddNumber16ToJsonObject).WillRepeatedly(Return(true));
    EXPECT_CALL(softbusMOpenChannelMock, AddNumberToJsonObject).WillRepeatedly(Return(true));
    EXPECT_CALL(softbusMOpenChannelMock, AddStringToJsonObject).WillRepeatedly(Return(true));
    EXPECT_CALL(softbusMOpenChannelMock, cJSON_PrintUnformatted).WillRepeatedly(Return(nullptr));
    EXPECT_CALL(softbusMOpenChannelMock, SoftBusBase64Encode).WillRepeatedly(Return(SOFTBUS_OK));
    char *ret = PackRequest(appInfo, 0);
    EXPECT_EQ(nullptr, ret);

    if (appInfo != nullptr) {
        SoftBusFree(appInfo);
    }
}

/*
 * @tc.name: PackReply001
 * @tc.desc: PackReply001 test
 *           use the wrong parameter or normal parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusMessageOpenChannelMockTest, PackReply001, TestSize.Level1)
{
    AppInfo *appInfo = reinterpret_cast<AppInfo *>(SoftBusMalloc(sizeof(AppInfo)));
    ASSERT_NE(nullptr, appInfo);
    (void)memset_s(appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    OHOS::SoftbusMessageOpenChannelInterfaceMock softbusMOpenChannelMock;
    EXPECT_CALL(softbusMOpenChannelMock, cJSON_CreateObject).WillOnce(Return(nullptr));
    char *ret = PackReply(appInfo);
    EXPECT_EQ(nullptr, ret);

    if (appInfo != nullptr) {
        SoftBusFree(appInfo);
    }
}

/*
 * @tc.name: PackReply002
 * @tc.desc: PackReply002 test
 *           use the wrong parameter or normal parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusMessageOpenChannelMockTest, PackReply002, TestSize.Level1)
{
    AppInfo *appInfo = reinterpret_cast<AppInfo *>(SoftBusCalloc(sizeof(AppInfo)));
    ASSERT_NE(nullptr, appInfo);
    cJSON json = {0};
    OHOS::SoftbusMessageOpenChannelInterfaceMock softbusMOpenChannelMock;
    EXPECT_CALL(softbusMOpenChannelMock, cJSON_CreateObject).WillRepeatedly(Return(&json));
    EXPECT_CALL(softbusMOpenChannelMock, AddNumberToJsonObject).WillRepeatedly(Return(false));
    char *ret = PackReply(appInfo);
    EXPECT_EQ(nullptr, ret);

    if (appInfo != nullptr) {
        SoftBusFree(appInfo);
    }
}

/*
 * @tc.name: PackReply003
 * @tc.desc: PackReply003 test
 *           use the wrong parameter or normal parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusMessageOpenChannelMockTest, PackReply003, TestSize.Level1)
{
    AppInfo *appInfo = reinterpret_cast<AppInfo *>(SoftBusCalloc(sizeof(AppInfo)));
    ASSERT_NE(nullptr, appInfo);
    cJSON json = {0};
    OHOS::SoftbusMessageOpenChannelInterfaceMock softbusMOpenChannelMock;
    EXPECT_CALL(softbusMOpenChannelMock, cJSON_CreateObject).WillRepeatedly(Return(&json));
    EXPECT_CALL(softbusMOpenChannelMock, AddNumberToJsonObject).WillRepeatedly(Return(true));
    EXPECT_CALL(softbusMOpenChannelMock, AddStringToJsonObject).WillRepeatedly(Return(true));
    EXPECT_CALL(softbusMOpenChannelMock, AddNumber16ToJsonObject).WillOnce(Return(false));
    char *ret = PackReply(appInfo);
    EXPECT_EQ(nullptr, ret);

    if (appInfo != nullptr) {
        SoftBusFree(appInfo);
    }
}

/*
 * @tc.name: PackReply004
 * @tc.desc: PackReply004 test
 *           use the wrong parameter or normal parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusMessageOpenChannelMockTest, PackReply004, TestSize.Level1)
{
    AppInfo *appInfo = reinterpret_cast<AppInfo *>(SoftBusCalloc(sizeof(AppInfo)));
    ASSERT_NE(nullptr, appInfo);
    cJSON json = {0};
    OHOS::SoftbusMessageOpenChannelInterfaceMock softbusMOpenChannelMock;
    EXPECT_CALL(softbusMOpenChannelMock, cJSON_CreateObject).WillRepeatedly(Return(&json));
    EXPECT_CALL(softbusMOpenChannelMock, AddNumberToJsonObject).WillRepeatedly(Return(true));
    EXPECT_CALL(softbusMOpenChannelMock, AddStringToJsonObject).WillRepeatedly(Return(true));
    EXPECT_CALL(softbusMOpenChannelMock, AddNumber16ToJsonObject).WillOnce(Return(true));
    EXPECT_CALL(softbusMOpenChannelMock, cJSON_PrintUnformatted).WillRepeatedly(Return(nullptr));
    char *ret = PackReply(appInfo);
    EXPECT_EQ(nullptr, ret);

    if (appInfo != nullptr) {
        SoftBusFree(appInfo);
    }
}

/*
 * @tc.name: UnpackReply001
 * @tc.desc: UnpackReply001 test
 *           use the wrong parameter or normal parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusMessageOpenChannelMockTest, UnpackReply001, TestSize.Level1)
{
    AppInfo *appInfo = reinterpret_cast<AppInfo *>(SoftBusCalloc(sizeof(AppInfo)));
    ASSERT_NE(nullptr, appInfo);
    cJSON msg = {0};
    OHOS::SoftbusMessageOpenChannelInterfaceMock softbusMOpenChannelMock;
    EXPECT_CALL(softbusMOpenChannelMock, GetJsonObjectStringItem).WillOnce(Return(false));
    int32_t ret = UnpackReply(&msg, appInfo, nullptr);
    EXPECT_EQ(SOFTBUS_PARSE_JSON_ERR, ret);

    if (appInfo != nullptr) {
        SoftBusFree(appInfo);
    }
}

/*
 * @tc.name: UnpackReply002
 * @tc.desc: UnpackReply002 test
 *           use the wrong parameter or normal parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusMessageOpenChannelMockTest, UnpackReply002, TestSize.Level1)
{
    AppInfo *appInfo = reinterpret_cast<AppInfo *>(SoftBusCalloc(sizeof(AppInfo)));
    ASSERT_NE(nullptr, appInfo);
    cJSON msg = {0};
    OHOS::SoftbusMessageOpenChannelInterfaceMock softbusMOpenChannelMock;
    char deviceId[DEVICE_ID_SIZE_MAX] = {"12345"};
    EXPECT_CALL(softbusMOpenChannelMock, GetJsonObjectStringItem)
        .WillOnce(DoAll(SetArgPointee<2>(*deviceId), Return(true)));
    int32_t ret = UnpackReply(&msg, appInfo, nullptr);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_UUID, ret);

    if (appInfo != nullptr) {
        SoftBusFree(appInfo);
    }
}

/*
 * @tc.name: TransTdcPackFastData001
 * @tc.desc: TransTdcPackFastData001 test
 *           use the wrong parameter or normal parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusMessageOpenChannelMockTest, TransTdcPackFastData001, TestSize.Level1)
{
    char *ret = TransTdcPackFastData(nullptr, nullptr);
    EXPECT_EQ(nullptr, ret);
}

/*
 * @tc.name: JsonObjectPackRequestEx001
 * @tc.desc: JsonObjectPackRequestEx001 test
 *           use the wrong parameter or normal parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusMessageOpenChannelMockTest, JsonObjectPackRequestEx001, TestSize.Level3)
{
    OHOS::SoftbusMessageOpenChannelInterfaceMock softbusMOpenChannelMock;
    EXPECT_CALL(softbusMOpenChannelMock, AddNumberToJsonObject).WillRepeatedly(Return(false));
    EXPECT_CALL(softbusMOpenChannelMock, AddStringToJsonObject).WillRepeatedly(Return(false));
    int32_t ret = JsonObjectPackRequestEx(nullptr, nullptr, nullptr);
    EXPECT_EQ(SOFTBUS_CREATE_JSON_ERR, ret);
}

/*
 * @tc.name: ParseMessageToAppInfo001
 * @tc.desc: ParseMessageToAppInfo001 test
 *           use the wrong parameter or normal parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusMessageOpenChannelMockTest, ParseMessageToAppInfo001, TestSize.Level3)
{
    AppInfo *appInfo = reinterpret_cast<AppInfo *>(SoftBusMalloc(sizeof(AppInfo)));
    ASSERT_NE(nullptr, appInfo);
    (void)memset_s(appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    OHOS::SoftbusMessageOpenChannelInterfaceMock softbusMOpenChannelMock;
    EXPECT_CALL(softbusMOpenChannelMock, GetJsonObjectStringItem).WillRepeatedly(Return(false));
    int32_t ret = ParseMessageToAppInfo(nullptr, nullptr);
    EXPECT_EQ(SOFTBUS_PARSE_JSON_ERR, ret);

    if (appInfo != nullptr) {
        SoftBusFree(appInfo);
    }
}

/*
 * @tc.name: ParseMessageToAppInfo002
 * @tc.desc: ParseMessageToAppInfo002 test
 *           use the wrong parameter or normal parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusMessageOpenChannelMockTest, ParseMessageToAppInfo002, TestSize.Level3)
{
    cJSON msg = {0};
    AppInfo *appInfo = reinterpret_cast<AppInfo *>(SoftBusMalloc(sizeof(AppInfo)));
    ASSERT_NE(nullptr, appInfo);
    (void)memset_s(appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    OHOS::SoftbusMessageOpenChannelInterfaceMock softbusMOpenChannelMock;
    EXPECT_CALL(softbusMOpenChannelMock, GetJsonObjectStringItem).WillRepeatedly(Return(true));
    EXPECT_CALL(softbusMOpenChannelMock, GetJsonObjectNumberItem).WillRepeatedly(Return(false));
    EXPECT_CALL(softbusMOpenChannelMock, GetJsonObjectInt32Item).WillRepeatedly(Return(false));
    int32_t ret = ParseMessageToAppInfo(&msg, appInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);

    if (appInfo != nullptr) {
        SoftBusFree(appInfo);
    }
}

/*
 * @tc.name: PackExternalDeviceRequest001
 * @tc.desc: PackExternalDeviceRequest test
 *           use the wrong parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusMessageOpenChannelMockTest, PackExternalDeviceRequest001, TestSize.Level1)
{
    EXPECT_EQ(PackExternalDeviceRequest(nullptr, 321), nullptr);
}

/*
 * @tc.name: PackExternalDeviceRequest002
 * @tc.desc: PackExternalDeviceRequest test
 *           use the wrong parameter or normal parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusMessageOpenChannelMockTest, PackExternalDeviceRequest002, TestSize.Level1)
{
    AppInfo appInfo;
    OHOS::SoftbusMessageOpenChannelInterfaceMock softbusMOpenChannelMock;
    EXPECT_CALL(softbusMOpenChannelMock, cJSON_CreateObject).WillOnce(Return(nullptr));

    char *ret = PackExternalDeviceRequest(&appInfo, 123);
    EXPECT_EQ(ret, nullptr);
}

/*
 * @tc.name: PackExternalDeviceRequest003
 * @tc.desc: PackExternalDeviceRequest test
 *           use the wrong parameter or normal parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusMessageOpenChannelMockTest, PackExternalDeviceRequest003, TestSize.Level1)
{
    AppInfo appInfo;
    appInfo.metaType = META_HA;
    cJSON *json = static_cast<cJSON *>(SoftBusCalloc(sizeof(cJSON)));
    ASSERT_TRUE(json != nullptr);

    OHOS::SoftbusMessageOpenChannelInterfaceMock softbusMOpenChannelMock;
    EXPECT_CALL(softbusMOpenChannelMock, cJSON_CreateObject).WillOnce(Return(json));
    EXPECT_CALL(softbusMOpenChannelMock, SoftBusBase64Encode).WillOnce(Return(SOFTBUS_INVALID_PARAM));

    char *ret = PackExternalDeviceRequest(&appInfo, 123);
    EXPECT_EQ(ret, nullptr);
}

/*
 * @tc.name: PackExternalDeviceRequest004
 * @tc.desc: PackExternalDeviceRequest test
 *           use the wrong parameter or normal parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusMessageOpenChannelMockTest, PackExternalDeviceRequest004, TestSize.Level1)
{
    AppInfo appInfo;
    appInfo.metaType = META_HA;
    cJSON *json = static_cast<cJSON *>(SoftBusCalloc(sizeof(cJSON)));
    ASSERT_TRUE(json != nullptr);
    unsigned char encodeSessionKey[] = "123";

    OHOS::SoftbusMessageOpenChannelInterfaceMock softbusMOpenChannelMock;
    EXPECT_CALL(softbusMOpenChannelMock, cJSON_CreateObject).WillOnce(Return(json));
    EXPECT_CALL(softbusMOpenChannelMock, SoftBusBase64Encode)
        .WillOnce(DoAll(SetArrayArgument<0>(encodeSessionKey, encodeSessionKey + 3), Return(SOFTBUS_OK)));
    EXPECT_CALL(softbusMOpenChannelMock, AddNumberToJsonObject).WillOnce(Return(false));

    char *ret = PackExternalDeviceRequest(&appInfo, 123);
    EXPECT_EQ(ret, nullptr);
}

/*
 * @tc.name: PackExternalDeviceRequest005
 * @tc.desc: PackExternalDeviceRequest test
 *           use the wrong parameter or normal parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusMessageOpenChannelMockTest, PackExternalDeviceRequest005, TestSize.Level1)
{
    AppInfo appInfo;
    appInfo.metaType = META_HA;
    appInfo.myData.apiVersion = API_V2;
    unsigned char encodeSessionKey[] = "123";
    cJSON *json = static_cast<cJSON *>(SoftBusCalloc(sizeof(cJSON)));
    ASSERT_TRUE(json != nullptr);

    OHOS::SoftbusMessageOpenChannelInterfaceMock softbusMOpenChannelMock;
    EXPECT_CALL(softbusMOpenChannelMock, cJSON_CreateObject).WillOnce(Return(json));
    EXPECT_CALL(softbusMOpenChannelMock, SoftBusBase64Encode)
        .WillRepeatedly(DoAll(SetArrayArgument<0>(encodeSessionKey, encodeSessionKey + 3), Return(SOFTBUS_OK)));
    EXPECT_CALL(softbusMOpenChannelMock, AddNumberToJsonObject).WillRepeatedly(Return(true));
    EXPECT_CALL(softbusMOpenChannelMock, AddStringToJsonObject).WillRepeatedly(Return(true));
    EXPECT_CALL(softbusMOpenChannelMock, cJSON_PrintUnformatted).WillOnce(Return(nullptr));

    char *ret = PackExternalDeviceRequest(&appInfo, 123);
    EXPECT_EQ(ret, nullptr);

    char data[] = "test_data";
    cJSON *jsonTest = static_cast<cJSON *>(SoftBusCalloc(sizeof(cJSON)));
    ASSERT_TRUE(jsonTest != nullptr);
    EXPECT_CALL(softbusMOpenChannelMock, cJSON_CreateObject).WillOnce(Return(jsonTest));
    EXPECT_CALL(softbusMOpenChannelMock, cJSON_PrintUnformatted).WillOnce(Return(data));

    ret = PackExternalDeviceRequest(&appInfo, 123);
    EXPECT_STREQ(ret, data);
}

/*
 * @tc.name: PackExternalDeviceJsonObiect001
 * @tc.desc: PackExternalDeviceJsonObject test
 *           use the wrong parameter or normal parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusMessageOpenChannelMockTest, PackExternalDeviceJsonObiect001, TestSize.Level1)
{
    AppInfo appInfo;
    cJSON json = { 0 };
    unsigned char *encodeSessionKey = reinterpret_cast<unsigned char *>(const_cast<char *>("testEncodeSessionKey"));

    OHOS::SoftbusMessageOpenChannelInterfaceMock softbusMOpenChannelMock;
    EXPECT_CALL(softbusMOpenChannelMock, AddNumberToJsonObject).WillOnce(Return(false));
    int32_t ret = PackExternalDeviceJsonObject(&appInfo, &json, encodeSessionKey);
    EXPECT_EQ(ret, SOFTBUS_CREATE_JSON_ERR);

    EXPECT_CALL(softbusMOpenChannelMock, AddNumberToJsonObject)
        .Times(2)
        .WillOnce(Return(true))
        .WillOnce(Return(false));
    ret = PackExternalDeviceJsonObject(&appInfo, &json, encodeSessionKey);
    EXPECT_EQ(ret, SOFTBUS_CREATE_JSON_ERR);
}

/*
 * @tc.name: PackExternalDeviceJsonObiect002
 * @tc.desc: PackExternalDeviceJsonObject test
 *           use the wrong parameter or normal parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusMessageOpenChannelMockTest, PackExternalDeviceJsonObiect002, TestSize.Level1)
{
    AppInfo appInfo;
    cJSON json = { 0 };
    unsigned char *encodeSessionKey = reinterpret_cast<unsigned char *>(const_cast<char *>("testEncodeSessionKey"));

    OHOS::SoftbusMessageOpenChannelInterfaceMock softbusMOpenChannelMock;
    EXPECT_CALL(softbusMOpenChannelMock, AddNumberToJsonObject).WillRepeatedly(Return(true));
    EXPECT_CALL(softbusMOpenChannelMock, AddStringToJsonObject).WillOnce(Return(false));
    int32_t ret = PackExternalDeviceJsonObject(&appInfo, &json, encodeSessionKey);
    EXPECT_EQ(ret, SOFTBUS_CREATE_JSON_ERR);
}

/*
 * @tc.name: PackExternalDeviceJsonObiect003
 * @tc.desc: PackExternalDeviceJsonObject test
 *           use the wrong parameter or normal parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusMessageOpenChannelMockTest, PackExternalDeviceJsonObiect003, TestSize.Level1)
{
    AppInfo appInfo;
    cJSON json = { 0 };
    unsigned char *encodeSessionKey = reinterpret_cast<unsigned char *>(const_cast<char *>("testEncodeSessionKey"));

    OHOS::SoftbusMessageOpenChannelInterfaceMock softbusMOpenChannelMock;
    EXPECT_CALL(softbusMOpenChannelMock, AddNumberToJsonObject).WillRepeatedly(Return(true));
    EXPECT_CALL(softbusMOpenChannelMock, AddStringToJsonObject)
        .Times(2)
        .WillOnce(Return(true))
        .WillOnce(Return(false));
    int32_t ret = PackExternalDeviceJsonObject(&appInfo, &json, encodeSessionKey);
    EXPECT_EQ(ret, SOFTBUS_CREATE_JSON_ERR);
}

/*
 * @tc.name: PackExternalDeviceJsonObiect004
 * @tc.desc: PackExternalDeviceJsonObject test
 *           use the wrong parameter or normal parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusMessageOpenChannelMockTest, PackExternalDeviceJsonObiect004, TestSize.Level1)
{
    AppInfo appInfo;
    cJSON json = { 0 };
    unsigned char *encodeSessionKey = reinterpret_cast<unsigned char *>(const_cast<char *>("testEncodeSessionKey"));

    OHOS::SoftbusMessageOpenChannelInterfaceMock softbusMOpenChannelMock;
    EXPECT_CALL(softbusMOpenChannelMock, AddNumberToJsonObject).WillRepeatedly(Return(true));
    EXPECT_CALL(softbusMOpenChannelMock, AddStringToJsonObject).WillRepeatedly(Return(true));
    EXPECT_CALL(softbusMOpenChannelMock, AddNumberToJsonObject).WillOnce(Return(false));
    int32_t ret = PackExternalDeviceJsonObject(&appInfo, &json, encodeSessionKey);
    EXPECT_EQ(ret, SOFTBUS_CREATE_JSON_ERR);
}

/*
 * @tc.name: PackExternalDeviceJsonObiect005
 * @tc.desc: PackExternalDeviceJsonObject test
 *           use the wrong parameter or normal parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusMessageOpenChannelMockTest, PackExternalDeviceJsonObiect005, TestSize.Level1)
{
    AppInfo appInfo;
    cJSON json = { 0 };
    unsigned char *encodeSessionKey = reinterpret_cast<unsigned char *>(const_cast<char *>("testEncodeSessionKey"));

    OHOS::SoftbusMessageOpenChannelInterfaceMock softbusMOpenChannelMock;
    EXPECT_CALL(softbusMOpenChannelMock, AddNumberToJsonObject).WillRepeatedly(Return(true));
    EXPECT_CALL(softbusMOpenChannelMock, AddStringToJsonObject).WillRepeatedly(Return(true));
    EXPECT_CALL(softbusMOpenChannelMock, AddNumberToJsonObject)
        .Times(2)
        .WillOnce(Return(true))
        .WillOnce(Return(false));
    int32_t ret = PackExternalDeviceJsonObject(&appInfo, &json, encodeSessionKey);
    EXPECT_EQ(ret, SOFTBUS_CREATE_JSON_ERR);
}

/*
 * @tc.name: PackExternalDeviceJsonObiect006
 * @tc.desc: PackExternalDeviceJsonObject test
 *           use the wrong parameter or normal parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusMessageOpenChannelMockTest, PackExternalDeviceJsonObiect006, TestSize.Level1)
{
    AppInfo appInfo;
    appInfo.myData.apiVersion = API_V2;
    cJSON json = { 0 };
    unsigned char *encodeSessionKey = reinterpret_cast<unsigned char *>(const_cast<char *>("testEncodeSessionKey"));

    OHOS::SoftbusMessageOpenChannelInterfaceMock softbusMOpenChannelMock;
    EXPECT_CALL(softbusMOpenChannelMock, AddNumberToJsonObject).WillRepeatedly(Return(true));
    EXPECT_CALL(softbusMOpenChannelMock, AddStringToJsonObject).WillRepeatedly(Return(true));
    EXPECT_CALL(softbusMOpenChannelMock, AddStringToJsonObject).WillOnce(Return(false));
    int32_t ret = PackExternalDeviceJsonObject(&appInfo, &json, encodeSessionKey);
    EXPECT_EQ(ret, SOFTBUS_CREATE_JSON_ERR);
}

/*
 * @tc.name: PackExternalDeviceJsonObiect007
 * @tc.desc: PackExternalDeviceJsonObject test
 *           use the wrong parameter or normal parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusMessageOpenChannelMockTest, PackExternalDeviceJsonObiect007, TestSize.Level1)
{
    AppInfo appInfo;
    appInfo.myData.apiVersion = API_V2;
    cJSON json = { 0 };
    unsigned char *encodeSessionKey = reinterpret_cast<unsigned char *>(const_cast<char *>("testEncodeSessionKey"));

    OHOS::SoftbusMessageOpenChannelInterfaceMock softbusMOpenChannelMock;
    EXPECT_CALL(softbusMOpenChannelMock, AddNumberToJsonObject).WillRepeatedly(Return(true));
    EXPECT_CALL(softbusMOpenChannelMock, AddStringToJsonObject).WillRepeatedly(Return(true));
    EXPECT_CALL(softbusMOpenChannelMock, AddStringToJsonObject)
        .Times(2)
        .WillOnce(Return(true))
        .WillOnce(Return(false));
    int32_t ret = PackExternalDeviceJsonObject(&appInfo, &json, encodeSessionKey);
    EXPECT_EQ(ret, SOFTBUS_CREATE_JSON_ERR);

    EXPECT_CALL(softbusMOpenChannelMock, AddStringToJsonObject).WillRepeatedly(Return(true));
    EXPECT_CALL(softbusMOpenChannelMock, AddNumberToJsonObject).WillOnce(Return(false));
    ret = PackExternalDeviceJsonObject(&appInfo, &json, encodeSessionKey);
    EXPECT_EQ(ret, SOFTBUS_CREATE_JSON_ERR);
}

/*
 * @tc.name: PackExternalDeviceJsonObiect008
 * @tc.desc: PackExternalDeviceJsonObject test
 *           use the wrong parameter or normal parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusMessageOpenChannelMockTest, PackExternalDeviceJsonObiect008, TestSize.Level1)
{
    AppInfo appInfo;
    appInfo.myData.apiVersion = API_V1;
    cJSON json = { 0 };
    unsigned char *encodeSessionKey = reinterpret_cast<unsigned char *>(const_cast<char *>("testEncodeSessionKey"));

    OHOS::SoftbusMessageOpenChannelInterfaceMock softbusMOpenChannelMock;
    EXPECT_CALL(softbusMOpenChannelMock, AddNumberToJsonObject).WillRepeatedly(Return(true));
    EXPECT_CALL(softbusMOpenChannelMock, AddStringToJsonObject).WillRepeatedly(Return(true));

    int32_t ret = PackExternalDeviceJsonObject(&appInfo, &json, encodeSessionKey);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: PackExternalDeviceJsonObiect009
 * @tc.desc: PackExternalDeviceJsonObject test
 *           use the wrong parameter or normal parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusMessageOpenChannelMockTest, PackExternalDeviceJsonObiect009, TestSize.Level1)
{
    AppInfo appInfo;
    cJSON json = { 0 };
    unsigned char *encodeSessionKey = reinterpret_cast<unsigned char *>(const_cast<char *>("testEncodeSessionKey"));

    OHOS::SoftbusMessageOpenChannelInterfaceMock softbusMOpenChannelMock;
    EXPECT_CALL(softbusMOpenChannelMock, AddNumberToJsonObject)
        .WillOnce(Return(true))
        .WillOnce(Return(true))
        .WillOnce(Return(true))
        .WillOnce(Return(false));
    EXPECT_CALL(softbusMOpenChannelMock, AddStringToJsonObject).WillRepeatedly(Return(true));
    int32_t ret = PackExternalDeviceJsonObject(&appInfo, &json, encodeSessionKey);
    EXPECT_EQ(ret, SOFTBUS_CREATE_JSON_ERR);
}

/*
 * @tc.name: PackExternalDeviceJsonObiect010
 * @tc.desc: PackExternalDeviceJsonObject test
 *           use the wrong parameter or normal parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusMessageOpenChannelMockTest, PackExternalDeviceJsonObiect010, TestSize.Level1)
{
    AppInfo appInfo;
    cJSON json = { 0 };
    unsigned char *encodeSessionKey = reinterpret_cast<unsigned char *>(const_cast<char *>("testEncodeSessionKey"));

    OHOS::SoftbusMessageOpenChannelInterfaceMock softbusMOpenChannelMock;
    EXPECT_CALL(softbusMOpenChannelMock, AddNumberToJsonObject)
        .WillOnce(Return(true))
        .WillOnce(Return(true))
        .WillOnce(Return(true))
        .WillOnce(Return(true));
    EXPECT_CALL(softbusMOpenChannelMock, AddStringToJsonObject)
        .WillOnce(Return(true))
        .WillOnce(Return(true))
        .WillOnce(Return(false));
    int32_t ret = PackExternalDeviceJsonObject(&appInfo, &json, encodeSessionKey);
    EXPECT_EQ(ret, SOFTBUS_CREATE_JSON_ERR);
}

/*
 * @tc.name: UnpackExternalDeviceRequest001
 * @tc.desc: UnpackExternalDeviceRequest test
 *           use the wrong parameter or normal parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusMessageOpenChannelMockTest, UnpackExternalDeviceRequest001, TestSize.Level1)
{
    cJSON msg;
    AppInfo appInfo;
    int32_t ret = UnpackExternalDeviceRequest(nullptr, &appInfo);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = UnpackExternalDeviceRequest(&msg, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    OHOS::SoftbusMessageOpenChannelInterfaceMock softbusMOpenChannelMock;
    EXPECT_CALL(softbusMOpenChannelMock, GetJsonObjectNumberItem).WillOnce(Return(true));
    EXPECT_CALL(softbusMOpenChannelMock, GetJsonObjectStringItem).WillOnce(Return(false));
    ret = UnpackExternalDeviceRequest(&msg, &appInfo);
    EXPECT_EQ(ret, SOFTBUS_PARSE_JSON_ERR);
}

/*
 * @tc.name: UnpackExternalDeviceRequest002
 * @tc.desc: UnpackExternalDeviceRequest test
 *           use the wrong parameter or normal parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusMessageOpenChannelMockTest, UnpackExternalDeviceRequest002, TestSize.Level1)
{
    cJSON msg;
    AppInfo appInfo;

    OHOS::SoftbusMessageOpenChannelInterfaceMock softbusMOpenChannelMock;
    EXPECT_CALL(softbusMOpenChannelMock, GetJsonObjectNumberItem)
        .Times(2)
        .WillOnce(Return(true))
        .WillOnce(Return(false));
    EXPECT_CALL(softbusMOpenChannelMock, GetJsonObjectStringItem).WillOnce(Return(true));
    int32_t ret = UnpackExternalDeviceRequest(&msg, &appInfo);
    EXPECT_EQ(ret, SOFTBUS_PARSE_JSON_ERR);
}

/*
 * @tc.name: UnpackExternalDeviceRequest003
 * @tc.desc: UnpackExternalDeviceRequest test
 *           use the wrong parameter or normal parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusMessageOpenChannelMockTest, UnpackExternalDeviceRequest003, TestSize.Level1)
{
    cJSON msg;
    AppInfo appInfo;

    OHOS::SoftbusMessageOpenChannelInterfaceMock softbusMOpenChannelMock;
    EXPECT_CALL(softbusMOpenChannelMock, GetJsonObjectNumberItem).WillRepeatedly(Return(true));
    EXPECT_CALL(softbusMOpenChannelMock, GetJsonObjectStringItem)
        .Times(2)
        .WillOnce(Return(true))
        .WillOnce(Return(false));
    int32_t ret = UnpackExternalDeviceRequest(&msg, &appInfo);
    EXPECT_EQ(ret, SOFTBUS_PARSE_JSON_ERR);
}

/*
 * @tc.name: UnpackExternalDeviceRequest004
 * @tc.desc: UnpackExternalDeviceRequest test
 *           use the wrong parameter or normal parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusMessageOpenChannelMockTest, UnpackExternalDeviceRequest004, TestSize.Level1)
{
    cJSON msg;
    AppInfo appInfo;

    OHOS::SoftbusMessageOpenChannelInterfaceMock softbusMOpenChannelMock;
    EXPECT_CALL(softbusMOpenChannelMock, GetJsonObjectNumberItem).WillRepeatedly(Return(true));
    EXPECT_CALL(softbusMOpenChannelMock, GetJsonObjectStringItem).WillRepeatedly(Return(true));
    EXPECT_CALL(softbusMOpenChannelMock, GetJsonObjectStringItem).WillOnce(Return(false));
    int32_t ret = UnpackExternalDeviceRequest(&msg, &appInfo);
    EXPECT_EQ(ret, SOFTBUS_PARSE_JSON_ERR);
}

/*
 * @tc.name: UnpackExternalDeviceRequest005
 * @tc.desc: UnpackExternalDeviceRequest test
 *           use the wrong parameter or normal parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusMessageOpenChannelMockTest, UnpackExternalDeviceRequest005, TestSize.Level1)
{
    cJSON msg;
    AppInfo appInfo;

    OHOS::SoftbusMessageOpenChannelInterfaceMock softbusMOpenChannelMock;
    EXPECT_CALL(softbusMOpenChannelMock, GetJsonObjectNumberItem).WillRepeatedly(Return(true));
    EXPECT_CALL(softbusMOpenChannelMock, GetJsonObjectStringItem).WillRepeatedly(Return(true));
    EXPECT_CALL(softbusMOpenChannelMock, GetJsonObjectNumberItem)
        .Times(2)
        .WillOnce(Return(true))
        .WillOnce(Return(false));
    int32_t ret = UnpackExternalDeviceRequest(&msg, &appInfo);
    EXPECT_EQ(ret, SOFTBUS_PARSE_JSON_ERR);
}

/*
 * @tc.name: UnpackExternalDeviceRequest006
 * @tc.desc: UnpackExternalDeviceRequest test
 *           use the wrong parameter or normal parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusMessageOpenChannelMockTest, UnpackExternalDeviceRequest006, TestSize.Level1)
{
    cJSON msg;
    AppInfo appInfo;
    size_t len = 2;
    unsigned char sessionKey[] = "test.sessionkey";

    OHOS::SoftbusMessageOpenChannelInterfaceMock softbusMOpenChannelMock;
    EXPECT_CALL(softbusMOpenChannelMock, GetJsonObjectNumberItem).WillRepeatedly(Return(true));
    EXPECT_CALL(softbusMOpenChannelMock, GetJsonObjectStringItem).WillRepeatedly(Return(true));
    EXPECT_CALL(softbusMOpenChannelMock, GetJsonObjectStringItem)
        .WillRepeatedly(DoAll(SetArrayArgument<2>(sessionKey, sessionKey + 32), Return(true)));
    EXPECT_CALL(softbusMOpenChannelMock, SoftBusBase64Decode)
        .WillOnce(DoAll(SetArgPointee<2>(len), Return(SOFTBUS_OK)));
    int32_t ret = UnpackExternalDeviceRequest(&msg, &appInfo);
    EXPECT_EQ(ret, SOFTBUS_PARSE_JSON_ERR);
}

/*
 * @tc.name: UnpackExternalDeviceRequest007
 * @tc.desc: UnpackExternalDeviceRequest test
 *           use the wrong parameter or normal parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusMessageOpenChannelMockTest, UnpackExternalDeviceRequest007, TestSize.Level1)
{
    cJSON msg;
    AppInfo appInfo;
    size_t len = 32;
    unsigned char sessionKey[] = "test.sessionkey";

    OHOS::SoftbusMessageOpenChannelInterfaceMock softbusMOpenChannelMock;
    EXPECT_CALL(softbusMOpenChannelMock, GetJsonObjectNumberItem).WillRepeatedly(Return(true));
    EXPECT_CALL(softbusMOpenChannelMock, GetJsonObjectStringItem).WillRepeatedly(Return(true));
    EXPECT_CALL(softbusMOpenChannelMock, GetJsonObjectStringItem)
        .WillRepeatedly(DoAll(SetArrayArgument<2>(sessionKey, sessionKey + 32), Return(true)));
    EXPECT_CALL(softbusMOpenChannelMock, SoftBusBase64Decode)
        .WillOnce(DoAll(SetArgPointee<2>(len), Return(SOFTBUS_OK)));

    int32_t ret = UnpackExternalDeviceRequest(&msg, &appInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: PackExternalDeviceReply001
 * @tc.desc: PackExternalDeviceReply test
 *           use the wrong parameter or normal parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusMessageOpenChannelMockTest, PackExternalDeviceReply001, TestSize.Level1)
{
    EXPECT_EQ(PackExternalDeviceReply(nullptr), nullptr);

    OHOS::SoftbusMessageOpenChannelInterfaceMock softbusMOpenChannelMock;
    EXPECT_CALL(softbusMOpenChannelMock, cJSON_CreateObject).WillOnce(Return(nullptr));

    AppInfo appInfo;
    char *ret = PackExternalDeviceReply(&appInfo);
    EXPECT_EQ(ret, nullptr);
}

/*
 * @tc.name: PackExternalDeviceReply002
 * @tc.desc: PackExternalDeviceReply test
 *           use the wrong parameter or normal parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusMessageOpenChannelMockTest, PackExternalDeviceReply002, TestSize.Level1)
{
    AppInfo appInfo;
    cJSON *json = static_cast<cJSON *>(SoftBusCalloc(sizeof(cJSON)));
    ASSERT_TRUE(json != nullptr);

    OHOS::SoftbusMessageOpenChannelInterfaceMock softbusMOpenChannelMock;
    EXPECT_CALL(softbusMOpenChannelMock, cJSON_CreateObject).WillOnce(Return(json));
    EXPECT_CALL(softbusMOpenChannelMock, AddNumberToJsonObject).WillOnce(Return(false));
    char *ret = PackExternalDeviceReply(&appInfo);
    EXPECT_EQ(ret, nullptr);

    cJSON *json1 = static_cast<cJSON *>(SoftBusCalloc(sizeof(cJSON)));
    ASSERT_TRUE(json != nullptr);
    EXPECT_CALL(softbusMOpenChannelMock, cJSON_CreateObject).WillOnce(Return(json1));
    EXPECT_CALL(softbusMOpenChannelMock, AddNumberToJsonObject)
        .Times(2)
        .WillOnce(Return(true))
        .WillOnce(Return(false));
    ret = PackExternalDeviceReply(&appInfo);
    EXPECT_EQ(ret, nullptr);

    cJSON *json2 = static_cast<cJSON *>(SoftBusCalloc(sizeof(cJSON)));
    ASSERT_TRUE(json != nullptr);
    EXPECT_CALL(softbusMOpenChannelMock, cJSON_CreateObject).WillOnce(Return(json2));
    EXPECT_CALL(softbusMOpenChannelMock, AddNumberToJsonObject).Times(2).WillRepeatedly(Return(true));
    EXPECT_CALL(softbusMOpenChannelMock, AddStringToJsonObject).WillOnce(Return(false));
    ret = PackExternalDeviceReply(&appInfo);
    EXPECT_EQ(ret, nullptr);
}

/*
 * @tc.name: PackExternalDeviceReply003
 * @tc.desc: PackExternalDeviceReply test
 *           use the wrong parameter or normal parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusMessageOpenChannelMockTest, PackExternalDeviceReply003, TestSize.Level1)
{
    AppInfo appInfo;
    cJSON *json = static_cast<cJSON *>(SoftBusCalloc(sizeof(cJSON)));
    ASSERT_TRUE(json != nullptr);

    OHOS::SoftbusMessageOpenChannelInterfaceMock softbusMOpenChannelMock;
    EXPECT_CALL(softbusMOpenChannelMock, cJSON_CreateObject).WillOnce(Return(json));
    EXPECT_CALL(softbusMOpenChannelMock, AddNumberToJsonObject).WillRepeatedly(Return(true));
    EXPECT_CALL(softbusMOpenChannelMock, AddStringToJsonObject).WillRepeatedly(Return(true));
    EXPECT_CALL(softbusMOpenChannelMock, AddNumberToJsonObject).WillOnce(Return(false));
    char *ret = PackExternalDeviceReply(&appInfo);
    EXPECT_EQ(ret, nullptr);
}

/*
 * @tc.name: PackExternalDeviceReply004
 * @tc.desc: PackExternalDeviceReply test
 *           use the wrong parameter or normal parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusMessageOpenChannelMockTest, PackExternalDeviceReply004, TestSize.Level1)
{
    AppInfo appInfo;
    cJSON *json = static_cast<cJSON *>(SoftBusCalloc(sizeof(cJSON)));
    ASSERT_TRUE(json != nullptr);

    OHOS::SoftbusMessageOpenChannelInterfaceMock softbusMOpenChannelMock;
    EXPECT_CALL(softbusMOpenChannelMock, cJSON_CreateObject).WillOnce(Return(json));
    EXPECT_CALL(softbusMOpenChannelMock, AddNumberToJsonObject).WillRepeatedly(Return(true));
    EXPECT_CALL(softbusMOpenChannelMock, AddStringToJsonObject).WillRepeatedly(Return(true));
    EXPECT_CALL(softbusMOpenChannelMock, AddNumberToJsonObject)
        .Times(2)
        .WillOnce(Return(true))
        .WillOnce(Return(false));
    char *ret = PackExternalDeviceReply(&appInfo);
    EXPECT_EQ(ret, nullptr);
}

/*
 * @tc.name: PackExternalDeviceReply005
 * @tc.desc: PackExternalDeviceReply test
 *           use the wrong parameter or normal parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusMessageOpenChannelMockTest, PackExternalDeviceReply005, TestSize.Level1)
{
    AppInfo appInfo;
    cJSON *json = static_cast<cJSON *>(SoftBusCalloc(sizeof(cJSON)));
    ASSERT_TRUE(json != nullptr);

    OHOS::SoftbusMessageOpenChannelInterfaceMock softbusMOpenChannelMock;
    EXPECT_CALL(softbusMOpenChannelMock, cJSON_CreateObject).WillOnce(Return(json));
    EXPECT_CALL(softbusMOpenChannelMock, AddNumberToJsonObject).WillRepeatedly(Return(true));
    EXPECT_CALL(softbusMOpenChannelMock, AddStringToJsonObject)
        .Times(2)
        .WillOnce(Return(true))
        .WillOnce(Return(false));
    char *ret = PackExternalDeviceReply(&appInfo);
    EXPECT_EQ(ret, nullptr);
}

/*
 * @tc.name: PackExternalDeviceReply006
 * @tc.desc: PackExternalDeviceReply test
 *           use the wrong parameter or normal parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusMessageOpenChannelMockTest, PackExternalDeviceReply006, TestSize.Level1)
{
    AppInfo appInfo;
    cJSON *json = static_cast<cJSON *>(SoftBusCalloc(sizeof(cJSON)));
    ASSERT_TRUE(json != nullptr);

    OHOS::SoftbusMessageOpenChannelInterfaceMock softbusMOpenChannelMock;
    EXPECT_CALL(softbusMOpenChannelMock, cJSON_CreateObject).WillOnce(Return(json));
    EXPECT_CALL(softbusMOpenChannelMock, AddNumberToJsonObject).WillRepeatedly(Return(true));
    EXPECT_CALL(softbusMOpenChannelMock, AddStringToJsonObject).WillRepeatedly(Return(true));
    EXPECT_CALL(softbusMOpenChannelMock, cJSON_PrintUnformatted).WillOnce(Return(nullptr));
    char *ret = PackExternalDeviceReply(&appInfo);
    EXPECT_EQ(ret, nullptr);

    char data[] = "test_data";
    cJSON *json1 = static_cast<cJSON *>(SoftBusCalloc(sizeof(cJSON)));
    ASSERT_TRUE(json != nullptr);

    EXPECT_CALL(softbusMOpenChannelMock, cJSON_CreateObject).WillOnce(Return(json1));
    EXPECT_CALL(softbusMOpenChannelMock, cJSON_PrintUnformatted).WillOnce(Return(data));
    ret = PackExternalDeviceReply(&appInfo);
    EXPECT_STREQ(ret, data);
}

/*
 * @tc.name: UnpackExternalDeviceReply001
 * @tc.desc: UnpackExternalDeviceReply test
 *           use the wrong parameter or normal parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusMessageOpenChannelMockTest, UnpackExternalDeviceReply001, TestSize.Level1)
{
    AppInfo *appInfo = static_cast<AppInfo *>(SoftBusCalloc(sizeof(AppInfo)));
    ASSERT_TRUE(appInfo != nullptr);
    int32_t ret = UnpackExternalDeviceReply(nullptr, appInfo);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    cJSON cjson;
    ret = UnpackExternalDeviceReply(&cjson, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    OHOS::SoftbusMessageOpenChannelInterfaceMock softbusMOpenChannelMock;
    EXPECT_CALL(softbusMOpenChannelMock, GetJsonObjectNumberItem).WillOnce(Return(true));
    EXPECT_CALL(softbusMOpenChannelMock, GetJsonObjectStringItem).WillOnce(Return(false));
    ret = UnpackExternalDeviceReply(&cjson, appInfo);
    EXPECT_EQ(ret, SOFTBUS_PARSE_JSON_ERR);

    char uuid[] = "test_uuid";
    EXPECT_CALL(softbusMOpenChannelMock, GetJsonObjectStringItem)
        .WillOnce(DoAll(SetArrayArgument<2>(uuid, uuid + 12), Return(true)));
    EXPECT_CALL(softbusMOpenChannelMock, GetJsonObjectNumberItem).Times(3).WillRepeatedly(Return(false));
    ret = UnpackExternalDeviceReply(&cjson, appInfo);
    EXPECT_EQ(ret, SOFTBUS_PARSE_JSON_ERR);
    SoftBusFree(appInfo);
}

/*
 * @tc.name: UnpackExternalDeviceReply002
 * @tc.desc: UnpackExternalDeviceReply test
 *           use the wrong parameter or normal parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusMessageOpenChannelMockTest, UnpackExternalDeviceReply002, TestSize.Level1)
{
    cJSON cjson;
    AppInfo *appInfo = static_cast<AppInfo *>(SoftBusCalloc(sizeof(AppInfo)));
    ASSERT_TRUE(appInfo != nullptr);

    OHOS::SoftbusMessageOpenChannelInterfaceMock softbusMOpenChannelMock;
    EXPECT_CALL(softbusMOpenChannelMock, GetJsonObjectNumberItem).WillRepeatedly(Return(true));
    EXPECT_CALL(softbusMOpenChannelMock, GetJsonObjectStringItem)
        .Times(2)
        .WillOnce(Return(true))
        .WillOnce(Return(false));
    int32_t ret = UnpackExternalDeviceReply(&cjson, appInfo);
    EXPECT_EQ(ret, SOFTBUS_PARSE_JSON_ERR);
    SoftBusFree(appInfo);
}

/*
 * @tc.name: UnpackExternalDeviceReply003
 * @tc.desc: UnpackExternalDeviceReply test
 *           use the wrong parameter or normal parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusMessageOpenChannelMockTest, UnpackExternalDeviceReply003, TestSize.Level1)
{
    cJSON cjson;
    AppInfo *appInfo = static_cast<AppInfo *>(SoftBusCalloc(sizeof(AppInfo)));
    ASSERT_TRUE(appInfo != nullptr);

    OHOS::SoftbusMessageOpenChannelInterfaceMock softbusMOpenChannelMock;
    EXPECT_CALL(softbusMOpenChannelMock, GetJsonObjectNumberItem).WillRepeatedly(Return(true));
    EXPECT_CALL(softbusMOpenChannelMock, GetJsonObjectStringItem).WillRepeatedly(Return(true));
    int32_t ret = UnpackExternalDeviceReply(&cjson, appInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(appInfo);
}

/*
 * @tc.name: TransUnpackMetaTypeSpecificData001
 * @tc.desc: TransUnpackMetaTypeSpecificData test
 *           use the wrong parameter or normal parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusMessageOpenChannelMockTest, TransUnpackMetaTypeSpecificData001, TestSize.Level1)
{
    int32_t metaType = META_SDK;
    OHOS::SoftbusMessageOpenChannelInterfaceMock softbusMOpenChannelMock;
    EXPECT_CALL(softbusMOpenChannelMock, LnnGetRemoteNumInfo)
        .WillOnce(DoAll(SetArgPointee<2>(metaType), Return(SOFTBUS_OK)));
    EXPECT_CALL(softbusMOpenChannelMock, GetJsonObjectStringItem).WillOnce(Return(false));

    cJSON cjson;
    AppInfo *appInfo = static_cast<AppInfo *>(SoftBusCalloc(sizeof(AppInfo)));
    ASSERT_TRUE(appInfo != nullptr);
    int32_t ret = TransUnpackMetaTypeSpecificData(&cjson, appInfo);
    EXPECT_EQ(ret, SOFTBUS_PARSE_JSON_ERR);
    SoftBusFree(appInfo);
}

/*
 * @tc.name: TransTdcEncrypt001
 * @tc.desc: TransTdcEncrypt test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusMessageOpenChannelMockTest, TransTdcEncrypt001, TestSize.Level1)
{
    char sessionKey[SESSION_KEY_LENGTH] = { 0 };
    const char *inData = "inData";
    char outData[32];
    uint32_t outDataLen;
    (void)strcpy_s(sessionKey, SESSION_KEY_LENGTH, "test-sessionkey");

    OHOS::SoftbusMessageOpenChannelInterfaceMock softbusMOpenChannelMock;
    EXPECT_CALL(softbusMOpenChannelMock, SoftBusEncryptData).WillOnce(Return(SOFTBUS_ENCRYPT_ERR));
    int32_t ret = TransTdcEncrypt(sessionKey, inData, strlen(inData), outData, &outDataLen);
    EXPECT_EQ(ret, SOFTBUS_ENCRYPT_ERR);
}

/*
 * @tc.name: UnpackRequest001
 * @tc.desc: UnpackRequest test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusMessageOpenChannelMockTest, UnpackRequest001, TestSize.Level1)
{
    cJSON *msg = static_cast<cJSON *>(SoftBusCalloc(sizeof(cJSON)));
    ASSERT_TRUE(msg != nullptr);
    int32_t osType = HO_OS_TYPE;
    AppInfo appInfo = {
        .fastTransDataSize = 32
    };

    OHOS::SoftbusMessageOpenChannelInterfaceMock softbusMOpenChannelMock;
    EXPECT_CALL(softbusMOpenChannelMock, GetJsonObjectStringItem)
        .Times(2).WillRepeatedly(Return(false));
    EXPECT_CALL(softbusMOpenChannelMock, LnnGetNetworkIdByUuid).WillOnce(Return(0));
    EXPECT_CALL(softbusMOpenChannelMock, GetOsTypeByNetworkId)
        .WillOnce(DoAll(SetArgPointee<1>(osType), Return()));
    EXPECT_CALL(softbusMOpenChannelMock, GetJsonObjectNumber16Item).WillOnce(Return(true));

    int32_t ret = UnpackRequest(msg, &appInfo);
    EXPECT_EQ(ret, SOFTBUS_PARSE_JSON_ERR);
    SoftBusFree(msg);
}

/*
 * @tc.name: UnpackRequest002
 * @tc.desc: UnpackRequest test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusMessageOpenChannelMockTest, UnpackRequest002, TestSize.Level1)
{
    cJSON *msg = static_cast<cJSON *>(SoftBusCalloc(sizeof(cJSON)));
    ASSERT_TRUE(msg != nullptr);
    int32_t osType = OH_OS_TYPE;
    AppInfo appInfo;

    OHOS::SoftbusMessageOpenChannelInterfaceMock softbusMOpenChannelMock;
    EXPECT_CALL(softbusMOpenChannelMock, LnnGetNetworkIdByUuid).WillOnce(Return(false));
    EXPECT_CALL(softbusMOpenChannelMock, GetOsTypeByNetworkId).WillOnce(DoAll(SetArgPointee<1>(osType), Return()));
    EXPECT_CALL(softbusMOpenChannelMock, GetJsonObjectNumberItem).WillRepeatedly(Return(true));
    EXPECT_CALL(softbusMOpenChannelMock, GetJsonObjectStringItem).WillRepeatedly(Return(true));
    EXPECT_CALL(softbusMOpenChannelMock, GetJsonObjectNumber64Item).WillRepeatedly(Return(true));
    EXPECT_CALL(softbusMOpenChannelMock, GetJsonObjectBoolItem).WillOnce(Return(true));
    EXPECT_CALL(softbusMOpenChannelMock, GetJsonObjectInt32Item).WillRepeatedly(Return(true));

    int32_t ret = UnpackRequest(msg, &appInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(msg);
}

/*
 * @tc.name: UnpackRequest003
 * @tc.desc: UnpackRequest test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusMessageOpenChannelMockTest, UnpackRequest003, TestSize.Level1)
{
    cJSON *msg = static_cast<cJSON *>(SoftBusCalloc(sizeof(cJSON)));
    ASSERT_TRUE(msg != nullptr);
    int32_t osType = OH_OS_TYPE;
    int32_t apiVersion = API_V2;
    AppInfo appInfo;
    appInfo.fastTransData = const_cast<const uint8_t *>(static_cast<uint8_t *>(SoftBusCalloc(sizeof(uint8_t) * 32)));
    ASSERT_TRUE(appInfo.fastTransData != nullptr);

    OHOS::SoftbusMessageOpenChannelInterfaceMock softbusMOpenChannelMock;
    EXPECT_CALL(softbusMOpenChannelMock, LnnGetNetworkIdByUuid).WillOnce(Return(false));
    EXPECT_CALL(softbusMOpenChannelMock, GetOsTypeByNetworkId).WillOnce(DoAll(SetArgPointee<1>(osType), Return()));

    EXPECT_CALL(softbusMOpenChannelMock, GetJsonObjectNumberItem)
        .WillOnce(DoAll(SetArgPointee<2>(apiVersion), Return(true)));

    EXPECT_CALL(softbusMOpenChannelMock, GetJsonObjectStringItem).WillRepeatedly(Return(false));

    EXPECT_CALL(softbusMOpenChannelMock, GetJsonObjectNumber64Item).WillRepeatedly(Return(true));
    EXPECT_CALL(softbusMOpenChannelMock, GetJsonObjectBoolItem).WillRepeatedly(Return(true));
    EXPECT_CALL(softbusMOpenChannelMock, GetJsonObjectInt32Item).WillRepeatedly(Return(true));

    int32_t ret = UnpackRequest(msg, &appInfo);
    EXPECT_EQ(ret, SOFTBUS_PARSE_JSON_ERR);
    SoftBusFree(msg);
}

/*
 * @tc.name: UnpackRequest004
 * @tc.desc: UnpackRequest test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusMessageOpenChannelMockTest, UnpackRequest004, TestSize.Level1)
{
    cJSON *msg = static_cast<cJSON *>(SoftBusCalloc(sizeof(cJSON)));
    ASSERT_TRUE(msg != nullptr);
    int32_t osType = OH_OS_TYPE;
    int32_t apiVersion = API_V2;
    AppInfo appInfo;

    OHOS::SoftbusMessageOpenChannelInterfaceMock softbusMOpenChannelMock;
    EXPECT_CALL(softbusMOpenChannelMock, LnnGetNetworkIdByUuid).WillOnce(Return(true));
    EXPECT_CALL(softbusMOpenChannelMock, GetOsTypeByNetworkId).WillOnce(DoAll(SetArgPointee<1>(osType), Return()));
    EXPECT_CALL(softbusMOpenChannelMock, GetJsonObjectNumberItem)
        .WillOnce(DoAll(SetArgPointee<2>(apiVersion), Return(true)))
        .WillRepeatedly(Return(true));

    EXPECT_CALL(softbusMOpenChannelMock, GetJsonObjectStringItem).WillRepeatedly(Return(true));
    EXPECT_CALL(softbusMOpenChannelMock, GetJsonObjectNumber64Item).WillRepeatedly(Return(true));
    EXPECT_CALL(softbusMOpenChannelMock, GetJsonObjectBoolItem).WillRepeatedly(Return(true));
    EXPECT_CALL(softbusMOpenChannelMock, GetJsonObjectInt32Item).WillRepeatedly(Return(true));

    int32_t ret = UnpackRequest(msg, &appInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(msg);
}

/*
 * @tc.name: UnpackFirstData001
 * @tc.desc: UnpackFirstData test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusMessageOpenChannelMockTest, UnpackFirstData001, TestSize.Level1)
{
    int32_t osType = OH_OS_TYPE;

    OHOS::SoftbusMessageOpenChannelInterfaceMock softbusMOpenChannelMock;
    EXPECT_CALL(softbusMOpenChannelMock, LnnGetNetworkIdByUuid).WillOnce(Return(false));
    EXPECT_CALL(softbusMOpenChannelMock, GetOsTypeByNetworkId).WillOnce(DoAll(SetArgPointee<1>(osType), Return()));

    int32_t ret = UnpackFirstData(nullptr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_OK);
}
} // OHOS
