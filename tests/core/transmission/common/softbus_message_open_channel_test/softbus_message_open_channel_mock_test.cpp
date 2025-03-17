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


/**
 * @tc.name: PackError001
 * @tc.desc: PackError001, use the wrong parameter or normal parameter.
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

/**
 * @tc.name: PackError002
 * @tc.desc: PackError002, use the wrong parameter or normal parameter.
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

/**
 * @tc.name: PackError003
 * @tc.desc: PackError003, use the wrong parameter or normal parameter.
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

/**
 * @tc.name: PackRequest001
 * @tc.desc: PackRequest001, use the wrong parameter or normal parameter.
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
    char *ret = PackRequest(appInfo);
    EXPECT_EQ(nullptr, ret);

    if (appInfo != nullptr) {
        SoftBusFree(appInfo);
    }
}

/**
 * @tc.name: PackRequest002
 * @tc.desc: PackRequest002, use the wrong parameter or normal parameter.
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
    char *ret = PackRequest(appInfo);
    EXPECT_EQ(nullptr, ret);

    if (appInfo != nullptr) {
        SoftBusFree(appInfo);
    }
}

/**
 * @tc.name: PackRequest003
 * @tc.desc: PackRequest003, use the wrong parameter or normal parameter.
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

    char *ret = PackRequest(appInfo);
    EXPECT_EQ(nullptr, ret);

    if (appInfo != nullptr) {
        SoftBusFree(appInfo);
    }
}

/**
 * @tc.name: PackRequest004
 * @tc.desc: PackRequest004, use the wrong parameter or normal parameter.
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
    char *ret = PackRequest(appInfo);
    EXPECT_EQ(nullptr, ret);

    if (appInfo != nullptr) {
        SoftBusFree(appInfo);
    }
}

/**
 * @tc.name: PackReply001
 * @tc.desc: PackReply001, use the wrong parameter or normal parameter.
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

/**
 * @tc.name: PackReply002
 * @tc.desc: PackReply002, use the wrong parameter or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusMessageOpenChannelMockTest, PackReply002, TestSize.Level1)
{
    AppInfo *appInfo = reinterpret_cast<AppInfo *>(SoftBusMalloc(sizeof(AppInfo)));
    ASSERT_NE(nullptr, appInfo);
    (void)memset_s(appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
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

/**
 * @tc.name: PackReply003
 * @tc.desc: PackReply003, use the wrong parameter or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusMessageOpenChannelMockTest, PackReply003, TestSize.Level1)
{
    AppInfo *appInfo = reinterpret_cast<AppInfo *>(SoftBusMalloc(sizeof(AppInfo)));
    ASSERT_NE(nullptr, appInfo);
    (void)memset_s(appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
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

/**
 * @tc.name: PackReply004
 * @tc.desc: PackReply004, use the wrong parameter or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusMessageOpenChannelMockTest, PackReply004, TestSize.Level1)
{
    AppInfo *appInfo = reinterpret_cast<AppInfo *>(SoftBusMalloc(sizeof(AppInfo)));
    ASSERT_NE(nullptr, appInfo);
    (void)memset_s(appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
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

/**
 * @tc.name: UnpackReply001
 * @tc.desc: UnpackReply001, use the wrong parameter or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusMessageOpenChannelMockTest, UnpackReply001, TestSize.Level1)
{
    AppInfo *appInfo = reinterpret_cast<AppInfo *>(SoftBusMalloc(sizeof(AppInfo)));
    ASSERT_NE(nullptr, appInfo);
    (void)memset_s(appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    cJSON msg = {0};
    OHOS::SoftbusMessageOpenChannelInterfaceMock softbusMOpenChannelMock;
    EXPECT_CALL(softbusMOpenChannelMock, GetJsonObjectStringItem).WillOnce(Return(false));
    int32_t ret = UnpackReply(&msg, appInfo, nullptr);
    EXPECT_EQ(SOFTBUS_PARSE_JSON_ERR, ret);

    if (appInfo != nullptr) {
        SoftBusFree(appInfo);
    }
}

/**
 * @tc.name: UnpackReply002
 * @tc.desc: UnpackReply002, use the wrong parameter or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusMessageOpenChannelMockTest, UnpackReply002, TestSize.Level1)
{
    AppInfo *appInfo = reinterpret_cast<AppInfo *>(SoftBusMalloc(sizeof(AppInfo)));
    ASSERT_NE(nullptr, appInfo);
    (void)memset_s(appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
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

/**
 * @tc.name: TransTdcPackFastData001
 * @tc.desc: TransTdcPackFastData001, use the wrong parameter or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusMessageOpenChannelMockTest, TransTdcPackFastData001, TestSize.Level1)
{
    char *ret = TransTdcPackFastData(nullptr, nullptr);
    EXPECT_EQ(nullptr, ret);
}

/**
 * @tc.name: JsonObjectPackRequestEx001
 * @tc.desc: JsonObjectPackRequestEx001, use the wrong parameter or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftBusMessageOpenChannelMockTest, JsonObjectPackRequestEx001, TestSize.Level3)
{
    OHOS::SoftbusMessageOpenChannelInterfaceMock softbusMOpenChannelMock;
    EXPECT_CALL(softbusMOpenChannelMock, AddNumberToJsonObject).WillRepeatedly(Return(false));
    EXPECT_CALL(softbusMOpenChannelMock, AddStringToJsonObject).WillRepeatedly(Return(false));
    int32_t ret = JsonObjectPackRequestEx(nullptr, nullptr, nullptr);
    EXPECT_EQ(SOFTBUS_PARSE_JSON_ERR, ret);
}

/**
 * @tc.name: ParseMessageToAppInfo001
 * @tc.desc: ParseMessageToAppInfo001, use the wrong parameter or normal parameter.
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

/**
 * @tc.name: ParseMessageToAppInfo002
 * @tc.desc: ParseMessageToAppInfo002, use the wrong parameter or normal parameter.
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
    EXPECT_NE(SOFTBUS_OK, ret);

    if (appInfo != nullptr) {
        SoftBusFree(appInfo);
    }
}
} // OHOS
