/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#include "auth_channel_mock.h"
#include "lnn_lane_interface_struct.h"
#include "softbus_adapter_mem.h"
#include "softbus_config_type.h"
#include "trans_auth_message.h"
#include "trans_auth_message.c"

using namespace testing::ext;
using namespace OHOS;
using ::testing::Return;

namespace OHOS {

class TransAuthChannelMessageTest : public testing::Test {
public:
    TransAuthChannelMessageTest() { }
    ~TransAuthChannelMessageTest() { }
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override { }
    void TearDown() override { }
};

void TransAuthChannelMessageTest::SetUpTestCase(void)
{}

void TransAuthChannelMessageTest::TearDownTestCase(void)
{}

/*
 * @tc.name: PackUsbLinkTypeMsg001
 * @tc.desc: PackUsbLinkTypeMsg test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthChannelMessageTest, PackUsbLinkTypeMsg001, TestSize.Level1)
{
    cJSON *obj = cJSON_CreateObject();
    ASSERT_TRUE(obj != nullptr);
    AppInfo *appInfo = static_cast<AppInfo *>(SoftBusCalloc(sizeof(AppInfo)));
    ASSERT_TRUE(appInfo != nullptr);
    appInfo->linkType = LANE_P2P;

    int32_t ret = PackUsbLinkTypeMsg(obj, appInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);

    cJSON_Delete(obj);
    SoftBusFree(appInfo);
}

/*
 * @tc.name: PackUsbLinkTypeMsg002
 * @tc.desc: PackUsbLinkTypeMsg test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthChannelMessageTest, PackUsbLinkTypeMsg002, TestSize.Level1)
{
    cJSON *obj = cJSON_CreateObject();
    ASSERT_TRUE(obj != nullptr);
    AppInfo *appInfo = static_cast<AppInfo *>(SoftBusCalloc(sizeof(AppInfo)));
    ASSERT_TRUE(appInfo != nullptr);
    appInfo->linkType = LANE_USB;

    AuthChannelInterfaceMock authChannelObj;
    EXPECT_CALL(authChannelObj, AddNumberToJsonObject).WillOnce(Return(false));
    int32_t ret = PackUsbLinkTypeMsg(obj, appInfo);
    EXPECT_EQ(ret, SOFTBUS_CREATE_JSON_ERR);

    cJSON_Delete(obj);
    SoftBusFree(appInfo);
}

/*
 * @tc.name: TransAuthChannelMsgPack001
 * @tc.desc: TransAuthChannelMsgPack test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthChannelMessageTest, TransAuthChannelMsgPack001, TestSize.Level1)
{
    cJSON *obj = cJSON_CreateObject();
    ASSERT_TRUE(obj != nullptr);
    AppInfo *appInfo = static_cast<AppInfo *>(SoftBusCalloc(sizeof(AppInfo)));
    ASSERT_TRUE(appInfo != nullptr);
    appInfo->reqId[0] = '\0';

    AuthChannelInterfaceMock authChannelObj;
    EXPECT_CALL(authChannelObj, GenerateRandomStr).WillOnce(Return(SOFTBUS_INVALID_PARAM));

    int32_t ret = TransAuthChannelMsgPack(obj, appInfo);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    cJSON_Delete(obj);
    SoftBusFree(appInfo);
}

/*
 * @tc.name: TransAuthChannelMsgPack002
 * @tc.desc: TransAuthChannelMsgPack test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthChannelMessageTest, TransAuthChannelMsgPack002, TestSize.Level1)
{
    cJSON *obj = cJSON_CreateObject();
    ASSERT_TRUE(obj != nullptr);
    AppInfo *appInfo = static_cast<AppInfo *>(SoftBusCalloc(sizeof(AppInfo)));
    ASSERT_TRUE(appInfo != nullptr);
    (void)strcpy_s(appInfo->reqId, REQ_ID_SIZE_MAX, "1033");

    AuthChannelInterfaceMock authChannelObj;
    EXPECT_CALL(authChannelObj, AddNumberToJsonObject).WillOnce(Return(false));
    int32_t ret = TransAuthChannelMsgPack(obj, appInfo);
    EXPECT_EQ(ret, SOFTBUS_CREATE_JSON_ERR);

    cJSON_Delete(obj);
    SoftBusFree(appInfo);
}

/*
 * @tc.name: TransAuthChannelMsgPack003
 * @tc.desc: TransAuthChannelMsgPack test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthChannelMessageTest, TransAuthChannelMsgPack003, TestSize.Level1)
{
    cJSON *obj = cJSON_CreateObject();
    ASSERT_TRUE(obj != nullptr);

    AppInfo *appInfo = static_cast<AppInfo *>(SoftBusCalloc(sizeof(AppInfo)));
    ASSERT_TRUE(appInfo != nullptr);
    *appInfo = {
        .myData = {
            .deviceId = "DEV_001_ABCD1234",
            .pkgName = "com.example.app.v1.0.0",
            .sessionName = "my_SESS_2023Q3_7X9B2Y",
            .dataConfig = SOFTBUS_INT_MAX_MESSAGE_NEW_LENGTH,
            .apiVersion = API_V1
        },
        .peerData = {
            .sessionName = "peer_name_2023_258X"
        },
        .peerNetWorkId = "NET_192.168.1.100_5G",
        .reqId = "REQ_8877665544332211",
        .routeType = BT_BR,
        .linkType = LANE_HML_RAW
    };

    AuthChannelInterfaceMock authChannelObj;
    EXPECT_CALL(authChannelObj, AddNumberToJsonObject).WillOnce(Return(false));
    int32_t ret = TransAuthChannelMsgPack(obj, appInfo);
    EXPECT_EQ(ret, SOFTBUS_CREATE_JSON_ERR);

    cJSON_Delete(obj);
    SoftBusFree(appInfo);
}

/*
 * @tc.name: TransAuthChannelMsgPack004
 * @tc.desc: TransAuthChannelMsgPack test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthChannelMessageTest, TransAuthChannelMsgPack004, TestSize.Level1)
{
    cJSON *obj = cJSON_CreateObject();
    ASSERT_TRUE(obj != nullptr);

    AppInfo *appInfo = static_cast<AppInfo *>(SoftBusCalloc(sizeof(AppInfo)));
    ASSERT_TRUE(appInfo != nullptr);
    *appInfo = {
        .myData = {
            .deviceId = "DEV_001_ABCD1234",
            .pkgName = "com.example.app.v1.0.0",
            .sessionName = "my_SESS_2023Q3_7X9B2Y",
            .dataConfig = SOFTBUS_INT_MAX_MESSAGE_NEW_LENGTH,
            .apiVersion = API_V1
        },
        .peerData = {
            .sessionName = "peer_name_2023_258X"
        },
        .peerNetWorkId = "NET_192.168.1.100_5G",
        .reqId = "REQ_8877665544332211",
        .routeType = BT_BR,
        .linkType = LANE_HML_RAW
    };

    AuthChannelInterfaceMock authChannelObj;
    EXPECT_CALL(authChannelObj, AddNumberToJsonObject).WillOnce(Return(true));
    EXPECT_CALL(authChannelObj, AddStringToJsonObject)
    .Times(2)
    .WillOnce(testing::Return(true))
    .WillOnce(testing::Return(false));
    int32_t ret = TransAuthChannelMsgPack(obj, appInfo);
    EXPECT_EQ(ret, SOFTBUS_CREATE_JSON_ERR);

    cJSON_Delete(obj);
    SoftBusFree(appInfo);
}

/*
 * @tc.name: TransAuthChannelErrorPack001
 * @tc.desc: TransAuthChannelErrorPack test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthChannelMessageTest, TransAuthChannelErrorPack001, TestSize.Level1)
{
    int32_t errcode = SOFTBUS_OK;
    char cJsonStr = '\0';
    char *errMsg = static_cast<char *>(SoftBusCalloc(sizeof(ERR_MSG_MAX_LEN)));
    ASSERT_TRUE(errMsg != nullptr);

    AuthChannelInterfaceMock authChannelObj;
    EXPECT_CALL(authChannelObj, AddNumberToJsonObject)
    .Times(2)
    .WillOnce(testing::Return(true))
    .WillOnce(testing::Return(true));
    EXPECT_CALL(authChannelObj, AddStringToJsonObject).WillOnce(testing::Return(false));

    int32_t ret = TransAuthChannelErrorPack(errcode, errMsg, &cJsonStr, ERR_MSG_MAX_LEN);
    EXPECT_EQ(ret, SOFTBUS_CREATE_JSON_ERR);

    SoftBusFree(errMsg);
}

/*
 * @tc.name: TransAuthChannelErrorPack002
 * @tc.desc: TransAuthChannelErrorPack test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthChannelMessageTest, TransAuthChannelErrorPack002, TestSize.Level1)
{
    int32_t errcode = SOFTBUS_OK;
    char *cJsonStr = static_cast<char *>(SoftBusCalloc(sizeof(ERR_MSG_MAX_LEN)));
    ASSERT_TRUE(cJsonStr != nullptr);

    char *errMsg = static_cast<char *>(SoftBusCalloc(sizeof(ERR_MSG_MAX_LEN)));
    ASSERT_TRUE(errMsg != nullptr);

    AuthChannelInterfaceMock authChannelObj;
    EXPECT_CALL(authChannelObj, AddNumberToJsonObject)
    .Times(2)
    .WillOnce(testing::Return(true))
    .WillOnce(testing::Return(true));
    EXPECT_CALL(authChannelObj, AddStringToJsonObject).WillOnce(testing::Return(true));

    EXPECT_CALL(authChannelObj, cJSON_PrintUnformatted).WillOnce(testing::Return(nullptr));

    int32_t ret = TransAuthChannelErrorPack(errcode, errMsg, cJsonStr, ERR_MSG_MAX_LEN);
    EXPECT_EQ(ret, SOFTBUS_CREATE_JSON_ERR);

    SoftBusFree(errMsg);
    SoftBusFree(cJsonStr);
}

/*
 * @tc.name: TransAuthChannelErrorPack003
 * @tc.desc: TransAuthChannelErrorPack test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransAuthChannelMessageTest, TransAuthChannelErrorPack003, TestSize.Level1)
{
    int32_t errcode = SOFTBUS_OK;

    char *cJsonStr = static_cast<char *>(SoftBusCalloc(ERR_MSG_MAX_LEN));
    ASSERT_TRUE(cJsonStr != nullptr);

    AuthChannelInterfaceMock authChannelObj;
    EXPECT_CALL(authChannelObj, AddNumberToJsonObject)
    .Times(2)
    .WillOnce(testing::Return(true))
    .WillOnce(testing::Return(true));
    EXPECT_CALL(authChannelObj, AddStringToJsonObject).WillOnce(testing::Return(true));

    char *data = static_cast<char *>(SoftBusCalloc(20));
    (void)strcpy_s(data, 20, "hfohfOHFEPJFHWQ");
    EXPECT_CALL(authChannelObj, cJSON_PrintUnformatted).WillOnce(Return(data));

    int32_t ret = TransAuthChannelErrorPack(errcode, "errMsg", cJsonStr, ERR_MSG_MAX_LEN);
    EXPECT_EQ(ret, SOFTBUS_OK);

    SoftBusFree(cJsonStr);
}
} // namespace OHOS
