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

#include "gtest/gtest.h"
#include <securec.h>

#include "softbus_adapter_mem.h"
#include "trans_udp_negotiation_exchange.h"

using namespace testing::ext;

namespace OHOS {

#define TEST_SOCKET_ADDR "192.168.8.119"
#define TEST_ERROR_CODE (-12345)

const char *g_sessionKey = "www.huaweitest.com";
const char *g_pkgName = "dms";
const char *g_sessionName = "ohos.distributedschedule.dms.test";
const char *g_networkid = "ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00";
const char *g_groupid = "TEST_GROUP_ID";

class TransUdpNegotiationExchangeTest : public testing::Test {
public:
    TransUdpNegotiationExchangeTest()
    {}
    ~TransUdpNegotiationExchangeTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void TransUdpNegotiationExchangeTest::SetUpTestCase(void)
{}

void TransUdpNegotiationExchangeTest::TearDownTestCase(void)
{}

static void GenerateAppInfo(AppInfo *appInfo)
{
    if (appInfo == NULL) {
        appInfo = (AppInfo*)SoftBusMalloc(sizeof(AppInfo));
        EXPECT_TRUE(appInfo != NULL);
        memset_s(appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    }
    int32_t res = strcpy_s(appInfo->sessionKey, sizeof(appInfo->sessionKey), g_sessionKey);
    EXPECT_EQ(res, EOK);
    res = strcpy_s(appInfo->myData.addr, sizeof(appInfo->myData.addr), TEST_SOCKET_ADDR);
    EXPECT_EQ(res, EOK);
    res = strcpy_s(appInfo->peerData.addr, sizeof(appInfo->peerData.addr), TEST_SOCKET_ADDR);
    EXPECT_EQ(res, EOK);
    res = strcpy_s(appInfo->myData.sessionName, sizeof(appInfo->myData.sessionName), g_sessionName);
    EXPECT_EQ(res, EOK);
    res = strcpy_s(appInfo->peerData.sessionName, sizeof(appInfo->peerData.sessionName), g_sessionName);
    EXPECT_EQ(res, EOK);
    res = strcpy_s(appInfo->myData.pkgName, sizeof(appInfo->myData.pkgName), g_pkgName);
    EXPECT_EQ(res, EOK);
    res = strcpy_s(appInfo->peerData.pkgName, sizeof(appInfo->peerData.pkgName), g_pkgName);
    EXPECT_EQ(res, EOK);
    res = strcpy_s(appInfo->groupId, sizeof(appInfo->groupId), g_groupid);
    EXPECT_EQ(res, EOK);
}

/**
 * @tc.name: TransUdpNegotiationExchangeTest001
 * @tc.desc: Transmission udp negotiation pack and unpack request with invalid parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegotiationExchangeTest, TransUdpNegotiationExchangeTest001, TestSize.Level1)
{
    AppInfo* appInfo = (AppInfo*)SoftBusMalloc(sizeof(AppInfo));
    EXPECT_TRUE(appInfo != NULL);
    memset_s(appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    cJSON *msg = cJSON_CreateObject();
    int32_t ret = TransPackRequestUdpInfo(NULL, appInfo);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = TransUnpackRequestUdpInfo(NULL, appInfo);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = TransPackRequestUdpInfo(msg, NULL);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = TransUnpackRequestUdpInfo(msg, NULL);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    cJSON_Delete(msg);
    SoftBusFree(appInfo);
}

/**
 * @tc.name: TransUdpNegotiationExchangeTest002
 * @tc.desc: Transmission udp negotiation pack and unpack request.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegotiationExchangeTest, TransUdpNegotiationExchangeTest002, TestSize.Level1)
{
    AppInfo* appInfo = (AppInfo*)SoftBusMalloc(sizeof(AppInfo));
    EXPECT_TRUE(appInfo != NULL);
    memset_s(appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    GenerateAppInfo(appInfo);
    appInfo->udpChannelOptType = TYPE_UDP_CHANNEL_OPEN;
    cJSON *msg = cJSON_CreateObject();
    EXPECT_TRUE(msg != NULL);
    int32_t ret = TransPackRequestUdpInfo(msg, appInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    memset_s(appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    ret = TransUnpackRequestUdpInfo(msg, appInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    cJSON_Delete(msg);
    msg = cJSON_CreateObject();
    appInfo->udpChannelOptType = TYPE_UDP_CHANNEL_CLOSE;
    ret = TransPackRequestUdpInfo(msg, appInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    memset_s(appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    ret = TransUnpackRequestUdpInfo(msg, appInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    cJSON_Delete(msg);
    msg = cJSON_CreateObject();
    appInfo->udpChannelOptType = TYPE_INVALID_CHANNEL;
    ret = TransPackRequestUdpInfo(msg, appInfo);
    EXPECT_EQ(ret, SOFTBUS_TRANS_INVALID_CHANNEL_TYPE);
    memset_s(appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    cJSON_Delete(msg);
    SoftBusFree(appInfo);
}

/**
 * @tc.name: TransUdpNegotiationExchangeTest003
 * @tc.desc: Transmission udp negotiation pack and unpack reply with invalid parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegotiationExchangeTest, TransUdpNegotiationExchangeTest003, TestSize.Level1)
{
    AppInfo* appInfo = (AppInfo*)SoftBusMalloc(sizeof(AppInfo));
    EXPECT_TRUE(appInfo != NULL);
    memset_s(appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    cJSON *msg = cJSON_CreateObject();
    int32_t ret = TransPackReplyUdpInfo(NULL, appInfo);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransUnpackReplyUdpInfo(NULL, appInfo);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransPackReplyUdpInfo(msg, NULL);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    appInfo->udpChannelOptType = TYPE_UDP_CHANNEL_OPEN;
    ret = TransPackReplyUdpInfo(msg, appInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);
    appInfo->udpChannelOptType = TYPE_INVALID_CHANNEL;
    ret = TransPackReplyUdpInfo(msg, appInfo);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_CHANNEL_TYPE, ret);
    ret = TransUnpackReplyUdpInfo(msg, NULL);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    cJSON_Delete(msg);
    SoftBusFree(appInfo);
}

/**
 * @tc.name: TransUdpNegotiationExchangeTest004
 * @tc.desc: Transmission udp negotiation pack and unpack reply.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegotiationExchangeTest, TransUdpNegotiationExchangeTest004, TestSize.Level1)
{
    AppInfo* appInfo = (AppInfo*)SoftBusMalloc(sizeof(AppInfo));
    EXPECT_TRUE(appInfo != NULL);
    memset_s(appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));

    GenerateAppInfo(appInfo);
    appInfo->udpChannelOptType = TYPE_UDP_CHANNEL_OPEN;
    cJSON *msg = cJSON_CreateObject();
    EXPECT_TRUE(msg != NULL);
    int32_t ret = TransPackReplyUdpInfo(msg, appInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    memset_s(appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    appInfo->udpChannelOptType = TYPE_UDP_CHANNEL_OPEN;
    ret = TransUnpackReplyUdpInfo(msg, appInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    cJSON_Delete(msg);

    msg = cJSON_CreateObject();
    appInfo->udpChannelOptType = TYPE_UDP_CHANNEL_CLOSE;
    GenerateAppInfo(appInfo);
    ret = TransPackReplyUdpInfo(msg, appInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    memset_s(appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    appInfo->udpChannelOptType = TYPE_UDP_CHANNEL_CLOSE;
    ret = TransUnpackReplyUdpInfo(msg, appInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    cJSON_Delete(msg);
    SoftBusFree(appInfo);
}

/**
 * @tc.name: TransUdpNegotiationExchangeTest005
 * @tc.desc: Transmission udp negotiation pack and unpack reply with invalid channel option type.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegotiationExchangeTest, TransUdpNegotiationExchangeTest005, TestSize.Level1)
{
    AppInfo* appInfo = (AppInfo*)SoftBusMalloc(sizeof(AppInfo));
    EXPECT_TRUE(appInfo != NULL);
    memset_s(appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    cJSON *msg = cJSON_CreateObject();
    GenerateAppInfo(appInfo);
    appInfo->udpChannelOptType = TYPE_INVALID_CHANNEL;
    int32_t ret = TransPackReplyUdpInfo(msg, appInfo);
    EXPECT_EQ(ret, SOFTBUS_TRANS_INVALID_CHANNEL_TYPE);
    memset_s(appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    cJSON_Delete(msg);

    msg = cJSON_CreateObject();
    GenerateAppInfo(appInfo);
    appInfo->udpChannelOptType = TYPE_UDP_CHANNEL_CLOSE;
    ret = TransPackReplyUdpInfo(msg, appInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    memset_s(appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    appInfo->udpChannelOptType = TYPE_INVALID_CHANNEL;
    ret = TransUnpackReplyUdpInfo(msg, appInfo);
    EXPECT_EQ(ret, SOFTBUS_TRANS_INVALID_CHANNEL_TYPE);
    cJSON_Delete(msg);
    SoftBusFree(appInfo);
}

/**
 * @tc.name: TransUdpNegotiationExchangeTest006
 * @tc.desc: Transmission udp negotiation pack and unpack error info with invalid parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegotiationExchangeTest, TransUdpNegotiationExchangeTest006, TestSize.Level1)
{
    cJSON *msg = cJSON_CreateObject();
    int32_t errCode = TEST_ERROR_CODE;
    int32_t ret = TransPackReplyErrInfo(msg, errCode, NULL);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = TransUnpackReplyErrInfo(NULL, &errCode);
    EXPECT_EQ(ret, SOFTBUS_PARSE_JSON_ERR);
    ret = TransPackReplyErrInfo(NULL, errCode, "error descriptor test");
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = TransUnpackReplyErrInfo(msg, NULL);
    EXPECT_EQ(ret, SOFTBUS_PARSE_JSON_ERR);
    cJSON_Delete(msg);
}

/**
 * @tc.name: TransUdpNegotiationExchangeTest007
 * @tc.desc: Transmission udp negotiation pack and unpack error info.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegotiationExchangeTest, TransUdpNegotiationExchangeTest007, TestSize.Level1)
{
    cJSON *msg = cJSON_CreateObject();
    EXPECT_TRUE(msg != NULL);
    int32_t errCode = TEST_ERROR_CODE;
    int32_t ret = TransPackReplyErrInfo(msg, errCode, "error descriptor test");
    EXPECT_EQ(ret, SOFTBUS_OK);
    int32_t recvErrcode = 0;
    ret = TransUnpackReplyErrInfo(msg, &recvErrcode);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(errCode, recvErrcode);
    cJSON_Delete(msg);
}

}