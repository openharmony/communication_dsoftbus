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
 
#include <securec.h>

#include "auth_interface.h"
#include "gtest/gtest.h"
#include "softbus_app_info.h"
#include "softbus_errcode.h"
#include "softbus_json_utils.h"
#include "softbus_log.h"
#include "softbus_protocol_def.h"
#include "trans_channel_manager.h"
#include "trans_udp_channel_manager.c"
#include "trans_udp_negotiation.c"
#include "trans_udp_negotiation_exchange.c"
#include "trans_udp_channel_manager.h"
#include "trans_udp_negotiation.h"
#include "trans_udp_negotiation_exchange.h"

using namespace testing::ext;

namespace OHOS {

#define INVALID_ID (-1)
#define INVALID_AUTH_ID (-2)

class TransUdpNegoTest : public testing::Test {
public:
    TransUdpNegoTest()
    {}
    ~TransUdpNegoTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void TransUdpNegoTest::SetUpTestCase(void)
{}

void TransUdpNegoTest::TearDownTestCase(void)
{}

char* TestGetMsgInfo(void)
{
    AppInfo info;
    info.udpChannelOptType = TYPE_UDP_CHANNEL_CLOSE;
    cJSON *requestMsg = cJSON_CreateObject();
    if (requestMsg == NULL) {
        cJSON_Delete(requestMsg);
        return NULL;
    }

    if (TransPackRequestUdpInfo(requestMsg, &info) != SOFTBUS_OK) {
        cJSON_Delete(requestMsg);
        return NULL;
    }
    char *msgStr = cJSON_PrintUnformatted(requestMsg);
    cJSON_Delete(requestMsg);
    return msgStr;
}

/**
 * @tc.name: TransUdpNegoTest001
 * @tc.desc: extern module active publish, stop session whitout start.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegoTest, TransUdpNegoTest001, TestSize.Level1)
{
    int32_t errCode = 0;
    string msgStr = "ProcessMessage";
    int32_t ret = TransUnpackReplyErrInfo(NULL, NULL);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    cJSON *msg = cJSON_Parse((char *)msgStr.c_str());
    ret = TransUnpackReplyErrInfo(msg, &errCode);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    cJSON_Delete(msg);
}

/**
 * @tc.name: TransUdpNegoTest002
 * @tc.desc: extern module active publish, stop session whitout start.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegoTest, TransUdpNegoTest002, TestSize.Level1)
{
    int32_t errCode = 0;
    string msgStr = "ProcessMessage";
    cJSON *msg = cJSON_Parse((char *)msgStr.c_str());
    const char* errDesc = "errDesc";

    int32_t ret = TransPackReplyErrInfo(NULL, errCode, NULL);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = TransPackReplyErrInfo(msg, errCode, errDesc);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    cJSON_Delete(msg);
}

/**
 * @tc.name: TransUdpNegoTest003
 * @tc.desc: extern module active publish, stop session whitout start.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegoTest, TransUdpNegoTest003, TestSize.Level1)
{
    int64_t authId = AUTH_INVALID_ID;
    int64_t seq = 0;
    string msg = "ProcessMessage";
    cJSON *replyMsg = cJSON_Parse((char *)msg.c_str());

    int32_t ret = sendUdpInfo(NULL, authId, seq);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = sendUdpInfo(replyMsg, NULL, NULL);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    cJSON_Delete(replyMsg);
}

/**
 * @tc.name: TransUdpNegoTest004
 * @tc.desc: extern module active publish, stop session whitout start.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegoTest, TransUdpNegoTest004, TestSize.Level1)
{
    int32_t errCode = 0;
    string errDesc = "ProcessMessage";
    int32_t ret = SendReplyErrInfo(errCode, NULL, NULL, NULL);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = SendReplyErrInfo(errCode, (char *)errDesc.c_str(), NULL, NULL);
    EXPECT_TRUE(ret != SOFTBUS_OK);
}

/**
 * @tc.name: TransUdpNegoTest005
 * @tc.desc: extern module active publish, stop session whitout start.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegoTest, TransUdpNegoTest005, TestSize.Level1)
{
    int64_t authId = INVALID_ID;
    int64_t seq = INVALID_SEQ;
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));

    appInfo.udpChannelOptType = TYPE_UDP_CHANNEL_CLOSE;

    int32_t ret = SendReplyUdpInfo(NULL, authId, seq);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = SendReplyUdpInfo(&appInfo, NULL, seq);
    EXPECT_TRUE(ret != SOFTBUS_OK);
}

/**
 * @tc.name: TransUdpNegoTest006
 * @tc.desc: extern module active publish, stop session whitout start.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegoTest, TransUdpNegoTest006, TestSize.Level1)
{
    (void)TransChannelInit();
    char* data = TestGetMsgInfo();
    cJSON *msg = cJSON_Parse(data);

    UdpChannelInfo *newChannel = (UdpChannelInfo*)SoftBusCalloc(sizeof(UdpChannelInfo));
    if (newChannel == NULL) {
        return;
    }

    (void)memset_s(newChannel, sizeof(UdpChannelInfo), 0, sizeof(UdpChannelInfo));
    newChannel->seq = 1;
    int64_t authId = AUTH_INVALID_ID;

    int32_t ret = TransAddUdpChannel(newChannel);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    TransOnExchangeUdpInfoReply(authId, INVALID_SEQ, msg);
    TransOnExchangeUdpInfoReply(INVALID_AUTH_ID, newChannel->seq, msg);
    TransOnExchangeUdpInfoReply(authId, newChannel->seq, msg);
    cJSON_Delete(msg);
    SoftBusFree(newChannel);
    TransChannelDeinit();
}

/**
 * @tc.name: TransUdpNegoTest007
 * @tc.desc: extern module active publish, stop session whitout start.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegoTest, TransUdpNegoTest007, TestSize.Level1)
{
    (void)TransChannelInit();
    char* data = TestGetMsgInfo();
    cJSON *msg = cJSON_Parse(data);

    UdpChannelInfo *newChannel = (UdpChannelInfo*)SoftBusCalloc(sizeof(UdpChannelInfo));
    if (newChannel == NULL) {
        return;
    }

    (void)memset_s(newChannel, sizeof(UdpChannelInfo), 0, sizeof(UdpChannelInfo));
    newChannel->seq = 1;
    int64_t authId = AUTH_INVALID_ID;

    int32_t ret = TransAddUdpChannel(newChannel);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    TransOnExchangeUdpInfoRequest(authId, newChannel->seq, NULL);

    cJSON_Delete(msg);
    SoftBusFree(newChannel);
    TransChannelDeinit();
}

/**
 * @tc.name: TransUdpNegoTest008
 * @tc.desc: extern module active publish, stop session whitout start.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegoTest, TransUdpNegoTest008, TestSize.Level1)
{
    int64_t seq = 0;
    UdpChannelInfo channel;
    (void)memset_s(&channel, sizeof(UdpChannelInfo), 0, sizeof(UdpChannelInfo));
    channel.info.udpChannelOptType = TYPE_UDP_CHANNEL_OPEN;
    int32_t ret = StartExchangeUdpInfo(&channel, NULL, NULL);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    channel.info.udpChannelOptType = TYPE_UDP_CHANNEL_CLOSE;
    ret = StartExchangeUdpInfo(&channel, NULL, seq);
    EXPECT_TRUE(ret != SOFTBUS_OK);
}

/**
 * @tc.name: TransUdpNegoTest009
 * @tc.desc: extern module active publish, stop session whitout start.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegoTest, TransUdpNegoTest009, TestSize.Level1)
{
    int64_t authId = AUTH_INVALID_ID;
    AuthTransData data;
    int32_t ret = memset_s(&channel, sizeof(UdpChannelInfo), 0, sizeof(UdpChannelInfo));
    EXPECT_TRUE(ret == SOFTBUS_OK);
    UdpModuleCb(authId, NULL);
    
    data.data = NULL;
    UdpModuleCb(authId, &data);
    
    data.data = (const uint8_t *)"data";
    data.len = 0;
    UdpModuleCb(authId, &data);

    data.flag = 0;
    UdpModuleCb(authId, &data);
}

/**
 * @tc.name: TransUdpNegoTest010
 * @tc.desc: extern module active publish, stop session whitout start.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegoTest, TransUdpNegoTest010, TestSize.Level1)
{
    IServerChannelCallBack *cb = TransServerGetChannelCb();
    int32_t ret = TransUdpChannelInit(cb);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    TransUdpChannelDeinit();
}
}