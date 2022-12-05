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

#include <gtest/gtest.h>
#include "securec.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "session.h"
#include "trans_udp_channel_manager.h"
#include "client_trans_session_callback.h"
#include "client_trans_udp_manager.c"

using namespace std;
using namespace testing::ext;

const char *g_sessionName = "ohos.distributedschedule.dms.test";
const char *g_networkid = "ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00";
const char *g_groupid = "TEST_GROUP_ID";

namespace OHOS {
#define TEST_CHANNELID 5
#define TEST_SESSIONID 1
#define TEST_COUNT 2
#define STREAM_DATA_LENGTH 10
#define TEST_EVENT_ID 2
class ClientTransUdpManagerStaticTest : public testing::Test {
public:
    ClientTransUdpManagerStaticTest() {}
    ~ClientTransUdpManagerStaticTest() {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override {}
    void TearDown() override {}
};

void ClientTransUdpManagerStaticTest::SetUpTestCase(void) {}

void ClientTransUdpManagerStaticTest::TearDownTestCase(void) {}

/**
 * @tc.name: ClientTransUdpManagerStaticTest001
 * @tc.desc: client trans udp manager static test, use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransUdpManagerStaticTest, ClientTransUdpManagerStaticTest001, TestSize.Level0)
{
    int32_t ret;
    char sendStringData[STREAM_DATA_LENGTH] = "diudiudiu";
    StreamData tmpData = {
        sendStringData,
        STREAM_DATA_LENGTH,
    };
    char str[STREAM_DATA_LENGTH] = "oohoohooh";
    StreamData tmpData2 = {
        str,
        STREAM_DATA_LENGTH,
    };

    StreamFrameInfo tmpf = {};
    int32_t sessionId = 0;
    QosTv tvList;
    OnStreamReceived(TEST_CHANNELID, &tmpData, &tmpData2, &tmpf);

    ret = OnFileGetSessionId(TEST_CHANNELID, &sessionId);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    OnUdpChannelOpened(TEST_CHANNELID);
    OnUdpChannelClosed(TEST_CHANNELID);
    OnQosEvent(TEST_CHANNELID, TEST_EVENT_ID, TEST_COUNT, &tvList);

    ret = TransDeleteUdpChannel(TEST_CHANNELID);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    UdpChannel channel;
    ret = TransGetUdpChannel(TEST_CHANNELID, &channel);
    EXPECT_EQ(SOFTBUS_ERR, ret);
}
} // namespace OHOS