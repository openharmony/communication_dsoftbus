/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include "trans_tcp_direct_json.h"

#include <gtest/gtest.h>

#include "softbus_error_code.h"
#include "softbus_json_utils.h"
#include "softbus_proxychannel_message.h"
#include "trans_log.h"
#include "trans_tcp_direct_p2p.h"

#define MY_IP "1111"
#define PEER_IP "2222"
#define MY_PORT 1111
#define IP_LENGTH 16
#define CODE 1
#define ERRCODE 0
#define ERR_PORT 0

using namespace testing;
using namespace testing::ext;

namespace OHOS {
class TransTcpDirectJsonTest : public testing::Test {
public:
    TransTcpDirectJsonTest()
    {}
    ~TransTcpDirectJsonTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void TransTcpDirectJsonTest::SetUpTestCase(void)
{}

void TransTcpDirectJsonTest::TearDownTestCase(void)
{}

/*
 * @tc.name: VerifyP2pPackErrorTest001
 * @tc.desc: notify Verify P2p PackError test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectJsonTest, VerifyP2pPackErrorTest001, TestSize.Level1)
{
    int32_t code = CODE;
    int32_t errCode = ERRCODE;
    char *ret = VerifyP2pPackError(code, errCode, nullptr);
    EXPECT_EQ(nullptr, ret);
    
    const char *errDesc = "P2p Pack Err Test";
    ret = VerifyP2pPackError(code, errCode, errDesc);
    EXPECT_NE(nullptr, ret);
}

/*
 * @tc.name: VerifyP2pPackErrorTest001
 * @tc.desc: Verify P2p Pack test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectJsonTest, VerifyP2pPackTest001, TestSize.Level1)
{
    int32_t myPort = MY_PORT;
    const char *peerIp = PEER_IP;
    char *ret = VerifyP2pPack(nullptr, myPort, peerIp, 0, 0);
    EXPECT_EQ(nullptr, ret);

    const char *myIp = MY_IP;
    myPort = ERR_PORT;
    ret = VerifyP2pPack(myIp, myPort, peerIp, 0, 0);
    EXPECT_EQ(nullptr, ret);

    myPort = MY_PORT;
    ret = VerifyP2pPack(myIp, myPort, peerIp, 0, 0);
    EXPECT_NE(nullptr, ret);
}

/*
 * @tc.name: VerifyP2pPackErrorTest001
 * @tc.desc: Verify P2p UnPack test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectJsonTest, VerifyP2pUnPackTest001, TestSize.Level1)
{
    char ip[] = MY_IP;
    int32_t port = MY_PORT;
    ProtocolType protocol = 0;
    int32_t uid = MY_PORT;
    int32_t ret = VerifyP2pUnPack(nullptr, ip, &port, &protocol, &uid);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    cJSON *json = cJSON_CreateObject();
    ret = VerifyP2pUnPack(json, ip, nullptr, &protocol, &uid);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = VerifyP2pUnPack(json, nullptr, &port, &protocol, &uid);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = VerifyP2pUnPack(json, ip, &port, &protocol, &uid);
    EXPECT_NE(SOFTBUS_PEER_PROC_ERR, ret);
}
}
