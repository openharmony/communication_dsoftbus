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

#include "trans_tcp_direct_callback.h"

#include <securec.h>
#include <gtest/gtest.h>
#include <cstddef>

#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "softbus_error_code.h"

#define TEST_SESSION_NAME "com.softbus.tcpdirect.test"
#define TEST_PKG_NAME "com.test.tcpdirect.demo.pkgname"
#define PID 123
#define UID 0
#define CHANNELID 1010
#define ERRCODE 111

using namespace testing;
using namespace testing::ext;

namespace OHOS {
static IServerChannelCallBack g_channelCallBack;

static int32_t TransServerOnChannelOpened(const char *pkgName, int32_t pid, const char *sessionName,
    const ChannelInfo *channel)
{
    return SOFTBUS_OK;
}

static int32_t TransServerOnChannelClosed(const char *pkgName, int32_t pid,
    int32_t channelId, int32_t channelType, int32_t messageType)
{
    return SOFTBUS_OK;
}

static int32_t TransServerOnChannelOpenFailed(const char *pkgName, int32_t pid, int32_t channelId,
    int32_t channelType, int32_t errCode)
{
    return SOFTBUS_OK;
}

static int32_t TransServerOnMsgReceived(const char *pkgName, int32_t pid, int32_t channelId, int32_t channelType,
    TransReceiveData* receiveData)
{
    return SOFTBUS_OK;
}

static int32_t TransServerOnQosEvent(const char *pkgName, const QosParam *param)
{
    return SOFTBUS_OK;
}

int32_t TransGetPkgNameBySessionName(const char *sessionName, char *pkgName, uint16_t len)
{
    return SOFTBUS_OK;
}

int32_t TransGetUidAndPid(const char *sessionName, int32_t *uid, int32_t *pid)
{
    return SOFTBUS_OK;
}

static int32_t TransServerOnChannelBind(const char *pkgName, int32_t pid, int32_t channelId, int32_t channelType)
{
    return SOFTBUS_OK;
}

    class TransTcpDirectCallbackTest : public testing::Test {
public:
    TransTcpDirectCallbackTest()
    {
        g_channelCallBack.OnChannelOpened = TransServerOnChannelOpened;
        g_channelCallBack.OnChannelClosed = TransServerOnChannelClosed;
        g_channelCallBack.OnChannelOpenFailed = TransServerOnChannelOpenFailed;
        g_channelCallBack.OnDataReceived = TransServerOnMsgReceived;
        g_channelCallBack.OnQosEvent = TransServerOnQosEvent;
        g_channelCallBack.GetPkgNameBySessionName = TransGetPkgNameBySessionName;
        g_channelCallBack.GetUidAndPidBySessionName = TransGetUidAndPid;
        g_channelCallBack.OnChannelBind = TransServerOnChannelBind;
        int32_t ret = TransTdcSetCallBack(&g_channelCallBack);
        EXPECT_EQ(ret, SOFTBUS_OK);
    }
    ~TransTcpDirectCallbackTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void TransTcpDirectCallbackTest::SetUpTestCase(void)
{}

void TransTcpDirectCallbackTest::TearDownTestCase(void)
{}

/**
 * @tc.name: TransTdcOnChannelOpenedTest001
 * @tc.desc: notify channel opend  test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectCallbackTest, TransTdcOnChannelOpenedTest001, TestSize.Level1)
{
    int32_t ret;
    const char *pkgName = TEST_PKG_NAME;
    int32_t pid = PID;
    const char *sessionName = TEST_SESSION_NAME;
    ChannelInfo *channel = (ChannelInfo *)SoftBusMalloc(sizeof(ChannelInfo));
    ASSERT_TRUE(channel != nullptr);

    ret = TransTdcOnChannelOpened(pkgName, pid, sessionName, channel);
    EXPECT_EQ(SOFTBUS_OK, ret);
    SoftBusFree(channel);
}

/**
 * @tc.name: TransTdcOnChannelClosedTest002
 * @tc.desc: notify channel Closed  test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectCallbackTest, TransTdcOnChannelClosedTest001, TestSize.Level1)
{
    int32_t ret;
    const char *pkgName = TEST_PKG_NAME;
    int32_t pid = PID;
    int32_t channelId = CHANNELID;
    ChannelInfo *channel = (ChannelInfo *)SoftBusMalloc(sizeof(ChannelInfo));
    ASSERT_TRUE(channel != nullptr);

    channel->channelType = CHANNEL_TYPE_TCP_DIRECT;
    ret = TransTdcOnChannelClosed(pkgName, pid, channelId);
    EXPECT_EQ(SOFTBUS_OK, ret);

    SoftBusFree(channel);
}

/**
 * @tc.name: TransTdcOnChannelOpenFailedTest003
 * @tc.desc: notify channel opend Failed test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectCallbackTest, TransTdcOnChannelOpenFailedTest001, TestSize.Level1)
{
    int32_t ret;
    const char *pkgName = TEST_PKG_NAME;
    int32_t pid = PID;
    int32_t channelId = CHANNELID;
    int32_t errCode = ERRCODE;
    ChannelInfo *channel = (ChannelInfo *)SoftBusMalloc(sizeof(ChannelInfo));
    ASSERT_TRUE(channel != nullptr);

    ret = TransTdcOnChannelOpenFailed(pkgName, pid, channelId, errCode);
    EXPECT_EQ(SOFTBUS_OK, ret);

    SoftBusFree(channel);
}

/**
 * @tc.name: TransTdcGetPkgNameTest004
 * @tc.desc: GetPkgName test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectCallbackTest, TransTdcGetPkgNameTest001, TestSize.Level1)
{
    int32_t ret;
    char pkgName[] = TEST_PKG_NAME;
    const char *sessionName = TEST_SESSION_NAME;
    uint16_t len = 23;

    ret = TransTdcGetPkgName(sessionName, pkgName, len);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransTdcGetUidAndPidTest005
 * @tc.desc: GetUidAndPid test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectCallbackTest, TransTdcGetUidAndPidTest001, TestSize.Level1)
{
    int32_t ret;
    int32_t pid = PID;
    int32_t uid = UID;
    const char *sessionName = TEST_SESSION_NAME;

    ret = TransTdcGetUidAndPid(sessionName, &pid, &uid);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransTdcOnMsgReceivedTest006
 * @tc.desc: OnMsgReceived test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectCallbackTest, TransTdcOnMsgReceivedTest001, TestSize.Level1)
{
    int32_t ret;
    const char *pkgName = TEST_PKG_NAME;
    int32_t pid = PID;
    int32_t channelId = CHANNELID;
    TransReceiveData *receiveData = (TransReceiveData *)SoftBusMalloc(sizeof(TransReceiveData));
    ASSERT_TRUE(receiveData != nullptr);

    ret = TransTdcOnMsgReceived(pkgName, pid, channelId, receiveData);
    EXPECT_EQ(SOFTBUS_OK, ret);
    SoftBusFree(receiveData);
}

/**
 * @tc.name: TransTdcOnChannelBindTest001
 * @tc.desc: OnChannelBind test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectCallbackTest, TransTdcOnChannelBindTest001, TestSize.Level1)
{
    int32_t ret;
    const char *pkgName = TEST_PKG_NAME;
    int32_t pid = PID;
    int32_t channelId = CHANNELID;

    ret = TransTdcOnChannelBind(pkgName, pid, channelId);
    EXPECT_EQ(SOFTBUS_OK, ret);
}
}