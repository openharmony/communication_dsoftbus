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

#include "client_trans_file.c"
#include "mock/client_trans_file_mock.h"
#include "softbus_access_token_test.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"

using namespace testing;
using namespace testing::ext;

#define TEST_CHANNEL_ID 1049
#define TEST_SESSION_ID 1001
#define TEST_DFILE_ID 100
#define TEST_PORT 8888
#define TEST_SESSION_NAME "test.file.session"
#define TEST_MCAST_RATE 1024
#define TEST_MCAST_BYTES 4096
#define TEST_TOTAL_BYTES 6144

/* Fallback definitions for missing headers in unit test environment */
#ifndef TEST_IP_LEN_MAX
#define TEST_IP_LEN_MAX 46
#endif

#ifndef TEST_PROXY
#define TEST_PROXY 6
#endif

namespace OHOS {

static UdpChannelMgrCb g_mockUdpChannelMgrCb;

class ClientTransFileTest : public testing::Test {
public:
    ClientTransFileTest() {}
    ~ClientTransFileTest() {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override {}
    void TearDown() override {}
};

void ClientTransFileTest::SetUpTestCase(void)
{
    g_mockUdpChannelMgrCb.OnFileGetSessionId = [](int32_t channelId, int32_t *sessionId) -> int32_t {
        if (sessionId == nullptr) {
            return SOFTBUS_INVALID_PARAM;
        }
        *sessionId = TEST_SESSION_ID;
        return SOFTBUS_OK;
    };
    g_mockUdpChannelMgrCb.OnUdpChannelOpened = [](int32_t channelId, SocketAccessInfo *accessInfo) -> int32_t {
        return SOFTBUS_OK;
    };
    g_mockUdpChannelMgrCb.OnIdleTimeoutReset = [](int32_t sessionId) -> int32_t {
        return SOFTBUS_OK;
    };
    RegisterFileCb(&g_mockUdpChannelMgrCb);
}

void ClientTransFileTest::TearDownTestCase(void)
{
    RegisterFileCb(nullptr);
}

static UdpChannel* CreateTestUdpChannel(void)
{
    UdpChannel *channel = reinterpret_cast<UdpChannel *>(SoftBusCalloc(sizeof(UdpChannel)));
    if (channel == nullptr) {
        return nullptr;
    }
    channel->channelId = TEST_CHANNEL_ID;
    channel->dfileId = TEST_DFILE_ID;
    channel->sessionId = TEST_SESSION_ID;
    channel->businessType = BUSINESS_TYPE_FILE;
    channel->enableMultipath = false;
    channel->info.isServer = 0;
    (void)strcpy_s(channel->info.mySessionName, SESSION_NAME_SIZE_MAX, TEST_SESSION_NAME);
    (void)strcpy_s(channel->info.peerSessionName, SESSION_NAME_SIZE_MAX, "peer.session.name");
    (void)strcpy_s(channel->info.peerDeviceId, DEVICE_ID_SIZE_MAX, "ABC123DEF456");
    return channel;
}

static ChannelInfo* CreateTestChannelInfo(void)
{
    ChannelInfo *channelInfo = reinterpret_cast<ChannelInfo *>(SoftBusCalloc(sizeof(ChannelInfo)));
    if (channelInfo == nullptr) {
        return nullptr;
    }
    channelInfo->channelId = TEST_CHANNEL_ID;
    channelInfo->isServer = true;
    channelInfo->enableMultipath = false;
    channelInfo->isMultiNeg = false;
    channelInfo->isUdpFile = true;
    channelInfo->myIp = reinterpret_cast<char *>(SoftBusCalloc(TEST_IP_LEN_MAX));
    channelInfo->peerIp = reinterpret_cast<char *>(SoftBusCalloc(TEST_IP_LEN_MAX));
    if (channelInfo->myIp != nullptr) {
        (void)strcpy_s(channelInfo->myIp, TEST_IP_LEN_MAX, "192.168.1.1");
    }
    if (channelInfo->peerIp != nullptr) {
        (void)strcpy_s(channelInfo->peerIp, TEST_IP_LEN_MAX, "192.168.1.1");
    }
    channelInfo->peerPort = TEST_PORT;
    channelInfo->sessionKey = const_cast<char *>("testSessionKey123");
    return channelInfo;
}

static void FreeTestChannelInfo(ChannelInfo *channelInfo)
{
    if (channelInfo == nullptr) {
        return;
    }
    SoftBusFree(channelInfo->myIp);
    SoftBusFree(channelInfo->peerIp);
    SoftBusFree(channelInfo);
}

/*
 * @tc.name: RegisterFileCbTest001
 * @tc.desc: Test RegisterFileCb with nullptr unregisters callback safely
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransFileTest, RegisterFileCbTest001, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(RegisterFileCb(nullptr));
    EXPECT_NO_FATAL_FAILURE(RegisterFileCb(nullptr));

    EXPECT_NO_FATAL_FAILURE(RegisterFileCb(&g_mockUdpChannelMgrCb));
    EXPECT_NO_FATAL_FAILURE(RegisterFileCb(nullptr));
}

/*
 * @tc.name: RegisterFileCbTest002
 * @tc.desc: Test RegisterFileCb duplicate registration is ignored after initial setup
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransFileTest, RegisterFileCbTest002, TestSize.Level1)
{
    UdpChannelMgrCb duplicateCb = {0};
    duplicateCb.OnFileGetSessionId = g_mockUdpChannelMgrCb.OnFileGetSessionId;
    EXPECT_NO_FATAL_FAILURE(RegisterFileCb(&duplicateCb));
    EXPECT_NO_FATAL_FAILURE(RegisterFileCb(nullptr));
    EXPECT_NO_FATAL_FAILURE(RegisterFileCb(&g_mockUdpChannelMgrCb));
}

/*
 * @tc.name: TransSendFileTest001
 * @tc.desc: Test TransSendFile with valid dfileId and dFileList
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransFileTest, TransSendFileTest001, TestSize.Level1)
{
    int32_t dfileId = TEST_DFILE_ID;
    const char *sFileList[] = {"/path/to/file1.txt", "/path/to/file2.txt"};
    const char *dFileList[] = {"/dest/file1.txt", "/dest/file2.txt"};
    uint32_t fileCnt = 2;

    NiceMock<ClientTransFileInterfaceMock> mock;
    EXPECT_CALL(mock, NSTACKX_DFileSendFilesWithRemotePath(_, _, _, _, _))
        .WillOnce(Return(NSTACKX_EOK));

    int32_t ret = TransSendFile(dfileId, sFileList, dFileList, fileCnt);
    EXPECT_EQ(NSTACKX_EOK, ret);
}

/*
 * @tc.name: TransSendFileTest002
 * @tc.desc: Test TransSendFile with null dFileList
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransFileTest, TransSendFileTest002, TestSize.Level1)
{
    int32_t dfileId = TEST_DFILE_ID;
    const char *sFileList[] = {"/path/to/file1.txt"};
    uint32_t fileCnt = 1;

    NiceMock<ClientTransFileInterfaceMock> mock;
    EXPECT_CALL(mock, NSTACKX_DFileSendFiles(_, _, _, _))
        .WillOnce(Return(NSTACKX_EOK));

    int32_t ret = TransSendFile(dfileId, sFileList, nullptr, fileCnt);
    EXPECT_EQ(NSTACKX_EOK, ret);
}

/*
 * @tc.name: TransCloseFileChannelTest001
 * @tc.desc: Test TransCloseFileChannel with valid dfileId triggers close async
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransFileTest, TransCloseFileChannelTest001, TestSize.Level1)
{
    int32_t dfileId = TEST_DFILE_ID;
    EXPECT_NO_FATAL_FAILURE(TransCloseFileChannel(dfileId));
    int32_t invalidDfileId = -1;
    EXPECT_NO_FATAL_FAILURE(TransCloseFileChannel(invalidDfileId));
    EXPECT_NO_FATAL_FAILURE(TransCloseFileChannel(0));
}

/*
 * @tc.name: TransCloseReserveFileChannelTest001
 * @tc.desc: Test TransCloseReserveFileChannel with null addr handles safely
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransFileTest, TransCloseReserveFileChannelTest001, TestSize.Level1)
{
    int32_t dfileId = TEST_DFILE_ID;
    int32_t type = WIFI_STA;
    EXPECT_NO_FATAL_FAILURE(TransCloseReserveFileChannel(dfileId, nullptr, 0, type));
    EXPECT_NO_FATAL_FAILURE(TransCloseReserveFileChannel(0, nullptr, 0, type));
    EXPECT_NO_FATAL_FAILURE(TransCloseReserveFileChannel(dfileId, nullptr, 0, WIFI_P2P));
}

/*
 * @tc.name: NotifyTransLimitChangedTest001
 * @tc.desc: Test NotifyTransLimitChanged with valid channelId and FILE_PRIORITY_BE
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransFileTest, NotifyTransLimitChangedTest001, TestSize.Level1)
{
    int32_t channelId = TEST_CHANNEL_ID;
    uint8_t tos = FILE_PRIORITY_BE;

    NiceMock<ClientTransFileInterfaceMock> mock;

    EXPECT_CALL(mock, ClientGetSessionNameByChannelId(_, CHANNEL_TYPE_UDP, _, _))
        .WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, TransGetFileListener(_, _))
        .WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, ClientGetSessionIdByChannelId(_, CHANNEL_TYPE_UDP, _, false))
        .WillOnce(DoAll(SetArgPointee<2>(TEST_SESSION_ID), Return(SOFTBUS_OK)));

    int32_t ret = NotifyTransLimitChanged(channelId, tos);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: NotifyTransLimitChangedTest002
 * @tc.desc: Test NotifyTransLimitChanged when ClientGetSessionNameByChannelId fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransFileTest, NotifyTransLimitChangedTest002, TestSize.Level1)
{
    int32_t channelId = TEST_CHANNEL_ID;
    uint8_t tos = FILE_PRIORITY_BE;

    NiceMock<ClientTransFileInterfaceMock> mock;

    EXPECT_CALL(mock, ClientGetSessionNameByChannelId(_, CHANNEL_TYPE_UDP, _, _))
        .WillOnce(Return(SOFTBUS_TRANS_FILE_LISTENER_NOT_INIT));

    int32_t ret = NotifyTransLimitChanged(channelId, tos);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/*
 * @tc.name: NotifyTransLimitChangedTest003
 * @tc.desc: Test NotifyTransLimitChanged with FILE_PRIORITY_LOW
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransFileTest, NotifyTransLimitChangedTest003, TestSize.Level1)
{
    int32_t channelId = TEST_CHANNEL_ID;
    uint8_t tos = 0;

    NiceMock<ClientTransFileInterfaceMock> mock;

    EXPECT_CALL(mock, ClientGetSessionNameByChannelId(_, CHANNEL_TYPE_UDP, _, _))
        .WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, TransGetFileListener(_, _))
        .WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, ClientGetSessionIdByChannelId(_, CHANNEL_TYPE_UDP, _, false))
        .WillOnce(DoAll(SetArgPointee<2>(TEST_SESSION_ID), Return(SOFTBUS_OK)));

    int32_t ret = NotifyTransLimitChanged(channelId, tos);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: TransOnFileChannelOpenedTest001
 * @tc.desc: Test TransOnFileChannelOpened with null channel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransFileTest, TransOnFileChannelOpenedTest001, TestSize.Level1)
{
    const char *sessionName = TEST_SESSION_NAME;
    int32_t filePort = TEST_PORT;
    SocketAccessInfo accessInfo = {0};

    int32_t ret = TransOnFileChannelOpened(sessionName, nullptr, &filePort, &accessInfo);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: TransOnFileChannelOpenedTest002
 * @tc.desc: Test TransOnFileChannelOpened with null filePort
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransFileTest, TransOnFileChannelOpenedTest002, TestSize.Level1)
{
    const char *sessionName = TEST_SESSION_NAME;
    ChannelInfo *channelInfo = CreateTestChannelInfo();
    ASSERT_NE(channelInfo, nullptr);
    SocketAccessInfo accessInfo = {0};

    int32_t ret = TransOnFileChannelOpened(sessionName, channelInfo, nullptr, &accessInfo);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    FreeTestChannelInfo(channelInfo);
}

/*
 * @tc.name: TransOnFileChannelOpenedTest003
 * @tc.desc: Test TransOnFileChannelOpened as server without multipath
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransFileTest, TransOnFileChannelOpenedTest003, TestSize.Level1)
{
    const char *sessionName = TEST_SESSION_NAME;
    ChannelInfo *channelInfo = CreateTestChannelInfo();
    ASSERT_NE(channelInfo, nullptr);
    channelInfo->isServer = true;
    channelInfo->enableMultipath = false;
    int32_t filePort = TEST_PORT;
    SocketAccessInfo accessInfo = {0};

    NiceMock<ClientTransFileInterfaceMock> mock;

    EXPECT_CALL(mock, TransGetFileListener(_, _))
        .WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, StartNStackXDFileServer(_, _, _, _))
        .WillOnce(Return(TEST_DFILE_ID));

    int32_t ret = TransOnFileChannelOpened(sessionName, channelInfo, &filePort, &accessInfo);
    EXPECT_EQ(TEST_DFILE_ID, ret);

    FreeTestChannelInfo(channelInfo);
}

/*
 * @tc.name: TransOnFileChannelOpenedTest004
 * @tc.desc: Test TransOnFileChannelOpened as client without multipath
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransFileTest, TransOnFileChannelOpenedTest004, TestSize.Level1)
{
    const char *sessionName = TEST_SESSION_NAME;
    ChannelInfo *channelInfo = CreateTestChannelInfo();
    ASSERT_NE(channelInfo, nullptr);
    channelInfo->isServer = false;
    channelInfo->enableMultipath = false;
    int32_t filePort = TEST_PORT;
    SocketAccessInfo accessInfo = {0};

    NiceMock<ClientTransFileInterfaceMock> mock;

    EXPECT_CALL(mock, StartNStackXDFileClient(_, _, _))
        .WillOnce(Return(TEST_DFILE_ID));

    int32_t ret = TransOnFileChannelOpened(sessionName, channelInfo, &filePort, &accessInfo);
    EXPECT_EQ(TEST_DFILE_ID, ret);

    FreeTestChannelInfo(channelInfo);
}

/*
 * @tc.name: TransOnFileChannelOpenedTest005
 * @tc.desc: Test TransOnFileChannelOpened as server with multipath enabled (first path)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransFileTest, TransOnFileChannelOpenedTest005, TestSize.Level1)
{
    const char *sessionName = TEST_SESSION_NAME;
    ChannelInfo *channelInfo = CreateTestChannelInfo();
    ASSERT_NE(channelInfo, nullptr);
    channelInfo->isServer = true;
    channelInfo->enableMultipath = true;
    channelInfo->isMultiNeg = false;
    channelInfo->linkType = WIFI_P2P;
    int32_t filePort = TEST_PORT;
    SocketAccessInfo accessInfo = {0};

    NiceMock<ClientTransFileInterfaceMock> mock;

    EXPECT_CALL(mock, TransGetFileListener(_, _))
        .WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, StartNStackXDFileServerV2(_, _, _, _, _, _))
        .WillOnce(Return(TEST_DFILE_ID));

    int32_t ret = TransOnFileChannelOpened(sessionName, channelInfo, &filePort, &accessInfo);
    EXPECT_EQ(TEST_DFILE_ID, ret);

    FreeTestChannelInfo(channelInfo);
}

/*
 * @tc.name: TransOnFileChannelOpenedTest006
 * @tc.desc: Test TransOnFileChannelOpened as client with multipath enabled (first path)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransFileTest, TransOnFileChannelOpenedTest006, TestSize.Level1)
{
    const char *sessionName = TEST_SESSION_NAME;
    ChannelInfo *channelInfo = CreateTestChannelInfo();
    ASSERT_NE(channelInfo, nullptr);
    channelInfo->isServer = false;
    channelInfo->enableMultipath = true;
    channelInfo->isMultiNeg = false;
    channelInfo->linkType = WIFI_P2P;
    int32_t filePort = TEST_PORT;
    SocketAccessInfo accessInfo = {0};

    NiceMock<ClientTransFileInterfaceMock> mock;

    EXPECT_CALL(mock, StartNStackXDFileClientV2(_, _, _, _, _, _))
        .WillOnce(Return(TEST_DFILE_ID));

    int32_t ret = TransOnFileChannelOpened(sessionName, channelInfo, &filePort, &accessInfo);
    EXPECT_EQ(TEST_DFILE_ID, ret);

    FreeTestChannelInfo(channelInfo);
}

/*
 * @tc.name: TransOnFileChannelOpenedTest007
 * @tc.desc: Test TransOnFileChannelOpened as server with multipath second path
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransFileTest, TransOnFileChannelOpenedTest007, TestSize.Level1)
{
    const char *sessionName = TEST_SESSION_NAME;
    ChannelInfo *channelInfo = CreateTestChannelInfo();
    ASSERT_NE(channelInfo, nullptr);
    channelInfo->isServer = true;
    channelInfo->enableMultipath = true;
    channelInfo->isMultiNeg = true;
    channelInfo->linkedChannelId = TEST_CHANNEL_ID + 1;
    channelInfo->linkType = WIFI_P2P;
    int32_t filePort = TEST_PORT;
    SocketAccessInfo accessInfo = {0};

    NiceMock<ClientTransFileInterfaceMock> mock;

    UdpChannel *linkedChannel = CreateTestUdpChannel();
    ASSERT_NE(linkedChannel, nullptr);
    linkedChannel->dfileId = TEST_DFILE_ID;

    EXPECT_CALL(mock, TransGetFileListener(_, _))
        .WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, TransGetUdpChannel(_, _))
        .WillOnce(DoAll(SetArgPointee<1>(*linkedChannel), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, DFileServerAddSecondPath(_, _, _, _))
        .WillOnce(Return(TEST_DFILE_ID));

    int32_t ret = TransOnFileChannelOpened(sessionName, channelInfo, &filePort, &accessInfo);
    EXPECT_EQ(TEST_DFILE_ID, ret);

    FreeTestChannelInfo(channelInfo);
    SoftBusFree(linkedChannel);
}

/*
 * @tc.name: TransOnFileChannelOpenedTest008
 * @tc.desc: Test TransOnFileChannelOpened as client with multipath second path
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransFileTest, TransOnFileChannelOpenedTest008, TestSize.Level1)
{
    const char *sessionName = TEST_SESSION_NAME;
    ChannelInfo *channelInfo = CreateTestChannelInfo();
    ASSERT_NE(channelInfo, nullptr);
    channelInfo->isServer = false;
    channelInfo->enableMultipath = true;
    channelInfo->isMultiNeg = true;
    channelInfo->linkedChannelId = TEST_CHANNEL_ID + 1;
    channelInfo->linkType = WIFI_P2P;
    int32_t filePort = TEST_PORT;
    SocketAccessInfo accessInfo = {0};

    NiceMock<ClientTransFileInterfaceMock> mock;

    UdpChannel *linkedChannel = CreateTestUdpChannel();
    ASSERT_NE(linkedChannel, nullptr);
    linkedChannel->dfileId = TEST_DFILE_ID;

    EXPECT_CALL(mock, TransGetUdpChannel(_, _))
        .WillOnce(DoAll(SetArgPointee<1>(*linkedChannel), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, DFileClientAddSecondPath(_, _, _))
        .WillOnce(Return(TEST_DFILE_ID));

    int32_t ret = TransOnFileChannelOpened(sessionName, channelInfo, &filePort, &accessInfo);
    EXPECT_EQ(TEST_DFILE_ID, ret);

    FreeTestChannelInfo(channelInfo);
    SoftBusFree(linkedChannel);
}

/*
 * @tc.name: TransOnFileChannelOpenedTest009
 * @tc.desc: Test TransOnFileChannelOpened as server when StartNStackXDFileServer fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransFileTest, TransOnFileChannelOpenedTest009, TestSize.Level1)
{
    const char *sessionName = TEST_SESSION_NAME;
    ChannelInfo *channelInfo = CreateTestChannelInfo();
    ASSERT_NE(channelInfo, nullptr);
    channelInfo->isServer = true;
    channelInfo->enableMultipath = false;
    int32_t filePort = TEST_PORT;
    SocketAccessInfo accessInfo = {0};

    NiceMock<ClientTransFileInterfaceMock> mock;

    EXPECT_CALL(mock, TransGetFileListener(_, _))
        .WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, StartNStackXDFileServer(_, _, _, _))
        .WillOnce(Return(-1));

    int32_t ret = TransOnFileChannelOpened(sessionName, channelInfo, &filePort, &accessInfo);
    EXPECT_EQ(SOFTBUS_FILE_ERR, ret);

    FreeTestChannelInfo(channelInfo);
}

/*
 * @tc.name: TransOnFileChannelOpenedTest010
 * @tc.desc: Test TransOnFileChannelOpened as client when StartNStackXDFileClient fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransFileTest, TransOnFileChannelOpenedTest010, TestSize.Level1)
{
    const char *sessionName = TEST_SESSION_NAME;
    ChannelInfo *channelInfo = CreateTestChannelInfo();
    ASSERT_NE(channelInfo, nullptr);
    channelInfo->isServer = false;
    channelInfo->enableMultipath = false;
    int32_t filePort = TEST_PORT;
    SocketAccessInfo accessInfo = {0};

    NiceMock<ClientTransFileInterfaceMock> mock;

    EXPECT_CALL(mock, StartNStackXDFileClient(_, _, _))
        .WillOnce(Return(-1));

    int32_t ret = TransOnFileChannelOpened(sessionName, channelInfo, &filePort, &accessInfo);
    EXPECT_EQ(SOFTBUS_FILE_ERR, ret);

    FreeTestChannelInfo(channelInfo);
}

/*
 * @tc.name: TransOnFileChannelOpenedTest011
 * @tc.desc: Test TransOnFileChannelOpened as server when TransGetFileListener fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransFileTest, TransOnFileChannelOpenedTest011, TestSize.Level1)
{
    const char *sessionName = TEST_SESSION_NAME;
    ChannelInfo *channelInfo = CreateTestChannelInfo();
    ASSERT_NE(channelInfo, nullptr);
    channelInfo->isServer = true;
    channelInfo->enableMultipath = false;
    int32_t filePort = TEST_PORT;
    SocketAccessInfo accessInfo = {0};

    NiceMock<ClientTransFileInterfaceMock> mock;

    EXPECT_CALL(mock, TransGetFileListener(_, _))
        .WillOnce(Return(SOFTBUS_TRANS_FILE_LISTENER_NOT_INIT));

    int32_t ret = TransOnFileChannelOpened(sessionName, channelInfo, &filePort, &accessInfo);
    EXPECT_EQ(SOFTBUS_TRANS_FILE_LISTENER_NOT_INIT, ret);

    FreeTestChannelInfo(channelInfo);
}

/*
 * @tc.name: TransOnFileChannelOpenedTest012
 * @tc.desc: Test TransOnFileChannelOpened as server with multipath when TransGetUdpChannel fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransFileTest, TransOnFileChannelOpenedTest012, TestSize.Level1)
{
    const char *sessionName = TEST_SESSION_NAME;
    ChannelInfo *channelInfo = CreateTestChannelInfo();
    ASSERT_NE(channelInfo, nullptr);
    channelInfo->isServer = true;
    channelInfo->enableMultipath = true;
    channelInfo->isMultiNeg = true;
    channelInfo->linkedChannelId = TEST_CHANNEL_ID + 1;
    channelInfo->linkType = WIFI_P2P;
    int32_t filePort = TEST_PORT;
    SocketAccessInfo accessInfo = {0};

    NiceMock<ClientTransFileInterfaceMock> mock;

    EXPECT_CALL(mock, TransGetFileListener(_, _))
        .WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, TransGetUdpChannel(_, _))
        .WillOnce(Return(SOFTBUS_TRANS_UDP_CHANNEL_NOT_FOUND));

    int32_t ret = TransOnFileChannelOpened(sessionName, channelInfo, &filePort, &accessInfo);
    EXPECT_EQ(SOFTBUS_FILE_ERR, ret);

    FreeTestChannelInfo(channelInfo);
}

/*
 * @tc.name: TransOnFileChannelOpenedTest013
 * @tc.desc: Test TransOnFileChannelOpened as server with multipath when DFileServerAddSecondPath fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransFileTest, TransOnFileChannelOpenedTest013, TestSize.Level1)
{
    const char *sessionName = TEST_SESSION_NAME;
    ChannelInfo *channelInfo = CreateTestChannelInfo();
    ASSERT_NE(channelInfo, nullptr);
    channelInfo->isServer = true;
    channelInfo->enableMultipath = true;
    channelInfo->isMultiNeg = true;
    channelInfo->linkedChannelId = TEST_CHANNEL_ID + 1;
    channelInfo->linkType = WIFI_P2P;
    int32_t filePort = TEST_PORT;
    SocketAccessInfo accessInfo = {0};

    NiceMock<ClientTransFileInterfaceMock> mock;

    UdpChannel *linkedChannel = CreateTestUdpChannel();
    ASSERT_NE(linkedChannel, nullptr);
    linkedChannel->dfileId = TEST_DFILE_ID;

    EXPECT_CALL(mock, TransGetFileListener(_, _))
        .WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, TransGetUdpChannel(_, _))
        .WillOnce(DoAll(SetArgPointee<1>(*linkedChannel), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, DFileServerAddSecondPath(_, _, _, _))
        .WillOnce(Return(-1));

    int32_t ret = TransOnFileChannelOpened(sessionName, channelInfo, &filePort, &accessInfo);
    EXPECT_EQ(SOFTBUS_FILE_ERR, ret);

    FreeTestChannelInfo(channelInfo);
    SoftBusFree(linkedChannel);
}

/*
 * @tc.name: TransOnFileChannelOpenedTest014
 * @tc.desc: Test TransOnFileChannelOpened as client with multipath when DFileClientAddSecondPath fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransFileTest, TransOnFileChannelOpenedTest014, TestSize.Level1)
{
    const char *sessionName = TEST_SESSION_NAME;
    ChannelInfo *channelInfo = CreateTestChannelInfo();
    ASSERT_NE(channelInfo, nullptr);
    channelInfo->isServer = false;
    channelInfo->enableMultipath = true;
    channelInfo->isMultiNeg = true;
    channelInfo->linkedChannelId = TEST_CHANNEL_ID + 1;
    channelInfo->linkType = WIFI_P2P;
    int32_t filePort = TEST_PORT;
    SocketAccessInfo accessInfo = {0};

    NiceMock<ClientTransFileInterfaceMock> mock;

    UdpChannel *linkedChannel = CreateTestUdpChannel();
    ASSERT_NE(linkedChannel, nullptr);
    linkedChannel->dfileId = TEST_DFILE_ID;

    EXPECT_CALL(mock, TransGetUdpChannel(_, _))
        .WillOnce(DoAll(SetArgPointee<1>(*linkedChannel), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, DFileClientAddSecondPath(_, _, _))
        .WillOnce(Return(-1));

    int32_t ret = TransOnFileChannelOpened(sessionName, channelInfo, &filePort, &accessInfo);
    EXPECT_EQ(SOFTBUS_FILE_ERR, ret);

    FreeTestChannelInfo(channelInfo);
    SoftBusFree(linkedChannel);
}

/*
 * @tc.name: RenameHookTest001
 * @tc.desc: Test RenameHook with null parameter handles gracefully
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransFileTest, RenameHookTest001, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(RenameHook(nullptr));
    EXPECT_NO_FATAL_FAILURE(RenameHook(nullptr));
    char emptyBuf[NSTACKX_MAX_REMOTE_PATH_LEN] = {0};
    DFileRenamePara renamePara;
    (void)memset_s(&renamePara, sizeof(DFileRenamePara), 0, sizeof(DFileRenamePara));
    renamePara.initFileName = emptyBuf;
    EXPECT_NO_FATAL_FAILURE(RenameHook(&renamePara));
}

/*
 * @tc.name: RenameHookTest002
 * @tc.desc: Test RenameHook with valid parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransFileTest, RenameHookTest002, TestSize.Level1)
{
    DFileRenamePara renamePara;
    (void)memset_s(&renamePara, sizeof(DFileRenamePara), 0, sizeof(DFileRenamePara));
    char initFileNameBuf[NSTACKX_MAX_REMOTE_PATH_LEN] = {0};
    const char *initFileName = "/path/to/original_file.txt";
    (void)strcpy_s(initFileNameBuf, NSTACKX_MAX_REMOTE_PATH_LEN, initFileName);
    renamePara.initFileName = initFileNameBuf;

    RenameHook(&renamePara);

    EXPECT_STREQ(initFileName, renamePara.newFileName);
}

/*
 * @tc.name: ConvertRouteToDFileLinkTypeTest001
 * @tc.desc: Test ConvertRouteToDFileLinkType with WIFI_USB returns DFILE_LINK_WIRED
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransFileTest, ConvertRouteToDFileLinkTypeTest001, TestSize.Level1)
{
    RouteType routeType = WIFI_USB;
    DFileLinkType linkType = ConvertRouteToDFileLinkType(routeType);
    EXPECT_EQ(DFILE_LINK_WIRED, linkType);
    EXPECT_NE(DFILE_LINK_WIRELESS, linkType);
    EXPECT_NE(DFILE_LINK_MAX, linkType);
}

/*
 * @tc.name: ConvertRouteToDFileLinkTypeTest002
 * @tc.desc: Test ConvertRouteToDFileLinkType with WIFI_STA returns DFILE_LINK_WIRELESS
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransFileTest, ConvertRouteToDFileLinkTypeTest002, TestSize.Level1)
{
    RouteType routeType = WIFI_STA;
    DFileLinkType linkType = ConvertRouteToDFileLinkType(routeType);
    EXPECT_EQ(DFILE_LINK_WIRELESS, linkType);
    EXPECT_NE(DFILE_LINK_WIRED, linkType);
    EXPECT_NE(DFILE_LINK_MAX, linkType);
}

/*
 * @tc.name: ConvertRouteToDFileLinkTypeTest003
 * @tc.desc: Test ConvertRouteToDFileLinkType with WIFI_P2P returns DFILE_LINK_WIRELESS
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransFileTest, ConvertRouteToDFileLinkTypeTest003, TestSize.Level1)
{
    RouteType routeType = WIFI_P2P;
    DFileLinkType linkType = ConvertRouteToDFileLinkType(routeType);
    EXPECT_EQ(DFILE_LINK_WIRELESS, linkType);
    EXPECT_NE(DFILE_LINK_WIRED, linkType);
    EXPECT_NE(DFILE_LINK_MAX, linkType);
}

/*
 * @tc.name: ConvertRouteToDFileLinkTypeTest004
 * @tc.desc: Test ConvertRouteToDFileLinkType with BT_SLE returns DFILE_LINK_MAX
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransFileTest, ConvertRouteToDFileLinkTypeTest004, TestSize.Level1)
{
    RouteType routeType = BT_SLE;
    DFileLinkType linkType = ConvertRouteToDFileLinkType(routeType);
    EXPECT_EQ(DFILE_LINK_MAX, linkType);
    EXPECT_NE(DFILE_LINK_WIRED, linkType);
    EXPECT_NE(DFILE_LINK_WIRELESS, linkType);
}

/*
 * @tc.name: ConvertRouteToDFileLinkTypeTest005
 * @tc.desc: Test ConvertRouteToDFileLinkType with TEST_PROXY returns DFILE_LINK_MAX
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransFileTest, ConvertRouteToDFileLinkTypeTest005, TestSize.Level1)
{
    RouteType routeType = static_cast<RouteType>(TEST_PROXY);
    DFileLinkType linkType = ConvertRouteToDFileLinkType(routeType);
    EXPECT_EQ(DFILE_LINK_MAX, linkType);
    EXPECT_NE(DFILE_LINK_WIRED, linkType);
    EXPECT_NE(DFILE_LINK_WIRELESS, linkType);
}

static FileEvent *g_currentCapturedFileEvent = nullptr;
static bool *g_currentFileEventCaptured = nullptr;

static void MockSocketSendCallback(int32_t socket, FileEvent *event)
{
    if (event != nullptr && g_currentCapturedFileEvent != nullptr && g_currentFileEventCaptured != nullptr) {
        *g_currentCapturedFileEvent = *event;
        *g_currentFileEventCaptured = true;
    }
}

/*
 * @tc.name: ReportMcastDfxEventTest001
 * @tc.desc: Test ReportMcastDfxEvent emits DFX when mcastRate != 0
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransFileTest, ReportMcastDfxEventTest001, TestSize.Level1)
{
    ResetTransEventState();

    DFileMsg msgData;
    (void)memset_s(&msgData, sizeof(DFileMsg), 0, sizeof(DFileMsg));
    msgData.transferUpdate.bytesTransferred = TEST_TOTAL_BYTES;
    msgData.transferUpdate.mcastBytesTransferred = TEST_MCAST_BYTES;
    msgData.mcastRate = TEST_MCAST_RATE;

    ReportMcastDfxEvent(TEST_SESSION_ID, &msgData);

    EXPECT_TRUE(IsTransEventCalled());
    TransEventExtra extra = GetLastTransEventExtra();
    EXPECT_EQ(extra.sessionId, TEST_SESSION_ID);
    EXPECT_EQ(extra.multicastRate, static_cast<uint32_t>(TEST_MCAST_RATE));
    EXPECT_EQ(extra.multicastBytes, static_cast<uint64_t>(TEST_MCAST_BYTES));
}

/*
 * @tc.name: ReportMcastDfxEventTest002
 * @tc.desc: Test ReportMcastDfxEvent does not emit DFX when mcastRate == 0
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransFileTest, ReportMcastDfxEventTest002, TestSize.Level1)
{
    ResetTransEventState();

    DFileMsg msgData;
    (void)memset_s(&msgData, sizeof(DFileMsg), 0, sizeof(DFileMsg));
    msgData.mcastRate = 0;

    ReportMcastDfxEvent(TEST_SESSION_ID, &msgData);

    EXPECT_FALSE(IsTransEventCalled());
}

/*
 * @tc.name: NotifySocketSendResultMcastTest001
 * @tc.desc: Test NotifySocketSendResult sets multicast fields and emits DFX when mcastRate != 0
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransFileTest, NotifySocketSendResultMcastTest001, TestSize.Level1)
{
    FileEvent capturedFileEvent;
    bool fileEventCaptured = false;
    (void)memset_s(&capturedFileEvent, sizeof(FileEvent), 0, sizeof(FileEvent));
    g_currentCapturedFileEvent = &capturedFileEvent;
    g_currentFileEventCaptured = &fileEventCaptured;
    ResetTransEventState();

    NiceMock<ClientTransFileInterfaceMock> mock;

    DFileMsg msgData;
    (void)memset_s(&msgData, sizeof(DFileMsg), 0, sizeof(DFileMsg));
    msgData.transferUpdate.bytesTransferred = TEST_TOTAL_BYTES;
    msgData.transferUpdate.totalBytes = TEST_TOTAL_BYTES * 2;
    msgData.transferUpdate.mcastBytesTransferred = TEST_MCAST_BYTES;
    msgData.mcastRate = TEST_MCAST_RATE;
    msgData.errorCode = NSTACKX_EOK;

    FileListener listener;
    (void)memset_s(&listener, sizeof(FileListener), 0, sizeof(FileListener));
    listener.socketSendCallback = MockSocketSendCallback;

    NotifySocketSendResult(TEST_SESSION_ID, DFILE_ON_FILE_SEND_SUCCESS, &msgData, &listener);

    EXPECT_TRUE(fileEventCaptured);
    EXPECT_EQ(capturedFileEvent.type, FILE_EVENT_SEND_FINISH);
    EXPECT_EQ(capturedFileEvent.multicastRate, static_cast<uint32_t>(TEST_MCAST_RATE));
    EXPECT_EQ(capturedFileEvent.multicastBytesProcessed, static_cast<uint64_t>(TEST_MCAST_BYTES));

    EXPECT_TRUE(IsTransEventCalled());
    TransEventExtra extra = GetLastTransEventExtra();
    EXPECT_EQ(extra.multicastRate, static_cast<uint32_t>(TEST_MCAST_RATE));
    EXPECT_EQ(extra.multicastBytes, static_cast<uint64_t>(TEST_MCAST_BYTES));

    g_currentCapturedFileEvent = nullptr;
    g_currentFileEventCaptured = nullptr;
}

/*
 * @tc.name: NotifySocketSendResultMcastTest002
 * @tc.desc: Test NotifySocketSendResult multicast fields with zero mcastRate, no DFX event emitted
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransFileTest, NotifySocketSendResultMcastTest002, TestSize.Level1)
{
    FileEvent capturedFileEvent;
    bool fileEventCaptured = false;
    (void)memset_s(&capturedFileEvent, sizeof(FileEvent), 0, sizeof(FileEvent));
    g_currentCapturedFileEvent = &capturedFileEvent;
    g_currentFileEventCaptured = &fileEventCaptured;
    ResetTransEventState();

    NiceMock<ClientTransFileInterfaceMock> mock;

    DFileMsg msgData;
    (void)memset_s(&msgData, sizeof(DFileMsg), 0, sizeof(DFileMsg));
    msgData.transferUpdate.bytesTransferred = TEST_TOTAL_BYTES;
    msgData.transferUpdate.totalBytes = TEST_TOTAL_BYTES * 2;
    msgData.transferUpdate.mcastBytesTransferred = 0;
    msgData.mcastRate = 0;
    msgData.errorCode = NSTACKX_EOK;

    FileListener listener;
    (void)memset_s(&listener, sizeof(FileListener), 0, sizeof(FileListener));
    listener.socketSendCallback = MockSocketSendCallback;

    NotifySocketSendResult(TEST_SESSION_ID, DFILE_ON_FILE_SEND_SUCCESS, &msgData, &listener);

    EXPECT_TRUE(fileEventCaptured);
    EXPECT_EQ(capturedFileEvent.type, FILE_EVENT_SEND_FINISH);
    EXPECT_EQ(capturedFileEvent.multicastRate, static_cast<uint32_t>(0));
    EXPECT_EQ(capturedFileEvent.multicastBytesProcessed, static_cast<uint64_t>(0));

    EXPECT_FALSE(IsTransEventCalled());

    g_currentCapturedFileEvent = nullptr;
    g_currentFileEventCaptured = nullptr;
}

/*
 * @tc.name: FileSendListenerExMcastTest001
 * @tc.desc: Test FileSendListenerEx routes DFILE_ON_FILE_SEND_SUCCESS to listener notification + multicast DFX
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransFileTest, FileSendListenerExMcastTest001, TestSize.Level1)
{
    FileEvent capturedFileEvent;
    bool fileEventCaptured = false;
    (void)memset_s(&capturedFileEvent, sizeof(FileEvent), 0, sizeof(FileEvent));
    g_currentCapturedFileEvent = &capturedFileEvent;
    g_currentFileEventCaptured = &fileEventCaptured;
    ResetTransEventState();

    NiceMock<ClientTransFileInterfaceMock> mock;

    UdpChannel *udpChannel = CreateTestUdpChannel();
    ASSERT_NE(udpChannel, nullptr);
    udpChannel->channelId = TEST_CHANNEL_ID;
    (void)strcpy_s(udpChannel->info.mySessionName, SESSION_NAME_SIZE_MAX, TEST_SESSION_NAME);
    (void)strcpy_s(udpChannel->info.peerDeviceId, DEVICE_ID_SIZE_MAX, "testPeerDeviceId");

    FileListener fileListener;
    (void)memset_s(&fileListener, sizeof(FileListener), 0, sizeof(FileListener));
    fileListener.socketSendCallback = MockSocketSendCallback;
    EXPECT_CALL(mock, TransGetFileListener(_, _))
        .WillOnce(DoAll(SetArgPointee<1>(fileListener), Return(SOFTBUS_OK)));

    DFileMsg msgData;
    (void)memset_s(&msgData, sizeof(DFileMsg), 0, sizeof(DFileMsg));
    msgData.transferUpdate.bytesTransferred = TEST_TOTAL_BYTES;
    msgData.transferUpdate.totalBytes = TEST_TOTAL_BYTES * 2;
    msgData.transferUpdate.mcastBytesTransferred = TEST_MCAST_BYTES;
    msgData.mcastRate = TEST_MCAST_RATE;
    msgData.errorCode = NSTACKX_EOK;

    FileSendListenerEx(udpChannel, DFILE_ON_FILE_SEND_SUCCESS, &msgData);

    EXPECT_TRUE(IsTransEventCalled());
    TransEventExtra extra = GetLastTransEventExtra();
    EXPECT_EQ(extra.multicastRate, static_cast<uint32_t>(TEST_MCAST_RATE));
    EXPECT_EQ(extra.multicastBytes, static_cast<uint64_t>(TEST_MCAST_BYTES));

    EXPECT_TRUE(fileEventCaptured);
    EXPECT_EQ(capturedFileEvent.type, FILE_EVENT_SEND_FINISH);

    g_currentCapturedFileEvent = nullptr;
    g_currentFileEventCaptured = nullptr;

    SoftBusFree(udpChannel);
}

/*
 * @tc.name: NotifySendRateNullParamTest001
 * @tc.desc: Test NotifySendRate with null udpChannel parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransFileTest, NotifySendRateNullParamTest001, TestSize.Level1)
{
    ResetTransEventState();

    DFileMsg msgData;
    (void)memset_s(&msgData, sizeof(DFileMsg), 0, sizeof(DFileMsg));

    NotifySendRate(nullptr, DFILE_ON_SESSION_TRANSFER_RATE, &msgData);
    EXPECT_FALSE(IsTransEventCalled());
}

/*
 * @tc.name: NotifySendRateNullParamTest002
 * @tc.desc: Test NotifySendRate with null msgData parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransFileTest, NotifySendRateNullParamTest002, TestSize.Level1)
{
    ResetTransEventState();

    UdpChannel *udpChannel = CreateTestUdpChannel();
    ASSERT_NE(udpChannel, nullptr);
    NotifySendRate(udpChannel, DFILE_ON_SESSION_TRANSFER_RATE, nullptr);
    EXPECT_FALSE(IsTransEventCalled());

    SoftBusFree(udpChannel);
}
} // namespace OHOS
