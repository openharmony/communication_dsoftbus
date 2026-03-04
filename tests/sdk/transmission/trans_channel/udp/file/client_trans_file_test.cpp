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

#include <fcntl.h>
#include <gtest/gtest.h>
#include <securec.h>
#include <sys/stat.h>
#include <sys/types.h>

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
#define TEST_IP "192.168.1.1"
#define TEST_PORT 8888
#define TEST_SESSION_NAME "test.file.session"

namespace OHOS {

// Mock global callback structure
static UdpChannelMgrCb g_mockUdpChannelMgrCb;
static bool g_mockUdpChannelMgrCbInitialized = false;

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
    // Initialize mock callback
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
    g_mockUdpChannelMgrCbInitialized = true;
    RegisterFileCb(&g_mockUdpChannelMgrCb);
}

void ClientTransFileTest::TearDownTestCase(void)
{
    g_mockUdpChannelMgrCbInitialized = false;
}

// Helper function to create test UdpChannel
static UdpChannel* CreateTestUdpChannel()
{
    UdpChannel *channel = (UdpChannel *)SoftBusCalloc(sizeof(UdpChannel));
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

// Helper function to create test ChannelInfo
static ChannelInfo* CreateTestChannelInfo()
{
    ChannelInfo *channelInfo = (ChannelInfo *)SoftBusCalloc(sizeof(ChannelInfo));
    if (channelInfo == nullptr) {
        return nullptr;
    }
    channelInfo->channelId = TEST_CHANNEL_ID;
    channelInfo->isServer = true;
    channelInfo->enableMultipath = false;
    channelInfo->isMultiNeg = false;
    channelInfo->isUdpFile = true;
    static char myIp[] = "192.168.1.1";
    static char peerIp[] = "192.168.1.1";
    channelInfo->myIp = myIp;
    channelInfo->peerIp = peerIp;
    channelInfo->peerPort = TEST_PORT;
    channelInfo->sessionKey = const_cast<char *>("testSessionKey123");
    return channelInfo;
}

/*
 * @tc.name: RegisterFileCbTest001
 * @tc.desc: Test RegisterFileCb with nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransFileTest, RegisterFileCbTest001, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(RegisterFileCb(nullptr));
    EXPECT_NO_FATAL_FAILURE(RegisterFileCb(&g_mockUdpChannelMgrCb));
}

/*
 * @tc.name: RegisterFileCbTest002
 * @tc.desc: Test RegisterFileCb when already registered
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransFileTest, RegisterFileCbTest002, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(RegisterFileCb(&g_mockUdpChannelMgrCb));
    EXPECT_NO_FATAL_FAILURE(RegisterFileCb(&g_mockUdpChannelMgrCb));
}

/*
 * @tc.name: TransSendFileTest001
 * @tc.desc: Test TransSendFile with valid dfileId
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
 * @tc.desc: Test TransCloseFileChannel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransFileTest, TransCloseFileChannelTest001, TestSize.Level1)
{
    int32_t dfileId = TEST_DFILE_ID;

    EXPECT_NO_FATAL_FAILURE(TransCloseFileChannel(dfileId));
}

/*
 * @tc.name: TransCloseReserveFileChannelTest001
 * @tc.desc: Test TransCloseReserveFileChannel with null srvIp
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransFileTest, TransCloseReserveFileChannelTest002, TestSize.Level1)
{
    int32_t dfileId = TEST_DFILE_ID;
    int32_t srvPort = TEST_PORT;
    int32_t type = WIFI_STA;

    EXPECT_NO_FATAL_FAILURE(TransCloseReserveFileChannel(dfileId, nullptr, srvPort, type));
}

/*
 * @tc.name: NotifyTransLimitChangedTest001
 * @tc.desc: Test NotifyTransLimitChanged with valid channelId
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
 * @tc.desc: Test NotifyTransLimitChanged with invalid channelId
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

    SoftBusFree(channelInfo);
}

/*
 * @tc.name: TransOnFileChannelOpenedTest003
 * @tc.desc: Test TransOnFileChannelOpened as server with valid parameters
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
    EXPECT_CALL(mock, StartNStackXDFileServer(_, _, _, _, _))
        .WillOnce(Return(TEST_DFILE_ID));

    int32_t ret = TransOnFileChannelOpened(sessionName, channelInfo, &filePort, &accessInfo);
    EXPECT_EQ(TEST_DFILE_ID, ret);

    SoftBusFree(channelInfo);
}

/*
 * @tc.name: TransOnFileChannelOpenedTest004
 * @tc.desc: Test TransOnFileChannelOpened as client with valid parameters
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

    EXPECT_CALL(mock, StartNStackXDFileClient(_, _, _, _, _))
        .WillOnce(Return(TEST_DFILE_ID));

    int32_t ret = TransOnFileChannelOpened(sessionName, channelInfo, &filePort, &accessInfo);
    EXPECT_EQ(TEST_DFILE_ID, ret);

    SoftBusFree(channelInfo);
}

/*
 * @tc.name: TransOnFileChannelOpenedTest005
 * @tc.desc: Test TransOnFileChannelOpened with multipath enabled as server
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

    SoftBusFree(channelInfo);
}

/*
 * @tc.name: TransOnFileChannelOpenedTest006
 * @tc.desc: Test TransOnFileChannelOpened with multipath enabled as client
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

    SoftBusFree(channelInfo);
}

/*
 * @tc.name: RenameHookTest001
 * @tc.desc: Test RenameHook with null parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransFileTest, RenameHookTest001, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(RenameHook(nullptr));
    // Should not crash
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
    memset_s(&renamePara, sizeof(DFileRenamePara), 0, sizeof(DFileRenamePara));
    static char initFileNameBuf[NSTACKX_MAX_REMOTE_PATH_LEN];
    const char *initFileName = "/path/to/original_file.txt";
    strcpy_s(initFileNameBuf, NSTACKX_MAX_REMOTE_PATH_LEN, initFileName);
    renamePara.initFileName = initFileNameBuf;

    RenameHook(&renamePara);

    EXPECT_STREQ(initFileName, renamePara.newFileName);
}

/*
 * @tc.name: ConvertRouteToDFileLinkTypeTest001
 * @tc.desc: Test ConvertRouteToDFileLinkType with WIFI_USB
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransFileTest, ConvertRouteToDFileLinkTypeTest001, TestSize.Level1)
{
    DFileLinkType linkType = ConvertRouteToDFileLinkType(WIFI_USB);
    EXPECT_EQ(DFILE_LINK_WIRED, linkType);
}

/*
 * @tc.name: ConvertRouteToDFileLinkTypeTest002
 * @tc.desc: Test ConvertRouteToDFileLinkType with WIFI_STA
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransFileTest, ConvertRouteToDFileLinkTypeTest002, TestSize.Level1)
{
    DFileLinkType linkType = ConvertRouteToDFileLinkType(WIFI_STA);
    EXPECT_EQ(DFILE_LINK_WIRELESS, linkType);
}

/*
 * @tc.name: ConvertRouteToDFileLinkTypeTest003
 * @tc.desc: Test ConvertRouteToDFileLinkType with WIFI_P2P
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransFileTest, ConvertRouteToDFileLinkTypeTest003, TestSize.Level1)
{
    DFileLinkType linkType = ConvertRouteToDFileLinkType(WIFI_P2P);
    EXPECT_EQ(DFILE_LINK_WIRELESS, linkType);
}

/*
 * @tc.name: ConvertRouteToDFileLinkTypeTest004
 * @tc.desc: Test ConvertRouteToDFileLinkType with unknown type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransFileTest, ConvertRouteToDFileLinkTypeTest004, TestSize.Level1)
{
    DFileLinkType linkType = ConvertRouteToDFileLinkType(BT_SLE);
    EXPECT_EQ(DFILE_LINK_MAX, linkType);
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
    uint8_t tos = 0; // Low priority

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
 * @tc.name: TransOnFileChannelOpenedTest007
 * @tc.desc: Test TransOnFileChannelOpened with multipath second path as server
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
    EXPECT_CALL(mock, TransOnFileChannelServerAddSecondPath(_, _, _, _))
        .WillOnce(Return(TEST_DFILE_ID));

    int32_t ret = TransOnFileChannelOpened(sessionName, channelInfo, &filePort, &accessInfo);
    EXPECT_EQ(TEST_DFILE_ID, ret);

    SoftBusFree(channelInfo);
    SoftBusFree(linkedChannel);
}

/*
 * @tc.name: TransOnFileChannelOpenedTest008
 * @tc.desc: Test TransOnFileChannelOpened with multipath second path as client
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
    EXPECT_CALL(mock, TransOnFileChannelClientAddSecondPath(_, _, _))
        .WillOnce(Return(TEST_DFILE_ID));

    int32_t ret = TransOnFileChannelOpened(sessionName, channelInfo, &filePort, &accessInfo);
    EXPECT_EQ(TEST_DFILE_ID, ret);

    SoftBusFree(channelInfo);
    SoftBusFree(linkedChannel);
}

/*
 * @tc.name: TransOnFileChannelOpenedTest009
 * @tc.desc: Test TransOnFileChannelOpened when StartNStackXDFileServer fails
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
    EXPECT_CALL(mock, StartNStackXDFileServer(_, _, _, _, _))
        .WillOnce(Return(-1)); // Failure

    int32_t ret = TransOnFileChannelOpened(sessionName, channelInfo, &filePort, &accessInfo);
    EXPECT_EQ(SOFTBUS_FILE_ERR, ret);

    SoftBusFree(channelInfo);
}

/*
 * @tc.name: TransOnFileChannelOpenedTest010
 * @tc.desc: Test TransOnFileChannelOpened when StartNStackXDFileClient fails
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

    EXPECT_CALL(mock, StartNStackXDFileClient(_, _, _, _, _))
        .WillOnce(Return(-1)); // Failure

    int32_t ret = TransOnFileChannelOpened(sessionName, channelInfo, &filePort, &accessInfo);
    EXPECT_EQ(SOFTBUS_FILE_ERR, ret);

    SoftBusFree(channelInfo);
}

} // namespace OHOS
