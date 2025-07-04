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
#include "securec.h"
#include <sys/stat.h>
#include <sys/types.h>

#include "client_trans_proxy_file_manager.c"
#include "trans_client_proxy_file_manager_mock.h"
#include "client_trans_proxy_manager.c"
#include "softbus_access_token_test.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "trans_proxy_process_data.h"

using namespace testing;
using namespace testing::ext;

#define TEST_CHANNEL_ID 1049
#define TEST_IS_ENCRYPTED 1
#define TEST_LINK_TYPE 11
#define TEST_OS_TYPE 10
#define TEST_SEQ 1234
#define TEST_DATA_LENGTH 9
#define TEST_DATA "testdata"

static const char *TEST_SESSION_NAME = "test.trans.proxy.demo";

namespace OHOS {

class TransClientProxyFileManagerMockTest : public testing::Test {
public:
    TransClientProxyFileManagerMockTest() {}
    ~TransClientProxyFileManagerMockTest() {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override {}
    void TearDown() override {}
};

void TransClientProxyFileManagerMockTest::SetUpTestCase(void)
{
}

void TransClientProxyFileManagerMockTest::TearDownTestCase(void)
{
}

static int32_t TestOnSessionClosed(int32_t channelId, int32_t channelType, ShutdownReason reason)
{
    (void)channelId;
    (void)channelType;
    (void)reason;
    return SOFTBUS_INVALID_PARAM;
}

int32_t TestOnSessionOpenFailed(int32_t channelId, int32_t channelType, int32_t errCode)
{
    (void)channelId;
    (void)channelType;
    (void)errCode;
    return SOFTBUS_INVALID_PARAM;
}

IClientSessionCallBack cb {
    .OnSessionClosed = TestOnSessionClosed,
    .OnSessionOpenFailed = TestOnSessionOpenFailed,
};

static ClientProxyChannelInfo *TestCreateClientProxyChannelInfo()
{
    ClientProxyChannelInfo *info = (ClientProxyChannelInfo *)SoftBusCalloc(sizeof(ClientProxyChannelInfo));
    if (info == NULL) {
        TRANS_LOGE(TRANS_SDK, "info is null");
        return NULL;
    }
    info->channelId = TEST_CHANNEL_ID;
    info->detail.isEncrypted = TEST_IS_ENCRYPTED;
    info->detail.sequence = 0;
    info->detail.linkType = TEST_LINK_TYPE;
    info->detail.osType = TEST_OS_TYPE;
    return info;
}

/**
 * @tc.name: ClientTransProxyListInitTest001
 * @tc.desc: use normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientProxyFileManagerMockTest, ClientTransProxyListInitTest001, TestSize.Level1)
{
    NiceMock<TransClientProxyFileManagerInterfaceMock> TransProxyFileManagerMock;
    EXPECT_CALL(TransProxyFileManagerMock, CreateSoftBusList).WillOnce(Return(nullptr));
    int32_t ret = ClientTransProxyListInit();
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
    SoftBusList *list = (SoftBusList *)SoftBusCalloc(sizeof(SoftBusList));
    ASSERT_NE(nullptr, list);
    SoftBusMutexAttr mutexAttr;
    mutexAttr.type = SOFTBUS_MUTEX_RECURSIVE;
    ret = SoftBusMutexInit(&list->lock, &mutexAttr);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ListInit(&list->list);
    SoftBusList *testList = (SoftBusList *)SoftBusCalloc(sizeof(SoftBusList));
    ASSERT_NE(nullptr, testList);
    SoftBusMutexAttr testMutexAttr;
    testMutexAttr.type = SOFTBUS_MUTEX_RECURSIVE;
    ret = SoftBusMutexInit(&testList->lock, &testMutexAttr);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ListInit(&testList->list);
    SoftBusList *testListTest = (SoftBusList *)SoftBusCalloc(sizeof(SoftBusList));
    ASSERT_NE(nullptr, testListTest);
    SoftBusMutexAttr testMutexAttrTest;
    testMutexAttrTest.type = SOFTBUS_MUTEX_RECURSIVE;
    ret = SoftBusMutexInit(&testListTest->lock, &testMutexAttrTest);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ListInit(&testListTest->list);

    EXPECT_CALL(TransProxyFileManagerMock, CreateSoftBusList).WillOnce(Return(list)).WillOnce(Return(nullptr));
    ret = ClientTransProxyListInit();
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);

    EXPECT_CALL(TransProxyFileManagerMock, CreateSoftBusList).WillOnce(Return(testListTest)).WillOnce(Return(testList));
    EXPECT_CALL(TransProxyFileManagerMock, RegisterTimeoutCallback).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    ret = ClientTransProxyListInit();
    EXPECT_EQ(SOFTBUS_TIMOUT, ret);
}

/**
 * @tc.name: ClientTransProxyListInitTest002
 * @tc.desc: use normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientProxyFileManagerMockTest, ClientTransProxyListInitTest002, TestSize.Level1)
{
    SoftBusList *list = (SoftBusList *)SoftBusCalloc(sizeof(SoftBusList));
    ASSERT_NE(nullptr, list);
    SoftBusMutexAttr mutexAttr;
    mutexAttr.type = SOFTBUS_MUTEX_RECURSIVE;
    int32_t ret = SoftBusMutexInit(&list->lock, &mutexAttr);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ListInit(&list->list);
    SoftBusList *testList = (SoftBusList *)SoftBusCalloc(sizeof(SoftBusList));
    ASSERT_NE(nullptr, testList);
    SoftBusMutexAttr testMutexAttr;
    testMutexAttr.type = SOFTBUS_MUTEX_RECURSIVE;
    ret = SoftBusMutexInit(&testList->lock, &testMutexAttr);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ListInit(&testList->list);

    NiceMock<TransClientProxyFileManagerInterfaceMock> TransProxyFileManagerMock;
    EXPECT_CALL(TransProxyFileManagerMock, CreateSoftBusList).WillOnce(Return(list)).WillOnce(Return(testList));
    EXPECT_CALL(TransProxyFileManagerMock, RegisterTimeoutCallback).WillOnce(Return(SOFTBUS_OK));
    ret = ClientTransProxyListInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_CALL(TransProxyFileManagerMock, UnRegisterTimeoutCallback).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    ClientTransProxyListDeinit();
    EXPECT_CALL(TransProxyFileManagerMock, UnRegisterTimeoutCallback).WillOnce(Return(SOFTBUS_OK));
    ClientTransProxyListDeinit();
}

/**
 * @tc.name: ClientTransProxyListInitTest003
 * @tc.desc: use normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientProxyFileManagerMockTest, ClientTransProxyListInitTest003, TestSize.Level1)
{
    int32_t ret = ClientTransProxyInit(nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    SoftBusList *list = (SoftBusList *)SoftBusCalloc(sizeof(SoftBusList));
    ASSERT_NE(nullptr, list);
    SoftBusMutexAttr mutexAttr;
    mutexAttr.type = SOFTBUS_MUTEX_RECURSIVE;
    ret = SoftBusMutexInit(&list->lock, &mutexAttr);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ListInit(&list->list);
    SoftBusList *testList = (SoftBusList *)SoftBusCalloc(sizeof(SoftBusList));
    ASSERT_NE(nullptr, testList);
    SoftBusMutexAttr testMutexAttr;
    testMutexAttr.type = SOFTBUS_MUTEX_RECURSIVE;
    ret = SoftBusMutexInit(&testList->lock, &testMutexAttr);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ListInit(&testList->list);

    NiceMock<TransClientProxyFileManagerInterfaceMock> TransProxyFileManagerMock;
    EXPECT_CALL(TransProxyFileManagerMock, InitPendingPacket).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    ret = ClientTransProxyInit(&cb);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
    EXPECT_CALL(TransProxyFileManagerMock, InitPendingPacket).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(TransProxyFileManagerMock, CreateSoftBusList).WillOnce(Return(list)).WillOnce(Return(testList));
    EXPECT_CALL(TransProxyFileManagerMock, RegisterTimeoutCallback).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(TransProxyFileManagerMock, PendingInit).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    ret = ClientTransProxyInit(&cb);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
    EXPECT_CALL(TransProxyFileManagerMock, UnRegisterTimeoutCallback).WillOnce(Return(SOFTBUS_OK));
    ClientTransProxyListDeinit();
}

/**
 * @tc.name: ClientTransProxyListInitTest004
 * @tc.desc: use normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientProxyFileManagerMockTest, ClientTransProxyListInitTest004, TestSize.Level1)
{
    SoftBusList *list = (SoftBusList *)SoftBusCalloc(sizeof(SoftBusList));
    ASSERT_NE(nullptr, list);
    SoftBusMutexAttr mutexAttr;
    mutexAttr.type = SOFTBUS_MUTEX_RECURSIVE;
    int32_t ret = SoftBusMutexInit(&list->lock, &mutexAttr);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ListInit(&list->list);
    SoftBusList *testList = (SoftBusList *)SoftBusCalloc(sizeof(SoftBusList));
    ASSERT_NE(nullptr, testList);
    SoftBusMutexAttr testMutexAttr;
    testMutexAttr.type = SOFTBUS_MUTEX_RECURSIVE;
    ret = SoftBusMutexInit(&testList->lock, &testMutexAttr);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ListInit(&testList->list);

    NiceMock<TransClientProxyFileManagerInterfaceMock> TransProxyFileManagerMock;
    EXPECT_CALL(TransProxyFileManagerMock, InitPendingPacket).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(TransProxyFileManagerMock, CreateSoftBusList).WillOnce(Return(list)).WillOnce(Return(testList));
    EXPECT_CALL(TransProxyFileManagerMock, RegisterTimeoutCallback).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(TransProxyFileManagerMock, PendingInit).WillOnce(Return(SOFTBUS_OK));
    ret = ClientTransProxyInit(&cb);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: ClientTransProxyAddChannelInfoTest001
 * @tc.desc: use normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientProxyFileManagerMockTest, ClientTransProxyAddChannelInfoTest001, TestSize.Level1)
{
    ProxyChannelInfoDetail detailInfo;
    int32_t osType;
    int32_t linkType;
    ClientProxyChannelInfo *info = TestCreateClientProxyChannelInfo();
    ASSERT_NE(nullptr, info);
    int32_t ret = ClientTransProxyAddChannelInfo(nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = ClientTransProxyAddChannelInfo(info);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = ClientTransProxyGetInfoByChannelId(TEST_CHANNEL_ID, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = ClientTransProxyGetInfoByChannelId(TEST_CHANNEL_ID + 1, &detailInfo);
    EXPECT_EQ(SOFTBUS_TRANS_PROXY_CHANNEL_NOT_FOUND, ret);
    ret = ClientTransProxyGetInfoByChannelId(TEST_CHANNEL_ID, &detailInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = ClientTransProxyGetOsTypeByChannelId(TEST_CHANNEL_ID, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = ClientTransProxyGetOsTypeByChannelId(TEST_CHANNEL_ID + 1, &osType);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
    ret = ClientTransProxyGetOsTypeByChannelId(TEST_CHANNEL_ID, &osType);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = ClientTransProxyGetLinkTypeByChannelId(TEST_CHANNEL_ID, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = ClientTransProxyGetLinkTypeByChannelId(TEST_CHANNEL_ID + 1, &linkType);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
    ret = ClientTransProxyGetLinkTypeByChannelId(TEST_CHANNEL_ID, &linkType);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = ClientTransProxyDelChannelInfo(TEST_CHANNEL_ID);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: ClientTransProxyOnChannelClosedTest001
 * @tc.desc: use normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientProxyFileManagerMockTest, ClientTransProxyOnChannelClosedTest001, TestSize.Level1)
{
    ShutdownReason reason = SHUTDOWN_REASON_LNN_OFFLINE;
    int32_t ret = ClientTransProxyOnChannelClosed(TEST_CHANNEL_ID, reason);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = ClientTransProxyOnChannelOpenFailed(TEST_CHANNEL_ID, SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**
 * @tc.name: ClientTransProxyOnChannelOpenedTest001
 * @tc.desc: use normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientProxyFileManagerMockTest, ClientTransProxyOnChannelOpenedTest001, TestSize.Level1)
{
    ChannelInfo channel;
    SocketAccessInfo accessInfo;
    int32_t ret = ClientTransProxyOnChannelOpened(nullptr, &channel, &accessInfo);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = ClientTransProxyOnChannelOpened(TEST_SESSION_NAME, nullptr, &accessInfo);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**
 * @tc.name: ClientTransProxyDecryptPacketDataTest001
 * @tc.desc: use normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientProxyFileManagerMockTest, ClientTransProxyDecryptPacketDataTest001, TestSize.Level1)
{
    ProxyDataInfo dataInfo;
    ClientProxyChannelInfo *info = TestCreateClientProxyChannelInfo();
    ASSERT_NE(nullptr, info);
    int32_t ret = ClientTransProxyAddChannelInfo(nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = ClientTransProxyAddChannelInfo(info);
    EXPECT_EQ(SOFTBUS_OK, ret);
    NiceMock<TransClientProxyFileManagerInterfaceMock> TransProxyFileManagerMock;
    EXPECT_CALL(TransProxyFileManagerMock, TransProxyDecryptPacketData).WillRepeatedly(Return(SOFTBUS_OK));

    ret = ClientTransProxyDecryptPacketData(TEST_CHANNEL_ID, TEST_SEQ, &dataInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = ClientTransProxyDelChannelInfo(TEST_CHANNEL_ID);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: ClientTransProxySendSessionAckTest001
 * @tc.desc: use normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientProxyFileManagerMockTest, ClientTransProxySendSessionAckTest001, TestSize.Level1)
{
    ClientProxyChannelInfo *info = TestCreateClientProxyChannelInfo();
    ASSERT_NE(nullptr, info);
    int32_t ret = ClientTransProxyAddChannelInfo(nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    info->detail.osType = OH_TYPE;
    ret = ClientTransProxyAddChannelInfo(info);
    EXPECT_EQ(SOFTBUS_OK, ret);
    NiceMock<TransClientProxyFileManagerInterfaceMock> TransProxyFileManagerMock;
    EXPECT_CALL(TransProxyFileManagerMock, GetSupportTlvAndNeedAckById).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));

    ClientTransProxySendSessionAck(TEST_CHANNEL_ID, TEST_SEQ);

    ret = ClientTransProxyDelChannelInfo(TEST_CHANNEL_ID);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: ClientTransProxySendSessionAckTest002
 * @tc.desc: use normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientProxyFileManagerMockTest, ClientTransProxySendSessionAckTest002, TestSize.Level1)
{
    ClientProxyChannelInfo *info = TestCreateClientProxyChannelInfo();
    ASSERT_NE(nullptr, info);
    int32_t ret = ClientTransProxyAddChannelInfo(nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    info->detail.osType = TEST_LINK_TYPE;
    ret = ClientTransProxyAddChannelInfo(info);
    EXPECT_EQ(SOFTBUS_OK, ret);
    NiceMock<TransClientProxyFileManagerInterfaceMock> TransProxyFileManagerMock;
    EXPECT_CALL(TransProxyFileManagerMock, GetSupportTlvAndNeedAckById).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));

    ClientTransProxySendSessionAck(TEST_CHANNEL_ID, TEST_SEQ);

    ret = ClientTransProxyDelChannelInfo(TEST_CHANNEL_ID);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: ClientTransProxySendBytesAckTest001
 * @tc.desc: use normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientProxyFileManagerMockTest, ClientTransProxySendBytesAckTest001, TestSize.Level1)
{
    uint32_t dataSeq = TEST_CHANNEL_ID;
    ClientProxyChannelInfo *info = TestCreateClientProxyChannelInfo();
    ASSERT_NE(nullptr, info);
    int32_t ret = ClientTransProxyAddChannelInfo(nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    info->detail.osType = TEST_LINK_TYPE;
    ret = ClientTransProxyAddChannelInfo(info);
    EXPECT_EQ(SOFTBUS_OK, ret);
    NiceMock<TransClientProxyFileManagerInterfaceMock> TransProxyFileManagerMock;
    EXPECT_CALL(TransProxyFileManagerMock, GetSupportTlvAndNeedAckById).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));

    ClientTransProxySendBytesAck(TEST_CHANNEL_ID, TEST_SEQ, dataSeq, true);

    ret = ClientTransProxyDelChannelInfo(TEST_CHANNEL_ID);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: ClientTransProxySendBytesAckTest002
 * @tc.desc: use normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientProxyFileManagerMockTest, ClientTransProxySendBytesAckTest002, TestSize.Level1)
{
    uint32_t dataSeq = TEST_CHANNEL_ID;
    ClientProxyChannelInfo *info = TestCreateClientProxyChannelInfo();
    ASSERT_NE(nullptr, info);
    int32_t ret = ClientTransProxyAddChannelInfo(nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    info->detail.osType = OH_TYPE;
    ret = ClientTransProxyAddChannelInfo(info);
    EXPECT_EQ(SOFTBUS_OK, ret);
    NiceMock<TransClientProxyFileManagerInterfaceMock> TransProxyFileManagerMock;
    EXPECT_CALL(TransProxyFileManagerMock, GetSupportTlvAndNeedAckById).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));

    ClientTransProxySendBytesAck(TEST_CHANNEL_ID, TEST_SEQ, dataSeq, true);

    ret = ClientTransProxyDelChannelInfo(TEST_CHANNEL_ID);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: ClientTransProxyPackTlvBytesTest001
 * @tc.desc: use normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientProxyFileManagerMockTest, ClientTransProxyPackTlvBytesTest001, TestSize.Level1)
{
    ProxyDataInfo dataInfo;
    ProxyChannelInfoDetail info;
    SessionPktType flag = TRANS_SESSION_FILE_RESULT_FRAME;
    uint32_t dataSeq = 0;
    NiceMock<TransClientProxyFileManagerInterfaceMock> TransProxyFileManagerMock;
    EXPECT_CALL(TransProxyFileManagerMock, GetSupportTlvAndNeedAckById).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = ClientTransProxyPackTlvBytes(TEST_CHANNEL_ID, &dataInfo, &info, flag, dataSeq);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    EXPECT_CALL(TransProxyFileManagerMock, GetSupportTlvAndNeedAckById).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(TransProxyFileManagerMock, GetSupportTlvAndNeedAckById).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    ret = ClientTransProxyPackTlvBytes(TEST_CHANNEL_ID, &dataInfo, &info, flag, dataSeq);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**
 * @tc.name: ClientTransProxyPackBytesTest001
 * @tc.desc: use normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientProxyFileManagerMockTest, ClientTransProxyPackBytesTest001, TestSize.Level1)
{
    ProxyDataInfo dataInfo;
    ProxyChannelInfoDetail info;
    SessionPktType flag = TRANS_SESSION_FILE_RESULT_FRAME;
    NiceMock<TransClientProxyFileManagerInterfaceMock> TransProxyFileManagerMock;
    EXPECT_CALL(TransProxyFileManagerMock, GetSupportTlvAndNeedAckById)
        .WillRepeatedly(DoAll(SetArgPointee<2>(true), Return(SOFTBUS_OK)));
    EXPECT_CALL(TransProxyFileManagerMock, GetSupportTlvAndNeedAckById).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = ClientTransProxyPackBytes(TEST_CHANNEL_ID, &dataInfo, &info, flag);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    EXPECT_CALL(TransProxyFileManagerMock, GetSupportTlvAndNeedAckById).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(TransProxyFileManagerMock, TransProxyPackBytes).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    ret = ClientTransProxyPackBytes(TEST_CHANNEL_ID, &dataInfo, &info, flag);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = ClientTransProxyPackBytes(TEST_CHANNEL_ID, nullptr, &info, flag);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = ClientTransProxyPackBytes(TEST_CHANNEL_ID, &dataInfo, nullptr, flag);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**
 * @tc.name: TransProxyAsyncPackAndSendDataTest002
 * @tc.desc: use normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientProxyFileManagerMockTest, TransProxyAsyncPackAndSendDataTest002, TestSize.Level1)
{
    int32_t ret = TransProxyChannelSendBytes(TEST_CHANNEL_ID, nullptr, TEST_DATA_LENGTH, false);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**
 * @tc.name: SendOneFrame001
 * @tc.desc: use abnormal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientProxyFileManagerMockTest, SendOneFrame001, TestSize.Level1)
{
    int32_t ret = 0;
    SendListenerInfo *sendInfo = reinterpret_cast<SendListenerInfo *>(SoftBusCalloc(sizeof(SendListenerInfo)));
    FileFrame *fileFrame = reinterpret_cast<FileFrame *>(SoftBusCalloc(sizeof(FileFrame)));
    sendInfo->osType = OH_TYPE;
    sendInfo->crc = 0;

    NiceMock<TransClientProxyFileManagerInterfaceMock> TransProxyFileManagerMock;
    ret = SendOneFrame(sendInfo, NULL);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = SendOneFrame(sendInfo, fileFrame);
    EXPECT_EQ(SOFTBUS_OK, ret);

    sendInfo->osType = 0;
    EXPECT_CALL(TransProxyFileManagerMock, ProxyChannelSendFileStream).WillOnce(Return(SOFTBUS_OK));
    ret = SendOneFrame(sendInfo, fileFrame);
    EXPECT_EQ(SOFTBUS_OK, ret);

    SoftBusFree(sendInfo);
    SoftBusFree(fileFrame);
}
/**
 * @tc.name: SendFileCrcCheckSum001
 * @tc.desc: use abnormal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientProxyFileManagerMockTest, SendFileCrcCheckSum001, TestSize.Level1)
{
    int32_t ret = 0;
    SendListenerInfo *sendInfo = reinterpret_cast<SendListenerInfo *>(SoftBusCalloc(sizeof(SendListenerInfo)));
    sendInfo->crc = APP_INFO_FILE_FEATURES_SUPPORT;

    NiceMock<TransClientProxyFileManagerInterfaceMock> TransProxyFileManagerMock;
    EXPECT_CALL(TransProxyFileManagerMock, CreatePendingPacket).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(TransProxyFileManagerMock, ProxyChannelSendFileStream).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(TransProxyFileManagerMock, GetPendingPacketData).WillOnce(Return(SOFTBUS_ALREADY_TRIGGERED));
    ret = SendFileCrcCheckSum(sendInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);

    EXPECT_CALL(TransProxyFileManagerMock, GetPendingPacketData).WillOnce(Return(SOFTBUS_OK));
    ret = SendFileCrcCheckSum(sendInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);

    EXPECT_CALL(TransProxyFileManagerMock, GetPendingPacketData).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    ret = SendFileCrcCheckSum(sendInfo);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    SoftBusFree(sendInfo);
}

/**
 * @tc.name: HandleSendProgress001
 * @tc.desc: use normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientProxyFileManagerMockTest, HandleSendProgress001, TestSize.Level1)
{
    uint64_t fileOffset = 0;
    uint64_t fileSize = 0;
    SendListenerInfo *sendInfo = reinterpret_cast<SendListenerInfo *>(SoftBusCalloc(sizeof(SendListenerInfo)));
    FileListener *fileListener = reinterpret_cast<FileListener *>(SoftBusCalloc(sizeof(FileListener)));

    (void)HandleSendProgress(sendInfo, fileOffset, fileSize);

    sendInfo->fileListener.sendListener.OnSendFileProcess = [](
        int sessionId, uint64_t bytesUpload, uint64_t bytesTotal) -> int {return SOFTBUS_OK;};
    sendInfo->fileListener = *fileListener;
    (void)HandleSendProgress(sendInfo, fileOffset, fileSize);

    fileListener->socketSendCallback = [](int32_t socket, FileEvent *event) {};
    sendInfo->fileListener = *fileListener;
    (void)HandleSendProgress(sendInfo, fileOffset, fileSize);
    EXPECT_EQ(0, fileSize);

    SoftBusFree(sendInfo);
    SoftBusFree(fileListener);
}

/**
 * @tc.name: DelRecipient001
 * @tc.desc: use normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientProxyFileManagerMockTest, DelRecipient001, TestSize.Level1)
{
    NiceMock<TransClientProxyFileManagerInterfaceMock> TransProxyFileManagerMock;
    EXPECT_CALL(TransProxyFileManagerMock, InitPendingPacket).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = ClinetTransProxyFileManagerInit();
    EXPECT_EQ(SOFTBUS_OK, ret);

    FileRecipientInfo *info = (FileRecipientInfo *)SoftBusCalloc(sizeof(FileRecipientInfo));
    info->channelId = 1;
    info->sessionId = 1;
    info->osType = 0;
    ListInit(&info->node);
    info->objRefCount = 1;
    info->recvFileInfo.fileFd = INVALID_FD;
    ListTailInsert(&g_recvRecipientInfoList, &info->node);

    FileRecipientInfo *tarinfo = (FileRecipientInfo *)SoftBusCalloc(sizeof(FileRecipientInfo));
    tarinfo->channelId = 2;
    tarinfo->sessionId = 2;
    tarinfo->osType = 10;
    ListInit(&tarinfo->node);
    tarinfo->objRefCount = 2;
    tarinfo->recvFileInfo.fileFd = INVALID_FD;
    ListTailInsert(&g_recvRecipientInfoList, &tarinfo->node);

    (void)DelRecipient(info->sessionId);
    (void)DelRecipient(tarinfo->sessionId);
    (void)DelRecipient(tarinfo->sessionId);
    ClinetTransProxyFileManagerDeinit();
}

/**
 * @tc.name: ClientDeleteRecvFileList001
 * @tc.desc: use abnormal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientProxyFileManagerMockTest, ClientDeleteRecvFileList001, TestSize.Level1)
{
    int32_t sessionId = -1;
    (void)ClientDeleteRecvFileList(sessionId);
    EXPECT_EQ(-1, sessionId);
}

/**
 * @tc.name: UpdateFileReceivePath001
 * @tc.desc: use abnormal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientProxyFileManagerMockTest, UpdateFileReceivePath001, TestSize.Level1)
{
    int32_t ret = 0;
    FileListener *fileListener = reinterpret_cast<FileListener *>(SoftBusCalloc(sizeof(FileListener)));
    fileListener->socketRecvCallback = [] (int32_t socket, FileEvent *event){return;};

    int32_t sessionId = 1;

    ret = UpdateFileReceivePath(sessionId, fileListener);
    EXPECT_EQ(SOFTBUS_FILE_ERR, ret);

    SoftBusFree(fileListener);
}

/**
 * @tc.name: HandleFileTransferCompletion001
 * @tc.desc: use abnormal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientProxyFileManagerMockTest, HandleFileTransferCompletion001, TestSize.Level1)
{
    FileRecipientInfo *recipient = (FileRecipientInfo *)SoftBusCalloc(sizeof(FileRecipientInfo));
    SingleFileInfo *file = (SingleFileInfo *)SoftBusCalloc(sizeof(SingleFileInfo));

    int32_t sessionId = 1;

    HandleFileTransferCompletion(recipient, sessionId, file);

    recipient->fileListener.recvListener.OnReceiveFileStarted = [](int sessionId, const char *files, int fileCnt)
        -> int {return 0;};
    HandleFileTransferCompletion(recipient, sessionId, file);

    recipient->fileListener.socketRecvCallback = [] (int32_t socket, FileEvent *event){return;};
    HandleFileTransferCompletion(recipient, sessionId, file);
    EXPECT_EQ(1, sessionId);

    SoftBusFree(recipient);
    SoftBusFree(file);
}

/**
 * @tc.name: ProcessOneFrame001
 * @tc.desc: use abnormal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientProxyFileManagerMockTest, ProcessOneFrame001, TestSize.Level1)
{
    int32_t ret = 0;
    FileFrame *fileFrame = (FileFrame *)SoftBusCalloc(sizeof(FileFrame));
    SingleFileInfo *fileInfo = (SingleFileInfo *)SoftBusCalloc(sizeof(SingleFileInfo));
    uint32_t dataLen = MAX_FILE_SIZE + FRAME_DATA_SEQ_OFFSET + 1;
    int32_t crc = APP_INFO_FILE_FEATURES_SUPPORT;
    int32_t osType = OH_TYPE;
    NiceMock<TransClientProxyFileManagerInterfaceMock> TransProxyFileManagerMock;

    ret = ProcessOneFrame(fileFrame, dataLen, crc, fileInfo, osType);
    EXPECT_EQ(SOFTBUS_FILE_ERR, ret);

    osType = 0;
    ret = ProcessOneFrame(fileFrame, dataLen, crc, fileInfo, osType);
    EXPECT_EQ(SOFTBUS_FILE_ERR, ret);

    dataLen = FRAME_DATA_SEQ_OFFSET + 1;
    fileInfo->fileOffset = MAX_FILE_SIZE + 1;
    ret = ProcessOneFrame(fileFrame, dataLen, crc, fileInfo, osType);
    EXPECT_EQ(SOFTBUS_FILE_ERR, ret);

    int64_t writeLength = dataLen - FRAME_DATA_SEQ_OFFSET;
    fileInfo->fileOffset = MAX_FILE_SIZE - FRAME_DATA_SEQ_OFFSET;
    EXPECT_CALL(TransProxyFileManagerMock, SoftBusPwriteFile).WillOnce(Return(writeLength));
    ret = ProcessOneFrame(fileFrame, dataLen, crc, fileInfo, osType);
    EXPECT_EQ(SOFTBUS_OK, ret);

    SoftBusFree(fileFrame);
    SoftBusFree(fileInfo);
}

/**
 * @tc.name: UpdateFileReceptionStatus001
 * @tc.desc: use abnormal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransClientProxyFileManagerMockTest, UpdateFileReceptionStatus001, TestSize.Level1)
{
    int32_t ret = 0;
    FileFrame *fileFrame = (FileFrame *)SoftBusCalloc(sizeof(FileFrame));
    SingleFileInfo *fileInfo = (SingleFileInfo *)SoftBusCalloc(sizeof(SingleFileInfo));
    FileRecipientInfo *recipient = (FileRecipientInfo *)SoftBusCalloc(sizeof(FileRecipientInfo));
    int32_t sessionId = 1;
    NiceMock<TransClientProxyFileManagerInterfaceMock> TransProxyFileManagerMock;

    recipient->crc = APP_INFO_FILE_FEATURES_SUPPORT;
    ret = UpdateFileReceptionStatus(fileInfo, recipient, fileFrame, sessionId);
    EXPECT_EQ(SOFTBUS_OK, ret);

    recipient->crc = APP_INFO_FILE_FEATURES_NO_SUPPORT;
    fileFrame->frameType = TRANS_SESSION_ACK;
    ret = UpdateFileReceptionStatus(fileInfo, recipient, fileFrame, sessionId);
    EXPECT_EQ(SOFTBUS_OK, ret);

    recipient->fileListener.recvListener.OnReceiveFileProcess = [](int sessionId, const char *firstFile,
        uint64_t bytesUpload, uint64_t bytesTotal) -> int {return 0;};
    recipient->crc = APP_INFO_FILE_FEATURES_SUPPORT;
    ret = UpdateFileReceptionStatus(fileInfo, recipient, fileFrame, sessionId);
    EXPECT_EQ(SOFTBUS_OK, ret);

    recipient->fileListener.socketRecvCallback = [] (int32_t socket, FileEvent *event){return;};
    ret = UpdateFileReceptionStatus(fileInfo, recipient, fileFrame, sessionId);
    EXPECT_EQ(SOFTBUS_OK, ret);

    SoftBusFree(fileFrame);
    SoftBusFree(fileInfo);
    SoftBusFree(recipient);
}


} // namespace OHOS