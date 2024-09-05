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

#include <fcntl.h>
#include <gtest/gtest.h>
#include "securec.h"
#include <sys/stat.h>
#include <sys/types.h>

#include "client_trans_proxy_file_manager.c"
#include "client_trans_proxy_file_manager_mock.h"
#include "client_trans_proxy_manager.c"
#include "softbus_access_token_test.h"
#include "softbus_def.h"
#include "softbus_errcode.h"

using namespace testing;
using namespace testing::ext;

#define TEST_SESSION_ID 1026
#define TEST_HEADER_LENGTH 24
#define TEST_DATA_LENGTH 100
#define TEST_PACKET_SIZE 1024
#define TEST_FILE_LENGTH 12
#define TEST_FILE_DATA_SIZE 958
#define TEST_FILE_TEST_TXT_FILE 16

namespace OHOS {

const char *g_testProxyFileList[] = {
    "/data/test.txt",
    "/data/ss.txt",
};

class ClientTransProxyFileManagerMockTest : public testing::Test {
public:
    ClientTransProxyFileManagerMockTest() {}
    ~ClientTransProxyFileManagerMockTest() {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override {}
    void TearDown() override {}
};

void ClientTransProxyFileManagerMockTest::SetUpTestCase(void)
{
    int32_t ret = ClinetTransProxyFileManagerInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
    ClientTransProxyListInit();
}

void ClientTransProxyFileManagerMockTest::TearDownTestCase(void)
{
    ClinetTransProxyFileManagerDeinit();
    ClientTransProxyListDeinit();
}

/**
 * @tc.name: AddSendListenerInfoTest001
 * @tc.desc: client add send listener info, use normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerMockTest, AddSendListenerInfoTest001, TestSize.Level0)
{
    // will free in DelSendListenerInfo
    SendListenerInfo *info = (SendListenerInfo *)SoftBusCalloc(sizeof(SendListenerInfo));
    EXPECT_TRUE(info != nullptr);
    info->sessionId = TEST_SESSION_ID;

    int32_t ret = AddSendListenerInfo(nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = AddSendListenerInfo(info);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = AddSendListenerInfo(info);
    EXPECT_EQ(SOFTBUS_ALREADY_EXISTED, ret);

    DelSendListenerInfo(info);
}

/**
 * @tc.name: PackFileTransStartInfoTest001
 * @tc.desc: client trans proxy pack file data frame test, use normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerMockTest, PackFileTransStartInfoTest001, TestSize.Level0)
{
    uint8_t data[TEST_DATA_LENGTH] = {0};
    FileFrame fileFrame = {
        .frameLength = 0,
        .data = data,
        .fileData = data,
    };
    SendListenerInfo info = {
        .crc = APP_INFO_FILE_FEATURES_SUPPORT,
        .osType = OH_TYPE,
        .packetSize = 1,
    };

    int32_t ret = PackFileTransStartInfo(nullptr, g_testProxyFileList[0], TEST_FILE_TEST_TXT_FILE, &info);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = PackFileTransStartInfo(&fileFrame, nullptr, TEST_FILE_TEST_TXT_FILE, &info);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = PackFileTransStartInfo(&fileFrame, g_testProxyFileList[0], TEST_FILE_TEST_TXT_FILE, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = PackFileTransStartInfo(&fileFrame, g_testProxyFileList[0], TEST_FILE_TEST_TXT_FILE, &info);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_DATA_LENGTH, ret);

    info.packetSize = PROXY_BLE_MAX_PACKET_SIZE;
    NiceMock<ClientTransProxyFileManagerInterfaceMock> ClientProxyFileManagerMock;
    EXPECT_CALL(ClientProxyFileManagerMock, SoftBusHtoLl).WillRepeatedly(Return(FILE_MAGIC_NUMBER));
    EXPECT_CALL(ClientProxyFileManagerMock, SoftBusHtoLll).WillRepeatedly(
        Return(FILE_MAGIC_NUMBER + FRAME_MAGIC_OFFSET));
    EXPECT_CALL(ClientProxyFileManagerMock, SoftBusHtoLl).WillRepeatedly(Return(TEST_FILE_DATA_SIZE));
    EXPECT_CALL(ClientProxyFileManagerMock, SoftBusHtoLll).WillRepeatedly(Return(TEST_FILE_TEST_TXT_FILE));

    ret = PackFileTransStartInfo(&fileFrame, g_testProxyFileList[0], TEST_FILE_TEST_TXT_FILE, &info);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: UnpackFileTransStartInfoTest001
 * @tc.desc: client trans proxy pack file data frame test, use normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileManagerMockTest, UnpackFileTransStartInfoTest001, TestSize.Level0)
{
    uint32_t packetSize = TEST_PACKET_SIZE;

    uint8_t data[TEST_DATA_LENGTH] = {0};
    FileFrame fileFrame = {
        .frameLength = TEST_HEADER_LENGTH,
        .data = data,
        .fileData = data,
    };
    FileRecipientInfo info;
    info.crc = APP_INFO_FILE_FEATURES_SUPPORT;
    info.osType = OH_TYPE;
    SingleFileInfo singleFileInfo;

    NiceMock<ClientTransProxyFileManagerInterfaceMock> ClientProxyFileManagerMock;
    EXPECT_CALL(ClientProxyFileManagerMock, SoftBusLtoHl).WillOnce(Return(FILE_MAGIC_NUMBER))
        .WillRepeatedly(Return(TEST_FILE_LENGTH));
    EXPECT_CALL(ClientProxyFileManagerMock, SoftBusLtoHll).WillOnce(Return(TEST_FILE_LENGTH))
        .WillRepeatedly(Return(MAX_FILE_SIZE));
    
    int32_t ret = UnpackFileTransStartInfo(&fileFrame, &info, &singleFileInfo, packetSize);
    EXPECT_EQ(SOFTBUS_OK, ret);

    EXPECT_CALL(ClientProxyFileManagerMock, SoftBusLtoHl).WillOnce(Return(FILE_MAGIC_NUMBER))
        .WillRepeatedly(Return(TEST_FILE_LENGTH));
    EXPECT_CALL(ClientProxyFileManagerMock, SoftBusLtoHll).WillOnce(Return(TEST_FILE_LENGTH))
        .WillRepeatedly(Return(MAX_FILE_SIZE + 1));

    ret = UnpackFileTransStartInfo(&fileFrame, &info, &singleFileInfo, packetSize);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_DATA_LENGTH, ret);
}
} // namespace OHOS