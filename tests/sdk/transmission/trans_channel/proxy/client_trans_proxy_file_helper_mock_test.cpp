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

#include "client_trans_proxy_file_helper.c"
#include "client_trans_proxy_file_helper_mock.h"
#include "softbus_access_token_test.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "trans_proxy_process_data.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
class ClientTransProxyFileHelperMockTest : public testing::Test {
public:
    ClientTransProxyFileHelperMockTest() {}
    ~ClientTransProxyFileHelperMockTest() {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override {}
    void TearDown() override {}
};

void ClientTransProxyFileHelperMockTest::SetUpTestCase(void)
{
}

void ClientTransProxyFileHelperMockTest::TearDownTestCase(void)
{
}

/**
 * @tc.name: SendFileTransResult001
 * @tc.desc: SendFileTransResult, use normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileHelperMockTest, SendFileTransResult001, TestSize.Level1)
{
    int32_t ret = 0;
    int32_t channelId = 1;
    uint32_t seq = 1;
    uint64_t seq64 = 1;
    int32_t result = 0;
    uint32_t side = 0;

    NiceMock<ClientTransProxyFileHelperInterfaceMock> ClientHelperMock;
    EXPECT_CALL(ClientHelperMock, SoftBusHtoLl).WillRepeatedly(Return(seq));
    EXPECT_CALL(ClientHelperMock, SoftBusHtoLll).WillRepeatedly(Return(seq64));
    EXPECT_CALL(ClientHelperMock, ClientTransProxyGetInfoByChannelId).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ClientHelperMock, ClientTransProxyPackAndSendData).WillRepeatedly(Return(SOFTBUS_OK));
    ret = SendFileTransResult(channelId, seq, result, side);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: SendFileAckReqAndResData001
 * @tc.desc: SendFileAckReqAndResData, use normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileHelperMockTest, SendFileAckReqAndResData001, TestSize.Level1)
{
    int32_t ret = 0;
    int32_t channelId = 1;
    uint32_t seq = 1;
    uint64_t seq64 = 1;
    int32_t result = 0;
    uint32_t side = 0;

    NiceMock<ClientTransProxyFileHelperInterfaceMock> ClientHelperMock;
    EXPECT_CALL(ClientHelperMock, SoftBusHtoLl).WillRepeatedly(Return(seq));
    EXPECT_CALL(ClientHelperMock, SoftBusHtoLll).WillRepeatedly(Return(seq64));
    EXPECT_CALL(ClientHelperMock, ClientTransProxyGetInfoByChannelId).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ClientHelperMock, ClientTransProxyPackAndSendData).WillRepeatedly(Return(SOFTBUS_OK));
    ret = SendFileAckReqAndResData(channelId, seq, result, side);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: PackReadFileData001
 * @tc.desc: PackReadFileData, use abnormal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileHelperMockTest, PackReadFileData001, TestSize.Level1)
{
    int64_t ret = 0;
    FileFrame *fileFrame = (FileFrame *)SoftBusCalloc(sizeof(FileFrame));
    SendListenerInfo *info = (SendListenerInfo *)SoftBusCalloc(sizeof(SendListenerInfo));
    fileFrame->data = (uint8_t *)SoftBusCalloc(sizeof(uint64_t) * 64);
    fileFrame->fileData = (uint8_t *)SoftBusCalloc(sizeof(uint32_t) * 64);
    info->crc = APP_INFO_FILE_FEATURES_SUPPORT;
    info->osType = OH_TYPE;
    info->packetSize = 0;
    uint32_t seq = 0;
    uint64_t seq64 = 0;
    uint16_t seq16 = 0;
    uint64_t readLength = 8;
    uint64_t fileOffset = 0;
    int64_t len = 1;
    NiceMock<ClientTransProxyFileHelperInterfaceMock> ClientHelperMock;

    ret = PackReadFileData(NULL, readLength, fileOffset, info);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = PackReadFileData(fileFrame, readLength, fileOffset, NULL);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    EXPECT_CALL(ClientHelperMock, SoftBusPreadFile).WillRepeatedly(Return(len));
    ret = PackReadFileData(fileFrame, readLength, fileOffset, info);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_DATA_LENGTH, ret);


    info->packetSize = 64;
    EXPECT_CALL(ClientHelperMock, SoftBusHtoLl).WillRepeatedly(Return(seq));
    EXPECT_CALL(ClientHelperMock, SoftBusHtoLll).WillRepeatedly(Return(seq64));
    EXPECT_CALL(ClientHelperMock, SoftBusHtoLs).WillRepeatedly(Return(seq16));
    EXPECT_CALL(ClientHelperMock, RTU_CRC).WillOnce(Return(seq16));
    ret = PackReadFileData(fileFrame, readLength, fileOffset, info);
    EXPECT_EQ(len, ret);

    SoftBusFree(fileFrame->data);
    SoftBusFree(fileFrame->fileData);
    SoftBusFree(fileFrame);
    SoftBusFree(info);
}

/**
 * @tc.name: PackReadFileData002
 * @tc.desc: PackReadFileData, use abnormal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileHelperMockTest, PackReadFileData002, TestSize.Level1)
{
    int64_t ret = 0;
    FileFrame *fileFrame = (FileFrame *)SoftBusCalloc(sizeof(FileFrame));
    SendListenerInfo *info = (SendListenerInfo *)SoftBusCalloc(sizeof(SendListenerInfo));
    fileFrame->data = (uint8_t *)SoftBusCalloc(sizeof(uint64_t) * 64);
    fileFrame->fileData = (uint8_t *)SoftBusCalloc(sizeof(uint32_t) * 64);
    info->crc = APP_INFO_FILE_FEATURES_SUPPORT;
    info->osType = 0;
    info->packetSize = 0;
    uint64_t readLength = 8;
    uint64_t fileOffset = 0;
    int64_t len = UINT32_MAX;
    NiceMock<ClientTransProxyFileHelperInterfaceMock> ClientHelperMock;

    EXPECT_CALL(ClientHelperMock, SoftBusPreadFile).WillOnce(Return(len));
    ret = PackReadFileData(fileFrame, readLength, fileOffset, info);
    EXPECT_EQ(SOFTBUS_INVALID_NUM, ret);

    len = 64;
    EXPECT_CALL(ClientHelperMock, SoftBusPreadFile).WillOnce(Return(len));
    ret = PackReadFileData(fileFrame, readLength, fileOffset, info);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_DATA_LENGTH, ret);

    SoftBusFree(fileFrame->data);
    SoftBusFree(fileFrame->fileData);
    SoftBusFree(fileFrame);
    SoftBusFree(info);
}

/**
 * @tc.name: PackReadFileRetransData001
 * @tc.desc: PackReadFileRetransData, use abnormal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileHelperMockTest, PackReadFileRetransData001, TestSize.Level1)
{
    int64_t ret = 0;
    FileFrame *fileFrame = (FileFrame *)SoftBusCalloc(sizeof(FileFrame));
    SendListenerInfo *info = (SendListenerInfo *)SoftBusCalloc(sizeof(SendListenerInfo));
    fileFrame->data = (uint8_t *)SoftBusCalloc(sizeof(uint64_t) * 64);
    fileFrame->fileData = (uint8_t *)SoftBusCalloc(sizeof(uint32_t) * 64);
    info->crc = APP_INFO_FILE_FEATURES_SUPPORT;
    info->osType = OH_TYPE;
    info->packetSize = 0;
    uint32_t seq = 0;
    uint64_t seq64 = 0;
    uint16_t seq16 = 0;
    uint64_t readLength = 8;
    uint64_t fileOffset = 0;
    int64_t len = 1;
    NiceMock<ClientTransProxyFileHelperInterfaceMock> ClientHelperMock;

    EXPECT_CALL(ClientHelperMock, FrameIndexToType).WillRepeatedly(Return(0));
    ret = PackReadFileRetransData(NULL, seq, readLength, fileOffset, info);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = PackReadFileRetransData(fileFrame, seq, readLength, fileOffset, NULL);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    EXPECT_CALL(ClientHelperMock, SoftBusPreadFile).WillRepeatedly(Return(len));
    ret = PackReadFileRetransData(fileFrame, seq, readLength, fileOffset, info);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_DATA_LENGTH, ret);


    info->packetSize = 64;
    EXPECT_CALL(ClientHelperMock, SoftBusHtoLl).WillRepeatedly(Return(seq));
    EXPECT_CALL(ClientHelperMock, SoftBusHtoLll).WillRepeatedly(Return(seq64));
    EXPECT_CALL(ClientHelperMock, SoftBusHtoLs).WillRepeatedly(Return(seq16));
    EXPECT_CALL(ClientHelperMock, RTU_CRC).WillOnce(Return(seq16));
    EXPECT_CALL(ClientHelperMock, ClientTransProxyGetInfoByChannelId).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ClientHelperMock, ClientTransProxyPackAndSendData).WillRepeatedly(Return(SOFTBUS_OK));
    ret = PackReadFileRetransData(fileFrame, seq, readLength, fileOffset, info);
    EXPECT_EQ(len, ret);

    SoftBusFree(fileFrame->data);
    SoftBusFree(fileFrame->fileData);
    SoftBusFree(fileFrame);
    SoftBusFree(info);
}

/**
 * @tc.name: UnpackFileDataFrame001
 * @tc.desc: UnpackFileDataFrame, use abnormal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileHelperMockTest, UnpackFileDataFrame001, TestSize.Level1)
{
    int32_t ret = 0;
    FileFrame *fileFrame = (FileFrame *)SoftBusCalloc(sizeof(FileFrame));
    FileRecipientInfo *info = (FileRecipientInfo *)SoftBusCalloc(sizeof(FileRecipientInfo));
    uint32_t *fileDataLen = (uint32_t *)SoftBusCalloc(sizeof(uint32_t));
    fileFrame->data = (uint8_t *)SoftBusCalloc(sizeof(uint64_t) * 64);
    fileFrame->frameLength = FRAME_HEAD_LEN + FRAME_CRC_LEN + 16;
    fileFrame->magic = FILE_MAGIC_NUMBER;

    info->crc = APP_INFO_FILE_FEATURES_SUPPORT;
    info->osType = OH_TYPE;
    *fileDataLen = 0;
    uint32_t seq16 = 0;
    uint64_t dataLen = 16;
    int32_t magic = FILE_MAGIC_NUMBER;
    NiceMock<ClientTransProxyFileHelperInterfaceMock> ClientHelperMock;

    ret = UnpackFileDataFrame(NULL, fileFrame, fileDataLen);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = UnpackFileDataFrame(info, NULL, fileDataLen);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = UnpackFileDataFrame(info, fileFrame, NULL);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    EXPECT_CALL(ClientHelperMock, SoftBusLtoHl).WillRepeatedly(Return(magic));
    EXPECT_CALL(ClientHelperMock, SoftBusLtoHll).WillRepeatedly(Return(dataLen));
    EXPECT_CALL(ClientHelperMock, SoftBusHtoLs).WillRepeatedly(Return(seq16));
    EXPECT_CALL(ClientHelperMock, RTU_CRC).WillOnce(Return(seq16));
    ret = UnpackFileDataFrame(info, fileFrame, fileDataLen);
    EXPECT_EQ(SOFTBUS_OK, ret);

    EXPECT_CALL(ClientHelperMock, SoftBusLtoHl).WillRepeatedly(Return(magic));
    EXPECT_CALL(ClientHelperMock, SoftBusLtoHll).WillRepeatedly(Return(dataLen));
    EXPECT_CALL(ClientHelperMock, SoftBusHtoLs).WillRepeatedly(Return(seq16));
    EXPECT_CALL(ClientHelperMock, RTU_CRC).WillOnce(Return(seq16 + 1));
    ret = UnpackFileDataFrame(info, fileFrame, fileDataLen);
    EXPECT_EQ(SOFTBUS_FILE_ERR, ret);

    SoftBusFree(fileFrame->data);
    SoftBusFree(fileFrame);
    SoftBusFree(info);
}

/**
 * @tc.name: AckResponseDataHandle001
 * @tc.desc: AckResponseDataHandle, use abnormal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileHelperMockTest, AckResponseDataHandle001, TestSize.Level1)
{
    int32_t ret = 0;
    SendListenerInfo *info = (SendListenerInfo *)SoftBusCalloc(sizeof(SendListenerInfo));
    AckResponseData *resData = (AckResponseData *)SoftBusCalloc(sizeof(AckResponseData));
    resData->startSeq = 0;
    resData->seqResult = FILE_SEND_ACK_RESULT_SUCCESS;
    char *data = (char *)resData;
    uint32_t len = sizeof(AckResponseData) + 1;

    NiceMock<ClientTransProxyFileHelperInterfaceMock> ClientHelperMock;
    EXPECT_CALL(ClientHelperMock, FrameIndexToType).WillRepeatedly(Return(0));
    ret = AckResponseDataHandle(NULL, data, len);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = AckResponseDataHandle(info, NULL, len);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = AckResponseDataHandle(info, data, len - 1);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = AckResponseDataHandle(info, data, len);
    EXPECT_EQ(SOFTBUS_OK, ret);

    SoftBusFree(info);
    SoftBusFree(resData);
}

/**
 * @tc.name: RetransFileFrameBySeq001
 * @tc.desc: RetransFileFrameBySeq, use abnormal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileHelperMockTest, RetransFileFrameBySeq001, TestSize.Level1)
{
    int32_t ret = 0;
    SendListenerInfo *info = (SendListenerInfo *)SoftBusCalloc(sizeof(SendListenerInfo));
    info->crc = APP_INFO_FILE_FEATURES_SUPPORT;
    info->packetSize = 64;
    info->fileSize = 1;
    uint32_t seq = 1;
    uint64_t seq64 = 1;
    uint16_t seq16 = 1;
    int32_t len = 0;

    NiceMock<ClientTransProxyFileHelperInterfaceMock> ClientHelperMock;
    EXPECT_CALL(ClientHelperMock, FrameIndexToType).WillRepeatedly(Return(0));
    EXPECT_CALL(ClientHelperMock, SoftBusPreadFile).WillOnce(Return(len));
    ret = RetransFileFrameBySeq(info, seq);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_DATA_LENGTH, ret);

    EXPECT_CALL(ClientHelperMock, SoftBusPreadFile).WillOnce(Return(len + 1));
    EXPECT_CALL(ClientHelperMock, SoftBusHtoLl).WillRepeatedly(Return(seq));
    EXPECT_CALL(ClientHelperMock, SoftBusHtoLll).WillRepeatedly(Return(seq64));
    EXPECT_CALL(ClientHelperMock, SoftBusHtoLs).WillRepeatedly(Return(seq16));
    EXPECT_CALL(ClientHelperMock, RTU_CRC).WillOnce(Return(seq16));
    EXPECT_CALL(ClientHelperMock, ClientTransProxyGetInfoByChannelId).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ClientHelperMock, ClientTransProxyPackAndSendData).WillRepeatedly(Return(SOFTBUS_OK));
    ret = RetransFileFrameBySeq(info, seq);
    SoftBusFree(info);
}

/**
 * @tc.name: GetAbsFullPath001
 * @tc.desc: GetAbsFullPath, use abnormal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransProxyFileHelperMockTest, GetAbsFullPath001, TestSize.Level1)
{
    int32_t ret = 0;
    SendListenerInfo *info = (SendListenerInfo *)SoftBusCalloc(sizeof(SendListenerInfo));
    info->crc = APP_INFO_FILE_FEATURES_SUPPORT;
    info->packetSize = 64;
    info->fileSize = 1;
    uint32_t seq = 1;
    uint64_t seq64 = 1;
    uint16_t seq16 = 1;
    int32_t len = 0;

    NiceMock<ClientTransProxyFileHelperInterfaceMock> ClientHelperMock;

    EXPECT_CALL(ClientHelperMock, SoftBusPreadFile).WillOnce(Return(len));
    ret = RetransFileFrameBySeq(info, seq);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_DATA_LENGTH, ret);

    EXPECT_CALL(ClientHelperMock, SoftBusPreadFile).WillOnce(Return(len + 1));
    EXPECT_CALL(ClientHelperMock, SoftBusHtoLl).WillRepeatedly(Return(seq));
    EXPECT_CALL(ClientHelperMock, SoftBusHtoLll).WillRepeatedly(Return(seq64));
    EXPECT_CALL(ClientHelperMock, SoftBusHtoLs).WillRepeatedly(Return(seq16));
    EXPECT_CALL(ClientHelperMock, RTU_CRC).WillOnce(Return(seq16));
    EXPECT_CALL(ClientHelperMock, ClientTransProxyGetInfoByChannelId).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ClientHelperMock, ClientTransProxyPackAndSendData).WillRepeatedly(Return(SOFTBUS_OK));
    ret = RetransFileFrameBySeq(info, seq);
    SoftBusFree(info);
}
}