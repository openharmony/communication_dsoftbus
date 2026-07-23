/*
 * Copyright (c) 2022-2026 Huawei Device Co., Ltd.
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

#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"

#define private   public
#define protected public
#include "stream_common_data.cpp"
#include "stream_common_data.h"
#undef protected
#undef private

using namespace std;
using namespace testing::ext;
using namespace Communication;
using namespace SoftBus;
namespace OHOS {
#define DEVICE_ID "DEVICE_ID"

class StreamCommonDataTest : public testing::Test {
public:
    StreamCommonDataTest() { }
    ~StreamCommonDataTest() { }
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override { }
    void TearDown() override { }
};

void StreamCommonDataTest::SetUpTestCase(void) { }

void StreamCommonDataTest::TearDownTestCase(void) { }

/**
 * @tc.name: SetTimeStamp001
 * @tc.desc: SetTimeStamp and GetTimeStamp with zero timestamp
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamCommonDataTest, SetTimeStamp001, TestSize.Level1)
{
    std::shared_ptr<StreamCommonData> streamCommonData = std::make_shared<StreamCommonData>();
    uint32_t timestamp = 0;
    streamCommonData->SetTimeStamp(timestamp);
    int32_t ret = static_cast<int32_t>(streamCommonData->GetTimeStamp());
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: GetDefaultValues001
 * @tc.desc: Test default getter values on empty StreamCommonData
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamCommonDataTest, GetDefaultValues001, TestSize.Level1)
{
    std::shared_ptr<StreamCommonData> streamCommonData = std::make_shared<StreamCommonData>();
    EXPECT_EQ(nullptr, streamCommonData->GetBuffer());
    EXPECT_EQ(0, streamCommonData->GetBufferLen());
    EXPECT_EQ(nullptr, streamCommonData->GetExtBuffer());
    EXPECT_EQ(0, streamCommonData->GetExtBufferLen());
    EXPECT_EQ(0, streamCommonData->GetSeqNum());
    EXPECT_EQ(0, streamCommonData->GetStreamId());
    EXPECT_NE(nullptr, streamCommonData->GetStreamFrameInfo());
}

/**
 * @tc.name: MakeCommonStreamTest001
 * @tc.desc: Test MakeCommonStream returns non-null with default data.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamCommonDataTest, MakeCommonStreamTest001, TestSize.Level1)
{
    StreamData *data = reinterpret_cast<StreamData *>(SoftBusCalloc(sizeof(StreamData)));
    ASSERT_TRUE(data != nullptr);
    StreamFrameInfo *info = reinterpret_cast<StreamFrameInfo *>(SoftBusCalloc(sizeof(StreamFrameInfo)));
    ASSERT_TRUE(info != nullptr);

    std::shared_ptr<StreamCommonData> streamCommonData = std::make_shared<StreamCommonData>();
    std::unique_ptr<IStream> tmpIStream = streamCommonData->MakeCommonStream(*data, *info);
    EXPECT_TRUE(tmpIStream != nullptr);

    SoftBusFree(data);
    SoftBusFree(info);
}

/**
 * @tc.name: InitStreamDataTest001
 * @tc.desc: Test InitStreamData with nullptr buffer returns -1.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamCommonDataTest, InitStreamDataTest001, TestSize.Level1)
{
    StreamFrameInfo *frameInfo = reinterpret_cast<StreamFrameInfo *>(SoftBusCalloc(sizeof(StreamFrameInfo)));
    ASSERT_TRUE(frameInfo != nullptr);
    uint32_t streamId = 0;
    uint16_t seq = 0;
    std::shared_ptr<StreamCommonData> tmpStreamCommonData =
        std::make_shared<StreamCommonData>(streamId, seq, *frameInfo);
    StreamData *data = reinterpret_cast<StreamData *>(SoftBusCalloc(sizeof(StreamData)));
    ASSERT_TRUE(data != nullptr);
    int32_t ret = tmpStreamCommonData->InitStreamData(nullptr, data->bufLen, std::move(data->extBuffer), data->extLen);
    EXPECT_NE(SOFTBUS_OK, ret);
    SoftBusFree(data);
    SoftBusFree(frameInfo);
}

/**
 * @tc.name: InitStreamDataTest002
 * @tc.desc: Test InitStreamData with nullptr extBuffer sets extBufLen to 0.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamCommonDataTest, InitStreamDataTest002, TestSize.Level1)
{
    StreamFrameInfo *frameInfo = reinterpret_cast<StreamFrameInfo *>(SoftBusCalloc(sizeof(StreamFrameInfo)));
    ASSERT_TRUE(frameInfo != nullptr);
    uint32_t streamId = 0;
    uint16_t seq = 0;
    std::shared_ptr<StreamCommonData> tmpStreamCommonData =
        std::make_shared<StreamCommonData>(streamId, seq, *frameInfo);
    StreamData *streamData = reinterpret_cast<StreamData *>(SoftBusCalloc(sizeof(StreamData)));
    ASSERT_TRUE(streamData != nullptr);
    int32_t tmpLength = 3;
    streamData->buffer = std::make_unique<char[]>(tmpLength);
    ASSERT_TRUE(streamData->buffer != nullptr);
    StreamData *data = reinterpret_cast<StreamData *>(SoftBusCalloc(sizeof(StreamData)));
    ASSERT_TRUE(data != nullptr);
    int32_t ret =
        tmpStreamCommonData->InitStreamData(std::move(streamData->buffer), data->bufLen, nullptr, data->extLen);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_EQ(0, tmpStreamCommonData->extBufLen_);
    SoftBusFree(data);
    SoftBusFree(streamData);
    SoftBusFree(frameInfo);
}

/**
 * @tc.name: InitStreamDataTest003
 * @tc.desc: Test InitStreamData with both buffers sets extBufLen correctly.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamCommonDataTest, InitStreamDataTest003, TestSize.Level1)
{
    StreamFrameInfo *frameInfo = reinterpret_cast<StreamFrameInfo *>(SoftBusCalloc(sizeof(StreamFrameInfo)));
    ASSERT_TRUE(frameInfo != nullptr);
    uint32_t streamId = 0;
    uint16_t seq = 0;
    std::shared_ptr<StreamCommonData> tmpStreamCommonData =
        std::make_shared<StreamCommonData>(streamId, seq, *frameInfo);
    StreamData *streamData = reinterpret_cast<StreamData *>(SoftBusCalloc(sizeof(StreamData)));
    ASSERT_TRUE(streamData != nullptr);
    int32_t tmpLength = 3;
    streamData->buffer = std::make_unique<char[]>(tmpLength);
    ASSERT_TRUE(streamData->buffer != nullptr);
    StreamData *data = reinterpret_cast<StreamData *>(SoftBusCalloc(sizeof(StreamData)));
    ASSERT_TRUE(data != nullptr);
    data->extLen = 2;
    data->buffer = std::make_unique<char[]>(tmpLength);
    ASSERT_TRUE(data->buffer != nullptr);
    int32_t ret = tmpStreamCommonData->InitStreamData(
        std::move(streamData->buffer), data->bufLen, std::move(data->buffer), data->extLen);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_EQ(data->extLen, tmpStreamCommonData->extBufLen_);
    SoftBusFree(data);
    SoftBusFree(streamData);
    SoftBusFree(frameInfo);
}
} // namespace OHOS
