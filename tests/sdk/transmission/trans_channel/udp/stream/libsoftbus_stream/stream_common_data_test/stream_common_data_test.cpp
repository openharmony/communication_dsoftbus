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
#include <securec.h>

#include "softbus_error_code.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_mem.h"

#define private public
#define protected public
#include "stream_common_data.h"
#include "stream_common_data.cpp"
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
    StreamCommonDataTest()
    {}
    ~StreamCommonDataTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void StreamCommonDataTest::SetUpTestCase(void)
{}

void StreamCommonDataTest::TearDownTestCase(void)
{}

/**
 * @tc.name: InitStreamData001
 * @tc.desc: InitStreamData001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamCommonDataTest, InitStreamData001, TestSize.Level1)
{
    std::shared_ptr<StreamCommonData> streamCommonData = std::make_shared<StreamCommonData>();
    uint32_t timestamp = 0;

    streamCommonData->SetTimeStamp(timestamp);

    int32_t ret = (int32_t)streamCommonData->GetTimeStamp();
    EXPECT_EQ(0, ret);
 
    auto buffer = streamCommonData->GetBuffer();
    EXPECT_TRUE(buffer == nullptr);

    ret = streamCommonData->GetBufferLen();
    EXPECT_EQ(0, ret);
    EXPECT_EQ(nullptr, streamCommonData->GetExtBuffer());

    ret = streamCommonData->GetExtBufferLen();
    EXPECT_EQ(0, ret);

    ret = streamCommonData->GetSeqNum();
    EXPECT_EQ(0, ret);

    ret = streamCommonData->GetStreamId();
    EXPECT_EQ(0, ret);

    streamCommonData->GetStreamFrameInfo();
    streamCommonData->~StreamCommonData();
}

/**
 * @tc.name: MakeCommonStream001
 * @tc.desc: MakeCommonStream, use the wrong parameter.
 * @tc.desc: InitStreamData, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamCommonDataTest, MakeCommonStream001, TestSize.Level1)
{
    StreamData *data = (StreamData *)SoftBusCalloc(sizeof(StreamData));
    ASSERT_TRUE(data != nullptr);
    StreamFrameInfo *info = (StreamFrameInfo *)SoftBusCalloc(sizeof(StreamFrameInfo));
    ASSERT_TRUE(info != nullptr);

    std::shared_ptr<StreamCommonData> streamCommonData = std::make_shared<StreamCommonData>();
    std::unique_ptr<IStream> tmpIStream = nullptr;

    tmpIStream = streamCommonData->MakeCommonStream(*data, *info);
    EXPECT_TRUE(tmpIStream != nullptr);

    streamCommonData->~StreamCommonData();

    uint32_t streamId;
    uint16_t seq;
    StreamFrameInfo *frameInfo = (StreamFrameInfo *)SoftBusCalloc(sizeof(StreamFrameInfo));
    ASSERT_TRUE(frameInfo != nullptr);
    std::shared_ptr<StreamCommonData> tmpStreamCommonData =
        std::make_shared<StreamCommonData>(streamId, seq, *frameInfo);

    int32_t ret = tmpStreamCommonData->InitStreamData(nullptr, data->bufLen, std::move(data->extBuffer), data->extLen);
    EXPECT_EQ(-1, ret);

    StreamData *streamData = (StreamData *)SoftBusCalloc(sizeof(StreamData));
    ASSERT_TRUE(streamData != nullptr);

    int32_t tmpLength = 3;
    streamData->buffer = std::make_unique<char[]>(tmpLength);
    ASSERT_TRUE(std::move(streamData->buffer) != nullptr);

    ret = tmpStreamCommonData->InitStreamData(std::move(streamData->buffer), data->bufLen, nullptr, data->extLen);
    EXPECT_EQ(0, tmpStreamCommonData->extBufLen_);

    data->extLen = 2;
    data->buffer = std::make_unique<char[]>(tmpLength);

    streamData->buffer = std::make_unique<char[]>(tmpLength);
    ASSERT_TRUE(std::move(streamData->buffer) != nullptr);
    ASSERT_TRUE(std::move(data->buffer) != nullptr);
    ret = tmpStreamCommonData->InitStreamData(std::move(streamData->buffer), data->bufLen, std::move(data->buffer),
        data->extLen);
    EXPECT_EQ(data->extLen, tmpStreamCommonData->extBufLen_);

    SoftBusFree(data);
    SoftBusFree(info);
    SoftBusFree(frameInfo);
    SoftBusFree(streamData);
}
} // OHOS
