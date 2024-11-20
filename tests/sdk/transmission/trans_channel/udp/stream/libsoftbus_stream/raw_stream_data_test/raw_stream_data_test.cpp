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
#include <securec.h>
#include <gtest/gtest.h>

#include "softbus_error_code.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_mem.h"
#include "i_stream.h"
#include "stream_adaptor.h"

#define private public
#include "raw_stream_data.h"
#include "raw_stream_data.cpp"
#undef private

using namespace std;
using namespace testing::ext;
using namespace Communication;
using namespace SoftBus;

namespace OHOS {
#define DEVICE_ID "DEVICE_ID"

class RawStreamDataTest : public testing::Test {
public:
    RawStreamDataTest()
    {}
    ~RawStreamDataTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void RawStreamDataTest::SetUpTestCase(void)
{}

void RawStreamDataTest::TearDownTestCase(void)
{}

/**
 * @tc.name: SetTimeStamp001
 * @tc.desc: SetTimeStamp, use the wrong parameter.
 * @tc.desc: GetTimeStamp, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RawStreamDataTest, SetTimeStamp001, TestSize.Level1)
{
    std::shared_ptr<RawStreamData> rRawStreamData = std::make_shared<RawStreamData>();

    uint32_t timestamp = 0;
    rRawStreamData->SetTimeStamp(timestamp);
    uint32_t tmp = rRawStreamData->GetTimeStamp();
    EXPECT_EQ(0, (int)tmp);
    rRawStreamData->~RawStreamData();
}

/**
 * @tc.name: GetExtBuffer001
 * @tc.desc: GetExtBuffer, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RawStreamDataTest, GetExtBuffer001, TestSize.Level1)
{
    std::shared_ptr<RawStreamData> rRawStreamData = std::make_shared<RawStreamData>();

    EXPECT_EQ(nullptr, rRawStreamData->GetExtBuffer());
}

/**
 * @tc.name: GetExtBufferLen001
 * @tc.desc: GetExtBufferLen001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RawStreamDataTest, GetExtBufferLen001, TestSize.Level1)
{
    std::shared_ptr<RawStreamData> rRawStreamData = std::make_shared<RawStreamData>();

    EXPECT_EQ(0, rRawStreamData->GetExtBufferLen());
}

/**
 * @tc.name: GetSeqNum001
 * @tc.desc: GetSeqNum001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RawStreamDataTest, GetSeqNum001, TestSize.Level1)
{
    std::shared_ptr<RawStreamData> rRawStreamData = std::make_shared<RawStreamData>();

    EXPECT_EQ(0, rRawStreamData->GetSeqNum());
}
/**
 * @tc.name: GetStreamId001
 * @tc.desc: GetStreamId001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RawStreamDataTest, GetStreamId001, TestSize.Level1)
{
    std::shared_ptr<RawStreamData> rRawStreamData = std::make_shared<RawStreamData>();
    EXPECT_EQ(0, rRawStreamData->GetStreamId());
}

/**
 * @tc.name: GetStreamFrameInfo001
 * @tc.desc: GetStreamFrameInfo001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RawStreamDataTest, GetStreamFrameInfo001, TestSize.Level1)
{
    std::shared_ptr<RawStreamData> rRawStreamData = std::make_shared<RawStreamData>();

    EXPECT_NE(nullptr, rRawStreamData->GetStreamFrameInfo());
}

/**
 * @tc.name: MakeRawStream001
 * @tc.desc: MakeRawStream001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RawStreamDataTest, MakeRawStream001, TestSize.Level1)
{
    std::shared_ptr<IStream> iStream;

    Communication::SoftBus::StreamData *data =
        (Communication::SoftBus::StreamData *)SoftBusCalloc(sizeof(Communication::SoftBus::StreamData));
    ASSERT_TRUE(data != nullptr);
    Communication::SoftBus::StreamFrameInfo *info =
        (Communication::SoftBus::StreamFrameInfo *)SoftBusCalloc(sizeof(Communication::SoftBus::StreamFrameInfo));
    ASSERT_TRUE(info != nullptr);

    std::unique_ptr<IStream> tmpIStream = nullptr;
    tmpIStream = iStream->MakeRawStream(*data, *info);
    EXPECT_TRUE(tmpIStream != nullptr);

    if (data != nullptr) {
        SoftBusFree(data);
    }
    if (info != nullptr) {
        SoftBusFree(info);
    }
}

/**
 * @tc.name: MakeRawStream002
 * @tc.desc: MakeRawStream002, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RawStreamDataTest, MakeRawStream002, TestSize.Level1)
{
    std::shared_ptr<IStream> iStream;
    int32_t scene = UNKNOWN_SCENE;

    std::unique_ptr<IStream> tmpIStream = nullptr;
    std::shared_ptr<StreamAdaptor> adaptor = nullptr;
    Communication::SoftBus::StreamData *indata =
        (Communication::SoftBus::StreamData *)SoftBusCalloc(sizeof(Communication::SoftBus::StreamData));
    ASSERT_TRUE(indata != nullptr);

    Communication::SoftBus::StreamFrameInfo *info = {};

    ssize_t dataLen = indata->bufLen + adaptor->GetEncryptOverhead();
    ssize_t bufLen = MAX_STREAM_LEN;
    std::unique_ptr<char[]> data = std::make_unique<char[]>(dataLen);

    tmpIStream = iStream->MakeRawStream(data.get(), bufLen, *info, scene);
    EXPECT_TRUE(tmpIStream == nullptr);

    scene = COMPATIBLE_SCENE;
    bufLen = MAX_STREAM_LEN + 1;
    tmpIStream = iStream->MakeRawStream(data.get(), bufLen, *info, scene);
    EXPECT_TRUE(tmpIStream == nullptr);

    scene = COMPATIBLE_SCENE;
    tmpIStream = iStream->MakeRawStream(data.get(), bufLen, *info, scene);
    EXPECT_TRUE(tmpIStream == nullptr);

    scene = COMPATIBLE_SCENE - 1;
    tmpIStream = iStream->MakeRawStream(data.get(), bufLen, *info, scene);
    EXPECT_TRUE(tmpIStream == nullptr);

    if (indata != nullptr) {
        SoftBusFree(indata);
    }
}

/**
 * @tc.name: InitStreamData001
 * @tc.desc: InitStreamData001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RawStreamDataTest, InitStreamData001, TestSize.Level1)
{
    std::shared_ptr<RawStreamData> rawStreamData = std::make_shared<RawStreamData>();

    ssize_t bufLen = 22;
    auto buffer = std::make_unique<char[]>(bufLen + RawStreamData::FRAME_HEADER_LEN);

    ssize_t extLen = 33;
    auto extBuffer = std::make_unique<char[]>(extLen + RawStreamData::FRAME_HEADER_LEN);

    int32_t ret = rawStreamData->InitStreamData(std::move(buffer), bufLen, std::move(extBuffer), extLen);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: GetBuffer001
 * @tc.desc: GetBuffer001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RawStreamDataTest, GetBuffer001, TestSize.Level1)
{
    std::shared_ptr<RawStreamData> rawStreamData = std::make_shared<RawStreamData>();
    EXPECT_EQ(nullptr, rawStreamData->GetBuffer());
}

/**
 * @tc.name: GetBufferLen001
 * @tc.desc: GetBufferLen001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RawStreamDataTest, GetBufferLen001, TestSize.Level1)
{
    std::shared_ptr<RawStreamData> rawStreamData = std::make_shared<RawStreamData>();

    EXPECT_EQ(0, rawStreamData->GetBufferLen());

    ssize_t bufLen = 1;
    auto buffer = std::make_unique<char[]>(bufLen + RawStreamData::FRAME_HEADER_LEN);
    ASSERT_TRUE(buffer != nullptr);
    int32_t num = 3;
    int32_t length = 1;;

    rawStreamData->InsertBufferLength(num, length, reinterpret_cast<uint8_t *>(buffer.get()));
}
} // OHOS
