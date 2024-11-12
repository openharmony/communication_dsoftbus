/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "common_inner.h"
#include "i_stream.h"
#include "softbus_adapter_crypto.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"
#include "stream_common.h"
#include "stream_common_data.h"

#define private   public
#define protected public
#include "stream_packetizer.cpp"
#include "stream_packetizer.h"
#undef protected
#undef private

#include <cstddef>
#include <cstdint>
#include <securec.h>

using namespace testing::ext;
using namespace Communication;
using namespace SoftBus;
namespace OHOS {
class StreamPacketizerTest : public testing::Test {
public:
    StreamPacketizerTest() { }
    ~StreamPacketizerTest() { }
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override { }
    void TearDown() override { }
};

void StreamPacketizerTest::SetUpTestCase(void) { }

void StreamPacketizerTest::TearDownTestCase(void) { }

/**
 * @tc.name: CalculateHeaderSizeTest001
 * @tc.desc: CalculateHeaderSize
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamPacketizerTest, CalculateHeaderSizeTest001, TestSize.Level1)
{
    StreamPacketizer streamPacketizer(COMMON_VIDEO_STREAM, nullptr);
    ssize_t ret = streamPacketizer.CalculateExtSize(0);
    EXPECT_EQ(ret, 0);

    const ssize_t extSize = 16;
    ret = streamPacketizer.CalculateExtSize(1);
    EXPECT_EQ(ret, extSize);
}

/**
 * @tc.name: PacketizeStreamTest001
 * @tc.desc: PacketizeStream
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamPacketizerTest, PacketizeStreamTest001, TestSize.Level1)
{
    StreamData data = {
        .buffer = std::make_unique<char[]>(1),
        .bufLen = 1,
        .extBuffer = nullptr,
        .extLen = 0,
    };
    StreamFrameInfo frameInfo = {
        .streamId = 0,
        .seqNum = 1,
        .level = 1,
        .frameType = FrameType::RADIO_MAX,
        .seqSubNum = 1,
        .bitMap = 1,
        .bitrate = 0,
    };

    std::unique_ptr<IStream> stream = IStream::MakeCommonStream(data, frameInfo);
    EXPECT_NE(stream, nullptr);
    StreamPacketizer streamPacketizer(COMMON_VIDEO_STREAM, std::move(stream));
    auto pdata = streamPacketizer.PacketizeStream();
    EXPECT_NE(pdata, nullptr);
}
} // namespace OHOS
