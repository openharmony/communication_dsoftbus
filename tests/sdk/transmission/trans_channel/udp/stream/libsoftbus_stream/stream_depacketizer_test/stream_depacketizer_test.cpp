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

#include "common_inner.h"
#include "i_stream.h"
#include "softbus_adapter_crypto.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"
#include "stream_common.h"

#define private   public
#define protected public
#include "stream_depacketizer.cpp"
#include "stream_depacketizer.h"
#undef protected
#undef private

#include <cstddef>
#include <cstdint>
#include <securec.h>

using namespace testing::ext;
namespace OHOS {
class StreamDepacketizerTest : public testing::Test {
public:
    StreamDepacketizerTest() { }
    ~StreamDepacketizerTest() { }
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override { }
    void TearDown() override { }
};

void StreamDepacketizerTest::SetUpTestCase(void) { }

void StreamDepacketizerTest::TearDownTestCase(void) { }

/**
 * @tc.name: GetDefaultValues001
 * @tc.desc: stream depacketizer getter methods return zero or nullptr on uninitialized state
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamDepacketizerTest, GetDefaultValues001, TestSize.Level1)
{
    int32_t streamType = Communication::SoftBus::COMMON_VIDEO_STREAM;
    std::shared_ptr<Communication::SoftBus::StreamDepacketizer> streamDepacketizer =
        std::make_shared<Communication::SoftBus::StreamDepacketizer>(streamType);

    int32_t ret = streamDepacketizer->GetHeaderDataLen();
    EXPECT_EQ(0, ret);

    EXPECT_EQ(nullptr, streamDepacketizer->GetUserExt());
    ret = streamDepacketizer->GetUserExtSize();
    EXPECT_EQ(0, ret);

    EXPECT_EQ(nullptr, streamDepacketizer->GetData());
    ret = streamDepacketizer->GetDataLength();
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: DepacketizeHeader001
 * @tc.desc: DepacketizeHeader with COMMON_VIDEO_STREAM does not crash
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamDepacketizerTest, DepacketizeHeader001, TestSize.Level1)
{
    int32_t streamType = Communication::SoftBus::COMMON_VIDEO_STREAM;
    std::shared_ptr<Communication::SoftBus::StreamDepacketizer> streamDepacketizer =
        std::make_shared<Communication::SoftBus::StreamDepacketizer>(streamType);
    char header[Communication::SoftBus::MAX_STREAM_LEN - OVERHEAD_LEN + 1] = { 0 };
    EXPECT_NO_FATAL_FAILURE(streamDepacketizer->DepacketizeHeader(header));
    int32_t ret = streamDepacketizer->GetHeaderDataLen();
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: DepacketizeHeader002
 * @tc.desc: DepacketizeHeader with COMMON_AUDIO_STREAM does not crash
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamDepacketizerTest, DepacketizeHeader002, TestSize.Level1)
{
    int32_t streamType = Communication::SoftBus::COMMON_VIDEO_STREAM;
    std::shared_ptr<Communication::SoftBus::StreamDepacketizer> streamDepacketizer =
        std::make_shared<Communication::SoftBus::StreamDepacketizer>(streamType);
    streamDepacketizer->streamType_ = Communication::SoftBus::COMMON_AUDIO_STREAM;
    char header[Communication::SoftBus::MAX_STREAM_LEN - OVERHEAD_LEN + 1] = { 0 };
    EXPECT_NO_FATAL_FAILURE(streamDepacketizer->DepacketizeHeader(header));
    int32_t ret = streamDepacketizer->GetHeaderDataLen();
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: DepacketizeBuffer001
 * @tc.desc: DepacketizeBuffer with zeroed buffer does not crash
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamDepacketizerTest, DepacketizeBuffer001, TestSize.Level1)
{
    int32_t streamType = Communication::SoftBus::COMMON_VIDEO_STREAM;
    std::shared_ptr<Communication::SoftBus::StreamDepacketizer> streamDepacketizer =
        std::make_shared<Communication::SoftBus::StreamDepacketizer>(streamType);
    char buffer[Communication::SoftBus::MAX_STREAM_LEN - OVERHEAD_LEN + 1] = { 0 };
    EXPECT_NO_FATAL_FAILURE(streamDepacketizer->DepacketizeBuffer(buffer, sizeof(buffer)));
    int32_t ret = streamDepacketizer->GetDataLength();
    EXPECT_EQ(0, ret);
}
} // namespace OHOS
