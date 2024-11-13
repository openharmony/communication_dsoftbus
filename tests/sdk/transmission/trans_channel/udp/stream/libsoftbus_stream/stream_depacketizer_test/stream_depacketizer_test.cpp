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

#include "softbus_error_code.h"
#include "softbus_adapter_mem.h"
#include "stream_common.h"
#include "common_inner.h"
#include "i_stream.h"
#include "softbus_adapter_crypto.h"

#define private public
#define protected public
#include "stream_depacketizer.h"
#include "stream_depacketizer.cpp"
#undef protected
#undef private

#include <securec.h>
#include <cstddef>
#include <cstdint>

using namespace testing::ext;
namespace OHOS {
class StreamDepacketizerTest : public testing::Test {
public:
    StreamDepacketizerTest()
    {}
    ~StreamDepacketizerTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void StreamDepacketizerTest::SetUpTestCase(void)
{}

void StreamDepacketizerTest::TearDownTestCase(void)
{}

/**
 * @tc.name: GetDataLength001
 * @tc.desc: GetDataLength001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamDepacketizerTest, GetDataLength001, TestSize.Level1)
{
    int32_t streamType_ = Communication::SoftBus::COMMON_VIDEO_STREAM;
    std::shared_ptr<Communication::SoftBus::StreamDepacketizer> streamDepacketizer =
        std::make_shared<Communication::SoftBus::StreamDepacketizer>(streamType_);

    int32_t ret = streamDepacketizer->GetHeaderDataLen();
    EXPECT_EQ(0, ret);

    streamDepacketizer->GetUserExt();
    ret = streamDepacketizer->GetUserExtSize();
    EXPECT_EQ(0, ret);

    streamDepacketizer->GetData();
    ret = streamDepacketizer->GetDataLength();
    EXPECT_EQ(0, ret);

    streamDepacketizer->~StreamDepacketizer();
}

/**
 * @tc.name: DepacketizeHeader001
 * @tc.desc: DepacketizeHeader, use the wrong parameter.
 * @tc.desc: DepacketizeBuffer, use the wrong parameter.
 * @tc.desc: GetDataLength, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamDepacketizerTest, DepacketizeHeader001, TestSize.Level1)
{
    int32_t streamType_ = Communication::SoftBus::COMMON_VIDEO_STREAM;
    std::shared_ptr<Communication::SoftBus::StreamDepacketizer> streamDepacketizer =
        std::make_shared<Communication::SoftBus::StreamDepacketizer>(streamType_);

    char header[Communication::SoftBus::MAX_STREAM_LEN - OVERHEAD_LEN + 1]  = {0};
    char buffer[Communication::SoftBus::MAX_STREAM_LEN - OVERHEAD_LEN + 1]  = {0};

    streamDepacketizer->DepacketizeHeader((char *)header);

    streamDepacketizer->streamType_ = Communication::SoftBus::COMMON_VIDEO_STREAM;
    streamDepacketizer->DepacketizeHeader((char *)header);

    streamDepacketizer->streamType_ = Communication::SoftBus::COMMON_AUDIO_STREAM;
    streamDepacketizer->DepacketizeHeader((char *)header);

    streamDepacketizer->DepacketizeBuffer((char *)buffer, sizeof(buffer));

    int32_t ret = streamDepacketizer->GetDataLength();
    EXPECT_EQ(0, ret);
}
} // OHOS
