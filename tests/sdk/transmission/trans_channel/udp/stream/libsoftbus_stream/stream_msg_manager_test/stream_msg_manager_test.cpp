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
#include "stream_depacketizer.h"
#include "vtp_stream_socket.h"

#define private public
#include "stream_adaptor.h"
#include "stream_msg_manager.cpp"
#include "stream_msg_manager.h"
#undef private

#include <cstddef>
#include <cstdint>
#include <map>
#include <securec.h>

using namespace testing::ext;
using namespace Communication;
using namespace Communication::SoftBus;
namespace OHOS {

class StreamMsgManagerTest : public testing::Test {
public:
    StreamMsgManagerTest() { }
    ~StreamMsgManagerTest() { }
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override { }
    void TearDown() override { }
};

void StreamMsgManagerTest::SetUpTestCase(void) { }

void StreamMsgManagerTest::TearDownTestCase(void) { }

/**
 * @tc.name: SendTest001
 * @tc.desc: Send
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamMsgManagerTest, SendTest001, TestSize.Level1)
{
    std::shared_ptr<StreamMsgManager> streamMsgManger = std::make_shared<StreamMsgManager>();

    HistoryStats stats;

    streamMsgManger->Update(stats);

    streamMsgManger->Recv(stats);

    bool ret = streamMsgManger->Send(stats);
    EXPECT_EQ(ret, false);
}
} // namespace OHOS
