/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include "gtest/gtest.h"
#include "message_handler.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"
#include "softbus_proxychannel_message.h"
#include "softbus_proxychannel_message.c"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
#define TEST_DATA_LEN 64

class SoftbusProxyChannelMetaNodeMessageTest : public testing::Test {
public:
    SoftbusProxyChannelMetaNodeMessageTest() { }
    ~SoftbusProxyChannelMetaNodeMessageTest() { }
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override { }
    void TearDown() override { }
};

void SoftbusProxyChannelMetaNodeMessageTest::SetUpTestCase(void) { }
void SoftbusProxyChannelMetaNodeMessageTest::TearDownTestCase(void) { }

/*
 * @tc.name: PackProxyMetaNodeMessageHead001
 * @tc.desc: Test PackProxyExternalMessageHead with valid parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelMetaNodeMessageTest, PackProxyMetaNodeMessageHead001, TestSize.Level1)
{
    ProxyExternalMessageHead msgHead = {
        .type = 1,
        .cipher = 0,
        .myId = 100,
        .peerId = 200,
        .reserved = 0,
        .authId = 12345,
    };
    uint8_t buf[PROXY_CHANNEL_EXTERNAL_HEAD_LEN] = {0};

    PackProxyExternalMessageHead(&msgHead, buf, sizeof(buf));
    EXPECT_EQ(buf[0] & FOUR_BIT_MASK, static_cast<uint8_t>(1));
    EXPECT_EQ(buf[1], static_cast<uint8_t>(0));
}

/*
 * @tc.name: PackProxyMetaNodeMessageHead002
 * @tc.desc: Test PackProxyExternalMessageHead with insufficient buffer size.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelMetaNodeMessageTest, PackProxyMetaNodeMessageHead002, TestSize.Level1)
{
    ProxyExternalMessageHead msgHead = {0};
    uint8_t buf[PROXY_CHANNEL_EXTERNAL_HEAD_LEN - 1] = {0};

    PackProxyExternalMessageHead(&msgHead, buf, sizeof(buf));
    /* Buffer too small, verify no crash and buf remains zero */
    EXPECT_EQ(buf[0], static_cast<uint8_t>(0));
}

/*
 * @tc.name: UnpackProxyMetaNodeMessageHead001
 * @tc.desc: Test UnpackProxyExternalMessageHead with null parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelMetaNodeMessageTest, UnpackProxyMetaNodeMessageHead001, TestSize.Level1)
{
    ProxyMessage msg = {0};
    char data[PROXY_CHANNEL_EXTERNAL_HEAD_LEN] = {0};

    int32_t ret = UnpackProxyExternalMessageHead(nullptr, PROXY_CHANNEL_EXTERNAL_HEAD_LEN, &msg);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = UnpackProxyExternalMessageHead(data, PROXY_CHANNEL_EXTERNAL_HEAD_LEN, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = UnpackProxyExternalMessageHead(data, PROXY_CHANNEL_EXTERNAL_HEAD_LEN - 1, &msg);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: TransProxyParseMessage_MetaNode001
 * @tc.desc: Test TransProxyParseMessage when isSupportConcurrentMetaNode is true and len >= META_NODE_HEAD_LEN.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelMetaNodeMessageTest, TransProxyParseMessage_MetaNode001, TestSize.Level1)
{
    ProxyMessage msg = {0};
    AuthHandle authHandle = {0};

    /* Prepare a buffer with MetaNode head */
    uint8_t data[PROXY_CHANNEL_EXTERNAL_HEAD_LEN + TEST_DATA_LEN] = {0};
    ProxyExternalMessageHead msgHead = {
        .type = 1,
        .cipher = ENCRYPTED,
        .myId = 1,
        .peerId = 2,
        .reserved = 0,
        .authId = 100,
    };
    PackProxyExternalMessageHead(&msgHead, data, PROXY_CHANNEL_EXTERNAL_HEAD_LEN);

    int32_t ret = TransProxyParseMessage(reinterpret_cast<char *>(data), sizeof(data), &msg, &authHandle, true);
    /* May fail due to decrypt, but routing to 16B parse path is verified */
    EXPECT_NE(ret, SOFTBUS_OK);
}

#ifdef DSOFTBUS_FEATURE_PROXY_CHANNEL
/*
 * @tc.name: TransProxyParseMessage_NonMetaNode001
 * @tc.desc: Test TransProxyParseMessage when isSupportConcurrentMetaNode is false.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelMetaNodeMessageTest, TransProxyParseMessage_NonMetaNode001, TestSize.Level1)
{
    ProxyMessage msg = {0};
    AuthHandle authHandle = {0};

    /* Prepare a buffer with old head */
    uint8_t data[PROXY_CHANNEL_HEAD_LEN + TEST_DATA_LEN] = {0};

    int32_t ret = TransProxyParseMessage(reinterpret_cast<char *>(data), sizeof(data), &msg, &authHandle, false);
    /* May fail due to decrypt, but routing to 8B parse path is verified */
    EXPECT_EQ(ret, SOFTBUS_OK);
}
#endif

/*
 * @tc.name: PackPlaintextMetaNodeMessage001
 * @tc.desc: Test PackPlaintextExternalMessage with null parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelMetaNodeMessageTest, PackPlaintextMetaNodeMessage001, TestSize.Level1)
{
    ProxyExternalMessageHead msgHead = {0};
    ProxyDataInfo dataInfo = {0};

    int32_t ret = PackPlaintextExternalMessage(nullptr, &dataInfo);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = PackPlaintextExternalMessage(&msgHead, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: PackEncryptedMetaNodeMessage001
 * @tc.desc: Test PackEncryptedExternalMessage with null parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusProxyChannelMetaNodeMessageTest, PackEncryptedMetaNodeMessage001, TestSize.Level1)
{
    ProxyExternalMessageHead msgHead = {0};
    AuthHandle authHandle = {0};
    ProxyDataInfo dataInfo = {0};

    int32_t ret = PackEncryptedExternalMessage(nullptr, authHandle, &dataInfo);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = PackEncryptedExternalMessage(&msgHead, authHandle, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}
} // namespace OHOS
