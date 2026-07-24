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
#include <iostream>

#include "session.h"
#include "softbus_error_code.h"
#include "stream_adaptor.h"

using namespace testing::ext;

#define STREAM_ADAPT_DATA_LENGTH 10

namespace OHOS {
class StreamAdaptorTest : public testing::Test {
public:
    StreamAdaptorTest() { }
    ~StreamAdaptorTest() { }
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override { }
    void TearDown() override { }
};

void StreamAdaptorTest::SetUpTestCase(void) { }

void StreamAdaptorTest::TearDownTestCase(void) { }

void SetStatus(int32_t channelId, int32_t status)
{
    std::cout << "SetStatus, channelId=" << channelId << ", status=" << status << std::endl;
}

static IStreamListener g_callback = {
    .OnStatusChange = SetStatus,
};
static char g_pkgName[] = "test";
static char g_ip[] = "127.0.0.1";
static char g_sessionKeyData[] = "abcdef@ghabcdefghabcdefghfgdabc";
static VtpStreamOpenParam g_param = {
    g_pkgName,
    g_ip,
    nullptr,
    -1,
    RAW_STREAM,
    reinterpret_cast<uint8_t *>(g_sessionKeyData),
    SESSION_KEY_LENGTH,
};

/*
 * @tc.name: InitAdaptorTest01
 * @tc.desc: test InitAdaptor with isServerSide=true
 *           Stream adaptor init adaptor as server side
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamAdaptorTest, InitAdaptorTest01, TestSize.Level1)
{
    int32_t channelId = 1;
    std::shared_ptr<StreamAdaptor> adaptor = std::make_shared<StreamAdaptor>(g_pkgName);
    adaptor->InitAdaptor(channelId, &g_param, true, &g_callback);
    EXPECT_EQ(adaptor->GetChannelId(), channelId);
    adaptor->ReleaseAdaptor();
}

/*
 * @tc.name: InitAdaptorTest02
 * @tc.desc: test InitAdaptor with isServerSide=false
 *           Stream adaptor init adaptor as client side
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamAdaptorTest, InitAdaptorTest02, TestSize.Level1)
{
    int32_t channelId = 1;
    std::shared_ptr<StreamAdaptor> adaptor = std::make_shared<StreamAdaptor>(g_pkgName);
    adaptor->InitAdaptor(channelId, &g_param, false, &g_callback);
    EXPECT_EQ(adaptor->GetChannelId(), channelId);
    adaptor->ReleaseAdaptor();
}

/*
 * @tc.name: InitAdaptorTest03
 * @tc.desc: test InitAdaptor with null param
 *           Stream adaptor init adaptor with null param returns early
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamAdaptorTest, InitAdaptorTest03, TestSize.Level1)
{
    int32_t channelId = 1;
    std::shared_ptr<StreamAdaptor> adaptor = std::make_shared<StreamAdaptor>(g_pkgName);
    EXPECT_EQ(adaptor->GetChannelId(), -1);
    adaptor->InitAdaptor(channelId, nullptr, true, &g_callback);
    EXPECT_EQ(adaptor->GetChannelId(), -1);
}

/*
 * @tc.name: EncryptTest01
 * @tc.desc: test Encrypt with empty data returns encrypt error
 *           Stream adaptor encrypt with empty data
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamAdaptorTest, EncryptTest01, TestSize.Level1)
{
    int32_t channelId = 1;
    StreamData streamData = { const_cast<char *>(""), 0 };
    std::shared_ptr<StreamAdaptor> adaptor = std::make_shared<StreamAdaptor>(g_pkgName);
    adaptor->InitAdaptor(channelId, &g_param, true, &g_callback);
    ssize_t dataLen = streamData.bufLen + adaptor->GetEncryptOverhead();
    std::unique_ptr<char[]> data = std::make_unique<char[]>(dataLen);
    int32_t ret = adaptor->Encrypt(streamData.buf, streamData.bufLen, data.get(), dataLen, adaptor->GetSessionKey());
    EXPECT_EQ(SOFTBUS_ENCRYPT_ERR, ret);
    adaptor->ReleaseAdaptor();
}

/*
 * @tc.name: EncryptTest02
 * @tc.desc: test Encrypt with valid data returns success
 *           Stream adaptor encrypt with valid data
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamAdaptorTest, EncryptTest02, TestSize.Level1)
{
    int32_t channelId = 1;
    StreamData streamData = { const_cast<char *>("balabalab"), STREAM_ADAPT_DATA_LENGTH };
    std::shared_ptr<StreamAdaptor> adaptor = std::make_shared<StreamAdaptor>(g_pkgName);
    adaptor->InitAdaptor(channelId, &g_param, true, &g_callback);
    ssize_t dataLen = streamData.bufLen + adaptor->GetEncryptOverhead();
    std::unique_ptr<char[]> data = std::make_unique<char[]>(dataLen);
    int32_t ret = adaptor->Encrypt(streamData.buf, streamData.bufLen, data.get(), dataLen, adaptor->GetSessionKey());
    EXPECT_EQ(dataLen, ret);
    adaptor->ReleaseAdaptor();
}

/*
 * @tc.name: DecryptTest01
 * @tc.desc: test Decrypt with empty data returns decrypt error
 *           Stream adaptor decrypt with empty data
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamAdaptorTest, DecryptTest01, TestSize.Level1)
{
    int32_t channelId = 1;
    StreamData streamData = { const_cast<char *>(""), 0 };
    std::shared_ptr<StreamAdaptor> adaptor = std::make_shared<StreamAdaptor>(g_pkgName);
    adaptor->InitAdaptor(channelId, &g_param, true, &g_callback);
    ssize_t dataLen = streamData.bufLen + adaptor->GetEncryptOverhead();
    std::unique_ptr<char[]> data = std::make_unique<char[]>(dataLen);
    int32_t ret = adaptor->Decrypt(data.get(), dataLen, streamData.buf, streamData.bufLen, adaptor->GetSessionKey());
    EXPECT_EQ(SOFTBUS_DECRYPT_ERR, ret);
    adaptor->ReleaseAdaptor();
}

/*
 * @tc.name: DecryptTest02
 * @tc.desc: test Decrypt with inLen exceeding actual encrypted length returns invalid param
 *           Stream adaptor decrypt with invalid inLen
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamAdaptorTest, DecryptTest02, TestSize.Level1)
{
    int32_t channelId = 1;
    StreamData streamData = { const_cast<char *>("balabalab"), STREAM_ADAPT_DATA_LENGTH };
    std::shared_ptr<StreamAdaptor> adaptor = std::make_shared<StreamAdaptor>(g_pkgName);
    adaptor->InitAdaptor(channelId, &g_param, true, &g_callback);
    ssize_t dataLen = streamData.bufLen + adaptor->GetEncryptOverhead();
    std::unique_ptr<char[]> data = std::make_unique<char[]>(dataLen);
    adaptor->Encrypt(streamData.buf, streamData.bufLen, data.get(), dataLen, adaptor->GetSessionKey());
    int32_t ret =
        adaptor->Decrypt(data.get(), dataLen + 1, streamData.buf, streamData.bufLen, adaptor->GetSessionKey());
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    adaptor->ReleaseAdaptor();
}
} // namespace OHOS
