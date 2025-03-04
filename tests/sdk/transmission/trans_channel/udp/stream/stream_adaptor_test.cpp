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
#include <iostream>
#include <gtest/gtest.h>

#include "session.h"
#include "softbus_error_code.h"
#include "stream_adaptor.h"

using namespace testing::ext;

#define STREAM_ADAPT_DATA_LENGTH 10

namespace OHOS {
class StreamAdaptorTest : public testing::Test {
public:
    StreamAdaptorTest()
    {}
    ~StreamAdaptorTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void StreamAdaptorTest::SetUpTestCase(void)
{}

void StreamAdaptorTest::TearDownTestCase(void)
{}

void SetStatus(int32_t channelId, int32_t status)
{
    std::cout << "[server]:channelID:" << channelId << ", status:" << status << std::endl;
}

static IStreamListener g_callback = {
    .OnStatusChange = SetStatus,
};
static char g_pkgName[] = "test";
static char g_ip[] = "127.0.0.1";
static VtpStreamOpenParam g_param = {
    g_pkgName,
    g_ip,
    NULL,
    -1,
    RAW_STREAM,
    (uint8_t*)"abcdef@ghabcdefghabcdefghfgdabc",
    SESSION_KEY_LENGTH,
};

/**
 * @tc.name: InitAdaptorTest001
 * @tc.desc: InitAdaptor branch test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamAdaptorTest, InitAdaptorTest001, TestSize.Level0)
{
    int32_t channelId = 1;
    std::shared_ptr<StreamAdaptor> adaptor = std::make_shared<StreamAdaptor>(g_pkgName);
    adaptor->InitAdaptor(channelId, &g_param, true, &g_callback);
    EXPECT_EQ(adaptor->GetChannelId(), channelId);
    adaptor->InitAdaptor(channelId, &g_param, false, &g_callback);
    EXPECT_EQ(adaptor->GetChannelId(), channelId);
    adaptor->ReleaseAdaptor();
}

/**
 * @tc.name: EncryptTest001
 * @tc.desc: Encrypt error.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamAdaptorTest, EncryptTest001, TestSize.Level0)
{
    int32_t channelId = 1;
    StreamData streamData = {
        (char *)"",
        0,
    };
    std::shared_ptr<StreamAdaptor> adaptor = std::make_shared<StreamAdaptor>(g_pkgName);
    adaptor->InitAdaptor(channelId, &g_param, true, &g_callback);
    ssize_t dataLen = streamData.bufLen + adaptor->GetEncryptOverhead();
    std::unique_ptr<char[]> data = std::make_unique<char[]>(dataLen);
    int32_t ret = adaptor->Encrypt(streamData.buf, streamData.bufLen, data.get(), dataLen, adaptor->GetSessionKey());
    EXPECT_EQ(SOFTBUS_ENCRYPT_ERR, ret);
    ret = adaptor->Decrypt(data.get(), dataLen, streamData.buf, streamData.bufLen, adaptor->GetSessionKey());
    EXPECT_EQ(SOFTBUS_DECRYPT_ERR, ret);
    adaptor->ReleaseAdaptor();
}

/**
 * @tc.name: EncryptTest002
 * @tc.desc: Encrypt success, Decrypt error.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamAdaptorTest, EncryptTest002, TestSize.Level0)
{
    int32_t channelId = 1;
    StreamData streamData = {
        (char *)"balabalab\0",
        STREAM_ADAPT_DATA_LENGTH,
    };
    std::shared_ptr<StreamAdaptor> adaptor = std::make_shared<StreamAdaptor>(g_pkgName);
    adaptor->InitAdaptor(channelId, &g_param, true, &g_callback);
    ssize_t dataLen = streamData.bufLen + adaptor->GetEncryptOverhead();
    std::unique_ptr<char[]> data = std::make_unique<char[]>(dataLen);
    int32_t ret = adaptor->Encrypt(streamData.buf, streamData.bufLen, data.get(), dataLen, adaptor->GetSessionKey());
    EXPECT_EQ(dataLen, ret);
    ret = adaptor->Decrypt(data.get(), dataLen + 1, streamData.buf, streamData.bufLen, adaptor->GetSessionKey());
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    adaptor->ReleaseAdaptor();
}
}