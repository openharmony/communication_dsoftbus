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

#include <gtest/gtest.h>
#include <securec.h>

#include "lnn_common_utils.h"
#include "softbus_adapter_crypto.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"
#include "softbus_init_common.h"

namespace OHOS {
using namespace testing::ext;

constexpr uint32_t TEST_KEY_LEN = 32;
constexpr uint32_t TEST_DATA_LEN = 16;
constexpr uint8_t TEST_KEY[SESSION_KEY_LENGTH] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
};
constexpr uint8_t TEST_DATA[TEST_DATA_LEN] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10
};

class LnnCommonUtilsTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void LnnCommonUtilsTest::SetUpTestCase() { }

void LnnCommonUtilsTest::TearDownTestCase() { }

void LnnCommonUtilsTest::SetUp() { }

void LnnCommonUtilsTest::TearDown() { }

/*
 * @tc.name: LNN_IS_ENABLE_SOFTBUS_HEARTBEAT_TEST_001
 * @tc.desc: Verify IsEnableSoftBusHeartbeat returns true
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(LnnCommonUtilsTest, LNN_IS_ENABLE_SOFTBUS_HEARTBEAT_TEST_001, TestSize.Level1)
{
    bool result = IsEnableSoftBusHeartbeat();
    EXPECT_TRUE(result);
}

/*
 * @tc.name: LNN_IS_SCREEN_UNLOCK_TEST_001
 * @tc.desc: Verify IsScreenUnlock returns true
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(LnnCommonUtilsTest, LNN_IS_SCREEN_UNLOCK_TEST_001, TestSize.Level1)
{
    bool result = IsScreenUnlock();
    EXPECT_TRUE(result);
}

/*
 * @tc.name: LNN_ENCRYPT_AES_GCM_TEST_002
 * @tc.desc: Verify LnnEncryptAesGcm handles null output parameter
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(LnnCommonUtilsTest, LNN_ENCRYPT_AES_GCM_TEST_002, TestSize.Level1)
{
    AesGcmInputParam in;
    uint8_t data[TEST_DATA_LEN] = {0};
    uint8_t key[TEST_KEY_LEN] = {0};

    in.data = data;
    in.dataLen = TEST_DATA_LEN;
    in.key = key;
    in.keyLen = TEST_KEY_LEN;

    int32_t ret = LnnEncryptAesGcm(&in, 0, nullptr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LNN_ENCRYPT_AES_GCM_TEST_003
 * @tc.desc: Verify LnnEncryptAesGcm handles invalid data length
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(LnnCommonUtilsTest, LNN_ENCRYPT_AES_GCM_TEST_003, TestSize.Level1)
{
    AesGcmInputParam in;
    uint8_t key[TEST_KEY_LEN] = {0};

    in.data = nullptr;
    in.dataLen = UINT32_MAX - OVERHEAD_LEN + 1; // Invalid length
    in.key = key;
    in.keyLen = TEST_KEY_LEN;

    uint8_t *out = nullptr;
    uint32_t outLen = 0;

    int32_t ret = LnnEncryptAesGcm(&in, 0, &out, &outLen);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LNN_ENCRYPT_AES_GCM_TEST_004
 * @tc.desc: Verify LnnEncryptAesGcm encrypts valid data successfully
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(LnnCommonUtilsTest, LNN_ENCRYPT_AES_GCM_TEST_004, TestSize.Level1)
{
    AesGcmInputParam in;
    uint8_t data[TEST_DATA_LEN] = {0};
    uint8_t key[TEST_KEY_LEN] = {0};

    (void)memcpy_s(data, TEST_DATA_LEN, TEST_DATA, TEST_DATA_LEN);
    (void)memcpy_s(key, TEST_KEY_LEN, TEST_KEY, TEST_KEY_LEN);

    in.data = data;
    in.dataLen = TEST_DATA_LEN;
    in.key = key;
    in.keyLen = TEST_KEY_LEN;

    uint8_t *out = nullptr;
    uint32_t outLen = 0;

    int32_t ret = LnnEncryptAesGcm(&in, 0, &out, &outLen);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_NE(out, nullptr);
    EXPECT_EQ(outLen, TEST_DATA_LEN + OVERHEAD_LEN);

    if (out != nullptr) {
        SoftBusFree(out);
    }
}

/*
 * @tc.name: LNN_DECRYPT_AES_GCM_TEST_002
 * @tc.desc: Verify LnnDecryptAesGcm handles null output parameter
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(LnnCommonUtilsTest, LNN_DECRYPT_AES_GCM_TEST_002, TestSize.Level1)
{
    AesGcmInputParam in;
    uint8_t data[TEST_DATA_LEN + OVERHEAD_LEN] = {0};
    uint8_t key[TEST_KEY_LEN] = {0};

    in.data = data;
    in.dataLen = TEST_DATA_LEN + OVERHEAD_LEN;
    in.key = key;
    in.keyLen = TEST_KEY_LEN;

    int32_t ret = LnnDecryptAesGcm(&in, nullptr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LNN_DECRYPT_AES_GCM_TEST_003
 * @tc.desc: Verify LnnDecryptAesGcm handles invalid data length (too short)
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(LnnCommonUtilsTest, LNN_DECRYPT_AES_GCM_TEST_003, TestSize.Level1)
{
    AesGcmInputParam in;
    uint8_t data[TEST_DATA_LEN] = {0};
    uint8_t key[TEST_KEY_LEN] = {0};

    in.data = data;
    in.dataLen = OVERHEAD_LEN - 1;
    in.key = key;
    in.keyLen = TEST_KEY_LEN;

    uint8_t *out = nullptr;
    uint32_t outLen = 0;

    int32_t ret = LnnDecryptAesGcm(&in, &out, &outLen);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LNN_DECRYPT_AES_GCM_TEST_004
 * @tc.desc: Verify LnnDecryptAesGcm handles edge case data length
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(LnnCommonUtilsTest, LNN_DECRYPT_AES_GCM_TEST_004, TestSize.Level1)
{
    AesGcmInputParam in;
    uint8_t data[OVERHEAD_LEN] = {0};
    uint8_t key[TEST_KEY_LEN] = {0};

    in.data = data;
    in.dataLen = OVERHEAD_LEN;
    in.key = key;
    in.keyLen = TEST_KEY_LEN;

    uint8_t *out = nullptr;
    uint32_t outLen = 0;

    int32_t ret = LnnDecryptAesGcm(&in, &out, &outLen);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LNN_ENCRYPT_DECRYPT_AES_GCM_TEST_001
 * @tc.desc: Verify encrypt then decrypt produces original data
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(LnnCommonUtilsTest, LNN_ENCRYPT_DECRYPT_AES_GCM_TEST_001, TestSize.Level1)
{
    AesGcmInputParam encIn;
    AesGcmInputParam decIn;
    uint8_t data[TEST_DATA_LEN] = {0};
    uint8_t key[TEST_KEY_LEN] = {0};

    (void)memcpy_s(data, TEST_DATA_LEN, TEST_DATA, TEST_DATA_LEN);
    (void)memcpy_s(key, TEST_KEY_LEN, TEST_KEY, TEST_KEY_LEN);

    encIn.data = data;
    encIn.dataLen = TEST_DATA_LEN;
    encIn.key = key;
    encIn.keyLen = TEST_KEY_LEN;

    uint8_t *encrypted = nullptr;
    uint32_t encLen = 0;

    int32_t ret = LnnEncryptAesGcm(&encIn, 0, &encrypted, &encLen);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_NE(encrypted, nullptr);
    EXPECT_EQ(encLen, TEST_DATA_LEN + OVERHEAD_LEN);

    if (encrypted == nullptr) {
        return;
    }

    decIn.data = encrypted;
    decIn.dataLen = encLen;
    decIn.key = key;
    decIn.keyLen = TEST_KEY_LEN;

    uint8_t *decrypted = nullptr;
    uint32_t decLen = 0;

    ret = LnnDecryptAesGcm(&decIn, &decrypted, &decLen);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_NE(decrypted, nullptr);
    EXPECT_EQ(decLen, TEST_DATA_LEN);

    if (decrypted != nullptr) {
        EXPECT_EQ(memcmp(decrypted, TEST_DATA, TEST_DATA_LEN), 0);
        SoftBusFree(decrypted);
    }

    SoftBusFree(encrypted);
}

/*
 * @tc.name: LNN_ENCRYPT_AES_GCM_TEST_005
 * @tc.desc: Verify LnnEncryptAesGcm with 16-byte key
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(LnnCommonUtilsTest, LNN_ENCRYPT_AES_GCM_TEST_005, TestSize.Level1)
{
    AesGcmInputParam in;
    uint8_t data[TEST_DATA_LEN] = {0};
    uint8_t key[16] = {0};

    (void)memcpy_s(data, TEST_DATA_LEN, TEST_DATA, TEST_DATA_LEN);

    in.data = data;
    in.dataLen = TEST_DATA_LEN;
    in.key = key;
    in.keyLen = 16;

    uint8_t *out = nullptr;
    uint32_t outLen = 0;

    int32_t ret = LnnEncryptAesGcm(&in, 0, &out, &outLen);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_NE(out, nullptr);

    if (out != nullptr) {
        SoftBusFree(out);
    }
}
} // namespace OHOS
