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

#include "softbus_aes_encrypt.h"

#include <cstring>
#include <securec.h>

#include "softbus_adapter_crypto.h"
#include "softbus_adapter_log.h"
#include "softbus_adapter_mem.h"
#include "softbus_errcode.h"
#include "gtest/gtest.h"

using namespace std;
using namespace testing::ext;

namespace OHOS {
class AdapterDsoftbusAesCryptoTest : public testing::Test {
protected:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};
void AdapterDsoftbusAesCryptoTest::SetUpTestCase(void) { }
void AdapterDsoftbusAesCryptoTest::TearDownTestCase(void) { }
void AdapterDsoftbusAesCryptoTest::SetUp() { }
void AdapterDsoftbusAesCryptoTest::TearDown() { }

/*
 * @tc.name: SoftBusGenerateHmacHash001
 * @tc.desc: parameters are Legal
 * @tc.type: FUNC
 * @tc.require: I5OHDE
 */
HWTEST_F(AdapterDsoftbusAesCryptoTest, SoftBusGenerateHmacHash001, TestSize.Level0)
{
    uint32_t randLen = 8;
    uint32_t rootKeyLen = 16;
    uint32_t hashLen = 32;
    uint8_t randStr[randLen];
    uint8_t rootKey[rootKeyLen];
    uint8_t hash[hashLen];

    int32_t ret = SoftBusGenerateRandomArray(randStr, randLen);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SoftBusGenerateRandomArray(rootKey, rootKeyLen);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EncryptKey randomKey = { randStr, randLen };

    ret = SoftBusGenerateHmacHash(&randomKey, rootKey, rootKeyLen, hash, hashLen);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: SoftBusGenerateHmacHash002
 * @tc.desc: parameter is nullptr
 * @tc.type: FUNC
 * @tc.require: I5OHDE
 */
HWTEST_F(AdapterDsoftbusAesCryptoTest, SoftBusGenerateHmacHash002, TestSize.Level0)
{
    uint32_t randLen = 8;
    uint32_t rootKeyLen = 16;
    uint32_t hashLen = 32;
    uint8_t randStr[randLen];
    uint8_t rootKey[rootKeyLen];
    uint8_t hash[hashLen];

    int32_t ret = SoftBusGenerateRandomArray(randStr, randLen);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SoftBusGenerateRandomArray(rootKey, rootKeyLen);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EncryptKey randomKey = { randStr, randLen };

    ret = SoftBusGenerateHmacHash(nullptr, rootKey, rootKeyLen, hash, hashLen);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = SoftBusGenerateHmacHash(&randomKey, nullptr, rootKeyLen, hash, hashLen);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = SoftBusGenerateHmacHash(&randomKey, rootKey, rootKeyLen, nullptr, hashLen);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: SoftBusGenerateHmacHash003
 * @tc.desc: rootKeyLen or hashLen is illegal
 * @tc.type: FUNC
 * @tc.require: I5OHDE
 */
HWTEST_F(AdapterDsoftbusAesCryptoTest, SoftBusGenerateHmacHash003, TestSize.Level0)
{
    uint32_t randLen = 8;
    uint32_t rootKeyLen = 16;
    uint32_t hashLen = 32;
    uint32_t rootKeyLen1 = 0;
    uint32_t hashLen1 = 0;
    uint8_t randStr[randLen];
    uint8_t rootKey[rootKeyLen];
    uint8_t hash[hashLen];

    int32_t ret = SoftBusGenerateRandomArray(randStr, randLen);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SoftBusGenerateRandomArray(rootKey, rootKeyLen);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EncryptKey randomKey = { randStr, randLen };

    ret = SoftBusGenerateHmacHash(&randomKey, rootKey, rootKeyLen1, hash, hashLen);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = SoftBusGenerateHmacHash(&randomKey, rootKey, rootKeyLen, hash, hashLen1);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: SoftbusAesCfbRootEncrypt001
 * @tc.desc: parameters are Legal
 * @tc.type: FUNC
 * @tc.require: I5OHDE
 */
HWTEST_F(AdapterDsoftbusAesCryptoTest, SoftbusAesCfbRootEncrypt001, TestSize.Level0)
{
    uint32_t randLen = 8;
    uint32_t inDataLen = 10;
    uint32_t rootKeyLen = 16;
    uint8_t randStr[randLen];
    uint8_t inData[inDataLen];
    uint8_t rKey[rootKeyLen];
    AesOutputData encryptOutData = { 0 };
    AesOutputData decryptOutData = { 0 };

    int32_t ret = SoftBusGenerateRandomArray(inData, inDataLen);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SoftBusGenerateRandomArray(randStr, randLen);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SoftBusGenerateRandomArray(rKey, rootKeyLen);
    EXPECT_EQ(SOFTBUS_OK, ret);
    AesInputData encryptInData = { inData, inDataLen };
    EncryptKey randomKey = { randStr, randLen };
    EncryptKey rootKey = { rKey, rootKeyLen };

    ret = SoftbusAesCfbRootEncrypt(&encryptInData, &randomKey, &rootKey, ENCRYPT_MODE, &encryptOutData);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SoftbusAesCfbRootEncrypt(
        (const AesInputData *)&encryptOutData, &randomKey, &rootKey, DECRYPT_MODE, &decryptOutData);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = memcmp((const char *)decryptOutData.data, (const char *)encryptInData.data, decryptOutData.len);
    EXPECT_EQ(SOFTBUS_OK, ret);
    SoftBusFree(encryptOutData.data);
    SoftBusFree(decryptOutData.data);
}

/*
 * @tc.name: SoftbusAesCfbRootEncrypt002
 * @tc.desc: encrypt parameter is nullptr
 * @tc.type: FUNC
 * @tc.require: I5OHDE
 */
HWTEST_F(AdapterDsoftbusAesCryptoTest, SoftbusAesCfbRootEncrypt002, TestSize.Level0)
{
    uint32_t randLen = 8;
    uint32_t inDataLen = 10;
    uint32_t rootKeyLen = 16;
    uint8_t randStr[randLen];
    uint8_t inData[inDataLen];
    uint8_t rKey[rootKeyLen];
    AesOutputData encryptOutData = { 0 };
    AesOutputData decryptOutData = { 0 };

    int32_t ret = SoftBusGenerateRandomArray(inData, inDataLen);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SoftBusGenerateRandomArray(randStr, randLen);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SoftBusGenerateRandomArray(rKey, rootKeyLen);
    EXPECT_EQ(SOFTBUS_OK, ret);
    AesInputData encryptInData = { inData, inDataLen };
    EncryptKey randomKey = { randStr, randLen };
    EncryptKey rootKey = { rKey, rootKeyLen };

    ret = SoftbusAesCfbRootEncrypt(nullptr, &randomKey, &rootKey, ENCRYPT_MODE, &encryptOutData);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = SoftbusAesCfbRootEncrypt(
        (const AesInputData *)&encryptOutData, &randomKey, &rootKey, DECRYPT_MODE, &decryptOutData);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = SoftbusAesCfbRootEncrypt(&encryptInData, nullptr, &rootKey, ENCRYPT_MODE, &encryptOutData);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = SoftbusAesCfbRootEncrypt(
        (const AesInputData *)&encryptOutData, &randomKey, &rootKey, DECRYPT_MODE, &decryptOutData);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = SoftbusAesCfbRootEncrypt(&encryptInData, &randomKey, nullptr, ENCRYPT_MODE, &encryptOutData);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = SoftbusAesCfbRootEncrypt(
        (const AesInputData *)&encryptOutData, &randomKey, &rootKey, DECRYPT_MODE, &decryptOutData);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = SoftbusAesCfbRootEncrypt(&encryptInData, &randomKey, &rootKey, ENCRYPT_MODE, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = SoftbusAesCfbRootEncrypt(
        (const AesInputData *)&encryptOutData, &randomKey, &rootKey, DECRYPT_MODE, &decryptOutData);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: SoftbusAesCfbRootEncrypt003
 * @tc.desc: decrypt parameter is nullptr
 * @tc.type: FUNC
 * @tc.require: I5OHDE
 */
HWTEST_F(AdapterDsoftbusAesCryptoTest, SoftbusAesCfbRootEncrypt003, TestSize.Level0)
{
    uint32_t randLen = 8;
    uint32_t inDataLen = 10;
    uint32_t rootKeyLen = 16;
    uint8_t randStr[randLen];
    uint8_t inData[inDataLen];
    uint8_t rKey[rootKeyLen];
    AesOutputData encryptOutData = { 0 };
    AesOutputData decryptOutData = { 0 };

    int32_t ret = SoftBusGenerateRandomArray(inData, inDataLen);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SoftBusGenerateRandomArray(randStr, randLen);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SoftBusGenerateRandomArray(rKey, rootKeyLen);
    EXPECT_EQ(SOFTBUS_OK, ret);
    AesInputData encryptInData = { inData, inDataLen };
    EncryptKey randomKey = { randStr, randLen };
    EncryptKey rootKey = { rKey, rootKeyLen };

    ret = SoftbusAesCfbRootEncrypt(&encryptInData, &randomKey, &rootKey, ENCRYPT_MODE, &encryptOutData);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = SoftbusAesCfbRootEncrypt(nullptr, &randomKey, &rootKey, DECRYPT_MODE, &decryptOutData);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = SoftbusAesCfbRootEncrypt(
        (const AesInputData *)&encryptOutData, nullptr, &rootKey, DECRYPT_MODE, &decryptOutData);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = SoftbusAesCfbRootEncrypt(
        (const AesInputData *)&encryptOutData, &randomKey, nullptr, DECRYPT_MODE, &decryptOutData);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = SoftbusAesCfbRootEncrypt((const AesInputData *)&encryptOutData, &randomKey, &rootKey, DECRYPT_MODE, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    SoftBusFree(encryptOutData.data);
}

/*
 * @tc.name: SoftbusAesCfbRootEncrypt004
 * @tc.desc: encMode is illegal
 * @tc.type: FUNC
 * @tc.require: I5OHDE
 */
HWTEST_F(AdapterDsoftbusAesCryptoTest, SoftbusAesCfbRootEncrypt004, TestSize.Level0)
{
    uint32_t randLen = 8;
    uint32_t inDataLen = 10;
    uint32_t rootKeyLen = 16;
    int32_t encMode = 2;
    uint8_t randStr[randLen];
    uint8_t inData[inDataLen];
    uint8_t rKey[rootKeyLen];
    AesOutputData encryptOutData = { 0 };
    AesOutputData decryptOutData = { 0 };

    int32_t ret = SoftBusGenerateRandomArray(inData, inDataLen);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SoftBusGenerateRandomArray(randStr, randLen);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SoftBusGenerateRandomArray(rKey, rootKeyLen);
    EXPECT_EQ(SOFTBUS_OK, ret);
    AesInputData encryptInData = { inData, inDataLen };
    EncryptKey randomKey = { randStr, randLen };
    EncryptKey rootKey = { rKey, rootKeyLen };

    ret = SoftbusAesCfbRootEncrypt(&encryptInData, &randomKey, &rootKey, encMode, &encryptOutData);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = SoftbusAesCfbRootEncrypt(
        (const AesInputData *)&encryptOutData, &randomKey, &rootKey, DECRYPT_MODE, &decryptOutData);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = SoftbusAesCfbRootEncrypt(&encryptInData, &randomKey, &rootKey, ENCRYPT_MODE, &encryptOutData);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret =
        SoftbusAesCfbRootEncrypt((const AesInputData *)&encryptOutData, &randomKey, &rootKey, encMode, &decryptOutData);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    SoftBusFree(encryptOutData.data);
}

/*
 * @tc.name: SoftbusAesGcmEncrypt001
 * @tc.desc: parameters are Legal
 * @tc.type: FUNC
 * @tc.require: I5OHDE
 */
HWTEST_F(AdapterDsoftbusAesCryptoTest, SoftbusAesGcmEncrypt001, TestSize.Level0)
{
    uint32_t randKeyLen = 32;
    uint32_t randIvLen = 16;
    uint32_t inDataLen = 10;
    uint8_t randSession[randKeyLen];
    uint8_t randIv[randIvLen];
    uint8_t inData[inDataLen];
    AesOutputData encryptOutData = { 0 };
    AesOutputData decryptOutData = { 0 };

    int32_t ret = SoftBusGenerateRandomArray(inData, inDataLen);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SoftBusGenerateRandomArray(randSession, randKeyLen);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SoftBusGenerateRandomArray(randIv, randIvLen);
    EXPECT_EQ(SOFTBUS_OK, ret);
    AesInputData encryptInData = { inData, inDataLen };
    AesCipherKey cipherKey = { randSession, randKeyLen, randIv, randIvLen };

    ret = SoftbusAesGcmEncrypt(&encryptInData, &cipherKey, ENCRYPT_MODE, &encryptOutData);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SoftbusAesGcmEncrypt((const AesInputData *)&encryptOutData, &cipherKey, DECRYPT_MODE, &decryptOutData);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = memcmp((const char *)decryptOutData.data, (const char *)encryptInData.data, decryptOutData.len);
    EXPECT_EQ(SOFTBUS_OK, ret);
    SoftBusFree(encryptOutData.data);
    SoftBusFree(decryptOutData.data);
}

/*
 * @tc.name: SoftbusAesGcmEncrypt002
 * @tc.desc: encrypt parameter is nullptr
 * @tc.type: FUNC
 * @tc.require: I5OHDE
 */
HWTEST_F(AdapterDsoftbusAesCryptoTest, SoftbusAesGcmEncrypt002, TestSize.Level0)
{
    uint32_t randKeyLen = 32;
    uint32_t randIvLen = 16;
    uint32_t inDataLen = 10;
    uint8_t randSession[randKeyLen];
    uint8_t randIv[randIvLen];
    uint8_t inData[inDataLen];
    AesOutputData encryptOutData = { 0 };
    AesOutputData decryptOutData = { 0 };

    int32_t ret = SoftBusGenerateRandomArray(inData, inDataLen);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SoftBusGenerateRandomArray(randSession, randKeyLen);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SoftBusGenerateRandomArray(randIv, randIvLen);
    EXPECT_EQ(SOFTBUS_OK, ret);
    AesInputData encryptInData = { inData, inDataLen };
    AesCipherKey cipherKey = { randSession, randKeyLen, randIv, randIvLen };

    ret = SoftbusAesGcmEncrypt(nullptr, &cipherKey, ENCRYPT_MODE, &encryptOutData);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = SoftbusAesGcmEncrypt((const AesInputData *)&encryptOutData, &cipherKey, DECRYPT_MODE, &decryptOutData);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = SoftbusAesGcmEncrypt(&encryptInData, nullptr, ENCRYPT_MODE, &encryptOutData);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = SoftbusAesGcmEncrypt((const AesInputData *)&encryptOutData, &cipherKey, DECRYPT_MODE, &decryptOutData);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = SoftbusAesGcmEncrypt(&encryptInData, &cipherKey, ENCRYPT_MODE, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = SoftbusAesGcmEncrypt((const AesInputData *)&encryptOutData, &cipherKey, DECRYPT_MODE, &decryptOutData);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: SoftbusAesGcmEncrypt003
 * @tc.desc: decrypt parameter is nullptr
 * @tc.type: FUNC
 * @tc.require: I5OHDE
 */
HWTEST_F(AdapterDsoftbusAesCryptoTest, SoftbusAesGcmEncrypt003, TestSize.Level0)
{
    uint32_t randKeyLen = 32;
    uint32_t randIvLen = 16;
    uint32_t inDataLen = 10;
    uint8_t randSession[randKeyLen];
    uint8_t randIv[randIvLen];
    uint8_t inData[inDataLen];
    AesOutputData encryptOutData = { 0 };
    AesOutputData decryptOutData = { 0 };

    int32_t ret = SoftBusGenerateRandomArray(inData, inDataLen);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SoftBusGenerateRandomArray(randSession, randKeyLen);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SoftBusGenerateRandomArray(randIv, randIvLen);
    EXPECT_EQ(SOFTBUS_OK, ret);
    AesInputData encryptInData = { inData, inDataLen };
    AesCipherKey cipherKey = { randSession, randKeyLen, randIv, randIvLen };

    ret = SoftbusAesGcmEncrypt(&encryptInData, &cipherKey, ENCRYPT_MODE, &encryptOutData);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = SoftbusAesGcmEncrypt(nullptr, &cipherKey, DECRYPT_MODE, &decryptOutData);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = SoftbusAesGcmEncrypt((const AesInputData *)&encryptOutData, nullptr, DECRYPT_MODE, &decryptOutData);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = SoftbusAesGcmEncrypt((const AesInputData *)&encryptOutData, &cipherKey, DECRYPT_MODE, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    SoftBusFree(encryptOutData.data);
}

/*
 * @tc.name: SoftbusAesGcmEncrypt004
 * @tc.desc: decrypt parameter is nullptr
 * @tc.type: FUNC
 * @tc.require: I5OHDE
 */
HWTEST_F(AdapterDsoftbusAesCryptoTest, SoftbusAesGcmEncrypt004, TestSize.Level0)
{
    uint32_t randKeyLen = 32;
    uint32_t randIvLen = 16;
    uint32_t inDataLen = 10;
    int32_t encMode = 2;
    uint8_t randSession[randKeyLen];
    uint8_t randIv[randIvLen];
    uint8_t inData[inDataLen];
    AesOutputData encryptOutData = { 0 };
    AesOutputData decryptOutData = { 0 };

    int32_t ret = SoftBusGenerateRandomArray(inData, inDataLen);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SoftBusGenerateRandomArray(randSession, randKeyLen);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SoftBusGenerateRandomArray(randIv, randIvLen);
    EXPECT_EQ(SOFTBUS_OK, ret);
    AesInputData encryptInData = { inData, inDataLen };
    AesCipherKey cipherKey = { randSession, randKeyLen, randIv, randIvLen };

    ret = SoftbusAesGcmEncrypt(&encryptInData, &cipherKey, encMode, &encryptOutData);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = SoftbusAesGcmEncrypt((const AesInputData *)&encryptOutData, &cipherKey, DECRYPT_MODE, &decryptOutData);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = SoftbusAesGcmEncrypt(&encryptInData, &cipherKey, ENCRYPT_MODE, &encryptOutData);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SoftbusAesGcmEncrypt((const AesInputData *)&encryptOutData, &cipherKey, encMode, &decryptOutData);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    SoftBusFree(encryptOutData.data);
}
} // namespace OHOS
