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
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"
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
 * @tc.name: SoftBusAesCfbRootEncrypt001
 * @tc.desc: parameters are Legal
 * @tc.type: FUNC
 * @tc.require: I5OHDE
 */
HWTEST_F(AdapterDsoftbusAesCryptoTest, SoftBusAesCfbRootEncrypt001, TestSize.Level0)
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

    ret = SoftBusAesCfbRootEncrypt(&encryptInData, &randomKey, &rootKey, ENCRYPT_MODE, &encryptOutData);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SoftBusAesCfbRootEncrypt(
        (const AesInputData *)&encryptOutData, &randomKey, &rootKey, DECRYPT_MODE, &decryptOutData);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = memcmp((const char *)decryptOutData.data, (const char *)encryptInData.data, decryptOutData.len);
    EXPECT_EQ(0, ret);
    SoftBusFree(encryptOutData.data);
    SoftBusFree(decryptOutData.data);
}

/*
 * @tc.name: SoftBusAesCfbRootEncrypt002
 * @tc.desc: encrypt parameter is nullptr
 * @tc.type: FUNC
 * @tc.require: I5OHDE
 */
HWTEST_F(AdapterDsoftbusAesCryptoTest, SoftBusAesCfbRootEncrypt002, TestSize.Level0)
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

    ret = SoftBusAesCfbRootEncrypt(nullptr, &randomKey, &rootKey, ENCRYPT_MODE, &encryptOutData);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = SoftBusAesCfbRootEncrypt(
        (const AesInputData *)&encryptOutData, &randomKey, &rootKey, DECRYPT_MODE, &decryptOutData);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = SoftBusAesCfbRootEncrypt(&encryptInData, nullptr, &rootKey, ENCRYPT_MODE, &encryptOutData);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = SoftBusAesCfbRootEncrypt(
        (const AesInputData *)&encryptOutData, &randomKey, &rootKey, DECRYPT_MODE, &decryptOutData);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = SoftBusAesCfbRootEncrypt(&encryptInData, &randomKey, nullptr, ENCRYPT_MODE, &encryptOutData);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = SoftBusAesCfbRootEncrypt(
        (const AesInputData *)&encryptOutData, &randomKey, &rootKey, DECRYPT_MODE, &decryptOutData);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = SoftBusAesCfbRootEncrypt(&encryptInData, &randomKey, &rootKey, ENCRYPT_MODE, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = SoftBusAesCfbRootEncrypt(
        (const AesInputData *)&encryptOutData, &randomKey, &rootKey, DECRYPT_MODE, &decryptOutData);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: SoftBusAesCfbRootEncrypt003
 * @tc.desc: decrypt parameter is nullptr
 * @tc.type: FUNC
 * @tc.require: I5OHDE
 */
HWTEST_F(AdapterDsoftbusAesCryptoTest, SoftBusAesCfbRootEncrypt003, TestSize.Level0)
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

    ret = SoftBusAesCfbRootEncrypt(&encryptInData, &randomKey, &rootKey, ENCRYPT_MODE, &encryptOutData);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = SoftBusAesCfbRootEncrypt(nullptr, &randomKey, &rootKey, DECRYPT_MODE, &decryptOutData);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = SoftBusAesCfbRootEncrypt(
        (const AesInputData *)&encryptOutData, nullptr, &rootKey, DECRYPT_MODE, &decryptOutData);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = SoftBusAesCfbRootEncrypt(
        (const AesInputData *)&encryptOutData, &randomKey, nullptr, DECRYPT_MODE, &decryptOutData);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = SoftBusAesCfbRootEncrypt((const AesInputData *)&encryptOutData, &randomKey, &rootKey, DECRYPT_MODE, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    SoftBusFree(encryptOutData.data);
}

/*
 * @tc.name: SoftBusAesCfbRootEncrypt004
 * @tc.desc: encMode is illegal
 * @tc.type: FUNC
 * @tc.require: I5OHDE
 */
HWTEST_F(AdapterDsoftbusAesCryptoTest, SoftBusAesCfbRootEncrypt004, TestSize.Level0)
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

    ret = SoftBusAesCfbRootEncrypt(&encryptInData, &randomKey, &rootKey, encMode, &encryptOutData);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = SoftBusAesCfbRootEncrypt(
        (const AesInputData *)&encryptOutData, &randomKey, &rootKey, DECRYPT_MODE, &decryptOutData);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = SoftBusAesCfbRootEncrypt(&encryptInData, &randomKey, &rootKey, ENCRYPT_MODE, &encryptOutData);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret =
        SoftBusAesCfbRootEncrypt((const AesInputData *)&encryptOutData, &randomKey, &rootKey, encMode, &decryptOutData);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    SoftBusFree(encryptOutData.data);
}

/*
 * @tc.name: SoftBusAesGcmEncrypt001
 * @tc.desc: parameters are Legal
 * @tc.type: FUNC
 * @tc.require: I5OHDE
 */
HWTEST_F(AdapterDsoftbusAesCryptoTest, SoftBusAesGcmEncrypt001, TestSize.Level0)
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

    ret = SoftBusAesGcmEncrypt(&encryptInData, &cipherKey, ENCRYPT_MODE, &encryptOutData);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SoftBusAesGcmEncrypt((const AesInputData *)&encryptOutData, &cipherKey, DECRYPT_MODE, &decryptOutData);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = memcmp((const char *)decryptOutData.data, (const char *)encryptInData.data, decryptOutData.len);
    EXPECT_EQ(0, ret);
    SoftBusFree(encryptOutData.data);
    SoftBusFree(decryptOutData.data);
}

/*
 * @tc.name: SoftBusAesGcmEncrypt002
 * @tc.desc: encrypt parameter is nullptr
 * @tc.type: FUNC
 * @tc.require: I5OHDE
 */
HWTEST_F(AdapterDsoftbusAesCryptoTest, SoftBusAesGcmEncrypt002, TestSize.Level0)
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

    ret = SoftBusAesGcmEncrypt(nullptr, &cipherKey, ENCRYPT_MODE, &encryptOutData);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = SoftBusAesGcmEncrypt((const AesInputData *)&encryptOutData, &cipherKey, DECRYPT_MODE, &decryptOutData);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = SoftBusAesGcmEncrypt(&encryptInData, nullptr, ENCRYPT_MODE, &encryptOutData);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = SoftBusAesGcmEncrypt((const AesInputData *)&encryptOutData, &cipherKey, DECRYPT_MODE, &decryptOutData);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = SoftBusAesGcmEncrypt(&encryptInData, &cipherKey, ENCRYPT_MODE, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = SoftBusAesGcmEncrypt((const AesInputData *)&encryptOutData, &cipherKey, DECRYPT_MODE, &decryptOutData);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: SoftBusAesGcmEncrypt003
 * @tc.desc: decrypt parameter is nullptr
 * @tc.type: FUNC
 * @tc.require: I5OHDE
 */
HWTEST_F(AdapterDsoftbusAesCryptoTest, SoftBusAesGcmEncrypt003, TestSize.Level0)
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

    ret = SoftBusAesGcmEncrypt(&encryptInData, &cipherKey, ENCRYPT_MODE, &encryptOutData);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = SoftBusAesGcmEncrypt(nullptr, &cipherKey, DECRYPT_MODE, &decryptOutData);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = SoftBusAesGcmEncrypt((const AesInputData *)&encryptOutData, nullptr, DECRYPT_MODE, &decryptOutData);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = SoftBusAesGcmEncrypt((const AesInputData *)&encryptOutData, &cipherKey, DECRYPT_MODE, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    SoftBusFree(encryptOutData.data);
}

/*
 * @tc.name: SoftBusAesGcmEncrypt004
 * @tc.desc: decrypt parameter is nullptr
 * @tc.type: FUNC
 * @tc.require: I5OHDE
 */
HWTEST_F(AdapterDsoftbusAesCryptoTest, SoftBusAesGcmEncrypt004, TestSize.Level0)
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

    ret = SoftBusAesGcmEncrypt(&encryptInData, &cipherKey, encMode, &encryptOutData);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = SoftBusAesGcmEncrypt((const AesInputData *)&encryptOutData, &cipherKey, DECRYPT_MODE, &decryptOutData);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = SoftBusAesGcmEncrypt(&encryptInData, &cipherKey, ENCRYPT_MODE, &encryptOutData);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SoftBusAesGcmEncrypt((const AesInputData *)&encryptOutData, &cipherKey, encMode, &decryptOutData);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    SoftBusFree(encryptOutData.data);
}

/*
 * @tc.name: SoftBusAesCfbEncrypt001
 * @tc.desc: parameters are Legal
 * @tc.type: FUNC
 * @tc.require: I5OHDE
 */
HWTEST_F(AdapterDsoftbusAesCryptoTest, SoftBusAesCfbEncrypt001, TestSize.Level0)
{
    uint32_t randKeyLen = 32;
    uint32_t randIvLen = 16;
    uint32_t inDataLen = 10;
    uint8_t inData[inDataLen];
    uint8_t randSession[randKeyLen];
    uint8_t randIv[randIvLen];
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

    uint8_t randSession1[randKeyLen];
    (void)memcpy_s(randSession1, randKeyLen, randSession, randKeyLen);
    uint8_t randIv1[randIvLen];
    (void)memcpy_s(randIv1, randIvLen, randIv, randIvLen);

    ret = SoftBusAesCfbEncrypt(&encryptInData, &cipherKey, ENCRYPT_MODE, &encryptOutData);
    EXPECT_EQ(SOFTBUS_OK, ret);

    AesCipherKey cipherKey1 = { randSession1, randKeyLen, randIv1, randIvLen };
    ret = SoftBusAesCfbEncrypt((const AesInputData *)&encryptOutData, &cipherKey1, DECRYPT_MODE, &decryptOutData);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = memcmp((const char *)decryptOutData.data, (const char *)encryptInData.data, decryptOutData.len);
    EXPECT_EQ(0, ret);
    SoftBusFree(encryptOutData.data);
    SoftBusFree(decryptOutData.data);
}

/*
 * @tc.name: SoftBusAesCfbEncrypt002
 * @tc.desc: encrypt parameter is nullptr
 * @tc.require: I5OHDE
 */
HWTEST_F(AdapterDsoftbusAesCryptoTest, SoftBusAesCfbEncrypt002, TestSize.Level0)
{
    uint32_t randKeyLen = 32;
    uint32_t randIvLen = 16;
    uint32_t inDataLen = 10;
    uint8_t inData[inDataLen];
    uint8_t randSession[randKeyLen];
    uint8_t randIv[randIvLen];
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

    uint8_t randSession1[randKeyLen];
    (void)memcpy_s(randSession1, randKeyLen, randSession, randKeyLen);
    uint8_t randIv1[randIvLen];
    (void)memcpy_s(randIv1, randIvLen, randIv, randIvLen);
    AesCipherKey cipherKey1 = { randSession1, randKeyLen, randIv1, randIvLen };

    ret = SoftBusAesCfbEncrypt(nullptr, &cipherKey, ENCRYPT_MODE, &encryptOutData);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = SoftBusAesCfbEncrypt((const AesInputData *)&encryptOutData, &cipherKey1, DECRYPT_MODE, &decryptOutData);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = SoftBusAesCfbEncrypt(&encryptInData, nullptr, ENCRYPT_MODE, &encryptOutData);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = SoftBusAesCfbEncrypt((const AesInputData *)&encryptOutData, &cipherKey1, DECRYPT_MODE, &decryptOutData);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = SoftBusAesCfbEncrypt(&encryptInData, &cipherKey, ENCRYPT_MODE, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = SoftBusAesCfbEncrypt((const AesInputData *)&encryptOutData, &cipherKey1, DECRYPT_MODE, &decryptOutData);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: SoftBusAesCfbEncrypt003
 * @tc.desc: decrypt parameter is nullptr
 * @tc.type: FUNC
 * @tc.require: I5OHDE
 */
HWTEST_F(AdapterDsoftbusAesCryptoTest, SoftBusAesCfbEncrypt003, TestSize.Level0)
{
    uint32_t randKeyLen = 32;
    uint32_t randIvLen = 16;
    uint32_t inDataLen = 10;
    uint8_t inData[inDataLen];
    uint8_t randSession[randKeyLen];
    uint8_t randIv[randIvLen];
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

    uint8_t randSession1[randKeyLen];
    (void)memcpy_s(randSession1, randKeyLen, randSession, randKeyLen);
    uint8_t randIv1[randIvLen];
    (void)memcpy_s(randIv1, randIvLen, randIv, randIvLen);
    AesCipherKey cipherKey1 = { randSession1, randKeyLen, randIv1, randIvLen };

    ret = SoftBusAesCfbEncrypt(&encryptInData, &cipherKey, ENCRYPT_MODE, &encryptOutData);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = SoftBusAesCfbEncrypt(nullptr, &cipherKey1, DECRYPT_MODE, &decryptOutData);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = SoftBusAesCfbEncrypt((const AesInputData *)&encryptOutData, nullptr, DECRYPT_MODE, &decryptOutData);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = SoftBusAesCfbEncrypt((const AesInputData *)&encryptOutData, &cipherKey1, DECRYPT_MODE, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    SoftBusFree(encryptOutData.data);
}

/*
 * @tc.name: SoftBusAesCfbEncrypt004
 * @tc.desc: encMode is illegal
 * @tc.type: FUNC
 * @tc.require: I5OHDE
 */
HWTEST_F(AdapterDsoftbusAesCryptoTest, SoftBusAesCfbEncrypt004, TestSize.Level0)
{
    uint32_t randKeyLen = 32;
    uint32_t randIvLen = 16;
    uint32_t inDataLen = 10;
    int32_t encMode = 2;
    uint8_t inData[inDataLen];
    uint8_t randSession[randKeyLen];
    uint8_t randIv[randIvLen];
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

    uint8_t randSession1[randKeyLen];
    (void)memcpy_s(randSession1, randKeyLen, randSession, randKeyLen);
    uint8_t randIv1[randIvLen];
    (void)memcpy_s(randIv1, randIvLen, randIv, randIvLen);
    AesCipherKey cipherKey1 = { randSession1, randKeyLen, randIv1, randIvLen };

    ret = SoftBusAesCfbEncrypt(&encryptInData, &cipherKey, encMode, &encryptOutData);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = SoftBusAesCfbEncrypt((const AesInputData *)&encryptOutData, &cipherKey1, DECRYPT_MODE, &decryptOutData);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = SoftBusAesCfbEncrypt(&encryptInData, &cipherKey, ENCRYPT_MODE, &encryptOutData);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SoftBusAesCfbEncrypt((const AesInputData *)&encryptOutData, &cipherKey1, encMode, &decryptOutData);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    SoftBusFree(encryptOutData.data);
}
} // namespace OHOS
