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

#include "softbus_rsa_encrypt.h"

#include <securec.h>

#include "softbus_adapter_crypto.h"
#include "softbus_adapter_log.h"
#include "softbus_adapter_mem.h"
#include "softbus_errcode.h"
#include "gtest/gtest.h"

using namespace std;
using namespace testing::ext;

namespace OHOS {
class AdapterDsoftbusRsaCryptoTest : public testing::Test {
protected:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};
void AdapterDsoftbusRsaCryptoTest::SetUpTestCase(void) { }
void AdapterDsoftbusRsaCryptoTest::TearDownTestCase(void) { }
void AdapterDsoftbusRsaCryptoTest::SetUp() { }
void AdapterDsoftbusRsaCryptoTest::TearDown() { }

/*
 * @tc.name: SoftbusGetPublicKey001
 * @tc.desc: parameters are Legal
 * @tc.type: FUNC
 * @tc.require: I5OHDE
 */
HWTEST_F(AdapterDsoftbusRsaCryptoTest, SoftbusGetPublicKey001, TestSize.Level0)
{
    uint32_t pKeyLen = SOFTBUS_RSA_PUB_KEY_LEN;
    uint8_t publicKey[pKeyLen];
    int32_t ret = SoftbusGetPublicKey(publicKey, pKeyLen);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: SoftbusGetPublicKey002
 * @tc.desc: parameter is nullptr
 * @tc.type: FUNC
 * @tc.require: I5OHDE
 */
HWTEST_F(AdapterDsoftbusRsaCryptoTest, SoftbusGetPublicKey002, TestSize.Level0)
{
    uint32_t pKeyLen = SOFTBUS_RSA_PUB_KEY_LEN;
    int32_t ret = SoftbusGetPublicKey(nullptr, pKeyLen);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: SoftbusGetPublicKey003
 * @tc.desc: len is illegal
 * @tc.type: FUNC
 * @tc.require: I5OHDE
 */
HWTEST_F(AdapterDsoftbusRsaCryptoTest, SoftbusGetPublicKey003, TestSize.Level0)
{
    uint8_t publicKey[SOFTBUS_RSA_PUB_KEY_LEN];
    uint32_t pKeyLen = 0;
    int32_t ret = SoftbusGetPublicKey(publicKey, pKeyLen);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: SoftbusRsaEncrypt001
 * @tc.desc: parameters are Legal
 * @tc.type: FUNC
 * @tc.require: I5OHDE
 */
HWTEST_F(AdapterDsoftbusRsaCryptoTest, SoftbusRsaEncrypt001, TestSize.Level0)
{
    uint32_t pKeyLen = SOFTBUS_RSA_PUB_KEY_LEN;
    uint8_t publicKey[pKeyLen];
    uint32_t srcDataLen = 5;
    uint8_t srcData[srcDataLen];
    uint32_t encryptedDataLen = 0;
    uint8_t *encryptedData = NULL;

    int32_t ret = SoftbusGetPublicKey(publicKey, pKeyLen);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SoftBusGenerateRandomArray(srcData, srcDataLen);
    EXPECT_EQ(SOFTBUS_OK, ret);
    PublicKey peerPublicKey = { publicKey, pKeyLen };

    ret = SoftbusRsaEncrypt(srcData, srcDataLen, &peerPublicKey, &encryptedData, &encryptedDataLen);
    EXPECT_EQ(SOFTBUS_OK, ret);
    SoftBusFree(encryptedData);
}

/*
 * @tc.name: SoftbusRsaEncrypt002
 * @tc.desc: parameter is nullptr
 * @tc.type: FUNC
 * @tc.require: I5OHDE
 */
HWTEST_F(AdapterDsoftbusRsaCryptoTest, SoftbusRsaEncrypt002, TestSize.Level0)
{
    uint32_t pKeyLen = SOFTBUS_RSA_PUB_KEY_LEN;
    uint8_t publicKey[pKeyLen];
    uint32_t srcDataLen = 5;
    uint8_t srcData[srcDataLen];
    uint32_t encryptedDataLen = 0;
    uint8_t *encryptedData = NULL;

    int32_t ret = SoftbusGetPublicKey(publicKey, pKeyLen);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SoftBusGenerateRandomArray(srcData, srcDataLen);
    EXPECT_EQ(SOFTBUS_OK, ret);
    PublicKey peerPublicKey = { publicKey, pKeyLen };

    ret = SoftbusRsaEncrypt(nullptr, srcDataLen, &peerPublicKey, &encryptedData, &encryptedDataLen);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = SoftbusRsaEncrypt(srcData, srcDataLen, nullptr, &encryptedData, &encryptedDataLen);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = SoftbusRsaEncrypt(srcData, srcDataLen, &peerPublicKey, nullptr, &encryptedDataLen);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = SoftbusRsaEncrypt(srcData, srcDataLen, &peerPublicKey, &encryptedData, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: SoftbusRsaEncrypt003
 * @tc.desc: srcDataLen is illegal
 * @tc.type: FUNC
 * @tc.require: I5OHDE
 */
HWTEST_F(AdapterDsoftbusRsaCryptoTest, SoftbusRsaEncrypt003, TestSize.Level0)
{
    uint32_t pKeyLen = SOFTBUS_RSA_PUB_KEY_LEN;
    uint8_t publicKey[pKeyLen];
    uint32_t inDataLen = 0;
    uint32_t srcDataLen = 5;
    uint8_t srcData[srcDataLen];
    uint32_t encryptedDataLen = 0;
    uint8_t *encryptedData = NULL;

    int32_t ret = SoftbusGetPublicKey(publicKey, pKeyLen);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SoftBusGenerateRandomArray(srcData, srcDataLen);
    EXPECT_EQ(SOFTBUS_OK, ret);
    PublicKey peerPublicKey = { publicKey, pKeyLen };

    ret = SoftbusRsaEncrypt(srcData, inDataLen, &peerPublicKey, &encryptedData, &encryptedDataLen);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: SoftbusRsaDecrypt001
 * @tc.desc: parameters are Legal
 * @tc.type: FUNC
 * @tc.require: I5OHDE
 */
HWTEST_F(AdapterDsoftbusRsaCryptoTest, SoftbusRsaDecrypt001, TestSize.Level0)
{
    uint32_t pKeyLen = SOFTBUS_RSA_PUB_KEY_LEN;
    uint8_t publicKey[pKeyLen];
    uint32_t srcDataLen = 5;
    uint8_t srcData[srcDataLen];
    uint32_t encryptedDataLen = 0;
    uint8_t *encryptedData = NULL;
    uint32_t decryptedDataLen = 0;
    uint8_t *decryptedData = NULL;

    int32_t ret = SoftbusGetPublicKey(publicKey, pKeyLen);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SoftBusGenerateRandomArray(srcData, srcDataLen);
    EXPECT_EQ(SOFTBUS_OK, ret);
    PublicKey peerPublicKey = { publicKey, pKeyLen };

    ret = SoftbusRsaEncrypt(srcData, srcDataLen, &peerPublicKey, &encryptedData, &encryptedDataLen);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SoftbusRsaDecrypt(encryptedData, encryptedDataLen, &decryptedData, &decryptedDataLen);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = memcmp((const char *)decryptedData, (const char *)srcData, decryptedDataLen);
    EXPECT_EQ(0, ret);

    SoftBusFree(encryptedData);
    SoftBusFree(decryptedData);
}

/*
 * @tc.name: SoftbusRsaDecrypt002
 * @tc.desc: parameter is nullptr
 * @tc.type: FUNC
 * @tc.require: I5OHDE
 */
HWTEST_F(AdapterDsoftbusRsaCryptoTest, SoftbusRsaDecrypt002, TestSize.Level0)
{
    uint32_t pKeyLen = SOFTBUS_RSA_PUB_KEY_LEN;
    uint8_t publicKey[pKeyLen];
    uint32_t srcDataLen = 5;
    uint8_t srcData[srcDataLen];
    uint32_t encryptedDataLen = 0;
    uint8_t *encryptedData = NULL;
    uint32_t decryptedDataLen = 0;
    uint8_t *decryptedData = NULL;

    int32_t ret = SoftbusGetPublicKey(publicKey, pKeyLen);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SoftBusGenerateRandomArray(srcData, srcDataLen);
    EXPECT_EQ(SOFTBUS_OK, ret);
    PublicKey peerPublicKey = { publicKey, pKeyLen };
    ret = SoftbusRsaEncrypt(srcData, srcDataLen, &peerPublicKey, &encryptedData, &encryptedDataLen);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = SoftbusRsaDecrypt(nullptr, encryptedDataLen, &decryptedData, &decryptedDataLen);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = SoftbusRsaDecrypt(encryptedData, encryptedDataLen, nullptr, &decryptedDataLen);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = SoftbusRsaDecrypt(encryptedData, encryptedDataLen, &decryptedData, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    SoftBusFree(encryptedData);
}

/*
 * @tc.name: SoftbusRsaDecrypt003
 * @tc.desc: inDatalen is illegal
 * @tc.type: FUNC
 * @tc.require: I5OHDE
 */
HWTEST_F(AdapterDsoftbusRsaCryptoTest, SoftbusRsaDecrypt003, TestSize.Level0)
{
    uint32_t pKeyLen = SOFTBUS_RSA_PUB_KEY_LEN;
    uint8_t publicKey[pKeyLen];
    uint32_t srcDataLen = 5;
    uint8_t srcData[srcDataLen];
    uint32_t encryptedDataLen = 0;
    uint8_t *encryptedData = NULL;
    uint32_t decryptedDataLen = 0;
    uint8_t *decryptedData = NULL;
    uint32_t srcDataLen1 = 0;

    int32_t ret = SoftbusGetPublicKey(publicKey, pKeyLen);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SoftBusGenerateRandomArray(srcData, srcDataLen);
    EXPECT_EQ(SOFTBUS_OK, ret);
    PublicKey peerPublicKey = { publicKey, pKeyLen };
    ret = SoftbusRsaEncrypt(srcData, srcDataLen, &peerPublicKey, &encryptedData, &encryptedDataLen);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = SoftbusRsaDecrypt(encryptedData, srcDataLen1, &decryptedData, &decryptedDataLen);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    SoftBusFree(encryptedData);
}
} // namespace OHOS
