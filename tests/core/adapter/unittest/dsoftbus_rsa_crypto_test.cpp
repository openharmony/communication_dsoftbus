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
 * @tc.name: SoftBusGetPublicKey001
 * @tc.desc: parameters are Legal
 * @tc.type: FUNC
 * @tc.require: I5OHDE
 */
HWTEST_F(AdapterDsoftbusRsaCryptoTest, SoftBusGetPublicKey001, TestSize.Level0)
{
    uint32_t pKeyLen = SOFTBUS_RSA_PUB_KEY_LEN;
    uint8_t publicKey[pKeyLen];
    int32_t ret = SoftBusGetPublicKey(publicKey, pKeyLen);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: SoftBusGetPublicKey002
 * @tc.desc: parameter is nullptr
 * @tc.type: FUNC
 * @tc.require: I5OHDE
 */
HWTEST_F(AdapterDsoftbusRsaCryptoTest, SoftBusGetPublicKey002, TestSize.Level0)
{
    uint32_t pKeyLen = SOFTBUS_RSA_PUB_KEY_LEN;
    int32_t ret = SoftBusGetPublicKey(nullptr, pKeyLen);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: SoftBusGetPublicKey003
 * @tc.desc: len is illegal
 * @tc.type: FUNC
 * @tc.require: I5OHDE
 */
HWTEST_F(AdapterDsoftbusRsaCryptoTest, SoftBusGetPublicKey003, TestSize.Level0)
{
    uint8_t publicKey[SOFTBUS_RSA_PUB_KEY_LEN];
    uint32_t pKeyLen = 0;
    int32_t ret = SoftBusGetPublicKey(publicKey, pKeyLen);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: SoftBusRsaEncrypt001
 * @tc.desc: parameters are Legal
 * @tc.type: FUNC
 * @tc.require: I5OHDE
 */
HWTEST_F(AdapterDsoftbusRsaCryptoTest, SoftBusRsaEncrypt001, TestSize.Level0)
{
    uint32_t pKeyLen = SOFTBUS_RSA_PUB_KEY_LEN;
    uint8_t publicKey[pKeyLen];
    uint32_t srcDataLen = 5;
    uint8_t srcData[srcDataLen];
    uint32_t encryptedDataLen = 0;
    uint8_t *encryptedData = NULL;

    int32_t ret = SoftBusGetPublicKey(publicKey, pKeyLen);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SoftBusGenerateRandomArray(srcData, srcDataLen);
    EXPECT_EQ(SOFTBUS_OK, ret);
    PublicKey peerPublicKey = { publicKey, pKeyLen };

    ret = SoftBusRsaEncrypt(srcData, srcDataLen, &peerPublicKey, &encryptedData, &encryptedDataLen);
    EXPECT_EQ(SOFTBUS_OK, ret);
    SoftBusFree(encryptedData);
}

/*
 * @tc.name: SoftBusRsaEncrypt002
 * @tc.desc: parameter is nullptr
 * @tc.type: FUNC
 * @tc.require: I5OHDE
 */
HWTEST_F(AdapterDsoftbusRsaCryptoTest, SoftBusRsaEncrypt002, TestSize.Level0)
{
    uint32_t pKeyLen = SOFTBUS_RSA_PUB_KEY_LEN;
    uint8_t publicKey[pKeyLen];
    uint32_t srcDataLen = 5;
    uint8_t srcData[srcDataLen];
    uint32_t encryptedDataLen = 0;
    uint8_t *encryptedData = NULL;

    int32_t ret = SoftBusGetPublicKey(publicKey, pKeyLen);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SoftBusGenerateRandomArray(srcData, srcDataLen);
    EXPECT_EQ(SOFTBUS_OK, ret);
    PublicKey peerPublicKey = { publicKey, pKeyLen };

    ret = SoftBusRsaEncrypt(nullptr, srcDataLen, &peerPublicKey, &encryptedData, &encryptedDataLen);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = SoftBusRsaEncrypt(srcData, srcDataLen, nullptr, &encryptedData, &encryptedDataLen);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = SoftBusRsaEncrypt(srcData, srcDataLen, &peerPublicKey, nullptr, &encryptedDataLen);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = SoftBusRsaEncrypt(srcData, srcDataLen, &peerPublicKey, &encryptedData, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: SoftBusRsaEncrypt003
 * @tc.desc: srcDataLen is illegal
 * @tc.type: FUNC
 * @tc.require: I5OHDE
 */
HWTEST_F(AdapterDsoftbusRsaCryptoTest, SoftBusRsaEncrypt003, TestSize.Level0)
{
    uint32_t pKeyLen = SOFTBUS_RSA_PUB_KEY_LEN;
    uint8_t publicKey[pKeyLen];
    uint32_t inDataLen = 0;
    uint32_t srcDataLen = 5;
    uint8_t srcData[srcDataLen];
    uint32_t encryptedDataLen = 0;
    uint8_t *encryptedData = NULL;

    int32_t ret = SoftBusGetPublicKey(publicKey, pKeyLen);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SoftBusGenerateRandomArray(srcData, srcDataLen);
    EXPECT_EQ(SOFTBUS_OK, ret);
    PublicKey peerPublicKey = { publicKey, pKeyLen };

    ret = SoftBusRsaEncrypt(srcData, inDataLen, &peerPublicKey, &encryptedData, &encryptedDataLen);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: SoftBusRsaDecrypt001
 * @tc.desc: parameters are Legal
 * @tc.type: FUNC
 * @tc.require: I5OHDE
 */
HWTEST_F(AdapterDsoftbusRsaCryptoTest, SoftBusRsaDecrypt001, TestSize.Level0)
{
    uint32_t pKeyLen = SOFTBUS_RSA_PUB_KEY_LEN;
    uint8_t publicKey[pKeyLen];
    uint32_t srcDataLen = 5;
    uint8_t srcData[srcDataLen];
    uint32_t encryptedDataLen = 0;
    uint8_t *encryptedData = NULL;
    uint32_t decryptedDataLen = 0;
    uint8_t *decryptedData = NULL;

    int32_t ret = SoftBusGetPublicKey(publicKey, pKeyLen);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SoftBusGenerateRandomArray(srcData, srcDataLen);
    EXPECT_EQ(SOFTBUS_OK, ret);
    PublicKey peerPublicKey = { publicKey, pKeyLen };

    ret = SoftBusRsaEncrypt(srcData, srcDataLen, &peerPublicKey, &encryptedData, &encryptedDataLen);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SoftBusRsaDecrypt(encryptedData, encryptedDataLen, &decryptedData, &decryptedDataLen);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = memcmp((const char *)decryptedData, (const char *)srcData, decryptedDataLen);
    EXPECT_EQ(0, ret);

    SoftBusFree(encryptedData);
    SoftBusFree(decryptedData);
}

/*
 * @tc.name: SoftBusRsaDecrypt002
 * @tc.desc: parameter is nullptr
 * @tc.type: FUNC
 * @tc.require: I5OHDE
 */
HWTEST_F(AdapterDsoftbusRsaCryptoTest, SoftBusRsaDecrypt002, TestSize.Level0)
{
    uint32_t pKeyLen = SOFTBUS_RSA_PUB_KEY_LEN;
    uint8_t publicKey[pKeyLen];
    uint32_t srcDataLen = 5;
    uint8_t srcData[srcDataLen];
    uint32_t encryptedDataLen = 0;
    uint8_t *encryptedData = NULL;
    uint32_t decryptedDataLen = 0;
    uint8_t *decryptedData = NULL;

    int32_t ret = SoftBusGetPublicKey(publicKey, pKeyLen);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SoftBusGenerateRandomArray(srcData, srcDataLen);
    EXPECT_EQ(SOFTBUS_OK, ret);
    PublicKey peerPublicKey = { publicKey, pKeyLen };
    ret = SoftBusRsaEncrypt(srcData, srcDataLen, &peerPublicKey, &encryptedData, &encryptedDataLen);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = SoftBusRsaDecrypt(nullptr, encryptedDataLen, &decryptedData, &decryptedDataLen);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = SoftBusRsaDecrypt(encryptedData, encryptedDataLen, nullptr, &decryptedDataLen);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = SoftBusRsaDecrypt(encryptedData, encryptedDataLen, &decryptedData, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    SoftBusFree(encryptedData);
}

/*
 * @tc.name: SoftBusRsaDecrypt003
 * @tc.desc: inDatalen is illegal
 * @tc.type: FUNC
 * @tc.require: I5OHDE
 */
HWTEST_F(AdapterDsoftbusRsaCryptoTest, SoftBusRsaDecrypt003, TestSize.Level0)
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

    int32_t ret = SoftBusGetPublicKey(publicKey, pKeyLen);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SoftBusGenerateRandomArray(srcData, srcDataLen);
    EXPECT_EQ(SOFTBUS_OK, ret);
    PublicKey peerPublicKey = { publicKey, pKeyLen };
    ret = SoftBusRsaEncrypt(srcData, srcDataLen, &peerPublicKey, &encryptedData, &encryptedDataLen);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = SoftBusRsaDecrypt(encryptedData, srcDataLen1, &decryptedData, &decryptedDataLen);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    SoftBusFree(encryptedData);
}
} // namespace OHOS
