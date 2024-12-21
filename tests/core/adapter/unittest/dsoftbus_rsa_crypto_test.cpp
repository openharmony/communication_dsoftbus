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

#include "data_bus_native.h"
#include "softbus_rsa_encrypt.h"

#include <hks_api.h>
#include <hks_param.h>
#include <hks_type.h>
#include <securec.h>

#include "comm_log.h"
#include "softbus_adapter_crypto.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"
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

static struct HksParam g_encryptParams[] = {
    { .tag = HKS_TAG_ALGORITHM,          .uint32Param = HKS_ALG_RSA               },
    { .tag = HKS_TAG_PURPOSE,            .uint32Param = HKS_KEY_PURPOSE_ENCRYPT   },
    { .tag = HKS_TAG_KEY_SIZE,           .uint32Param = HKS_RSA_KEY_SIZE_2048     },
    { .tag = HKS_TAG_PADDING,            .uint32Param = HKS_PADDING_OAEP          },
    { .tag = HKS_TAG_DIGEST,             .uint32Param = HKS_DIGEST_SHA256         },
    { .tag = HKS_TAG_BLOCK_MODE,         .uint32Param = HKS_MODE_ECB              },
    { .tag = HKS_TAG_MGF_DIGEST,         .uint32Param = HKS_DIGEST_SHA1           },
    { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE },
};
static struct HksParam g_decryptParams[] = {
    { .tag = HKS_TAG_ALGORITHM,          .uint32Param = HKS_ALG_RSA               },
    { .tag = HKS_TAG_PURPOSE,            .uint32Param = HKS_KEY_PURPOSE_DECRYPT   },
    { .tag = HKS_TAG_KEY_SIZE,           .uint32Param = HKS_RSA_KEY_SIZE_2048     },
    { .tag = HKS_TAG_PADDING,            .uint32Param = HKS_PADDING_OAEP          },
    { .tag = HKS_TAG_DIGEST,             .uint32Param = HKS_DIGEST_SHA256         },
    { .tag = HKS_TAG_BLOCK_MODE,         .uint32Param = HKS_MODE_ECB              },
    { .tag = HKS_TAG_MGF_DIGEST,         .uint32Param = HKS_DIGEST_SHA1           },
    { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE },
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

/*
 * @tc.name: DataBusNativeVirtual00
 * @tc.desc: function
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterDsoftbusRsaCryptoTest, DataBusNativeVirtual001, TestSize.Level0)
{
    int32_t channelId = 0;
    int32_t ret = NotifyNearByUpdateMigrateOption(channelId);
    EXPECT_EQ(SOFTBUS_OK, ret);

    const char *peerDeviceId = NULL;
    int32_t routeType = 0;
    bool isUpgrade = true;
    ret = NotifyNearByOnMigrateEvents(peerDeviceId, routeType, isUpgrade);
    EXPECT_EQ(SOFTBUS_OK, ret);

    const char *busName = NULL;
    ret = NotifyNearByGetBrAgingTimeoutByBusName(busName);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

static int32_t ConstructKeyParamSet(struct HksParamSet **paramSet, const struct HksParam *params, uint32_t paramCount)
{
    if (HksInitParamSet(paramSet) != HKS_SUCCESS) {
        COMM_LOGE(COMM_TEST, "HksInitParamSet failed.");
        return SOFTBUS_HUKS_ERR;
    }
    if (HksAddParams(*paramSet, params, paramCount) != HKS_SUCCESS) {
        COMM_LOGE(COMM_TEST, "HksAddParams failed.");
        HksFreeParamSet(paramSet);
        return SOFTBUS_HUKS_ERR;
    }
    if (HksBuildParamSet(paramSet) != HKS_SUCCESS) {
        COMM_LOGE(COMM_TEST, "HksBuildParamSet failed.");
        HksFreeParamSet(paramSet);
        return SOFTBUS_HUKS_ERR;
    }
    return SOFTBUS_OK;
}

/*
 * @tc.name: HksDecrypt001
 * @tc.desc: parameters are Legal
 * @tc.type: FUNC
 * @tc.require: I5OHDE
 */
HWTEST_F(AdapterDsoftbusRsaCryptoTest, HksDecrypt001, TestSize.Level0)
{
    uint32_t pKeyLen = SOFTBUS_RSA_PUB_KEY_LEN;
    uint32_t srcDataLen = 5;
    uint8_t publicKey[pKeyLen];
    uint8_t srcData[srcDataLen];
    const uint8_t SOFTBUS_RSA_KEY_ALIAS[] = "DsoftbusRsaKey";
    const struct HksBlob rsaKeyAlias = { sizeof(SOFTBUS_RSA_KEY_ALIAS), (uint8_t *)SOFTBUS_RSA_KEY_ALIAS };
    struct HksBlob srcBlob = { srcDataLen, srcData };

    int32_t ret = SoftBusGetPublicKey(publicKey, pKeyLen);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SoftBusGenerateRandomArray(srcData, srcDataLen);
    EXPECT_EQ(SOFTBUS_OK, ret);

    struct HksBlob encryptedBlob = { HKS_RSA_KEY_SIZE_4096, (uint8_t *)SoftBusCalloc(HKS_RSA_KEY_SIZE_4096) };
    ASSERT_TRUE(encryptedBlob.data != nullptr);
    struct HksParamSet *encryptParamSet = nullptr;
    ret = ConstructKeyParamSet(&encryptParamSet, g_encryptParams, sizeof(g_encryptParams) / sizeof(struct HksParam));
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = HksEncrypt(&rsaKeyAlias, encryptParamSet, &srcBlob, &encryptedBlob);
    EXPECT_NE(HKS_ERROR_NULL_POINTER, ret);
    HksFreeParamSet(&encryptParamSet);

    struct HksBlob decryptedBlob = { HKS_RSA_KEY_SIZE_4096, (uint8_t *)SoftBusCalloc(HKS_RSA_KEY_SIZE_4096) };
    ASSERT_TRUE(decryptedBlob.data != nullptr);
    struct HksParamSet *decryptParamSet = nullptr;
    ret = ConstructKeyParamSet(&decryptParamSet, g_decryptParams, sizeof(g_decryptParams) / sizeof(struct HksParam));
    EXPECT_NE(HKS_ERROR_NULL_POINTER, ret);
    ret = HksDecrypt(&rsaKeyAlias, decryptParamSet, &encryptedBlob, &decryptedBlob);
    EXPECT_NE(HKS_ERROR_NULL_POINTER, ret);
    ret = memcmp((const char *)decryptedBlob.data, (const char *)srcData, srcDataLen);
    EXPECT_EQ(0, ret);

    HksFreeParamSet(&decryptParamSet);
    SoftBusFree(encryptedBlob.data);
    SoftBusFree(decryptedBlob.data);
}
} // namespace OHOS
