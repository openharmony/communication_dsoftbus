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

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <gtest/gtest.h>
#include <securec.h>

#include "lnn_huks_utils.c"
#include "lnn_huks_utils.h"
#include "lnn_huks_utils_deps_mock.h"
#include "lnn_log.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "softbus_error_code.h"

namespace OHOS {
using namespace testing::ext;
using namespace testing;

class LNNHuksUtilsMockTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    static HuksUtilsDepsInterfaceMock huksUtilsMock;
};

HuksUtilsDepsInterfaceMock LNNHuksUtilsMockTest::huksUtilsMock = HuksUtilsDepsInterfaceMock();

void LNNHuksUtilsMockTest::SetUpTestCase()
{
    huksUtilsMock.SetInterface();
    EXPECT_CALL(huksUtilsMock, HksInitialize()).WillRepeatedly(Return(HKS_SUCCESS));
    EXPECT_CALL(huksUtilsMock, HksInitParamSet(_)).WillRepeatedly(Return(HKS_SUCCESS));
    EXPECT_CALL(huksUtilsMock, HksAddParams(_, _, _)).WillRepeatedly(Return(HKS_SUCCESS));
    EXPECT_CALL(huksUtilsMock, HksBuildParamSet(_)).WillRepeatedly(Return(HKS_SUCCESS));
    EXPECT_CALL(huksUtilsMock, IsActiveOsAccountUnlocked()).WillRepeatedly(Return(true));
    EXPECT_CALL(huksUtilsMock, LnnCheckGenerateSoftBusKeyByHuks()).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = LnnInitHuksInterface();
    EXPECT_EQ(ret, SOFTBUS_OK);
    LNN_LOGI(LNN_TEST, "LNNHuksUtilsMockTest start");
}

void LNNHuksUtilsMockTest::TearDownTestCase()
{
    EXPECT_CALL(huksUtilsMock, HksFreeParamSet(_)).WillRepeatedly(Return(HKS_SUCCESS));
    EXPECT_NO_FATAL_FAILURE(LnnDeinitHuksInterface());
    huksUtilsMock.ClearInterface();
    LNN_LOGI(LNN_TEST, "LNNHuksUtilsMockTest finish");
}

void LNNHuksUtilsMockTest::SetUp() { }

void LNNHuksUtilsMockTest::TearDown() { }

/*
 * @tc.name: LNN_INIT_HUKS_INTERFACE_Test_001
 * @tc.desc: Verify LnnInitHuksInterface returns SOFTBUS_HUKS_INIT_FAILED when HksInitialize fails
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNHuksUtilsMockTest, LNN_INIT_HUKS_INTERFACE_Test_001, TestSize.Level1)
{
    EXPECT_CALL(huksUtilsMock, HksInitialize()).WillRepeatedly(Return(HKS_ERROR_BAD_STATE));
    int32_t ret = LnnInitHuksInterface();
    EXPECT_EQ(ret, SOFTBUS_HUKS_INIT_FAILED);
}

/*
 * @tc.name: LNN_GENERATE_KEY_BY_HUKS_Test_001
 * @tc.desc: Verify LnnGenerateKeyByHuks returns SOFTBUS_OK when key generation succeeds
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNHuksUtilsMockTest, LNN_GENERATE_KEY_BY_HUKS_Test_001, TestSize.Level1)
{
    EXPECT_CALL(huksUtilsMock, HksInitialize()).WillRepeatedly(Return(HKS_SUCCESS));
    EXPECT_CALL(huksUtilsMock, HksInitParamSet(_)).WillRepeatedly(Return(HKS_SUCCESS));
    EXPECT_CALL(huksUtilsMock, HksAddParams(_, _, _)).WillRepeatedly(Return(HKS_SUCCESS));
    EXPECT_CALL(huksUtilsMock, HksBuildParamSet(_)).WillRepeatedly(Return(HKS_SUCCESS));
    EXPECT_CALL(huksUtilsMock, HksKeyExist(_, _)).WillRepeatedly(Return(HKS_ERROR_NOT_EXIST));
    EXPECT_CALL(huksUtilsMock, HksGenerateKey(_, _, _)).WillRepeatedly(Return(HKS_SUCCESS));
    EXPECT_CALL(huksUtilsMock, HksFreeParamSet(_)).WillRepeatedly(Return(HKS_SUCCESS));
    EXPECT_CALL(huksUtilsMock, IsActiveOsAccountUnlocked()).WillRepeatedly(Return(true));
    EXPECT_CALL(huksUtilsMock, LnnCheckGenerateSoftBusKeyByHuks()).WillRepeatedly(Return(SOFTBUS_OK));
    uint8_t aliasData[] = "test_key_alias";
    struct HksBlob keyAlias = { sizeof(aliasData), aliasData };
    int32_t ret = LnnGenerateKeyByHuks(&keyAlias);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_GENERATE_KEY_BY_HUKS_Test_002
 * @tc.desc: Verify LnnGenerateKeyByHuks returns SOFTBUS_INVALID_PARAM when keyAlias is NULL
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNHuksUtilsMockTest, LNN_GENERATE_KEY_BY_HUKS_Test_002, TestSize.Level1)
{
    int32_t ret = LnnGenerateKeyByHuks(NULL);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LNN_DELETE_KEY_BY_HUKS_Test_001
 * @tc.desc: Verify LnnDeleteKeyByHuks returns SOFTBUS_OK when key deletion succeeds
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNHuksUtilsMockTest, LNN_DELETE_KEY_BY_HUKS_Test_001, TestSize.Level1)
{
    EXPECT_CALL(huksUtilsMock, HksInitialize()).WillRepeatedly(Return(HKS_SUCCESS));
    EXPECT_CALL(huksUtilsMock, HksInitParamSet(_)).WillRepeatedly(Return(HKS_SUCCESS));
    EXPECT_CALL(huksUtilsMock, HksAddParams(_, _, _)).WillRepeatedly(Return(HKS_SUCCESS));
    EXPECT_CALL(huksUtilsMock, HksBuildParamSet(_)).WillRepeatedly(Return(HKS_SUCCESS));
    EXPECT_CALL(huksUtilsMock, HksKeyExist(_, _)).WillRepeatedly(Return(HKS_SUCCESS));
    EXPECT_CALL(huksUtilsMock, HksDeleteKey(_, _)).WillRepeatedly(Return(HKS_SUCCESS));
    EXPECT_CALL(huksUtilsMock, HksFreeParamSet(_)).WillRepeatedly(Return(HKS_SUCCESS));
    EXPECT_CALL(huksUtilsMock, IsActiveOsAccountUnlocked()).WillRepeatedly(Return(true));
    EXPECT_CALL(huksUtilsMock, LnnCheckGenerateSoftBusKeyByHuks()).WillRepeatedly(Return(SOFTBUS_OK));
    uint8_t aliasData[] = "test_key_alias";
    struct HksBlob keyAlias = { sizeof(aliasData), aliasData };
    int32_t ret = LnnDeleteKeyByHuks(&keyAlias);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_DELETE_KEY_BY_HUKS_Test_002
 * @tc.desc: Verify LnnDeleteKeyByHuks returns SOFTBUS_INVALID_PARAM when keyAlias is NULL
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNHuksUtilsMockTest, LNN_DELETE_KEY_BY_HUKS_Test_002, TestSize.Level1)
{
    int32_t ret = LnnDeleteKeyByHuks(NULL);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LNN_ENCRYPT_DATA_BY_HUKS_Test_001
 * @tc.desc: Verify LnnEncryptDataByHuks returns SOFTBUS_INVALID_PARAM when params are NULL
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNHuksUtilsMockTest, LNN_ENCRYPT_DATA_BY_HUKS_Test_001, TestSize.Level1)
{
    uint8_t inDataBuffer[] = "test data";
    struct HksBlob inData = { sizeof(inDataBuffer), inDataBuffer };
    uint8_t outDataBuffer[256] = { 0 };
    struct HksBlob outData = { sizeof(outDataBuffer), outDataBuffer };

    int32_t ret = LnnEncryptDataByHuks(NULL, &inData, &outData);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    uint8_t aliasData[] = "test_key_alias";
    struct HksBlob keyAlias = { sizeof(aliasData), aliasData };
    ret = LnnEncryptDataByHuks(&keyAlias, NULL, &outData);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = LnnEncryptDataByHuks(&keyAlias, &inData, NULL);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LNN_DECRYPT_DATA_BY_HUKS_Test_001
 * @tc.desc: Verify LnnDecryptDataByHuks returns SOFTBUS_INVALID_PARAM when params are NULL
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNHuksUtilsMockTest, LNN_DECRYPT_DATA_BY_HUKS_Test_001, TestSize.Level1)
{
    uint8_t inDataBuffer[] = "test data";
    struct HksBlob inData = { sizeof(inDataBuffer), inDataBuffer };
    uint8_t outDataBuffer[256] = { 0 };
    struct HksBlob outData = { sizeof(outDataBuffer), outDataBuffer };

    int32_t ret = LnnDecryptDataByHuks(NULL, &inData, &outData);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    uint8_t aliasData[] = "test_key_alias";
    struct HksBlob keyAlias = { sizeof(aliasData), aliasData };
    ret = LnnDecryptDataByHuks(&keyAlias, NULL, &outData);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = LnnDecryptDataByHuks(&keyAlias, &inData, NULL);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LNN_GENERATE_RANDOM_BY_HUKS_Test_001
 * @tc.desc: Verify LnnGenerateRandomByHuks returns SOFTBUS_OK when random generation succeeds
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNHuksUtilsMockTest, LNN_GENERATE_RANDOM_BY_HUKS_Test_001, TestSize.Level1)
{
    EXPECT_CALL(huksUtilsMock, HksGenerateRandom(_, _)).WillRepeatedly(Return(HKS_SUCCESS));

    uint8_t randomBuffer[32] = { 0 };
    int32_t ret = LnnGenerateRandomByHuks(randomBuffer, sizeof(randomBuffer));
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_GENERATE_RANDOM_BY_HUKS_Test_002
 * @tc.desc: Verify LnnGenerateRandomByHuks returns SOFTBUS_INVALID_PARAM when random is NULL
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNHuksUtilsMockTest, LNN_GENERATE_RANDOM_BY_HUKS_Test_002, TestSize.Level1)
{
    int32_t ret = LnnGenerateRandomByHuks(NULL, 32);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LNN_GENERATE_CE_KEY_BY_HUKS_Test_001
 * @tc.desc: Verify LnnGenerateCeKeyByHuks returns SOFTBUS_OK when CE key generation succeeds
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNHuksUtilsMockTest, LNN_GENERATE_CE_KEY_BY_HUKS_Test_001, TestSize.Level1)
{
    EXPECT_CALL(huksUtilsMock, HksInitialize()).WillRepeatedly(Return(HKS_SUCCESS));
    EXPECT_CALL(huksUtilsMock, HksInitParamSet(_)).WillRepeatedly(Return(HKS_SUCCESS));
    EXPECT_CALL(huksUtilsMock, HksAddParams(_, _, _)).WillRepeatedly(Return(HKS_SUCCESS));
    EXPECT_CALL(huksUtilsMock, HksBuildParamSet(_)).WillRepeatedly(Return(HKS_SUCCESS));
    EXPECT_CALL(huksUtilsMock, HksFreeParamSet(_)).WillRepeatedly(Return(HKS_SUCCESS));
    EXPECT_CALL(huksUtilsMock, HksKeyExist(_, _)).WillRepeatedly(Return(HKS_ERROR_NOT_EXIST));
    EXPECT_CALL(huksUtilsMock, HksGenerateKey(_, _, _)).WillRepeatedly(Return(HKS_SUCCESS));
    EXPECT_CALL(huksUtilsMock, IsActiveOsAccountUnlocked()).WillRepeatedly(Return(true));
    EXPECT_CALL(huksUtilsMock, LnnCheckGenerateSoftBusKeyByHuks()).WillRepeatedly(Return(SOFTBUS_OK));
    uint8_t aliasData[] = "test_ce_key_alias";
    struct HksBlob keyAlias = { sizeof(aliasData), aliasData };
    int32_t ret = LnnGenerateCeKeyByHuks(&keyAlias, true);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_GENERATE_CE_KEY_BY_HUKS_Test_002
 * @tc.desc: Verify LnnGenerateCeKeyByHuks returns SOFTBUS_INVALID_PARAM when keyAlias is NULL
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNHuksUtilsMockTest, LNN_GENERATE_CE_KEY_BY_HUKS_Test_002, TestSize.Level1)
{
    int32_t ret = LnnGenerateCeKeyByHuks(NULL, true);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LNN_DELETE_CE_KEY_BY_HUKS_Test_001
 * @tc.desc: Verify LnnDeleteCeKeyByHuks returns SOFTBUS_OK when CE key deletion succeeds
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNHuksUtilsMockTest, LNN_DELETE_CE_KEY_BY_HUKS_Test_001, TestSize.Level1)
{
    EXPECT_CALL(huksUtilsMock, HksInitialize()).WillRepeatedly(Return(HKS_SUCCESS));
    EXPECT_CALL(huksUtilsMock, HksInitParamSet(_)).WillRepeatedly(Return(HKS_SUCCESS));
    EXPECT_CALL(huksUtilsMock, HksAddParams(_, _, _)).WillRepeatedly(Return(HKS_SUCCESS));
    EXPECT_CALL(huksUtilsMock, HksBuildParamSet(_)).WillRepeatedly(Return(HKS_SUCCESS));
    EXPECT_CALL(huksUtilsMock, HksFreeParamSet(_)).WillRepeatedly(Return(HKS_SUCCESS));
    EXPECT_CALL(huksUtilsMock, HksKeyExist(_, _)).WillRepeatedly(Return(HKS_SUCCESS));
    EXPECT_CALL(huksUtilsMock, HksDeleteKey(_, _)).WillRepeatedly(Return(HKS_SUCCESS));
    EXPECT_CALL(huksUtilsMock, IsActiveOsAccountUnlocked()).WillRepeatedly(Return(true));
    EXPECT_CALL(huksUtilsMock, LnnCheckGenerateSoftBusKeyByHuks()).WillRepeatedly(Return(SOFTBUS_OK));
    uint8_t aliasData[] = "test_ce_key_alias";
    struct HksBlob keyAlias = { sizeof(aliasData), aliasData };
    int32_t ret = LnnDeleteCeKeyByHuks(&keyAlias, true);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_DELETE_CE_KEY_BY_HUKS_Test_002
 * @tc.desc: Verify LnnDeleteCeKeyByHuks returns SOFTBUS_INVALID_PARAM when keyAlias is NULL
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNHuksUtilsMockTest, LNN_DELETE_CE_KEY_BY_HUKS_Test_002, TestSize.Level1)
{
    int32_t ret = LnnDeleteCeKeyByHuks(NULL, true);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LNN_CE_ENCRYPT_DATA_BY_HUKS_Test_001
 * @tc.desc: Verify LnnCeEncryptDataByHuks returns SOFTBUS_INVALID_PARAM when params are invalid
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNHuksUtilsMockTest, LNN_CE_ENCRYPT_DATA_BY_HUKS_Test_001, TestSize.Level1)
{
    uint8_t inDataBuffer[] = "test data";
    struct HksBlob inData = { sizeof(inDataBuffer), inDataBuffer };
    uint8_t outDataBuffer[256] = { 0 };
    struct HksBlob outData = { sizeof(outDataBuffer), outDataBuffer };

    int32_t ret = LnnCeEncryptDataByHuks(NULL, &inData, &outData);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    uint8_t aliasData[] = "test_ce_key_alias";
    struct HksBlob keyAlias = { sizeof(aliasData), aliasData };
    ret = LnnCeEncryptDataByHuks(&keyAlias, NULL, &outData);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = LnnCeEncryptDataByHuks(&keyAlias, &inData, NULL);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    struct HksBlob emptyInData = { 0, inDataBuffer };
    ret = LnnCeEncryptDataByHuks(&keyAlias, &emptyInData, &outData);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LNN_CE_DECRYPT_DATA_BY_HUKS_Test_002
 * @tc.desc: Verify LnnCeDecryptDataByHuks returns SOFTBUS_INVALID_PARAM when params are invalid
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(LNNHuksUtilsMockTest, LNN_CE_DECRYPT_DATA_BY_HUKS_Test_002, TestSize.Level1)
{
    uint8_t inDataBuffer[] = "test data";
    struct HksBlob inData = { sizeof(inDataBuffer), inDataBuffer };
    uint8_t outDataBuffer[256] = { 0 };
    struct HksBlob outData = { sizeof(outDataBuffer), outDataBuffer };

    int32_t ret = LnnCeDecryptDataByHuks(NULL, &inData, &outData);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    uint8_t aliasData[] = "test_ce_key_alias";
    struct HksBlob keyAlias = { sizeof(aliasData), aliasData };
    ret = LnnCeDecryptDataByHuks(&keyAlias, NULL, &outData);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = LnnCeDecryptDataByHuks(&keyAlias, &inData, NULL);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    struct HksBlob emptyInData = { 0, inDataBuffer };
    ret = LnnCeDecryptDataByHuks(&keyAlias, &emptyInData, &outData);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}
} // namespace OHOS
