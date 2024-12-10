/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "bus_center_utils_mock.h"
#include "lnn_async_callback_utils.h"
#include "lnn_common_utils.h"
#include "lnn_compress.h"
#include "lnn_map.h"
#include "lnn_network_id.c"
#include "lnn_network_id.h"
#include "lnn_state_machine.h"
#include "softbus_adapter_mem.h"
#include "softbus_common.h"
#include "softbus_def.h"
#include "softbus_error_code.h"

namespace OHOS {
using namespace testing::ext;
using namespace testing;
static Map g_bcUtilsMap;
#define NETWORK_ID_BUF_LEN 65
#define HDF_MAP_VALUE_MAX_SIZE 4000
#define FSM_MSG_TYPE_JOIN_LNN_TIMEOUT 6

class BusCenterUtilsTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void BusCenterUtilsTest::SetUpTestCase() {}

void BusCenterUtilsTest::TearDownTestCase() {}

void BusCenterUtilsTest::SetUp() {}

void BusCenterUtilsTest::TearDown() {}

static void LooperRemoveMessage(const SoftBusLooper *looper, const SoftBusHandler *handler, int32_t what)
{
    (void)looper;
    (void)handler;
    (void)what;
}

static void LoopRemoveMessageCustom(const SoftBusLooper *looper, const SoftBusHandler *handler,
    int (*customFunc)(const SoftBusMessage*, void*), void *args)
{
    (void)looper;
    (void)handler;
    (void)customFunc;
    (void)args;
}

static void LooperPostMessageDelay(const SoftBusLooper *looper, SoftBusMessage *msg, uint64_t delayMillis)
{
    (void)looper;
    (void)msg;
    (void)delayMillis;
}

static SoftBusHandler g_buscenterUtilsHandler = {
    .name = (char *)"g_buscenterUtilsHandler"
};

/*
* @tc.name: GET_UUID_FROM_FILE_TEST_001
* @tc.desc: get uuid from file test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BusCenterUtilsTest, GET_UUID_FROM_FILE_TEST_001, TestSize.Level1)
{
    NiceMock<BusCenterUtilsInterfaceMock> bcUtilsMock;
    EXPECT_CALL(bcUtilsMock, LnnGetFullStoragePath)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    char id[] = "11u22u33i44d55";
    int32_t ret = GetUuidFromFile(id, UUID_BUF_LEN);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    EXPECT_CALL(bcUtilsMock, SoftBusReadFullFile).WillRepeatedly(Return(SOFTBUS_FILE_ERR));
    EXPECT_CALL(bcUtilsMock, GenerateRandomStr)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    ret = GetUuidFromFile(id, UUID_BUF_LEN);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    EXPECT_CALL(bcUtilsMock, SoftBusWriteFile)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    ret = GetUuidFromFile(id, UUID_BUF_LEN);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = GetUuidFromFile(id, UUID_BUF_LEN);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_GET_UUID_FROM_FILE_FAILED);

    char id1[] = "ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00";
    ret = GetUuidFromFile(id1, UUID_BUF_LEN);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: LNN_GEN_LOCAL_NETWORKID_TEST_001
* @tc.desc: lnn generate local networkid test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BusCenterUtilsTest, LNN_GEN_LOCAL_NETWORKID_TEST_001, TestSize.Level1)
{
    NiceMock<BusCenterUtilsInterfaceMock> bcUtilsMock;
    int32_t ret = LnnGenLocalNetworkId(nullptr, NETWORK_ID_BUF_LEN);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    char networkId[NETWORK_ID_BUF_LEN] = "ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF0";
    ret = LnnGenLocalNetworkId(networkId, NETWORK_ID_BUF_LEN - 1);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    EXPECT_CALL(bcUtilsMock, GenerateRandomStr)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    ret = LnnGenLocalNetworkId(networkId, NETWORK_ID_BUF_LEN);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = LnnGenLocalNetworkId(networkId, NETWORK_ID_BUF_LEN);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: LNN_GEN_LOCAL_UUID_TEST_001
* @tc.desc: lnn generate local uuid test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BusCenterUtilsTest, LNN_GEN_LOCAL_UUID_TEST_001, TestSize.Level1)
{
    NiceMock<BusCenterUtilsInterfaceMock> bcUtilsMock;
    int32_t ret = LnnGenLocalUuid(nullptr, UUID_BUF_LEN);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    char uuid[] = "11u22u33i44d55";
    ret = LnnGenLocalUuid(uuid, UUID_BUF_LEN - 1);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    EXPECT_CALL(bcUtilsMock, LnnGetFullStoragePath).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    ret = LnnGenLocalUuid(uuid, UUID_BUF_LEN);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_GET_UUID_FROM_FILE_FAILED);
}

/*
* @tc.name: GET_IRK_FROM_FILE_TEST_001
* @tc.desc: get irk from file test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BusCenterUtilsTest, GET_IRK_FROM_FILE_TEST_001, TestSize.Level1)
{
    NiceMock<BusCenterUtilsInterfaceMock> bcUtilsMock;
    unsigned char irk[] = "test_irk_123";
    EXPECT_CALL(bcUtilsMock, LnnGetFullStoragePath)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = GetIrkFromFile(irk, LFINDER_IRK_LEN);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    EXPECT_CALL(bcUtilsMock, SoftBusReadFullFile).WillRepeatedly(Return(SOFTBUS_FILE_ERR));
    EXPECT_CALL(bcUtilsMock, SoftBusGenerateRandomArray)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    ret = GetIrkFromFile(irk, LFINDER_IRK_LEN);
    EXPECT_NE(ret, SOFTBUS_OK);

    EXPECT_CALL(bcUtilsMock, SoftBusWriteFile)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    ret = GetIrkFromFile(irk, LFINDER_IRK_LEN);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = GetIrkFromFile(irk, LFINDER_IRK_LEN);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: LNN_GEN_LOCAL_IRK_TEST_001
* @tc.desc: lnn generate local irk test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BusCenterUtilsTest, LNN_GEN_LOCAL_IRK_TEST_001, TestSize.Level1)
{
    NiceMock<BusCenterUtilsInterfaceMock> bcUtilsMock;
    unsigned char irk[] = "test_irk_123";
    int32_t ret = LnnGenLocalIrk(nullptr, LFINDER_IRK_LEN);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = LnnGenLocalIrk(irk, LFINDER_IRK_LEN - 1);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    EXPECT_CALL(bcUtilsMock, LnnGetFullStoragePath)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    ret = LnnGenLocalIrk(irk, LFINDER_IRK_LEN);
    EXPECT_EQ(ret, SOFTBUS_GET_IRK_FAIL);
}

/*
* @tc.name: LNN_ENCRYPT_AES_GCM_TEST_001
* @tc.desc: lnn encrypt aes gcm test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BusCenterUtilsTest, LNN_ENCRYPT_AES_GCM_TEST_001, TestSize.Level1)
{
    NiceMock<BusCenterUtilsInterfaceMock> bcUtilsMock;
    int32_t keyIndex = 0;
    int32_t ret = LnnEncryptAesGcm(nullptr, keyIndex, nullptr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    AesGcmInputParam in;
    (void)memset_s(&in, sizeof(AesGcmInputParam), 0, sizeof(AesGcmInputParam));
    ret = LnnEncryptAesGcm(&in, keyIndex, nullptr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    uint8_t *out = nullptr;
    ret = LnnEncryptAesGcm(&in, keyIndex, &out, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    uint32_t outLen = 0;
    in.dataLen = UINT32_MAX - OVERHEAD_LEN;
    ret = LnnEncryptAesGcm(&in, keyIndex, &out, &outLen);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    in.data = (uint8_t *)"true";
    in.dataLen = strlen("true");
    in.key = (uint8_t *)"www.test.com";
    in.keyLen = SESSION_KEY_LENGTH;

    EXPECT_CALL(bcUtilsMock, SoftBusGenerateRandomArray)
        .WillOnce(Return(SOFTBUS_ENCRYPT_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    ret = LnnEncryptAesGcm(&in, keyIndex, &out, &outLen);
    EXPECT_EQ(ret, SOFTBUS_ENCRYPT_ERR);
    SoftBusFree(out);

    ret = LnnEncryptAesGcm(&in, keyIndex, &out, &outLen);
    EXPECT_EQ(ret, SOFTBUS_OK);
    in.key = nullptr;
    SoftBusFree(out);
}

/*
* @tc.name: LNN_DECRYPT_AES_GCM_TEST_001
* @tc.desc: lnn decrypt aes gcm test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BusCenterUtilsTest, LNN_DECRYPT_AES_GCM_TEST_001, TestSize.Level1)
{
    NiceMock<BusCenterUtilsInterfaceMock> bcUtilsMock;
    int32_t ret = LnnDecryptAesGcm(nullptr, nullptr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    AesGcmInputParam in;
    (void)memset_s(&in, sizeof(AesGcmInputParam), 0, sizeof(AesGcmInputParam));
    ret = LnnDecryptAesGcm(&in, nullptr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    uint8_t *out = nullptr;
    ret = LnnDecryptAesGcm(&in, &out, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    uint32_t outLen = 0;
    in.dataLen = OVERHEAD_LEN;
    ret = LnnDecryptAesGcm(&in, &out, &outLen);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    in.data = (uint8_t *)"hw.test.data.true/false.com.s.s";
    in.dataLen = strlen("hw.test.data.true/false.com.s.s");
    in.key = (uint8_t *)"www.test.com";
    in.keyLen = SESSION_KEY_LENGTH;
    ret = LnnDecryptAesGcm(&in, &out, &outLen);
    EXPECT_EQ(ret, SOFTBUS_OK);
    in.key = nullptr;
    SoftBusFree(out);
}

/*
* @tc.name: LNN_MAP_SET_TEST_001
* @tc.desc: lnn map set test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BusCenterUtilsTest, LNN_MAP_SET_TEST_001, TestSize.Level1)
{
    Map *cMap = (Map *)SoftBusCalloc(sizeof(Map));
    ASSERT_NE(cMap, nullptr);
    cMap->nodes = (MapNode **)SoftBusCalloc(sizeof(MapNode *));
    if (cMap->nodes == nullptr) {
        SoftBusFree(cMap);
    }
    cMap->bucketSize = 0;
    cMap->nodeSize = 1;
    const char *key = "123412341234abcdef";
    NodeInfo nodeInfo;
    (void)memset_s(&nodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    uint32_t valueSize = HDF_MAP_VALUE_MAX_SIZE + 1;
    int32_t ret = LnnMapSet(cMap, key, &nodeInfo, valueSize);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    valueSize = HDF_MAP_VALUE_MAX_SIZE;
    ret = LnnMapSet(cMap, key, &nodeInfo, valueSize);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    cMap->bucketSize = 1;
    ret = LnnMapSet(cMap, key, &nodeInfo, valueSize);
    EXPECT_EQ(ret, SOFTBUS_OK);

    EXPECT_EQ(LnnMapErase(cMap, key), SOFTBUS_OK);
    EXPECT_NO_FATAL_FAILURE(LnnMapDelete(cMap));
    SoftBusFree(cMap);
}

/*
* @tc.name: LNN_MAP_GET_TEST_001
* @tc.desc: lnn map get test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BusCenterUtilsTest, LNN_MAP_GET_TEST_001, TestSize.Level1)
{
    void *ret = LnnMapGet(nullptr, nullptr);
    EXPECT_EQ(ret, nullptr);

    Map *cMap = (Map *)SoftBusCalloc(sizeof(Map));
    ASSERT_NE(cMap, nullptr);
    LnnMapInit(cMap);
    ret = LnnMapGet(cMap, nullptr);
    EXPECT_EQ(ret, nullptr);

    const char *key = "123412341234abcdef";
    ret = LnnMapGet(cMap, key);
    EXPECT_EQ(ret, nullptr);

    cMap->nodeSize = 1;
    ret = LnnMapGet(cMap, key);
    EXPECT_EQ(ret, nullptr);

    NodeInfo nodeInfo;
    (void)memset_s(&nodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    EXPECT_EQ(LnnMapSet(&g_bcUtilsMap, key, &nodeInfo, HDF_MAP_VALUE_MAX_SIZE), SOFTBUS_OK);
    cMap->bucketSize = 0;
    ret = LnnMapGet(cMap, key);
    EXPECT_EQ(ret, nullptr);

    cMap->bucketSize = 1;
    ret = LnnMapGet(cMap, key);
    EXPECT_EQ(ret, nullptr);

    EXPECT_NO_FATAL_FAILURE(LnnMapErase(cMap, key));
    EXPECT_NO_FATAL_FAILURE(LnnMapDelete(cMap));
    SoftBusFree(cMap);
}

/*
* @tc.name: LNN_MAP_ERASE_TEST_001
* @tc.desc: lnn map erase test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BusCenterUtilsTest, LNN_MAP_ERASE_TEST_001, TestSize.Level1)
{
    int32_t ret = LnnMapErase(nullptr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    Map *cMap = (Map *)SoftBusCalloc(sizeof(Map));
    ASSERT_NE(cMap, nullptr);
    LnnMapInit(cMap);
    ret = LnnMapErase(cMap, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    const char *key = "123412341234abcdef";
    ret = LnnMapErase(cMap, key);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    cMap->nodeSize = 1;
    ret = LnnMapErase(cMap, key);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    NodeInfo nodeInfo;
    (void)memset_s(&nodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    EXPECT_EQ(LnnMapSet(&g_bcUtilsMap, key, &nodeInfo, HDF_MAP_VALUE_MAX_SIZE), SOFTBUS_OK);
    cMap->bucketSize = 0;
    ret = LnnMapErase(cMap, key);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    cMap->bucketSize = 1;
    ret = LnnMapErase(cMap, key);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    EXPECT_NO_FATAL_FAILURE(LnnMapDelete(cMap));
    SoftBusFree(cMap);
}

/*
* @tc.name: LNN_MAP_INIT_TEST_001
* @tc.desc: lnn map init test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BusCenterUtilsTest, LNN_MAP_INIT_TEST_001, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(LnnMapInit(nullptr));

    Map *cMap = (Map *)SoftBusCalloc(sizeof(Map));
    ASSERT_NE(cMap, nullptr);
    EXPECT_NO_FATAL_FAILURE(LnnMapInit(cMap));

    EXPECT_NO_FATAL_FAILURE(LnnMapDelete(cMap));
    SoftBusFree(cMap);
}

/*
* @tc.name: LNN_MAP_DELETE_TEST_001
* @tc.desc: lnn map delete test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BusCenterUtilsTest, LNN_MAP_DELETE_TEST_001, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(LnnMapDelete(nullptr));

    Map *cMap = (Map *)SoftBusCalloc(sizeof(Map));
    ASSERT_NE(cMap, nullptr);
    cMap->nodes = nullptr;
    EXPECT_NO_FATAL_FAILURE(LnnMapDelete(cMap));

    NodeInfo nodeInfo;
    (void)memset_s(&nodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    const char *key = "123412341234abcdef";
    EXPECT_EQ(LnnMapSet(&g_bcUtilsMap, key, &nodeInfo, HDF_MAP_VALUE_MAX_SIZE), SOFTBUS_OK);
    EXPECT_NO_FATAL_FAILURE(LnnMapDelete(cMap));
    SoftBusFree(cMap);
}

/*
* @tc.name: LNN_MAP_INIT_ITERATOR_TEST_001
* @tc.desc: lnn map init iterator test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BusCenterUtilsTest, LNN_MAP_INIT_ITERATOR_TEST_001, TestSize.Level1)
{
    MapIterator *ret = LnnMapInitIterator(nullptr);
    EXPECT_EQ(ret, nullptr);

    Map *cMap = (Map *)SoftBusCalloc(sizeof(Map));
    ASSERT_NE(cMap, nullptr);
    ret = LnnMapInitIterator(cMap);
    EXPECT_NE(ret, nullptr);

    EXPECT_NO_FATAL_FAILURE(LnnMapDeinitIterator(ret));
    SoftBusFree(cMap);
}

/*
* @tc.name: LNN_MAP_HAS_NEXT_TEST_001
* @tc.desc: lnn map has next test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BusCenterUtilsTest, LNN_MAP_HAS_NEXT_TEST_001, TestSize.Level1)
{
    MapIterator *it = (MapIterator *)SoftBusCalloc(sizeof(MapIterator));
    ASSERT_NE(it, nullptr);
    it->map = (Map *)SoftBusCalloc(sizeof(Map));
    if (it->map == nullptr) {
        SoftBusFree(it);
        return;
    }
    it->map->nodeSize = HDF_MAP_VALUE_MAX_SIZE + 1;
    it->nodeNum = 1;
    bool ret = LnnMapHasNext(it);
    EXPECT_EQ(ret, true);

    it->map->nodeSize = HDF_MAP_VALUE_MAX_SIZE;
    it->nodeNum = HDF_MAP_VALUE_MAX_SIZE;
    ret = LnnMapHasNext(it);
    EXPECT_EQ(ret, false);

    SoftBusFree(it->map);
    SoftBusFree(it);
}

/*
* @tc.name: LNN_MAP_DEINIT_ITERATOR_TEST_001
* @tc.desc: lnn map deinit iterator test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BusCenterUtilsTest, LNN_MAP_DEINIT_ITERATOR_TEST_001, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(LnnMapDeinitIterator(nullptr));

    MapIterator *it = (MapIterator *)SoftBusCalloc(sizeof(MapIterator));
    ASSERT_NE(it, nullptr);
    EXPECT_NO_FATAL_FAILURE(LnnMapDeinitIterator(it));
}

/*
* @tc.name: DATA_COMPRESS_TEST_001
* @tc.desc: data compress test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BusCenterUtilsTest, DATA_COMPRESS_TEST_001, TestSize.Level1)
{
    int32_t ret = DataCompress(nullptr, 0, nullptr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    char in[] = "123txt321";
    ret = DataCompress((uint8_t *)in, 0, nullptr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    uint32_t inLen = strlen(in);
    ret = DataCompress((uint8_t *)in, inLen, nullptr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    uint8_t *out = nullptr;
    ret = DataCompress((uint8_t *)in, inLen, &out, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    uint32_t outLen = 0;
    ret = DataCompress((uint8_t *)in, inLen, &out, &outLen);
    EXPECT_EQ(ret, SOFTBUS_DEFLATE_FAIL);
}

/*
* @tc.name: DATA_DE_COMPRESS_TEST_001
* @tc.desc: data decompress test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BusCenterUtilsTest, DATA_DE_COMPRESS_TEST_001, TestSize.Level1)
{
    int32_t ret = DataDecompress(nullptr, 0, nullptr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    char in[] = "123txt321";
    ret = DataDecompress((uint8_t *)in, 0, nullptr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    uint32_t inLen = strlen(in);
    ret = DataDecompress((uint8_t *)in, inLen, nullptr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    uint8_t *out = nullptr;
    ret = DataDecompress((uint8_t *)in, inLen, &out, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
* @tc.name: LNN_FSM_POST_MESSAGE_DELAY_TEST_001
* @tc.desc: lnn fsm post message delay test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BusCenterUtilsTest, LNN_FSM_POST_MESSAGE_DELAY_TEST_001, TestSize.Level1)
{
    int32_t ret = LnnFsmPostMessageDelay(nullptr, FSM_MSG_TYPE_JOIN_LNN_TIMEOUT, nullptr, 0);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    FsmStateMachine *fsm = (FsmStateMachine *)SoftBusCalloc(sizeof(FsmStateMachine));
    ASSERT_NE(fsm, nullptr);
    fsm->looper = nullptr;
    ret = LnnFsmPostMessageDelay(fsm, FSM_MSG_TYPE_JOIN_LNN_TIMEOUT, nullptr, 0);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    SoftBusLooper loop;
    fsm->looper = &loop;
    fsm->looper->PostMessageDelay = nullptr;
    ret = LnnFsmPostMessageDelay(fsm, FSM_MSG_TYPE_JOIN_LNN_TIMEOUT, nullptr, 0);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    fsm->looper->PostMessageDelay = LooperPostMessageDelay;
    ret = LnnFsmPostMessageDelay(fsm, FSM_MSG_TYPE_JOIN_LNN_TIMEOUT, nullptr, 0);
    EXPECT_EQ(ret, SOFTBUS_OK);

    SoftBusFree(fsm);
}

/*
* @tc.name: LNN_FSM_REMOVE_MESSAGE_BY_TYPE_TEST_001
* @tc.desc: lnn fsm remove message by type test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BusCenterUtilsTest, LNN_FSM_REMOVE_MESSAGE_BY_TYPE_TEST_001, TestSize.Level1)
{
    int32_t ret = LnnFsmRemoveMessageByType(nullptr, FSM_CTRL_MSG_START);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    SoftBusLooper loop;
    FsmStateMachine *fsm = (FsmStateMachine *)SoftBusCalloc(sizeof(FsmStateMachine));
    ASSERT_NE(fsm, nullptr);
    fsm->looper = nullptr;
    ret = LnnFsmRemoveMessageByType(fsm, FSM_CTRL_MSG_START);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    fsm->looper = &loop;
    fsm->looper->RemoveMessage = nullptr;
    ret = LnnFsmRemoveMessageByType(fsm, FSM_CTRL_MSG_START);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    fsm->looper->RemoveMessage = LooperRemoveMessage;
    fsm->handler = g_buscenterUtilsHandler;
    ret = LnnFsmRemoveMessageByType(fsm, FSM_CTRL_MSG_START);
    EXPECT_EQ(ret, SOFTBUS_OK);

    SoftBusFree(fsm);
}

/*
* @tc.name: LNN_FSM_REMOVE_MESSAGE_TEST_001
* @tc.desc: lnn fsm remove message test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BusCenterUtilsTest, LNN_FSM_REMOVE_MESSAGE_TEST_001, TestSize.Level1)
{
    int32_t ret = LnnFsmRemoveMessage(nullptr, FSM_MSG_TYPE_JOIN_LNN_TIMEOUT);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    FsmStateMachine *fsm = (FsmStateMachine *)SoftBusCalloc(sizeof(FsmStateMachine));
    ASSERT_NE(fsm, nullptr);
    fsm->looper = nullptr;
    ret = LnnFsmRemoveMessage(fsm, FSM_MSG_TYPE_JOIN_LNN_TIMEOUT);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    SoftBusLooper loop;
    fsm->looper = &loop;
    fsm->looper->RemoveMessageCustom = nullptr;
    ret = LnnFsmRemoveMessage(fsm, FSM_MSG_TYPE_JOIN_LNN_TIMEOUT);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    fsm->looper->RemoveMessageCustom = LoopRemoveMessageCustom;
    fsm->handler = g_buscenterUtilsHandler;
    ret = LnnFsmRemoveMessage(fsm, FSM_MSG_TYPE_JOIN_LNN_TIMEOUT);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(fsm);
}

/*
* @tc.name: LNN_MAP_NEXT_TEST_001
* @tc.desc: lnn map next test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(BusCenterUtilsTest, LNN_MAP_NEXT_TEST_001, TestSize.Level1)
{
    MapIterator *ret = LnnMapNext(nullptr);
    EXPECT_EQ(ret, nullptr);

    MapIterator *it = (MapIterator *)SoftBusCalloc(sizeof(MapIterator));
    ASSERT_NE(it, nullptr);
    it->map = (Map *)SoftBusCalloc(sizeof(Map));
    if (it->map == nullptr) {
        SoftBusFree(it);
        return;
    }
    it->map->nodeSize = HDF_MAP_VALUE_MAX_SIZE + 1;
    it->nodeNum = 1;
    it->node = (MapNode *)SoftBusCalloc(sizeof(MapNode));
    if (it->node == nullptr) {
        SoftBusFree(it->map);
        SoftBusFree(it);
        return;
    }
    it->node->next = (MapNode *)SoftBusCalloc(sizeof(MapNode));
    if (it->node->next == nullptr) {
        SoftBusFree(it->node);
        SoftBusFree(it->map);
        SoftBusFree(it);
        return;
    }
    ret = LnnMapNext(it);
    EXPECT_NE(ret, nullptr);

    it->map->nodeSize = HDF_MAP_VALUE_MAX_SIZE;
    it->nodeNum = HDF_MAP_VALUE_MAX_SIZE;
    ret = LnnMapNext(it);
    EXPECT_NE(ret, nullptr);

    SoftBusFree(it->node->next);
    SoftBusFree(it->node);
    SoftBusFree(it->map);
    SoftBusFree(it);
}
} // namespace OHOS