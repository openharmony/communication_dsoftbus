/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#include <sys/time.h>

#include "auth_common.h"
#include "auth_connection.h"
#include "auth_interface.h"
#include "auth_manager.h"
#include "auth_sessionkey.h"
#include "message_handler.h"
#include "softbus_errcode.h"
#include "softbus_json_utils.h"
#include "softbus_log.h"
#include "softbus_mem_interface.h"
#include "softbus_server_frame.h"

namespace OHOS {
using namespace testing::ext;
constexpr char SERVER_MAC[BT_MAC_LEN] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
constexpr char CLIENT_MAC[BT_MAC_LEN] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x07};
constexpr uint8_t ENCRYPT_DATA[] = "auth_encrypt_data_test.";
constexpr uint8_t SESSION_KEY[4] = {'a', 'b', 'c', 'd'};
constexpr uint32_t SESSION_KEY_LEN = 4;
constexpr uint64_t DEFAULT_SEQ = 123456789;
constexpr char UUID[] = "B4FE52C465D0A53D5AECE2ED9498F28BEA87C8FE3F1581CFFC673425B11F6608";
constexpr char UDID[] = "AE3017B79036A7EE19991538BBE303E8826CEB2B5B6CC5130BD74C83BF63137F";

class AuthTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void AuthTest::SetUpTestCase()
{
}

void AuthTest::TearDownTestCase()
{
}

void AuthTest::SetUp()
{
    LOG_INFO("AuthTest start.");
}

void AuthTest::TearDown()
{
}

void OnDeviceVerifyPass(int64_t authId, ConnectOption *option, SoftBusVersion peerVersion)
{
    (void)option;
    (void)peerVersion;
    LOG_INFO("OnDeviceVerifyPass! authId=%lld", authId);
}

void OnDeviceVerifyFail(int64_t authId, ConnectOption *option)
{
    (void)option;
    LOG_INFO("OnDeviceVerifyFail! authId=%lld", authId);
}

void OnRecvSyncDeviceInfo(int64_t authId, AuthSideFlag side, const char *peerUdid, uint8_t *data, uint32_t len)
{
    (void)side;
    (void)peerUdid;
    (void)data;
    (void)len;
    LOG_INFO("OnRecvSyncDeviceInfo! authId=%lld", authId);
}

void OnDeviceNotTrusted(const char *peerUdid)
{
    (void)peerUdid;
    LOG_INFO("OnDeviceNotTrusted!");
}

/*
* @tc.name: AUTH_INIT_Test_001
* @tc.desc: auth init test
* @tc.type: FUNC
* @tc.require: AR000FK6J4
*/
HWTEST_F(AuthTest, AUTH_INIT_Test_001, TestSize.Level0)
{
    int32_t ret;
    ret = LooperInit();
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = ConnServerInit();
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = AuthInit();
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
* @tc.name: AUTH_REG_CB_Test_001
* @tc.desc: register auth callback test
* @tc.type: FUNC
* @tc.require: AR000FK6J4
*/
HWTEST_F(AuthTest, AUTH_REG_CB_Test_001, TestSize.Level0)
{
    int32_t ret;
    VerifyCallback cb = {0};
    cb.onDeviceVerifyPass = OnDeviceVerifyPass;
    cb.onDeviceVerifyFail = OnDeviceVerifyFail;
    cb.onRecvSyncDeviceInfo = OnRecvSyncDeviceInfo;
    cb.onDeviceNotTrusted = OnDeviceNotTrusted;

    ret = AuthRegCallback(LNN, &cb);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
* @tc.name: AUTH_SET_SESSIONKEY_Test_001
* @tc.desc: set server side sessionkey test
* @tc.type: FUNC
* @tc.require: AR000FK6J4
*/
HWTEST_F(AuthTest, AUTH_SET_SESSIONKEY_Test_001, TestSize.Level0)
{
    int32_t ret;
    NecessaryDevInfo devInfo = {0};
    devInfo.type = CONNECT_BR;
    devInfo.side = SERVER_SIDE_FLAG;
    ret = memcpy_s(devInfo.deviceKey, MAX_DEVICE_KEY_LEN, CLIENT_MAC, BT_MAC_LEN);
    EXPECT_TRUE(ret == EOK);
    devInfo.deviceKeyLen = BT_MAC_LEN;
    devInfo.seq = DEFAULT_SEQ;
    AuthSetLocalSessionKey(&devInfo, "udid_server", SESSION_KEY, SESSION_KEY_LEN);
}

/*
* @tc.name: AUTH_SET_SESSIONKEY_Test_002
* @tc.desc: set client side sessionkey test
* @tc.type: FUNC
* @tc.require: AR000FK6J4
*/
HWTEST_F(AuthTest, AUTH_SET_SESSIONKEY_Test_002, TestSize.Level0)
{
    int32_t ret;
    NecessaryDevInfo devInfo;
    devInfo.type = CONNECT_BR;
    devInfo.side = CLIENT_SIDE_FLAG;
    ret = memcpy_s(devInfo.deviceKey, MAX_DEVICE_KEY_LEN, SERVER_MAC, BT_MAC_LEN);
    EXPECT_TRUE(ret == EOK);
    devInfo.deviceKeyLen = BT_MAC_LEN;
    devInfo.seq = DEFAULT_SEQ;
    AuthSetLocalSessionKey(&devInfo, "udid_client", SESSION_KEY, SESSION_KEY_LEN);
}

/*
* @tc.name: AUTH_ENCRYPT_AND_DECRYPT_Test_001
* @tc.desc: auth encrypt and decrypt data test
* @tc.type: FUNC
* @tc.require: AR000FK6J4
*/
HWTEST_F(AuthTest, AUTH_ENCRYPT_AND_DECRYPT_Test_001, TestSize.Level0)
{
    int32_t ret;
    AuthSideFlag clientSide;
    ConnectOption option;
    option.type = CONNECT_BR;

    ret = memcpy_s(option.info.brOption.brMac, BT_MAC_LEN, SERVER_MAC, BT_MAC_LEN);
    EXPECT_TRUE(ret == EOK);
    uint32_t totalLen = strlen((char *)ENCRYPT_DATA) + AuthGetEncryptHeadLen();
    uint8_t *sendBuf = (uint8_t *)SoftBusMalloc(totalLen);
    ASSERT_TRUE(sendBuf != NULL);
    (void)memset_s(sendBuf, totalLen, 0, totalLen);
    OutBuf outBuf;
    outBuf.buf = sendBuf;
    outBuf.bufLen = totalLen;
    ret= AuthEncrypt(&option, &clientSide, (uint8_t *)ENCRYPT_DATA, strlen((char *)ENCRYPT_DATA), &outBuf);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    ConnectOption option1;
    option1.type = CONNECT_BR;

    ret = memcpy_s(option1.info.brOption.brMac, BT_MAC_LEN, CLIENT_MAC, BT_MAC_LEN);
    EXPECT_TRUE(ret == EOK);
    uint8_t *recvBuf = (uint8_t *)SoftBusMalloc(strlen((char *)ENCRYPT_DATA) + 1);
    if (recvBuf == NULL) {
        SoftBusFree(sendBuf);
    }
    ASSERT_TRUE(recvBuf != NULL);
    (void)memset_s(recvBuf, strlen((char *)ENCRYPT_DATA) + 1, 0, strlen((char *)ENCRYPT_DATA) + 1);
    OutBuf outBuf1;
    outBuf1.buf = recvBuf;
    outBuf1.bufLen = strlen((char *)ENCRYPT_DATA) + 1;
    ret = AuthDecrypt(&option1, SERVER_SIDE_FLAG, outBuf.buf, outBuf.outLen, &outBuf1);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    SoftBusFree(sendBuf);
    SoftBusFree(recvBuf);
}

static cJSON *AuthPackDeviceInfo(void)
{
    cJSON *msg = cJSON_CreateObject();
    if (msg == NULL) {
        return NULL;
    }

    EXPECT_TRUE(AddStringToJsonObject(msg, CMD_TAG, CMD_RET_AUTH_INFO));
    EXPECT_TRUE(AddStringToJsonObject(msg, DATA_TAG, UUID));
    EXPECT_TRUE(AddStringToJsonObject(msg, TE_DEVICE_ID_TAG, UDID));
    EXPECT_TRUE(AddNumberToJsonObject(msg, DATA_BUF_SIZE_TAG, PACKET_SIZE));
    EXPECT_TRUE(AddNumberToJsonObject(msg, SOFTBUS_VERSION_INFO, SOFT_BUS_NEW_V1));
    return msg;
}

/*
* @tc.name: AUTH_PACK_AND_UNPACK_Test_001
* @tc.desc: auth pack and unpack data test
* @tc.type: FUNC
* @tc.require: AR000FK6J4
*/
HWTEST_F(AuthTest, AUTH_PACK_AND_UNPACK_Test_001, TestSize.Level0)
{
    cJSON *obj = AuthPackDeviceInfo();
    EXPECT_TRUE(obj != NULL);
    char *msgStr = cJSON_PrintUnformatted(obj);
    EXPECT_TRUE(msgStr != NULL);
    cJSON_Delete(obj);
    cJSON *msg = cJSON_Parse((char*)msgStr);
    cJSON_free(msgStr);
    char cmd[CMD_TAG_LEN] = {0};
    EXPECT_TRUE(GetJsonObjectStringItem(msg, CMD_TAG, cmd, CMD_TAG_LEN));
    char uuid[UUID_BUF_LEN] = {0};
    EXPECT_TRUE(GetJsonObjectStringItem(msg, DATA_TAG, uuid, UUID_BUF_LEN));
    char deviceUdid[UDID_BUF_LEN] = {0};
    EXPECT_TRUE(GetJsonObjectStringItem(msg, TE_DEVICE_ID_TAG, deviceUdid, UDID_BUF_LEN));
    int32_t packetSize;
    EXPECT_TRUE(GetJsonObjectNumberItem(msg, DATA_BUF_SIZE_TAG, &packetSize));
    int32_t peerVersion;
    EXPECT_TRUE(GetJsonObjectNumberItem(msg, SOFTBUS_VERSION_INFO, &peerVersion));
    cJSON_Delete(msg);
}

/*
* @tc.name: AUTH_DEINIT_Test_001
* @tc.desc: auth deinit test
* @tc.type: FUNC
* @tc.require: AR000FK6J4
*/
HWTEST_F(AuthTest, AUTH_DEINIT_Test_001, TestSize.Level0)
{
    ConnServerDeinit();
    AuthDeinit();
    LooperDeinit();
}
}