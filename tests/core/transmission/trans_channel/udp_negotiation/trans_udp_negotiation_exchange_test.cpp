/*
 * Copyright (c) 2022-2026 Huawei Device Co., Ltd.
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

#include "gtest/gtest.h"
#include <securec.h>

#include "bus_center_info_key_struct.h"
#include "softbus_adapter_crypto.h"
#include "softbus_adapter_mem.h"
#include "softbus_utils.h"
#include "trans_udp_channel_manager.h"
#include "trans_udp_negotiation_exchange.h"

using namespace testing::ext;

namespace OHOS {

#define TEST_SOCKET_ADDR       "192.168.8.119"
#define TEST_ERROR_CODE        (-12345)
#define COLLABORATION_FWK_UID  5520
#define CODE_EXCHANGE_UDP_INFO 6

const char *g_sessionKey = "www.test.com";
const char *g_pkgName = "dms";
const char *g_sessionName = "ohos.distributedschedule.dms.test";
const char *g_networkid = "ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00";
const char *g_groupid = "TEST_GROUP_ID";

class TransUdpNegotiationExchangeTest : public testing::Test {
public:
    TransUdpNegotiationExchangeTest() { }
    ~TransUdpNegotiationExchangeTest() { }
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override { }
    void TearDown() override { }
};

void TransUdpNegotiationExchangeTest::SetUpTestCase(void) { }

void TransUdpNegotiationExchangeTest::TearDownTestCase(void) { }

static void GenerateAppInfo(AppInfo *appInfo)
{
    if (appInfo == nullptr) {
        appInfo = (AppInfo*)SoftBusCalloc(sizeof(AppInfo));
        EXPECT_TRUE(appInfo != nullptr);
    }
    int32_t res = strcpy_s(appInfo->sessionKey, sizeof(appInfo->sessionKey), g_sessionKey);
    EXPECT_EQ(res, EOK);
    res = strcpy_s(appInfo->myData.addr, sizeof(appInfo->myData.addr), TEST_SOCKET_ADDR);
    EXPECT_EQ(res, EOK);
    res = strcpy_s(appInfo->peerData.addr, sizeof(appInfo->peerData.addr), TEST_SOCKET_ADDR);
    EXPECT_EQ(res, EOK);
    res = strcpy_s(appInfo->myData.sessionName, sizeof(appInfo->myData.sessionName), g_sessionName);
    EXPECT_EQ(res, EOK);
    res = strcpy_s(appInfo->peerData.sessionName, sizeof(appInfo->peerData.sessionName), g_sessionName);
    EXPECT_EQ(res, EOK);
    res = strcpy_s(appInfo->myData.pkgName, sizeof(appInfo->myData.pkgName), g_pkgName);
    EXPECT_EQ(res, EOK);
    res = strcpy_s(appInfo->peerData.pkgName, sizeof(appInfo->peerData.pkgName), g_pkgName);
    EXPECT_EQ(res, EOK);
    res = strcpy_s(appInfo->groupId, sizeof(appInfo->groupId), g_groupid);
    EXPECT_EQ(res, EOK);
}

/*
 * @tc.name: TransUdpNegotiationExchangeTest001
 * @tc.desc: test TransUdpNegotiationExchange
 *           Transmission udp negotiation pack and unpack request with invalid parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegotiationExchangeTest, TransUdpNegotiationExchangeTest001, TestSize.Level1)
{
    AppInfo* appInfo = (AppInfo*)SoftBusCalloc(sizeof(AppInfo));
    EXPECT_TRUE(appInfo != nullptr);
    cJSON *msg = cJSON_CreateObject();
    int32_t ret = TransPackRequestUdpInfo(nullptr, appInfo);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = TransUnpackRequestUdpInfo(nullptr, appInfo);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = TransPackRequestUdpInfo(msg, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = TransUnpackRequestUdpInfo(msg, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    cJSON_Delete(msg);
    SoftBusFree(appInfo);
}

/*
 * @tc.name: TransUdpNegotiationExchangeTest002
 * @tc.desc: test TransUdpNegotiationExchange
 *           Transmission udp negotiation pack and unpack request
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegotiationExchangeTest, TransUdpNegotiationExchangeTest002, TestSize.Level1)
{
    AppInfo* appInfo = (AppInfo*)SoftBusCalloc(sizeof(AppInfo));
    EXPECT_TRUE(appInfo != nullptr);
    GenerateAppInfo(appInfo);
    appInfo->udpChannelOptType = TYPE_UDP_CHANNEL_OPEN;
    cJSON *msg = cJSON_CreateObject();
    EXPECT_TRUE(msg != nullptr);
    int32_t ret = TransPackRequestUdpInfo(msg, appInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    memset_s(appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    ret = TransUnpackRequestUdpInfo(msg, appInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    cJSON_Delete(msg);
    msg = cJSON_CreateObject();
    appInfo->udpChannelOptType = TYPE_UDP_CHANNEL_CLOSE;
    ret = TransPackRequestUdpInfo(msg, appInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    memset_s(appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    ret = TransUnpackRequestUdpInfo(msg, appInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    cJSON_Delete(msg);
    msg = cJSON_CreateObject();
    appInfo->udpChannelOptType = TYPE_INVALID_CHANNEL;
    ret = TransPackRequestUdpInfo(msg, appInfo);
    EXPECT_EQ(ret, SOFTBUS_TRANS_INVALID_CHANNEL_TYPE);
    memset_s(appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    cJSON_Delete(msg);
    SoftBusFree(appInfo);
}

/*
 * @tc.name: TransUdpNegotiationExchangeTest003
 * @tc.desc: test TransUdpNegotiationExchange
 *           Transmission udp negotiation pack and unpack reply with invalid parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegotiationExchangeTest, TransUdpNegotiationExchangeTest003, TestSize.Level1)
{
    AppInfo* appInfo = (AppInfo*)SoftBusCalloc(sizeof(AppInfo));
    EXPECT_TRUE(appInfo != nullptr);
    cJSON *msg = cJSON_CreateObject();
    int32_t ret = TransPackReplyUdpInfo(nullptr, appInfo);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransUnpackReplyUdpInfo(nullptr, appInfo);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TransPackReplyUdpInfo(msg, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    appInfo->udpChannelOptType = TYPE_UDP_CHANNEL_OPEN;
    ret = TransPackReplyUdpInfo(msg, appInfo);
    EXPECT_EQ(SOFTBUS_OK, ret);
    appInfo->udpChannelOptType = TYPE_INVALID_CHANNEL;
    ret = TransPackReplyUdpInfo(msg, appInfo);
    EXPECT_EQ(SOFTBUS_TRANS_INVALID_CHANNEL_TYPE, ret);
    ret = TransUnpackReplyUdpInfo(msg, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    cJSON_Delete(msg);
    SoftBusFree(appInfo);
}

/*
 * @tc.name: TransUdpNegotiationExchangeTest004
 * @tc.desc: test TransUdpNegotiationExchange
 *           Transmission udp negotiation pack and unpack reply
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegotiationExchangeTest, TransUdpNegotiationExchangeTest004, TestSize.Level1)
{
    AppInfo* appInfo = (AppInfo*)SoftBusCalloc(sizeof(AppInfo));
    EXPECT_TRUE(appInfo != nullptr);

    GenerateAppInfo(appInfo);
    appInfo->udpChannelOptType = TYPE_UDP_CHANNEL_OPEN;
    cJSON *msg = cJSON_CreateObject();
    EXPECT_TRUE(msg != nullptr);
    int32_t ret = TransPackReplyUdpInfo(msg, appInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    memset_s(appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    appInfo->udpChannelOptType = TYPE_UDP_CHANNEL_OPEN;
    ret = TransUnpackReplyUdpInfo(msg, appInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    cJSON_Delete(msg);

    msg = cJSON_CreateObject();
    appInfo->udpChannelOptType = TYPE_UDP_CHANNEL_CLOSE;
    GenerateAppInfo(appInfo);
    ret = TransPackReplyUdpInfo(msg, appInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    memset_s(appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    appInfo->udpChannelOptType = TYPE_UDP_CHANNEL_CLOSE;
    ret = TransUnpackReplyUdpInfo(msg, appInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    cJSON_Delete(msg);
    SoftBusFree(appInfo);
}

/*
 * @tc.name: TransUdpNegotiationExchangeTest005
 * @tc.desc: test TransUdpNegotiationExchange
 *           Transmission udp negotiation pack and unpack reply with invalid channel option type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegotiationExchangeTest, TransUdpNegotiationExchangeTest005, TestSize.Level1)
{
    AppInfo* appInfo = (AppInfo*)SoftBusCalloc(sizeof(AppInfo));
    EXPECT_TRUE(appInfo != nullptr);
    cJSON *msg = cJSON_CreateObject();
    GenerateAppInfo(appInfo);
    appInfo->udpChannelOptType = TYPE_INVALID_CHANNEL;
    int32_t ret = TransPackReplyUdpInfo(msg, appInfo);
    EXPECT_EQ(ret, SOFTBUS_TRANS_INVALID_CHANNEL_TYPE);
    memset_s(appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    cJSON_Delete(msg);

    msg = cJSON_CreateObject();
    GenerateAppInfo(appInfo);
    appInfo->udpChannelOptType = TYPE_UDP_CHANNEL_CLOSE;
    ret = TransPackReplyUdpInfo(msg, appInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    memset_s(appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    appInfo->udpChannelOptType = TYPE_INVALID_CHANNEL;
    ret = TransUnpackReplyUdpInfo(msg, appInfo);
    EXPECT_EQ(ret, SOFTBUS_TRANS_INVALID_CHANNEL_TYPE);
    cJSON_Delete(msg);
    SoftBusFree(appInfo);
}

/*
 * @tc.name: TransUdpNegotiationExchangeTest006
 * @tc.desc: test TransUdpNegotiationExchange
 *           Transmission udp negotiation pack and unpack error info with invalid parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegotiationExchangeTest, TransUdpNegotiationExchangeTest006, TestSize.Level1)
{
    cJSON *msg = cJSON_CreateObject();
    int32_t errCode = TEST_ERROR_CODE;
    int32_t ret = TransPackReplyErrInfo(msg, errCode, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = TransUnpackReplyErrInfo(nullptr, &errCode);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = TransPackReplyErrInfo(nullptr, errCode, "error descriptor test");
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = TransUnpackReplyErrInfo(msg, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    cJSON_Delete(msg);
}

/*
 * @tc.name: TransUdpNegotiationExchangeTest007
 * @tc.desc: test TransUdpNegotiationExchange
 *           Transmission udp negotiation pack and unpack error info
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegotiationExchangeTest, TransUdpNegotiationExchangeTest007, TestSize.Level1)
{
    cJSON *msg = cJSON_CreateObject();
    EXPECT_TRUE(msg != nullptr);
    int32_t errCode = TEST_ERROR_CODE;
    int32_t ret = TransPackReplyErrInfo(msg, errCode, "error descriptor test");
    EXPECT_EQ(ret, SOFTBUS_OK);
    int32_t recvErrcode = 0;
    ret = TransUnpackReplyErrInfo(msg, &recvErrcode);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(errCode, recvErrcode);
    cJSON_Delete(msg);
}

/*
 * @tc.name: TransMetaCheckCancelEncryptionPermission001
 * @tc.desc: Test TransMetaCheckCancelEncryptionPermission with valid parameters
 *           All conditions met: correct uid, P2P connection type, FILE business type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegotiationExchangeTest, TransMetaCheckCancelEncryptionPermission001, TestSize.Level1)
{
    AppInfo *appInfo = (AppInfo *)SoftBusCalloc(sizeof(AppInfo));
    EXPECT_TRUE(appInfo != nullptr);

    appInfo->osType = OTHER_OS_TYPE;
    appInfo->metaType = META_SDK;
    appInfo->myData.uid = COLLABORATION_FWK_UID;
    appInfo->udpConnType = UDP_CONN_TYPE_P2P;
    appInfo->businessType = BUSINESS_TYPE_FILE;

    cJSON *msg = cJSON_CreateObject();
    EXPECT_TRUE(msg != nullptr);

    cJSON_AddNumberToObject(msg, "TRANS_CAPABILITY", 0);
    cJSON_AddNumberToObject(msg, "UDP_CHANNEL_CAPABILITY", (1 << UDP_CHANNEL_CANCEL_ENCRYPTION));

    GenerateAppInfo(appInfo);
    appInfo->udpChannelOptType = TYPE_UDP_CHANNEL_OPEN;

    int32_t ret = TransUnpackRequestUdpInfo(msg, appInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);

    bool hasCancelEncryption = GetCapabilityBit(appInfo->udpChannelCapability, UDP_CHANNEL_CANCEL_ENCRYPTION);
    EXPECT_TRUE(hasCancelEncryption);

    cJSON_Delete(msg);
    SoftBusFree(appInfo);
}

/*
 * @tc.name: TransMetaCheckCancelEncryptionPermission002
 * @tc.desc: Test TransMetaCheckCancelEncryptionPermission with invalid uid
 *           Session name is not IShareReceiverFileSession
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegotiationExchangeTest, TransMetaCheckCancelEncryptionPermission002, TestSize.Level1)
{
    AppInfo *appInfo = (AppInfo *)SoftBusCalloc(sizeof(AppInfo));
    EXPECT_TRUE(appInfo != nullptr);

    appInfo->osType = OTHER_OS_TYPE;
    appInfo->metaType = META_SDK;
    appInfo->udpConnType = UDP_CONN_TYPE_P2P;
    appInfo->businessType = BUSINESS_TYPE_FILE;

    cJSON *msg = cJSON_CreateObject();
    EXPECT_TRUE(msg != nullptr);

    cJSON_AddNumberToObject(msg, "TRANS_CAPABILITY", 0);
    cJSON_AddNumberToObject(msg, "UDP_CHANNEL_CAPABILITY", (1 << UDP_CHANNEL_CANCEL_ENCRYPTION));

    GenerateAppInfo(appInfo);
    appInfo->udpChannelOptType = TYPE_UDP_CHANNEL_OPEN;

    int32_t ret = TransUnpackRequestUdpInfo(msg, appInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);

    bool hasCancelEncryption = GetCapabilityBit(appInfo->udpChannelCapability, UDP_CHANNEL_CANCEL_ENCRYPTION);
    EXPECT_TRUE(hasCancelEncryption);

    cJSON_Delete(msg);
    SoftBusFree(appInfo);
}

/*
 * @tc.name: TransMetaCheckCancelEncryptionPermission003
 * @tc.desc: Test TransMetaCheckCancelEncryptionPermission with invalid UDP connection type
 *           UDP connection type is not P2P
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegotiationExchangeTest, TransMetaCheckCancelEncryptionPermission003, TestSize.Level1)
{
    AppInfo *appInfo = (AppInfo *)SoftBusCalloc(sizeof(AppInfo));
    EXPECT_TRUE(appInfo != nullptr);

    appInfo->osType = OTHER_OS_TYPE;
    appInfo->metaType = META_SDK;
    appInfo->myData.uid = COLLABORATION_FWK_UID;
    appInfo->udpConnType = UDP_CONN_TYPE_WIFI;
    appInfo->businessType = BUSINESS_TYPE_FILE;

    cJSON *msg = cJSON_CreateObject();
    EXPECT_TRUE(msg != nullptr);

    cJSON_AddNumberToObject(msg, "TRANS_CAPABILITY", 0);
    cJSON_AddNumberToObject(msg, "UDP_CHANNEL_CAPABILITY", (1 << UDP_CHANNEL_CANCEL_ENCRYPTION));

    GenerateAppInfo(appInfo);
    appInfo->udpChannelOptType = TYPE_UDP_CHANNEL_OPEN;

    int32_t ret = TransUnpackRequestUdpInfo(msg, appInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);

    bool hasCancelEncryption = GetCapabilityBit(appInfo->udpChannelCapability, UDP_CHANNEL_CANCEL_ENCRYPTION);
    EXPECT_TRUE(hasCancelEncryption);

    cJSON_Delete(msg);
    SoftBusFree(appInfo);
}

/*
 * @tc.name: TransMetaCheckCancelEncryptionPermission004
 * @tc.desc: Test TransMetaCheckCancelEncryptionPermission with invalid business type
 *           Business type is not FILE
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegotiationExchangeTest, TransMetaCheckCancelEncryptionPermission004, TestSize.Level1)
{
    AppInfo *appInfo = (AppInfo *)SoftBusCalloc(sizeof(AppInfo));
    EXPECT_TRUE(appInfo != nullptr);

    appInfo->osType = OTHER_OS_TYPE;
    appInfo->metaType = META_SDK;
    appInfo->myData.uid = COLLABORATION_FWK_UID;
    appInfo->udpConnType = UDP_CONN_TYPE_P2P;
    appInfo->businessType = BUSINESS_TYPE_STREAM;

    cJSON *msg = cJSON_CreateObject();
    EXPECT_TRUE(msg != nullptr);

    cJSON_AddNumberToObject(msg, "TRANS_CAPABILITY", 0);
    cJSON_AddNumberToObject(msg, "UDP_CHANNEL_CAPABILITY", (1 << UDP_CHANNEL_CANCEL_ENCRYPTION));

    GenerateAppInfo(appInfo);
    appInfo->udpChannelOptType = TYPE_UDP_CHANNEL_OPEN;

    int32_t ret = TransUnpackRequestUdpInfo(msg, appInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);

    bool hasCancelEncryption = GetCapabilityBit(appInfo->udpChannelCapability, UDP_CHANNEL_CANCEL_ENCRYPTION);
    EXPECT_TRUE(hasCancelEncryption);

    cJSON_Delete(msg);
    SoftBusFree(appInfo);
}

/*
 * @tc.name: TransProcessCapabilityFromJson001
 * @tc.desc: Test TransGetCapabilityFromJson with non-meta device
 *           Non-meta device should use CancelEncryptionCheckPacked
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegotiationExchangeTest, TransProcessCapabilityFromJson001, TestSize.Level1)
{
    AppInfo *appInfo = (AppInfo *)SoftBusCalloc(sizeof(AppInfo));
    EXPECT_TRUE(appInfo != nullptr);

    appInfo->osType = OH_OS_TYPE;
    appInfo->metaType = META_HA;

    cJSON *msg = cJSON_CreateObject();
    EXPECT_TRUE(msg != nullptr);

    cJSON_AddNumberToObject(msg, "TRANS_CAPABILITY", 0x1);
    cJSON_AddNumberToObject(msg, "UDP_CHANNEL_CAPABILITY", (1 << UDP_CHANNEL_CANCEL_ENCRYPTION));

    GenerateAppInfo(appInfo);
    appInfo->udpChannelOptType = TYPE_UDP_CHANNEL_OPEN;
    int32_t ret = TransUnpackRequestUdpInfo(msg, appInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);

    EXPECT_EQ(appInfo->channelCapability, 0x1);

    cJSON_Delete(msg);
    SoftBusFree(appInfo);
}

/*
 * @tc.name: TransProcessCapabilityFromJson002
 * @tc.desc: Test TransGetCapabilityFromJson with capability masking
 *           Verify that capabilities are properly masked
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegotiationExchangeTest, TransProcessCapabilityFromJson002, TestSize.Level1)
{
    AppInfo *appInfo = (AppInfo *)SoftBusCalloc(sizeof(AppInfo));
    EXPECT_TRUE(appInfo != nullptr);

    cJSON *msg = cJSON_CreateObject();
    EXPECT_TRUE(msg != nullptr);

    uint32_t testCapability = 0xFFFFFFFF;
    cJSON_AddNumberToObject(msg, "TRANS_CAPABILITY", testCapability);
    cJSON_AddNumberToObject(msg, "UDP_CHANNEL_CAPABILITY", testCapability);

    GenerateAppInfo(appInfo);
    appInfo->udpChannelOptType = TYPE_UDP_CHANNEL_OPEN;
    int32_t ret = TransUnpackRequestUdpInfo(msg, appInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);

    EXPECT_EQ(appInfo->channelCapability, (testCapability & TRANS_CHANNEL_CAPABILITY));

    EnableCapabilityBit(&testCapability, UDP_CHANNEL_CANCEL_ENCRYPTION);
    EXPECT_EQ(appInfo->udpChannelCapability, (testCapability & TRANS_UDP_CHANNEL_CAPBILITY));

    cJSON_Delete(msg);
    SoftBusFree(appInfo);
}

/*
 * @tc.name: TransUnpackRequestUdpInfoWithSessionKey001
 * @tc.desc: Test TransUnpackRequestUdpInfo with valid session key
 * @tc.type.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegotiationExchangeTest, TransUnpackRequestUdpInfoWithSessionKey001, TestSize.Level1)
{
    AppInfo *appInfo = (AppInfo *)SoftBusCalloc(sizeof(AppInfo));
    EXPECT_TRUE(appInfo != nullptr);

    cJSON *msg = cJSON_CreateObject();
    EXPECT_TRUE(msg != nullptr);

    unsigned char testSessionKey[SESSION_KEY_LENGTH] = { 0 };
    for (int i = 0; i < SESSION_KEY_LENGTH; i++) {
        testSessionKey[i] = (unsigned char)i;
    }

    char base64Key[BASE64_SESSION_KEY_LEN] = { 0 };
    size_t outLen = 0;
    int32_t ret = SoftBusBase64Encode(
        (unsigned char *)base64Key, BASE64_SESSION_KEY_LEN, &outLen, testSessionKey, SESSION_KEY_LENGTH);
    EXPECT_EQ(ret, 0);

    cJSON_AddStringToObject(msg, "SESSION_KEY", base64Key);
    cJSON_AddNumberToObject(msg, "TRANS_CAPABILITY", 0);
    cJSON_AddNumberToObject(msg, "UDP_CHANNEL_CAPABILITY", 0);
    cJSON_AddNumberToObject(msg, "CODE", CODE_EXCHANGE_UDP_INFO);
    cJSON_AddNumberToObject(msg, "UDPChannelOptType", TYPE_UDP_CHANNEL_OPEN);

    GenerateAppInfo(appInfo);
    appInfo->udpChannelOptType = TYPE_UDP_CHANNEL_OPEN;
    ret = TransUnpackRequestUdpInfo(msg, appInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);

    cJSON_Delete(msg);
    SoftBusFree(appInfo);
}

/*
 * @tc.name: TransUnpackRequestUdpInfoWithSessionKey002
 * @tc.desc: Test TransUnpackRequestUdpInfo with empty session key
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegotiationExchangeTest, TransUnpackRequestUdpInfoWithSessionKey002, TestSize.Level1)
{
    AppInfo *appInfo = (AppInfo *)SoftBusCalloc(sizeof(AppInfo));
    EXPECT_TRUE(appInfo != nullptr);

    cJSON *msg = cJSON_CreateObject();
    EXPECT_TRUE(msg != nullptr);

    cJSON_AddStringToObject(msg, "SESSION_KEY", "");
    cJSON_AddNumberToObject(msg, "TRANS_CAPABILITY", 0);
    cJSON_AddNumberToObject(msg, "UDP_CHANNEL_CAPABILITY", 0);
    cJSON_AddNumberToObject(msg, "CODE", CODE_EXCHANGE_UDP_INFO);
    cJSON_AddNumberToObject(msg, "UDPChannelOptType", TYPE_UDP_CHANNEL_OPEN);

    GenerateAppInfo(appInfo);
    appInfo->udpChannelOptType = TYPE_UDP_CHANNEL_OPEN;
    int32_t ret = TransUnpackRequestUdpInfo(msg, appInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);

    cJSON_Delete(msg);
    SoftBusFree(appInfo);
}

/*
 * @tc.name: TransUnpackRequestUdpInfoCloseChannel001
 * @tc.desc: Test TransUnpackRequestUdpInfo with TYPE_UDP_CHANNEL_CLOSE
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegotiationExchangeTest, TransUnpackRequestUdpInfoCloseChannel001, TestSize.Level1)
{
    AppInfo *appInfo = (AppInfo *)SoftBusCalloc(sizeof(AppInfo));
    EXPECT_TRUE(appInfo != nullptr);

    cJSON *msg = cJSON_CreateObject();
    EXPECT_TRUE(msg != nullptr);

    cJSON_AddStringToObject(msg, "SESSION_KEY", "");
    cJSON_AddNumberToObject(msg, "TRANS_CAPABILITY", 0);
    cJSON_AddNumberToObject(msg, "UDP_CHANNEL_CAPABILITY", 0);
    cJSON_AddNumberToObject(msg, "CODE", CODE_EXCHANGE_UDP_INFO);
    cJSON_AddNumberToObject(msg, "UDPChannelOptType", TYPE_UDP_CHANNEL_CLOSE);
    cJSON_AddNumberToObject(msg, "PEER_CHANNEL_ID", 12345);
    cJSON_AddNumberToObject(msg, "MY_CHANNEL_ID", 67890);
    cJSON_AddStringToObject(msg, "MY_IP", "192.168.1.1");

    GenerateAppInfo(appInfo);
    appInfo->udpChannelOptType = TYPE_UDP_CHANNEL_CLOSE;
    int32_t ret = TransUnpackRequestUdpInfo(msg, appInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);

    cJSON_Delete(msg);
    SoftBusFree(appInfo);
}

/*
 * @tc.name: TransUnpackExtDeviceRequestInfo001
 * @tc.desc: Test TransUnpackExtDeviceRequestInfo with meta device
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegotiationExchangeTest, TransUnpackExtDeviceRequestInfo001, TestSize.Level1)
{
    AppInfo *appInfo = (AppInfo *)SoftBusCalloc(sizeof(AppInfo));
    EXPECT_TRUE(appInfo != nullptr);

    appInfo->osType = OTHER_OS_TYPE;
    appInfo->metaType = META_SDK;
    appInfo->myData.uid = COLLABORATION_FWK_UID;
    appInfo->udpConnType = UDP_CONN_TYPE_P2P;
    appInfo->businessType = BUSINESS_TYPE_FILE;
    appInfo->udpChannelOptType = TYPE_UDP_CHANNEL_OPEN;

    cJSON *msg = cJSON_CreateObject();
    EXPECT_TRUE(msg != nullptr);

    cJSON_AddNumberToObject(msg, "CODE", CODE_EXCHANGE_UDP_INFO);
    cJSON_AddNumberToObject(msg, "TRANS_CAPABILITY", 0x1);
    cJSON_AddNumberToObject(msg, "UDP_CHANNEL_CAPABILITY", (1 << UDP_CHANNEL_CANCEL_ENCRYPTION));

    GenerateAppInfo(appInfo);

    int32_t ret = TransUnpackExtDeviceRequestInfo(msg, appInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);

    bool hasCancelEncryption = GetCapabilityBit(appInfo->udpChannelCapability, UDP_CHANNEL_CANCEL_ENCRYPTION);
    EXPECT_TRUE(hasCancelEncryption);

    cJSON_Delete(msg);
    SoftBusFree(appInfo);
}

/*
 * @tc.name: TransUnpackExtDeviceRequestInfo002
 * @tc.desc: Test TransUnpackExtDeviceRequestInfo with meta device but invalid permission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpNegotiationExchangeTest, TransUnpackExtDeviceRequestInfo002, TestSize.Level1)
{
    AppInfo *appInfo = (AppInfo *)SoftBusCalloc(sizeof(AppInfo));
    EXPECT_TRUE(appInfo != nullptr);

    appInfo->osType = OTHER_OS_TYPE;
    appInfo->metaType = META_SDK;
    appInfo->udpConnType = UDP_CONN_TYPE_P2P;
    appInfo->businessType = BUSINESS_TYPE_FILE;
    appInfo->udpChannelOptType = TYPE_UDP_CHANNEL_OPEN;

    cJSON *msg = cJSON_CreateObject();
    EXPECT_TRUE(msg != nullptr);

    cJSON_AddNumberToObject(msg, "CODE", CODE_EXCHANGE_UDP_INFO);
    cJSON_AddNumberToObject(msg, "TRANS_CAPABILITY", 0x1);
    cJSON_AddNumberToObject(msg, "UDP_CHANNEL_CAPABILITY", (1 << UDP_CHANNEL_CANCEL_ENCRYPTION));

    GenerateAppInfo(appInfo);
    int32_t ret = TransUnpackExtDeviceRequestInfo(msg, appInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);

    bool hasCancelEncryption = GetCapabilityBit(appInfo->udpChannelCapability, UDP_CHANNEL_CANCEL_ENCRYPTION);
    EXPECT_TRUE(hasCancelEncryption);

    cJSON_Delete(msg);
    SoftBusFree(appInfo);
}
} // namespace OHOS
