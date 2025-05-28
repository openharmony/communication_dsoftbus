/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <cinttypes>
#include <gtest/gtest.h>
#include <securec.h>
#include <sys/time.h>

#include "auth_hichain.c"
#include "auth_hichain_deps_mock.h"
#include "softbus_error_code.h"
#include "auth_session_json.c"
#include "auth_hichain_adapter.c"

namespace OHOS {
using namespace testing;
using namespace testing::ext;

constexpr int64_t TEST_AUTH_SEQ = 1;
constexpr uint32_t TMP_DATA_LEN = 10;
constexpr uint8_t TMP_DATA[TMP_DATA_LEN] = "tmpInData";
static constexpr int32_t DEFALUT_USERID = 100;

class AuthHichainMockTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void AuthHichainMockTest::SetUpTestCase() {}

void AuthHichainMockTest::TearDownTestCase() {}

void AuthHichainMockTest::SetUp() {}

void AuthHichainMockTest::TearDown() {}

/*
 * @tc.name: GEN_DEVICE_LEVEL_PARAM_TEST_001
 * @tc.desc: GenDeviceLevelParam test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthHichainMockTest, GEN_DEVICE_LEVEL_PARAM_TEST_001, TestSize.Level1)
{
    AuthHichainInterfaceMock hichainMock;
    HiChainAuthParam hiChainParam = {};
    cJSON *msg = reinterpret_cast<cJSON *>(SoftBusCalloc(sizeof(cJSON)));
    if (msg == nullptr) {
        return;
    }
    EXPECT_CALL(hichainMock, cJSON_CreateObject).WillOnce(Return(nullptr)).WillOnce(Return(msg));
    const char *udid = "123456";
    const char *uid = "123";
    if (strcpy_s(hiChainParam.udid, UDID_BUF_LEN, (char *)udid) != EOK ||
        strcpy_s(hiChainParam.uid, MAX_ACCOUNT_HASH_LEN, (char *)uid) != EOK) {
        return;
    }
    hiChainParam.userId = DEFALUT_USERID;
    static char *ptr = GenDeviceLevelParam(&hiChainParam);
    EXPECT_EQ(ptr, nullptr);
    EXPECT_CALL(hichainMock, AddStringToJsonObject).WillOnce(Return(false)).WillRepeatedly(Return(true));
    ptr = GenDeviceLevelParam(&hiChainParam);
    EXPECT_EQ(ptr, nullptr);
    cJSON *msg1 = reinterpret_cast<cJSON *>(SoftBusCalloc(sizeof(cJSON)));
    if (msg1 == nullptr) {
        return;
    }
    EXPECT_CALL(hichainMock, cJSON_CreateObject).WillOnce(Return(msg1));
    EXPECT_CALL(hichainMock, AddBoolToJsonObject).WillRepeatedly(Return(true));
    EXPECT_CALL(hichainMock, AddNumberToJsonObject).WillRepeatedly(Return(true));
    EXPECT_CALL(hichainMock, cJSON_PrintUnformatted).WillOnce(Return(nullptr));
    ptr = GenDeviceLevelParam(&hiChainParam);
    EXPECT_EQ(ptr, nullptr);
}

/*
 * @tc.name: ON_TRANSMIT_TEST_001
 * @tc.desc: OnTransmit test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthHichainMockTest, ON_TRANSMIT_TEST_001, TestSize.Level1)
{
    AuthHichainInterfaceMock hichainMock;
    EXPECT_CALL(hichainMock, AuthSessionPostAuthData).WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    int64_t authSeq = TEST_AUTH_SEQ;
    const uint8_t *data = reinterpret_cast<const unsigned char *>(TMP_DATA);
    uint32_t len = TMP_DATA_LEN;
    bool ret = OnTransmit(authSeq, data, len);
    EXPECT_EQ(ret, false);
    ret = OnTransmit(authSeq, data, len);
    EXPECT_EQ(ret, true);
}

/*
 * @tc.name: GET_DEVICE_SIDE_FLAG_TEST_001
 * @tc.desc: GetDeviceSideFlag test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthHichainMockTest, GET_DEVICE_SIDE_FLAG_TEST_001, TestSize.Level1)
{
    AuthHichainInterfaceMock hichainMock;
    void *para = reinterpret_cast<void *>(SoftBusCalloc(sizeof(ProofInfo)));
    if (para == nullptr) {
        return;
    }
    EXPECT_CALL(hichainMock, AuthFailNotifyProofInfo).WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_NO_FATAL_FAILURE(ProcessAuthFailCallBack(nullptr));
    EXPECT_NO_FATAL_FAILURE(ProcessAuthFailCallBack(para));
    void *para1 = reinterpret_cast<void *>(SoftBusCalloc(sizeof(ProofInfo)));
    if (para1 == nullptr) {
        return;
    }
    EXPECT_NO_FATAL_FAILURE(ProcessAuthFailCallBack(para1));
    AuthFsm authFsm;
    (void)memset_s(&authFsm, sizeof(AuthFsm), 0, sizeof(AuthFsm));
    EXPECT_CALL(hichainMock, GetAuthFsmByAuthSeq).WillOnce(Return(nullptr))
        .WillRepeatedly(Return(&authFsm));
    const char *side = "server";
    EXPECT_CALL(hichainMock, GetAuthSideStr).WillRepeatedly(Return(side));
    EXPECT_CALL(hichainMock, RequireAuthLock).WillOnce(Return(false))
        .WillRepeatedly(Return(true));
    EXPECT_CALL(hichainMock, ReleaseAuthLock).WillRepeatedly(Return());
    int64_t authSeq = TEST_AUTH_SEQ;
    bool flag;
    int32_t ret = GetDeviceSideFlag(authSeq, &flag);
    EXPECT_EQ(ret, SOFTBUS_LOCK_ERR);
    ret = GetDeviceSideFlag(authSeq, &flag);
    EXPECT_EQ(ret, SOFTBUS_AUTH_NOT_FOUND);
    ret = GetDeviceSideFlag(authSeq, &flag);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: CHECK_ERR_RETURN_VALIDITY_TEST_001
 * @tc.desc: CheckErrReturnValidity test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthHichainMockTest, CHECK_ERR_RETURN_VALIDITY_TEST_001, TestSize.Level1)
{
    AuthHichainInterfaceMock hichainMock;
    EXPECT_CALL(hichainMock, LnnAsyncCallbackDelayHelper).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(hichainMock, RequireAuthLock).WillRepeatedly(Return(true));
    EXPECT_CALL(hichainMock, ReleaseAuthLock).WillRepeatedly(Return());
    const char *errorReturn = "errorReturnTest";
    int32_t ret = CheckErrReturnValidity(errorReturn);
    EXPECT_EQ(ret, SOFTBUS_PARSE_JSON_ERR);
    ret = CheckErrReturnValidity(errorReturn);
    EXPECT_EQ(ret, SOFTBUS_PARSE_JSON_ERR);
    int errCode = PC_AUTH_ERRCODE;
    EXPECT_NO_FATAL_FAILURE(NotifyPcAuthFail(TEST_AUTH_SEQ, errCode, nullptr));
    EXPECT_NO_FATAL_FAILURE(NotifyPcAuthFail(TEST_AUTH_SEQ, errCode, errorReturn));
    EXPECT_NO_FATAL_FAILURE(NotifyPcAuthFail(TEST_AUTH_SEQ, errCode, errorReturn));
    errCode = PC_PROOF_NON_CONSISTENT_ERRCODE;
    EXPECT_NO_FATAL_FAILURE(NotifyPcAuthFail(TEST_AUTH_SEQ, errCode, errorReturn));
}

/*
 * @tc.name: ON_REQUEST_TEST_001
 * @tc.desc: OnRequest test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthHichainMockTest, ON_REQUEST_TEST_001, TestSize.Level1)
{
    int64_t authSeq = TEST_AUTH_SEQ - 1;
    const char *reqParams = "reqParams";
    int operationCode = 100;
    AuthHichainInterfaceMock hichainMock;
    cJSON *msg = reinterpret_cast<cJSON *>(SoftBusCalloc(sizeof(cJSON)));
    if (msg == nullptr) {
        return;
    }
    cJSON *msg1 = reinterpret_cast<cJSON *>(SoftBusCalloc(sizeof(cJSON)));
    if (msg1 == nullptr) {
        SoftBusFree(msg);
        return;
    }
    cJSON *msg2 = reinterpret_cast<cJSON *>(SoftBusCalloc(sizeof(cJSON)));
    if (msg2 == nullptr) {
        SoftBusFree(msg);
        SoftBusFree(msg1);
        return;
    }
    EXPECT_CALL(hichainMock, AuthSessionGetUdid).WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(hichainMock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    char *ptr = OnRequest(authSeq, operationCode, reqParams);
    EXPECT_EQ(ptr, nullptr);
    EXPECT_CALL(hichainMock, cJSON_CreateObject).WillOnce(Return(nullptr)).WillOnce(Return(msg))
        .WillOnce(Return(msg1)).WillOnce(Return(msg2));

    ptr = OnRequest(authSeq, operationCode, reqParams);
    EXPECT_EQ(ptr, nullptr);
    EXPECT_CALL(hichainMock, AddNumberToJsonObject).WillOnce(Return(false)).WillRepeatedly(Return(true));
    ptr = OnRequest(authSeq, operationCode, reqParams);
    EXPECT_EQ(ptr, nullptr);
    EXPECT_CALL(hichainMock, AddStringToJsonObject).WillOnce(Return(false)).WillRepeatedly(Return(true));
    ptr = OnRequest(authSeq, operationCode, reqParams);
    EXPECT_EQ(ptr, nullptr);
    EXPECT_CALL(hichainMock, AddBoolToJsonObject).WillOnce(Return(false)).WillRepeatedly(Return(true));
    ptr = OnRequest(authSeq, operationCode, reqParams);
    EXPECT_EQ(ptr, nullptr);
}

/*
 * @tc.name: ON_REQUEST_TEST_002
 * @tc.desc: OnRequest test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthHichainMockTest, ON_REQUEST_TEST_002, TestSize.Level1)
{
    int64_t authSeq = TEST_AUTH_SEQ;
    const char *reqParams = "reqParams";
    int operationCode = 100;
    AuthHichainInterfaceMock hichainMock;
    cJSON *msg3 = reinterpret_cast<cJSON *>(SoftBusCalloc(sizeof(cJSON)));
    if (msg3 == nullptr) {
        return;
    }
    cJSON *msg4 = reinterpret_cast<cJSON *>(SoftBusCalloc(sizeof(cJSON)));
    if (msg4 == nullptr) {
        SoftBusFree(msg3);
        return;
    }
    cJSON *msg5 = reinterpret_cast<cJSON *>(SoftBusCalloc(sizeof(cJSON)));
    if (msg5 == nullptr) {
        SoftBusFree(msg3);
        SoftBusFree(msg4);
        return;
    }

    cJSON *msg6 = reinterpret_cast<cJSON *>(SoftBusCalloc(sizeof(cJSON)));
    if (msg6 == nullptr) {
        SoftBusFree(msg3);
        SoftBusFree(msg4);
        SoftBusFree(msg5);
        return;
    }

    EXPECT_CALL(hichainMock, AuthSessionGetUdid).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(hichainMock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(hichainMock, cJSON_CreateObject).WillOnce(Return(msg3)).WillOnce(Return(msg4))
        .WillOnce(Return(msg5)).WillOnce(Return(msg6));
    EXPECT_CALL(hichainMock, AddNumberToJsonObject).WillRepeatedly(Return(true));
    EXPECT_CALL(hichainMock, AddStringToJsonObject).WillOnce(Return(true)).WillOnce(Return(true))
        .WillOnce(Return(true)).WillOnce(Return(false)).WillRepeatedly(Return(true));
    EXPECT_CALL(hichainMock, AddBoolToJsonObject).WillRepeatedly(Return(true));

    char msgStr[10] = {0};
    const char *val = "returnStr";
    EXPECT_EQ(strcpy_s(msgStr, sizeof(msgStr), val), EOK);
    EXPECT_CALL(hichainMock, cJSON_PrintUnformatted).WillOnce(Return(nullptr)).WillRepeatedly(Return(msgStr));
    char *ptr = OnRequest(authSeq, operationCode, reqParams);
    EXPECT_EQ(ptr, nullptr);

    authSeq = 0;
    ptr = OnRequest(authSeq, operationCode, reqParams);
    EXPECT_EQ(ptr, nullptr);

    ptr = OnRequest(authSeq, operationCode, reqParams);
    EXPECT_EQ(ptr, nullptr);

    ptr = OnRequest(authSeq, operationCode, reqParams);
    EXPECT_NE(ptr, nullptr);
}

/*
 * @tc.name: GET_UDID_HASH_TEST_001
 * @tc.desc: GetUdidHash test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthHichainMockTest, GET_UDID_HASH_TEST_001, TestSize.Level1)
{
    AuthHichainInterfaceMock hichainMock;
    EXPECT_CALL(hichainMock, SoftBusGenerateStrHash).WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(hichainMock, ConvertBytesToHexString).WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    const char *udid = "udidTest";
    char udidHash[HB_SHORT_UDID_HASH_HEX_LEN + 1] = { 0 };

    int32_t ret = GetUdidHash(nullptr, udidHash);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GetUdidHash(udid, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GetUdidHash(udid, udidHash);
    EXPECT_NE(ret, SOFTBUS_OK);
    ret = GetUdidHash(udid, udidHash);
    EXPECT_NE(ret, SOFTBUS_OK);
    ret = GetUdidHash(udid, udidHash);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_NO_FATAL_FAILURE(DeletePcRestrictNode(nullptr));
    EXPECT_CALL(hichainMock, GetNodeFromPcRestrictMap).WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_NO_FATAL_FAILURE(DeletePcRestrictNode(udid));
    EXPECT_CALL(hichainMock, DeleteNodeFromPcRestrictMap).WillRepeatedly(Return());
    EXPECT_NO_FATAL_FAILURE(DeletePcRestrictNode(udid));
}

/*
 * @tc.name: HICHAIN_START_AUTH_TEST_001
 * @tc.desc: HichainStartAuth test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthHichainMockTest, HICHAIN_START_AUTH_TEST_001, TestSize.Level1)
{
    AuthHichainInterfaceMock hichainMock;
    HiChainAuthParam hiChainParam = {};
    EXPECT_CALL(hichainMock, cJSON_CreateObject).WillOnce(Return(nullptr));
    int64_t authSeq = TEST_AUTH_SEQ;
    const char *udid = "udidTest";
    const char *uid = "uidTest";
    const char *groupInfo = "groupInfoTest";

    if (strcpy_s(hiChainParam.udid, UDID_BUF_LEN, (char *)udid) != EOK ||
        strcpy_s(hiChainParam.uid, MAX_ACCOUNT_HASH_LEN, (char *)uid) != EOK) {
        return;
    }
    hiChainParam.userId = DEFALUT_USERID;
    EXPECT_NO_FATAL_FAILURE(OnDeviceBound(hiChainParam.udid, nullptr));
    EXPECT_NO_FATAL_FAILURE(OnDeviceBound(nullptr, groupInfo));
    int32_t ret = HichainStartAuth(authSeq, &hiChainParam, HICHAIN_AUTH_DEVICE);
    EXPECT_EQ(ret, SOFTBUS_CREATE_JSON_ERR);
    cJSON *msg = reinterpret_cast<cJSON *>(SoftBusCalloc(sizeof(cJSON)));
    if (msg == nullptr) {
        return;
    }
    EXPECT_NO_FATAL_FAILURE(OnDeviceBound(udid, groupInfo));
    EXPECT_CALL(hichainMock, GetJsonObjectStringItem).WillRepeatedly(Return(true));
    EXPECT_CALL(hichainMock, GetJsonObjectNumberItem)
        .WillRepeatedly(DoAll(SetArgPointee<2>(AUTH_IDENTICAL_ACCOUNT_GROUP), Return(true)));
    EXPECT_CALL(hichainMock, SoftBusGenerateStrHash).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_NO_FATAL_FAILURE(OnDeviceBound(udid, groupInfo));
}

/*
 * @tc.name: PACK_EXTERNAL_AUTH_INFO_001
 * @tc.desc: PackExternalAuthInfo test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthHichainMockTest, PACK_EXTERNAL_AUTH_INFO_001, TestSize.Level1)
{
    AuthHichainInterfaceMock hichainMock;
    int32_t ret = SOFTBUS_OK;

    JsonObj *obj = JSON_CreateObject();
    EXPECT_NE(obj, NULL);

    EXPECT_CALL(hichainMock, LnnGetLocalStrInfo).WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(hichainMock, SoftBusGenerateStrHash).WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(hichainMock, LnnGetLocalByteInfo).WillOnce(Return(SOFTBUS_NETWORK_NOT_FOUND))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(hichainMock, ConvertBytesToHexString).WillOnce(Return(SOFTBUS_OK)).WillOnce(Return(SOFTBUS_OK))
        .WillOnce(Return(SOFTBUS_OK))
        .WillOnce(Return(SOFTBUS_NETWORK_NOT_FOUND)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(hichainMock, JSON_AddStringToObject).WillOnce(Return(false)).WillRepeatedly(Return(true));

    ret = PackExternalAuthInfo(obj);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_GET_LOCAL_NODE_INFO_ERR);

    ret = PackExternalAuthInfo(obj);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_GET_LOCAL_NODE_INFO_ERR);

    ret = PackExternalAuthInfo(obj);
    EXPECT_EQ(ret, SOFTBUS_CREATE_JSON_ERR);

    ret = PackExternalAuthInfo(obj);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_GET_LOCAL_NODE_INFO_ERR);

    ret = PackExternalAuthInfo(obj);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_BYTES_TO_HEX_STR_ERR);

    ret = PackExternalAuthInfo(obj);
    EXPECT_EQ(ret, SOFTBUS_OK);

    JSON_Delete(obj);
}

/*
 * @tc.name: UNPACK_EXTERNAL_AUTH_INFO_001
 * @tc.desc: UnpackExternalAuthInfo test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthHichainMockTest, UNPACK_EXTERNAL_AUTH_INFO_001, TestSize.Level1)
{
    AuthHichainInterfaceMock hichainMock;
    AuthSessionInfo info = { 0 };
    const char *credID = "1234";

    JsonObj *obj = JSON_CreateObject();
    EXPECT_NE(obj, NULL);

    EXPECT_CALL(hichainMock, JSON_GetStringFromObject).WillOnce(Return(false)).WillRepeatedly(Return(true));
    EXPECT_CALL(hichainMock, LnnGetLocalNodeInfoSafe).WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(hichainMock, LnnGetLocalByteInfo).WillOnce(Return(SOFTBUS_NETWORK_NOT_FOUND))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(hichainMock, ConvertBytesToHexString).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(hichainMock, LnnIsDefaultOhosAccount).WillRepeatedly(Return(false));
    EXPECT_CALL(hichainMock, LnnGetLocalStrInfo).WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(hichainMock, IdServiceQueryCredential).WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(hichainMock, IdServiceGetCredIdFromCredList).WillOnce(Return(NULL))
        .WillRepeatedly(Return((char *)credID));
    EXPECT_CALL(hichainMock, SoftBusGenerateStrHash).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(hichainMock, IdServiceDestroyCredentialList).Times(2);

    UnpackExternalAuthInfo(obj, &info);
    EXPECT_EQ(info.credId, NULL);

    info.authVersion = (AuthVersion)2;  // AUTH_VERSION_V2
    UnpackExternalAuthInfo(obj, &info);
    EXPECT_EQ(info.credId, NULL);

    UnpackExternalAuthInfo(obj, &info);
    EXPECT_EQ(info.credId, NULL);

    UnpackExternalAuthInfo(obj, &info);
    EXPECT_EQ(info.credId, NULL);

    UnpackExternalAuthInfo(obj, &info);
    EXPECT_EQ(info.credId, NULL);

    UnpackExternalAuthInfo(obj, &info);
    EXPECT_EQ(info.credId, NULL);

    UnpackExternalAuthInfo(obj, &info);
    EXPECT_NE(info.credId, NULL);

    JSON_Delete(obj);
}
} // namespace OHOS
