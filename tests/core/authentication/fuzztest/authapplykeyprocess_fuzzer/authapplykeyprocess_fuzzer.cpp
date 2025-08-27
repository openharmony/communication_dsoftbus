/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "authapplykeyprocess_fuzzer.h"
#include <cstddef>
#include <cstring>
#include <fuzzer/FuzzedDataProvider.h>
#include <securec.h>

#include "auth_apply_key_process.c"
#include "auth_apply_key_process.h"
#include "auth_manager.h"
#include "comm_log.h"
#include "fuzz_environment.h"
#include "softbus_access_token_test.h"

#define BUF_LEN            30
#define OPERATION_CODE     25
#define AUTH_LINK_TYPE_MIN AUTH_LINK_TYPE_WIFI
#define AUTH_LINK_TYPE_MAX AUTH_LINK_TYPE_MAX

using namespace std;

namespace {
class TestEnv {
public:
    TestEnv()
    {
        AuthCommonInit();
        isInited_ = true;
    }
    ~TestEnv()
    {
        AuthCommonDeinit();
        isInited_ = false;
    }

    bool IsEnvInited(void)
    {
        return isInited_;
    }

private:
    volatile bool isInited_ = false;
};
} // namespace

namespace OHOS {

void SetApplyKeyNegoInfo(
    FuzzedDataProvider &provider, uint32_t requestId, bool isRecv, const GenApplyKeyStartState state)
{
    uint32_t len = provider.ConsumeIntegral<uint32_t>();
    vector<uint8_t> applyKey = provider.ConsumeRemainingBytes<uint8_t>();
    string accountHashBuf = provider.ConsumeRandomLengthString(len);
    SetApplyKeyNegoInfoRecvSessionKey(requestId, isRecv, applyKey.data(), applyKey.size());
    SetApplyKeyNegoInfoRecvCloseAck(requestId, isRecv);
    SetApplyKeyNegoInfoRecvFinish(requestId, isRecv, (char *)accountHashBuf.c_str());
    SetApplyKeyStartState(requestId, state);
}

void ProcessApplyKeyInfo(FuzzedDataProvider &provider, RequestBusinessInfo reqBusInfo, int32_t channelId,
    uint32_t requestId, uint32_t connId)
{
    uint32_t len = provider.ConsumeIntegral<uint32_t>();
    string data = provider.ConsumeRandomLengthString(len);
    UnpackApplyKeyAclParam(data.c_str(), len, &reqBusInfo);
    int32_t reason = provider.ConsumeIntegral<int32_t>();
    UpdateAllGenCbCallback(&reqBusInfo, true, reason);
    string accountHashBuf = provider.ConsumeRandomLengthString(len);
    string accountString = provider.ConsumeRandomLengthString(len);
    GenerateAccountHash((char *)accountString.c_str(), (char *)accountHashBuf.c_str(), accountHashBuf.length());
    string localUdidShortHash = provider.ConsumeRandomLengthString(len);
    string localAccountShortHash = provider.ConsumeRandomLengthString(len);
    GetUdidAndAccountShortHash((char *)localUdidShortHash.c_str(), localUdidShortHash.length(),
        (char *)localAccountShortHash.c_str(), localAccountShortHash.length());
    bool isGreater = true;
    ProcessApplyKeyNegoState(&reqBusInfo, &isGreater);
    StartApplyKeyHichain(connId, &reqBusInfo, requestId);
    SendApplyKeyNegoDeviceId(connId, &reqBusInfo, requestId);
    ConnectionInfo connInfo;
    (void)memset_s(&connInfo, sizeof(ConnectionInfo), 0, sizeof(ConnectionInfo));
    connInfo.type = CONNECT_P2P;
    int32_t isAvailable = provider.ConsumeIntegral<int32_t>();
    connInfo.isAvailable = isAvailable;
    OnCommConnected(connId, &connInfo);
    int64_t seq = provider.ConsumeIntegral<int64_t>();
    OnCommDataReceived(connId, MODULE_AUTH_CHANNEL, seq, (char *)data.c_str(), len);
    OnCommDataReceived(connId, MODULE_AUTH_MSG, seq, (char *)data.c_str(), len);
    OnCommDataReceived(connId, MODULE_CONNECTION, seq, (char *)data.c_str(), len);
    vector<uint8_t> applyKey = provider.ConsumeRemainingBytes<uint8_t>();
    AuthFindApplyKey(
        &reqBusInfo, applyKey.data(), (char *)localAccountShortHash.c_str(), localAccountShortHash.length());
    UpdateUniqueId();
    GenApplyKeySeq();
    OnCommDisconnected(connId, &connInfo);
    uint64_t time = provider.ConsumeIntegral<uint64_t>();
    AuthIsApplyKeyExpired(time);
}

void ProcessApplyKey(FuzzedDataProvider &provider, AuthSessionInfo &sessionInfo, int64_t authSeq, uint32_t requestId)
{
    vector<uint8_t> data = provider.ConsumeRemainingBytes<uint8_t>();
    RequestBusinessInfo reqBusInfo;
    (void)memset_s(&reqBusInfo, sizeof(RequestBusinessInfo), 0, sizeof(RequestBusinessInfo));
    string udidHash = provider.ConsumeRandomLengthString(D2D_UDID_HASH_STR_LEN);
    if (strcpy_s(reqBusInfo.udidHash, D2D_UDID_HASH_STR_LEN, udidHash.c_str()) != EOK) {
        COMM_LOGE(COMM_TEST, "strcpy_s udidHash failed !");
        return;
    }
    string accountHash = provider.ConsumeRandomLengthString(D2D_ACCOUNT_HASH_STR_LEN);
    if (strcpy_s(reqBusInfo.accountHash, D2D_ACCOUNT_HASH_STR_LEN, accountHash.c_str()) != EOK) {
        COMM_LOGE(COMM_TEST, "strcpy_s accountHash failed !");
        return;
    }
    string peerAccountHash = provider.ConsumeRandomLengthString(SHA_256_HEX_HASH_LEN);
    if (strcpy_s(reqBusInfo.peerAccountHash, SHA_256_HEX_HASH_LEN, peerAccountHash.c_str()) != EOK) {
        COMM_LOGE(COMM_TEST, "strcpy_s peerAccountHash failed !");
        return;
    }
    reqBusInfo.type = BUSINESS_TYPE_D2D;
    GetSameApplyKeyInstanceNum(&reqBusInfo);
    SetApplyKeyStartState(requestId, GEN_APPLY_KEY_STATE_START);
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    ProcessApplyKeyDeviceId(channelId, requestId, data.data(), data.size());
    ProcessApplyKeyData(requestId, data.data(), data.size());
    AuthDataHead authDataHead = {
        .dataType = provider.ConsumeIntegralInRange<uint32_t>(DATA_TYPE_AUTH, DATA_TYPE_APPLY_KEY_CONNECTION),
        .module = (int32_t)provider.ConsumeIntegralInRange<int32_t>(MODULE_MIN, MODULE_MAX),
        .seq = authSeq,
        .flag = sessionInfo.isConnectServer ? SERVER_SIDE_FLAG : CLIENT_SIDE_FLAG,
        .len = data.size(),
    };
    ApplyKeyMsgHandler(channelId, requestId, &authDataHead, data.data(), data.size());
    ApplyKeyNegoInstance applykeyinstance;
    uint32_t connId = provider.ConsumeIntegral<uint32_t>();
    (void)memset_s(&applykeyinstance, sizeof(ApplyKeyNegoInstance), 0, sizeof(ApplyKeyNegoInstance));
    applykeyinstance.connId = connId;
    applykeyinstance.requestId = requestId;
    applykeyinstance.state = GEN_APPLY_KEY_STATE_START;
    GetGenApplyKeyInstanceByReq(requestId, &applykeyinstance);
    GetGenApplyKeyInstanceByChannel(channelId, &applykeyinstance);
    ProcessApplyKeyInfo(provider, reqBusInfo, channelId, requestId, connId);
    PostApplyKeyData(connId, true, &authDataHead, data.data());
    SendApplyKeyNegoCloseAckEvent(channelId, requestId, true);
    OnTransmitted(authSeq, data.data(), data.size());
    AuthGenApplyKeyStartTimeout(requestId);
    ProcessApplyKeyCloseAckData(requestId, data.data(), data.size());
    vector<uint8_t> sessionKey = provider.ConsumeRemainingBytes<uint8_t>();
    OnSessionKeyReturned(authSeq, sessionKey.data(), sessionKey.size());
}

bool AuthApplyKeyProcessFuzzTest(FuzzedDataProvider &provider)
{
    AuthSessionInfo sessionInfo;
    (void)memset_s(&sessionInfo, sizeof(AuthSessionInfo), 0, sizeof(AuthSessionInfo));
    sessionInfo.isServer = provider.ConsumeBool();
    string udid = provider.ConsumeRandomLengthString(UDID_BUF_LEN);
    string uuid = provider.ConsumeRandomLengthString(UUID_BUF_LEN);
    if (strcpy_s(sessionInfo.udid, UDID_BUF_LEN, udid.c_str()) != EOK) {
        COMM_LOGE(COMM_TEST, "strcpy_s udid failed !");
        return false;
    }
    if (strcpy_s(sessionInfo.uuid, UUID_BUF_LEN, uuid.c_str()) != EOK) {
        COMM_LOGE(COMM_TEST, "strcpy_s uuid failed !");
        return false;
    }
    sessionInfo.connInfo.type =
        (AuthLinkType)provider.ConsumeIntegralInRange<uint32_t>(AUTH_LINK_TYPE_MIN, AUTH_LINK_TYPE_MAX);
    sessionInfo.connId = (uint64_t)sessionInfo.connInfo.type << INT32_BIT_NUM;
    sessionInfo.isConnectServer = provider.ConsumeBool();
    ApplyKeyNegoInit();
    InitApplyKeyNegoInstanceList();
    uint32_t requestId = provider.ConsumeIntegral<uint32_t>();
    int64_t authSeq = provider.ConsumeIntegral<int64_t>();
    string reqParams = provider.ConsumeRandomLengthString(BUF_LEN);
    OnRequest(authSeq, OPERATION_CODE, reqParams.c_str());
    PackApplyKeyAclParam(BUSINESS_TYPE_D2D);
    ProcessApplyKey(provider, sessionInfo, authSeq, requestId);
    SetApplyKeyNegoInfo(provider, requestId, true, GEN_APPLY_KEY_STATE_START);
    SetApplyKeyNegoInfo(provider, requestId, true, GEN_APPLY_KEY_STATE_UNKNOW);
    ApplyKeyGetLightAccountInstance();
    OnGenSuccess(requestId);
    uint32_t len = provider.ConsumeIntegral<uint32_t>();
    string returnData = provider.ConsumeRandomLengthString(len);
    int32_t operationCode = provider.ConsumeIntegral<int32_t>();
    OnFinished(authSeq, operationCode, returnData.c_str());
    int32_t errCode = provider.ConsumeIntegral<int32_t>();
    OnError(authSeq, operationCode, errCode, returnData.c_str());
    DeleteApplyKeyNegoInstance(requestId);
    ApplyKeyNegoDeinit();
    DeInitApplyKeyNegoInstanceList();
    RequireApplyKeyNegoListLock();
    ReleaseApplyKeyNegoListLock();
    return true;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static TestEnv env;
    if (!env.IsEnvInited()) {
        return -1;
    }
    FuzzedDataProvider provider(data, size);
    /* Run your code on data */
    if (!OHOS::AuthApplyKeyProcessFuzzTest(provider)) {
        return -1;
    }
    return 0;
}