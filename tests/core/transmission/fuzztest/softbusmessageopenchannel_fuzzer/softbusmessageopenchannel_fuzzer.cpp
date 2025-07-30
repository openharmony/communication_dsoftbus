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

#include "softbusmessageopenchannel_fuzzer.h"

#include <fuzzer/FuzzedDataProvider.h>
#include "securec.h"

#include "fuzz_data_generator.h"
#include "softbus_message_open_channel.c"

namespace OHOS {
class SoftbusMessageOpenChannelTestEvent {
public:
    SoftbusMessageOpenChannelTestEvent()
    {
    }

    ~SoftbusMessageOpenChannelTestEvent()
    {
    }
};

static void InitTcpFastDataPacketHead(FuzzedDataProvider &provider, TcpFastDataPacketHead *head)
{
    if (head == nullptr) {
        COMM_LOGE(COMM_TEST, "PacketHead is nullptr!");
        return;
    }
    head->magicNumber = provider.ConsumeIntegral<uint32_t>();
    head->flags = provider.ConsumeIntegral<uint32_t>();
    head->dataLen = provider.ConsumeIntegral<uint32_t>();
    head->seq = provider.ConsumeIntegral<int32_t>();
}

static void InitTransFlowInfo(FuzzedDataProvider &provider, TransFlowInfo flowInfo)
{
    flowInfo.flowSize = provider.ConsumeIntegral<uint64_t>();
    flowInfo.sessionType = LONG_BACKGROUND_SESSION;
    flowInfo.flowQosType = LOW_LATENCY_50MS;
}

static bool InitAppInfoDataInfo(FuzzedDataProvider &provider, AppInfoData appInfoData)
{
    std::string deviceId = provider.ConsumeRandomLengthString(DEVICE_ID_SIZE_MAX);
    if (strcpy_s(appInfoData.deviceId, DEVICE_ID_SIZE_MAX, deviceId.c_str()) != EOK) {
        COMM_LOGE(COMM_TEST, "strcpy_s deviceId failed!");
        return false;
    }
    std::string pkgName = provider.ConsumeRandomLengthString(PKG_NAME_SIZE_MAX);
    if (strcpy_s(appInfoData.pkgName, PKG_NAME_SIZE_MAX, pkgName.c_str()) != EOK) {
        COMM_LOGE(COMM_TEST, "strcpy_s pkgName failed!");
        return false;
    }
    std::string sessionName = provider.ConsumeRandomLengthString(SESSION_NAME_SIZE_MAX);
    if (strcpy_s(appInfoData.sessionName, SESSION_NAME_SIZE_MAX, sessionName.c_str()) != EOK) {
        COMM_LOGE(COMM_TEST, "strcpy_s sessionName failed!");
        return false;
    }
    std::string authState = provider.ConsumeRandomLengthString(AUTH_STATE_SIZE_MAX);
    if (strcpy_s(appInfoData.authState, AUTH_STATE_SIZE_MAX, authState.c_str()) != EOK) {
        COMM_LOGE(COMM_TEST, "strcpy_s authState failed!");
        return false;
    }
    std::string addr = provider.ConsumeRandomLengthString(IP_LEN);
    if (strcpy_s(appInfoData.addr, IP_LEN, addr.c_str()) != EOK) {
        COMM_LOGE(COMM_TEST, "strcpy_s addr failed!");
        return false;
    }
    std::string mac = provider.ConsumeRandomLengthString(MAC_MAX_LEN);
    if (strcpy_s(appInfoData.mac, MAC_MAX_LEN, mac.c_str()) != EOK) {
        COMM_LOGE(COMM_TEST, "strcpy_s mac failed!");
        return false;
    }
    std::string accountId = provider.ConsumeRandomLengthString(ACCOUNT_UID_LEN_MAX);
    if (strcpy_s(appInfoData.accountId, ACCOUNT_UID_LEN_MAX, accountId.c_str()) != EOK) {
        COMM_LOGE(COMM_TEST, "strcpy_s accountId failed!");
        return false;
    }
    std::string callerAccountId = provider.ConsumeRandomLengthString(ACCOUNT_UID_LEN_MAX);
    if (strcpy_s(appInfoData.callerAccountId, ACCOUNT_UID_LEN_MAX, callerAccountId.c_str()) != EOK) {
        COMM_LOGE(COMM_TEST, "strcpy_s callerAccountId failed!");
        return false;
    }
    std::string calleeAccountId = provider.ConsumeRandomLengthString(ACCOUNT_UID_LEN_MAX);
    if (strcpy_s(appInfoData.calleeAccountId, ACCOUNT_UID_LEN_MAX, calleeAccountId.c_str()) != EOK) {
        COMM_LOGE(COMM_TEST, "strcpy_s calleeAccountId failed!");
        return false;
    }
    std::string extraData = provider.ConsumeRandomLengthString(EXTRA_DATA_MAX_LEN);
    if (strcpy_s(appInfoData.extraData, EXTRA_DATA_MAX_LEN, extraData.c_str()) != EOK) {
        COMM_LOGE(COMM_TEST, "strcpy_s extraData failed!");
        return false;
    }
    for (uint8_t i = 0; i < D2D_SHORT_ACCOUNT_HASH_LEN; i++) {
        appInfoData.shortAccountHash[i] = provider.ConsumeIntegral<uint8_t>();
    }
    for (uint8_t i = 0; i < D2D_SHORT_UDID_HASH_LEN; i++) {
        appInfoData.shortUdidHash[i] = provider.ConsumeIntegral<uint8_t>();
    }
    appInfoData.dataLen = provider.ConsumeIntegral<uint32_t>();
    appInfoData.businessFlag = provider.ConsumeIntegral<uint32_t>();
    appInfoData.devTypeId = provider.ConsumeIntegral<uint32_t>();
    appInfoData.dataConfig = provider.ConsumeIntegral<uint32_t>();
    appInfoData.uid = provider.ConsumeIntegral<int32_t>();
    appInfoData.pid = provider.ConsumeIntegral<int32_t>();
    appInfoData.port = provider.ConsumeIntegral<int32_t>();
    appInfoData.userId = provider.ConsumeIntegral<int32_t>();
    appInfoData.userKeyId = provider.ConsumeIntegral<int32_t>();
    appInfoData.tokenType = provider.ConsumeIntegral<int32_t>();
    appInfoData.sessionId = provider.ConsumeIntegral<int32_t>();
    appInfoData.channelId = provider.ConsumeIntegral<int64_t>();
    appInfoData.tokenId = provider.ConsumeIntegral<uint64_t>();
    appInfoData.apiVersion = API_V2;
    return true;
}

static bool InitAppInfo(FuzzedDataProvider &provider, AppInfo *appInfo)
{
    if (appInfo == nullptr) {
        COMM_LOGE(COMM_TEST, "appInfo is nullptr!");
        return false;
    }
    
    std::string groupId = provider.ConsumeRandomLengthString(GROUP_ID_SIZE_MAX);
    if (strcpy_s(appInfo->groupId, GROUP_ID_SIZE_MAX, groupId.c_str()) != EOK) {
        COMM_LOGE(COMM_TEST, "strcpy_s groupId failed!");
        return false;
    }
    std::string sessionKey = provider.ConsumeRandomLengthString(SESSION_KEY_LENGTH);
    if (strcpy_s(appInfo->sessionKey, SESSION_KEY_LENGTH, sessionKey.c_str()) != EOK) {
        COMM_LOGE(COMM_TEST, "strcpy_s sessionKey failed!");
        return false;
    }
    std::string sinkSessionKey = provider.ConsumeRandomLengthString(SESSION_KEY_LENGTH);
    if (strcpy_s(appInfo->sinkSessionKey, SESSION_KEY_LENGTH, sinkSessionKey.c_str()) != EOK) {
        COMM_LOGE(COMM_TEST, "strcpy_s sinkSessionKey failed!");
        return false;
    }
    std::string reqId = provider.ConsumeRandomLengthString(REQ_ID_SIZE_MAX);
    if (strcpy_s(appInfo->reqId, REQ_ID_SIZE_MAX, reqId.c_str()) != EOK) {
        COMM_LOGE(COMM_TEST, "strcpy_s reqId failed!");
        return false;
    }
    std::string peerNetWorkId = provider.ConsumeRandomLengthString(DEVICE_ID_SIZE_MAX);
    if (strcpy_s(appInfo->peerNetWorkId, DEVICE_ID_SIZE_MAX, peerNetWorkId.c_str()) != EOK) {
        COMM_LOGE(COMM_TEST, "strcpy_s peerNetWorkId failed!");
        return false;
    }
    std::string peerUdid = provider.ConsumeRandomLengthString(GROUP_ID_SIZE_MAX);
    if (strcpy_s(appInfo->peerUdid, GROUP_ID_SIZE_MAX, peerUdid.c_str()) != EOK) {
        COMM_LOGE(COMM_TEST, "strcpy_s peerUdid failed!");
        return false;
    }
    std::string peerVersion = provider.ConsumeRandomLengthString(DEVICE_VERSION_SIZE_MAX);
    if (strcpy_s(appInfo->peerVersion, DEVICE_VERSION_SIZE_MAX, peerVersion.c_str()) != EOK) {
        COMM_LOGE(COMM_TEST, "strcpy_s peerVersion failed!");
        return false;
    }
    std::string tokenName = provider.ConsumeRandomLengthString(PKG_NAME_SIZE_MAX);
    if (strcpy_s(appInfo->tokenName, PKG_NAME_SIZE_MAX, tokenName.c_str()) != EOK) {
        COMM_LOGE(COMM_TEST, "strcpy_s tokenName failed!");
        return false;
    }
    std::string extraAccessInfo = provider.ConsumeRandomLengthString(EXTRA_ACCESS_INFO_LEN_MAX);
    if (strcpy_s(appInfo->extraAccessInfo, EXTRA_ACCESS_INFO_LEN_MAX, extraAccessInfo.c_str()) != EOK) {
        COMM_LOGE(COMM_TEST, "strcpy_s extraAccessInfo failed!");
        return false;
    }
    std::string pagingNonce = provider.ConsumeRandomLengthString(PAGING_NONCE_LEN);
    if (strcpy_s(appInfo->pagingNonce, PAGING_NONCE_LEN, pagingNonce.c_str()) != EOK) {
        COMM_LOGE(COMM_TEST, "strcpy_s pagingNonce failed!");
        return false;
    }
    std::string pagingSessionkey = provider.ConsumeRandomLengthString(SHORT_SESSION_KEY_LENGTH);
    if (strcpy_s(appInfo->pagingSessionkey, SHORT_SESSION_KEY_LENGTH, pagingSessionkey.c_str()) != EOK) {
        COMM_LOGE(COMM_TEST, "strcpy_s pagingSessionkey failed!");
        return false;
    }
    appInfo->isClient = provider.ConsumeBool();
    appInfo->isD2D = provider.ConsumeBool();
    appInfo->isLowLatency = provider.ConsumeBool();
    appInfo->isFlashLight = provider.ConsumeBool();
    appInfo->fastTransDataSize = provider.ConsumeIntegral<uint16_t>();
    int32_t tmp32 = provider.ConsumeIntegral<int32_t>();
    appInfo->fd = (int)tmp32;
    appInfo->encrypt = provider.ConsumeIntegral<int32_t>();
    appInfo->algorithm = provider.ConsumeIntegral<int32_t>();
    appInfo->crc = provider.ConsumeIntegral<int32_t>();
    appInfo->fileProtocol = provider.ConsumeIntegral<int32_t>();
    appInfo->autoCloseTime = provider.ConsumeIntegral<int32_t>();
    appInfo->myHandleId = provider.ConsumeIntegral<int32_t>();
    appInfo->peerHandleId = provider.ConsumeIntegral<int32_t>();
    appInfo->transFlag = provider.ConsumeIntegral<int32_t>();
    appInfo->linkType = provider.ConsumeIntegral<int32_t>();
    appInfo->connectType = provider.ConsumeIntegral<int32_t>();
    appInfo->channelType = provider.ConsumeIntegral<int32_t>();
    appInfo->errorCode = provider.ConsumeIntegral<int32_t>();
    appInfo->waitOpenReplyCnt = provider.ConsumeIntegral<int32_t>();
    appInfo->callingTokenId = provider.ConsumeIntegral<uint64_t>();
    appInfo->channelCapability = provider.ConsumeIntegral<uint32_t>();
    uint8_t tmpU8 = provider.ConsumeIntegral<uint8_t>();
    appInfo->fastTransData = &tmpU8;
    appInfo->timeStart = provider.ConsumeIntegral<int64_t>();
    appInfo->connectedStart = provider.ConsumeIntegral<int64_t>();
    appInfo->authSeq = provider.ConsumeIntegral<int64_t>();
    appInfo->routeType = WIFI_STA;
    appInfo->streamType = RAW_STREAM;
    appInfo->businessType = BUSINESS_TYPE_STREAM;
    appInfo->udpConnType = UDP_CONN_TYPE_WIFI;
    appInfo->udpChannelOptType = TYPE_UDP_CHANNEL_OPEN;
    appInfo->blePriority = BLE_PRIORITY_BALANCED;
    appInfo->appType = APP_TYPE_NORMAL;
    appInfo->protocol = LNN_PROTOCOL_VTP;
    appInfo->fdProtocol = LNN_PROTOCOL_VTP;
    InitTransFlowInfo(provider, appInfo->flowInfo);
    if (!InitAppInfoDataInfo(provider, appInfo->myData)) {
        COMM_LOGE(COMM_TEST, "Init myData failed!");
        return false;
    }
    if (!InitAppInfoDataInfo(provider, appInfo->peerData)) {
        COMM_LOGE(COMM_TEST, "Init peerData failed!");
        return false;
    }
    return true;
}

void PackErrorTest(FuzzedDataProvider &provider)
{
    int32_t errCode = provider.ConsumeIntegral<int32_t>();
    std::string str = provider.ConsumeRandomLengthString();
    const char* errDesc = str.c_str();

    (void)PackError(errCode, errDesc);
    (void)PackError(errCode, nullptr);
}

void PackFirstDataTest(FuzzedDataProvider &provider)
{
    AppInfo appInfo;
    if (!InitAppInfo(provider, &appInfo)) {
        COMM_LOGE(COMM_TEST, "Init appInfo failed!");
        return;
    }
    cJSON *json = cJSON_CreateObject();
    if (json == nullptr) {
        COMM_LOGE(COMM_TEST, "Init cJSON failed!");
        return;
    }

    PackFirstData(&appInfo, json);
    cJSON_Delete(json);
}

void JsonObjectPackRequestExTest(FuzzedDataProvider &provider)
{
    AppInfo appInfo;
    if (!InitAppInfo(provider, &appInfo)) {
        COMM_LOGE(COMM_TEST, "Init appInfo failed!");
        return;
    }
    cJSON *json = cJSON_CreateObject();
    if (json == nullptr) {
        COMM_LOGE(COMM_TEST, "Init cJSON failed!");
        return;
    }
    std::string str = provider.ConsumeRandomLengthString();
    unsigned char *encodeSessionKey = (unsigned char *)str.c_str();

    JsonObjectPackRequestEx(&appInfo, json, encodeSessionKey);
    cJSON_Delete(json);
}

void PackRequestTest(FuzzedDataProvider &provider)
{
    AppInfo appInfo;
    if (!InitAppInfo(provider, &appInfo)) {
        COMM_LOGE(COMM_TEST, "Init appInfo failed!");
        return;
    }
    int64_t requestId = provider.ConsumeIntegral<int64_t>();

    (void)PackRequest(&appInfo, requestId);
}

void AddItemsToJsonObjectTest(FuzzedDataProvider &provider)
{
    AppInfo appInfo;
    if (!InitAppInfo(provider, &appInfo)) {
        COMM_LOGE(COMM_TEST, "Init appInfo failed!");
        return;
    }
    cJSON *json = cJSON_CreateObject();
    if (json == nullptr) {
        COMM_LOGE(COMM_TEST, "Init cJSON failed!");
        return;
    }

    AddItemsToJsonObject(&appInfo, json);
    cJSON_Delete(json);
}

void PackReplyTest(FuzzedDataProvider &provider)
{
    AppInfo appInfo;
    if (!InitAppInfo(provider, &appInfo)) {
        COMM_LOGE(COMM_TEST, "Init appInfo failed!");
        return;
    }

    (void)PackReply(&appInfo);
}

void TransTdcEncryptTest(FuzzedDataProvider &provider)
{
    uint32_t inLen = provider.ConsumeIntegral<uint32_t>();
    uint32_t outLen = provider.ConsumeIntegral<uint32_t>();

    std::string str = provider.ConsumeRandomLengthString();
    const char *sessionKey = str.c_str();
    str = provider.ConsumeRandomLengthString();
    const char *in = str.c_str();
    str = provider.ConsumeRandomLengthString();
    char *out = (char *)str.c_str();

    TransTdcEncrypt(sessionKey, in, inLen, out, &outLen);
}

void PackTcpFastDataPacketHeadTest(FuzzedDataProvider &provider)
{
    TcpFastDataPacketHead head;
    InitTcpFastDataPacketHead(provider, &head);
    PackTcpFastDataPacketHead(&head);
}

void TransTdcPackFastDataTest(FuzzedDataProvider &provider)
{
    AppInfo appInfo;
    if (!InitAppInfo(provider, &appInfo)) {
        COMM_LOGE(COMM_TEST, "Init appInfo failed!");
        return;
    }
    uint32_t outLen = provider.ConsumeIntegral<uint32_t>();

    (void)TransTdcPackFastData(&appInfo, &outLen);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(FuzzedDataProvider &provider)
{
    /* Run your code on data */
    OHOS::PackErrorTest(provider);
    OHOS::PackFirstDataTest(provider);
    OHOS::JsonObjectPackRequestExTest(provider);
    OHOS::PackRequestTest(provider);
    OHOS::AddItemsToJsonObjectTest(provider);
    OHOS::PackReplyTest(provider);
    OHOS::TransTdcEncryptTest(provider);
    OHOS::PackTcpFastDataPacketHeadTest(provider);
    OHOS::TransTdcPackFastDataTest(provider);

    return 0;
}
