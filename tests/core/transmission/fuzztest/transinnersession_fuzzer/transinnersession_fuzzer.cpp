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

#include "transinnersession_fuzzer.h"

#include <cstring>
#include <fuzzer/FuzzedDataProvider.h>
#include <securec.h>
#include <vector>

#include "fuzz_data_generator.h"
#include "trans_inner_session_struct.h"
#include "trans_inner_session.c"

#define PKG_NAME_SIZE_MAX_LEN 65
#define SESSION_NAME_MAX_LEN 256
#define TRANS_TEST_DATA "test auth message data"
#define TRANS_TEST_DATA_LEN 256

namespace OHOS {
static const char *PKG_NAME = "dms";


class TransInnerSession {
public:
    TransInnerSession()
    {
        isInited_ = false;
        (void)TransProxyManagerInit(TransServerGetChannelCb());
        isInited_ = true;
    }

    ~TransInnerSession()
    {
        isInited_ = false;
        TransProxyManagerDeinit();
    }

    bool IsInited(void)
    {
        return isInited_;
    }

private:
    volatile bool isInited_;
};

static int32_t OnSessionOpened(int32_t channelId, int32_t channelType, char *peerNetworkId, int32_t result)
{
    (void)channelType;
    (void)peerNetworkId;
    (void)result;
    TRANS_LOGI(TRANS_TEST, "on session opened, channelId=%{public}d", channelId);
    return SOFTBUS_OK;
}

static void OnSessionClosed(int32_t channelId)
{
    TRANS_LOGI(TRANS_TEST, "on session close, channelId=%{public}d", channelId);
}

static void OnBytesReceived(int32_t channelId, const void *data, uint32_t dataLen)
{
    (void)data;
    (void)dataLen;
    TRANS_LOGI(TRANS_TEST, "data recv, channelId=%{public}d", channelId);
}

static void OnLinkDown(const char *networkId)
{
    TRANS_LOGI(TRANS_TEST, "link down, networkId=%{public}s", networkId);
}

static ISessionListenerInner g_innerSessionListener = {
    .OnSessionOpened = OnSessionOpened,
    .OnSessionClosed = OnSessionClosed,
    .OnBytesReceived = OnBytesReceived,
    .OnLinkDown = OnLinkDown,
};

SessionConn *TestSetSessionConn()
{
    SessionConn *conn = (SessionConn*)SoftBusCalloc(sizeof(SessionConn));
    if (conn == nullptr) {
        return nullptr;
    }

    (void)memset_s(conn, sizeof(SessionConn), 0, sizeof(SessionConn));
    conn->serverSide = true;
    conn->channelId = 1;
    conn->status = TCP_DIRECT_CHANNEL_STATUS_INIT;
    conn->timeout = 0;
    conn->req = -1;
    conn->authHandle.authId = 1;
    conn->requestId = 0;
    conn->listenMod = DIRECT_CHANNEL_SERVER_WIFI;
    conn->appInfo.myData.pid = 1;
    (void)memcpy_s(conn->appInfo.myData.pkgName, PKG_NAME_SIZE_MAX_LEN, PKG_NAME, (strlen(PKG_NAME) + 1));
    return conn;
}

void TransCreateSessionServerInnerTest(FuzzedDataProvider &provider)
{
    std::string pkgName = provider.ConsumeRandomLengthString(PKG_NAME_SIZE_MAX_LEN);
    char tmpPkaName[PKG_NAME_SIZE_MAX_LEN] = { 0 };
    if (strcpy_s(tmpPkaName, PKG_NAME_SIZE_MAX_LEN, pkgName.c_str()) != EOK) {
        return;
    }
    const char *sessionName = "ohos.trans_inner_session_test";
    (void)TransCreateSessionServerInner(sessionName, tmpPkaName, &g_innerSessionListener);
}

void InnerMessageHandlerTest(FuzzedDataProvider &provider)
{
    int32_t sessionId = provider.ConsumeIntegral<int32_t>();
    (void)InnerMessageHandler(sessionId, TRANS_TEST_DATA, static_cast<uint32_t>(strlen(TRANS_TEST_DATA)));
}

void GetIsClientInfoByIdTest(FuzzedDataProvider &provider)
{
    int32_t channelType = CHANNEL_TYPE_TCP_DIRECT;
    SessionConn *conn = TestSetSessionConn();
    (void)CreatSessionConnList();
    TransTdcAddSessionConn(conn);
    bool value = provider.ConsumeBool();
    (void)GetIsClientInfoById(1, channelType, &value);
    channelType = CHANNEL_TYPE_PROXY;
    (void)GetIsClientInfoById(1, channelType, &value);
    TransDelSessionConnById(conn->channelId);
}

void OnSessionOpenedInnerTest(FuzzedDataProvider &provider)
{
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    int32_t result = 0;
    std::string peerNetworkId = provider.ConsumeRandomLengthString(NETWORK_ID_BUF_LEN);
    char tmpPeerNetworkId[NETWORK_ID_BUF_LEN] = { 0 };
    if (strcpy_s(tmpPeerNetworkId, NETWORK_ID_BUF_LEN, peerNetworkId.c_str()) != EOK) {
        return;
    }
    (void)OnSessionOpenedInner(channelId, tmpPeerNetworkId, result);
}

void TransOnSessionOpenedInnerTest(FuzzedDataProvider &provider)
{
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    int32_t result = 0;
    std::string peerNetworkId = provider.ConsumeRandomLengthString(NETWORK_ID_BUF_LEN);
    char tmpPeerNetworkId[NETWORK_ID_BUF_LEN] = { 0 };
    if (strcpy_s(tmpPeerNetworkId, NETWORK_ID_BUF_LEN, peerNetworkId.c_str()) != EOK) {
        return;
    }
    (void)TransOnSessionOpenedInner(channelId, -1, tmpPeerNetworkId, result);
    int32_t res = provider.ConsumeIntegral<int32_t>();
    (void)TransOnSessionOpenedInner(channelId, CHANNEL_TYPE_PROXY, tmpPeerNetworkId, res);
}

void TransOnSessionClosedInnerTest(FuzzedDataProvider &provider)
{
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    TransOnSessionClosedInner(channelId);
}

void TransOnBytesReceivedInnerTest(FuzzedDataProvider &provider)
{
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    (void)InnerMessageHandler(channelId, TRANS_TEST_DATA, static_cast<uint32_t>(strlen(TRANS_TEST_DATA)));
}

void TransOnSetChannelInfoByReqIdTest(FuzzedDataProvider &provider)
{
    uint32_t reqId = provider.ConsumeIntegral<uint32_t>();
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    int32_t channelType = provider.ConsumeIntegral<int32_t>();
    (void)TransOnSetChannelInfoByReqId(reqId, channelId, channelType);
}

void TransOnLinkDownInnerTest(FuzzedDataProvider &provider)
{
    std::string networkId = provider.ConsumeRandomLengthString(NETWORK_ID_BUF_LEN);
    char tmpNetworkId[NETWORK_ID_BUF_LEN] = { 0 };
    if (strcpy_s(tmpNetworkId, NETWORK_ID_BUF_LEN, networkId.c_str()) != EOK) {
        return;
    }
    (void)TransOnLinkDownInner(tmpNetworkId);
}

void TransOpenSessionInnerTest(FuzzedDataProvider &provider)
{
    std::string peerNetworkId = provider.ConsumeRandomLengthString(NETWORK_ID_BUF_LEN);
    std::string sessionName = provider.ConsumeRandomLengthString(SESSION_NAME_MAX_LEN);
    uint32_t reqId = provider.ConsumeIntegral<uint32_t>();
    char tmpSessionName[SESSION_NAME_MAX_LEN] = { 0 };
    if (strcpy_s(tmpSessionName, SESSION_NAME_MAX_LEN, sessionName.c_str()) != EOK) {
        return;
    }
    char tmpPeerNetworkId[NETWORK_ID_BUF_LEN] = { 0 };
    if (strcpy_s(tmpPeerNetworkId, NETWORK_ID_BUF_LEN, peerNetworkId.c_str()) != EOK) {
        return;
    }
    (void)TransOpenSessionInner(tmpPeerNetworkId, tmpSessionName, reqId);
}

void TransSendDataInnerTest(FuzzedDataProvider &provider)
{
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    std::string data = provider.ConsumeRandomLengthString(TRANS_TEST_DATA_LEN);
    char tmpData[TRANS_TEST_DATA_LEN] = { 0 };
    if (strcpy_s(tmpData, TRANS_TEST_DATA_LEN, data.c_str()) != EOK) {
        return;
    }
    (void)TransSendDataInner(channelId, tmpData, static_cast<uint32_t>(strlen(tmpData)));
}

void TransCloseSessionInnerTest(FuzzedDataProvider &provider)
{
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    (void)TransCloseSessionInner(channelId);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static OHOS::TransInnerSession testEvent;
    if (!testEvent.IsInited()) {
        return 0;
    }

    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::InnerMessageHandlerTest(provider);
    OHOS::GetIsClientInfoByIdTest(provider);
    OHOS::OnSessionOpenedInnerTest(provider);
    OHOS::TransOnSessionOpenedInnerTest(provider);
    OHOS::TransCreateSessionServerInnerTest(provider);
    OHOS::TransOnSessionClosedInnerTest(provider);
    OHOS::TransOnBytesReceivedInnerTest(provider);
    OHOS::TransOnSetChannelInfoByReqIdTest(provider);
    OHOS::TransOnLinkDownInnerTest(provider);
    OHOS::TransOpenSessionInnerTest(provider);
    OHOS::TransSendDataInnerTest(provider);
    OHOS::TransCloseSessionInnerTest(provider);
    return 0;
}
