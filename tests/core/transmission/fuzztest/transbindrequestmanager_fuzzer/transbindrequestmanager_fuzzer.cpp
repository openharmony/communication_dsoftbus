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

#include "transbindrequestmanager_fuzzer.h"

#include <cstring>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>
#include <securec.h>
#include <string>
#include <vector>

#include "fuzz_data_generator.h"
#include "trans_bind_request_manager.c"
#include "trans_bind_request_manager.h"

namespace OHOS {
class TransBindRequestManager {
public:
    TransBindRequestManager()
    {
        isInited_ = false;
        (void)LooperInit();
        isInited_ = true;
    }

    ~TransBindRequestManager()
    {
        isInited_ = false;
        LooperDeinit();
    }

    bool IsInited(void)
    {
        return isInited_;
    }

private:
    volatile bool isInited_;
};

static void FillBindRequestParam(FuzzedDataProvider &provider, BindRequestParam *param)
{
    if (param == nullptr) {
        return;
    }
    std::string socketName = provider.ConsumeRandomLengthString(SESSION_NAME_SIZE_MAX);
    std::string peerSocketName = provider.ConsumeRandomLengthString(SESSION_NAME_SIZE_MAX);
    std::string netWorkId = provider.ConsumeRandomLengthString(NETWORK_ID_BUF_LEN);
    if (strcpy_s(param->mySocketName, SESSION_NAME_SIZE_MAX, socketName.c_str()) != EOK ||
        strcpy_s(param->peerSocketName, SESSION_NAME_SIZE_MAX, peerSocketName.c_str()) != EOK ||
        strcpy_s(param->peerNetworkId, NETWORK_ID_BUF_LEN, netWorkId.c_str()) != EOK) {
        return;
    }
}

void GetBindRequestManagerByPeerTest(FuzzedDataProvider &provider)
{
    BindRequestParam param;
    (void)memset_s(&param, sizeof(BindRequestParam), 0, sizeof(BindRequestParam));
    std::string socketName = provider.ConsumeRandomLengthString(SESSION_NAME_SIZE_MAX);
    std::string peerSocketName = provider.ConsumeRandomLengthString(SESSION_NAME_SIZE_MAX);
    std::string netWorkId = provider.ConsumeRandomLengthString(NETWORK_ID_BUF_LEN);
    if (strcpy_s(param.mySocketName, SESSION_NAME_SIZE_MAX, socketName.c_str()) != EOK ||
        strcpy_s(param.peerSocketName, SESSION_NAME_SIZE_MAX, peerSocketName.c_str()) != EOK ||
        strcpy_s(param.peerNetworkId, NETWORK_ID_BUF_LEN, netWorkId.c_str()) != EOK) {
        return;
    }
    (void)TransBindRequestManagerInit();
    (void)GetBindRequestManagerByPeer(&param);
    (void)CreateBindRequestManager(param.mySocketName, param.peerSocketName, param.peerNetworkId);
    (void)GetBindRequestManagerByPeer(&param);
    (void)memset_s(param.peerNetworkId, NETWORK_ID_BUF_LEN, 0, NETWORK_ID_BUF_LEN);
    (void)GetBindRequestManagerByPeer(&param);
    (void)memset_s(param.peerSocketName, SESSION_NAME_SIZE_MAX, 0, SESSION_NAME_SIZE_MAX);
    (void)GetBindRequestManagerByPeer(&param);
    TransBindRequestManagerDeinit();
}

void GenerateParamTest(FuzzedDataProvider &provider)
{
    BindRequestParam param;
    (void)memset_s(&param, sizeof(BindRequestParam), 0, sizeof(BindRequestParam));
    std::string mySocketName = provider.ConsumeRandomLengthString(SESSION_NAME_SIZE_MAX);
    std::string peerSocketName = provider.ConsumeRandomLengthString(SESSION_NAME_SIZE_MAX);
    std::string netWorkId = provider.ConsumeRandomLengthString(NETWORK_ID_BUF_LEN);
    (void)GenerateParam(mySocketName.c_str(), peerSocketName.c_str(), netWorkId.c_str(), &param);
}

void CreateBindRequestManagerTest(FuzzedDataProvider &provider)
{
    std::string mySocketName = provider.ConsumeRandomLengthString(SESSION_NAME_SIZE_MAX);
    std::string peerSocketName = provider.ConsumeRandomLengthString(SESSION_NAME_SIZE_MAX);
    std::string netWorkId = provider.ConsumeRandomLengthString(NETWORK_ID_BUF_LEN);
    (void)TransBindRequestManagerInit();
    (void)CreateBindRequestManager(mySocketName.c_str(), peerSocketName.c_str(), netWorkId.c_str());
    TransBindRequestManagerDeinit();
}

void TransAddTimestampToListTest(FuzzedDataProvider &provider)
{
    BindRequestParam param;
    (void)memset_s(&param, sizeof(BindRequestParam), 0, sizeof(BindRequestParam));
    FillBindRequestParam(provider, &param);
    uint64_t timestamp = provider.ConsumeIntegral<uint64_t>();
    (void)TransAddTimestampToList(nullptr, param.peerSocketName, param.peerNetworkId, timestamp);
    (void)TransAddTimestampToList(param.mySocketName, nullptr, param.peerNetworkId, timestamp);
    (void)TransAddTimestampToList(param.mySocketName, param.peerSocketName, nullptr, timestamp);
    (void)TransAddTimestampToList(param.mySocketName, param.peerSocketName, param.peerNetworkId, timestamp);
    (void)TransBindRequestManagerInit();
    (void)TransAddTimestampToList(param.mySocketName, param.peerSocketName, param.peerNetworkId, timestamp);
    TransBindRequestManagerDeinit();
}

void TransDelTimestampFormListTest(FuzzedDataProvider &provider)
{
    BindRequestParam param;
    (void)memset_s(&param, sizeof(BindRequestParam), 0, sizeof(BindRequestParam));
    FillBindRequestParam(provider, &param);
    TransDelTimestampFormList(&param, 0);

    (void)TransBindRequestManagerInit();
    TransDelTimestampFormList(&param, 0);
    uint64_t timestamp = provider.ConsumeIntegral<uint64_t>();
    (void)CreateBindRequestManager(param.mySocketName, param.peerSocketName, param.peerNetworkId);
    TransDelTimestampFormList(&param, 0);

    TransDelTimestampFormList(&param, timestamp);
    TransBindRequestManagerDeinit();
}

void GetDeniedFlagByPeerTest(FuzzedDataProvider &provider)
{
    (void)GetDeniedFlagByPeer(nullptr, nullptr, nullptr);
    std::string mySocketName = provider.ConsumeRandomLengthString(SESSION_NAME_SIZE_MAX);
    (void)GetDeniedFlagByPeer(mySocketName.c_str(), nullptr, nullptr);
    std::string peerSocketName = provider.ConsumeRandomLengthString(SESSION_NAME_SIZE_MAX);
    (void)GetDeniedFlagByPeer(mySocketName.c_str(), peerSocketName.c_str(), nullptr);
    std::string netWorkId = provider.ConsumeRandomLengthString(NETWORK_ID_BUF_LEN);
    (void)GetDeniedFlagByPeer(mySocketName.c_str(), peerSocketName.c_str(), netWorkId.c_str());

    (void)TransBindRequestManagerInit();
    (void)GetDeniedFlagByPeer(mySocketName.c_str(), peerSocketName.c_str(), netWorkId.c_str());
    (void)CreateBindRequestManager(mySocketName.c_str(), peerSocketName.c_str(), netWorkId.c_str());
    (void)GetDeniedFlagByPeer(mySocketName.c_str(), peerSocketName.c_str(), netWorkId.c_str());
    TransBindRequestManagerDeinit();
}

void TransResetBindDeniedFlagTest(FuzzedDataProvider &provider)
{
    BindRequestParam param;
    (void)memset_s(&param, sizeof(BindRequestParam), 0, sizeof(BindRequestParam));
    FillBindRequestParam(provider, &param);
    (void)TransResetBindDeniedFlag(&param);
    (void)TransBindRequestManagerInit();
    (void)TransBindRequestManagerInit();
    (void)TransResetBindDeniedFlag(&param);
    (void)CreateBindRequestManager(param.mySocketName, param.peerSocketName, param.peerNetworkId);
    (void)TransResetBindDeniedFlag(&param);
    TransBindRequestManagerDeinit();
    TransBindRequestManagerDeinit();
}

void FreeBindRequestMessageTest(FuzzedDataProvider &provider)
{
    FreeBindRequestMessage(nullptr);
    SoftBusMessage *msg = (SoftBusMessage *)SoftBusMalloc(sizeof(SoftBusMessage));
    if (msg == nullptr) {
        return;
    }
    (void)memset_s(msg, sizeof(SoftBusMessage), 0, sizeof(SoftBusMessage));
    uint8_t value = provider.ConsumeIntegral<uint8_t>();
    msg->obj = calloc(1, sizeof(value));
    (void)memset_s(msg->obj, sizeof(value), value, sizeof(value));
    FreeBindRequestMessage(msg);
}

void TransBindRequestLoopMsgHandlerTest(FuzzedDataProvider &provider)
{
    SoftBusMessage *msg = (SoftBusMessage *)SoftBusMalloc(sizeof(SoftBusMessage));
    if (msg == nullptr) {
        return;
    }
    (void)memset_s(msg, sizeof(SoftBusMessage), 0, sizeof(SoftBusMessage));
    TransBindRequestLoopMsgHandler(msg);
    msg->what = LOOP_DELETE_TIMESTAMP;
    TransBindRequestLoopMsgHandler(msg);
    msg->what = LOOP_RESET_BIND_DENIED_FLAG;
    TransBindRequestLoopMsgHandler(msg);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static OHOS::TransBindRequestManager testEvent;
    if (!testEvent.IsInited()) {
        return 0;
    }

    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::GetBindRequestManagerByPeerTest(provider);
    OHOS::GenerateParamTest(provider);
    OHOS::CreateBindRequestManagerTest(provider);
    OHOS::TransAddTimestampToListTest(provider);
    OHOS::TransDelTimestampFormListTest(provider);
    OHOS::GetDeniedFlagByPeerTest(provider);
    OHOS::TransResetBindDeniedFlagTest(provider);
    OHOS::FreeBindRequestMessageTest(provider);
    OHOS::TransBindRequestLoopMsgHandlerTest(provider);

    return 0;
}
