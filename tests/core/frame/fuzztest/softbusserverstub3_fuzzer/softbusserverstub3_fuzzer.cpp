/*
 * Copyright (c) 2025-2026 Huawei Device Co., Ltd.
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

#include "softbusserverstub3_fuzzer.h"
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <fuzzer/FuzzedDataProvider.h>
#include "fuzz_data_generator.h"
#include "iservice_registry.h"
#include "message_option.h"
#include "message_parcel.h"
#include "softbus_access_token_test.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"
#include "legacy/softbus_hisysevt_transreporter.h"
#include "softbus_server_frame.h"
#include "system_ability_definition.h"
#include "securec.h"
#define private public
#include "softbus_def.h"
#include "softbus_server_stub.h"
#include "softbus_server.h"

#define TEST_BR_MAC_LEN     18
#define TEST_UUID_LEN       38
#define TEST_MAX_LEN        1025

namespace OHOS {
class SoftBusServerStub3FuzzTest {
public:
    SoftBusServerStub3FuzzTest()
    {
        isInited_ = true;
    }
 
    ~SoftBusServerStub3FuzzTest()
    {
        isInited_ = false;
    }
 
    bool IsInited(void)
    {
        return isInited_;
    }
 
private:
    volatile bool isInited_;
};

void TriggerRangeForMsdpInnerTest(FuzzedDataProvider &provider)
{
    MessageParcel data;
    MessageParcel reply;
    (void)memset_s(&data, sizeof(MessageParcel), 0, sizeof(MessageParcel));
    (void)memset_s(&reply, sizeof(MessageParcel), 0, sizeof(MessageParcel));
    std::string pkgName = provider.ConsumeRandomLengthString(PKG_NAME_SIZE_MAX);
    data.WriteCString(pkgName.c_str());
    sptr<OHOS::SoftBusServerStub> SoftBusServer = new OHOS::SoftBusServer(SOFTBUS_SERVER_SA_ID, true);
    if (SoftBusServer == nullptr) {
        return;
    }
    SoftBusServer->TriggerRangeForMsdpInner(data, reply);
}

void StopRangeForMsdpInnerTest(FuzzedDataProvider &provider)
{
    MessageParcel data;
    MessageParcel reply;
    (void)memset_s(&data, sizeof(MessageParcel), 0, sizeof(MessageParcel));
    (void)memset_s(&reply, sizeof(MessageParcel), 0, sizeof(MessageParcel));
    std::string pkgName = provider.ConsumeRandomLengthString(PKG_NAME_SIZE_MAX);
    data.WriteCString(pkgName.c_str());
    sptr<OHOS::SoftBusServerStub> SoftBusServer = new OHOS::SoftBusServer(SOFTBUS_SERVER_SA_ID, true);
    if (SoftBusServer == nullptr) {
        return;
    }
    SoftBusServer->StopRangeForMsdpInner(data, reply);
}

void RegRangeCbForMsdpInnerTest(FuzzedDataProvider &provider)
{
    MessageParcel data;
    MessageParcel reply;
    (void)memset_s(&data, sizeof(MessageParcel), 0, sizeof(MessageParcel));
    (void)memset_s(&reply, sizeof(MessageParcel), 0, sizeof(MessageParcel));
    std::string pkgName = provider.ConsumeRandomLengthString(PKG_NAME_SIZE_MAX);
    data.WriteCString(pkgName.c_str());
    sptr<OHOS::SoftBusServerStub> SoftBusServer = new OHOS::SoftBusServer(SOFTBUS_SERVER_SA_ID, true);
    if (SoftBusServer == nullptr) {
        return;
    }
    SoftBusServer->RegRangeCbForMsdpInner(data, reply);
    SoftBusServer->UnregRangeCbForMsdpInner(data, reply);
}

void SyncTrustedRelationShipInnerTest(FuzzedDataProvider &provider)
{
    MessageParcel data;
    MessageParcel reply;
    (void)memset_s(&data, sizeof(MessageParcel), 0, sizeof(MessageParcel));
    (void)memset_s(&reply, sizeof(MessageParcel), 0, sizeof(MessageParcel));
    std::string pkgName = provider.ConsumeRandomLengthString(PKG_NAME_SIZE_MAX);
    data.WriteCString(pkgName.c_str());
    sptr<OHOS::SoftBusServerStub> SoftBusServer = new OHOS::SoftBusServer(SOFTBUS_SERVER_SA_ID, true);
    if (SoftBusServer == nullptr) {
        return;
    }
    SoftBusServer->SyncTrustedRelationShipInner(data, reply);
}

void ProcessInnerEventInnerTest(FuzzedDataProvider &provider)
{
    MessageParcel data;
    MessageParcel reply;
    (void)memset_s(&data, sizeof(MessageParcel), 0, sizeof(MessageParcel));
    (void)memset_s(&reply, sizeof(MessageParcel), 0, sizeof(MessageParcel));
    std::string pkgName = provider.ConsumeRandomLengthString(PKG_NAME_SIZE_MAX);
    data.WriteCString(pkgName.c_str());
    sptr<OHOS::SoftBusServerStub> SoftBusServer = new OHOS::SoftBusServer(SOFTBUS_SERVER_SA_ID, true);
    if (SoftBusServer == nullptr) {
        return;
    }
    SoftBusServer->ProcessInnerEventInner(data, reply);
}

void CreateServerInnerTest(FuzzedDataProvider &provider)
{
    MessageParcel data;
    MessageParcel reply;
    (void)memset_s(&data, sizeof(MessageParcel), 0, sizeof(MessageParcel));
    (void)memset_s(&reply, sizeof(MessageParcel), 0, sizeof(MessageParcel));
    sptr<OHOS::SoftBusServerStub> SoftBusServer = new OHOS::SoftBusServer(SOFTBUS_SERVER_SA_ID, true);
    if (SoftBusServer == nullptr) {
        return;
    }
    SoftBusServer->CreateServerInner(data, reply);
    SoftBusServer->ConnectInner(data, reply);
    SoftBusServer->SendInner(data, reply);
    SoftBusServer->DisconnectInner(data, reply);
    SoftBusServer->RemoveServerInner(data, reply);
    std::string pkgName = provider.ConsumeRandomLengthString(PKG_NAME_SIZE_MAX + 1);
    data.WriteCString(pkgName.c_str());
    SoftBusServer->CreateServerInner(data, reply);
    SoftBusServer->ConnectInner(data, reply);
    SoftBusServer->RemoveServerInner(data, reply);
    pkgName = "ohos.distributedschedule.dms";
    data.WriteCString(pkgName.c_str());
    SoftBusServer->CreateServerInner(data, reply);
    SoftBusServer->ConnectInner(data, reply);
    SoftBusServer->RemoveServerInner(data, reply);
    std::string name = provider.ConsumeRandomLengthString(SESSION_NAME_SIZE_MAX + 1);
    data.WriteCString(name.c_str());
    SoftBusServer->CreateServerInner(data, reply);
    SoftBusServer->ConnectInner(data, reply);
    SoftBusServer->RemoveServerInner(data, reply);
    name = provider.ConsumeRandomLengthString(SESSION_NAME_SIZE_MAX);
    uint32_t handle = provider.ConsumeIntegral<uint32_t>();
    data.WriteCString(name.c_str());
    data.WriteUint32(handle);
    SoftBusServer->CreateServerInner(data, reply);
    SoftBusServer->ConnectInner(data, reply);
    SoftBusServer->SendInner(data, reply);
    uint32_t len = GENERAL_SEND_DATA_MAX_LEN + 1;
    data.WriteUint32(len);
    SoftBusServer->SendInner(data, reply);
    len = provider.ConsumeIntegral<uint32_t>();
    data.WriteUint32(len);
    SoftBusServer->SendInner(data, reply);
    SoftBusServer->DisconnectInner(data, reply);
    SoftBusServer->RemoveServerInner(data, reply);
}

void GetPeerDeviceIdInnerTest(FuzzedDataProvider &provider)
{
    MessageParcel data;
    MessageParcel reply;
    (void)memset_s(&data, sizeof(MessageParcel), 0, sizeof(MessageParcel));
    (void)memset_s(&reply, sizeof(MessageParcel), 0, sizeof(MessageParcel));
    sptr<OHOS::SoftBusServerStub> SoftBusServer = new OHOS::SoftBusServer(SOFTBUS_SERVER_SA_ID, true);
    if (SoftBusServer == nullptr) {
        return;
    }
    SoftBusServer->GetPeerDeviceIdInner(data, reply);
    std::string pkgName = "ohos.distributedschedule.dms";
    data.WriteCString(pkgName.c_str());
    std::string name = provider.ConsumeRandomLengthString(SESSION_NAME_SIZE_MAX);
    uint32_t handle = provider.ConsumeIntegral<uint32_t>();
    data.WriteCString(name.c_str());
    data.WriteUint32(handle);
    SoftBusServer->CreateServerInner(data, reply);
    SoftBusServer->ConnectInner(data, reply);
    SoftBusServer->GetPeerDeviceIdInner(data, reply);
    uint32_t len = BT_MAC_LEN + 1;
    data.WriteUint32(len);
    len = provider.ConsumeIntegral<uint32_t>();
    data.WriteUint32(len);
    SoftBusServer->GetPeerDeviceIdInner(data, reply);
    SoftBusServer->DisconnectInner(data, reply);
    SoftBusServer->RemoveServerInner(data, reply);
}

void SoftbusRegisterBrProxyServiceInnerTest(FuzzedDataProvider &provider)
{
    MessageParcel data;
    MessageParcel reply;
    (void)memset_s(&data, sizeof(MessageParcel), 0, sizeof(MessageParcel));
    (void)memset_s(&reply, sizeof(MessageParcel), 0, sizeof(MessageParcel));
    sptr<OHOS::SoftBusServerStub> SoftBusServer = new OHOS::SoftBusServer(SOFTBUS_SERVER_SA_ID, true);
    if (SoftBusServer == nullptr) {
        return;
    }
    std::string pkgName = provider.ConsumeRandomLengthString(PKG_NAME_SIZE_MAX);
    data.WriteCString(pkgName.c_str());
    SoftBusServer->SoftbusRegisterBrProxyServiceInner(data, reply);
}

void OpenBrProxyInnerTest(FuzzedDataProvider &provider)
{
    MessageParcel data;
    MessageParcel reply;
    (void)memset_s(&data, sizeof(MessageParcel), 0, sizeof(MessageParcel));
    (void)memset_s(&reply, sizeof(MessageParcel), 0, sizeof(MessageParcel));
    sptr<OHOS::SoftBusServerStub> SoftBusServer = new OHOS::SoftBusServer(SOFTBUS_SERVER_SA_ID, true);
    if (SoftBusServer == nullptr) {
        return;
    }
    SoftBusServer->OpenBrProxyInner(data, reply);
    std::string brMac = provider.ConsumeRandomLengthString(TEST_BR_MAC_LEN);
    data.WriteCString(brMac.c_str());
    SoftBusServer->OpenBrProxyInner(data, reply);
    std::string uuid = provider.ConsumeRandomLengthString(TEST_UUID_LEN);
    data.WriteCString(uuid.c_str());
    SoftBusServer->OpenBrProxyInner(data, reply);
}

void SendBrProxyDataInnerTest(FuzzedDataProvider &provider)
{
    MessageParcel data;
    MessageParcel reply;
    (void)memset_s(&data, sizeof(MessageParcel), 0, sizeof(MessageParcel));
    (void)memset_s(&reply, sizeof(MessageParcel), 0, sizeof(MessageParcel));
    sptr<OHOS::SoftBusServerStub> SoftBusServer = new OHOS::SoftBusServer(SOFTBUS_SERVER_SA_ID, true);
    if (SoftBusServer == nullptr) {
        return;
    }
    SoftBusServer->SendBrProxyDataInner(data, reply);
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    data.WriteInt32(channelId);
    SoftBusServer->SendBrProxyDataInner(data, reply);
    int32_t dataLen = provider.ConsumeIntegral<uint32_t>();
    data.WriteUint32(dataLen);
    SoftBusServer->SendBrProxyDataInner(data, reply);
}

void SetBrProxyListenerStateInnerTest(FuzzedDataProvider &provider)
{
    MessageParcel data;
    MessageParcel reply;
    (void)memset_s(&data, sizeof(MessageParcel), 0, sizeof(MessageParcel));
    (void)memset_s(&reply, sizeof(MessageParcel), 0, sizeof(MessageParcel));
    sptr<OHOS::SoftBusServerStub> SoftBusServer = new OHOS::SoftBusServer(SOFTBUS_SERVER_SA_ID, true);
    if (SoftBusServer == nullptr) {
        return;
    }
    SoftBusServer->SetBrProxyListenerStateInner(data, reply);
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    data.WriteInt32(channelId);
    SoftBusServer->SetBrProxyListenerStateInner(data, reply);
    int32_t type = provider.ConsumeIntegral<int32_t>();
    data.WriteInt32(type);
    SoftBusServer->SetBrProxyListenerStateInner(data, reply);
    bool cbEnabled = false;
    data.WriteBool(cbEnabled);
    SoftBusServer->SetBrProxyListenerStateInner(data, reply);
}

void GetBrProxyChannelStateInnerTest(FuzzedDataProvider &provider)
{
    MessageParcel data;
    MessageParcel reply;
    (void)memset_s(&data, sizeof(MessageParcel), 0, sizeof(MessageParcel));
    (void)memset_s(&reply, sizeof(MessageParcel), 0, sizeof(MessageParcel));
    sptr<OHOS::SoftBusServerStub> SoftBusServer = new OHOS::SoftBusServer(SOFTBUS_SERVER_SA_ID, true);
    if (SoftBusServer == nullptr) {
        return;
    }
    SoftBusServer->GetBrProxyChannelStateInner(data, reply);
    int32_t uid = provider.ConsumeIntegral<int32_t>();
    data.WriteInt32(uid);
    SoftBusServer->GetBrProxyChannelStateInner(data, reply);
    SoftBusServer->RegisterPushHookInner(data, reply);
}

void DestroyGroupOwnerInnerTest(FuzzedDataProvider &provider)
{
    MessageParcel data;
    MessageParcel reply;
    (void)memset_s(&data, sizeof(MessageParcel), 0, sizeof(MessageParcel));
    (void)memset_s(&reply, sizeof(MessageParcel), 0, sizeof(MessageParcel));
    sptr<OHOS::SoftBusServerStub> SoftBusServer = new OHOS::SoftBusServer(SOFTBUS_SERVER_SA_ID, true);
    if (SoftBusServer == nullptr) {
        return;
    }
    SoftBusServer->DestroyGroupOwnerInner(data, reply);

    char pkgName[PKG_NAME_SIZE_MAX] = { 0 };
    std::string providerPkgNameName = provider.ConsumeBytesAsString(PKG_NAME_SIZE_MAX - 1);
    if (strcpy_s(pkgName, PKG_NAME_SIZE_MAX - 1, providerPkgNameName.c_str()) != EOK) {
        return;
    }
    data.WriteCString(pkgName);
    SoftBusServer->DestroyGroupOwnerInner(data, reply);
}

void CreateGroupOwnerInnerTest(FuzzedDataProvider &provider)
{
    MessageParcel data;
    MessageParcel reply;
    (void)memset_s(&data, sizeof(MessageParcel), 0, sizeof(MessageParcel));
    (void)memset_s(&reply, sizeof(MessageParcel), 0, sizeof(MessageParcel));
    sptr<OHOS::SoftBusServerStub> SoftBusServer = new OHOS::SoftBusServer(SOFTBUS_SERVER_SA_ID, true);
    if (SoftBusServer == nullptr) {
        return;
    }
    SoftBusServer->CreateGroupOwnerInner(data, reply);

    char pkgName[PKG_NAME_SIZE_MAX] = { 0 };
    std::string providerPkgNameName = provider.ConsumeBytesAsString(PKG_NAME_SIZE_MAX - 1);
    if (strcpy_s(pkgName, PKG_NAME_SIZE_MAX - 1, providerPkgNameName.c_str()) != EOK) {
        return;
    }
    data.WriteCString(pkgName);
    SoftBusServer->CreateGroupOwnerInner(data, reply);
}

void CloseBrProxyInnerTest(FuzzedDataProvider &provider)
{
    MessageParcel data;
    MessageParcel reply;
    (void)memset_s(&data, sizeof(MessageParcel), 0, sizeof(MessageParcel));
    (void)memset_s(&reply, sizeof(MessageParcel), 0, sizeof(MessageParcel));
    sptr<OHOS::SoftBusServerStub> SoftBusServer = new OHOS::SoftBusServer(SOFTBUS_SERVER_SA_ID, true);
    if (SoftBusServer == nullptr) {
        return;
    }
    SoftBusServer->CloseBrProxyInner(data, reply);

    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    data.WriteInt32(channelId);
    SoftBusServer->CloseBrProxyInner(data, reply);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    static OHOS::SoftBusServerStub3FuzzTest testEvent;
    if (!testEvent.IsInited()) {
        return 0;
    }
 
    FuzzedDataProvider provider(data, size);
    OHOS::TriggerRangeForMsdpInnerTest(provider);
    OHOS::StopRangeForMsdpInnerTest(provider);
    OHOS::RegRangeCbForMsdpInnerTest(provider);
    OHOS::SyncTrustedRelationShipInnerTest(provider);
    OHOS::ProcessInnerEventInnerTest(provider);
    OHOS::CreateServerInnerTest(provider);
    OHOS::GetPeerDeviceIdInnerTest(provider);
    OHOS::SoftbusRegisterBrProxyServiceInnerTest(provider);
    OHOS::OpenBrProxyInnerTest(provider);
    OHOS::SendBrProxyDataInnerTest(provider);
    OHOS::SetBrProxyListenerStateInnerTest(provider);
    OHOS::GetBrProxyChannelStateInnerTest(provider);
    OHOS::DestroyGroupOwnerInnerTest(provider);
    OHOS::CreateGroupOwnerInnerTest(provider);
    OHOS::CloseBrProxyInnerTest(provider);
    return 0;
}