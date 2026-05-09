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

#include "softbusclientstub_fuzzer.h"

#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>
#include <securec.h>

#include "fuzz_data_generator.h"
#include "softbus_access_token_adapter.h"
#include "softbus_adapter_mem.h"
#include "softbus_app_info.h"
#include "softbus_client_stub.h"
#include "softbus_server_ipc_interface_code.h"

namespace OHOS {

const std::u16string SOFTBUS_CLIENT_STUB_INTERFACE_TOKEN = u"OHOS.ISoftBusClient";

static void WriteCollabInfo(MessageParcel &datas, CollabInfo &info)
{
    datas.WriteCString(info.accountId);
    datas.WriteUint64(info.tokenId);
    datas.WriteInt32(info.userId);
    datas.WriteInt32(info.pid);
    datas.WriteCString(info.deviceId);
}

static bool FillCollabInfo(CollabInfo *info, FuzzedDataProvider &provider)
{
    if (info == NULL) {
        return false;
    }
    std::string providerAccountId = provider.ConsumeBytesAsString(ACCOUNT_UID_LEN_MAX - 1);
    if (strcpy_s(info->accountId, ACCOUNT_UID_LEN_MAX - 1, providerAccountId.c_str()) != EOK) {
        return false;
    }
    info->tokenId = provider.ConsumeIntegral<uint64_t>();
    info->userId = provider.ConsumeIntegral<int32_t>();
    info->pid = provider.ConsumeIntegral<int32_t>();
    std::string providerDeviceId = provider.ConsumeBytesAsString(DEVICE_ID_LEN_MAX - 1);
    if (strcpy_s(info->deviceId, DEVICE_ID_LEN_MAX - 1, providerDeviceId.c_str()) != EOK) {
        return false;
    }
    return true;
}

bool OnCheckCollabRelationInnerTest(FuzzedDataProvider &provider)
{
    bool isSinkSide = provider.ConsumeBool();
    int32_t channelId = provider.ConsumeIntegral<uint32_t>();
    int32_t channelType = provider.ConsumeIntegral<uint32_t>();
    CollabInfo sourceInfo;
    (void)memset_s(&sourceInfo, sizeof(CollabInfo), 0, sizeof(CollabInfo));
    if (!FillCollabInfo(&sourceInfo, provider)) {
        return false;
    }

    CollabInfo sinkInfo;
    (void)memset_s(&sinkInfo, sizeof(CollabInfo), 0, sizeof(CollabInfo));
    if (!FillCollabInfo(&sinkInfo, provider)) {
        return false;
    }

    sptr<OHOS::SoftBusClientStub> softBusClientStub = new OHOS::SoftBusClientStub();
    if (softBusClientStub == nullptr) {
        return false;
    }
    MessageParcel datas;
    MessageParcel reply;
    MessageOption option;
    datas.WriteInterfaceToken(SOFTBUS_CLIENT_STUB_INTERFACE_TOKEN);
    datas.WriteBool(isSinkSide);
    WriteCollabInfo(datas, sourceInfo);
    WriteCollabInfo(datas, sinkInfo);
    datas.WriteInt32(channelId);
    datas.WriteInt32(channelType);
    softBusClientStub->OnRemoteRequest(CLIENT_CHECK_COLLAB_RELATION, datas, reply, option);
    return true;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static OHOS::TestEnv env;
    if (!env.IsInited()) {
        return 0;
    }
    FuzzedDataProvider provider(data, size);
    OHOS::OnCheckCollabRelationInnerTest(provider);
    return 0;
}