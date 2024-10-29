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

#include "softbusclientstub2_fuzzer.h"

#include "client_trans_channel_manager.h"
#include "softbus_client_stub.h"
#include "softbus_server_ipc_interface_code.h"

namespace {
const std::u16string SOFTBUS_CLIENT_STUB_INTERFACE_TOKEN = u"OHOS.ISoftBusClient";
const std::vector<SoftBusFuncId> CODE_LIST = {
    CLIENT_ON_CHANNEL_OPENED,
    CLIENT_ON_CHANNEL_OPENFAILED,
    CLIENT_ON_CHANNEL_LINKDOWN,
    CLIENT_ON_CHANNEL_CLOSED,
    CLIENT_ON_CHANNEL_MSGRECEIVED,
    CLIENT_ON_CHANNEL_QOSEVENT,
    CLIENT_ON_JOIN_RESULT,
    CLIENT_ON_JOIN_METANODE_RESULT,
    CLIENT_ON_LEAVE_RESULT,
    CLIENT_ON_LEAVE_METANODE_RESULT,
    CLIENT_ON_NODE_DEVICE_TRUST_CHANGED,
    CLIENT_ON_HICHAIN_PROOF_EXCEPTION,
    CLIENT_ON_NODE_ONLINE_STATE_CHANGED,
    CLIENT_ON_NODE_BASIC_INFO_CHANGED,
    CLIENT_ON_LOCAL_NETWORK_ID_CHANGED,
    CLIENT_ON_TIME_SYNC_RESULT,
    CLIENT_ON_PUBLISH_LNN_RESULT,
    CLIENT_ON_REFRESH_LNN_RESULT,
    CLIENT_ON_REFRESH_DEVICE_FOUND,
    CLIENT_ON_PERMISSION_CHANGE,
    CLIENT_SET_CHANNEL_INFO,
    CLIENT_ON_DATA_LEVEL_CHANGED,
    CLIENT_ON_TRANS_LIMIT_CHANGE,
    CLIENT_ON_CHANNEL_BIND,
};

class TestEnv {
public:
    TestEnv()
    {
        isInited_ = false;
        stub_ = new OHOS::SoftBusClientStub();
        if (stub_ == nullptr) {
            return;
        }
        isInited_ = true;
        (void)ClientTransChannelInit();
    }

    ~TestEnv()
    {
        isInited_ = false;
        stub_ = nullptr;
        (void)ClientTransChannelDeinit();
    }

    bool IsInited(void) const noexcept
    {
        return isInited_;
    }

    void DoRemoteRequest(SoftBusFuncId code, OHOS::MessageParcel &data)
    {
        if (code == CLIENT_ON_CHANNEL_OPENFAILED ||
            code == CLIENT_ON_CHANNEL_CLOSED ||
            code == CLIENT_ON_CHANNEL_MSGRECEIVED) {
            return;
        }
        OHOS::MessageParcel reply;
        OHOS::MessageOption option;
        if (stub_ != nullptr) {
            stub_->OnRemoteRequest(static_cast<uint32_t>(code), data, reply, option);
        }
    }

private:
    volatile bool isInited_;
    OHOS::sptr<OHOS::SoftBusClientStub> stub_;
};
} // anonymous namespace

extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static TestEnv env;
    if (!env.IsInited()) {
        return 0;
    }

    if (data == nullptr || size == 0) {
        return 0;
    }
    SoftBusFuncId code = CODE_LIST[data[0] % CODE_LIST.size()];

    OHOS::MessageParcel parcel;
    parcel.WriteInterfaceToken(SOFTBUS_CLIENT_STUB_INTERFACE_TOKEN);
    parcel.WriteBuffer(data + 1, size - 1);

    env.DoRemoteRequest(code, parcel);
    return 0;
}
