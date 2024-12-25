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

#include "softbusserverstub2_fuzzer.h"

#include "softbus_server_ipc_interface_code.h"
#include "softbus_server.h"

extern "C" {
bool GetServerIsInit(void)
{
    return true;
}

bool SoftBusCheckIsAccessAndRecordAccessToken(uint64_t tokenId, const char *permission)
{
    (void)tokenId;
    (void)permission;
    return true;
}
} // extern "C"

namespace {
constexpr int32_t SOFTBUS_SERVER_SA_ID = 4700;
const std::u16string SOFTBUS_SERVER_STUB_INTERFACE_TOKEN = u"OHOS.ISoftBusServer";
const std::vector<SoftBusFuncId> CODE_LIST = {
    MANAGE_REGISTER_SERVICE,
    SERVER_CREATE_SESSION_SERVER,
    SERVER_REMOVE_SESSION_SERVER,
    SERVER_OPEN_SESSION,
    SERVER_OPEN_AUTH_SESSION,
    SERVER_NOTIFY_AUTH_SUCCESS,
    SERVER_CLOSE_CHANNEL,
    SERVER_CLOSE_CHANNEL_STATISTICS,
    SERVER_SESSION_SENDMSG,
    SERVER_QOS_REPORT,
    SERVER_GRANT_PERMISSION,
    SERVER_REMOVE_PERMISSION,
    SERVER_STREAM_STATS,
    SERVER_GET_SOFTBUS_SPEC_OBJECT,
    SERVER_JOIN_LNN,
    SERVER_JOIN_METANODE,
    SERVER_LEAVE_LNN,
    SERVER_LEAVE_METANODE,
    SERVER_GET_ALL_ONLINE_NODE_INFO,
    SERVER_GET_LOCAL_DEVICE_INFO,
    SERVER_GET_NODE_KEY_INFO,
    SERVER_SET_NODE_DATA_CHANGE_FLAG,
    SERVER_START_TIME_SYNC,
    SERVER_STOP_TIME_SYNC,
    SERVER_PUBLISH_LNN,
    SERVER_STOP_PUBLISH_LNN,
    SERVER_REFRESH_LNN,
    SERVER_STOP_REFRESH_LNN,
    SERVER_ACTIVE_META_NODE,
    SERVER_DEACTIVE_META_NODE,
    SERVER_GET_ALL_META_NODE_INFO,
    SERVER_SHIFT_LNN_GEAR,
    SERVER_RIPPLE_STATS,
    SERVER_GET_BUS_CENTER_EX_OBJ,
    SERVER_EVALUATE_QOS,
    SERVER_RELEASE_RESOURCES,
    SERVER_REG_DATA_LEVEL_CHANGE_CB,
    SERVER_UNREG_DATA_LEVEL_CHANGE_CB,
    SERVER_SET_DATA_LEVEL,
};

class TestEnv {
public:
    TestEnv()
    {
        isInited_ = false;
        stub_ = new OHOS::SoftBusServer(SOFTBUS_SERVER_SA_ID, true);
        if (stub_ == nullptr) {
            return;
        }
        isInited_ = true;
    }

    ~TestEnv()
    {
        isInited_ = false;
        stub_ = nullptr;
    }

    bool IsInited(void) const noexcept
    {
        return isInited_;
    }

    void DoRemoteRequest(SoftBusFuncId code, OHOS::MessageParcel &data)
    {
        OHOS::MessageParcel reply;
        OHOS::MessageOption option;
        if (stub_ != nullptr) {
            stub_->OnRemoteRequest(static_cast<uint32_t>(code), data, reply, option);
        }
    }

private:
    volatile bool isInited_;
    OHOS::sptr<OHOS::SoftBusServer> stub_;
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
    parcel.WriteInterfaceToken(SOFTBUS_SERVER_STUB_INTERFACE_TOKEN);
    parcel.WriteBuffer(data + 1, size - 1);

    env.DoRemoteRequest(code, parcel);
    return 0;
}
