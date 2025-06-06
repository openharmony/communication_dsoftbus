/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_TRANS_SPEC_OBJECT_STUB_H
#define OHOS_TRANS_SPEC_OBJECT_STUB_H

#include "broadcast_struct.h"
#include "itrans_spec_object.h"
#include "iremote_stub.h"

namespace OHOS {
enum {
    SOFTBUS_TRANS_SPEC_OBJECT_STUB_INIT_SUCCESS = 0,
    SOFTBUS_TRANS_SPEC_OBJECT_STUB_DLOPEN_FAILED,
    SOFTBUS_TRANS_SPEC_OBJECT_STUB_DLSYM_FAILED,
    SOFTBUS_TRANS_SPEC_OBJECT_STUB_INSTANCE_EXIT,
    SOFTBUS_TRANS_SPEC_OBJECT_STUB_GET_SOFTBUS_SERVER_INFO_FAILED,
};

class TransSpecObjectStub : public IRemoteStub<ITransSpecObject> {
public:
    TransSpecObjectStub();

    int32_t OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

private:

    bool OpenSoftbusPluginSo();

    using OnRemoteRequestFunc = int32_t (*)(uint32_t code, MessageParcel &data, MessageParcel &reply,
        MessageOption &option);

    OnRemoteRequestFunc onRemoteRequestFunc_ = nullptr;

    std::mutex loadSoMutex_;
    bool isLoaded_ = false;
    void *soHandle_ = nullptr;
};
} // namespace OHOS

#endif // OHOS_TRANS_SPEC_OBJECT_STUB_H