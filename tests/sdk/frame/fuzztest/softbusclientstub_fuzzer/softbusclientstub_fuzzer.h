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

#ifndef SOFTBUSCLIENTSTUB_FUZZER_H
#define SOFTBUSCLIENTSTUB_FUZZER_H

#include <cstdint>
#include <unistd.h>
#include <climits>
#include <cstdio>
#include <cstdlib>
#include <fcntl.h>

#include "client_trans_channel_manager.h"

constexpr size_t FOO_MAX_LEN = 1024;
constexpr size_t U32_AT_SIZE = 4;
constexpr size_t UUID_STRING_LEN = 38;
constexpr size_t HAP_NAME_MAX_LEN = 256;

#define FUZZ_PROJECT_NAME "softbusclientstub_fuzzer"

namespace OHOS {
class TestEnv {
public:
    TestEnv()
    {
        isInited_ = false;
        ClientTransChannelInit();
        isInited_ = true;
    }

    ~TestEnv()
    {
        isInited_ = false;
        ClientTransChannelDeinit();
    }

    bool IsInited(void)
    {
        return isInited_;
    }

private:
    volatile bool isInited_;
};

enum SoftBusFuncId {
    CLIENT_ON_CHANNEL_OPENED = 256,
    CLIENT_ON_CHANNEL_OPENFAILED,
    CLIENT_ON_CHANNEL_LINKDOWN,
    CLIENT_ON_CHANNEL_CLOSED,
    CLIENT_ON_CHANNEL_MSGRECEIVED,
    CLIENT_ON_CHANNEL_QOSEVENT,

    CLIENT_DISCOVERY_DEVICE_FOUND,

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
    CLIENT_CHECK_COLLAB_RELATION,
};
} // namespace OHOS
#endif
