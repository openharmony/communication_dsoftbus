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

#ifndef TRANSTCPPROCESSDATA_FUZZER_H
#define TRANSTCPPROCESSDATA_FUZZER_H

#include <cstdint>
#include <unistd.h>
#include <climits>
#include <cstdio>
#include <cstdlib>
#include <fcntl.h>

#include "softbus_proxychannel_manager.h"
#include "trans_tcp_process_data.c"

#define FUZZ_PROJECT_NAME "transtcpprocessdata_fuzzer"

namespace OHOS {
class TransTcpProcessData {
public:
    TransTcpProcessData()
    {
        isInited_ = false;
        (void)TransProxyManagerInit(TransServerGetChannelCb());
        (void)TransGetDataBufSize();
        (void)TransGetTdcDataBufMaxSize();
        isInited_ = true;
    }

    ~TransTcpProcessData()
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
} // namespace OHOS
#endif