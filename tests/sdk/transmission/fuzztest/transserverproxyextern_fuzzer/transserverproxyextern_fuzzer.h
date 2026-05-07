/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#ifndef TRANSSERVERPROXYEXTERN_FUZZER_H
#define TRANSSERVERPROXYEXTERN_FUZZER_H

#include <cstdint>
#include <unistd.h>
#include <climits>
#include <cstdio>
#include <cstdlib>
#include <fcntl.h>

#include "trans_server_proxy.h"

#define LOOP_SLEEP_MILLS 100
#define FUZZ_PROJECT_NAME "transserverproxyextern_fuzzer"

namespace OHOS {
class TransServerProxyExternTestEnv {
public:
    TransServerProxyExternTestEnv()
    {
        isInited_ = false;
        (void)TransServerProxyInit();
        isInited_ = true;
    }

    ~TransServerProxyExternTestEnv()
    {
        isInited_ = false;
        TransServerProxyDeInit();
    }

    bool IsInited(void) const
    {
        return isInited_;
    }

private:
    volatile bool isInited_;
};
} // namespace OHOS

#endif