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

#include "lnn_kv_adapter_wrapper_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_lnnKvAdapterWrapperInterface;
LnnKvAdapterWrapperInterfaceMock::LnnKvAdapterWrapperInterfaceMock()
{
    g_lnnKvAdapterWrapperInterface = reinterpret_cast<void *>(this);
}

LnnKvAdapterWrapperInterfaceMock::~LnnKvAdapterWrapperInterfaceMock()
{
    g_lnnKvAdapterWrapperInterface = nullptr;
}

static LnnKvAdapterWrapperInterface *GetLnnKvAdapterWrapperInterface()
{
    return reinterpret_cast<LnnKvAdapterWrapperInterface *>(g_lnnKvAdapterWrapperInterface);
}

std::shared_ptr<KVAdapter> FindKvStorePtr(int32_t &dbId)
{
    return GetLnnKvAdapterWrapperInterface()->FindKvStorePtr(dbId);
}

extern "C" {
bool IsCloudSyncEnabled(void)
{
    return GetLnnKvAdapterWrapperInterface()->IsCloudSyncEnabled();
}
}
}
