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

#include "trans_common_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {

void *g_commonInterface = nullptr;

TransCommInterfaceMock::TransCommInterfaceMock()
{
    g_commonInterface = reinterpret_cast<void *>(this);
}

TransCommInterfaceMock::~TransCommInterfaceMock()
{
    g_commonInterface = nullptr;
}

static TransCommInterface *GetCommonInterface()
{
    return reinterpret_cast<TransCommInterface *>(g_commonInterface);
}

int TransCommInterfaceMock::ActionOfSoftbusGetConfig(ConfigType type, unsigned char *val, uint32_t len)
{
    (void)type;
    (void)len;
    *val = 1;
    return SOFTBUS_OK;
}

#ifdef __cplusplus
extern "C" {
#endif

int SoftbusGetConfig(ConfigType type, unsigned char *val, uint32_t len)
{
    return GetCommonInterface()->SoftbusGetConfig(type, val, len);
}

#ifdef __cplusplus
}
#endif
}
