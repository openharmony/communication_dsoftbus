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
#include "net_manager_adapter.h"
#include "softbus_error_code.h"

int32_t AddInterfaceAddress(const char *interface, const char *ipString, int32_t prefixLength)
{
    return SOFTBUS_OK;
}

int32_t DeleteInterfaceAddress(const char *interface, const char *ipString, int32_t prefixLength)
{
    return SOFTBUS_OK;
}

int32_t AddStaticArp(const char *interface, const char *ipString, const char *macString)
{
    return SOFTBUS_OK;
}

int32_t DeleteStaticArp(const char *interface, const char *ipString, const char *macString)
{
    return SOFTBUS_OK;
}