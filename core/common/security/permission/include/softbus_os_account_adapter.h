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

#ifndef SOFTBUS_MOCK_ADAPTER_H
#define SOFTBUS_MOCK_ADAPTER_H

#include <map>
#include <string>
#include <vector>

#include "os_account_manager.h"
#include "softbus_error_code.h"
#include "comm_log.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif /* __cplusplus */
#endif /* __cplusplus */


int32_t GetOsAccountLocalIdFromUidAdapter(const int32_t uid);
int32_t IsOsAccountForegroundAdapter(const int32_t appUserId, bool &isForegroundUser);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif /* SOFTBUS_OS_ACCOUNT_ADAPTER_H */