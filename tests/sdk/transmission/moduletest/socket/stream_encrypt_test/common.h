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

#ifndef SOCKET_COMMON_H
#define SOCKET_COMMON_H

#include "socket.h"
#include "softbus_common.h"
#include "softbus_error_code.h"

namespace OHOS {
#define LOG(fmt, args...)                     \
    do {                                      \
        fprintf(stdout, "" fmt "\n", ##args); \
    } while (false)

#define LOGI(fmt, args...)                                                     \
    do {                                                                       \
        fprintf(stdout, "[INFO][%s:%d]" fmt "\n", __func__, __LINE__, ##args); \
    } while (false)

#define LOGE(fmt, args...)                                                    \
    do {                                                                      \
        fprintf(stdout, "[ERR][%s:%d]" fmt "\n", __func__, __LINE__, ##args); \
    } while (false)

inline const char *PKG_NAME = "com.communication.demo";
inline const char *TEST_NOTIFY_NAME = "com.communication.demo.notify.client";
inline const char *TEST_NOTIFY_SRV_NAME = "com.communication.demo.notify.server";
inline const char *TEST_SESSION_NAME = "com.communication.demo.client";
inline const char *TEST_SESSION_NAME_SRV = "com.communication.demo.server";

inline const char *TEST_STREAM_DATA = "EncryptStreamOrUnencryptStreamTest";

int32_t TestInit();
int32_t TestDeInit();

char *WaitOnLineAndGetNetWorkId();
} // namespace OHOS
#endif // SOCKET_COMMON_H