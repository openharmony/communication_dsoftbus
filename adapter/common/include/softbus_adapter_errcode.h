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

#ifndef SOFTBUS_ADAPTER_ERROR_CODE_H
#define SOFTBUS_ADAPTER_ERROR_CODE_H

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

enum SoftBusAdapterErrNo {
    SOFTBUS_ADAPTER_COMMON_ERR_BASE = (-10000),
    SOFTBUS_ADAPTER_INVALID_PARAM,

    SOFTBUS_ADAPTER_FILE_ERR_BASE = (-9000),
    SOFTBUS_ADAPTER_FILE_EXIST,

    SOFTBUS_ADAPTER_SOCKET_ERR_BASE = (-8000),
    SOFTBUS_ADAPTER_SOCKET_EINTR,
    SOFTBUS_ADAPTER_SOCKET_EINPROGRESS,
    SOFTBUS_ADAPTER_SOCKET_EAGAIN,
    SOFTBUS_ADAPTER_SOCKET_EBADF,
    SOFTBUS_ADAPTER_SOCKET_EINVAL,
    SOFTBUS_ADAPTER_SOCKET_ENETUNREACH,

    SOFTBUS_ADAPTER_ERR = (-1),
    SOFTBUS_ADAPTER_OK = 0,
};

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */
#endif /* SOFTBUS_ADAPTER_ERROR_CODE_H */
