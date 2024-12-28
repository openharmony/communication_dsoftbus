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

#include "softbus_tcp_socket.h"

#include "conn_log.h"

int32_t ConnSetTcpKeepalive(int32_t fd, int32_t seconds, int32_t keepAliveIntvl, int32_t keepAliveCount)
{
    (void)fd;
    (void)seconds;
    (void)keepAliveIntvl;
    (void)keepAliveCount;
    CONN_LOGE(CONN_COMMON, "not support");
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t ConnSetTcpUserTimeOut(int32_t fd, uint32_t millSec)
{
    (void)fd;
    (void)millSec;
    CONN_LOGE(CONN_COMMON, "not support");
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t SetIpTos(int fd, uint32_t tos)
{
    (void)fd;
    (void)tos;
    CONN_LOGE(CONN_COMMON, "not support");
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t ConnToggleNonBlockMode(int32_t fd, bool isNonBlock)
{
    (void)fd;
    (void)isNonBlock;
    CONN_LOGE(CONN_COMMON, "not support");
    return SOFTBUS_NOT_IMPLEMENT;
}
