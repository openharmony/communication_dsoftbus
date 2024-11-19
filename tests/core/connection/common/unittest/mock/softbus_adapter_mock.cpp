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

#include "softbus_adapter_mock.h"

#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <securec.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

#include "comm_log.h"
#include "conn_event.h"
#include "endian.h" /* liteos_m htons */
#include "softbus_adapter_errcode.h"
#include "softbus_def.h"
#include "softbus_error_code.h"

using namespace testing;
using namespace testing::ext;

extern "C" {
SoftbusAdapterMock::SoftbusAdapterMock()
{
    gmock_.store(this);
}

SoftbusAdapterMock::~SoftbusAdapterMock()
{
    gmock_.store(nullptr);
}

int32_t SoftBusSocketGetPeerName(int32_t socketFd, SoftBusSockAddr *addr)
{
    return SoftbusAdapterMock::GetMock()->SoftBusSocketGetPeerName(socketFd, addr);
}

int32_t SoftBusSocketSetOpt(int32_t socketFd, int32_t level, int32_t optName, const void *optVal, int32_t optLen)
{
    return SoftbusAdapterMock::GetMock()->SoftBusSocketSetOpt(socketFd, level, optName, optVal, optLen);
}

int32_t SoftBusGetTime(SoftBusSysTime *sysTime)
{
    return SoftbusAdapterMock::GetMock()->SoftBusGetTime(sysTime);
}

int32_t SoftBusCondWait(SoftBusCond *cond, SoftBusMutex *mutex, SoftBusSysTime *time)
{
    return SoftbusAdapterMock::GetMock()->SoftBusCondWait(cond, mutex, time);
}

int32_t SoftbusAdapterMock::ActionOfSoftBusSocketGetPeerName(int32_t socketFd, SoftBusSockAddr *addr)
{
    if (addr == nullptr) {
        COMM_LOGE(COMM_ADAPTER, "get peer name invalid input");
        return SOFTBUS_ADAPTER_ERR;
    }
    addr->saFamily = SOFTBUS_AF_INET6;
    return SOFTBUS_ADAPTER_OK;
}
}
