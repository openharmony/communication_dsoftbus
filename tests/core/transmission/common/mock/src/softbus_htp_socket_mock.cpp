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

#include <gtest/gtest.h>
#include "softbus_htp_socket_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_softbusHtpSocket = nullptr;
SoftbusHtpSocketMock::SoftbusHtpSocketMock()
{
    g_softbusHtpSocket = reinterpret_cast<void *>(this);
}

SoftbusHtpSocketMock::~SoftbusHtpSocketMock()
{
    g_softbusHtpSocket = nullptr;
}

static SoftbusHtpSocket *GetSoftbusHtpSocket()
{
    return reinterpret_cast<SoftbusHtpSocket *>(g_softbusHtpSocket);
}

extern "C" {
int32_t SoftBusSocketAccept(int32_t socketFd, SoftBusSockAddr *addr, int32_t *acceptFd)
{
    return GetSoftbusHtpSocket()->SoftBusSocketAccept(socketFd, addr, acceptFd);
}

int32_t SoftBusSocketGetLocalName(int32_t socketFd, SoftBusSockAddr *addr)
{
    return GetSoftbusHtpSocket()->SoftBusSocketGetLocalName(socketFd, addr);
}
}
}
