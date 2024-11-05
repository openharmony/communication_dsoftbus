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

#include "softbus_stream_test_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
static void *g_softBusStreamTestInterface = nullptr;
SoftBusStreamTestInterfaceMock::SoftBusStreamTestInterfaceMock()
{
    g_softBusStreamTestInterface = reinterpret_cast<void *>(this);
}

SoftBusStreamTestInterfaceMock::~SoftBusStreamTestInterfaceMock()
{
    g_softBusStreamTestInterface = nullptr;
}

static SoftBusStreamTestInterface *GetSoftBusStreamTestInterface()
{
    return reinterpret_cast<SoftBusStreamTestInterface *>(g_softBusStreamTestInterface);
}

extern "C" {
FILLP_INT FtAccept(FILLP_INT fd, struct sockaddr *addr, socklen_t *addrLen)
{
    return GetSoftBusStreamTestInterface()->FtAccept(fd, addr, addrLen);
}
FILLP_INT FtGetPeerName(FILLP_INT fd, FILLP_SOCKADDR *name, socklen_t *nameLen)
{
    return GetSoftBusStreamTestInterface()->FtGetPeerName(fd, name, nameLen);
}
FILLP_INT FtEpollWait(FILLP_INT epFd, struct SpungeEpollEvent *events, FILLP_INT maxEvents, FILLP_INT timeout)
{
    return GetSoftBusStreamTestInterface()->FtEpollWait(epFd, events, maxEvents, timeout);
}
FILLP_INT32 FtConfigGet(IN FILLP_UINT32 name, IO void *value, IN FILLP_CONST void *param)
{
    return GetSoftBusStreamTestInterface()->FtConfigGet(name, value, param);
}
FILLP_INT32 FtConfigSet(IN FILLP_UINT32 name, IN FILLP_CONST void *value, IN FILLP_CONST void *param)
{
    return GetSoftBusStreamTestInterface()->FtConfigSet(name, value, param);
}
FILLP_INT FtSend(FILLP_INT fd, FILLP_CONST void *data, size_t size, FILLP_INT flag)
{
    return GetSoftBusStreamTestInterface()->FtSend(fd, data, size, flag);
}
}
}
