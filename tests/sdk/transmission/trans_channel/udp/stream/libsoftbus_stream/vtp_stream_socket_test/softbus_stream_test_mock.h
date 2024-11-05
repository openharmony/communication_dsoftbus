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

#ifndef SOFTBUS_STREAM_TEST_MOCK_H
#define SOFTBUS_STREAM_TEST_MOCK_H

#include <gmock/gmock.h>
#include <sys/socket.h>

#include "fillpinc.h"
#include "fillptypes.h"
#include "softbus_def.h"

namespace OHOS {
class SoftBusStreamTestInterface {
public:
    SoftBusStreamTestInterface() {};
    virtual ~SoftBusStreamTestInterface() {};
    virtual FILLP_INT FtAccept(FILLP_INT fd, struct sockaddr *addr, socklen_t *addrLen) = 0;
    virtual FILLP_INT FtGetPeerName(FILLP_INT fd, FILLP_SOCKADDR *name, socklen_t *nameLen) = 0;
    virtual FILLP_INT FtEpollWait(FILLP_INT epFd, struct SpungeEpollEvent *events, FILLP_INT maxEvents,
        FILLP_INT timeout) = 0;
    virtual FILLP_INT32 FtConfigGet(IN FILLP_UINT32 name, IO void *value, IN FILLP_CONST void *param) = 0;
    virtual FILLP_INT32 FtConfigSet(IN FILLP_UINT32 name, IN FILLP_CONST void *value, IN FILLP_CONST void *param) = 0;
    virtual FILLP_INT FtSend(FILLP_INT fd, FILLP_CONST void *data, size_t size, FILLP_INT flag) = 0;
};

class SoftBusStreamTestInterfaceMock : public SoftBusStreamTestInterface {
public:
    SoftBusStreamTestInterfaceMock();
    ~SoftBusStreamTestInterfaceMock() override;
    MOCK_METHOD3(FtAccept, FILLP_INT (FILLP_INT fd, struct sockaddr *addr, socklen_t *addrLen));
    MOCK_METHOD3(FtGetPeerName, FILLP_INT (FILLP_INT fd, FILLP_SOCKADDR *name, socklen_t *nameLen));
    MOCK_METHOD4(FtEpollWait, FILLP_INT (FILLP_INT epFd, struct SpungeEpollEvent *events, FILLP_INT maxEvents,
        FILLP_INT timeout));
    MOCK_METHOD3(FtConfigGet, FILLP_INT32 (IN FILLP_UINT32 name, IO void *value, IN FILLP_CONST void *param));
    MOCK_METHOD3(FtConfigSet, FILLP_INT32 (IN FILLP_UINT32 name, IN FILLP_CONST void *value,
        IN FILLP_CONST void *param));
    MOCK_METHOD4(FtSend, FILLP_INT (FILLP_INT fd, FILLP_CONST void *data, size_t size, FILLP_INT flag));
};
} // namespace OHOS
#endif // SOFTBUS_STREAM_TEST_MOCK_H
