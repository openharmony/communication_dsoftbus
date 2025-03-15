/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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
#include "stream_common.h"
#include "stream_packetizer.h"

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
    virtual FILLP_INT FtFillpStatsGet(IN FILLP_INT fd, OUT struct FillpStatisticsPcb *outStats) = 0;
    virtual FILLP_INT FtConnect(FILLP_INT fd, FILLP_CONST FILLP_SOCKADDR *name, socklen_t nameLen) = 0;
    virtual FILLP_INT FtEpollCreate(void) = 0;
    virtual FILLP_INT FtSendFrame(FILLP_INT fd, FILLP_CONST void *data, size_t size, FILLP_INT flag,
        FILLP_CONST struct FrameInfo *frame) = 0;
    virtual FILLP_INT FtListen(FILLP_INT fd, FILLP_INT backLog) = 0;
    virtual int32_t SoftBusGetTime(SoftBusSysTime *sysTime) = 0;
    virtual bool Connect(const Communication::SoftBus::IpAndPort &remote) = 0;
    virtual std::unique_ptr<char[]> PacketizeStream() = 0;
    virtual ssize_t GetPacketLen() = 0;
    virtual int SetSocketEpollMode(int fd) = 0;
    virtual bool CreateClient(
        Communication::SoftBus::IpAndPort &local, int streamType, std::pair<uint8_t *, uint32_t> sessionKey) = 0;
    virtual int CreateAndBindSocket(Communication::SoftBus::IpAndPort &local, bool isServer) = 0;
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
    MOCK_METHOD2(FtFillpStatsGet, FILLP_INT (IN FILLP_INT fd, OUT struct FillpStatisticsPcb *outStats));
    MOCK_METHOD3(FtConnect, FILLP_INT (FILLP_INT fd, FILLP_CONST FILLP_SOCKADDR *name, socklen_t nameLen));
    MOCK_METHOD0(FtEpollCreate, FILLP_INT (void));
    MOCK_METHOD5(FtSendFrame, FILLP_INT (FILLP_INT fd, FILLP_CONST void *data, size_t size,
        FILLP_INT flag, FILLP_CONST struct FrameInfo *frame));
    MOCK_METHOD1(SoftBusGetTime, int32_t (SoftBusSysTime *sysTime));
    MOCK_METHOD1(Connect, bool (const Communication::SoftBus::IpAndPort &remote));
    MOCK_METHOD2(FtListen, FILLP_INT (FILLP_INT fd, FILLP_INT backLog));
    MOCK_METHOD0(PacketizeStream, std::unique_ptr<char[]> ());
    MOCK_METHOD0(GetPacketLen, ssize_t ());
    MOCK_METHOD1(SetSocketEpollMode, int (int fd));
    MOCK_METHOD3(CreateClient,
        bool (Communication::SoftBus::IpAndPort &local, int streamType, std::pair<uint8_t *, uint32_t> sessionKey));
    MOCK_METHOD2(CreateAndBindSocket, int (Communication::SoftBus::IpAndPort &local, bool isServer));
};
} // namespace OHOS
#endif // SOFTBUS_STREAM_TEST_MOCK_H
