/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "vtp_stream_socket.h"
#define LOG_TAG "VTP_STREAM_SOCKET"

#include <ifaddrs.h>
#include <memory>
#include <netinet/in.h>
#include <securec.h>
#include <sys/socket.h>
#include <thread>

#include "fillpinc.h"
#include "raw_stream_data.h"
#include "softbus_adapter_crypto.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "stream_depacketizer.h"
#include "stream_packetizer.h"

namespace Communication {
namespace SoftBus {
bool g_logOn = false;
namespace {
void PrintOptionInfo(int type, const StreamAttr &value)
{
    switch (value.GetType()) {
        case INT_TYPE:
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO,
                "Int option: type:%d, value:%d", type, value.GetIntValue());
            break;
        case BOOL_TYPE:
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO,
                "Bool option: type:%d, value:%d", type, value.GetBoolValue());
            break;
        case STRING_TYPE:
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_DBG,
                "String option: type:%d, value:%s", type, value.GetStrValue().c_str());
            break;
        default:
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "Wrong StreamAttr!");
            (void)type;
    }
}
} // namespace
std::shared_ptr<VtpInstance> VtpStreamSocket::vtpInstance_ = VtpInstance::GetVtpInstance();

void VtpStreamSocket::InsertElementToFuncMap(int type, ValueType valueType, MySetFunc set, MyGetFunc get)
{
    OptionFunc fun = {
        valueType, set, get
    };
    optFuncMap_.insert(std::pair<int, OptionFunc>(type, fun));
}

VtpStreamSocket::VtpStreamSocket()
{
    InsertElementToFuncMap(TOS, INT_TYPE, &VtpStreamSocket::SetIpTos, &VtpStreamSocket::GetIpTos);
    InsertElementToFuncMap(FD, INT_TYPE, nullptr, &VtpStreamSocket::GetStreamSocketFd);
    InsertElementToFuncMap(SERVER_FD, INT_TYPE, nullptr, &VtpStreamSocket::GetListenSocketFd);
    InsertElementToFuncMap(LOCAL_IP, INT_TYPE, nullptr, &VtpStreamSocket::GetIp);
    InsertElementToFuncMap(LOCAL_PORT, INT_TYPE, nullptr, &VtpStreamSocket::GetPort);
    InsertElementToFuncMap(REMOTE_IP, STRING_TYPE, nullptr, &VtpStreamSocket::GetIp);
    InsertElementToFuncMap(REMOTE_PORT, INT_TYPE, nullptr, &VtpStreamSocket::GetPort);
    InsertElementToFuncMap(BOUND_INTERFACE_IP, STRING_TYPE, &VtpStreamSocket::SetSocketBindToDevices, nullptr);
    InsertElementToFuncMap(IP_TYPE, STRING_TYPE, nullptr, &VtpStreamSocket::GetIpType);
    InsertElementToFuncMap(REMOTE_SCOPE_ID, INT_TYPE, nullptr, &VtpStreamSocket::GetRemoteScopeId);
    InsertElementToFuncMap(NON_BLOCK, BOOL_TYPE, &VtpStreamSocket::SetNonBlockMode, &VtpStreamSocket::GetNonBlockMode);
    InsertElementToFuncMap(KEEP_ALIVE_TIMEOUT, INT_TYPE, &VtpStreamSocket::SetVtpStackConfig, nullptr);
    InsertElementToFuncMap(SEND_CACHE, INT_TYPE, &VtpStreamSocket::SetVtpStackConfig,
        &VtpStreamSocket::GetVtpStackConfig);
    InsertElementToFuncMap(RECV_CACHE, INT_TYPE, &VtpStreamSocket::SetVtpStackConfig,
        &VtpStreamSocket::GetVtpStackConfig);
    InsertElementToFuncMap(SEND_BUF_SIZE, INT_TYPE, &VtpStreamSocket::SetVtpStackConfig,
        &VtpStreamSocket::GetVtpStackConfig);
    InsertElementToFuncMap(RECV_BUF_SIZE, INT_TYPE, &VtpStreamSocket::SetVtpStackConfig,
        &VtpStreamSocket::GetVtpStackConfig);
    InsertElementToFuncMap(PACKET_SIZE, INT_TYPE, &VtpStreamSocket::SetVtpStackConfig,
        &VtpStreamSocket::GetVtpStackConfig);
    InsertElementToFuncMap(MAX_VTP_SOCKET_NUM, INT_TYPE, &VtpStreamSocket::SetVtpStackConfig,
        &VtpStreamSocket::GetVtpStackConfig);
    InsertElementToFuncMap(MAX_VTP_CONNECT_NUM, INT_TYPE, &VtpStreamSocket::SetVtpStackConfig,
        &VtpStreamSocket::GetVtpStackConfig);
    InsertElementToFuncMap(REDUNANCY_SWITCH, BOOL_TYPE, &VtpStreamSocket::SetVtpStackConfig,
        &VtpStreamSocket::GetVtpStackConfig);
    InsertElementToFuncMap(REDUNANCY_LEVEL, INT_TYPE, &VtpStreamSocket::SetVtpStackConfig,
        &VtpStreamSocket::GetVtpStackConfig);
    InsertElementToFuncMap(NACK_DELAY, BOOL_TYPE, &VtpStreamSocket::SetVtpStackConfig,
        &VtpStreamSocket::GetVtpStackConfig);
    InsertElementToFuncMap(NACK_DELAY_TIMEOUT, INT_TYPE, &VtpStreamSocket::SetVtpStackConfig,
        &VtpStreamSocket::GetVtpStackConfig);
    InsertElementToFuncMap(PACK_INTERVAL_ENLARGE, BOOL_TYPE, &VtpStreamSocket::SetVtpStackConfig,
        &VtpStreamSocket::GetVtpStackConfig);
    InsertElementToFuncMap(STREAM_TYPE_INT, INT_TYPE, &VtpStreamSocket::SetStreamType, &VtpStreamSocket::GetStreamType);
    InsertElementToFuncMap(IS_SERVER, INT_TYPE, nullptr, &VtpStreamSocket::IsServer);
    InsertElementToFuncMap(SCENE, INT_TYPE, &VtpStreamSocket::SetStreamScene, nullptr);
    InsertElementToFuncMap(STREAM_HEADER_SIZE, INT_TYPE, &VtpStreamSocket::SetStreamHeaderSize, nullptr);

    scene_ = UNKNOWN_SCENE;
}

VtpStreamSocket::~VtpStreamSocket()
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "~VtpStreamSocket");
}

std::shared_ptr<VtpStreamSocket> VtpStreamSocket::GetSelf()
{
    return shared_from_this();
}

bool VtpStreamSocket::CreateClient(IpAndPort &local, int streamType, const std::string &sessionKey)
{
    int fd = CreateAndBindSocket(local);
    if (fd == -1) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "CreateAndBindSocket failed, errorcode:%d", FtGetErrno());
        DestroyStreamSocket();
        return false;
    }

    sessionKey_ = sessionKey;
    streamType_ = streamType;
    std::lock_guard<std::mutex> guard(streamSocketLock_);
    streamFd_ = fd;
    configCv_.notify_all();

    SetDefaultConfig(fd);
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO,
        "Success to create a client socket(%d) of stream type(%d)", fd, streamType);
    return true;
}

bool VtpStreamSocket::CreateClient(IpAndPort &local, const IpAndPort &remote, int streamType,
    const std::string &sessionKey)
{
    if (!CreateClient(local, streamType, sessionKey)) {
        return false;
    }

    return Connect(remote);
}

bool VtpStreamSocket::CreateServer(IpAndPort &local, int streamType, const std::string &sessionKey)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "CreateVtpServer start");
    listenFd_ = CreateAndBindSocket(local);
    if (listenFd_ == -1) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "create listenFd failed, errorcode %d", FtGetErrno());
        DestroyStreamSocket();
        return false;
    }

    bool ret = FtListen(listenFd_, MAX_CONNECTION_VALUE);
    if (ret != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "FtListen failed, ret :%d errorcode %d", ret, FtGetErrno());
        DestroyStreamSocket();
        return false;
    }

    epollFd_ = FtEpollCreate();
    if (epollFd_ < 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "Failed to create epoll fd:%d", FtGetErrno());
        DestroyStreamSocket();
        return false;
    }
    isStreamRecv_ = true;
    streamType_ = streamType;
    sessionKey_ = sessionKey;
    auto self = this->GetSelf();
    std::thread([self]() { self->NotifyStreamListener(); }).detach();

    std::thread([self]() {
        if (!self->Accept()) {
            self->DestroyStreamSocket();
            return;
        }
        self->DoStreamRecv();
        self->DestroyStreamSocket();
    }).detach();

    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO,
        "CreateServer end, listenFd:%d, epollFd:%d, streamType:%d", listenFd_, epollFd_, streamType_);
    return true;
}

void VtpStreamSocket::DestroyStreamSocket()
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "DestroyStreamSocket start");
    std::lock_guard<std::mutex> guard(streamSocketLock_);
    if (isDestoryed_) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "StreamSocket is already destoryed");
        return;
    }
    if (listenFd_ != -1) {
        FtClose(listenFd_);
        listenFd_ = -1;
    }

    if (streamFd_ != -1) {
        FtClose(streamFd_);
        streamFd_ = -1;
    }

    if (epollFd_ != -1) {
        FtClose(epollFd_);
        epollFd_ = -1;
    }

    if (streamReceiver_ != nullptr) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "DestroyStreamSocket receiver delete");
        streamReceiver_->OnStreamStatus(STREAM_CLOSED);
        streamReceiver_.reset();
    }

    QuitStreamBuffer();
    vtpInstance_->UpdateSocketStreamCount(false);
    isDestoryed_ = true;
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "DestroyStreamSocket end");
}

bool VtpStreamSocket::Connect(const IpAndPort &remote)
{
    if (remote.ip.empty()) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "remote addr  error, ip is nullptr");
        DestroyStreamSocket();
        return false;
    }

    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_DBG,
        "Connect to server(addr:%s, server port:%d)", remote.ip.c_str(), remote.port);
    remoteIpPort_ = remote;

    struct sockaddr_in remoteSockAddr;
    remoteSockAddr.sin_family = AF_INET;
    remoteSockAddr.sin_port = htons(static_cast<short>(remote.port));
    remoteSockAddr.sin_addr.s_addr = inet_addr(remote.ip.c_str());

    int ret = FtConnect(streamFd_, reinterpret_cast<struct sockaddr *>(&remoteSockAddr), sizeof(remoteSockAddr));
    if (ret != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "FtConnect failed, ret :%d, errorno: %d", ret, FtGetErrno());
        DestroyStreamSocket();
        return false;
    }

    epollFd_ = FtEpollCreate();
    if (epollFd_ < 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "Failed to create epoll fd:%d", FtGetErrno());
        DestroyStreamSocket();
        return false;
    }

    if (SetSocketEpollMode(streamFd_) != ERR_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "SetSocketEpollMode failed, fd = %d", streamFd_);
        DestroyStreamSocket();
        return false;
    }
    isStreamRecv_ = true;
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "Success to connect remote, and create a thread to recv data.");

    auto self = this->GetSelf();
    std::thread([self]() { self->NotifyStreamListener(); }).detach();
    std::thread([self]() {
        self->DoStreamRecv();
        self->DestroyStreamSocket();
    }).detach();
    return true;
}

bool VtpStreamSocket::Send(std::unique_ptr<IStream> stream)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_DBG, "send in..., streamType:%d, data size:%zd, ext size:%zd", streamType_,
        stream->GetBufferLen(), stream->GetExtBufferLen());

    if (!isBlocked_) {
        isBlocked_ = true;
        if (!SetNonBlockMode(streamFd_, StreamAttr(false))) {
            return false;
        }
    }

    std::unique_ptr<char[]> data = nullptr;
    ssize_t len = 0;
    if (streamType_ == RAW_STREAM) {
        data = stream->GetBuffer();
        len = stream->GetBufferLen();
    } else if (streamType_ == COMMON_VIDEO_STREAM || streamType_ == COMMON_AUDIO_STREAM) {
        StreamPacketizer packet(streamType_, std::move(stream));

        auto plainData = packet.PacketizeStream();
        if (plainData == nullptr) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "PacketizeStream failed");
            return false;
        }
        len = packet.GetPacketLen() + GetEncryptOverhead();
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_DBG,
            "packet.GetPacketLen() = %zd, GetEncryptOverhead() = %zd", packet.GetPacketLen(), GetEncryptOverhead());
        data = std::make_unique<char[]>(len + FRAME_HEADER_LEN);
        ssize_t encLen = Encrypt(plainData.get(), packet.GetPacketLen(),
            data.get() + FRAME_HEADER_LEN, len);
        if (encLen != len) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR,
                "encrypted failed, dataLen = %zd, encryptLen = %zd", len, encLen);
            return false;
        }
        InsertBufferLength(len, FRAME_HEADER_LEN, reinterpret_cast<uint8_t *>(data.get()));
        len += FRAME_HEADER_LEN;
    }

    int ret = FtSend(streamFd_, data.get(), len, 0);
    if (ret == -1) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "send failed, errorno: %d", FtGetErrno());
        return false;
    }

    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_DBG, "send out..., streamType:%d, data size:%zd", streamType_, len);
    return true;
}

bool VtpStreamSocket::SetOption(int type, const StreamAttr &value)
{
    PrintOptionInfo(type, value);
    auto it = optFuncMap_.find(type);
    if (it == optFuncMap_.end()) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_WARN, "not found type = %d", type);
        return false;
    }

    if (value.GetType() != it->second.valueType) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_WARN,
            "type = %d, value.type = %d", value.GetType(), it->second.valueType);
        return false;
    }

    MySetFunc set = it->second.set;
    if (set == nullptr) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_WARN, "set is nullptr");
        return false;
    }

    if (type == NON_BLOCK || type == TOS) {
        return (this->*set)(static_cast<int>(streamFd_), value);
    }

    auto outerIt = FILLP_TYPE_MAP.find(type);
    if (outerIt != FILLP_TYPE_MAP.end()) {
        return (this->*set)(outerIt->second, value);
    }

    auto innerIt = INNER_FILLP_TYPE_MAP.find(type);
    if (innerIt != INNER_FILLP_TYPE_MAP.end()) {
        return (this->*set)(innerIt->second, value);
    }

    return (this->*set)(static_cast<int>(type), value);
}

StreamAttr VtpStreamSocket::GetOption(int type) const
{
    StreamAttr attr {};
    auto it = optFuncMap_.find(type);
    if (it != optFuncMap_.end()) {
        MyGetFunc get = it->second.get;
        if (get == nullptr) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "Can not get option:%d", type);
            return std::move(StreamAttr());
        }
        if (type == NON_BLOCK) {
            attr = (this->*get)(static_cast<int>(streamFd_));
        }
        attr = (this->*get)(static_cast<int>(type));
    }

    PrintOptionInfo(type, attr);
    return attr;
}

bool VtpStreamSocket::SetStreamListener(std::shared_ptr<IStreamSocketListener> receiver)
{
    if (receiver == nullptr) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_WARN, "receiver is nullptr");
        return false;
    }

    std::lock_guard<std::mutex> guard(streamSocketLock_);
    streamReceiver_ = receiver;
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "set receiver success");
    return true;
}

bool VtpStreamSocket::InitVtpInstance(const std::string &pkgName)
{
    return vtpInstance_->InitVtp(pkgName);
}

void VtpStreamSocket::DestroyVtpInstance(const std::string &pkgName)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "DestroyVtpInstance start");
    vtpInstance_->DestroyVtp(pkgName);
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "DestroyVtpInstance end");
}

int VtpStreamSocket::CreateAndBindSocket(IpAndPort &local)
{
    localIpPort_ = local;
    vtpInstance_->UpdateSocketStreamCount(true);
    if (local.ip.empty()) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "ip is empty");
        return -1;
    }

    int sockFd = FtSocket(AF_INET, SOCK_STREAM, IPPROTO_FILLP);
    if (sockFd == -1) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "FtSocket failed, errorcode = %d", FtGetErrno());
        return -1;
    }

    // bind
    sockaddr_in localSockAddr = {0};
    localSockAddr.sin_family = AF_INET;
    localSockAddr.sin_port = htons((short)local.port);
    localSockAddr.sin_addr.s_addr = inet_addr(local.ip.c_str());

    socklen_t localAddrLen = sizeof(localSockAddr);
    int ret = FtBind(sockFd, reinterpret_cast<sockaddr *>(&localSockAddr), localAddrLen);
    if (ret == -1) {
        FtClose(sockFd);
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "FtBind failed, errorcode %d", FtGetErrno());
        return -1;
    }

    // 获取port
    ret = FtGetSockName(sockFd, reinterpret_cast<sockaddr *>(&localSockAddr), &localAddrLen);
    if (ret != ERR_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "getsockname error ret: %d, errorcode :%d", ret, FtGetErrno());
        FtClose(sockFd);
        return -1;
    }

    char host[ADDR_MAX_SIZE];
    localIpPort_.port = ntohs(localSockAddr.sin_port);
    localIpPort_.ip = inet_ntop(AF_INET, &(localSockAddr.sin_addr), host, ADDR_MAX_SIZE);
    local.port = localIpPort_.port;

    if (SetSocketBoundInner(sockFd, localIpPort_.ip) == false) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "SetSocketBoundInner failed, errorcode :%d", FtGetErrno());
    }
    return sockFd;
}

bool VtpStreamSocket::Accept()
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_DBG, "accept start");

    auto fd = FtAccept(listenFd_, nullptr, nullptr);
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "accept streamFd:%d", fd);
    if (fd == -1) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "errorcode = %d", FtGetErrno());
        return false;
    }

    sockaddr remoteAddr {};
    socklen_t remoteAddrLen = sizeof(remoteAddr);
    auto ret = FtGetPeerName(fd, &remoteAddr, &remoteAddrLen);
    if (ret != ERR_OK) {
        FtClose(fd);
        return false;
    }

    char host[ADDR_MAX_SIZE];
    if (remoteAddr.sa_family == AF_INET) {
        auto v4Addr = reinterpret_cast<const sockaddr_in *>(&remoteAddr);
        remoteIpPort_.ip = inet_ntop(AF_INET, &(v4Addr->sin_addr), host, ADDR_MAX_SIZE);
        remoteIpPort_.port = v4Addr->sin_port;
    } else {
        auto v6Addr = reinterpret_cast<const sockaddr_in6 *>(&remoteAddr);
        remoteIpPort_.ip = inet_ntop(AF_INET6, &(v6Addr->sin6_addr), host, ADDR_MAX_SIZE);
        remoteIpPort_.port = v6Addr->sin6_port;
    }

    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_DBG,
        "Accept a client(addr:%s, server port:%d)", remoteIpPort_.ip.c_str(), remoteIpPort_.port);
    SetDefaultConfig(fd);

    if (SetSocketEpollMode(fd) != ERR_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "SetSocketEpollMode failed, fd = %d", fd);
        FtClose(fd);
        return false;
    }

    std::lock_guard<std::mutex> guard(streamSocketLock_);
    streamFd_ = fd;
    configCv_.notify_all();

    if (streamReceiver_ != nullptr) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "notify stream connected!");
        streamReceiver_->OnStreamStatus(STREAM_CONNECTED);
    }

    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "accept success!");
    return true;
}

int VtpStreamSocket::EpollTimeout(int fd, int timeout)
{
    struct SpungeEpollEvent events[MAX_EPOLL_NUM];
    while (true) {
        FILLP_INT fdNum = FtEpollWait(epollFd_, events, MAX_EPOLL_NUM, timeout);
        if (fdNum <= 0) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR,
                "FtEpollWait failed, ret = %d, errno = %d", fdNum, FtGetErrno());
            return -FtGetErrno();
        }

        for (FILLP_INT i = 0; i < fdNum; i++) {
            if (events[i].data.fd != fd) {
                continue;
            }

            if (events[i].events & (SPUNGE_EPOLLHUP | SPUNGE_EPOLLERR)) {
                SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR,
                    "EpollTimeout, something may be wrong in this socket, fd = %d, events = %u", fd,
                    (unsigned int)events[i].events);
                return -1;
            }

            if (events[i].events & SPUNGE_EPOLLIN) {
                return 0;
            }
        }
    }
}

int VtpStreamSocket::SetSocketEpollMode(int fd)
{
    if (!SetNonBlockMode(fd, StreamAttr(true))) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "SetNonBlockMode failed, errno = %d", FtGetErrno());
        return -1;
    }

    struct SpungeEpollEvent event = {0};
    event.events = SPUNGE_EPOLLIN;
    event.data.fd = fd;

    auto ret = FtEpollCtl(epollFd_, SPUNGE_EPOLL_CTL_ADD, fd, &event);
    if (ret != ERR_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "FtEpollCtl failed, ret = %d, errno = %d", ret, FtGetErrno());
        return ret;
    }

    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "SetNonBlockMode success");
    return 0;
}

void VtpStreamSocket::InsertBufferLength(int num, int length, uint8_t *output) const
{
    for (int i = 0; i < length; i++) {
        output[length - 1 - i] = static_cast<unsigned int>(
            ((static_cast<unsigned int>(num) >> static_cast<unsigned int>(BYTE_TO_BIT * i))) & INT_TO_BYTE);
    }
}

std::unique_ptr<IStream> VtpStreamSocket::MakeStreamData(StreamData &data, const FrameInfo &info) const
{
    std::unique_ptr<IStream> stream = nullptr;
    switch (streamType_) {
        case VIDEO_SLICE_STREAM:
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_DBG, "do not support VIDEO_SLICE_STREAM type = %d", streamType_);
            break;
        case COMMON_VIDEO_STREAM:
        case COMMON_AUDIO_STREAM:
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_DBG,
                "streamType = %d, seqnum=%d, streamid=%d", streamType_, info.seqNum, info.streamId);
            stream = IStream::MakeCommonStream(data, info);
            break;
        case RAW_STREAM:
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_DBG, "streamType = %d", streamType_);
            stream = IStream::MakeRawStream(data, info);
            break;
        default:
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "do not support type = %d", streamType_);
            break;
    }
    if (stream == nullptr) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "IStream construct error");
        return nullptr;
    }

    return stream;
}

int VtpStreamSocket::RecvStreamLen()
{
    int hdrSize = FRAME_HEADER_LEN;
    if (streamType_ == RAW_STREAM && scene_ == COMPATIBLE_SCENE) {
        hdrSize = streamHdrSize_;
    }

    int len = -1;
    int timeout = -1;
    auto buffer = std::make_unique<char[]>(hdrSize);
    if (EpollTimeout(streamFd_, timeout) == 0) {
        do {
            len = FtRecv(streamFd_, buffer.get(), hdrSize, 0);
        } while (len <= 0 && (FtGetErrno() == EINTR || FtGetErrno() == FILLP_EAGAIN));
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_DBG, "recv frame header, len = %d, scene:%d", len, scene_);

    if (len <= 0) {
        return -1;
    }

    if (streamType_ == RAW_STREAM && scene_ == COMPATIBLE_SCENE) {
        std::lock_guard<std::mutex> guard(streamSocketLock_);
        if (streamReceiver_ != nullptr) {
            return streamReceiver_->OnStreamHdrReceived(std::move(buffer), hdrSize);
        }
    }

    return ntohl(*reinterpret_cast<int *>(buffer.get()));
}

void VtpStreamSocket::DoStreamRecv()
{
    while (isStreamRecv_) {
        std::unique_ptr<char[]> dataBuffer = nullptr;
        std::unique_ptr<char[]> extBuffer = nullptr;
        int extLen = 0;
        FrameInfo info = {};
        int dataLength = 0;

        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_DBG, "recv stream");
        dataLength = VtpStreamSocket::RecvStreamLen();
        if (dataLength <= 0 || dataLength > MAX_STREAM_LEN) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "read frame lenth error, dataLength = %d", dataLength);
            break;
        }
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_DBG,
            "recv a new frame, dataLength = %d, stream type:%d", dataLength, streamType_);
        dataBuffer = VtpStreamSocket::RecvStream(dataLength);

        if (streamType_ == COMMON_VIDEO_STREAM || streamType_ == COMMON_AUDIO_STREAM) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_DBG, "recv common stream");
            int decryptedLength = dataLength;
            auto decryptedBuffer = std::move(dataBuffer);

            int plainDataLength = decryptedLength - GetEncryptOverhead();
            std::unique_ptr<char[]> plainData = std::make_unique<char[]>(plainDataLength);
            ssize_t decLen = Decrypt(decryptedBuffer.get(), decryptedLength, plainData.get(), plainDataLength);
            if (decLen != plainDataLength) {
                SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR,
                    "Decrypt failed, dataLength = %d, decryptedLen = %zd", plainDataLength, decLen);
                break;
            }
            auto header = plainData.get();
            StreamDepacketizer decode(streamType_);
            decode.DepacketizeHeader(header);

            auto buffer = plainData.get() + sizeof(CommonHeader);
            decode.DepacketizeBuffer(buffer);

            extBuffer = decode.GetUserExt();
            extLen = decode.GetUserExtSize();
            info.seqNum = decode.GetSeqNum();
            info.streamId = decode.GetStreamId();
            dataBuffer = decode.GetData();
            dataLength = decode.GetDataLength();
            if (dataLength <= 0) {
                SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR,
                    "common depacketize error, dataLength = %d", dataLength);
                break;
            }
        }

        StreamData data = { std::move(dataBuffer), dataLength, std::move(extBuffer), extLen };
        std::unique_ptr<IStream> stream = MakeStreamData(data, info);
        if (stream == nullptr) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "MakeStreamData failed, stream == nullptr");
            break;
        }

        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_DBG,
            "recv frame done, dataLength = %d, stream type:%d", dataLength, streamType_);

        if (streamType_ == RAW_STREAM && scene_ == COMPATIBLE_SCENE) {
            std::lock_guard<std::mutex> guard(streamSocketLock_);
            if (streamReceiver_ != nullptr) {
                streamReceiver_->OnStreamReceived(std::move(stream));
                continue;
            }
        }

        PutStream(std::move(stream));
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_DBG,
            "put frame done, dataLength = %d, stream type:%d", dataLength, streamType_);
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "recv thread exit");
}

std::unique_ptr<char[]> VtpStreamSocket::RecvStream(int dataLength)
{
    auto buffer = std::make_unique<char[]>(dataLength);
    int recvLen = 0;
    while (recvLen < dataLength) {
        int ret = -1;
        int timeout = -1;

        if (EpollTimeout(streamFd_, timeout) == 0) {
            do {
                ret = FtRecv(streamFd_, (buffer.get() + recvLen), dataLength - recvLen, 0);
            } while (ret < 0 && (FtGetErrno() == EINTR || FtGetErrno() == FILLP_EAGAIN));
        }

        if (ret == -1) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "read frame failed, errno: %d", FtGetErrno());
            return nullptr;
        }

        recvLen += ret;
    }
    return std::unique_ptr<char[]>(buffer.release());
}

void VtpStreamSocket::SetDefaultConfig(int fd)
{
    if (!SetIpTos(fd, StreamAttr(static_cast<int>(IPTOS_LOWDELAY)))) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_WARN, "SetIpTos failed");
    }

    if (!SetOption(SEND_BUF_SIZE, StreamAttr(static_cast<int>(DEFAULT_UDP_BUFFER_SIZE)))) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_WARN, "Set send buff failed");
    }

    if (!SetOption(InnerStreamOptionType::RECV_CACHE, StreamAttr(static_cast<int>(FILLP_VTP_RECV_CACHE_SIZE)))) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_WARN, "Set recv cache failed");
    }

    if (!SetOption(InnerStreamOptionType::SEND_CACHE, StreamAttr(static_cast<int>(FILLP_VTP_SEND_CACHE_SIZE)))) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_WARN, "Set send cache failed");
    }
}

bool VtpStreamSocket::SetIpTos(int fd, const StreamAttr &tos)
{
    auto tmp = tos.GetIntValue();
    if (FtSetSockOpt(fd, IPPROTO_IP, IP_TOS, &tmp, sizeof(tmp)) != ERR_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "SetIpTos wrong! fd=%d, errorcode=%d", fd, FtGetErrno());
        return false;
    }

    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "Success to set ip tos: fd=%d, tos=%d", fd, tmp);
    return true;
}

StreamAttr VtpStreamSocket::GetIpTos(int type) const
{
    static_cast<void>(type);
    int tos;
    int size = sizeof(tos);

    if (FtGetSockOpt(streamFd_, IPPROTO_IP, IP_TOS, &tos, &size) != ERR_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "FtGetSockOpt errorcode = %d", FtGetErrno());
        return std::move(StreamAttr());
    }

    return std::move(StreamAttr(tos));
}

StreamAttr VtpStreamSocket::GetStreamSocketFd(int type) const
{
    static_cast<void>(type);
    return std::move(StreamAttr(streamFd_));
}

StreamAttr VtpStreamSocket::GetListenSocketFd(int type) const
{
    static_cast<void>(type);
    return std::move(StreamAttr(listenFd_));
}

bool VtpStreamSocket::SetSocketBoundInner(int fd, std::string ip) const
{
    auto boundIp = (ip == "") ? localIpPort_.ip : ip;
    struct ifaddrs *ifList = nullptr;
    if (getifaddrs(&ifList) < 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR,
            "get interface address return error %d (%s)", errno, strerror(errno));
        return false;
    }

    struct ifaddrs *ifa = nullptr;
    for (ifa = ifList; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr->sa_family != AF_INET) {
            continue;
        }

        std::string devName(ifa->ifa_name);
        if (strcmp(boundIp.c_str(), inet_ntoa(((struct sockaddr_in *)ifa->ifa_addr)->sin_addr)) == 0) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "current use interface %s to bind to socket", ifa->ifa_name);
            auto err = FtSetSockOpt(fd, SOL_SOCKET, SO_BINDTODEVICE, devName.c_str(), devName.size());
            if (err < 0) {
                SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "fail to set socket binding to device");
                return false;
            }
            break;
        }
    }
    return true;
}

bool VtpStreamSocket::SetSocketBindToDevices(int type, const StreamAttr &ip)
{
    static_cast<void>(type);
    auto tmp = ip.GetStrValue();
    auto boundIp = (tmp == "") ? localIpPort_.ip : tmp;
    return SetSocketBoundInner(streamFd_, boundIp);
}

bool VtpStreamSocket::SetVtpStackConfigDelayed(int type, const StreamAttr &value)
{
    std::unique_lock<std::mutex> lock(streamSocketLock_);
    if (streamFd_ == -1) {
        configCv_.wait(lock, [this] { return streamFd_ != -1; });
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "set vtp stack config, streamFd = %d", streamFd_);
    return SetVtpStackConfig(type, value);
}

bool VtpStreamSocket::SetVtpStackConfig(int type, const StreamAttr &value)
{
    if (streamFd_ == -1) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "set vtp stack config when streamFd is legal");
        auto self = GetSelf();
        std::thread([self, type, value]() { self->SetVtpStackConfigDelayed(type, value); }).detach();
        return true;
    }

    if (value.GetType() == INT_TYPE) {
        int intVal = value.GetIntValue();
        int ret = FtConfigSet(type, &intVal, &streamFd_);
        if (ret != 0) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR,
                "FtConfigSet failed, type = %d, errorcode = %d", type, FtGetErrno());
            return false;
        }

        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO,
            "setVtpConfig(%d) success, fd= %d, value= %d", type, streamFd_, intVal);
        return true;
    }

    if (value.GetType() == BOOL_TYPE) {
        bool flag = value.GetBoolValue();
        int ret = FtConfigSet(type, &flag, &streamFd_);
        if (ret != 0) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR,
                "FtConfigSet failed, type = %d, errorcode = %d", type, FtGetErrno());
            return false;
        }

        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO,
            "setVtpConfig(%d) success, fd= %d, value= %d", type, streamFd_, flag);
        return true;
    }

    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "UNKNOWN TYPE!");
    return false;
}

StreamAttr VtpStreamSocket::GetVtpStackConfig(int type) const
{
    int intVal;
    int configFd = (streamFd_ == -1) ? FILLP_CONFIG_ALL_SOCKET : streamFd_;
    int ret = FtConfigGet(type, &intVal, &configFd);
    if (ret != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR,
            "FtConfigGet failed, type = %d, errorcode = %d", type, FtGetErrno());
        return std::move(StreamAttr());
    }

    int valType = ValueType::UNKNOWN;
    for (auto it = FILLP_TYPE_MAP.begin(); it != FILLP_TYPE_MAP.end(); it++) {
        if (it->second != type) {
            continue;
        }

        valType = optFuncMap_.at(it->first).valueType;
        break;
    }

    if (valType != ValueType::UNKNOWN) {
        for (auto it = INNER_FILLP_TYPE_MAP.begin(); it != INNER_FILLP_TYPE_MAP.end(); it++) {
            if (it->second != type) {
                continue;
            }

            valType = optFuncMap_.at(it->first).valueType;
            break;
        }
    }

    if (valType == BOOL_TYPE) {
        return std::move(StreamAttr(!!intVal));
    }

    return std::move(StreamAttr(intVal));
}

bool VtpStreamSocket::SetNonBlockMode(int fd, const StreamAttr &value)
{
    FILLP_INT flags = FtFcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "failed to get FtFcntl, flags = %d", flags);
        flags = 0;
    }
    bool nonBlock = value.GetBoolValue();

    flags = nonBlock ? static_cast<FILLP_INT>((static_cast<FILLP_UINT>(flags) | O_NONBLOCK)) :
        static_cast<FILLP_INT>((static_cast<FILLP_UINT>(flags) & ~O_NONBLOCK));

    FILLP_INT res = FtFcntl(fd, F_SETFL, flags);
    if (res < 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "failed to set FtFcntl, res = %d", res);
        return false;
    }

    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "Successfully to set fd(%d) nonBlock mode = %d", fd, nonBlock);
    return true;
}

StreamAttr VtpStreamSocket::GetNonBlockMode(int fd) const
{
    FILLP_INT flags = FtFcntl(fd, F_GETFL, 0);
    if (static_cast<unsigned int>(flags) & O_NONBLOCK) {
        return std::move(StreamAttr(true));
    }

    return std::move(StreamAttr(false));
}

StreamAttr VtpStreamSocket::GetIp(int type) const
{
    if (type == LOCAL_IP) {
        return std::move(StreamAttr(localIpPort_.ip));
    }

    return std::move(StreamAttr(remoteIpPort_.ip));
}

StreamAttr VtpStreamSocket::GetPort(int type) const
{
    if (type == LOCAL_PORT) {
        return std::move(StreamAttr(localIpPort_.port));
    }
    return std::move(StreamAttr(remoteIpPort_.port));
}

bool VtpStreamSocket::SetStreamType(int type, const StreamAttr &value)
{
    if (type != STREAM_TYPE_INT) {
        return false;
    }

    streamType_ = value.GetIntValue();
    return true;
}

StreamAttr VtpStreamSocket::GetStreamType(int type) const
{
    if (type != STREAM_TYPE_INT) {
        return std::move(StreamAttr());
    }

    return std::move(StreamAttr(streamType_));
}

bool VtpStreamSocket::SetStreamScene(int type, const StreamAttr &value)
{
    static_cast<void>(type);
    if (value.GetType() != INT_TYPE) {
        return false;
    }
    scene_ = value.GetIntValue();
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "Set scene to %d", scene_);
    return true;
}

bool VtpStreamSocket::SetStreamHeaderSize(int type, const StreamAttr &value)
{
    static_cast<void>(type);
    if (value.GetType() != INT_TYPE) {
        return false;
    }
    streamHdrSize_ = value.GetIntValue();
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "Set header size to %d", streamHdrSize_);
    return true;
}

void VtpStreamSocket::NotifyStreamListener()
{
    while (isStreamRecv_) {
        int streamNum = GetStreamNum();
        if (streamNum >= STREAM_BUFFER_THRESHOLD) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_WARN, "Too many data in receiver, num = %d", streamNum);
        }

        auto stream = TakeStream();
        if (stream == nullptr) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "Pop stream failed");
            break;
        }

        std::lock_guard<std::mutex> guard(streamSocketLock_);
        if (streamReceiver_ != nullptr) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_DBG, "notify listener");
            streamReceiver_->OnStreamReceived(std::move(stream));
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_DBG, "notify listener done.");
        }
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "notify thread exit");
}

ssize_t VtpStreamSocket::GetEncryptOverhead() const
{
    return OVERHEAD_LEN;
}

ssize_t VtpStreamSocket::Encrypt(const void *in, ssize_t inLen, void *out, ssize_t outLen) const
{
    AesGcmCipherKey cipherKey = {0};

    if (inLen - OVERHEAD_LEN > outLen) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "Encrypt invalid para.");
        return SOFTBUS_ERR;
    }

    cipherKey.keyLen = SESSION_KEY_LENGTH;
    if (memcpy_s(cipherKey.key, SESSION_KEY_LENGTH, sessionKey_.c_str(), SESSION_KEY_LENGTH) != EOK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "memcpy key error.");
        return SOFTBUS_ERR;
    }

    int ret = SoftBusEncryptData(&cipherKey, (unsigned char *)in, inLen, (unsigned char *)out, (unsigned int *)&outLen);
    (void)memset_s(&cipherKey, sizeof(AesGcmCipherKey), 0, sizeof(AesGcmCipherKey));
    if (ret != SOFTBUS_OK || outLen != inLen + OVERHEAD_LEN) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "Encrypt Data fail. %d", ret);
        return SOFTBUS_ENCRYPT_ERR;
    }
    return outLen;
}

ssize_t VtpStreamSocket::Decrypt(const void *in, ssize_t inLen, void *out, ssize_t outLen) const
{
    AesGcmCipherKey cipherKey = {0};

    if (inLen - OVERHEAD_LEN > outLen) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "Decrypt invalid para.");
        return SOFTBUS_ERR;
    }

    cipherKey.keyLen = SESSION_KEY_LENGTH; // 256 bit encryption
    if (memcpy_s(cipherKey.key, SESSION_KEY_LENGTH, sessionKey_.c_str(), SESSION_KEY_LENGTH) != EOK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "memcpy key error.");
        return SOFTBUS_ERR;
    }
    int ret = SoftBusDecryptData(&cipherKey, (unsigned char *)in, inLen, (unsigned char *)out, (unsigned int *)&outLen);
    (void)memset_s(&cipherKey, sizeof(AesGcmCipherKey), 0, sizeof(AesGcmCipherKey));
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "Decrypt Data fail. %d ", ret);
        return SOFTBUS_DECRYPT_ERR;
    }

    return outLen;
}

void VtpStreamSocket::GetCryptErrorReason(void) const
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_DBG, "Unsupport api");
}
} // namespace SoftBus
} // namespace Communication
