/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#ifndef VTP_STREAM_SOCKET_H
#define VTP_STREAM_SOCKET_H

#include <condition_variable>
#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <utility>

#include "fillpinc.h"

#include "common_inner.h"
#include "i_stream.h"
#include "i_stream_socket.h"
#include "stream_common.h"
#include "vtp_instance.h"
#include "vtp_stream_opt.h"

namespace Communication {
namespace SoftBus {
struct ConnectStatus {
    enum {
        UNCONNECTED,
        CONNECTED,
        CLOSED,
    };

    int status = UNCONNECTED;
};

class VtpStreamSocket : public std::enable_shared_from_this<VtpStreamSocket>, public IStreamSocket {
public:
    static constexpr int FILLP_VTP_SEND_CACHE_SIZE = 500;
    static constexpr int FILLP_VTP_RECV_CACHE_SIZE = 500;
    static constexpr int FILLP_KEEP_ALIVE_TIME = 300000;

    VtpStreamSocket();
    ~VtpStreamSocket() override;
    std::shared_ptr<VtpStreamSocket> GetSelf();

    bool CreateClient(IpAndPort &local, int streamType, std::pair<uint8_t*, uint32_t> sessionKey) override;
    bool CreateClient(IpAndPort &local, const IpAndPort &remote, int streamType,
        std::pair<uint8_t*, uint32_t> sessionKey) override;

    bool CreateServer(IpAndPort &local, int streamType, std::pair<uint8_t*, uint32_t> sessionKey) override;

    void DestroyStreamSocket() override;

    bool Connect(const IpAndPort &remote) override;
    bool Send(std::unique_ptr<IStream> stream) override;

    bool SetOption(int type, const StreamAttr &value) override;
    int32_t SetMultiLayer(const void *para) override;
    StreamAttr GetOption(int type) const override;

    bool SetStreamListener(std::shared_ptr<IStreamSocketListener> receiver) override;

    static bool InitVtpInstance(const std::string &pkgName);
    static void DestroyVtpInstance(const std::string &pkgName);

    ssize_t GetEncryptOverhead() const;

    ssize_t Encrypt(const void *in, ssize_t inLen, void *out, ssize_t outLen) const;

    ssize_t Decrypt(const void *in, ssize_t inLen, void *out, ssize_t outLen) const;

private:
    using MySetFunc = bool (VtpStreamSocket::*)(int, const StreamAttr &);
    using MyGetFunc = StreamAttr (VtpStreamSocket::*)(int) const;
    struct OptionFunc {
        ValueType valueType;
        MySetFunc set;
        MyGetFunc get;
    };

    const std::map<int, FillpConfigAppListEnum> FILLP_TYPE_MAP {
        { SEND_CACHE, FT_CONF_SEND_CACHE },           { RECV_CACHE, FT_CONF_RECV_CACHE },
        { SEND_BUF_SIZE, FT_CONF_SEND_BUFFER_SIZE },  { RECV_BUF_SIZE, FT_CONF_RECV_BUFFER_SIZE },
        { PACKET_SIZE, FT_CONF_PACKET_SIZE },         { KEEP_ALIVE_TIMEOUT, FT_CONF_TIMER_KEEP_ALIVE },
        { MAX_VTP_SOCKET_NUM, FT_CONF_MAX_SOCK_NUM }, { MAX_VTP_CONNECT_NUM, FT_CONF_MAX_CONNECTION_NUM },
        { REDUNANCY_SWITCH, FT_CONF_USE_FEC },        { REDUNANCY_LEVEL, FT_CONF_FEC_REDUNDANCY_LEVEL },
    };

    const std::map<int, FillpConfigAppListEnum> INNER_FILLP_TYPE_MAP {
        { NACK_DELAY, FT_CONF_ENABLE_NACK_DELAY },
        { NACK_DELAY_TIMEOUT, FT_CONF_NACK_DELAY_TIMEOUT },
        { PACK_INTERVAL_ENLARGE, FT_CONF_ENLARGE_PACK_INTERVAL },
        { PKT_STATISTICS, FT_CONF_APP_FC_STATISTICS },
        { PKT_LOSS, FT_CONF_APP_FC_RECV_PKT_LOSS },
    };
    bool EncryptStreamPacket(std::unique_ptr<IStream> stream, std::unique_ptr<char[]> &data, ssize_t &len);
    bool ProcessCommonDataStream(std::unique_ptr<char[]> &dataBuffer, int32_t &dataLength,
        std::unique_ptr<char[]> &extBuffer, int32_t &extLen, StreamFrameInfo &info);
    void InsertElementToFuncMap(int type, ValueType valueType, MySetFunc set, MyGetFunc get);
    int CreateAndBindSocket(IpAndPort &local, bool isServer) override;
    bool Accept() override;

    int EpollTimeout(int fd, int timeout) override;
    int SetSocketEpollMode(int fd) override;

    void InsertBufferLength(int num, int length, uint8_t *output) const;
    std::unique_ptr<IStream> MakeStreamData(StreamData &data, const StreamFrameInfo &info) const;
    int32_t RecvStreamLen();
    void DoStreamRecv();
    std::unique_ptr<char[]> RecvStream(int32_t dataLength) override;

    void SetDefaultConfig(int fd);
    bool SetIpTos(int fd, const StreamAttr &tos);
    StreamAttr GetIpTos(int type = -1) const;
    StreamAttr GetStreamSocketFd(int type = -1) const;
    StreamAttr GetListenSocketFd(int type = -1) const;
    bool SetSocketBoundInner(int fd, std::string ip = "") const;
    bool SetSocketBindToDevices(int type, const StreamAttr &ip);
    bool SetVtpStackConfigDelayed(int type, const StreamAttr &value);
    bool SetVtpStackConfig(int type, const StreamAttr &value);
    StreamAttr GetVtpStackConfig(int type) const;
    bool SetNonBlockMode(int fd, const StreamAttr &value);
    StreamAttr GetNonBlockMode(int fd) const;
    StreamAttr GetIp(int type) const;
    StreamAttr GetPort(int type) const;
    bool SetStreamType(int type, const StreamAttr &value);
    StreamAttr GetStreamType(int type) const;
    StreamAttr GetIpType(int type) const
    {
        if (type != static_cast<int>(IP_TYPE)) {
            return std::move(StreamAttr());
        }
        return std::move(StreamAttr(std::string("V4")));
    }
    StreamAttr GetRemoteScopeId(int type) const
    {
        if (type != static_cast<int>(REMOTE_SCOPE_ID)) {
            return std::move(StreamAttr());
        }
        return std::move(StreamAttr(0));
    }

    StreamAttr IsServer(int type) const
    {
        if (type != static_cast<int>(IS_SERVER)) {
            return std::move(StreamAttr());
        }
        return std::move(StreamAttr(listenFd_ != -1));
    }

    bool SetStreamScene(int type, const StreamAttr &value);
    bool SetStreamHeaderSize(int type, const StreamAttr &value);

    void NotifyStreamListener();

    bool EnableBwEstimationAlgo(int streamFd, bool isServer) const;

    bool EnableJitterDetectionAlgo(int streamFd) const;

    bool EnableDirectlySend(int streamFd) const;

    bool EnableSemiReliable(int streamFd) const;

    void RegisterMetricCallback(bool isServer); /* register the metric callback function */

    static void AddStreamSocketLock(int fd, std::mutex &streamsocketlock);

    static void AddStreamSocketListener(int fd, std::shared_ptr<VtpStreamSocket> streamreceiver);

    static void RemoveStreamSocketLock(int fd);

    static void RemoveStreamSocketListener(int fd);

    static int HandleFillpFrameStats(int fd, const FtEventCbkInfo *info);

    static int HandleRipplePolicy(int fd, const FtEventCbkInfo *info);

    static int HandleFillpFrameEvt(int fd, const FtEventCbkInfo *info);

    int HandleFillpFrameEvtInner(int fd, const FtEventCbkInfo *info);

    static int FillpStatistics(int fd, const FtEventCbkInfo *info);

    void FillpAppStatistics();

    static void FillSupportDet(int fd, const FtEventCbkInfo *info, QosTv* metricList);

    void CreateServerProcessThread();

    void CreateClientProcessThread();

    static std::map<int, std::mutex &> g_streamSocketLockMap;
    static std::mutex g_streamSocketLockMapLock_;
    static std::map<int, std::shared_ptr<VtpStreamSocket>> g_streamSocketMap;
    static std::mutex g_streamSocketMapLock_;

    std::map<int, OptionFunc> optFuncMap_ {};
    static std::shared_ptr<VtpInstance> vtpInstance_;
    std::condition_variable configCv_;
    std::mutex streamSocketLock_;
    int scene_ = UNKNOWN_SCENE;
    int streamHdrSize_ = 0;
    bool isDestroyed_ = false;
    OnFrameEvt onStreamEvtCb_ = nullptr;
};
} // namespace SoftBus
} // namespace Communication

#endif
