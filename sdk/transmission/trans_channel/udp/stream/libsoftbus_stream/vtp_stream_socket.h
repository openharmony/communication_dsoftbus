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

    bool CreateClient(IpAndPort &local, int32_t streamType, std::pair<uint8_t *, uint32_t> sessionKey) override;
    bool CreateClient(IpAndPort &local, const IpAndPort &remote, int32_t streamType,
        std::pair<uint8_t*, uint32_t> sessionKey) override;

    bool CreateServer(IpAndPort &local, int32_t streamType, std::pair<uint8_t *, uint32_t> sessionKey) override;

    void DestroyStreamSocket() override;

    bool Connect(const IpAndPort &remote) override;
    bool Send(std::unique_ptr<IStream> stream) override;

    bool SetOption(int32_t type, const StreamAttr &value) override;
    int32_t SetMultiLayer(const void *para) override;
    StreamAttr GetOption(int32_t type) const override;

    bool SetStreamListener(std::shared_ptr<IStreamSocketListener> receiver) override;

    static bool InitVtpInstance(const std::string &pkgName);
    static void DestroyVtpInstance(const std::string &pkgName);

    ssize_t GetEncryptOverhead() const;

    ssize_t Encrypt(const void *in, ssize_t inLen, void *out, ssize_t outLen) const;

    ssize_t Decrypt(const void *in, ssize_t inLen, void *out, ssize_t outLen) const;

private:
    using MySetFunc = bool (VtpStreamSocket::*)(int32_t, const StreamAttr &);
    using MyGetFunc = StreamAttr (VtpStreamSocket::*)(int32_t) const;
    struct OptionFunc {
        ValueType valueType;
        MySetFunc set;
        MyGetFunc get;
    };

    const std::map<int32_t, FillpConfigAppListEnum> FILLP_TYPE_MAP {
        { SEND_CACHE, FT_CONF_SEND_CACHE },           { RECV_CACHE, FT_CONF_RECV_CACHE },
        { SEND_BUF_SIZE, FT_CONF_SEND_BUFFER_SIZE },  { RECV_BUF_SIZE, FT_CONF_RECV_BUFFER_SIZE },
        { PACKET_SIZE, FT_CONF_PACKET_SIZE },         { KEEP_ALIVE_TIMEOUT, FT_CONF_TIMER_KEEP_ALIVE },
        { MAX_VTP_SOCKET_NUM, FT_CONF_MAX_SOCK_NUM }, { MAX_VTP_CONNECT_NUM, FT_CONF_MAX_CONNECTION_NUM },
        { REDUNANCY_SWITCH, FT_CONF_USE_FEC },        { REDUNANCY_LEVEL, FT_CONF_FEC_REDUNDANCY_LEVEL },
    };

    const std::map<int32_t, FillpConfigAppListEnum> INNER_FILLP_TYPE_MAP {
        { NACK_DELAY, FT_CONF_ENABLE_NACK_DELAY },
        { NACK_DELAY_TIMEOUT, FT_CONF_NACK_DELAY_TIMEOUT },
        { PACK_INTERVAL_ENLARGE, FT_CONF_ENLARGE_PACK_INTERVAL },
        { PKT_STATISTICS, FT_CONF_APP_FC_STATISTICS },
        { PKT_LOSS, FT_CONF_APP_FC_RECV_PKT_LOSS },
    };
    bool EncryptStreamPacket(std::unique_ptr<IStream> stream, std::unique_ptr<char[]> &data, ssize_t &len);
    bool ProcessCommonDataStream(std::unique_ptr<char[]> &dataBuffer, int32_t &dataLength,
        std::unique_ptr<char[]> &extBuffer, int32_t &extLen, StreamFrameInfo &info);
    void InsertElementToFuncMap(int32_t type, ValueType valueType, MySetFunc set, MyGetFunc get);
    int32_t CreateAndBindSocket(IpAndPort &local, bool isServer) override;
    bool Accept() override;

    int32_t EpollTimeout(int32_t fd, int32_t timeout) override;
    int32_t SetSocketEpollMode(int32_t fd) override;

    void InsertBufferLength(int32_t num, int32_t length, uint8_t *output) const;
    std::unique_ptr<IStream> MakeStreamData(StreamData &data, const StreamFrameInfo &info) const;
    int32_t RecvStreamLen();
    void DoStreamRecv();
    std::unique_ptr<char[]> RecvStream(int32_t dataLength) override;

    void SetDefaultConfig(int32_t fd);
    bool SetIpTos(int32_t fd, const StreamAttr &tos);
    StreamAttr GetIpTos(int32_t type = -1) const;
    StreamAttr GetStreamSocketFd(int32_t type = -1) const;
    StreamAttr GetListenSocketFd(int32_t type = -1) const;
    bool SetSocketBoundInner(int32_t fd, std::string ip = "") const;
    bool SetSocketBindToDevices(int32_t type, const StreamAttr &ip);
    bool SetVtpStackConfigDelayed(int32_t type, const StreamAttr &value);
    bool SetVtpStackConfig(int32_t type, const StreamAttr &value);
    StreamAttr GetVtpStackConfig(int32_t type) const;
    bool SetNonBlockMode(int32_t fd, const StreamAttr &value);
    StreamAttr GetNonBlockMode(int32_t fd) const;
    StreamAttr GetIp(int32_t type) const;
    StreamAttr GetPort(int32_t type) const;
    bool SetStreamType(int32_t type, const StreamAttr &value);
    StreamAttr GetStreamType(int32_t type) const;
    StreamAttr GetIpType(int32_t type) const
    {
        if (type != static_cast<int32_t>(IP_TYPE)) {
            return std::move(StreamAttr());
        }
        return std::move(StreamAttr(std::string("V4")));
    }
    StreamAttr GetRemoteScopeId(int32_t type) const
    {
        if (type != static_cast<int32_t>(REMOTE_SCOPE_ID)) {
            return std::move(StreamAttr());
        }
        return std::move(StreamAttr(0));
    }

    StreamAttr IsServer(int32_t type) const
    {
        if (type != static_cast<int32_t>(IS_SERVER)) {
            return std::move(StreamAttr());
        }
        return std::move(StreamAttr(listenFd_ != -1));
    }

    bool SetStreamScene(int32_t type, const StreamAttr &value);
    bool SetStreamHeaderSize(int32_t type, const StreamAttr &value);

    void NotifyStreamListener();

    bool EnableBwEstimationAlgo(int32_t streamFd, bool isServer) const;

    bool EnableJitterDetectionAlgo(int32_t streamFd) const;

    bool EnableDirectlySend(int32_t streamFd) const;

    bool EnableSemiReliable(int32_t streamFd) const;

    void RegisterMetricCallback(bool isServer); /* register the metric callback function */

    static void AddStreamSocketLock(int32_t fd, std::mutex &streamsocketlock);

    static void AddStreamSocketListener(int32_t fd, std::shared_ptr<VtpStreamSocket> streamreceiver);

    static void RemoveStreamSocketLock(int32_t fd);

    static void RemoveStreamSocketListener(int32_t fd);

    static int32_t HandleFillpFrameStats(int32_t fd, const FtEventCbkInfo *info);

    static int32_t HandleRipplePolicy(int32_t fd, const FtEventCbkInfo *info);

    static int32_t HandleFillpFrameEvt(int32_t fd, const FtEventCbkInfo *info);

    int32_t HandleFillpFrameEvtInner(int32_t fd, const FtEventCbkInfo *info);

    static int32_t FillpStatistics(int32_t fd, const FtEventCbkInfo *info);

    void FillpAppStatistics();

    static void FillSupportDet(int32_t fd, const FtEventCbkInfo *info, QosTv* metricList);

    void CreateServerProcessThread();

    void CreateClientProcessThread();

    static std::map<int32_t, std::mutex &> g_streamSocketLockMap;
    static std::mutex streamSocketLockMapLock_;
    static std::map<int32_t, std::shared_ptr<VtpStreamSocket>> g_streamSocketMap;
    static std::mutex streamSocketMapLock_;

    std::map<int32_t, OptionFunc> optFuncMap_ {};
    static std::shared_ptr<VtpInstance> vtpInstance_;
    std::condition_variable configCv_;
    std::mutex streamSocketLock_;
    int32_t scene_ = UNKNOWN_SCENE;
    int32_t streamHdrSize_ = 0;
    bool isDestroyed_ = false;
    OnFrameEvt onStreamEvtCb_;
};
} // namespace SoftBus
} // namespace Communication

#endif
