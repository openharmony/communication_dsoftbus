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

#include "vtp_stream_socket.h"

#include <chrono>
#include <ifaddrs.h>
#include <memory>
#include <netinet/in.h>
#include <securec.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <thread>

#include "fillpinc.h"
#include "raw_stream_data.h"
#include "session.h"
#include "softbus_adapter_crypto.h"
#include "softbus_adapter_socket.h"
#include "softbus_adapter_timer.h"
#include "softbus_error_code.h"
#include "softbus_trans_def.h"
#include "stream_common_data.h"
#include "stream_depacketizer.h"
#include "stream_packetizer.h"
#include "vtp_stream_opt.h"

namespace Communication {
namespace SoftBus {
bool g_logOn = false;
const int FEED_BACK_PERIOD = 1;  /* feedback period of fillp stream traffic statistics is 1s */
const int MS_PER_SECOND = 1000;
const int US_PER_MS = 1000;

namespace {
void PrintOptionInfo(int type, const StreamAttr &value)
{
    switch (value.GetType()) {
        case INT_TYPE:
            TRANS_LOGI(TRANS_STREAM,
                "Int option: type=%{public}d, value=%{public}d", type, value.GetIntValue());
            break;
        case BOOL_TYPE:
            TRANS_LOGI(TRANS_STREAM,
                "Bool option: type=%{public}d, value=%{public}d", type, value.GetBoolValue());
            break;
        case STRING_TYPE:
            TRANS_LOGD(TRANS_STREAM,
                "String option: type=%{public}d, value=%{public}s", type, value.GetStrValue().c_str());
            break;
        default:
            TRANS_LOGE(TRANS_STREAM, "Wrong StreamAttr!");
            (void)type;
    }
}
} // namespace
std::shared_ptr<VtpInstance> VtpStreamSocket::vtpInstance_ = VtpInstance::GetVtpInstance();

std::map<int, std::mutex &> VtpStreamSocket::g_streamSocketLockMap;
std::mutex VtpStreamSocket::g_streamSocketLockMapLock_;
std::map<int, std::shared_ptr<VtpStreamSocket>> VtpStreamSocket::g_streamSocketMap;
std::mutex VtpStreamSocket::g_streamSocketMapLock_;

static inline void ConvertStreamFrameInfo2FrameInfo(FrameInfo* frameInfo,
    const Communication::SoftBus::StreamFrameInfo* streamFrameInfo)
{
    frameInfo->frameType = (FILLP_INT)(streamFrameInfo->frameType);
    frameInfo->seqNum = (FILLP_INT)(streamFrameInfo->seqNum);
    frameInfo->subSeqNum = (FILLP_INT)(streamFrameInfo->seqSubNum);
    frameInfo->level = (FILLP_INT)(streamFrameInfo->level);
    frameInfo->timestamp = (FILLP_SLONG)streamFrameInfo->timeStamp;
    frameInfo->bitMap = (FILLP_UINT32)streamFrameInfo->bitMap;
}

void VtpStreamSocket::AddStreamSocketLock(int fd, std::mutex &streamsocketlock)
{
    std::lock_guard<std::mutex> guard(g_streamSocketLockMapLock_);
    if (!g_streamSocketLockMap.empty() && g_streamSocketLockMap.find(fd) != g_streamSocketLockMap.end()) {
        TRANS_LOGE(TRANS_STREAM, "streamsocketlock for the fd already exists. fd=%{public}d", fd);
        return;
    }

    g_streamSocketLockMap.emplace(std::pair<int, std::mutex &>(fd, streamsocketlock));
}

void VtpStreamSocket::AddStreamSocketListener(int fd, std::shared_ptr<VtpStreamSocket> streamreceiver)
{
    std::lock_guard<std::mutex> guard(g_streamSocketMapLock_);
    if (!g_streamSocketMap.empty() && g_streamSocketMap.find(fd) != g_streamSocketMap.end()) {
        TRANS_LOGE(TRANS_STREAM, "streamreceiver for the fd already exists. fd=%{public}d", fd);
        return;
    }

    g_streamSocketMap.emplace(std::pair<int, std::shared_ptr<VtpStreamSocket>>(fd, streamreceiver));
}

void VtpStreamSocket::RemoveStreamSocketLock(int fd)
{
    std::lock_guard<std::mutex> guard(g_streamSocketLockMapLock_);
    if (g_streamSocketLockMap.find(fd) != g_streamSocketLockMap.end()) {
        g_streamSocketLockMap.erase(fd);
        TRANS_LOGI(TRANS_STREAM, "Remove streamsocketlock for the fd success. fd=%{public}d", fd);
    } else {
        TRANS_LOGE(TRANS_STREAM,
            "Streamsocketlock for the fd not exist in the map. fd=%{public}d", fd);
    }
}

void VtpStreamSocket::RemoveStreamSocketListener(int fd)
{
    std::lock_guard<std::mutex> guard(g_streamSocketMapLock_);
    if (g_streamSocketMap.find(fd) != g_streamSocketMap.end()) {
        g_streamSocketMap.erase(fd);
        TRANS_LOGI(TRANS_STREAM, "Remove streamreceiver for the fd success. fd=%{public}d", fd);
    } else {
        TRANS_LOGE(TRANS_STREAM, "Streamreceiver for the fd not exist in the map. fd=%{public}d", fd);
    }
}

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
    TRANS_LOGW(TRANS_STREAM, "~VtpStreamSocket");
}

std::shared_ptr<VtpStreamSocket> VtpStreamSocket::GetSelf()
{
    return shared_from_this();
}

int VtpStreamSocket::HandleFillpFrameStats(int fd, const FtEventCbkInfo *info)
{
    if (info == nullptr) {
        TRANS_LOGE(TRANS_STREAM, "stats info is nullptr");
        return SOFTBUS_INVALID_PARAM;
    }
    StreamSendStats stats = {};
    if (memcpy_s(&stats, sizeof(StreamSendStats), &info->info.frameSendStats,
        sizeof(info->info.frameSendStats)) != EOK) {
        TRANS_LOGE(TRANS_STREAM, "streamStats info memcpy fail");
        return SOFTBUS_MEM_ERR;
    }

    std::lock_guard<std::mutex> guard(g_streamSocketMapLock_);
    auto itListener = g_streamSocketMap.find(fd);
    if (itListener != g_streamSocketMap.end()) {
        if (itListener->second->streamReceiver_ != nullptr) {
            TRANS_LOGD(TRANS_STREAM, "OnFrameStats enter");
            itListener->second->streamReceiver_->OnFrameStats(&stats);
        } else {
            TRANS_LOGE(TRANS_STREAM, "streamReceiver_ is nullptr");
        }
    } else {
        TRANS_LOGE(TRANS_STREAM, "StreamReceiver for the fd is empty in the map. fd=%{public}d", fd);
    }
    return SOFTBUS_OK;
}

int VtpStreamSocket::HandleRipplePolicy(int fd, const FtEventCbkInfo *info)
{
    if (info == nullptr) {
        TRANS_LOGE(TRANS_STREAM, "policy info is nullptr");
        return SOFTBUS_INVALID_PARAM;
    }
    TrafficStats stats;
    (void)memset_s(&stats, sizeof(TrafficStats), 0, sizeof(TrafficStats));
    if (memcpy_s(&stats.stats, sizeof(stats.stats), info->info.trafficData.stats,
        sizeof(info->info.trafficData.stats)) != EOK) {
        TRANS_LOGE(TRANS_STREAM, "RipplePolicy info memcpy fail");
        return SOFTBUS_MEM_ERR;
    }
    std::lock_guard<std::mutex> guard(g_streamSocketMapLock_);
    auto itListener = g_streamSocketMap.find(fd);
    if (itListener != g_streamSocketMap.end()) {
        if (itListener->second->streamReceiver_ != nullptr) {
            TRANS_LOGI(TRANS_STREAM, "OnRippleStats enter");
            itListener->second->streamReceiver_->OnRippleStats(&stats);
        } else {
            TRANS_LOGE(TRANS_STREAM, "OnRippleStats streamReceiver_ is nullptr");
        }
    } else {
        TRANS_LOGE(TRANS_STREAM,
            "OnRippleStats streamReceiver for the fd is empty in the map. fd=%{public}d", fd);
    }
    return SOFTBUS_OK;
}

int VtpStreamSocket::HandleFillpFrameEvt(int fd, const FtEventCbkInfo *info)
{
    if (info == nullptr) {
        TRANS_LOGE(TRANS_STREAM, "fd is %{public}d, info is nullptr", fd);
        return SOFTBUS_INVALID_PARAM;
    }
    std::lock_guard<std::mutex> guard(g_streamSocketMapLock_);
    auto itListener = g_streamSocketMap.find(fd);
    if (itListener != g_streamSocketMap.end()) {
        return itListener->second->HandleFillpFrameEvtInner(fd, info);
    } else {
        TRANS_LOGE(TRANS_STREAM, "OnFillpFrameEvt for the fd is empty in the map. fd=%{public}d", fd);
    }
    return SOFTBUS_OK;
}

int VtpStreamSocket::HandleFillpFrameEvtInner(int fd, const FtEventCbkInfo *info)
{
    if (onStreamEvtCb_ != nullptr) {
        TRANS_LOGD(TRANS_STREAM, "onStreamEvtCb_ enter");
        return HandleVtpFrameEvt(fd, onStreamEvtCb_, info);
    } else {
        TRANS_LOGD(TRANS_STREAM, "onStreamEvtCb_ is nullptr");
    }
    return SOFTBUS_OK;
}

#ifdef FILLP_SUPPORT_BW_DET
void VtpStreamSocket::FillSupportDet(int fd, const FtEventCbkInfo *info, QosTv *metricList)
{
    if (info == nullptr || metricList == nullptr) {
        TRANS_LOGE(TRANS_STREAM, "info or metricList is nullptr");
        return;
    }
    if (info->evt == FT_EVT_BW_DET) {
        TRANS_LOGI(TRANS_STREAM,
            "[Metric Return]: Fillp bandwidth information of socket fd=%{public}d is returned", fd);
        TRANS_LOGI(TRANS_STREAM,
            "[Metric Return]: Changed amount of current available bandwidth=%{public}d", info->info.bwInfo.bwStat);
        TRANS_LOGI(TRANS_STREAM,
            "[Metric Return]: Current bandwidth for receiving data rate=%{public}d kbps", info->info.bwInfo.rate);
        metricList->type = BANDWIDTH_ESTIMATE_VALUE;
        metricList->info.bandwidthInfo.trend = info->info.bwInfo.bwStat;
        metricList->info.bandwidthInfo.rate = info->info.bwInfo.rate;
    }
    if (info->evt == FT_EVT_JITTER_DET) {
        TRANS_LOGI(TRANS_STREAM,
            "[Metric Return]: Fillp connection quality information of socket fd=%{public}d is returned", fd);
        TRANS_LOGI(TRANS_STREAM,
            "[Metric Return]: Predeicted network condition jitterLevel=%{public}d", info->info.jitterInfo.jitterLevel);
        TRANS_LOGI(TRANS_STREAM,
            "[Metric Return]: Current available receiving buffer time=%{public}d ms", info->info.jitterInfo.bufferTime);
        metricList->type = JITTER_DETECTION_VALUE;
        metricList->info.jitterInfo.jitterLevel = info->info.jitterInfo.jitterLevel;
        metricList->info.jitterInfo.bufferTime = info->info.jitterInfo.bufferTime;
    }
}
#endif

/* This function is used to prompt the metrics returned by FtApiRegEventCallbackFunc() function */
int VtpStreamSocket::FillpStatistics(int fd, const FtEventCbkInfo *info)
{
    if (info == nullptr || fd < 0) {
        TRANS_LOGE(TRANS_STREAM, "param invalid fd is %{public}d", fd);
        return SOFTBUS_INVALID_PARAM;
    }
    if (info->evt == FT_EVT_FRAME_STATS) {
        TRANS_LOGI(TRANS_STREAM, "recv fillp frame stats");
        return HandleFillpFrameStats(fd, info);
    } else if (info->evt == FT_EVT_TRAFFIC_DATA) {
        TRANS_LOGI(TRANS_STREAM, "recv fillp traffic data");
        return HandleRipplePolicy(fd, info);
    } else if (IsVtpFrameSentEvt(info)) {
        TRANS_LOGI(TRANS_STREAM, "fd %{public}d recv fillp frame send evt", fd);
        return HandleFillpFrameEvt(fd, info);
    }
#ifdef FILLP_SUPPORT_BW_DET
    if (info->evt == FT_EVT_BW_DET || info->evt == FT_EVT_JITTER_DET) {
        int32_t eventId = TRANS_STREAM_QUALITY_EVENT;
        int16_t tvCount = 1;
        QosTv metricList = {};

        FillSupportDet(fd, info, &metricList);
        metricList.info.wifiChannelInfo = {};
        metricList.info.frameStatusInfo = {};

        std::lock_guard<std::mutex> guard(g_streamSocketLockMapLock_);
        auto itLock = g_streamSocketLockMap.find(fd);
        if (itLock != g_streamSocketLockMap.end()) {
            std::lock_guard<std::mutex> guard(g_streamSocketMapLock_);
            auto itListener = g_streamSocketMap.find(fd);
            if (itListener != g_streamSocketMap.end()) {
                std::thread([itListener, eventId, tvCount, metricList, &itLock]() {
                    const std::string threadName = "OS_qosEvent";
                    pthread_setname_np(pthread_self(), threadName.c_str());
                    std::lock_guard<std::mutex> guard(itLock->second);
                    itListener->second->OnQosEvent(eventId, tvCount, &metricList);
                }).detach();
            } else {
                TRANS_LOGE(TRANS_STREAM, "StreamReceiver for fd=%{public}d is empty in the map", fd);
            }
        } else {
            TRANS_LOGE(TRANS_STREAM, "StreamSocketLock for fd=%{public}d is empty in the map", fd);
        }
    } else {
        TRANS_LOGE(TRANS_STREAM,
            "[Metric Return]: Fail to retrieve bandwidth and connection quality information");
        return -1;
    }
#endif
    return SOFTBUS_OK;
}

void VtpStreamSocket::FillpAppStatistics()
{
    int32_t eventId = TRANS_STREAM_QUALITY_EVENT;
    int16_t tvCount = 1;
    QosTv metricList = {};
    FillpStatisticsPcb fillpPcbStats = {};
    SoftBusSysTime fillpStatsGetTime = {0};

    int getStatisticsRet = FtFillpStatsGet(streamFd_, &fillpPcbStats);
    SoftBusGetTime(&fillpStatsGetTime);
    if (getStatisticsRet == 0) {
        metricList.type = STREAM_TRAFFIC_STASTICS;
        metricList.info.appStatistics.statisticsGotTime = static_cast<uint64_t>((fillpStatsGetTime.sec *
            MS_PER_SECOND + fillpStatsGetTime.usec / US_PER_MS)); /* ms */
        metricList.info.appStatistics.periodRecvBits =
            static_cast<uint64_t>(fillpPcbStats.appFcStastics.periodRecvBits);
        metricList.info.appStatistics.pktNum = fillpPcbStats.appFcStastics.pktNum;
        metricList.info.appStatistics.periodRecvPkts = fillpPcbStats.appFcStastics.periodRecvPkts;
        metricList.info.appStatistics.periodRecvPktLoss = fillpPcbStats.appFcStastics.periodRecvPktLoss;
        metricList.info.appStatistics.periodRecvRate = fillpPcbStats.appFcStastics.periodRecvRate;
        metricList.info.appStatistics.periodRecvRateBps = fillpPcbStats.appFcStastics.periodRecvRateBps;
        metricList.info.appStatistics.periodRtt = fillpPcbStats.appFcStastics.periodRtt;
        metricList.info.appStatistics.periodRecvPktLossHighPrecision =
            fillpPcbStats.appFcStastics.periodRecvPktLossHighPrecision;
        metricList.info.appStatistics.periodSendLostPkts = fillpPcbStats.appFcStastics.periodSendLostPkts;
        metricList.info.appStatistics.periodSendPkts = fillpPcbStats.appFcStastics.periodSendPkts;
        metricList.info.appStatistics.periodSendPktLossHighPrecision =
            fillpPcbStats.appFcStastics.periodSendPktLossHighPrecision;
        metricList.info.appStatistics.periodSendBits = fillpPcbStats.appFcStastics.periodSendBits;
        metricList.info.appStatistics.periodSendRateBps = fillpPcbStats.appFcStastics.periodSendRateBps;

        TRANS_LOGD(TRANS_STREAM,
            "Succeed to get fillp statistics information for streamfd=%{public}d", streamFd_);
        TRANS_LOGD(TRANS_STREAM,
            "[Metric Return]: periodRtt=%{public}d", fillpPcbStats.appFcStastics.periodRtt);

        std::lock_guard<std::mutex> guard(streamSocketLock_);

        if (streamReceiver_ != nullptr) {
            TRANS_LOGD(TRANS_STREAM,
                "[Metric Notify]: Fillp traffic statistics information of socket is notified. streamfd=%{public}d",
                streamFd_);
            streamReceiver_->OnQosEvent(eventId, tvCount, &metricList);
        } else {
            TRANS_LOGE(TRANS_STREAM, "StreamReceiver for the streamFd is empty. streamFd=%{public}d", streamFd_);
        }
    } else {
        TRANS_LOGE(TRANS_STREAM,
            "Fail to get fillp statistics information for the streamfd. streamfd=%{public}d, errno=%{public}d",
            streamFd_, FtGetErrno());
    }
}

bool VtpStreamSocket::CreateClient(IpAndPort &local, int streamType, std::pair<uint8_t*, uint32_t> sessionKey)
{
    int fd = CreateAndBindSocket(local, false);
    if (fd == -1) {
        TRANS_LOGE(TRANS_STREAM, "CreateAndBindSocket failed, errno=%{public}d", FtGetErrno());
        DestroyStreamSocket();
        return false;
    }

    sessionKey_.second = sessionKey.second;
    if (sessionKey_.first == nullptr) {
        sessionKey_.first = new uint8_t[sessionKey_.second];
    }
    if (memcpy_s(sessionKey_.first, sessionKey_.second, sessionKey.first, sessionKey.second) != EOK) {
        TRANS_LOGE(TRANS_STREAM, "memcpy key error.");
        return false;
    }

    streamType_ = streamType;
    std::lock_guard<std::mutex> guard(streamSocketLock_);
    streamFd_ = fd;
    configCv_.notify_all();

    TRANS_LOGI(TRANS_STREAM,
        "Success to create a client socket. fd=%{public}d, streamType=%{public}d", fd, streamType);
    return true;
}

bool VtpStreamSocket::CreateClient(IpAndPort &local, const IpAndPort &remote, int streamType,
    std::pair<uint8_t*, uint32_t> sessionKey)
{
    if (!CreateClient(local, streamType, sessionKey)) {
        return false;
    }
    /* enable the bandwidth and CQE estimation algorithms by FtSetSockOpt() for current ftsocket */
#ifdef FILLP_SUPPORT_BW_DET
    bool isServer = false;
    EnableBwEstimationAlgo(streamFd_, isServer);
#endif

    bool connectRet = Connect(remote);
    if (connectRet) {
        bool isServer = false;
        RegisterMetricCallback(isServer); /* register the callback function */
    }
    return connectRet;
}

bool VtpStreamSocket::CreateServer(IpAndPort &local, int streamType, std::pair<uint8_t*, uint32_t> sessionKey)
{
    TRANS_LOGD(TRANS_STREAM, "enter.");
    listenFd_ = CreateAndBindSocket(local, true);
    if (listenFd_ == -1) {
        TRANS_LOGE(TRANS_STREAM, "create listenFd failed, errno=%{public}d", FtGetErrno());
        DestroyStreamSocket();
        return false;
    }

    bool ret = FtListen(listenFd_, MAX_CONNECTION_VALUE);
    if (ret) {
        TRANS_LOGE(TRANS_STREAM, "FtListen failed, ret=%{public}d, errno=%{public}d", ret, FtGetErrno());
        DestroyStreamSocket();
        return false;
    }

    epollFd_ = FtEpollCreate();
    if (epollFd_ < 0) {
        TRANS_LOGE(TRANS_STREAM, "Failed to create epoll fd errno=%{public}d", FtGetErrno());
        DestroyStreamSocket();
        return false;
    }
    isStreamRecv_ = true;
    streamType_ = streamType;
    sessionKey_.second = sessionKey.second;
    if (sessionKey_.first == nullptr) {
        sessionKey_.first = new uint8_t[sessionKey_.second];
    }
    if (memcpy_s(sessionKey_.first, sessionKey_.second, sessionKey.first, sessionKey.second) != EOK) {
        TRANS_LOGE(TRANS_STREAM, "memcpy key error.");
        return false;
    }

    CreateServerProcessThread();
    TRANS_LOGI(TRANS_STREAM,
        "CreateServer end, listenFd=%{public}d, epollFd=%{public}d, streamType=%{public}d", listenFd_, epollFd_,
        streamType_);
    return true;
}

void VtpStreamSocket::DestroyStreamSocket()
{
    TRANS_LOGD(TRANS_STREAM, "enter.");
    std::lock_guard<std::mutex> guard(streamSocketLock_);
    if (isDestroyed_) {
        TRANS_LOGI(TRANS_STREAM, "StreamSocket is already destroyed");
        return;
    }
    if (listenFd_ != -1) {
        TRANS_LOGI(TRANS_STREAM, "listenFd_ enter FtClose");
        FtClose(listenFd_);
        listenFd_ = -1;
    }

    if (streamFd_ != -1) {
        RemoveStreamSocketLock(streamFd_); /* remove the socket lock from the map */
        RemoveStreamSocketListener(streamFd_); /* remove the socket listener from the map */
        TRANS_LOGI(TRANS_STREAM, "streamFd_ enter FtClose");
        FtClose(streamFd_);
        streamFd_ = -1;
    }

    if (epollFd_ != -1) {
        TRANS_LOGI(TRANS_STREAM, "epollFd_ enter FtClose");
        FtClose(epollFd_);
        epollFd_ = -1;
    }

    if (streamReceiver_ != nullptr) {
        TRANS_LOGI(TRANS_STREAM, "DestroyStreamSocket receiver delete");
        streamReceiver_->OnStreamStatus(STREAM_CLOSED);
        streamReceiver_.reset();
    }

    QuitStreamBuffer();
    vtpInstance_->UpdateSocketStreamCount(false);
    isDestroyed_ = true;
    TRANS_LOGD(TRANS_STREAM, "ok");
}

bool VtpStreamSocket::Connect(const IpAndPort &remote)
{
    if (remote.ip.empty()) {
        TRANS_LOGE(TRANS_STREAM, "remote addr  error, ip is nullptr");
        DestroyStreamSocket();
        return false;
    }

    TRANS_LOGD(TRANS_STREAM,
        "Connect to server remotePort=%{public}d", remote.port);
    remoteIpPort_ = remote;

    struct sockaddr_in remoteSockAddr;
    remoteSockAddr.sin_family = AF_INET;
    remoteSockAddr.sin_port = htons(static_cast<short>(remote.port));
    remoteSockAddr.sin_addr.s_addr = inet_addr(remote.ip.c_str());

    int ret = FtConnect(streamFd_, reinterpret_cast<struct sockaddr *>(&remoteSockAddr), sizeof(remoteSockAddr));
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_STREAM, "FtConnect failed, ret=%{public}d, errno=%{public}d", ret, FtGetErrno());
        DestroyStreamSocket();
        return false;
    }

    epollFd_ = FtEpollCreate();
    if (epollFd_ < 0) {
        TRANS_LOGE(TRANS_STREAM, "Failed to create epoll fd errno=%{public}d", FtGetErrno());
        DestroyStreamSocket();
        return false;
    }

    if (SetSocketEpollMode(streamFd_) != ERR_OK) {
        TRANS_LOGE(TRANS_STREAM, "SetSocketEpollMode failed, streamFd=%{public}d", streamFd_);
        DestroyStreamSocket();
        return false;
    }
    isStreamRecv_ = true;
    TRANS_LOGI(TRANS_STREAM, "Success to connect remote, and create a thread to recv data.");

    CreateClientProcessThread();
    return true;
}

bool VtpStreamSocket::EncryptStreamPacket(std::unique_ptr<IStream> stream, std::unique_ptr<char[]> &data, ssize_t &len)
{
    StreamPacketizer packet(streamType_, std::move(stream));
    auto plainData = packet.PacketizeStream();
    if (plainData == nullptr) {
        TRANS_LOGE(TRANS_STREAM, "PacketizeStream failed");
        return false;
    }
    len = packet.GetPacketLen() + GetEncryptOverhead();
    TRANS_LOGD(TRANS_STREAM, "packetLen=%{public}zd, encryptOverhead=%{public}zd",
        packet.GetPacketLen(), GetEncryptOverhead());
    data = std::make_unique<char[]>(len + FRAME_HEADER_LEN);
    ssize_t encLen = Encrypt(plainData.get(), packet.GetPacketLen(), data.get() + FRAME_HEADER_LEN, len);
    if (encLen != len) {
        TRANS_LOGE(TRANS_STREAM, "encrypted failed, dataLen=%{public}zd, encLen=%{public}zd", len, encLen);
        return false;
    }
    InsertBufferLength(len, FRAME_HEADER_LEN, reinterpret_cast<uint8_t *>(data.get()));
    len += FRAME_HEADER_LEN;

    return true;
}

bool VtpStreamSocket::Send(std::unique_ptr<IStream> stream)
{
    TRANS_LOGD(TRANS_STREAM, "send in... streamType=%{public}d, dataSize=%{public}zd, extSize=%{public}zd",
        streamType_, stream->GetBufferLen(), stream->GetExtBufferLen());

    if (!isBlocked_) {
        isBlocked_ = true;
        if (!SetNonBlockMode(streamFd_, StreamAttr(false))) {
            TRANS_LOGE(TRANS_STREAM, "set non block mode fail");
            return false;
        }
    }

    int32_t ret = -1;
    std::unique_ptr<char[]> data = nullptr;
    ssize_t len = 0;

    const Communication::SoftBus::StreamFrameInfo *streamFrameInfo = stream->GetStreamFrameInfo();
    if (streamFrameInfo == nullptr) {
        TRANS_LOGE(TRANS_STREAM, "streamFrameInfo is null");
        return false;
    }
    FrameInfo frameInfo;
    ConvertStreamFrameInfo2FrameInfo(&frameInfo, streamFrameInfo);

    if (streamType_ == RAW_STREAM) {
        data = stream->GetBuffer();
        len = stream->GetBufferLen();

        ret = FtSendFrame(streamFd_, data.get(), len, 0, &frameInfo);
    } else if (streamType_ == COMMON_VIDEO_STREAM || streamType_ == COMMON_AUDIO_STREAM) {
        if (!EncryptStreamPacket(std::move(stream), data, len)) {
            return false;
        }
        ret = FtSendFrame(streamFd_, data.get(), len, 0, &frameInfo);
    }

    if (ret == -1) {
        TRANS_LOGE(TRANS_STREAM, "send failed, errno=%{public}d", FtGetErrno());
        return false;
    }

    TRANS_LOGD(TRANS_STREAM, "send out..., streamType=%{public}d, len=%{public}zd", streamType_, len);
    return true;
}

bool VtpStreamSocket::SetOption(int type, const StreamAttr &value)
{
    PrintOptionInfo(type, value);
    auto it = optFuncMap_.find(type);
    if (it == optFuncMap_.end()) {
        TRANS_LOGW(TRANS_STREAM, "not found type=%{public}d", type);
        return false;
    }

    if (value.GetType() != it->second.valueType) {
        TRANS_LOGW(TRANS_STREAM,
            "type=%{public}d, valueType=%{public}d", value.GetType(), it->second.valueType);
        return false;
    }

    MySetFunc set = it->second.set;
    if (set == nullptr) {
        TRANS_LOGW(TRANS_STREAM, "set is nullptr");
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
            TRANS_LOGE(TRANS_STREAM, "Can not get option type=%{public}d", type);
            return std::move(StreamAttr());
        }
        if (type == NON_BLOCK) {
            attr = (this->*get)(static_cast<int>(streamFd_));
        } else {
            attr = (this->*get)(static_cast<int>(type));
        }
    }

    PrintOptionInfo(type, attr);
    return attr;
}

bool VtpStreamSocket::SetStreamListener(std::shared_ptr<IStreamSocketListener> receiver)
{
    if (receiver == nullptr) {
        TRANS_LOGW(TRANS_STREAM, "receiver is nullptr");
        return false;
    }

    std::lock_guard<std::mutex> guard(streamSocketLock_);
    streamReceiver_ = receiver;
    TRANS_LOGI(TRANS_STREAM, "set receiver success");
    return true;
}

bool VtpStreamSocket::InitVtpInstance(const std::string &pkgName)
{
    return vtpInstance_->InitVtp(pkgName);
}

void VtpStreamSocket::DestroyVtpInstance(const std::string &pkgName)
{
    TRANS_LOGD(TRANS_STREAM, "enter.");
    vtpInstance_->DestroyVtp(pkgName);
    TRANS_LOGD(TRANS_STREAM, "ok");
}

int VtpStreamSocket::CreateAndBindSocket(IpAndPort &local, bool isServer)
{
    localIpPort_ = local;
    vtpInstance_->UpdateSocketStreamCount(true);
    if (local.ip.empty()) {
        TRANS_LOGE(TRANS_STREAM, "ip is empty");
        return -1;
    }

    int sockFd = FtSocket(AF_INET, SOCK_STREAM, IPPROTO_FILLP);
    if (sockFd == -1) {
        TRANS_LOGE(TRANS_STREAM, "FtSocket failed, errno=%{public}d", FtGetErrno());
        return -1;
    }
    if (!isServer) {
        TRANS_LOGI(TRANS_STREAM, "FtSocket set client, errno=%{public}d", FtGetErrno());
        streamFd_ = sockFd;
    }
    SetDefaultConfig(sockFd);

    // bind
    sockaddr_in localSockAddr = { 0 };
    char host[ADDR_MAX_SIZE];
    localSockAddr.sin_family = AF_INET;
    localSockAddr.sin_port = htons((short)local.port);
    localSockAddr.sin_addr.s_addr = inet_addr(local.ip.c_str());
    localIpPort_.ip = SoftBusInetNtoP(AF_INET, &(localSockAddr.sin_addr), host, ADDR_MAX_SIZE);
    if (!SetSocketBoundInner(sockFd, localIpPort_.ip)) {
        TRANS_LOGE(TRANS_STREAM, "SetSocketBoundInner failed, errno=%{public}d", FtGetErrno());
    }

    socklen_t localAddrLen = sizeof(localSockAddr);
    int ret = FtBind(sockFd, reinterpret_cast<sockaddr *>(&localSockAddr), localAddrLen);
    if (ret == -1) {
        FtClose(sockFd);
        TRANS_LOGE(TRANS_STREAM, "FtBind failed, errno=%{public}d", FtGetErrno());
        return -1;
    }

    // 获取port
    ret = FtGetSockName(sockFd, reinterpret_cast<sockaddr *>(&localSockAddr), &localAddrLen);
    if (ret != ERR_OK) {
        TRANS_LOGE(TRANS_STREAM, "getsockname error ret=%{public}d, errno=%{public}d", ret, FtGetErrno());
        FtClose(sockFd);
        return -1;
    }

    localIpPort_.port = static_cast<int32_t>(ntohs(localSockAddr.sin_port));
    local.port = localIpPort_.port;

    return sockFd;
}


bool VtpStreamSocket::EnableBwEstimationAlgo(int streamFd, bool isServer) const
{
#ifdef FILLP_SUPPORT_BW_DET
    int errBwDet;
    if (isServer) {
        int32_t enableBwDet = FILLP_BW_DET_RX_ENABLE;
        errBwDet = FtSetSockOpt(streamFd, IPPROTO_FILLP, FILLP_SOCK_BW_DET_ALGO,
            &enableBwDet, sizeof(enableBwDet));
    } else {
        int32_t enableBwDet = FILLP_BW_DET_TX_ENABLE;
        errBwDet = FtSetSockOpt(streamFd, IPPROTO_FILLP, FILLP_SOCK_BW_DET_ALGO,
            &enableBwDet, sizeof(enableBwDet));
    }
    if (errBwDet < 0) {
        TRANS_LOGE(TRANS_STREAM,
            "Fail to enable bandwidth estimation algorithm for streamFd=%{public}d, errno%{public}d",
            streamFd, FtGetErrno());
        return true;
    } else {
        TRANS_LOGE(TRANS_STREAM,
            "Success to enable bandwidth estimation algorithm for stream=Fd%{public}d", streamFd);
        return false;
    }
#else
    return true;
#endif
}

bool VtpStreamSocket::EnableJitterDetectionAlgo(int streamFd) const
{
#ifdef FILLP_SUPPORT_CQE
    int32_t  enableCQE = FILLP_CQE_ENABLE;
    auto errCQE = FtSetSockOpt(streamFd, IPPROTO_FILLP, FILLP_SOCK_CQE_ALGO, &enableCQE, sizeof(enableCQE));
    if (errCQE < 0) {
        TRANS_LOGE(TRANS_STREAM,
            "Fail to enable CQE algorithm for streamFd=%{public}d, errno=%{public}d", streamFd, FtGetErrno());
        return true;
    } else {
        TRANS_LOGE(TRANS_STREAM,
            "Success to enable CQE algorithm for streamFd=%{public}d", streamFd);
        return false;
    }
#else
    return true;
#endif
}

bool VtpStreamSocket::EnableDirectlySend(int streamFd) const
{
    int32_t enable = 1;
    FILLP_INT ret = FtSetSockOpt(streamFd, IPPROTO_FILLP, FILLP_SOCK_DIRECTLY_SEND, &enable, sizeof(enable));
    if (ret < 0) {
        TRANS_LOGE(TRANS_STREAM,
            "Fail to enable direct send for streamFd=%{public}d, rrno=%{public}d", streamFd, FtGetErrno());
        return false;
    }
    TRANS_LOGI(TRANS_STREAM, "Success to enable direct send for streamFd=%{public}d", streamFd);
    return true;
}

bool VtpStreamSocket::EnableSemiReliable(int streamFd) const
{
    int32_t enable = 1;
    FILLP_INT ret = FtSetSockOpt(streamFd, IPPROTO_FILLP, FILLP_SEMI_RELIABLE, &enable, sizeof(enable));
    if (ret < 0) {
        TRANS_LOGE(TRANS_STREAM,
            "Fail to enable direct send for streamFd=%{public}d, errno=%{public}d", streamFd, FtGetErrno());
        return false;
    }
    TRANS_LOGI(TRANS_STREAM, "Success to enable semi reliable for streamFd=%{public}d", streamFd);
    return true;
}

void VtpStreamSocket::RegisterMetricCallback(bool isServer)
{
    VtpStreamSocket::AddStreamSocketLock(streamFd_, streamSocketLock_);
    auto self = this->GetSelf();
    VtpStreamSocket::AddStreamSocketListener(streamFd_, self);
    int regStatisticsRet = FtApiRegEventCallbackFunc(FILLP_CONFIG_ALL_SOCKET, FillpStatistics);
    int value = 1;
    auto err = FtSetSockOpt(streamFd_, IPPROTO_FILLP, FILLP_SOCK_TRAFFIC, &value, sizeof(value));
    if (err < 0) {
        TRANS_LOGE(TRANS_STREAM, "fail to set socket binding to device");
        return;
    }
    TRANS_LOGD(TRANS_STREAM, "FtSetSockOpt start success");
    if (isServer) {
        if (regStatisticsRet == 0) {
            TRANS_LOGI(TRANS_STREAM,
                "Success to register the stream callback function at server side. streamFd=%{public}d", streamFd_);
        } else {
            TRANS_LOGE(TRANS_STREAM,
                "Fail to register the stream callback function at server side. streamFd=%{public}d, errno=%{public}d",
                streamFd_, regStatisticsRet);
        }
    } else {
        if (regStatisticsRet == 0) {
            TRANS_LOGI(TRANS_STREAM,
                "Success to register the stream callback function at client side. streamFd=%{public}d", streamFd_);
        } else {
            TRANS_LOGE(TRANS_STREAM,
                "Fail to register the stream callback function at client side. streamFd=%{public}d, errno=%{public}d",
                streamFd_, regStatisticsRet);
        }
    }
}

bool VtpStreamSocket::Accept()
{
    TRANS_LOGD(TRANS_STREAM, "enter.");
    auto fd = FtAccept(listenFd_, nullptr, nullptr);
    TRANS_LOGI(TRANS_STREAM, "accept streamFd=%{public}d", fd);
    if (fd == -1) {
        TRANS_LOGE(TRANS_STREAM, "errno=%{public}d", FtGetErrno());
        return false;
    }

    sockaddr remoteAddr {};
    socklen_t remoteAddrLen = sizeof(remoteAddr);
    auto ret = FtGetPeerName(fd, &remoteAddr, &remoteAddrLen);
    if (ret != ERR_OK) {
        TRANS_LOGE(TRANS_STREAM, "get name failed, fd=%{public}d", fd);
        FtClose(fd);
        return false;
    }

    char host[ADDR_MAX_SIZE];
    if (remoteAddr.sa_family == AF_INET) {
        auto v4Addr = reinterpret_cast<const sockaddr_in *>(&remoteAddr);
        remoteIpPort_.ip = SoftBusInetNtoP(AF_INET, &(v4Addr->sin_addr), host, ADDR_MAX_SIZE);
        remoteIpPort_.port = v4Addr->sin_port;
    } else {
        auto v6Addr = reinterpret_cast<const sockaddr_in6 *>(&remoteAddr);
        remoteIpPort_.ip = SoftBusInetNtoP(AF_INET6, &(v6Addr->sin6_addr), host, ADDR_MAX_SIZE);
        remoteIpPort_.port = v6Addr->sin6_port;
    }

    TRANS_LOGD(TRANS_STREAM, "Accept a client remotePort=%{public}d", remoteIpPort_.port);

    if (SetSocketEpollMode(fd) != ERR_OK) {
        TRANS_LOGE(TRANS_STREAM, "SetSocketEpollMode failed, fd=%{public}d", fd);
        FtClose(fd);
        return false;
    }

    std::lock_guard<std::mutex> guard(streamSocketLock_);
    streamFd_ = fd;
    configCv_.notify_all();

    if (streamReceiver_ != nullptr) {
        TRANS_LOGI(TRANS_STREAM, "notify stream connected!");
        streamReceiver_->OnStreamStatus(STREAM_CONNECTED);
    }

    bool isServer = true;
    RegisterMetricCallback(isServer); /* register the callback function */
    /* enable the bandwidth and CQE estimation algorithms for current ftsocket */
#ifdef FILLP_SUPPORT_BW_DET
    EnableBwEstimationAlgo(streamFd_, isServer);
#endif
#ifdef FILLP_SUPPORT_CQE
    EnableJitterDetectionAlgo(streamFd_);
#endif

    TRANS_LOGI(TRANS_STREAM, "accept success!");
    return true;
}

int VtpStreamSocket::EpollTimeout(int fd, int timeout)
{
    struct SpungeEpollEvent events[MAX_EPOLL_NUM];
    (void)memset_s(events, sizeof(events), 0, sizeof(events));
    while (true) {
        FILLP_INT fdNum = FtEpollWait(epollFd_, events, MAX_EPOLL_NUM, timeout);
        if (fdNum <= 0) {
            TRANS_LOGE(TRANS_STREAM,
                "FtEpollWait failed, ret=%{public}d, errno=%{public}d", fdNum, FtGetErrno());
            return -FtGetErrno();
        }

        for (FILLP_INT i = 0; i < fdNum; i++) {
            if (events[i].data.fd != fd) {
                continue;
            }

            if (events[i].events & (SPUNGE_EPOLLHUP | SPUNGE_EPOLLERR)) {
                TRANS_LOGE(TRANS_STREAM,
                    "EpollTimeout, something may be wrong in this socket, fd=%{public}d, events=%{public}u", fd,
                    (unsigned int)events[i].events);
                return -1;
            }

            if (events[i].events & SPUNGE_EPOLLIN) {
                return SOFTBUS_OK;
            }
        }
    }
}

int VtpStreamSocket::SetSocketEpollMode(int fd)
{
    if (!SetNonBlockMode(fd, StreamAttr(true))) {
        TRANS_LOGE(TRANS_STREAM, "SetNonBlockMode failed, errno=%{public}d", FtGetErrno());
        return -1;
    }

    struct SpungeEpollEvent event = {0};
    event.events = SPUNGE_EPOLLIN;
    event.data.fd = fd;

    auto ret = FtEpollCtl(epollFd_, SPUNGE_EPOLL_CTL_ADD, fd, &event);
    if (ret != ERR_OK) {
        TRANS_LOGE(TRANS_STREAM, "FtEpollCtl failed, ret=%{public}d, errno=%{public}d", ret, FtGetErrno());
        return ret;
    }

    TRANS_LOGD(TRANS_STREAM, "SetNonBlockMode success");
    return SOFTBUS_OK;
}

void VtpStreamSocket::InsertBufferLength(int num, int length, uint8_t *output) const
{
    for (int i = 0; i < length; i++) {
        output[length - 1 - i] = static_cast<unsigned int>(
            ((static_cast<unsigned int>(num) >> static_cast<unsigned int>(BYTE_TO_BIT * i))) & INT_TO_BYTE);
    }
}

std::unique_ptr<IStream> VtpStreamSocket::MakeStreamData(StreamData &data, const StreamFrameInfo &info) const
{
    std::unique_ptr<IStream> stream = nullptr;
    switch (streamType_) {
        case VIDEO_SLICE_STREAM:
            TRANS_LOGD(TRANS_STREAM, "do not support VIDEO_SLICE_STREAM streamType=%{public}d", streamType_);
            break;
        case COMMON_VIDEO_STREAM:
        case COMMON_AUDIO_STREAM:
            TRANS_LOGD(TRANS_STREAM,
                "streamType=%{public}d, seqNum=%{public}d, streamId=%{public}d",
                streamType_, info.seqNum, info.streamId);
            stream = IStream::MakeCommonStream(data, info);
            break;
        case RAW_STREAM:
            TRANS_LOGD(TRANS_STREAM, "streamType=%{public}d", streamType_);
            stream = IStream::MakeRawStream(data, info);
            break;
        default:
            TRANS_LOGE(TRANS_STREAM, "do not support streamType=%{public}d", streamType_);
            break;
    }
    if (stream == nullptr) {
        TRANS_LOGE(TRANS_STREAM, "IStream construct error");
        return nullptr;
    }

    return stream;
}

int32_t VtpStreamSocket::RecvStreamLen()
{
    int32_t hdrSize = FRAME_HEADER_LEN;
    if (streamType_ == RAW_STREAM && scene_ == COMPATIBLE_SCENE) {
        hdrSize = streamHdrSize_;
    }

    int32_t len = -1;
    int32_t timeout = -1;
    auto buffer = std::make_unique<char[]>(hdrSize);
    if (EpollTimeout(streamFd_, timeout) == 0) {
        do {
            len = FtRecv(streamFd_, buffer.get(), hdrSize, 0);
        } while (len <= 0 && (FtGetErrno() == EINTR || FtGetErrno() == FILLP_EAGAIN));
    }
    TRANS_LOGD(TRANS_STREAM, "recv frame header, len=%{public}d, scene=%{public}d", len, scene_);

    if (len <= 0) {
        TRANS_LOGE(TRANS_STREAM, "len invalid, len=%{public}d", len);
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

bool VtpStreamSocket::ProcessCommonDataStream(std::unique_ptr<char[]> &dataBuffer,
    int32_t &dataLength, std::unique_ptr<char[]> &extBuffer, int32_t &extLen, StreamFrameInfo &info)
{
    TRANS_LOGD(TRANS_STREAM, "recv common stream");
    int32_t decryptedLength = dataLength;
    auto decryptedBuffer = std::move(dataBuffer);

    int32_t plainDataLength = decryptedLength - GetEncryptOverhead();
    if (plainDataLength <= 0) {
        TRANS_LOGE(TRANS_STREAM, "Decrypt failed, invalid decryptedLen=%{public}d", decryptedLength);
        return false;
    }
    std::unique_ptr<char[]> plainData = std::make_unique<char[]>(plainDataLength);
    ssize_t decLen = Decrypt(decryptedBuffer.get(), decryptedLength, plainData.get(), plainDataLength);
    if (decLen != plainDataLength) {
        TRANS_LOGE(TRANS_STREAM,
            "Decrypt failed, dataLen=%{public}d, decryptedLen=%{public}zd", plainDataLength, decLen);
        return false;
    }
    auto header = plainData.get();
    StreamDepacketizer decode(streamType_);
    if (plainDataLength < static_cast<int32_t>(sizeof(CommonHeader))) {
        TRANS_LOGE(TRANS_STREAM,
            "failed, plainDataLen=%{public}d, CommonHeader=%{public}zu", plainDataLength, sizeof(CommonHeader));
        return false;
    }
    decode.DepacketizeHeader(header);

    auto buffer = plainData.get() + sizeof(CommonHeader);
    decode.DepacketizeBuffer(buffer, plainDataLength - sizeof(CommonHeader));

    extBuffer = decode.GetUserExt();
    extLen = decode.GetUserExtSize();
    info = decode.GetFrameInfo();
    dataBuffer = decode.GetData();
    dataLength = decode.GetDataLength();
    if (dataLength <= 0) {
        TRANS_LOGE(TRANS_STREAM, "common depacketize error, dataLen=%{public}d", dataLength);
        return false;
    }
    return true;
}

void VtpStreamSocket::DoStreamRecv()
{
    while (isStreamRecv_) {
        std::unique_ptr<char[]> dataBuffer = nullptr;
        std::unique_ptr<char[]> extBuffer = nullptr;
        int32_t extLen = 0;
        StreamFrameInfo info = {};
        TRANS_LOGD(TRANS_STREAM, "recv stream");
        int32_t dataLength = VtpStreamSocket::RecvStreamLen();
        if (dataLength <= 0 || dataLength > MAX_STREAM_LEN) {
            TRANS_LOGE(TRANS_STREAM, "read frame length error, dataLength=%{public}d", dataLength);
            break;
        }
        TRANS_LOGD(TRANS_STREAM,
            "recv a new frame, dataLen=%{public}d, streamType=%{public}d", dataLength, streamType_);
        dataBuffer = VtpStreamSocket::RecvStream(dataLength);

        if (streamType_ == COMMON_VIDEO_STREAM || streamType_ == COMMON_AUDIO_STREAM) {
            if (!ProcessCommonDataStream(dataBuffer, dataLength, extBuffer, extLen, info)) {
                break;
            }
        }

        StreamData data = { std::move(dataBuffer), dataLength, std::move(extBuffer), extLen };
        std::unique_ptr<IStream> stream = MakeStreamData(data, info);
        if (stream == nullptr) {
            TRANS_LOGE(TRANS_STREAM, "MakeStreamData failed, stream is null");
            break;
        }

        TRANS_LOGD(TRANS_STREAM,
            "recv frame done, dataLen=%{public}d, streamType=%{public}d", dataLength, streamType_);

        if (streamType_ == RAW_STREAM && scene_ == COMPATIBLE_SCENE) {
            std::lock_guard<std::mutex> guard(streamSocketLock_);
            if (streamReceiver_ != nullptr) {
                streamReceiver_->OnStreamReceived(std::move(stream));
                continue;
            }
        }

        PutStream(std::move(stream));
        TRANS_LOGD(TRANS_STREAM, "put frame done, dataLen=%{public}d, streamType=%{public}d", dataLength, streamType_);
    }
    TRANS_LOGI(TRANS_STREAM, "recv thread exit");
}

std::unique_ptr<char[]> VtpStreamSocket::RecvStream(int32_t dataLength)
{
    auto buffer = std::make_unique<char[]>(dataLength);
    int32_t recvLen = 0;
    while (recvLen < dataLength) {
        int32_t ret = -1;
        int32_t timeout = -1;

        if (EpollTimeout(streamFd_, timeout) == 0) {
            do {
                ret = FtRecv(streamFd_, (buffer.get() + recvLen), dataLength - recvLen, 0);
            } while (ret < 0 && (FtGetErrno() == EINTR || FtGetErrno() == FILLP_EAGAIN));
        }

        if (ret == -1) {
            TRANS_LOGE(TRANS_STREAM, "read frame failed, errno=%{public}d", FtGetErrno());
            return nullptr;
        }

        recvLen += ret;
    }
    return std::unique_ptr<char[]>(buffer.release());
}

void VtpStreamSocket::SetDefaultConfig(int fd)
{
    if (!SetIpTos(fd, StreamAttr(static_cast<int>(IPTOS_LOWDELAY)))) {
        TRANS_LOGW(TRANS_STREAM, "SetIpTos failed");
    }
    // Set Fillp direct sending
    if (!EnableDirectlySend(fd)) {
        TRANS_LOGW(TRANS_STREAM, "EnableDirectlySend failed");
    }

    if (!EnableSemiReliable(fd)) {
        TRANS_LOGW(TRANS_STREAM, "EnableSemiReliable failed");
    }
    // Set Fillp Differentiated Transmission
    FILLP_BOOL enable = 1;
    if (!FtConfigSet(FT_CONF_APP_DIFFER_TRANSMIT, &enable, &fd)) {
        TRANS_LOGW(TRANS_STREAM, "Set differ transmit failed");
    }

    if (!SetOption(RECV_BUF_SIZE, StreamAttr(static_cast<int>(DEFAULT_UDP_BUFFER_RCV_SIZE)))) {
        TRANS_LOGW(TRANS_STREAM, "Set recv buff failed");
    }

    if (!SetOption(SEND_BUF_SIZE, StreamAttr(static_cast<int>(DEFAULT_UDP_BUFFER_SIZE)))) {
        TRANS_LOGW(TRANS_STREAM, "Set send buff failed");
    }

    if (!SetOption(InnerStreamOptionType::RECV_CACHE, StreamAttr(static_cast<int>(FILLP_VTP_RECV_CACHE_SIZE)))) {
        TRANS_LOGW(TRANS_STREAM, "Set recv cache failed");
    }

    if (!SetOption(InnerStreamOptionType::SEND_CACHE, StreamAttr(static_cast<int>(FILLP_VTP_SEND_CACHE_SIZE)))) {
        TRANS_LOGW(TRANS_STREAM, "Set send cache failed");
    }
}

bool VtpStreamSocket::SetIpTos(int fd, const StreamAttr &tos)
{
    auto tmp = tos.GetIntValue();
    if (FtSetSockOpt(fd, IPPROTO_IP, IP_TOS, &tmp, sizeof(tmp)) != ERR_OK) {
        TRANS_LOGE(TRANS_STREAM, "SetIpTos wrong! fd=%{public}d, errno=%{public}d", fd, FtGetErrno());
        return false;
    }

    TRANS_LOGD(TRANS_STREAM, "Success to set ip tos: fd=%{public}d, tos=%{public}d", fd, tmp);
    return true;
}

StreamAttr VtpStreamSocket::GetIpTos(int type) const
{
    static_cast<void>(type);
    int tos;
    int size = sizeof(tos);

    if (FtGetSockOpt(streamFd_, IPPROTO_IP, IP_TOS, &tos, &size) != ERR_OK) {
        TRANS_LOGE(TRANS_STREAM, "FtGetSockOpt errno=%{public}d", FtGetErrno());
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
    auto boundIp = (ip.empty()) ? localIpPort_.ip : ip;
    struct ifaddrs *ifList = nullptr;
    if (getifaddrs(&ifList) < 0) {
        TRANS_LOGE(TRANS_STREAM,
            "get interface address return errno=%{public}d, strerror=%{public}s", errno, strerror(errno));
        return false;
    }

    struct ifaddrs *ifa = nullptr;
    for (ifa = ifList; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr) {
            continue;
        }
        if (ifa->ifa_addr->sa_family != AF_INET) {
            continue;
        }

        char host[ADDR_MAX_SIZE];
        std::string devName(ifa->ifa_name);
        if (strcmp(boundIp.c_str(), SoftBusInetNtoP(AF_INET, &(((struct sockaddr_in *)ifa->ifa_addr)->sin_addr),
            host, ADDR_MAX_SIZE)) == 0) {
            TRANS_LOGI(TRANS_STREAM, "current use interface to bind to socket. ifName=%{public}s", ifa->ifa_name);
            auto err = FtSetSockOpt(fd, SOL_SOCKET, SO_BINDTODEVICE, devName.c_str(), devName.size());
            if (err < 0) {
                TRANS_LOGE(TRANS_STREAM, "fail to set socket binding to device");
                freeifaddrs(ifList);
                return false;
            }
            break;
        }
    }
    freeifaddrs(ifList);

    return true;
}

bool VtpStreamSocket::SetSocketBindToDevices(int type, const StreamAttr &ip)
{
    static_cast<void>(type);
    auto tmp = ip.GetStrValue();
    auto boundIp = (tmp.empty()) ? localIpPort_.ip : tmp;
    return SetSocketBoundInner(streamFd_, boundIp);
}

bool VtpStreamSocket::SetVtpStackConfigDelayed(int type, const StreamAttr &value)
{
    std::unique_lock<std::mutex> lock(streamSocketLock_);
    if (streamFd_ == -1) {
        configCv_.wait(lock, [this] { return streamFd_ != -1; });
    }
    TRANS_LOGD(TRANS_STREAM, "set vtp stack config, streamFd=%{public}d", streamFd_);
    return SetVtpStackConfig(type, value);
}

bool VtpStreamSocket::SetVtpStackConfig(int type, const StreamAttr &value)
{
    if (streamFd_ == -1) {
        TRANS_LOGI(TRANS_STREAM, "set vtp stack config when streamFd is legal, type=%{public}d", type);
        auto self = GetSelf();
        std::thread([self, type, value]() {
            const std::string threadName = "OS_setVtpCfg";
            pthread_setname_np(pthread_self(), threadName.c_str());
            self->SetVtpStackConfigDelayed(type, value);
            }).detach();
        return true;
    }

    if (value.GetType() == INT_TYPE) {
        int intVal = value.GetIntValue();
        int ret = FtConfigSet(type, &intVal, &streamFd_);
        if (ret != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_STREAM,
                "FtConfigSet failed, type=%{public}d, errno=%{public}d", type, FtGetErrno());
            return false;
        }

        TRANS_LOGI(TRANS_STREAM,
            "setVtpConfig success, type=%{public}d, streamFd=%{public}d, value=%{public}d", type, streamFd_, intVal);
        return true;
    }

    if (value.GetType() == BOOL_TYPE) {
        bool flag = value.GetBoolValue();
        int ret = FtConfigSet(type, &flag, &streamFd_);
        if (ret != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_STREAM,
                "FtConfigSet failed, type=%{public}d, errno=%{public}d", type, FtGetErrno());
            return false;
        }

        TRANS_LOGI(TRANS_STREAM,
            "setVtpConfig success, streamFd=%{public}d, flag=%{public}d, type=%{public}d", type, streamFd_, flag);
        return true;
    }

    TRANS_LOGE(TRANS_STREAM, "UNKNOWN TYPE!");
    return false;
}

StreamAttr VtpStreamSocket::GetVtpStackConfig(int type) const
{
    int intVal = -1;
    int configFd = (streamFd_ == -1) ? FILLP_CONFIG_ALL_SOCKET : streamFd_;
    int ret = FtConfigGet(type, &intVal, &configFd);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_STREAM,
            "FtConfigGet failed, type=%{public}d, errno=%{public}d", type, FtGetErrno());
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
        TRANS_LOGE(TRANS_STREAM, "failed to get FtFcntl, flags=%{public}d", flags);
        flags = 0;
    }
    bool nonBlock = value.GetBoolValue();

    flags = nonBlock ? static_cast<FILLP_INT>((static_cast<FILLP_UINT>(flags) | O_NONBLOCK)) :
        static_cast<FILLP_INT>((static_cast<FILLP_UINT>(flags) & ~O_NONBLOCK));

    FILLP_INT res = FtFcntl(fd, F_SETFL, flags);
    if (res < 0) {
        TRANS_LOGE(TRANS_STREAM, "failed to set FtFcntl, res=%{public}d", res);
        return false;
    }

    TRANS_LOGI(TRANS_STREAM, "Successfully to set fd=%{public}d, nonBlock=%{public}d", fd, nonBlock);
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
        TRANS_LOGE(TRANS_STREAM, "value.GetType=%{public}d", value.GetType());
        return false;
    }
    scene_ = value.GetIntValue();
    TRANS_LOGI(TRANS_STREAM, "Set scene=%{public}d", scene_);
    return true;
}

bool VtpStreamSocket::SetStreamHeaderSize(int type, const StreamAttr &value)
{
    static_cast<void>(type);
    if (value.GetType() != INT_TYPE) {
        TRANS_LOGE(TRANS_STREAM, "value.GetType=%{public}d", value.GetType());
        return false;
    }
    streamHdrSize_ = value.GetIntValue();
    TRANS_LOGI(TRANS_STREAM, "Set headerSize=%{public}d", streamHdrSize_);
    return true;
}

void VtpStreamSocket::NotifyStreamListener()
{
    while (isStreamRecv_) {
        int streamNum = GetStreamNum();
        if (streamNum >= STREAM_BUFFER_THRESHOLD) {
            TRANS_LOGW(TRANS_STREAM, "Too many data in receiver, streamNum=%{public}d", streamNum);
        }

        auto stream = TakeStream();
        if (stream == nullptr) {
            TRANS_LOGE(TRANS_STREAM, "Pop stream failed");
            break;
        }

        std::lock_guard<std::mutex> guard(streamSocketLock_);
        if (streamReceiver_ != nullptr) {
            TRANS_LOGD(TRANS_STREAM, "notify listener");
            streamReceiver_->OnStreamReceived(std::move(stream));
            TRANS_LOGD(TRANS_STREAM, "notify listener done.");
        }
    }
    TRANS_LOGI(TRANS_STREAM, "notify thread exit");
}

ssize_t VtpStreamSocket::GetEncryptOverhead() const
{
    return OVERHEAD_LEN;
}

ssize_t VtpStreamSocket::Encrypt(const void *in, ssize_t inLen, void *out, ssize_t outLen) const
{
    if (in == nullptr || out == nullptr) {
        TRANS_LOGE(TRANS_STREAM, "param invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    AesGcmCipherKey cipherKey = {0};

    if (inLen - OVERHEAD_LEN > outLen) {
        TRANS_LOGE(TRANS_STREAM, "Encrypt invalid para.");
        return SOFTBUS_INVALID_PARAM;
    }

    cipherKey.keyLen = SESSION_KEY_LENGTH;
    if (memcpy_s(cipherKey.key, SESSION_KEY_LENGTH, sessionKey_.first, sessionKey_.second) != EOK) {
        TRANS_LOGE(TRANS_STREAM, "memcpy key error.");
        return SOFTBUS_MEM_ERR;
    }

    int ret = SoftBusEncryptData(&cipherKey, (unsigned char *)in, inLen, (unsigned char *)out, (unsigned int *)&outLen);
    (void)memset_s(&cipherKey, sizeof(AesGcmCipherKey), 0, sizeof(AesGcmCipherKey));
    if (ret != SOFTBUS_OK || outLen != inLen + OVERHEAD_LEN) {
        TRANS_LOGE(TRANS_STREAM, "Encrypt Data fail. ret=%{public}d", ret);
        return SOFTBUS_ENCRYPT_ERR;
    }
    return outLen;
}

ssize_t VtpStreamSocket::Decrypt(const void *in, ssize_t inLen, void *out, ssize_t outLen) const
{
    if (in == nullptr || out == nullptr) {
        TRANS_LOGE(TRANS_STREAM, "param invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    AesGcmCipherKey cipherKey = {0};

    if (inLen - OVERHEAD_LEN > outLen) {
        TRANS_LOGE(TRANS_STREAM, "Decrypt invalid para.");
        return SOFTBUS_INVALID_PARAM;
    }

    cipherKey.keyLen = SESSION_KEY_LENGTH; // 256 bit encryption
    if (memcpy_s(cipherKey.key, SESSION_KEY_LENGTH, sessionKey_.first, sessionKey_.second) != EOK) {
        TRANS_LOGE(TRANS_STREAM, "memcpy key error.");
        return SOFTBUS_MEM_ERR;
    }
    int ret = SoftBusDecryptData(&cipherKey, (unsigned char *)in, inLen, (unsigned char *)out, (unsigned int *)&outLen);
    (void)memset_s(&cipherKey, sizeof(AesGcmCipherKey), 0, sizeof(AesGcmCipherKey));
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_STREAM, "Decrypt Data fail. ret=%{public}d ", ret);
        return SOFTBUS_DECRYPT_ERR;
    }

    return outLen;
}

int32_t VtpStreamSocket::SetMultiLayer(const void *para)
{
    int fd = GetStreamSocketFd(FD).GetIntValue();
    return VtpSetSocketMultiLayer(fd, &onStreamEvtCb_, para);
}

void VtpStreamSocket::CreateServerProcessThread()
{
    auto self = this->GetSelf();
    std::thread([self]() {
        const std::string threadName = "OS_sntfStmLsn";
        pthread_setname_np(pthread_self(), threadName.c_str());
        self->NotifyStreamListener();
        }).detach();

    std::thread([self]() {
        const std::string threadName = "OS_sdstyStmSkt";
        pthread_setname_np(pthread_self(), threadName.c_str());
        if (!self->Accept()) {
            self->DestroyStreamSocket();
            return;
        }
        self->DoStreamRecv();
        self->DestroyStreamSocket();
        }).detach();

    bool &isDestroyed = isDestroyed_;
    std::thread([self, &isDestroyed]() {
        const std::string threadName = "OS_sfillStatic";
        pthread_setname_np(pthread_self(), threadName.c_str());
        while (!isDestroyed) {
            self->FillpAppStatistics();
            std::this_thread::sleep_for(std::chrono::seconds(FEED_BACK_PERIOD));
        }
        }).detach();
}

void VtpStreamSocket::CreateClientProcessThread()
{
    auto self = this->GetSelf();
    std::thread([self]() {
        const std::string threadName = "OS_cntfStmLsn";
        pthread_setname_np(pthread_self(), threadName.c_str());
        self->NotifyStreamListener();
        }).detach();

    std::thread([self]() {
        const std::string threadName = "OS_cdstyStmSkt";
        pthread_setname_np(pthread_self(), threadName.c_str());
        self->DoStreamRecv();
        self->DestroyStreamSocket();
        }).detach();

    bool &isDestroyed = isDestroyed_;
    std::thread([self, &isDestroyed]() {
        const std::string threadName = "OS_cfillStatic";
        pthread_setname_np(pthread_self(), threadName.c_str());
        while (!isDestroyed) {
            self->FillpAppStatistics();
            std::this_thread::sleep_for(std::chrono::seconds(FEED_BACK_PERIOD));
        }
        }).detach();
}
} // namespace SoftBus
} // namespace Communication
