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

#include "client_trans_udp_stream_interface.h"

#include <map>
#include <mutex>
#include <string>
#include <sys/types.h>

#include "securec.h"
#include "softbus_adapter_crypto.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "stream_adaptor.h"
#include "stream_adaptor_listener.h"
#include "stream_common.h"

using namespace OHOS;

namespace {
    std::map<int, std::shared_ptr<StreamAdaptor>> g_adaptorMap;
    std::mutex g_mutex;
}

static inline void ConvertStreamFrameInfo(const StreamFrameInfo *inFrameInfo,
    Communication::SoftBus::StreamFrameInfo *outFrameInfo)
{
    outFrameInfo->streamId = 0;
    outFrameInfo->seqNum = (uint32_t)(inFrameInfo->seqNum);
    outFrameInfo->level = (uint32_t)(inFrameInfo->level);
    outFrameInfo->frameType = (Communication::SoftBus::FrameType)(inFrameInfo->frameType);
    outFrameInfo->seqSubNum = (uint32_t)inFrameInfo->seqSubNum;
    outFrameInfo->bitMap = (uint32_t)inFrameInfo->bitMap;
    outFrameInfo->timeStamp = (uint32_t)inFrameInfo->timeStamp;
    outFrameInfo->bitrate = 0;
}

int32_t SendVtpStream(int32_t channelId, const StreamData *indata, const StreamData *ext, const StreamFrameInfo *param)
{
    if (indata == nullptr || indata->buf == nullptr || param == nullptr) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "invalid argument!");
        return SOFTBUS_ERR;
    }
    std::shared_ptr<StreamAdaptor> adaptor = nullptr;
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        auto it = g_adaptorMap.find(channelId);
        if (it == g_adaptorMap.end()) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "adaptor not existed!");
            return SOFTBUS_ERR;
        }
        adaptor = it->second;
    }

    std::unique_ptr<IStream> stream = nullptr;
    if (adaptor->GetStreamType() == RAW_STREAM) {
        ssize_t dataLen = indata->bufLen + adaptor->GetEncryptOverhead();
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_DBG,
            "bufLen = %d, GetEncryptOverhead() = %zd", indata->bufLen, adaptor->GetEncryptOverhead());
        std::unique_ptr<char[]> data = std::make_unique<char[]>(dataLen);
        ssize_t encLen = adaptor->Encrypt(indata->buf, indata->bufLen, data.get(), dataLen, adaptor->GetSessionKey());
        if (encLen != dataLen) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR,
                "encrypted failed, dataLen = %zd, encryptLen = %zd", dataLen, encLen);
            return SOFTBUS_ERR;
        }

        stream = IStream::MakeRawStream(data.get(), dataLen, {}, Communication::SoftBus::Scene::SOFTBUS_SCENE);
    } else if (adaptor->GetStreamType() == COMMON_VIDEO_STREAM || adaptor->GetStreamType() == COMMON_AUDIO_STREAM) {
        if (indata->bufLen < 0 || indata->bufLen > Communication::SoftBus::MAX_STREAM_LEN ||
            (ext != nullptr && (ext->bufLen < 0 || ext->bufLen > Communication::SoftBus::MAX_STREAM_LEN))) {
            return SOFTBUS_TRANS_INVALID_DATA_LENGTH;
        }
        Communication::SoftBus::StreamData data = {
            .buffer = std::make_unique<char[]>(indata->bufLen),
            .bufLen = indata->bufLen,
            .extBuffer = nullptr,
            .extLen = 0,
        };
        int32_t ret = memcpy_s(data.buffer.get(), data.bufLen, indata->buf, indata->bufLen);
        if (ret != EOK) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "Failed to memcpy data! ret: %d", ret);
            return SOFTBUS_ERR;
        }
        if (ext != nullptr && ext->bufLen > 0) {
            data.extBuffer = std::make_unique<char[]>(ext->bufLen);
            data.extLen = ext->bufLen;
            ret = memcpy_s(data.extBuffer.get(), data.extLen, ext->buf, ext->bufLen);
            if (ret != EOK) {
                SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "Failed to memcpy ext! ret: %d", ret);
                return SOFTBUS_ERR;
            }
        }

        Communication::SoftBus::StreamFrameInfo outFrameInfo;
        ConvertStreamFrameInfo(param, &outFrameInfo);
        stream = IStream::MakeCommonStream(data, outFrameInfo);
    } else {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "Do not support");
    }

    if (stream == nullptr) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "make stream failed, stream is nullptr");
        return SOFTBUS_ERR;
    }
    return adaptor->GetStreamManager()->Send(std::move(stream)) ? SOFTBUS_OK : SOFTBUS_ERR;
}

int32_t StartVtpStreamChannelServer(int32_t channelId, const VtpStreamOpenParam *param, const IStreamListener *callback)
{
    if (channelId < 0 || param == nullptr || param->pkgName == nullptr || callback == nullptr) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "StartVtpStreamChannelServer invalid channelId or pkgName");
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "cId=%d Start Channel Server.", channelId);
    int32_t ret = SOFTBUS_ERR;
    auto it = g_adaptorMap.find(channelId);
    if (it != g_adaptorMap.end()) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_WARN, "adaptor already existed!");
        return SOFTBUS_ERR;
    }

    {
        std::lock_guard<std::mutex> lock(g_mutex);
        it = g_adaptorMap.find(channelId);
        if (it == g_adaptorMap.end()) {
            std::string pkgStr(param->pkgName);
            it = g_adaptorMap.emplace(std::pair<int, std::shared_ptr<StreamAdaptor>>(channelId,
                std::make_shared<StreamAdaptor>(pkgStr))).first;
        } else {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_WARN, "adaptor already existed!");
            return SOFTBUS_ERR;
        }
    }

    auto newAdaptor = it->second;
    newAdaptor->InitAdaptor(channelId, param, true, callback);

    Communication::SoftBus::IpAndPort ipPort;
    ipPort.ip = param->myIp;
    ipPort.port = 0;

    ret = newAdaptor->GetStreamManager()->CreateStreamServerChannel(ipPort, Communication::SoftBus::VTP,
        param->type, newAdaptor->GetSessionKey());
    if (ret > 0) {
        newAdaptor->SetAliveState(true);
    } else {
        CloseVtpStreamChannel(channelId, param->pkgName);
    }

    return ret;
}

int32_t StartVtpStreamChannelClient(int32_t channelId, const VtpStreamOpenParam *param, const IStreamListener *callback)
{
    if (channelId < 0 || param == nullptr || param->pkgName == nullptr || callback == nullptr) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "invalid channelId or pkgName");
        return SOFTBUS_ERR;
    }

    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "StartChannelClient cId=%d.", channelId);
    auto it = g_adaptorMap.find(channelId);
    if (it != g_adaptorMap.end()) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_WARN, "adaptor already existed!");
        return SOFTBUS_ERR;
    }

    {
        std::lock_guard<std::mutex> lock(g_mutex);
        it = g_adaptorMap.find(channelId);
        if (it == g_adaptorMap.end()) {
            std::string pkgStr(param->pkgName);
            it = g_adaptorMap.emplace(std::pair<int, std::shared_ptr<StreamAdaptor>>(channelId,
                std::make_shared<StreamAdaptor>(pkgStr))).first;
        } else {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_WARN, "adaptor already existed!");
            return SOFTBUS_ERR;
        }
    }

    auto newAdaptor = it->second;
    newAdaptor->InitAdaptor(channelId, param, false, callback);

    Communication::SoftBus::IpAndPort ipPort;
    ipPort.ip = param->myIp;
    ipPort.port = 0;

    Communication::SoftBus::IpAndPort peerIpPort;
    peerIpPort.ip = param->peerIp;
    peerIpPort.port = param->peerPort;

    int32_t ret = newAdaptor->GetStreamManager()->CreateStreamClientChannel(ipPort, peerIpPort,
        Communication::SoftBus::VTP, param->type, newAdaptor->GetSessionKey());
    if (ret > 0) {
        newAdaptor->SetAliveState(true);
    } else {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "CreateStreamClientChannel failed, ret:%d", ret);
        CloseVtpStreamChannel(channelId, param->pkgName);
    }

    return ret;
}

int32_t CloseVtpStreamChannel(int32_t channelId, const char *pkgName)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "close stream channelid=%d", channelId);
    std::shared_ptr<StreamAdaptor> adaptor = nullptr;

    if (channelId < 0 || pkgName == nullptr) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "invalid channelId or pkgName");
        return SOFTBUS_ERR;
    }

    {
        std::lock_guard<std::mutex> lock(g_mutex);
        auto it = g_adaptorMap.find(channelId);
        if (it == g_adaptorMap.end()) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "adaptor not existed!");
            return SOFTBUS_ERR;
        }
        adaptor = it->second;
        g_adaptorMap.erase(it);
    }

    bool alive = adaptor->GetAliveState();
    if (!alive) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "VtpStreamChannel already closed");
        return SOFTBUS_ERR;
    }

    adaptor->ReleaseAdaptor();

    return SOFTBUS_OK;
}

