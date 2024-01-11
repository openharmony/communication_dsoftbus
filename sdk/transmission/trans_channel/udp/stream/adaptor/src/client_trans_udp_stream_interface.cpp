/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "securec.h"
#include "softbus_errcode.h"
#include "stream_adaptor.h"
#include "stream_adaptor_listener.h"
#include "stream_common.h"
#include "trans_log.h"

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

int32_t SendVtpStream(int32_t channelId, const StreamData *inData, const StreamData *ext, const StreamFrameInfo *param)
{
    if (inData == nullptr || inData->buf == nullptr || param == nullptr) {
        TRANS_LOGE(TRANS_STREAM, "invalid argument!");
        return SOFTBUS_ERR;
    }
    std::shared_ptr<StreamAdaptor> adaptor = nullptr;
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        auto it = g_adaptorMap.find(channelId);
        if (it == g_adaptorMap.end()) {
            TRANS_LOGE(TRANS_STREAM, "adaptor not existed!");
            return SOFTBUS_ERR;
        }
        adaptor = it->second;
    }

    std::unique_ptr<IStream> stream = nullptr;
    if (adaptor->GetStreamType() == RAW_STREAM) {
        ssize_t dataLen = inData->bufLen + adaptor->GetEncryptOverhead();
        TRANS_LOGD(TRANS_STREAM,
            "bufLen=%{public}d, encryptOverhead=%{public}zd", inData->bufLen, adaptor->GetEncryptOverhead());
        std::unique_ptr<char[]> data = std::make_unique<char[]>(dataLen);
        ssize_t encLen = adaptor->Encrypt(inData->buf, inData->bufLen, data.get(), dataLen, adaptor->GetSessionKey());
        if (encLen != dataLen) {
            TRANS_LOGE(TRANS_STREAM, "encrypted failed, dataLen=%{public}zd, encLen=%{public}zd", dataLen, encLen);
            return SOFTBUS_ERR;
        }

        stream = IStream::MakeRawStream(data.get(), dataLen, {}, Communication::SoftBus::Scene::SOFTBUS_SCENE);
    } else if (adaptor->GetStreamType() == COMMON_VIDEO_STREAM || adaptor->GetStreamType() == COMMON_AUDIO_STREAM) {
        if (inData->bufLen < 0 || inData->bufLen > Communication::SoftBus::MAX_STREAM_LEN ||
            (ext != nullptr && (ext->bufLen < 0 || ext->bufLen > Communication::SoftBus::MAX_STREAM_LEN))) {
            return SOFTBUS_TRANS_INVALID_DATA_LENGTH;
        }
        Communication::SoftBus::StreamData data = {
            .buffer = std::make_unique<char[]>(inData->bufLen),
            .bufLen = inData->bufLen,
            .extBuffer = nullptr,
            .extLen = 0,
        };
        int32_t ret = memcpy_s(data.buffer.get(), data.bufLen, inData->buf, inData->bufLen);
        if (ret != EOK) {
            TRANS_LOGE(TRANS_STREAM, "Failed to memcpy data! ret=%{public}d", ret);
            return SOFTBUS_ERR;
        }
        if (ext != nullptr && ext->bufLen > 0) {
            data.extBuffer = std::make_unique<char[]>(ext->bufLen);
            data.extLen = ext->bufLen;
            ret = memcpy_s(data.extBuffer.get(), data.extLen, ext->buf, ext->bufLen);
            if (ret != EOK) {
                TRANS_LOGE(TRANS_STREAM, "Failed to memcpy ext! ret=%{public}d", ret);
                return SOFTBUS_ERR;
            }
        }

        Communication::SoftBus::StreamFrameInfo outFrameInfo;
        ConvertStreamFrameInfo(param, &outFrameInfo);
        stream = IStream::MakeCommonStream(data, outFrameInfo);
    } else {
        TRANS_LOGE(TRANS_STREAM, "Do not support");
    }

    if (stream == nullptr) {
        TRANS_LOGE(TRANS_STREAM, "make stream failed, stream is nullptr");
        return SOFTBUS_ERR;
    }
    return adaptor->GetStreamManager()->Send(std::move(stream)) ? SOFTBUS_OK : SOFTBUS_ERR;
}

int32_t StartVtpStreamChannelServer(int32_t channelId, const VtpStreamOpenParam *param, const IStreamListener *callback)
{
    if (channelId < 0 || param == nullptr || param->pkgName == nullptr || callback == nullptr) {
        TRANS_LOGE(TRANS_STREAM, "invalid channelId or pkgName");
        return SOFTBUS_ERR;
    }
    TRANS_LOGI(TRANS_STREAM, "Start Channel Server. channelId=%{public}d ", channelId);
    auto it = g_adaptorMap.find(channelId);
    if (it != g_adaptorMap.end()) {
        TRANS_LOGE(TRANS_STREAM, "adaptor already existed!");
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
            TRANS_LOGE(TRANS_STREAM, "adaptor already existed!");
            return SOFTBUS_ERR;
        }
    }

    auto newAdaptor = it->second;
    newAdaptor->InitAdaptor(channelId, param, true, callback);

    Communication::SoftBus::IpAndPort ipPort;
    ipPort.ip = param->myIp;
    ipPort.port = 0;

    int32_t ret = SOFTBUS_ERR;
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
        TRANS_LOGE(TRANS_STREAM, "invalid channelId or pkgName");
        return SOFTBUS_ERR;
    }

    TRANS_LOGI(TRANS_STREAM, "StartChannelClient channelId=%{public}d.", channelId);
    auto it = g_adaptorMap.find(channelId);
    if (it != g_adaptorMap.end()) {
        TRANS_LOGE(TRANS_STREAM, "adaptor already existed!");
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
            TRANS_LOGE(TRANS_STREAM, "adaptor already existed!");
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
        TRANS_LOGE(TRANS_STREAM, "CreateStreamClientChannel failed, ret=%{public}d", ret);
        CloseVtpStreamChannel(channelId, param->pkgName);
    }

    return ret;
}

int32_t CloseVtpStreamChannel(int32_t channelId, const char *pkgName)
{
    TRANS_LOGI(TRANS_STREAM, "close stream channelId=%{public}d", channelId);
    std::shared_ptr<StreamAdaptor> adaptor = nullptr;

    if (channelId < 0 || pkgName == nullptr) {
        TRANS_LOGE(TRANS_STREAM, "invalid channelId or pkgName");
        return SOFTBUS_ERR;
    }

    {
        std::lock_guard<std::mutex> lock(g_mutex);
        auto it = g_adaptorMap.find(channelId);
        if (it == g_adaptorMap.end()) {
            TRANS_LOGE(TRANS_STREAM, "adaptor not existed!");
            return SOFTBUS_ERR;
        }
        adaptor = it->second;
        g_adaptorMap.erase(it);
    }

    bool alive = adaptor->GetAliveState();
    if (!alive) {
        TRANS_LOGE(TRANS_STREAM, "VtpStreamChannel already closed");
        return SOFTBUS_ERR;
    }

    adaptor->ReleaseAdaptor();

    return SOFTBUS_OK;
}

