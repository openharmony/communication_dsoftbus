/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include <memory>
#include <mutex>
#include <pthread.h>
#include <securec.h>
#include <semaphore.h>
#include <cstdio>
#include <cstdlib>

#include "br_proxy.h"
#include "br_proxy_session_manager.h"
#include "br_proxy_error_code.h"
#include "ohos.distributedsched.proxyChannelManager.proj.hpp"
#include "ohos.distributedsched.proxyChannelManager.impl.hpp"
#include "stdexcept"
#include "taihe/runtime.hpp"
#include "trans_log.h"

namespace {
// To be implemented.
static SoftBusList *g_channelInfoList = nullptr;

typedef struct {
    int32_t channelId;
    std::shared_ptr<::taihe::callback<
        void(::ohos::distributedsched::proxyChannelManager::DataInfo const& dataInfo)>> recvCallback;
    std::shared_ptr<::taihe::callback<
        void(::ohos::distributedsched::proxyChannelManager::ChannelStateInfo const& stateInfo)>> stateCallback;
    ListNode node;
} TaiheChannelInfo;

static void ThrowBusinessException(int32_t err)
{
    if (err == SOFTBUS_OK) {
        return;
    }
    int32_t jsRet = NapiTransConvertErr(err);
    const char *errMsg = GetErrMsgByErrCode(jsRet);
    taihe::set_business_error(jsRet, errMsg);
}

static int32_t InitTaiheChannelList(void)
{
    static bool initSuccess = false;
    static std::mutex initMutex;
    std::lock_guard<std::mutex> lock(initMutex);
    if (initSuccess) {
        return SOFTBUS_OK;
    }
    g_channelInfoList = CreateSoftBusList();
    if (g_channelInfoList == nullptr) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] channel list init failed.");
        return SOFTBUS_CREATE_LIST_ERR;
    }
    initSuccess = true;
    TRANS_LOGI(TRANS_SDK, "[br_proxy] channel list init success.");
    return SOFTBUS_OK;
}

static int32_t AddChannelInfoList(int32_t channelId)
{
    TaiheChannelInfo *chan = reinterpret_cast<TaiheChannelInfo *>(SoftBusCalloc(sizeof(TaiheChannelInfo)));
    if (chan == nullptr) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] channelId=%{public}d add list failed.", channelId);
        return SOFTBUS_MALLOC_ERR;
    }
    chan->channelId = channelId;
    chan->recvCallback = nullptr;
    chan->stateCallback = nullptr;
    ListInit(&chan->node);
    if (SoftBusMutexLock(&(g_channelInfoList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] lock failed");
        SoftBusFree(chan);
        return SOFTBUS_LOCK_ERR;
    }
    ListAdd(&g_channelInfoList->list, &chan->node);
    TRANS_LOGI(TRANS_SDK, "[br_proxy] add channel node success, channelId=%{public}d", channelId);
    (void)SoftBusMutexUnlock(&g_channelInfoList->lock);
    return SOFTBUS_OK;
}

static int32_t GetChannelInfoByChannelId(int32_t channelId, TaiheChannelInfo *info)
{
    if (g_channelInfoList == nullptr) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] not init");
        return SOFTBUS_NO_INIT;
    }
    if (info == nullptr) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] invalid param");
        return SOFTBUS_TRANS_BR_PROXY_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&(g_channelInfoList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    TaiheChannelInfo *nodeInfo = nullptr;
    LIST_FOR_EACH_ENTRY(nodeInfo, &(g_channelInfoList->list), TaiheChannelInfo, node) {
        if (nodeInfo->channelId != channelId) {
            continue;
        }
        info->channelId = nodeInfo->channelId;
        info->recvCallback = nodeInfo->recvCallback;
        info->stateCallback = nodeInfo->stateCallback;
        (void)SoftBusMutexUnlock(&(g_channelInfoList->lock));
        return SOFTBUS_OK;
    }
    (void)SoftBusMutexUnlock(&(g_channelInfoList->lock));
    TRANS_LOGE(TRANS_SDK, "[br_proxy] not find channelId=%{public}d", channelId);
    return SOFTBUS_NOT_FIND;
}

static int32_t SetCallbackByChannelId(int32_t channelId,
    std::shared_ptr<::taihe::callback<
        void(::ohos::distributedsched::proxyChannelManager::DataInfo const& dataInfo)>> recvCallback,
    std::shared_ptr<::taihe::callback<
        void(::ohos::distributedsched::proxyChannelManager::ChannelStateInfo const& stateInfo)>> stateCallback)
{
    if (g_channelInfoList == nullptr) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] not init");
        return SOFTBUS_NO_INIT;
    }
    if (SoftBusMutexLock(&(g_channelInfoList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    TaiheChannelInfo *nodeInfo = nullptr;
    LIST_FOR_EACH_ENTRY(nodeInfo, &(g_channelInfoList->list), TaiheChannelInfo, node) {
        if (nodeInfo->channelId != channelId) {
            continue;
        }
        if (recvCallback != nullptr) {
            nodeInfo->recvCallback = recvCallback;
        }
        if (stateCallback != nullptr) {
            nodeInfo->stateCallback = stateCallback;
        }
        (void)SoftBusMutexUnlock(&(g_channelInfoList->lock));
        return SOFTBUS_OK;
    }
    (void)SoftBusMutexUnlock(&(g_channelInfoList->lock));
    TRANS_LOGE(TRANS_SDK, "[br_proxy] not find channelId=%{public}d", channelId);
    return SOFTBUS_NOT_FIND;
}

static int32_t OffCallbackByChannelId(int32_t channelId, ListenerType type)
{
    if (g_channelInfoList == nullptr) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] not init");
        return SOFTBUS_NO_INIT;
    }
    if (SoftBusMutexLock(&(g_channelInfoList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    TaiheChannelInfo *nodeInfo = nullptr;
    LIST_FOR_EACH_ENTRY(nodeInfo, &(g_channelInfoList->list), TaiheChannelInfo, node) {
        if (nodeInfo->channelId != channelId) {
            continue;
        }
        if (type == DATA_RECEIVE) {
            nodeInfo->recvCallback = nullptr;
        } else if (type == CHANNEL_STATE) {
            nodeInfo->stateCallback = nullptr;
        }
        TRANS_LOGI(TRANS_SDK, "[br_proxy] channelId=%{public}d type=%{public}d is disable.", channelId, type);
        (void)SoftBusMutexUnlock(&(g_channelInfoList->lock));
        return SOFTBUS_OK;
    }
    (void)SoftBusMutexUnlock(&(g_channelInfoList->lock));
    TRANS_LOGE(TRANS_SDK, "[br_proxy] not find channelId=%{public}d", channelId);
    return SOFTBUS_NOT_FIND;
}

static int32_t DeleteChannelInfoById(int32_t channelId)
{
    if (g_channelInfoList == nullptr) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] not init");
        return SOFTBUS_NO_INIT;
    }
    if (SoftBusMutexLock(&(g_channelInfoList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    TaiheChannelInfo *chan = nullptr;
    TaiheChannelInfo *nextChan = nullptr;
    LIST_FOR_EACH_ENTRY_SAFE(chan, nextChan, &(g_channelInfoList->list), TaiheChannelInfo, node) {
        if (chan->channelId != channelId) {
            continue;
        }
        TRANS_LOGI(TRANS_SDK, "[br_proxy]delete node success, channelId=%{public}d", chan->channelId);
        ListDelete(&chan->node);
        SoftBusFree(chan);
        (void)SoftBusMutexUnlock(&(g_channelInfoList->lock));
        return SOFTBUS_OK;
    }
    (void)SoftBusMutexUnlock(&(g_channelInfoList->lock));
    TRANS_LOGE(TRANS_SDK, "[br_proxy] not find channelId=%{public}d", channelId);
    return SOFTBUS_NOT_FIND;
}

static int32_t OnChannelOpened(int32_t sessionId, int32_t channelId, int32_t result)
{
    TRANS_LOGI(TRANS_SDK, "[br_proxy] sessionId=%{public}d channelId=%{public}d opened.", sessionId, channelId);
    int32_t ret = UpdateListBySessionId(sessionId, channelId, result);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] sessionId=%{public}d update list failed.", sessionId);
        return ret;
    }
    return BrProxyPostCond(sessionId);
}

static void OnDataReceived(int32_t channelId, const char *data, uint32_t dataLen)
{
    if (data == nullptr || dataLen == 0 || dataLen > BR_PROXY_SEND_MAX_LEN) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] invalid param.");
        return;
    }
    TaiheChannelInfo chan;
    (void)memset_s(&chan, sizeof(TaiheChannelInfo), 0, sizeof(TaiheChannelInfo));
    int32_t ret = GetChannelInfoByChannelId(channelId, &chan);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] channelId=%{public}d get channel info failed.", channelId);
        return;
    }
    if (chan.recvCallback == nullptr) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] channelId=%{public}d recv callbck not init.", channelId);
        return;
    }
    std::vector<uint8_t> buffer(
        reinterpret_cast<const uint8_t *>(data),
        reinterpret_cast<const uint8_t *>(data) + dataLen
    );
    ::ohos::distributedsched::proxyChannelManager::DataInfo info = {
        .channelId = channelId,
        .data = ::taihe::array<uint8_t>(buffer),
    };
    (*chan.recvCallback)(info);
}

static ::ohos::distributedsched::proxyChannelManager::ChannelState SetChannelStateToTaihe(int32_t state)
{
    switch (state) {
        case CHANNEL_WAIT_RESUME:
            return ::ohos::distributedsched::proxyChannelManager::ChannelState::key_t::CHANNEL_WAIT_RESUME;
        case CHANNEL_RESUME:
            return ::ohos::distributedsched::proxyChannelManager::ChannelState::key_t::CHANNEL_RESUME;
        case CHANNEL_EXCEPTION_SOFTWARE_FAILED:
            return
                ::ohos::distributedsched::proxyChannelManager::ChannelState::key_t::CHANNEL_EXCEPTION_SOFTWARE_FAILED;
        case CHANNEL_BR_NO_PAIRED:
            return ::ohos::distributedsched::proxyChannelManager::ChannelState::key_t::CHANNEL_BR_NO_PAIRED;
        default:
            return
                ::ohos::distributedsched::proxyChannelManager::ChannelState::key_t::CHANNEL_EXCEPTION_SOFTWARE_FAILED;
    }
}

static void OnChannelStatusChanged(int32_t channelId, int32_t status)
{
    TaiheChannelInfo chan;
    (void)memset_s(&chan, sizeof(TaiheChannelInfo), 0, sizeof(TaiheChannelInfo));
    int32_t ret = GetChannelInfoByChannelId(channelId, &chan);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] channelId=%{public}d get channel info failed.", channelId);
        return;
    }
    if (chan.stateCallback == nullptr) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] channelId=%{public}d state callbck not init.", channelId);
        return;
    }
    ::ohos::distributedsched::proxyChannelManager::ChannelStateInfo info = {
        .channelId = channelId,
        .state = SetChannelStateToTaihe(status),
    };
    (*chan.stateCallback)(info);
}

static TSLinkType GetLinkTypeFromTaihe(::ohos::distributedsched::proxyChannelManager::LinkType linkType)
{
    switch (linkType.get_key()) {
        case ::ohos::distributedsched::proxyChannelManager::LinkType::key_t::LINK_BR:
            return LINK_BR;
        default:
            return LINK_BR;
    }
}

static int32_t IsvalidChannelInfo(::ohos::distributedsched::proxyChannelManager::ChannelInfo const& channelInfo)
{
    if (channelInfo.peerDevAddr.empty() || channelInfo.peerDevAddr.size() < MAC_MIN_LENGTH ||
        (channelInfo.peerDevAddr.size() > MAC_MAX_LENGTH && channelInfo.peerDevAddr.size() != MAC_SHA256_LEN)) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] peer dev addr len is wrong.");
        ThrowBusinessException(SOFTBUS_TRANS_BR_PROXY_INVALID_PARAM);
        return SOFTBUS_TRANS_BR_PROXY_INVALID_PARAM;
    }
    if (channelInfo.peerUuid.empty() ||
        (channelInfo.peerUuid.size() != UUID_STD_LENGTH && channelInfo.peerUuid.size() != UUID_NO_HYPHEN_LENGTH)) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] peer uuid len is wrong.");
        ThrowBusinessException(SOFTBUS_TRANS_BR_PROXY_INVALID_PARAM);
        return SOFTBUS_TRANS_BR_PROXY_INVALID_PARAM;
    }
    return SOFTBUS_OK;
}

static int32_t AddSessionList(void)
{
    int32_t ret = SessionInit();
    if (ret != SOFTBUS_OK) {
        ThrowBusinessException(ret);
        return ret;
    }
    ret = InitTaiheChannelList();
    if (ret != SOFTBUS_OK) {
        ThrowBusinessException(ret);
        return ret;
    }
    int32_t sessionId = GetSessionId();
    ret = AddSessionToList(sessionId);
    if (ret != SOFTBUS_OK) {
        ThrowBusinessException(ret);
        return ret;
    }
    return sessionId;
}

int32_t OpenProxyChannelAsync(::ohos::distributedsched::proxyChannelManager::ChannelInfo const& channelInfo)
{
    int32_t ret = IsvalidChannelInfo(channelInfo);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_SDK, "[br_proxy] invalid param.");
    BrProxyChannelInfo info;
    (void)memset_s(&info, sizeof(BrProxyChannelInfo), 0, sizeof(BrProxyChannelInfo));
    if (memcpy_s(info.peerBRMacAddr, sizeof(info.peerBRMacAddr),
        channelInfo.peerDevAddr.c_str(), channelInfo.peerDevAddr.size()) != EOK ||
        memcpy_s(info.peerBRUuid, sizeof(info.peerBRUuid),
            channelInfo.peerUuid.c_str(), channelInfo.peerUuid.size()) != EOK) {
        ThrowBusinessException(SOFTBUS_MEM_ERR);
        return SOFTBUS_MEM_ERR;
    }
    info.linktype = GetLinkTypeFromTaihe(channelInfo.linkType);
    int32_t sessionId = AddSessionList();
    TRANS_CHECK_AND_RETURN_RET_LOGE(sessionId > 0, ret, TRANS_SDK, "[br_proxy] invalid sessionId.");
   
    IBrProxyListener listener = {
        .onChannelOpened = OnChannelOpened,
        .onDataReceived = OnDataReceived,
        .onChannelStatusChanged = OnChannelStatusChanged,
    };
    ret = OpenBrProxy(sessionId, &info, &listener);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] sessionId=%{public}d open br proxy failed.", sessionId);
        goto EXIT_ERR;
    }

    ret = BrProxyWaitCond(sessionId);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] sessionId=%{public}d wait cond failed.", sessionId);
        goto EXIT_ERR;
    }

    SessionInfo sessionInfo;
    (void)memset_s(&sessionInfo, sizeof(SessionInfo), 0, sizeof(SessionInfo));
    ret = GetSessionInfoBySessionId(sessionId, &sessionInfo);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] sessionId=%{public}d get info failed. ret=%{public}d", sessionId, ret);
        goto EXIT_ERR;
    }
    ret = sessionInfo.openResult;
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] sessionId=%{public}d open failed. ret=%{public}d", sessionId, ret);
        goto EXIT_ERR;
    }
    AddChannelInfoList(sessionInfo.channelId);
    (void)DeleteSessionById(sessionId);
    return sessionInfo.channelId;
EXIT_ERR:
    (void)DeleteSessionById(sessionId);
    ThrowBusinessException(ret);
    return ret;
}

void CloseProxyChannel(int32_t channelId)
{
    (void)DeleteChannelInfoById(channelId);
    int32_t ret = CloseBrProxy(channelId);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] channelId=%{public}d close failed. ret=%{public}d", channelId, ret);
        ThrowBusinessException(ret);
        return;
    }
}

void SendDataAsync(int32_t channelId, ::taihe::array_view<uint8_t> data)
{
    if (data.empty()) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] channelId=%{public}d invalid param.", channelId);
        ThrowBusinessException(SOFTBUS_TRANS_BR_PROXY_INVALID_PARAM);
        return;
    }
    uint32_t dataLen = data.size();
    char *dataBuf = reinterpret_cast<char *>(SoftBusCalloc(data.size()));
    if (dataBuf == nullptr) {
        ThrowBusinessException(SOFTBUS_MALLOC_ERR);
        TRANS_LOGE(TRANS_SDK, "[br_proxy] channelId=%{public}d calloc failed.", channelId);
        return;
    }
    if (memcpy_s(dataBuf, dataLen, data.data(), data.size()) != EOK) {
        ThrowBusinessException(SOFTBUS_MEM_ERR);
        TRANS_LOGE(TRANS_SDK, "[br_proxy] channelId=%{public}d memcpy failed.", channelId);
        SoftBusFree(dataBuf);
        return;
    }
    int32_t ret = SendBrProxyData(channelId, dataBuf, dataLen);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] channelId=%{public}d send data failed. ret=%{public}d", channelId, ret);
        ThrowBusinessException(ret);
        SoftBusFree(dataBuf);
        return;
    }
    SoftBusFree(dataBuf);
}

void OnReceiveData(int32_t channelId,
    ::taihe::callback_view<void(::ohos::distributedsched::proxyChannelManager::DataInfo const& dataInfo)> callback)
{
    int32_t ret = SetListenerState(channelId, DATA_RECEIVE, true);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] channelId=%{public}d set listener failed.", channelId);
        ThrowBusinessException(ret);
        return;
    }
    auto recvCallback = std::make_shared<::taihe::callback<
        void(::ohos::distributedsched::proxyChannelManager::DataInfo const& dataInfo)>>(callback);
    ret = SetCallbackByChannelId(channelId, recvCallback, nullptr);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] channelId=%{public}d set recv callback failed.", channelId);
        ThrowBusinessException(ret);
        return;
    }
}

static int32_t DisableCallback(int32_t channelId, ListenerType type)
{
    int32_t ret = SetListenerState(channelId, type, false);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] channelId=%{public}d set listener failed. ret=%{public}d", channelId, ret);
        return ret;
    }
    ret = OffCallbackByChannelId(channelId, type);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] channelId=%{public}d off callback failed. ret=%{public}d", channelId, ret);
        return ret;
    }
    return SOFTBUS_OK;
}

void OffReceiveData(int32_t channelId, ::taihe::optional_view<
    ::taihe::callback<void(::ohos::distributedsched::proxyChannelManager::DataInfo const& dataInfo)>> callback)
{
    (void)callback;
    int32_t ret = DisableCallback(channelId, DATA_RECEIVE);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] channelId=%{public}d disable recv callback failed.", channelId);
        ThrowBusinessException(ret);
    }
}

void OnChannelStateChange(int32_t channelId, ::taihe::callback_view<
    void(::ohos::distributedsched::proxyChannelManager::ChannelStateInfo const& stateInfo)> callback)
{
    int32_t ret = SetListenerState(channelId, CHANNEL_STATE, true);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] channelId=%{public}d set listener failed.", channelId);
        ThrowBusinessException(ret);
        return;
    }
    auto stateCallback = std::make_shared<::taihe::callback<
        void(::ohos::distributedsched::proxyChannelManager::ChannelStateInfo const& stateInfo)>>(callback);
    ret = SetCallbackByChannelId(channelId, nullptr, stateCallback);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] channelId=%{public}d set state change callback failed.", channelId);
        ThrowBusinessException(ret);
        return;
    }
}

void OffChannelStateChange(int32_t channelId, ::taihe::optional_view<
    ::taihe::callback<void(::ohos::distributedsched::proxyChannelManager::ChannelStateInfo const& stateInfo)>> callback)
{
    (void)callback;
    int32_t ret = DisableCallback(channelId, CHANNEL_STATE);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] channelId=%{public}d disable state change callback failed.", channelId);
        ThrowBusinessException(ret);
    }
}
} // namespace

// Since these macros are auto-generate, lint will cause false positive.
// NOLINTBEGIN
TH_EXPORT_CPP_API_OpenProxyChannelAsync(OpenProxyChannelAsync);
TH_EXPORT_CPP_API_CloseProxyChannel(CloseProxyChannel);
TH_EXPORT_CPP_API_SendDataAsync(SendDataAsync);
TH_EXPORT_CPP_API_OnReceiveData(OnReceiveData);
TH_EXPORT_CPP_API_OffReceiveData(OffReceiveData);
TH_EXPORT_CPP_API_OnChannelStateChange(OnChannelStateChange);
TH_EXPORT_CPP_API_OffChannelStateChange(OffChannelStateChange);
// NOLINTEND
