/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "softbus_transmission_interface.h"

#include <securec.h>
#include <unistd.h>

#include "session.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_proxychannel_manager.h"
#include "softbus_trans_def.h"
#include "trans_channel_manager.h"
#include "trans_event.h"
#include "trans_event_form.h"
#include "trans_log.h"
#include "trans_inner.h"
#include "trans_inner_self_adaptive.h"
#include "trans_session_service.h"
#include "trans_tcp_direct_sessionconn.h"
#define MIN_BW (4 * 1024)
#define MIN_LATENCY 0
#define MAX_LATENCY 10000

static ISessionListenerInner *g_InnerListener = NULL;

static int32_t InnerMessageHandler(int32_t sessionId, const void *data, uint32_t dataLen)
{
    if (g_InnerListener == NULL || g_InnerListener->OnBytesReceived == NULL) {
        TRANS_LOGE(TRANS_CTRL, "inner session not create session server");
        return SOFTBUS_NO_INIT;
    }
    g_InnerListener->OnBytesReceived(sessionId, (const char *)data, dataLen);
    return SOFTBUS_OK;
}

static int32_t GetIsClientInfoById(int32_t channelId, int32_t channelType, bool *isClient)
{
    TRANS_CHECK_AND_RETURN_RET_LOGE(isClient != NULL, SOFTBUS_INVALID_PARAM, TRANS_CTRL, "invalid param");
    AppInfo appInfo = {};
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    int32_t ret = SOFTBUS_OK;
    if (channelType == CHANNEL_TYPE_TCP_DIRECT) {
        ret = GetAppInfoById(channelId, &appInfo);
        (void)memset_s(appInfo.sessionKey, SESSION_KEY_LENGTH, 0, SESSION_KEY_LENGTH);
        TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_CTRL, "get appInfo failed");
        *isClient = appInfo.isClient;
        return SOFTBUS_OK;
    }
    (void)memset_s(appInfo.sessionKey, SESSION_KEY_LENGTH, 0, SESSION_KEY_LENGTH);
    ret = TransProxyGetAppInfoById(channelId, &appInfo);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_CTRL, "get appInfo failed");
    *isClient = appInfo.isClient;
    return SOFTBUS_OK;
}

static int32_t OnSessionOpenedInner(int32_t channelId, char *peerNetworkId, int32_t result)
{
    int32_t fd = 0;
    bool isClient = 0;
    int32_t channelType = 0;
    SessionInnerCallback listener = { 0 };
    listener.func = InnerMessageHandler;
    char sessionKey[SESSION_KEY_LENGTH];
    (void)memset_s(sessionKey, SESSION_KEY_LENGTH, 0, SESSION_KEY_LENGTH);
    int32_t ret = GetSessionInfo(channelId, &fd, &channelType, sessionKey, SESSION_KEY_LENGTH);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_CTRL, "GetSessionInfo failed!");
    TRANS_LOGI(TRANS_CTRL, "inner session open success, channelId=%{public}d", channelId);
    if (channelType == CHANNEL_TYPE_TCP_DIRECT) {
        ret = DirectChannelCreateListener(fd);
        TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_CTRL, "inner session create listener failed");
    }
    InnerSessionInfo innerInfo;
    innerInfo.fd = fd;
    innerInfo.channelId = channelId;
    innerInfo.channelType = channelType;
    innerInfo.listener = &listener;
    innerInfo.supportTlv = true;
    memcpy_s(innerInfo.peerNetworkId, NETWORK_ID_BUF_LEN, peerNetworkId, NETWORK_ID_BUF_LEN);
    ret = GetIsClientInfoById(channelId, channelType, &isClient);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_CTRL, "GetSessionInfo failed");
    ret = memcpy_s(innerInfo.sessionKey, sizeof(innerInfo.sessionKey), sessionKey, sizeof(sessionKey));
    if (ret != EOK) {
        (void)memset_s(sessionKey, SESSION_KEY_LENGTH, 0, SESSION_KEY_LENGTH);
        TRANS_LOGE(TRANS_CTRL, "memcpy sessionkey failed, channelId=%{public}d", channelId);
        return SOFTBUS_MEM_ERR;
    }
    ret = InnerAddSession(&innerInfo);
    (void)memset_s(sessionKey, SESSION_KEY_LENGTH, 0, SESSION_KEY_LENGTH);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_CTRL,
        "InnerAddSession failed, channelId=%{public}d", channelId);
    ret = TransInnerAddDataBufNode(channelId, fd, channelType);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_CTRL,
        "Inner session add data buf node failed, channelId=%{public}d", channelId);
    if (isClient) {
        TRANS_LOGI(TRANS_CTRL, "OnSessionOpened,channelId=%{public}d", channelId);
        return g_InnerListener->OnSessionOpened(channelId, channelType, peerNetworkId, result);
    }
    ret = ServerSideSendAck(channelId, ret);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_CTRL,
        "Inner session opened failed, channelId=%{public}d", channelId);
    TRANS_LOGI(TRANS_CTRL, "OnSessionOpened,channelId=%{public}d", channelId);
    return g_InnerListener->OnSessionOpened(channelId, channelType, peerNetworkId, result);
}

static int32_t TransOnSessionOpenedInner(int32_t channelId, int32_t channelType, char *peerNetworkId, int32_t result)
{
    if (g_InnerListener == NULL || g_InnerListener->OnSessionOpened == NULL) {
        TRANS_LOGE(TRANS_CTRL, "inner session not create session server");
        return SOFTBUS_NO_INIT;
    }
    if (channelType == CHANNEL_TYPE_UNDEFINED) {
        return g_InnerListener->OnSessionOpened(channelId, channelType, peerNetworkId, result);
    }
    if (result != SOFTBUS_OK) {
        CloseSessionInner(channelId);
        return g_InnerListener->OnSessionOpened(channelId, channelType, peerNetworkId, result);
    }
    return OnSessionOpenedInner(channelId, peerNetworkId, result);
}

static void TransOnSessionClosedInner(int32_t channelId)
{
    if (g_InnerListener == NULL || g_InnerListener->OnSessionClosed== NULL) {
        TRANS_LOGE(TRANS_CTRL, "inner session not create session server");
        return;
    }
    TRANS_LOGI(TRANS_CTRL, "session close, channelId=%{public}d", channelId);
    g_InnerListener->OnSessionClosed(channelId);
    return;
}

static void TransOnBytesReceivedInner(int32_t channelId, const void *data, uint32_t dataLen)
{
    int32_t ret = ProxyDataRecvHandler(channelId, (const char *)data, dataLen);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "recv data failed channelId=%{public}d", channelId);
    }
}

static int32_t TransOnSetChannelInfoByReqId(uint32_t reqId, int32_t channelId, int32_t channelType)
{
    if (g_InnerListener == NULL || g_InnerListener->OnSetChannelInfoByReqId== NULL) {
        TRANS_LOGE(TRANS_CTRL, "inner session not create session server");
        return SOFTBUS_INVALID_PARAM;
    }
    return g_InnerListener->OnSetChannelInfoByReqId(reqId, channelId, channelType);
}

static void TransOnLinkDownInner(const char *networkId)
{
    (void)networkId;
}

static ISessionListenerInner g_innerSessionListener = {
    .OnSessionOpened = TransOnSessionOpenedInner,
    .OnSessionClosed = TransOnSessionClosedInner,
    .OnBytesReceived = TransOnBytesReceivedInner,
    .OnLinkDown = TransOnLinkDownInner,
    .OnSetChannelInfoByReqId = TransOnSetChannelInfoByReqId,
};

int32_t TransCreateSessionServerInner(
    const char *pkgName, const char *sessionName, const ISessionListenerInner *listener)
{
    int32_t ret = 0;
    if (g_InnerListener == NULL) {
        g_InnerListener = (ISessionListenerInner *)SoftBusCalloc(sizeof(ISessionListenerInner));
        if (g_InnerListener == NULL) {
            TRANS_LOGE(TRANS_CTRL, "malloc failed");
            return SOFTBUS_MALLOC_ERR;
        }
    }
    ret = memcpy_s(g_InnerListener, sizeof(ISessionListenerInner), listener, sizeof(ISessionListenerInner));
    if (ret != EOK) {
        SoftBusFree(g_InnerListener);
        g_InnerListener = NULL;
        TRANS_LOGE(TRANS_CTRL, "memcpy_s session listener failed");
        return SOFTBUS_MEM_ERR;
    }
    TransClientSetInnerListener(pkgName, sessionName, &g_innerSessionListener);
    ret = TransCreateSessionServer(pkgName, sessionName, getuid(), getpid());
    TRANS_LOGI(TRANS_CTRL, "create session inner server ret=%{public}d", ret);
    return ret;
}

int32_t TransOpenSessionInner(const char *sessionName, const char *peerNetworkId, uint32_t reqId)
{
    SessionAttribute addr = {
        .dataType = TYPE_BYTES,
    };
    static QosTV info[] = {
        { .qos = QOS_TYPE_MIN_BW, .value = MIN_BW, },
        { .qos = QOS_TYPE_MIN_LATENCY, .value = MIN_LATENCY, },
        { .qos = QOS_TYPE_MAX_LATENCY, .value = MAX_LATENCY, },
    };
    SessionParam param = {
        .sessionName = sessionName,
        .peerSessionName = sessionName,
        .peerDeviceId = peerNetworkId,
        .groupId = "",
        .attr = &addr,
        .qosCount = 3,
        .sessionId = reqId,
        .isQosLane = true,
        .pid = getpid(),
    };
    (void)memcpy_s(param.qos, sizeof(QosTV) * param.qosCount, info, sizeof(QosTV) * param.qosCount);
    
    TransInfo transInfo = { 0 };
    int32_t ret = TransOpenChannel(&param, &transInfo);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "inner session open failed! ret=%{public}d", ret);
        return ret;
    }
    TRANS_LOGI(TRANS_CTRL, "inner session open success! channelId=%{public}d", transInfo.channelId);
    return ret;
}

int32_t TransSendDataInner(int32_t channelId, const char *data, uint32_t len)
{
    TRANS_LOGI(TRANS_CTRL, "inner session send data! channelId=%{public}d, len=%{public}u", channelId, len);
    return TransSendData(channelId, (const void *)data, len);
}

void TransCloseSessionInner(int32_t channelId)
{
    TRANS_LOGI(TRANS_CTRL, "enter, channelId=%{public}d", channelId);
    CloseSessionInner(channelId);
    return;
}
