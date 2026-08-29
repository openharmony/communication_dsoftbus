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

#include "proxy_manager.h"

#include "far_field/far_field_proxy_adapter.h"
#include "far_field/far_field_proxy_manager.h"
#include "br/br_proxy_manager.h"
#include "softbus_rc_object.h"
#include "br/proxy_observer.h"
#include "conn_log.h"
#include "securec.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_bt_common.h"
#include "softbus_conn_interface_struct.h"
#include "softbus_conn_manager_struct.h"

static ProxyConnectListener g_listener = {0};
static SoftBusMutex g_reqIdLock;
static uint32_t g_reqId = 1;

#define REQUEST_ID_MATCH_ALL 0

typedef enum {
    BR_PROXY,
    FAR_FIELD_PROXY,
} ProxyChannelType;

typedef struct {
    SOFT_BUS_RC_OBJECT_BASE;
    ProxyChannelType type;
    bool isDirectly;
    int32_t requestId;
    char realBrMac[BT_MAC_LEN];
    char srcBrMac[BT_MAC_MAX_LEN];
    char uuid[UUID_STRING_LEN];
    bool isSupportFarField;
    OpenProxyChannelCallback callback;
} ProxyChannelInfo;

static uint32_t GenerateRequestId(void)
{
    int32_t ret = SoftBusMutexLock(&g_reqIdLock);
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, PROXY_CHANNEL_MAX_STATE, CONN_PROXY,
        "lock channel fail, error=%{public}d", ret);
    if (g_reqId == REQUEST_ID_MATCH_ALL) {
        g_reqId++;
    }
    uint32_t reqId = g_reqId++;
    SoftBusMutexUnlock(&g_reqIdLock);
    return reqId;
}

static bool IsRealMac(const char *brMac)
{
    if (strlen(brMac) != BT_MAC_LEN - 1) {
        CONN_LOGW(CONN_PROXY, "brMac length is not match, len=%{public}zu", strlen(brMac));
        return false;
    }
    int32_t macConLonPos = 3;
    for (int32_t i = 0; i < BT_MAC_LEN - 1; i++) {
        if ((i + 1) % macConLonPos == 0) {
            if (brMac[i] != ':') {
                CONN_LOGE(CONN_PROXY, "brMac format error");
                return false;
            }
        } else if (!(brMac[i] >= '0' && brMac[i] <= '9') &&
                   !(brMac[i] >= 'a' && brMac[i] <= 'f') &&
                   !(brMac[i] >= 'A' && brMac[i] <= 'F')) {
            CONN_LOGE(CONN_PROXY, "brMac format error");
            return false;
        }
    }
    return true;
}

static void DestroyProxyChannelInfo(ProxyChannelInfo *info)
{
    SoftBusFree(info);
}

static void ProxyChannelInfoFreeHook(SoftBusRcObject *object)
{
    DestroyProxyChannelInfo((ProxyChannelInfo*)object);
}

static ProxyChannelInfo *CreateProxyChannelInfo(ProxyChannelType type, ProxyChannelParam *param, bool isRealMac)
{
    ProxyChannelInfo *proxyChannel = (ProxyChannelInfo *)SoftBusCalloc(sizeof(ProxyChannelInfo));
    CONN_CHECK_AND_RETURN_RET_LOGE(proxyChannel != NULL, NULL, CONN_PROXY, "proxyChannel is NULL");
    int32_t ret = SoftBusRcObjectConstruct("proxy_channel", (SoftBusRcObject *)proxyChannel, ProxyChannelInfoFreeHook);
    if (ret != SOFTBUS_OK) {
        SoftBusFree(proxyChannel);
        return NULL;
    }
    proxyChannel->type = type;
    proxyChannel->requestId = param->requestId;

    ret = strcpy_s(proxyChannel->srcBrMac, sizeof(proxyChannel->srcBrMac), param->brMac);
    if (ret != EOK) {
        CONN_LOGE(CONN_PROXY, "reqId=%{public}u, strcpy brMac failed", param->requestId);
        SoftBusFree(proxyChannel);
        return NULL;
    }
    ret = strcpy_s(proxyChannel->uuid, sizeof(proxyChannel->uuid), param->uuid);
    if (ret != EOK) {
        CONN_LOGE(CONN_PROXY, "reqId=%{public}u, strcpy uuid failed", param->requestId);
        SoftBusFree(proxyChannel);
        return NULL;
    }
    if ((isRealMac && strcpy_s(proxyChannel->realBrMac, BT_MAC_LEN, param->brMac) != EOK) ||
        (!isRealMac && GetRealMac(proxyChannel->realBrMac, BT_MAC_LEN, param->brMac) != SOFTBUS_OK)) {
        CONN_LOGE(CONN_PROXY, "get real mac failed");
        SoftBusFree(proxyChannel);
        return NULL;
    }

    // Check if device supports far field
    P2PDeviceInfo device = {0};
    if (strcpy_s(device.brMac, BT_MAC_LEN, proxyChannel->realBrMac) != EOK ||
        strcpy_s(device.uuid, UUID_STRING_LEN, proxyChannel->uuid) != EOK) {
        CONN_LOGE(CONN_PROXY, "copy device brMac or uuid failed, ret=%{public}d", ret);
        SoftBusFree(proxyChannel);
        return NULL;
    }
    proxyChannel->isSupportFarField = FarFieldAdapterIsDeviceSupport(&device);
    ListInit(&proxyChannel->node);
    return proxyChannel;
}

static bool ProxyChannelInfoMacMatcher(const SoftBusRcObject *object, const void *arg)
{
    const char *brMac = (const char *)arg;
    ProxyChannelInfo *proxyChannel = (ProxyChannelInfo *)object;
    return StrCmpIgnoreCase(brMac, proxyChannel->realBrMac) == 0 ||
        StrCmpIgnoreCase(brMac, proxyChannel->srcBrMac) == 0;
}

static void OnBrOpenSuccess(uint32_t requestId, struct ProxyChannel *channel)
{
    CONN_CHECK_AND_RETURN_LOGE(channel != NULL, CONN_PROXY, "channel is NULL");
    ProxyChannelInfo *proxyChannel = SoftBusRcGetCommon(&GetProxyChannelManager()->proxyConnectionList,
        ProxyChannelInfoMacMatcher, channel->brMac);
    CONN_CHECK_AND_RETURN_LOGE(proxyChannel != NULL, CONN_PROXY, "proxyChannel is NULL");
    int32_t ret = proxyChannel->Lock((SoftBusRcObject *)proxyChannel);
    if (ret != SOFTBUS_OK) {
        proxyChannel->Dereference((SoftBusRcObject **)&proxyChannel);
        return;
    }

    OpenProxyChannelCallback callback = proxyChannel->callback;
    proxyChannel->Unlock((SoftBusRcObject *)proxyChannel);
    proxyChannel->Dereference((SoftBusRcObject **)&proxyChannel);
    if (callback.onOpenSuccess != NULL) {
        callback.onOpenSuccess(requestId, channel);
    }
}

static int32_t StartOpenFieldProxyChannel(uint32_t requestId, ProxyChannelInfo *proxyChannel)
{
    FarFieldProxyParam param = {0};
    if (strcpy_s(param.device.brMac, BT_MAC_LEN, proxyChannel->realBrMac) != EOK ||
        strcpy_s(param.device.uuid, UUID_STRING_LEN, proxyChannel->uuid) != EOK ||
        strcpy_s(param.srcMac, sizeof(param.srcMac), proxyChannel->srcBrMac) != EOK) {
        CONN_LOGE(CONN_PROXY, "copy param uuid or srcMac failed");
        return SOFTBUS_STRCPY_ERR;
    }
    param.requestId = requestId;
    int32_t ret = OpenFarFieldProxyChannel(&param);
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, CONN_PROXY, "proxyChannel failed=%{public}d", ret);
    ret = proxyChannel->Lock((SoftBusRcObject *)proxyChannel);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    proxyChannel->type = FAR_FIELD_PROXY;
    proxyChannel->Unlock((SoftBusRcObject *)proxyChannel);
    return SOFTBUS_OK;
}

static void OnBrOpenFail(uint32_t requestId, int32_t reason, const char *brMac)
{
    ProxyChannelInfo *proxyChannel = SoftBusRcGetCommon(&GetProxyChannelManager()->proxyConnectionList,
        ProxyChannelInfoMacMatcher, brMac);
    CONN_CHECK_AND_RETURN_LOGE(proxyChannel != NULL, CONN_PROXY, "proxyChannel is NULL");
    int32_t ret = proxyChannel->Lock((SoftBusRcObject *)proxyChannel);
    if (ret != SOFTBUS_OK) {
        proxyChannel->Dereference((SoftBusRcObject **)&proxyChannel);
        return;
    }
    proxyChannel->isDirectly = false;
    OpenProxyChannelCallback callback = proxyChannel->callback;
    bool isSupportFarField = proxyChannel->isSupportFarField;
    proxyChannel->Unlock((SoftBusRcObject *)proxyChannel);
    if (!isSupportFarField) {
        SoftBusRcRemove(&GetProxyChannelManager()->proxyConnectionList, (SoftBusRcObject *)proxyChannel);
    }

    int32_t retReason = isSupportFarField ? SOFTBUS_CONN_PROXY_BR_FAIL_BUT_SUPPORT_FAR_FIELD : reason;
    proxyChannel->Dereference((SoftBusRcObject **)&proxyChannel);
    if (callback.onOpenFail != NULL) {
        callback.onOpenFail(requestId, retReason, brMac);
    }
}

static int32_t OpenProxyChannel(ProxyChannelParam *param, const OpenProxyChannelCallback *callback)
{
    CONN_CHECK_AND_RETURN_RET_LOGE(param != NULL, SOFTBUS_INVALID_PARAM, CONN_PROXY, "param is NULL");
    CONN_CHECK_AND_RETURN_RET_LOGE(callback != NULL, SOFTBUS_INVALID_PARAM, CONN_PROXY, "callback is NULL");
    CONN_CHECK_AND_RETURN_RET_LOGE(callback->onOpenSuccess != NULL, SOFTBUS_INVALID_PARAM,
        CONN_PROXY, "onOpenSuccess is NULL");
    CONN_CHECK_AND_RETURN_RET_LOGE(callback->onOpenFail != NULL, SOFTBUS_INVALID_PARAM,
        CONN_PROXY, "onOpenFail is NULL");
    CONN_CHECK_AND_RETURN_RET_LOGE(SoftBusGetBrState() == BR_ENABLE, SOFTBUS_CONN_BR_DISABLE_ERR,
        CONN_PROXY, "br disable");
    bool isRealMac = IsRealMac(param->brMac);
    ProxyChannelInfo *proxyChannel = SoftBusRcGetCommon(&GetProxyChannelManager()->proxyConnectionList,
        ProxyChannelInfoMacMatcher, param->brMac);
    if (proxyChannel == NULL) {
        proxyChannel = CreateProxyChannelInfo(BR_PROXY, param, isRealMac);
        CONN_CHECK_AND_RETURN_RET_LOGE(proxyChannel != NULL, SOFTBUS_MALLOC_ERR, CONN_PROXY, "proxyChannel is NULL");
        int32_t ret = SoftBusRcSave(&GetProxyChannelManager()->proxyConnectionList, (SoftBusRcObject *)proxyChannel);
        if (ret != SOFTBUS_OK) {
            proxyChannel->Dereference((SoftBusRcObject **)&proxyChannel);
            return ret;
        }
    }
    int32_t ret = proxyChannel->Lock((SoftBusRcObject *)proxyChannel);
    if (ret != SOFTBUS_OK) {
        proxyChannel->Dereference((SoftBusRcObject **)&proxyChannel);
        return ret;
    }
    proxyChannel->requestId = param->requestId;
    proxyChannel->isDirectly = true;
    bool isConnectBr = proxyChannel->type == BR_PROXY;
    proxyChannel->callback = *callback;
    bool isSupportFarField = proxyChannel->isSupportFarField;
    proxyChannel->Unlock((SoftBusRcObject *)proxyChannel);

    bool isOpenBrProxy = (param->isFirstConnect || isConnectBr) ? true : false;
    if (isOpenBrProxy) {
        OpenProxyChannelCallback innerCallback = {
            .onOpenSuccess = OnBrOpenSuccess, .onOpenFail = OnBrOpenFail,
        };
        ret = GetBrProxyChannelManager()->openBrProxyChannel(param, isRealMac, isSupportFarField, &innerCallback);
    } else {
        ret = StartOpenFieldProxyChannel(proxyChannel->requestId, proxyChannel);
    }
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_PROXY, "send msg fail, error=%{public}d", ret);
        SoftBusRcRemove(&GetProxyChannelManager()->proxyConnectionList, (SoftBusRcObject *)proxyChannel);
        proxyChannel->Dereference((SoftBusRcObject **)&proxyChannel);
        return ret;
    }
    proxyChannel->Dereference((SoftBusRcObject **)&proxyChannel);
    return SOFTBUS_OK;
}

static void ClearProxyInfo(struct ProxyChannel *channel)
{
    CONN_CHECK_AND_RETURN_LOGE(channel != NULL, CONN_PROXY, "channel is NULL");
    CONN_LOGE(CONN_PROXY, "channelId=%{public}d", channel->channelId);
    ProxyChannelInfo *proxyChannel = SoftBusRcGetCommon(&GetProxyChannelManager()->proxyConnectionList,
        ProxyChannelInfoMacMatcher, channel->brMac);
    CONN_CHECK_AND_RETURN_LOGE(proxyChannel != NULL, CONN_PROXY, "proxyChannel is NULL");
    SoftBusRcRemove(&GetProxyChannelManager()->proxyConnectionList, (SoftBusRcObject *)proxyChannel);
    proxyChannel->Dereference((SoftBusRcObject **)&proxyChannel);
}

static void OnProxyChannelDataReceived(struct ProxyChannel *channel, const uint8_t *data, uint32_t dataLen)
{
    if (g_listener.onProxyChannelDataReceived != NULL) {
        g_listener.onProxyChannelDataReceived(channel, data, dataLen);
    }
}

static void OnBrProxyDisconnected(struct ProxyChannel *channel, int32_t reason)
{
    ProxyChannelInfo *proxyChannel = SoftBusRcGetCommon(&GetProxyChannelManager()->proxyConnectionList,
        ProxyChannelInfoMacMatcher, channel->brMac);
    CONN_CHECK_AND_RETURN_LOGE(proxyChannel != NULL, CONN_PROXY, "proxyChannel is NULL");
    ProxyChannelType type = proxyChannel->type;
    proxyChannel->Dereference((SoftBusRcObject **)&proxyChannel);
    if (type != BR_PROXY) {
        CONN_LOGI(CONN_PROXY, "not br proxy, skip br disconnect, type=%{public}d", type);
        return;
    }
    if (g_listener.onProxyChannelDisconnected != NULL) {
        g_listener.onProxyChannelDisconnected(channel, reason);
    }
}

static void OnFarFieldProxyDisconnected(struct ProxyChannel *channel, int32_t reason)
{
    ProxyChannelInfo *proxyChannel = SoftBusRcGetCommon(&GetProxyChannelManager()->proxyConnectionList,
        ProxyChannelInfoMacMatcher, channel->brMac);
    CONN_CHECK_AND_RETURN_LOGE(proxyChannel != NULL, CONN_PROXY, "proxyChannel is NULL");
    ProxyChannelType type = proxyChannel->type;
    proxyChannel->Dereference((SoftBusRcObject **)&proxyChannel);
    if (type != FAR_FIELD_PROXY) {
        CONN_LOGI(CONN_PROXY, "not far field proxy, skip far field disconnect, type=%{public}d", type);
        return;
    }
    if (g_listener.onProxyChannelDisconnected != NULL) {
        g_listener.onProxyChannelDisconnected(channel, reason);
    }
}

static void OnBrProxyReconnected(const char *addr, struct ProxyChannel *channel)
{
    if (g_listener.onProxyChannelReconnected != NULL) {
        g_listener.onProxyChannelReconnected(addr, channel);
    }
    ProxyChannelInfo *proxyChannel = SoftBusRcGetCommon(&GetProxyChannelManager()->proxyConnectionList,
        ProxyChannelInfoMacMatcher, addr);
    CONN_CHECK_AND_RETURN_LOGE(proxyChannel != NULL, CONN_PROXY, "proxyChannel is NULL");
    ClearFarFieldProxy(addr);
    int32_t ret = proxyChannel->Lock((SoftBusRcObject *)proxyChannel);
    if (ret != SOFTBUS_OK) {
        proxyChannel->Dereference((SoftBusRcObject **)&proxyChannel);
        return;
    }
    proxyChannel->type = BR_PROXY;
    proxyChannel->Unlock((SoftBusRcObject *)proxyChannel);
    proxyChannel->Dereference((SoftBusRcObject **)&proxyChannel);
}

static void OnBrProxyEnable(uint32_t requestId, const char *addr)
{
    ProxyChannelInfo *proxyChannel = SoftBusRcGetCommon(&GetProxyChannelManager()->proxyConnectionList,
        ProxyChannelInfoMacMatcher, addr);
    CONN_CHECK_AND_RETURN_LOGE(proxyChannel != NULL, CONN_PROXY, "proxyChannel is NULL");
    if (!proxyChannel->isSupportFarField) {
        CONN_LOGE(CONN_PROXY, "not support far filed ability");
        return;
    }
    int32_t ret = proxyChannel->Lock((SoftBusRcObject *)proxyChannel);
    if (ret != SOFTBUS_OK) {
        proxyChannel->Dereference((SoftBusRcObject **)&proxyChannel);
        return;
    }
    proxyChannel->isDirectly = false;
    proxyChannel->Unlock((SoftBusRcObject *)proxyChannel);

    ret = StartOpenFieldProxyChannel(requestId, proxyChannel);
    if (ret != SOFTBUS_OK) {
        proxyChannel->Dereference((SoftBusRcObject **)&proxyChannel);
        return;
    }
    proxyChannel->Dereference((SoftBusRcObject **)&proxyChannel);
}

static void OnFarFieldOpenFail(uint32_t requestId, int32_t reason, const char *brMac)
{
    CONN_CHECK_AND_RETURN_LOGE(brMac != NULL, CONN_PROXY, "brMac is NULL");
    CONN_LOGI(CONN_PROXY, "Far field open failed, reason=%{public}d", reason);
    ProxyChannelInfo *proxyChannel = SoftBusRcGetCommon(&GetProxyChannelManager()->proxyConnectionList,
        ProxyChannelInfoMacMatcher, brMac);
    CONN_CHECK_AND_RETURN_LOGE(proxyChannel != NULL, CONN_PROXY, "proxyChannel is NULL");
    int32_t ret = proxyChannel->Lock((SoftBusRcObject *)proxyChannel);
    if (ret != SOFTBUS_OK) {
        proxyChannel->Dereference((SoftBusRcObject **)&proxyChannel);
        return;
    }
    bool isDirectly = proxyChannel->isDirectly;
    OpenProxyChannelCallback callback = proxyChannel->callback;
    proxyChannel->Unlock((SoftBusRcObject *)proxyChannel);
    proxyChannel->Dereference((SoftBusRcObject **)&proxyChannel);
    if (callback.onOpenFail != NULL && isDirectly) {
        callback.onOpenFail(requestId, reason, brMac);
    }
}

static void OnFarFieldConnected(uint32_t requestId, struct ProxyChannel *channel)
{
    CONN_CHECK_AND_RETURN_LOGE(channel != NULL, CONN_PROXY, "channel is NULL");

    // Find the corresponding ProxyChannelInfo by brMac
    ProxyChannelInfo *proxyChannel = SoftBusRcGetCommon(&GetProxyChannelManager()->proxyConnectionList,
        ProxyChannelInfoMacMatcher, channel->brMac);
    CONN_CHECK_AND_RETURN_LOGE(proxyChannel != NULL, CONN_PROXY, "proxyChannel not found");

    int32_t ret = proxyChannel->Lock((SoftBusRcObject *)proxyChannel);
    if (ret != SOFTBUS_OK) {
        proxyChannel->Dereference((SoftBusRcObject **)&proxyChannel);
        return;
    }

    if (proxyChannel->type != FAR_FIELD_PROXY) {
        CONN_LOGW(CONN_PROXY, "Not a far field proxy channel");
        proxyChannel->Unlock((SoftBusRcObject *)proxyChannel);
        ClearFarFieldProxy(channel->brMac);
        proxyChannel->Dereference((SoftBusRcObject **)&proxyChannel);
        return;
    }

    bool isDirectly = proxyChannel->isDirectly;
    if (isDirectly) {
        proxyChannel->isDirectly = false;
    }
    OpenProxyChannelCallback callback = proxyChannel->callback;
    proxyChannel->Unlock((SoftBusRcObject *)proxyChannel);
    proxyChannel->Dereference((SoftBusRcObject **)&proxyChannel);

    if (isDirectly) {
        if (callback.onOpenSuccess != NULL) {
            callback.onOpenSuccess(requestId, channel);
        }
    } else {
        if (g_listener.onProxyChannelReconnected != NULL) {
            g_listener.onProxyChannelReconnected(channel->brMac, channel);
        }
    }
}

static int32_t RegisterProxyChannelListener(ProxyConnectListener *listener)
{
    CONN_CHECK_AND_RETURN_RET_LOGE(listener != NULL, SOFTBUS_INVALID_PARAM, CONN_PROXY, "listener is NULL");
    CONN_CHECK_AND_RETURN_RET_LOGE(listener->onProxyChannelDisconnected != NULL, SOFTBUS_INVALID_PARAM,
        CONN_PROXY, "Disconnected is NULL");
    CONN_CHECK_AND_RETURN_RET_LOGE(listener->onProxyChannelDataReceived != NULL, SOFTBUS_INVALID_PARAM,
        CONN_PROXY, "DataReceived is NULL");
    CONN_CHECK_AND_RETURN_RET_LOGE(listener->onProxyChannelReconnected != NULL, SOFTBUS_INVALID_PARAM,
        CONN_PROXY, "Reconnected is NULL");
    g_listener = *listener;
    return SOFTBUS_OK;
}

static uint32_t GenerateChannelId(void)
{
    static uint16_t nextId = 0;
    return (CONNECT_PROXY_CHANNEL << CONNECT_TYPE_SHIFT) + (++nextId);
}

static ProxyChannelManager g_proxyChannelManager = {
    .generateRequestId = GenerateRequestId,
    .openProxyChannel = OpenProxyChannel,
    .registerProxyChannelListener = RegisterProxyChannelListener,
    .generateChannelId = GenerateChannelId,
    .clearProxyInfo = ClearProxyInfo,
};

ProxyChannelManager *GetProxyChannelManager(void)
{
    return &g_proxyChannelManager;
}

int32_t ProxyChannelManagerInit(void)
{
    int32_t ret = SoftBusRcCollectionConstruct("proxy_channel", &GetProxyChannelManager()->proxyConnectionList, NULL);
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_CREATE_LIST_ERR,
        CONN_INIT, "create channels list fail");
    ret = SoftBusMutexInit(&g_reqIdLock, NULL);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_PROXY, "init lock falied");
        SoftBusRcCollectionDestruct(&g_proxyChannelManager.proxyConnectionList);
        return ret;
    }

    static BrProxyListener listener = {
        .onProxyChannelDataReceived = OnProxyChannelDataReceived,
        .onProxyChannelDisconnected = OnBrProxyDisconnected,
        .onProxyChannelReconnected = OnBrProxyReconnected,
        .onBrProxyStateChanged = OnBrProxyEnable,
    };
    ret = GetBrProxyChannelManager()->registerBrProxyListener(&listener);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_PROXY, "register br proxy listener failed, ret=%{public}d", ret);
        SoftBusRcCollectionDestruct(&g_proxyChannelManager.proxyConnectionList);
        return ret;
    }
    static FarFieldProxyListener farFieldProxyListener = {
        .onFarFieldProxyDataReceived = OnProxyChannelDataReceived,
        .onFarFieldProxyDisconnected = OnFarFieldProxyDisconnected,
        .onFarFieldConnected = OnFarFieldConnected,
        .onFarFieldOpenFail = OnFarFieldOpenFail,
    };
    ret = RegisterFarFieldProxyListener(&farFieldProxyListener);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_PROXY, "register far field listener failed");
        SoftBusRcCollectionDestruct(&g_proxyChannelManager.proxyConnectionList);
        return ret;
    }
    ret = FarFieldProxyManagerInit();
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_PROXY, "far field init failed=%{public}d", ret);
        SoftBusRcCollectionDestruct(&g_proxyChannelManager.proxyConnectionList);
        return ret;
    }
    ret = BrProxyChannelManagerInit();
    CONN_LOGI(CONN_PROXY, "ret=%{public}d", ret);
    return ret;
}