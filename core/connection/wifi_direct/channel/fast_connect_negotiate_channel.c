/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include "fast_connect_negotiate_channel.h"
#include "securec.h"
#include "conn_log.h"
#include "softbus_error_code.h"
#include "softbus_adapter_mem.h"
#include "softbus_proxychannel_pipeline.h"
#include "auth_interface.h"
#include "bus_center_manager.h"
#include "wifi_direct_manager.h"
#include "utils/wifi_direct_work_queue.h"

#define MAX_FAST_CONNECT_DATA_LEN 1024

struct DataStruct {
    int32_t channelId;
    size_t len;
    uint8_t data[];
};

static void DataReceivedWorkHandler(void *data)
{
    struct DataStruct *dataStruct = data;
    struct FastConnectNegotiateChannel channel;
    FastConnectNegotiateChannelConstructor(&channel, dataStruct->channelId);
    GetWifiDirectManager()->onNegotiateChannelDataReceived((struct WifiDirectNegotiateChannel *)&channel,
                                                           dataStruct->data, dataStruct->len);
    SoftBusFree(dataStruct);
}

static void OnDataReceived(int32_t channelId, const char *data, uint32_t len)
{
    CONN_CHECK_AND_RETURN_LOGW(data != NULL && len != 0, CONN_WIFI_DIRECT, "data invalid");
    CONN_CHECK_AND_RETURN_LOGW(len <= MAX_FAST_CONNECT_DATA_LEN, CONN_WIFI_DIRECT, "data too large");
    CONN_LOGI(CONN_WIFI_DIRECT, "len=%{public}u", len);

    struct DataStruct *dataStruct = SoftBusCalloc(sizeof(struct DataStruct) + len);
    CONN_CHECK_AND_RETURN_LOGE(dataStruct, CONN_WIFI_DIRECT, "malloc failed");

    dataStruct->channelId = channelId;
    dataStruct->len = len;
    if (memcpy_s(dataStruct->data, dataStruct->len, data, len) != EOK) {
        CONN_LOGE(CONN_WIFI_DIRECT, "copy data failed");
        SoftBusFree(dataStruct);
        return;
    }
    if (CallMethodAsync(DataReceivedWorkHandler, dataStruct, 0) != SOFTBUS_OK) {
        CONN_LOGE(CONN_WIFI_DIRECT, "async failed");
        SoftBusFree(dataStruct);
    }
}

static void OnDisconnected(int32_t channelId)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "channelId=%{public}d", channelId);
}

static int32_t PostData(struct WifiDirectNegotiateChannel *base, const uint8_t *data, size_t size)
{
    struct FastConnectNegotiateChannel *self = (struct FastConnectNegotiateChannel*)base;
    return TransProxyPipelineSendMessage(self->channelId, data, size, MSG_TYPE_P2P_NEGO);
}

static int32_t GetDeviceId(struct WifiDirectNegotiateChannel *base, char *deviceId, size_t deviceIdSize)
{
    struct FastConnectNegotiateChannel *self = (struct FastConnectNegotiateChannel*)base;
    return TransProxyPipelineGetUuidByChannelId(self->channelId, deviceId, deviceIdSize);
}

static int32_t GetP2pMac(struct WifiDirectNegotiateChannel *base, char *p2pMac, size_t p2pMacSize)
{
    struct FastConnectNegotiateChannel *self = (struct FastConnectNegotiateChannel*)base;
    char uuid[UUID_BUF_LEN] = {0};
    char networkId[NETWORK_ID_BUF_LEN] = {0};
    int32_t ret = self->getDeviceId(base, uuid, sizeof(uuid));
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "get uuid id failed");
    ret = LnnGetNetworkIdByUuid(uuid, networkId, sizeof(networkId));
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "get network id failed");
    ret = LnnGetRemoteStrInfo(networkId, STRING_KEY_P2P_MAC, p2pMac, p2pMacSize);
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "get remote p2p mac failed");
    return SOFTBUS_OK;
}

static void SetP2pMac(struct WifiDirectNegotiateChannel *base, const char *p2pMac)
{
    struct FastConnectNegotiateChannel *self = (struct FastConnectNegotiateChannel*)base;
    int32_t ret = strcpy_s(self->p2pMac, sizeof(self->p2pMac), p2pMac);
    CONN_CHECK_AND_RETURN_LOGW(ret == EOK, CONN_WIFI_DIRECT, "copy p2p mac failed");
}

static bool IsP2pChannel(struct WifiDirectNegotiateChannel *base)
{
    (void)base;
    return false;
}

static enum WifiDirectNegotiateChannelType GetMediumType(struct WifiDirectNegotiateChannel *base)
{
    (void)base;
    return NEGOTIATE_MAX;
}

static struct WifiDirectNegotiateChannel *Duplicate(struct WifiDirectNegotiateChannel *base)
{
    struct FastConnectNegotiateChannel *self = (struct FastConnectNegotiateChannel*)base;
    struct FastConnectNegotiateChannel *copy = FastConnectNegotiateChannelNew(self->channelId);
    return (struct WifiDirectNegotiateChannel*)copy;
}

static void Destructor(struct WifiDirectNegotiateChannel *base)
{
    struct FastConnectNegotiateChannel *self = (struct FastConnectNegotiateChannel*)base;
    FastConnectNegotiateChannelDelete(self);
}

void FastConnectNegotiateChannelConstructor(struct FastConnectNegotiateChannel *self, int32_t channelId)
{
    (void)memset_s(self, sizeof(*self), 0, sizeof(*self));

    self->postData = PostData;
    self->getDeviceId = GetDeviceId;
    self->getP2pMac = GetP2pMac;
    self->setP2pMac = SetP2pMac;
    self->isP2pChannel = IsP2pChannel;
    self->getMediumType = GetMediumType;
    self->duplicate = Duplicate;
    self->destructor = Destructor;

    self->channelId = channelId;
}

void FastConnectNegotiateChannelDestructor(struct FastConnectNegotiateChannel *self)
{
    (void)self;
}

struct FastConnectNegotiateChannel *FastConnectNegotiateChannelNew(int32_t channelId)
{
    struct FastConnectNegotiateChannel *self = SoftBusCalloc(sizeof(*self));
    if (self) {
        FastConnectNegotiateChannelConstructor(self, channelId);
    }
    return self;
}

void FastConnectNegotiateChannelDelete(struct FastConnectNegotiateChannel *self)
{
    FastConnectNegotiateChannelDestructor(self);
    SoftBusFree(self);
}

int32_t FastConnectNegotiateChannelInit(void)
{
    CONN_LOGI(CONN_INIT, "init enter");
    ITransProxyPipelineListener listener = {
        .onDataReceived = OnDataReceived,
        .onDisconnected = OnDisconnected,
    };
    int32_t ret = TransProxyPipelineRegisterListener(MSG_TYPE_P2P_NEGO, &listener);
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == SOFTBUS_OK, ret, CONN_INIT, "register proxy channel listener failed");
    return SOFTBUS_OK;
}