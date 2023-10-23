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

#include "default_negotiate_channel.h"
#include "securec.h"
#include "common_list.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_log.h"
#include "auth_interface.h"
#include "auth_manager.h"
#include "bus_center_manager.h"
#include "wifi_direct_manager.h"
#include "utils/wifi_direct_work_queue.h"
#include "utils/wifi_direct_anonymous.h"

#define LOG_LABEL "[WD] DNC: "
#define MAX_AUTH_DATA_LEN (1024 * 1024)

static void OnAuthDataReceived(int64_t authId, const AuthTransData *data);
static void OnAuthDisconnected(int64_t authId);

static AuthTransListener g_authListener = {.onDataReceived = OnAuthDataReceived, .onDisconnected = OnAuthDisconnected};

int32_t DefaultNegotiateChannelInit(void)
{
    int32_t ret = RegAuthTransListener(MODULE_P2P_LINK, &g_authListener);
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, SOFTBUS_ERR, LOG_LABEL "register auth transfer listener failed");
    CLOGI(LOG_LABEL "register auth transfer listener success");
    return SOFTBUS_OK;
}

struct DataStruct {
    int64_t authId;
    size_t len;
    uint8_t data[];
};

static void DataReceivedWorkHandler(void *data)
{
    struct DataStruct *dataStruct = data;
    struct DefaultNegotiateChannel channel;
    DefaultNegotiateChannelConstructor(&channel, dataStruct->authId);
    GetWifiDirectManager()->onNegotiateChannelDataReceived((struct WifiDirectNegotiateChannel *)&channel,
                                                           dataStruct->data, dataStruct->len);
    DefaultNegotiateChannelDestructor(&channel);
    SoftBusFree(dataStruct);
}

static void OnAuthDataReceived(int64_t authId, const AuthTransData *data)
{
    CONN_CHECK_AND_RETURN_LOG(data != NULL && data->data != NULL && data->len != 0, LOG_LABEL "data invalid");
    CONN_CHECK_AND_RETURN_LOG(data->len <= MAX_AUTH_DATA_LEN, LOG_LABEL "data too large");
    CLOGI(LOG_LABEL "len=%u", data->len);

    struct DataStruct *dataStruct = SoftBusCalloc(sizeof(struct DataStruct) + data->len);
    CONN_CHECK_AND_RETURN_LOG(dataStruct, LOG_LABEL "malloc failed");

    dataStruct->authId = authId;
    dataStruct->len = data->len;
    if (memcpy_s(dataStruct->data, dataStruct->len, data->data, data->len) != EOK) {
        CLOGE(LOG_LABEL "memcpy_s failed");
        SoftBusFree(dataStruct);
        return;
    }
    if (CallMethodAsync(DataReceivedWorkHandler, dataStruct, 0) != SOFTBUS_OK) {
        CLOGE(LOG_LABEL "async failed");
        SoftBusFree(dataStruct);
    }
}

static void OnAuthDisconnected(int64_t authId)
{
    struct DefaultNegotiateChannel channel;
    DefaultNegotiateChannelConstructor(&channel, authId);
    GetWifiDirectManager()->onNegotiateChannelDisconnected((struct WifiDirectNegotiateChannel *)&channel);
}

static int64_t GenerateSequence(void)
{
    static int64_t wifiDirectTransferSequence = 0;

    if (wifiDirectTransferSequence < 0) {
        wifiDirectTransferSequence = 0;
    }
    return wifiDirectTransferSequence++;
}

static int32_t PostData(struct WifiDirectNegotiateChannel *base, const uint8_t *data, size_t size)
{
    AuthTransData dataInfo = {
        .module = MODULE_P2P_LINK,
        .flag = 0,
        .seq = GenerateSequence(),
        .len = size,
        .data = data,
    };

    struct DefaultNegotiateChannel *channel = (struct DefaultNegotiateChannel *)base;
    CONN_CHECK_AND_RETURN_RET_LOG(AuthPostTransData(channel->authId, &dataInfo) == SOFTBUS_OK, SOFTBUS_ERR,
                                  LOG_LABEL "post data failed");
    return SOFTBUS_OK;
}

static int32_t GetDeviceId(struct WifiDirectNegotiateChannel *base, char *deviceId, size_t deviceIdSize)
{
    int32_t ret = AuthGetDeviceUuid(((struct DefaultNegotiateChannel *)base)->authId, deviceId, deviceIdSize);
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, ret, "get device id failed");
    return ret;
}

static int32_t GetP2pMac(struct WifiDirectNegotiateChannel *base, char *p2pMac, size_t p2pMacSize)
{
    struct DefaultNegotiateChannel *self = (struct DefaultNegotiateChannel *)base;
    int32_t ret = SOFTBUS_OK;
    if (strlen(self->p2pMac) == 0) {
        char uuid[UUID_BUF_LEN] = {0};
        char networkId[NETWORK_ID_BUF_LEN] = {0};
        ret = self->getDeviceId(base, uuid, sizeof(uuid));
        CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, ret, LOG_LABEL "get uuid id failed");
        ret = LnnGetNetworkIdByUuid(uuid, networkId, sizeof(networkId));
        CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, ret, LOG_LABEL "get network id failed");
        ret = LnnGetRemoteStrInfo(networkId, STRING_KEY_P2P_MAC, p2pMac, p2pMacSize);
        CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, ret, LOG_LABEL "get remote p2p mac failed");
        return ret;
    }

    ret = strcpy_s(p2pMac, p2pMacSize, self->p2pMac);
    return ret == EOK ? SOFTBUS_OK : SOFTBUS_ERR;
}

static void SetP2pMac(struct WifiDirectNegotiateChannel *base, const char *p2pMac)
{
    struct DefaultNegotiateChannel *self = (struct DefaultNegotiateChannel *)base;
    int32_t ret = strcpy_s(self->p2pMac, sizeof(self->p2pMac), p2pMac);
    CONN_CHECK_AND_RETURN_LOG(ret == EOK, LOG_LABEL "copy p2p mac failed");
    ret = AuthSetP2pMac(((struct DefaultNegotiateChannel *)base)->authId, p2pMac);
    CONN_CHECK_AND_RETURN_LOG(ret == SOFTBUS_OK, LOG_LABEL "set auth p2p mac failed");
}

static bool IsP2pChannel(struct WifiDirectNegotiateChannel *base)
{
    AuthConnInfo connInfo;
    int32_t ret = AuthGetConnInfo(((struct DefaultNegotiateChannel *)base)->authId, &connInfo);
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, false, LOG_LABEL "get auth conn info failed");
    return connInfo.type == AUTH_LINK_TYPE_P2P;
}

static bool IsMetaChannel(struct WifiDirectNegotiateChannel *base)
{
    struct DefaultNegotiateChannel *self = (struct DefaultNegotiateChannel *)base;
    bool isMeta = false;
    int32_t ret = AuthGetMetaType(self->authId, &isMeta);
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, false, LOG_LABEL "get meta type failed");
    return isMeta;
}

static struct WifiDirectNegotiateChannel* Duplicate(struct WifiDirectNegotiateChannel *base)
{
    struct DefaultNegotiateChannel *self = (struct DefaultNegotiateChannel *)base;
    struct DefaultNegotiateChannel *copy = DefaultNegotiateChannelNew(self->authId);
    return (struct WifiDirectNegotiateChannel*)copy;
}

static void Destructor(struct WifiDirectNegotiateChannel *base)
{
    DefaultNegotiateChannelDelete((struct DefaultNegotiateChannel *)base);
}

void DefaultNegotiateChannelConstructor(struct DefaultNegotiateChannel *self, int64_t authId)
{
    (void)memset_s(self, sizeof(*self), 0, sizeof(*self));
    self->authId = authId;

    self->postData = PostData;
    self->getDeviceId = GetDeviceId;
    self->getP2pMac = GetP2pMac;
    self->setP2pMac = SetP2pMac;
    self->isP2pChannel = IsP2pChannel;
    self->isMetaChannel = IsMetaChannel;
    self->duplicate = Duplicate;
    self->destructor = Destructor;
}

void DefaultNegotiateChannelDestructor(struct DefaultNegotiateChannel *self)
{
    (void)self;
}

struct DefaultNegotiateChannel* DefaultNegotiateChannelNew(int64_t authId)
{
    CLOGI(LOG_LABEL);
    struct DefaultNegotiateChannel *self = SoftBusCalloc(sizeof(*self));
    CONN_CHECK_AND_RETURN_RET_LOG(self, NULL, LOG_LABEL "malloc failed");
    DefaultNegotiateChannelConstructor(self, authId);
    return self;
}

void DefaultNegotiateChannelDelete(struct DefaultNegotiateChannel *self)
{
    CLOGI(LOG_LABEL);
    DefaultNegotiateChannelDestructor(self);
    SoftBusFree(self);
}

int32_t OpenDefaultNegotiateChannel(const char *remoteIp, int32_t remotePort,
                                    struct WifiDirectNegotiateChannel *srcChannel,
                                    struct DefaultNegoChannelOpenCallback *callback)
{
    bool isMeta = false;
    if (srcChannel && srcChannel->isMetaChannel) {
        isMeta = srcChannel->isMetaChannel(srcChannel);
    }
    CLOGI(LOG_LABEL "remoteIp=%s remotePort=%d isMeta=%d", WifiDirectAnonymizeIp(remoteIp), remotePort, isMeta);

    AuthConnInfo authConnInfo;
    authConnInfo.type = AUTH_LINK_TYPE_P2P;
    authConnInfo.info.ipInfo.port = remotePort;
    if (isMeta) {
        authConnInfo.info.ipInfo.authId = ((struct DefaultNegotiateChannel*)srcChannel)->authId;
    }
    int32_t ret = strcpy_s(authConnInfo.info.ipInfo.ip, sizeof(authConnInfo.info.ipInfo.ip), remoteIp);
    CONN_CHECK_AND_RETURN_RET_LOG(ret == EOK, SOFTBUS_ERR, "copy ip failed");

    AuthConnCallback authConnCallback = {
        .onConnOpened = callback->onConnectSuccess,
        .onConnOpenFailed = callback->onConnectFailure,
    };

    ret = AuthOpenConn(&authConnInfo, AuthGenRequestId(), &authConnCallback, isMeta);
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, SOFTBUS_ERR, "auth open connect failed");

    return SOFTBUS_OK;
}

void CloseDefaultNegotiateChannel(struct DefaultNegotiateChannel *self)
{
    AuthCloseConn(self->authId);
}

int32_t StartListeningForDefaultChannel(const char *localIp)
{
    int32_t port = AuthStartListening(AUTH_LINK_TYPE_P2P, localIp, 0);
    CLOGI(LOG_LABEL "localIp=%s port=%d", WifiDirectAnonymizeIp(localIp), port);
    return port;
}

void StopListeningForDefaultChannel(void)
{
    AuthStopListening(AUTH_LINK_TYPE_P2P);
}