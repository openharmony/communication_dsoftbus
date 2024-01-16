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
#include "conn_log.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "auth_manager.h"
#include "bus_center_manager.h"
#include "lnn_distributed_net_ledger.h"
#include "wifi_direct_negotiator.h"
#include "utils/wifi_direct_work_queue.h"
#include "utils/wifi_direct_anonymous.h"

#define MAX_AUTH_DATA_LEN (1024 * 1024)

static void OnAuthDataReceived(int64_t authId, const AuthTransData *data);
static void OnAuthDisconnected(int64_t authId);

static AuthTransListener g_authListener = {.onDataReceived = OnAuthDataReceived, .onDisconnected = OnAuthDisconnected};

int32_t DefaultNegotiateChannelInit(void)
{
    CONN_LOGI(CONN_INIT, "init enter");
    int32_t ret = RegAuthTransListener(MODULE_P2P_LINK, &g_authListener);
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == SOFTBUS_OK, SOFTBUS_ERR, CONN_INIT,
        "register auth transfer listener failed");
    CONN_LOGI(CONN_INIT, "register auth transfer listener success");
    return SOFTBUS_OK;
}

struct DataStruct {
    int64_t authId;
    int32_t flag;
    size_t len;
    uint8_t data[];
};

static void DataReceivedWorkHandler(void *data)
{
    struct DataStruct *dataStruct = data;
    struct DefaultNegotiateChannel channel;
    DefaultNegotiateChannelConstructor(&channel, dataStruct->authId);
    if (dataStruct->flag == 0) {
        GetWifiDirectNegotiator()->onNegotiateChannelDataReceived((struct WifiDirectNegotiateChannel *)&channel,
                                                                  dataStruct->data, dataStruct->len);
    } else {
        GetWifiDirectNegotiator()->onDefaultTriggerChannelDataReceived((struct WifiDirectNegotiateChannel *)&channel,
                                                                       dataStruct->data, dataStruct->len);
    }

    DefaultNegotiateChannelDestructor(&channel);
    SoftBusFree(dataStruct);
}

static void OnAuthDataReceived(int64_t authId, const AuthTransData *data)
{
    CONN_CHECK_AND_RETURN_LOGW(data != NULL && data->data != NULL && data->len != 0, CONN_WIFI_DIRECT, "data invalid");
    CONN_CHECK_AND_RETURN_LOGW(data->len <= MAX_AUTH_DATA_LEN, CONN_WIFI_DIRECT, "data too large");
    CONN_LOGI(CONN_WIFI_DIRECT, "len=%{public}u", data->len);

    struct DataStruct *dataStruct = SoftBusCalloc(sizeof(struct DataStruct) + data->len);
    CONN_CHECK_AND_RETURN_LOGE(dataStruct, CONN_WIFI_DIRECT, "malloc failed");

    dataStruct->authId = authId;
    dataStruct->flag = data->flag;
    dataStruct->len = data->len;
    if (memcpy_s(dataStruct->data, dataStruct->len, data->data, data->len) != EOK) {
        CONN_LOGE(CONN_WIFI_DIRECT, "memcpy_s failed");
        SoftBusFree(dataStruct);
        return;
    }
    if (CallMethodAsync(DataReceivedWorkHandler, dataStruct, 0) != SOFTBUS_OK) {
        CONN_LOGE(CONN_WIFI_DIRECT, "async failed");
        SoftBusFree(dataStruct);
    }
}

static void AuthDisconnectedWorkHandler(struct WifiDirectNegotiateChannel *channel)
{
    GetWifiDirectNegotiator()->onNegotiateChannelDisconnected(channel);
    channel->destructor(channel);
}

static void OnAuthDisconnected(int64_t authId)
{
    struct DefaultNegotiateChannel *channel = DefaultNegotiateChannelNew(authId);
    CONN_CHECK_AND_RETURN_LOGE(channel != NULL, CONN_WIFI_DIRECT, "create channel failed");
    if (CallMethodAsync((WorkFunction)AuthDisconnectedWorkHandler, channel, 0) != SOFTBUS_OK) {
        CONN_LOGE(CONN_WIFI_DIRECT, "async failed");
        DefaultNegotiateChannelDelete(channel);
    }
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
    struct DefaultNegotiateChannel *self = (struct DefaultNegotiateChannel *)base;
    return self->postDataWithFlag(self, data, size, 0);
}

static int32_t PostDataWithFlag(struct DefaultNegotiateChannel *self, const uint8_t *data, size_t size, int32_t flag)
{
    AuthTransData dataInfo = {
        .module = MODULE_P2P_LINK,
        .flag = flag,
        .seq = GenerateSequence(),
        .len = size,
        .data = data,
    };

    CONN_CHECK_AND_RETURN_RET_LOGE(AuthPostTransData(self->authId, &dataInfo) == SOFTBUS_OK, SOFTBUS_ERR,
                                   CONN_WIFI_DIRECT, "post data failed");
    return SOFTBUS_OK;
}

static int32_t GetDeviceId(struct WifiDirectNegotiateChannel *base, char *deviceId, size_t deviceIdSize)
{
    int32_t ret = SOFTBUS_OK;
    struct DefaultNegotiateChannel *self = (struct DefaultNegotiateChannel *)base;
    if (strlen(self->remoteDeviceId) != 0) {
        ret = strcpy_s(deviceId, deviceIdSize, self->remoteDeviceId);
        CONN_CHECK_AND_RETURN_RET_LOGW(ret == EOK, SOFTBUS_STRCPY_ERR, CONN_WIFI_DIRECT, "copy device id failed");
        return SOFTBUS_OK;
    }

    ret = AuthGetDeviceUuid(((struct DefaultNegotiateChannel *)base)->authId, deviceId, deviceIdSize);
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "get device id failed");
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
        CONN_CHECK_AND_RETURN_RET_LOGW(ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "get uuid id failed");
        ret = LnnGetNetworkIdByUuid(uuid, networkId, sizeof(networkId));
        CONN_CHECK_AND_RETURN_RET_LOGW(ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "get network id failed");
        ret = LnnGetRemoteStrInfo(networkId, STRING_KEY_P2P_MAC, p2pMac, p2pMacSize);
        CONN_CHECK_AND_RETURN_RET_LOGW(ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "get remote p2p mac failed");
        return ret;
    }

    ret = strcpy_s(p2pMac, p2pMacSize, self->p2pMac);
    return ret == EOK ? SOFTBUS_OK : SOFTBUS_ERR;
}

static void SetP2pMac(struct WifiDirectNegotiateChannel *base, const char *p2pMac)
{
    struct DefaultNegotiateChannel *self = (struct DefaultNegotiateChannel *)base;
    int32_t ret = strcpy_s(self->p2pMac, sizeof(self->p2pMac), p2pMac);
    CONN_CHECK_AND_RETURN_LOGW(ret == EOK, CONN_WIFI_DIRECT, "copy p2p mac failed");
    ret = AuthSetP2pMac(((struct DefaultNegotiateChannel *)base)->authId, p2pMac);
    CONN_CHECK_AND_RETURN_LOGW(ret == SOFTBUS_OK, CONN_WIFI_DIRECT, "set auth p2p mac failed");
}

static enum WifiDirectNegotiateChannelType GetMediumType(struct WifiDirectNegotiateChannel *base)
{
    AuthConnInfo connInfo;
    (void)memset_s(&connInfo, sizeof(connInfo), 0, sizeof(connInfo));
    int32_t ret = AuthGetConnInfo(((struct DefaultNegotiateChannel *)base)->authId, &connInfo);
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, NEGOTIATE_MAX, CONN_WIFI_DIRECT, "get auth conn info failed");
    if (connInfo.type == AUTH_LINK_TYPE_WIFI) {
        return NEGOTIATE_WIFI;
    } else if (connInfo.type == AUTH_LINK_TYPE_BLE) {
        return NEGOTIATE_BLE;
    } else if (connInfo.type == AUTH_LINK_TYPE_BR) {
        return NEGOTIATE_BR;
    }
    return NEGOTIATE_MAX;
}

static bool IsP2pChannel(struct WifiDirectNegotiateChannel *base)
{
    AuthConnInfo connInfo;
    (void)memset_s(&connInfo, sizeof(connInfo), 0, sizeof(connInfo));
    int32_t ret = AuthGetConnInfo(((struct DefaultNegotiateChannel *)base)->authId, &connInfo);
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, false, CONN_WIFI_DIRECT, "get auth conn info failed");
    return connInfo.type == AUTH_LINK_TYPE_P2P;
}

static bool IsMetaChannel(struct WifiDirectNegotiateChannel *base)
{
    struct DefaultNegotiateChannel *self = (struct DefaultNegotiateChannel *)base;
    bool isMeta = false;
    int32_t ret = AuthGetMetaType(self->authId, &isMeta);
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == SOFTBUS_OK, false, CONN_WIFI_DIRECT, "get meta type failed");
    return isMeta;
}

static bool Equal(struct WifiDirectNegotiateChannel *leftBase, struct WifiDirectNegotiateChannel *rightBase)
{
    struct DefaultNegotiateChannel *leftSelf = (struct DefaultNegotiateChannel *)leftBase;
    struct DefaultNegotiateChannel *rightSelf = (struct DefaultNegotiateChannel *)rightBase;
    return leftSelf->authId == rightSelf->authId;
}

static struct WifiDirectNegotiateChannel *Duplicate(struct WifiDirectNegotiateChannel *base)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "enter");
    struct DefaultNegotiateChannel *self = (struct DefaultNegotiateChannel *)base;
    struct DefaultNegotiateChannel *copy = DefaultNegotiateChannelNew(self->authId);
    int32_t ret = strcpy_s(copy->remoteDeviceId, UUID_BUF_LEN, self->remoteDeviceId);
    if (ret != EOK) {
        CONN_LOGE(CONN_WIFI_DIRECT, "copy remote device id failed");
        DefaultNegotiateChannelDelete(copy);
        return NULL;
    }
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
    self->postDataWithFlag = PostDataWithFlag;
    self->getDeviceId = GetDeviceId;
    self->getP2pMac = GetP2pMac;
    self->setP2pMac = SetP2pMac;
    self->isP2pChannel = IsP2pChannel;
    self->getMediumType = GetMediumType;
    self->isMetaChannel = IsMetaChannel;
    self->equal = Equal;
    self->duplicate = Duplicate;
    self->destructor = Destructor;

    int32_t ret = AuthGetDeviceUuid(self->authId, self->remoteDeviceId, UUID_BUF_LEN);
    CONN_CHECK_AND_RETURN_LOGW(ret == SOFTBUS_OK, CONN_WIFI_DIRECT, "get device id failed");
}

void DefaultNegotiateChannelDestructor(struct DefaultNegotiateChannel *self)
{
    (void)self;
}

struct DefaultNegotiateChannel *DefaultNegotiateChannelNew(int64_t authId)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "enter");
    struct DefaultNegotiateChannel *self = SoftBusCalloc(sizeof(*self));
    CONN_CHECK_AND_RETURN_RET_LOGE(self != NULL, NULL, CONN_WIFI_DIRECT, "malloc failed");
    DefaultNegotiateChannelConstructor(self, authId);
    return self;
}

void DefaultNegotiateChannelDelete(struct DefaultNegotiateChannel *self)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "enter");
    DefaultNegotiateChannelDestructor(self);
    SoftBusFree(self);
}

int32_t OpenDefaultNegotiateChannel(struct DefaultNegoChannelParam *param,
                                    struct WifiDirectNegotiateChannel *srcChannel,
                                    struct DefaultNegoChannelOpenCallback *callback)
{
    CONN_CHECK_AND_RETURN_RET_LOGW(param != NULL, SOFTBUS_ERR, CONN_WIFI_DIRECT, "param is null");
    CONN_CHECK_AND_RETURN_RET_LOGW(param->remoteUuid != NULL, SOFTBUS_ERR, CONN_WIFI_DIRECT, "remoteUuid is null");
    CONN_CHECK_AND_RETURN_RET_LOGW(param->remoteIp != NULL, SOFTBUS_ERR, CONN_WIFI_DIRECT, "remoteIp is null");
    CONN_CHECK_AND_RETURN_RET_LOGW(callback != NULL, SOFTBUS_ERR, CONN_WIFI_DIRECT, "callback is null");

    bool isMeta = false;
    if ((srcChannel != NULL) && (srcChannel->isMetaChannel != NULL)) {
        isMeta = srcChannel->isMetaChannel(srcChannel);
    }
    CONN_LOGI(CONN_WIFI_DIRECT, "remoteUuid=%{public}s, remoteIp=%{public}s, remotePort=%{public}d, isMeta=%{public}d",
              WifiDirectAnonymizeDeviceId(param->remoteUuid), WifiDirectAnonymizeIp(param->remoteIp),
              param->remotePort, isMeta);

    const char *remoteUdid = LnnConvertDLidToUdid(param->remoteUuid, CATEGORY_UUID);
    CONN_CHECK_AND_RETURN_RET_LOGE(remoteUdid != NULL && strlen(remoteUdid) != 0, SOFTBUS_ERR, CONN_WIFI_DIRECT,
                                   "get remote udid failed");
    CONN_LOGI(CONN_WIFI_DIRECT, "remoteUdid=%{public}s", WifiDirectAnonymizeDeviceId(remoteUdid));

    AuthConnInfo authConnInfo;
    (void)memset_s(&authConnInfo, sizeof(authConnInfo), 0, sizeof(authConnInfo));
    authConnInfo.type = param->type;
    authConnInfo.info.ipInfo.port = param->remotePort;
    authConnInfo.info.ipInfo.moduleId = param->localModuleId;
    if (isMeta) {
        authConnInfo.info.ipInfo.authId = ((struct DefaultNegotiateChannel*)srcChannel)->authId;
    }
    int32_t ret = strcpy_s(authConnInfo.info.ipInfo.ip, sizeof(authConnInfo.info.ipInfo.ip), param->remoteIp);
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == EOK, SOFTBUS_ERR, CONN_WIFI_DIRECT, "copy ip failed");
    ret = strcpy_s(authConnInfo.info.ipInfo.udid, UDID_BUF_LEN, remoteUdid);
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == EOK, SOFTBUS_ERR, CONN_WIFI_DIRECT, "copy udid failed");

    AuthConnCallback authConnCallback = {
        .onConnOpened = callback->onConnectSuccess,
        .onConnOpenFailed = callback->onConnectFailure,
    };

    ret = AuthOpenConn(&authConnInfo, AuthGenRequestId(), &authConnCallback, isMeta);
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == SOFTBUS_OK, SOFTBUS_ERR, CONN_WIFI_DIRECT, "auth open connect failed");

    return SOFTBUS_OK;
}

void CloseDefaultNegotiateChannel(struct DefaultNegotiateChannel *self)
{
    CONN_CHECK_AND_RETURN_LOGW(self != NULL, CONN_WIFI_DIRECT, "self is null");
    AuthCloseConn(self->authId);
}

int32_t StartListeningForDefaultChannel(AuthLinkType type, const char *localIp, int32_t port, ListenerModule *moduleId)
{
    int32_t ret = AuthStartListeningForWifiDirect(type, localIp, port, moduleId);
    CONN_LOGI(CONN_WIFI_DIRECT, "type=%{public}d, localIp=%{public}s, port=%{public}d, moduleId=%{public}d",
              type, WifiDirectAnonymizeIp(localIp), ret, *moduleId);
    return ret;
}

void StopListeningForDefaultChannel(AuthLinkType type, ListenerModule moduleId)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "type=%{public}d, moduleId=%{public}d", type, moduleId);
    AuthStopListeningForWifiDirect(type, moduleId);
}