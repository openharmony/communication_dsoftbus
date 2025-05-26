/*
* Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include <atomic>
#include <mutex>
#include <string>

#include "auth_interface_struct.h"
#include "bus_center_event_struct.h"
#include "g_enhance_lnn_func.h"
#include "lnn_distributed_net_ledger_struct.h"
#include "lnn_feature_capability_struct.h"
#include "softbus_proxychannel_pipeline_struct.h"
#include "stdint.h"
#include "stdbool.h"

#ifndef OHOS_WIFI_DIRECT_INIT_H
#define OHOS_WIFI_DIRECT_INIT_H

namespace OHOS {
enum {
   SOFTBUS_WIFI_DIRECT_INIT_SUCCESS = 0,
   SOFTBUS_WIFI_DIRECT_DLOPEN_FAILED,
   SOFTBUS_WIFI_DIRECT_DLSYM_FAILED,
   SOFTBUS_WIFI_DIRECT_INSTANCE_EXIT,
};

// static constexpr int MAX_SEND_MESSAGE_LENGTH = 4 * 1024;

class DBinderSoftbusServer {
public:
   static DBinderSoftbusServer& GetInstance();
   DBinderSoftbusServer();
   ~DBinderSoftbusServer();

   int32_t RegAuthTransListener(int32_t module, const AuthTransListener *listener);
   int32_t AuthGetDeviceUuid(int64_t authId, char *uuid, uint16_t size);
   int32_t AuthPostTransData(AuthHandle authHandle, const AuthTransData *dataInfo);
   void AuthCloseConn(AuthHandle authHandle);
   int32_t AuthGetMetaType(int64_t authId, bool *isMetaAuth);
   int32_t AuthStartListeningForWifiDirect(AuthLinkType type, const char *ip, int32_t port, ListenerModule *moduleId);
   void AuthStopListeningForWifiDirect(AuthLinkType type, ListenerModule moduleId);
   uint32_t AuthGenRequestId(void);
   int32_t AuthOpenConn(const AuthConnInfo *info, uint32_t requestId, const AuthConnCallback *callback, bool isMeta);
   const char *LnnConvertDLidToUdid(const char *id, IdCategory type);
   void AuthStopListening(AuthLinkType type);
   int32_t TransProxyPipelineRegisterListener(TransProxyPipelineMsgType type,
       const ITransProxyPipelineListener *listener);
   int32_t TransProxyPipelineGetUuidByChannelId(int32_t channelId, char *uuid, uint32_t uuidLen);
   int32_t TransProxyPipelineSendMessage(
       int32_t channelId, const uint8_t *data, uint32_t dataLen, TransProxyPipelineMsgType type);
   LnnEnhanceFuncList *LnnEnhanceFuncListGet(void);
   int32_t LnnGetRemoteStrInfo(const char *networkId, InfoKey key, char *info, uint32_t len);
   int32_t LnnGetNetworkIdByUuid(const char *uuid, char *buf, uint32_t len);
   int32_t LnnGetLocalStrInfo(InfoKey key, char *info, uint32_t len);
   int32_t LnnGetLocalNumU64Info(InfoKey key, uint64_t *info);
   int32_t LnnGetRemoteByteInfo(const char *networkId, InfoKey key, uint8_t *info, uint32_t len);
   int32_t LnnGetRemoteBoolInfoIgnoreOnline(const char *networkId, InfoKey key, bool *info);
   uint64_t LnnGetFeatureCapabilty(void);
   bool IsFeatureSupport(uint64_t feature, FeatureCapability capaBit);
   int32_t LnnSetLocalStrInfo(InfoKey key, const char *info);
   bool LnnGetOnlineStateById(const char *id, IdCategory type);
   int32_t LnnSetLocalNumInfo(InfoKey key, int32_t info);
   int32_t LnnSyncP2pInfo(void);
   int32_t LnnGetOsTypeByNetworkId(const char *networkId, int32_t *osType);
   int32_t LnnGetRemoteNumInfo(const char *networkId, InfoKey key, int32_t *info);
   int32_t LnnGetLocalNumInfo(InfoKey key, int32_t *info);
   int32_t LnnGetRemoteNumU64Info(const char *networkId, InfoKey key, uint64_t *info);
   int32_t LnnGetRemoteNodeInfoById(const char *id, IdCategory type, NodeInfo *info);
   int32_t LnnGetRemoteNodeInfoByKey(const char *key, NodeInfo *info);
   int32_t LnnGetAllOnlineNodeInfo(NodeBasicInfo **info, int32_t *infoNum);
   int32_t LnnRegisterEventHandler(LnnEventType event, LnnEventHandler handler);

private:
   // DISALLOW_COPY_AND_MOVE(DBinderSoftbusServer);

   bool OpenSoftbusServerSo();

   using RegAuthTransListenerFunc = int32_t (*)(int32_t module, const AuthTransListener *listener);
   using AuthGetDeviceUuidFunc = int32_t (*)(int64_t authId, char *uuid, uint16_t size);
   using AuthPostTransDataFunc = int32_t (*)(AuthHandle authHandle, const AuthTransData *dataInfo);
   using AuthCloseConnFunc = void (*)(AuthHandle authHandle);
   using AuthGetMetaTypeFunc = int32_t (*)(int64_t authId, bool *isMetaAuth);
   using AuthStartListeningForWifiDirectFunc = int32_t (*)(AuthLinkType type, const char *ip, int32_t port,
       ListenerModule *moduleId);
   using AuthStopListeningForWifiDirectFunc = void (*)(AuthLinkType type, ListenerModule moduleId);
   using AuthGenRequestIdFunc = uint32_t (*)(void);
   using AuthOpenConnFunc = int32_t (*)(const AuthConnInfo *info, uint32_t requestId,
       const AuthConnCallback *callback, bool isMeta);
   using LnnConvertDLidToUdidFunc = const char *(*)(const char *id, IdCategory type);
   using AuthStopListeningFunc = void(*)(AuthLinkType type);
   using TransProxyPipelineRegisterListenerFunc = int32_t (*)(TransProxyPipelineMsgType type,
       const ITransProxyPipelineListener *listener);
   using TransProxyPipelineGetUuidByChannelIdFunc = int32_t (*)(int32_t channelId, char *uuid, uint32_t uuidLen);
   using TransProxyPipelineSendMessageFunc = int32_t (*)(
       int32_t channelId, const uint8_t *data, uint32_t dataLen, TransProxyPipelineMsgType type);
   using LnnEnhanceFuncListGetFunc = LnnEnhanceFuncList *(*)(void);
   using LnnGetRemoteStrInfoFunc = int32_t (*)(const char *networkId, InfoKey key, char *info, uint32_t len);
   using LnnGetNetworkIdByUuidFunc = int32_t (*)(const char *uuid, char *buf, uint32_t len);
   using LnnGetLocalStrInfoFunc = int32_t (*)(InfoKey key, char *info, uint32_t len);
   using LnnGetLocalNumU64InfoFunc = int32_t (*)(InfoKey key, uint64_t *info);
   using LnnGetRemoteByteInfoFunc = int32_t (*)(const char *networkId, InfoKey key, uint8_t *info, uint32_t len);
   using LnnGetRemoteBoolInfoIgnoreOnlineFunc = int32_t (*)(const char *networkId, InfoKey key, bool *info);

   using LnnGetFeatureCapabiltyFunc = uint64_t (*)(void);
   using IsFeatureSupportFunc = bool (*)(uint64_t feature, FeatureCapability capaBit);
   using LnnSetLocalStrInfoFunc = int32_t (*)(InfoKey key, const char *info);
   using LnnGetOnlineStateByIdFunc = bool (*)(const char *id, IdCategory type);
   using LnnSetLocalNumInfoFunc = int32_t (*)(InfoKey key, int32_t info);
   using LnnSyncP2pInfoFunc = int32_t (*)(void);
   using LnnGetOsTypeByNetworkIdFunc = int32_t (*)(const char *networkId, int32_t *osType);
   using LnnGetRemoteNumInfoFunc = int32_t (*)(const char *networkId, InfoKey key, int32_t *info);
   using LnnGetLocalNumInfoFunc = int32_t (*)(InfoKey key, int32_t *info);
   using LnnGetRemoteNumU64InfoFunc = int32_t (*)(const char *networkId, InfoKey key, uint64_t *info);
   using LnnGetRemoteNodeInfoByIdFunc = int32_t (*)(const char *id, IdCategory type, NodeInfo *info);
   using LnnGetRemoteNodeInfoByKeyFunc = int32_t (*)(const char *key, NodeInfo *info);
   using LnnGetAllOnlineNodeInfoFunc = int32_t (*)(NodeBasicInfo **info, int32_t *infoNum);
   using LnnRegisterEventHandlerFunc = int32_t (*)(LnnEventType event, LnnEventHandler handler);

   RegAuthTransListenerFunc regAuthTransListenerFunc_ = nullptr;
   AuthGetDeviceUuidFunc authGetDeviceUuidFunc_ = nullptr;
   AuthPostTransDataFunc authPostTransDataFunc_ = nullptr;
   AuthCloseConnFunc authCloseConnFunc_ = nullptr;
   AuthGetMetaTypeFunc authGetMetaTypeFunc_ = nullptr;
   AuthStartListeningForWifiDirectFunc authStartListeningForWifiDirectFunc_ = nullptr;
   AuthStopListeningForWifiDirectFunc authStopListeningForWifiDirectFunc_ = nullptr;
   AuthGenRequestIdFunc authGenRequestIdFunc_ = nullptr;
   AuthOpenConnFunc authOpenConnFunc_ = nullptr;
   LnnConvertDLidToUdidFunc lnnConvertDLidToUdidFunc_ = nullptr;
   TransProxyPipelineRegisterListenerFunc transProxyPipelineRegisterListenerFunc_ = nullptr;
   TransProxyPipelineGetUuidByChannelIdFunc transProxyPipelineGetUuidByChannelIdFunc_ = nullptr;
   TransProxyPipelineSendMessageFunc transProxyPipelineSendMessageFunc_ = nullptr;
   LnnEnhanceFuncListGetFunc lnnEnhanceFuncListGetFunc_ = nullptr;
   LnnGetRemoteStrInfoFunc lnnGetRemoteStrInfoFunc_ = nullptr;
   LnnGetNetworkIdByUuidFunc lnnGetNetworkIdByUuidFunc_ = nullptr;
   LnnGetLocalStrInfoFunc lnnGetLocalStrInfoFunc_ = nullptr;
   LnnGetLocalNumU64InfoFunc lnnGetLocalNumU64InfoFunc_ = nullptr;
   LnnGetRemoteByteInfoFunc lnnGetRemoteByteInfoFunc_ = nullptr;
   LnnGetRemoteBoolInfoIgnoreOnlineFunc lnnGetRemoteBoolInfoIgnoreOnlineFunc_ = nullptr;
   AuthStopListeningFunc authStopListeningFunc_ = nullptr;
   LnnGetFeatureCapabiltyFunc lnnGetFeatureCapabiltyFunc_ = nullptr;
   IsFeatureSupportFunc isFeatureSupportFunc_ = nullptr;
   LnnSetLocalStrInfoFunc lnnSetLocalStrInfoFunc_ = nullptr;
   LnnGetOnlineStateByIdFunc lnnGetOnlineStateByIdFunc_ = nullptr;
   LnnSetLocalNumInfoFunc lnnSetLocalNumInfoFunc_ = nullptr;
   LnnSyncP2pInfoFunc lnnSyncP2pInfoFunc_ = nullptr;
   LnnGetOsTypeByNetworkIdFunc lnnGetOsTypeByNetworkIdFunc_ = nullptr;
   LnnGetRemoteNumInfoFunc lnnGetRemoteNumInfoFunc_ = nullptr;
   LnnGetLocalNumInfoFunc lnnGetLocalNumInfoFunc_ = nullptr;
   LnnGetRemoteNumU64InfoFunc lnnGetRemoteNumU64InfoFunc_ = nullptr;
   LnnGetRemoteNodeInfoByIdFunc lnnGetRemoteNodeInfoByIdFunc_ = nullptr;
   LnnGetRemoteNodeInfoByKeyFunc lnnGetRemoteNodeInfoByKeyFunc_ = nullptr;
   LnnGetAllOnlineNodeInfoFunc lnnGetAllOnlineNodeInfoFunc_ = nullptr;
   LnnRegisterEventHandlerFunc lnnRegisterEventHandlerFunc_ = nullptr;

   std::mutex loadSoMutex_;
   std::atomic<bool> exitFlag_ = false;
   bool isLoaded_ = false;
   void *soHandle_ = nullptr;
};
} // namespace OHOS
#endif // OHOS_WIFI_DIRECT_INIT_H