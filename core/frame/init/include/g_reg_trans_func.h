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

#ifndef G_REG_TRANS_FUNC_H
#define G_REG_TRANS_FUNC_H

#include "form/trans_event_form.h"
#include "g_enhance_trans_func.h"
#include "lnn_lane_interface_struct.h"
#include "softbus_app_info.h"
#include "softbus_trans_def.h"
#include "stdbool.h"
#include "stdint.h"
#include "trans_auth_lane_pending_ctl_struct.h"
#include "trans_inner_session_struct.h"

// 需要改成struct
#include "trans_inner.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef int32_t (*TransProxyGetAppInfoByChanIdFunc)(int32_t chanId, AppInfo* appInfo);
typedef int32_t (*TransLaneMgrDelLaneFunc)(int32_t channelId, int32_t channelType, bool isAsync);
typedef int32_t (*TransDelTcpChannelInfoByChannelIdFunc)(int32_t channelId);
typedef int32_t (*TransSendMsgFunc)(int32_t channelId, int32_t channelType, const void *data,
    uint32_t len, int32_t msgType);
typedef int32_t (*TransProxyCloseProxyChannelFunc)(int32_t channelId);
typedef int32_t (*GetAppInfoByIdFunc)(int32_t channelId, AppInfo *appInfo);
typedef int32_t (*TransDealTdcChannelOpenResultFunc)(int32_t channelId, int32_t openResult);
typedef int32_t (*TransDealProxyChannelOpenResultFunc)(int32_t channelId, int32_t openResult);
typedef int32_t (*TransOpenChannelFunc)(const SessionParam *param, TransInfo *transInfo);
typedef int32_t (*TransCreateSessionServerFunc)(const char *pkgName, const char *sessionName, int32_t uid, int32_t pid);
typedef TransDeviceState (*TransGetDeviceStateFunc)(const char *networkId);
typedef int32_t (*TransAuthWithParaGetLaneReqByLaneReqIdFunc)(uint32_t laneReqId, TransAuthWithParaNode *paraNode);
typedef int32_t (*TransAuthWithParaDelLaneReqByIdFunc)(uint32_t laneReqId);
typedef int32_t (*GetAppInfoFunc)(const char *sessionName, int32_t channelId, AppInfo *appInfo, bool isClient);
typedef int32_t (*TransOpenAuthMsgChannelWithParaFunc)(const char *sessionName, const LaneConnInfo *connInfo,
    int32_t *channelId, bool accountInfo);
typedef int32_t (*TransLaneMgrAddLaneFunc)(
    const TransInfo *transInfo, const LaneConnInfo *connInfo, uint32_t laneHandle, bool isQosLane, AppInfoData *myData);
typedef int32_t (*TransCloseChannelFunc)(const char *sessionName, int32_t channelId, int32_t channelType);
typedef int32_t (*NotifyOpenAuthChannelFailedFunc)(const char *pkgName, int32_t pid, int32_t channelId,
    int32_t errCode);
typedef int32_t (*TransUpdateAuthWithParaLaneConnInfoFunc)(uint32_t laneHandle, bool bSucc,
    const LaneConnInfo *connInfo, int32_t errCode);
typedef int32_t (*TransAuthWithParaAddLaneReqToListFunc)(uint32_t laneReqId, const char *sessionName,
    bool accountInfo, int32_t channelId);
typedef int32_t (*GenerateChannelIdFunc)(bool isTdcChannel);
typedef int32_t (*TransTdcGetIpAndConnectTypeByIdFunc)(int32_t channelId, char *localIp, char *remoteIp,
    uint32_t maxIpLen, int32_t *connectType);
typedef int32_t (*TransUdpGetIpAndConnectTypeByIdFunc)(int32_t channelId, char *localIp, char *remoteIp,
    uint32_t maxIpLen, int32_t *connectType);
typedef int32_t (*TransAuthGetRoleByAuthIdFunc)(int32_t authId, bool *isClient);

typedef void (*CloseSessionInnerFunc)(int32_t channelId);
typedef int32_t (*GetSessionInfoFunc)(int32_t channelId, int32_t *fd, int32_t *channelType, char *sessionKey, int32_t keyLen);
typedef int32_t (*DirectChannelCreateListenerFunc)(int32_t fd);
typedef int32_t (*InnerAddSessionFunc)(InnerSessionInfo *innerInfo);
typedef int32_t (*TransInnerAddDataBufNodeFunc)(int32_t channelId, int32_t fd, int32_t channelType);
typedef int32_t (*ServerSideSendAckFunc)(int32_t sessionId, int32_t result);
typedef int32_t (*TransSendDataFunc)(int32_t channelId, const void *data, uint32_t len);
typedef int32_t (*ProxyDataRecvHandlerFunc)(int32_t channelId, const char *data, uint32_t len);
typedef int32_t (*SoftbusAddServiceInnerForEnhanceFunc)(const char *pkgName, ISessionListenerInner *listener,
    int32_t pid);

typedef struct TagTransOpenFuncList {
    TransProxyGetAppInfoByChanIdFunc transProxyGetAppInfoByChanId;
    TransLaneMgrDelLaneFunc transLaneMgrDelLane;
    TransDelTcpChannelInfoByChannelIdFunc transDelTcpChannelInfoByChannelId;
    TransSendMsgFunc transSendMsg;
    TransProxyCloseProxyChannelFunc transProxyCloseProxyChannel;
    GetAppInfoByIdFunc getAppInfoById;
    TransDealTdcChannelOpenResultFunc transDealTdcChannelOpenResult;
    TransDealProxyChannelOpenResultFunc transDealProxyChannelOpenResult;
    TransOpenChannelFunc transOpenChannel;
    TransCreateSessionServerFunc transCreateSessionServer;
    TransGetDeviceStateFunc transGetDeviceState;
    TransAuthWithParaGetLaneReqByLaneReqIdFunc transAuthWithParaGetLaneReqByLaneReqId;
    TransAuthWithParaDelLaneReqByIdFunc transAuthWithParaDelLaneReqById;
    GetAppInfoFunc getAppInfo;
    TransOpenAuthMsgChannelWithParaFunc transOpenAuthMsgChannelWithPara;
    TransLaneMgrAddLaneFunc transLaneMgrAddLane;
    TransCloseChannelFunc transCloseChannel;
    NotifyOpenAuthChannelFailedFunc notifyOpenAuthChannelFailed;
    TransUpdateAuthWithParaLaneConnInfoFunc transUpdateAuthWithParaLaneConnInfo;

    TransAuthWithParaAddLaneReqToListFunc transAuthWithParaAddLaneReqToList;
    GenerateChannelIdFunc generateChannelId;
    TransTdcGetIpAndConnectTypeByIdFunc transTdcGetIpAndConnectTypeById;
    TransUdpGetIpAndConnectTypeByIdFunc transUdpGetIpAndConnectTypeById;
    TransAuthGetRoleByAuthIdFunc transAuthGetRoleByAuthId;
    CloseSessionInnerFunc closeSessionInner;
    GetSessionInfoFunc getSessionInfo;
    DirectChannelCreateListenerFunc directChannelCreateListener;
    InnerAddSessionFunc innerAddSession;
    TransInnerAddDataBufNodeFunc transInnerAddDataBufNode;
    ServerSideSendAckFunc serverSideSendAck;
    TransSendDataFunc transSendData;
    ProxyDataRecvHandlerFunc proxyDataRecvHandler;
    SoftbusAddServiceInnerForEnhanceFunc softbusAddServiceInnerForEnhance;
} TransOpenFuncList;

#ifdef __cplusplus
}
#endif

#endif