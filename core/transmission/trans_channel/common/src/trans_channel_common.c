/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "trans_channel_common.h"

#include "access_control.h"
#include "bus_center_manager.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_lane_interface.h"
#include "lnn_network_manager.h"
#include "lnn_ohos_account_adapter.h"
#include "softbus_access_token_adapter.h"
#include "softbus_adapter_mem.h"
#include "softbus_config_type.h"
#include "softbus_error_code.h"
#include "softbus_feature_config.h"
#include "legacy/softbus_hisysevt_transreporter.h"
#include "softbus_proxychannel_manager.h"
#include "softbus_qos.h"
#include "softbus_wifi_api_adapter.h"
#include "trans_auth_manager.h"
#include "trans_client_proxy.h"
#include "trans_event.h"
#include "trans_lane_manager.h"
#include "trans_lane_pending_ctl.h"
#include "trans_log.h"
#include "trans_session_account_adapter.h"
#include "trans_session_manager.h"
#include "trans_tcp_direct_manager.h"
#include "trans_tcp_direct_sessionconn.h"
#include "trans_udp_channel_manager.h"
#include "trans_udp_negotiation.h"
#include "wifi_direct_manager.h"

#define DMS_UID 5522
#define DMS_SESSIONNAME "ohos.distributedschedule.dms.connect"

typedef struct {
    int32_t channelType;
    int32_t businessType;
    ConfigType configType;
} ConfigTypeMap;

static const ConfigTypeMap g_configTypeMap[] = {
    { CHANNEL_TYPE_AUTH,       BUSINESS_TYPE_BYTE,    SOFTBUS_INT_AUTH_MAX_BYTES_LENGTH  },
    { CHANNEL_TYPE_AUTH,       BUSINESS_TYPE_MESSAGE, SOFTBUS_INT_AUTH_MAX_MESSAGE_LENGTH},
    { CHANNEL_TYPE_PROXY,      BUSINESS_TYPE_BYTE,    SOFTBUS_INT_MAX_BYTES_NEW_LENGTH   },
    { CHANNEL_TYPE_PROXY,      BUSINESS_TYPE_MESSAGE, SOFTBUS_INT_MAX_MESSAGE_NEW_LENGTH },
    { CHANNEL_TYPE_TCP_DIRECT, BUSINESS_TYPE_BYTE,    SOFTBUS_INT_MAX_BYTES_NEW_LENGTH   },
    { CHANNEL_TYPE_TCP_DIRECT, BUSINESS_TYPE_MESSAGE, SOFTBUS_INT_MAX_MESSAGE_NEW_LENGTH },
};

static int32_t FindConfigType(int32_t channelType, int32_t businessType)
{
    const int32_t configTypeMapLength = sizeof(g_configTypeMap) / sizeof(ConfigTypeMap);
    for (uint32_t i = 0; i < configTypeMapLength; i++) {
        if ((g_configTypeMap[i].channelType == channelType) && (g_configTypeMap[i].businessType == businessType)) {
            return g_configTypeMap[i].configType;
        }
    }
    return SOFTBUS_CONFIG_TYPE_MAX;
}

static LaneTransType GetStreamLaneType(int32_t streamType)
{
    switch (streamType) {
        case RAW_STREAM:
            return LANE_T_RAW_STREAM;
        case COMMON_VIDEO_STREAM:
            return LANE_T_COMMON_VIDEO;
        case COMMON_AUDIO_STREAM:
            return LANE_T_COMMON_VOICE;
        default:
            break;
    }
    return LANE_T_BUTT;
}

static void BuildTransCloseChannelEventExtra(
    TransEventExtra *extra, int32_t channelId, int32_t channelType, int32_t ret)
{
    extra->socketName = NULL;
    extra->peerNetworkId = NULL;
    extra->calleePkg = NULL;
    extra->callerPkg = NULL;
    extra->channelId = channelId;
    extra->channelType = channelType;
    extra->errcode = ret;
    extra->result = (ret == SOFTBUS_OK) ? EVENT_STAGE_RESULT_OK : EVENT_STAGE_RESULT_FAILED;
}

LaneTransType TransGetLaneTransTypeBySession(const SessionParam *param)
{
    if (param == NULL || param->attr == NULL) {
        return LANE_T_BUTT;
    }
    int32_t type = param->attr->dataType;
    int32_t streamType;
    switch (type) {
        case TYPE_MESSAGE:
            return LANE_T_MSG;
        case TYPE_BYTES:
            return LANE_T_BYTE;
        case TYPE_FILE:
            return LANE_T_FILE;
        case TYPE_STREAM:
            streamType = param->attr->attr.streamAttr.streamType;
            return GetStreamLaneType(streamType);
        default:
            break;
    }

    TRANS_LOGE(TRANS_SVC, "session type no support. type=%{public}u", type);
    return LANE_T_BUTT;
}

int32_t TransCommonGetLocalConfig(int32_t channelType, int32_t businessType, uint32_t *len)
{
    if (len == NULL) {
        TRANS_LOGE(TRANS_CTRL, "len is null");
        return SOFTBUS_INVALID_PARAM;
    }
    ConfigType configType = (ConfigType)FindConfigType(channelType, businessType);
    if (configType == SOFTBUS_CONFIG_TYPE_MAX) {
        TRANS_LOGE(TRANS_CTRL, "Invalid channelType=%{public}d businessType=%{public}d", channelType, businessType);
        return SOFTBUS_INVALID_PARAM;
    }
    uint32_t maxLen = 0;
    if (SoftbusGetConfig(configType, (unsigned char *)&maxLen, sizeof(maxLen)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get fail configType=%{public}d", configType);
        return SOFTBUS_GET_CONFIG_VAL_ERR;
    }
    *len = maxLen;
    TRANS_LOGI(TRANS_CTRL, "get appinfo local config len=%{public}d", *len);
    return SOFTBUS_OK;
}

static ChannelType TransGetChannelType(const SessionParam *param, const int32_t type)
{
    LaneTransType transType = TransGetLaneTransTypeBySession(param);
    if (transType == LANE_T_BUTT) {
        return CHANNEL_TYPE_BUTT;
    }

    if (type == LANE_BR || type == LANE_BLE || type == LANE_BLE_DIRECT || type == LANE_COC || type == LANE_COC_DIRECT) {
        return CHANNEL_TYPE_PROXY;
    } else if (transType == LANE_T_FILE || transType == LANE_T_COMMON_VIDEO || transType == LANE_T_COMMON_VOICE ||
        transType == LANE_T_RAW_STREAM) {
        return CHANNEL_TYPE_UDP;
    }
    return CHANNEL_TYPE_TCP_DIRECT;
}

void FillAppInfo(AppInfo *appInfo, const SessionParam *param, TransInfo *transInfo, const LaneConnInfo *connInfo)
{
    if (appInfo == NULL || param == NULL || transInfo == NULL || connInfo == NULL) {
        TRANS_LOGE(TRANS_CTRL, "Invalid param");
        return;
    }
    transInfo->channelType = TransGetChannelType(param, connInfo->type);
    appInfo->linkType = connInfo->type;
    appInfo->channelType = transInfo->channelType;
    (void)TransCommonGetLocalConfig(appInfo->channelType, appInfo->businessType, &appInfo->myData.dataConfig);
    if (connInfo->type == LANE_P2P || connInfo->type == LANE_HML) {
        if (strcpy_s(appInfo->myData.addr, IP_LEN, connInfo->connInfo.p2p.localIp) != EOK) {
            TRANS_LOGE(TRANS_CTRL, "copy local ip failed");
        }
    } else if (connInfo->type == LANE_P2P_REUSE) {
        struct WifiDirectManager *mgr = GetWifiDirectManager();
        if (mgr != NULL && mgr->getLocalIpByRemoteIp != NULL) {
            int32_t ret = mgr->getLocalIpByRemoteIp(connInfo->connInfo.wlan.addr, appInfo->myData.addr, IP_LEN);
            if (ret != SOFTBUS_OK) {
                TRANS_LOGE(TRANS_CTRL, "get Local Ip fail, ret = %{public}d", ret);
            }
        }
    }
}

void GetOsTypeByNetworkId(const char *networkId, int32_t *osType)
{
    int32_t errCode = LnnGetOsTypeByNetworkId(networkId, osType);
    if (errCode != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get remote osType err, errCode=%{public}d", errCode);
        return;
    }
}

void GetRemoteUdidWithNetworkId(const char *networkId, char *info, uint32_t len)
{
    int32_t errCode = LnnGetRemoteStrInfo(networkId, STRING_KEY_DEV_UDID, info, len);
    if (errCode != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get remote node udid err, errCode=%{public}d", errCode);
        return;
    }
}

void TransGetRemoteDeviceVersion(const char *id, IdCategory type, char *deviceVersion, uint32_t len)
{
    if (id == NULL || deviceVersion == NULL) {
        TRANS_LOGE(TRANS_CTRL, "invalid param.");
        return;
    }
    NodeInfo nodeInfo;
    (void)memset_s(&nodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    if (LnnGetRemoteNodeInfoById(id, type, &nodeInfo) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "GetRemoteNodeInfo failed IdCategory type=%{public}d", type);
        return;
    }
    if (strncpy_s(deviceVersion, len, nodeInfo.deviceInfo.deviceVersion,
        strlen(nodeInfo.deviceInfo.deviceVersion)) != EOK) {
        TRANS_LOGE(TRANS_CTRL, "STR COPY ERROR!");
        return;
    }
}

static int32_t CopyAppInfoFromSessionParam(AppInfo *appInfo, const SessionParam *param)
{
    if (param == NULL || param->attr == NULL) {
        TRANS_LOGE(TRANS_CTRL, "parm is null");
        return SOFTBUS_INVALID_PARAM;
    }
    if (param->attr->fastTransData != NULL && param->attr->fastTransDataSize > 0 &&
        param->attr->fastTransDataSize <= MAX_FAST_DATA_LEN) {
        if (appInfo->businessType == BUSINESS_TYPE_FILE || appInfo->businessType == BUSINESS_TYPE_STREAM) {
            TRANS_LOGE(TRANS_CTRL, "not support send fast data");
            return SOFTBUS_TRANS_BUSINESS_TYPE_NOT_MATCH;
        }
        appInfo->fastTransData = (uint8_t*)SoftBusCalloc(param->attr->fastTransDataSize);
        if (appInfo->fastTransData == NULL) {
            return SOFTBUS_MALLOC_ERR;
        }
        if (memcpy_s((char *)appInfo->fastTransData, param->attr->fastTransDataSize,
            (const char *)param->attr->fastTransData, param->attr->fastTransDataSize) != EOK) {
            TRANS_LOGE(TRANS_CTRL, "memcpy_s err");
            return SOFTBUS_MEM_ERR;
        }
    }
    appInfo->fastTransDataSize = param->attr->fastTransDataSize;
    int32_t errCode = TransGetUidAndPid(param->sessionName, &appInfo->myData.uid, &appInfo->myData.pid);
    if (errCode != SOFTBUS_OK) {
        return errCode;
    }
    errCode = strcpy_s(appInfo->groupId, sizeof(appInfo->groupId), param->groupId);
    TRANS_CHECK_AND_RETURN_RET_LOGE(errCode == EOK, SOFTBUS_MEM_ERR, TRANS_CTRL, "copy groupId failed");
    errCode = strcpy_s(appInfo->myData.sessionName, sizeof(appInfo->myData.sessionName), param->sessionName);
    TRANS_CHECK_AND_RETURN_RET_LOGE(errCode == EOK, SOFTBUS_MEM_ERR, TRANS_CTRL, "copy myData sessionName failed");
    errCode = strcpy_s(appInfo->peerNetWorkId, sizeof(appInfo->peerNetWorkId), param->peerDeviceId);
    TRANS_CHECK_AND_RETURN_RET_LOGE(errCode == EOK, SOFTBUS_MEM_ERR, TRANS_CTRL, "copy peerNetWorkId failed");

    errCode = TransGetPkgNameBySessionName(param->sessionName, appInfo->myData.pkgName, PKG_NAME_SIZE_MAX);
    if (errCode != SOFTBUS_OK) {
        return errCode;
    }
    errCode = strcpy_s(appInfo->peerData.sessionName, sizeof(appInfo->peerData.sessionName), param->peerSessionName);
    TRANS_CHECK_AND_RETURN_RET_LOGE(errCode == EOK, SOFTBUS_MEM_ERR, TRANS_CTRL, "copy peerData sessionName failed");

    errCode = LnnGetRemoteStrInfo(param->peerDeviceId, STRING_KEY_UUID,
                                  appInfo->peerData.deviceId, sizeof(appInfo->peerData.deviceId));
    if (errCode != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get remote node uuid err");
        return errCode;
    }
    GetRemoteUdidWithNetworkId(appInfo->peerNetWorkId, appInfo->peerUdid, sizeof(appInfo->peerUdid));
    GetOsTypeByNetworkId(appInfo->peerNetWorkId, &appInfo->osType);
    TransGetRemoteDeviceVersion(appInfo->peerNetWorkId, CATEGORY_NETWORK_ID, appInfo->peerVersion,
        sizeof(appInfo->peerVersion));
    return SOFTBUS_OK;
}

int32_t TransCommonGetAppInfo(const SessionParam *param, AppInfo *appInfo)
{
    TRANS_CHECK_AND_RETURN_RET_LOGE(param != NULL, SOFTBUS_INVALID_PARAM, TRANS_CTRL, "Invalid param");
    TRANS_CHECK_AND_RETURN_RET_LOGE(appInfo != NULL, SOFTBUS_INVALID_PARAM, TRANS_CTRL, "Invalid appInfo");
    char *tmpId = NULL;
    Anonymize(param->peerDeviceId, &tmpId);
    TRANS_LOGI(TRANS_CTRL, "GetAppInfo, deviceId=%{public}s", AnonymizeWrapper(tmpId));
    AnonymizeFree(tmpId);
    appInfo->appType = APP_TYPE_NORMAL;
    appInfo->myData.apiVersion = API_V2;
    appInfo->myData.channelId = INVALID_CHANNEL_ID;
    appInfo->peerData.channelId = INVALID_CHANNEL_ID;
    if (param->attr->dataType == TYPE_STREAM) {
        appInfo->businessType = BUSINESS_TYPE_STREAM;
        appInfo->streamType = (StreamType)param->attr->attr.streamAttr.streamType;
    } else if (param->attr->dataType == TYPE_FILE) {
        appInfo->businessType = BUSINESS_TYPE_FILE;
    } else if (param->attr->dataType == TYPE_MESSAGE) {
        appInfo->businessType = BUSINESS_TYPE_MESSAGE;
    } else if (param->attr->dataType == TYPE_BYTES) {
        appInfo->businessType = BUSINESS_TYPE_BYTE;
    }
    int32_t ret = LnnGetLocalStrInfo(STRING_KEY_UUID, appInfo->myData.deviceId, sizeof(appInfo->myData.deviceId));
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "LnnGetLocalStrInfo failed ret=%{public}d", ret);
        return ret;
    }
    ret = CopyAppInfoFromSessionParam(appInfo, param);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "CopyAppInfoFromSessionParam failed ret=%{public}d", ret);
        return ret;
    }
    appInfo->fd = -1;
    appInfo->peerData.apiVersion = API_V2;
    appInfo->encrypt = APP_INFO_FILE_FEATURES_SUPPORT;
    appInfo->algorithm = APP_INFO_ALGORITHM_AES_GCM_256;
    appInfo->crc = APP_INFO_FILE_FEATURES_SUPPORT;
    appInfo->autoCloseTime = 0;
    appInfo->myHandleId = -1;
    appInfo->peerHandleId = -1;
    appInfo->timeStart = GetSoftbusRecordTimeMillis();
    appInfo->callingTokenId = TransACLGetCallingTokenID();
    appInfo->isClient = true;
    appInfo->channelCapability = TRANS_CHANNEL_CAPABILITY;
    TRANS_LOGD(TRANS_CTRL, "GetAppInfo ok");
    return SOFTBUS_OK;
}

void TransOpenChannelSetModule(int32_t channelType, ConnectOption *connOpt)
{
    if (connOpt == NULL || connOpt->type != CONNECT_TCP || connOpt->socketOption.protocol != LNN_PROTOCOL_NIP) {
        TRANS_LOGD(TRANS_CTRL, "param err.");
        return;
    }

    int32_t module = UNUSE_BUTT;
    if (channelType == CHANNEL_TYPE_PROXY) {
        module = LnnGetProtocolListenerModule(connOpt->socketOption.protocol, LNN_LISTENER_MODE_PROXY);
    } else if (channelType == CHANNEL_TYPE_TCP_DIRECT) {
        module = LnnGetProtocolListenerModule(connOpt->socketOption.protocol, LNN_LISTENER_MODE_DIRECT);
    }
    if (module != UNUSE_BUTT) {
        connOpt->socketOption.moduleId = module;
    }
    TRANS_LOGI(TRANS_CTRL, "set nip moduleId=%{public}d", connOpt->socketOption.moduleId);
}

int32_t TransOpenChannelProc(ChannelType type, AppInfo *appInfo, const ConnectOption *connOpt, int32_t *channelId)
{
    if (type == CHANNEL_TYPE_BUTT) {
        TRANS_LOGE(TRANS_CTRL, "open invalid channel type.");
        return SOFTBUS_TRANS_INVALID_CHANNEL_TYPE;
    }
    int32_t ret = SOFTBUS_TRANS_INVALID_CHANNEL_TYPE;
    if (type == CHANNEL_TYPE_UDP) {
        ret = TransOpenUdpChannel(appInfo, connOpt, channelId);
        if (ret != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_CTRL, "open udp channel err, ret=%{public}d", ret);
            return ret;
        }
    } else if (type == CHANNEL_TYPE_PROXY) {
        ret = TransProxyOpenProxyChannel(appInfo, connOpt, channelId);
        if (ret != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_CTRL, "open proxy channel err");
            return ret;
        }
    } else {
        ret = TransOpenDirectChannel(appInfo, connOpt, channelId);
        if (ret != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_CTRL, "open direct channel err");
            return ret;
        }
    }
    return SOFTBUS_OK;
}

static int32_t CancelWaitLaneState(const char *sessionName, int32_t sessionId)
{
    uint32_t laneHandle = 0;
    bool isAsync = true;
    bool isQosLane = false;
    int32_t ret = TransGetSocketChannelLaneInfoBySession(sessionName, sessionId, &laneHandle, &isQosLane, &isAsync);
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        ret == SOFTBUS_OK, ret, TRANS_CTRL, "get socket channel lane info failed, ret=%{public}d", ret);
    TRANS_LOGI(TRANS_CTRL, "wait lane state, sessionId=%{public}d, laneHandle=%{public}u", sessionId, laneHandle);
    if (isQosLane && laneHandle != INVALID_LANE_REQ_ID) {
        TRANS_CHECK_AND_RETURN_RET_LOGE(
            GetLaneManager() != NULL, SOFTBUS_TRANS_GET_LANE_INFO_ERR, TRANS_CTRL, "GetLaneManager is null");
        TRANS_CHECK_AND_RETURN_RET_LOGE(GetLaneManager()->lnnCancelLane != NULL, SOFTBUS_TRANS_GET_LANE_INFO_ERR,
            TRANS_CTRL, "lnnCancelLane is null");
        ret = GetLaneManager()->lnnCancelLane(laneHandle);
        if (ret != SOFTBUS_OK) {
            TRANS_LOGE(
                TRANS_CTRL, "Cancel lane failed, free lane. laneHandle=%{public}u, ret=%{public}d", laneHandle, ret);
            TransFreeLane(laneHandle, isQosLane, isAsync);
        }
    }
    if (isAsync && laneHandle != INVALID_LANE_REQ_ID) {
        (void)TransDeleteLaneReqItemByLaneHandle(laneHandle, isAsync);
    }
    (void)TransDeleteSocketChannelInfoBySession(sessionName, sessionId);
    return SOFTBUS_OK;
}

int32_t TransCommonCloseChannel(const char *sessionName, int32_t channelId, int32_t channelType)
{
    TRANS_LOGI(TRANS_CTRL, "close channel: channelId=%{public}d, channelType=%{public}d", channelId, channelType);
    int32_t ret = SOFTBUS_TRANS_INVALID_CHANNEL_TYPE;
    if (channelType == CHANNEL_TYPE_UNDEFINED) {
        CoreSessionState state = CORE_SESSION_STATE_INIT;
        ret = TransGetSocketChannelStateBySession(sessionName, channelId, &state);
        TRANS_CHECK_AND_RETURN_RET_LOGE(
            ret == SOFTBUS_OK, ret, TRANS_CTRL, "get socket channel info failed, ret=%{public}d", ret);
        (void)TransSetSocketChannelStateBySession(sessionName, channelId, CORE_SESSION_STATE_CANCELLING);
        if (state == CORE_SESSION_STATE_WAIT_LANE) {
            ret = CancelWaitLaneState(sessionName, channelId);
            TRANS_CHECK_AND_RETURN_RET_LOGE(
                ret == SOFTBUS_OK, ret, TRANS_CTRL, "cancel wait lane failed, ret=%{public}d", ret);
        }
    } else {
        (void)TransSetSocketChannelStateByChannel(channelId, channelType, CORE_SESSION_STATE_CANCELLING);
        switch (channelType) {
            case CHANNEL_TYPE_PROXY:
                ret = TransProxyCloseProxyChannel(channelId);
                (void)TransLaneMgrDelLane(channelId, channelType, false);
                break;
            case CHANNEL_TYPE_TCP_DIRECT:
                (void)TransDelTcpChannelInfoByChannelId(channelId);
                TransDelSessionConnById(channelId); // socket Fd will be shutdown when recv peer reply
                (void)TransLaneMgrDelLane(channelId, channelType, false);
                ret = SOFTBUS_OK;
                break;
            case CHANNEL_TYPE_UDP:
                (void)NotifyQosChannelClosed(channelId, channelType);
                ret = TransCloseUdpChannel(channelId);
                (void)TransLaneMgrDelLane(channelId, channelType, false);
                break;
            case CHANNEL_TYPE_AUTH:
                ret = TransCloseAuthChannel(channelId);
                (void)TransLaneMgrDelLane(channelId, channelType, false);
                break;
            default:
                TRANS_LOGE(TRANS_CTRL, "Unknow channel type, type=%{public}d", channelType);
                break;
        }
        (void)TransDeleteSocketChannelInfoByChannel(channelId, channelType);
    }
    TransEventExtra extra;
    BuildTransCloseChannelEventExtra(&extra, channelId, channelType, ret);
    TRANS_EVENT(EVENT_SCENE_CLOSE_CHANNEL_ACTIVE, EVENT_STAGE_CLOSE_CHANNEL, extra);
    return ret;
}

void TransBuildTransOpenChannelStartEvent(TransEventExtra *extra, AppInfo *appInfo, NodeInfo *nodeInfo, int32_t peerRet)
{
    if (extra == NULL || appInfo == NULL || nodeInfo == NULL) {
        TRANS_LOGE(TRANS_CTRL, "invalid param.");
        return;
    }
    extra->calleePkg = NULL;
    extra->callerPkg = appInfo->myData.pkgName;
    extra->socketName = appInfo->myData.sessionName;
    extra->dataType = appInfo->businessType;
    if (LnnGetLocalStrInfo(STRING_KEY_DEV_UDID, nodeInfo->masterUdid, UDID_BUF_LEN) == SOFTBUS_OK) {
        extra->localUdid = nodeInfo->masterUdid;
    }
    appInfo->osType = nodeInfo->deviceInfo.osType;
    extra->osType = appInfo->osType;
    extra->peerNetworkId = appInfo->peerNetWorkId;
    extra->peerUdid = peerRet == SOFTBUS_OK ? nodeInfo->deviceInfo.deviceUdid : NULL,
    extra->peerDevVer = peerRet == SOFTBUS_OK ? nodeInfo->deviceInfo.deviceVersion : NULL,
    extra->result = EVENT_STAGE_RESULT_OK;
}

void TransBuildOpenAuthChannelStartEvent(TransEventExtra *extra, const char *sessionName, const ConnectOption *connOpt,
    char *localUdid, char *callerPkg)
{
    if (extra == NULL || connOpt == NULL || localUdid == NULL || callerPkg == NULL) {
        TRANS_LOGE(TRANS_CTRL, "invalid param.");
        return;
    }
    if (!IsValidString(sessionName, SESSION_NAME_SIZE_MAX)) {
        TRANS_LOGE(TRANS_CTRL, "invalid param.");
        return;
    }
    if (TransGetPkgNameBySessionName(sessionName, callerPkg, PKG_NAME_SIZE_MAX) == SOFTBUS_OK) {
        extra->callerPkg = callerPkg;
    }
    if (LnnGetLocalStrInfo(STRING_KEY_DEV_UDID, localUdid, UDID_BUF_LEN) == SOFTBUS_OK) {
        extra->localUdid = localUdid;
    }
    extra->socketName = sessionName;
    extra->channelType = CHANNEL_TYPE_AUTH;
    extra->linkType = connOpt->type;
    extra->result = EVENT_STAGE_RESULT_OK;
}

void TransBuildTransOpenChannelEndEvent(TransEventExtra *extra, TransInfo *transInfo, int64_t timeStart, int32_t ret)
{
    if (extra == NULL || transInfo == NULL) {
        TRANS_LOGE(TRANS_CTRL, "invalid param.");
        return;
    }
    extra->channelId = transInfo->channelId;
    extra->errcode = ret;
    extra->costTime = GetSoftbusRecordTimeMillis() - timeStart;
    extra->result = (ret == SOFTBUS_OK) ? EVENT_STAGE_RESULT_OK : EVENT_STAGE_RESULT_FAILED;
}

void TransBuildTransOpenChannelCancelEvent(TransEventExtra *extra, TransInfo *transInfo, int64_t timeStart, int32_t ret)
{
    if (extra == NULL || transInfo == NULL) {
        TRANS_LOGE(TRANS_CTRL, "invalid param.");
        return;
    }
    extra->channelId = transInfo->channelId;
    extra->errcode = ret;
    extra->costTime = GetSoftbusRecordTimeMillis() - timeStart;
    extra->result = EVENT_STAGE_RESULT_CANCELED;
}

void TransBuildTransAlarmEvent(TransAlarmExtra *extraAlarm, AppInfo *appInfo, int32_t ret)
{
    if (extraAlarm == NULL || appInfo == NULL) {
        TRANS_LOGE(TRANS_CTRL, "invalid param.");
        return;
    }
    extraAlarm->conflictName = NULL;
    extraAlarm->conflictedName = NULL;
    extraAlarm->occupyedName = NULL;
    extraAlarm->permissionName = NULL;
    extraAlarm->errcode = ret;
    extraAlarm->sessionName = appInfo->myData.sessionName;
}

void TransFreeAppInfo(AppInfo *appInfo)
{
    if (appInfo == NULL) {
        TRANS_LOGE(TRANS_CTRL, "invalid param.");
        return;
    }
    if (appInfo->fastTransData != NULL) {
        SoftBusFree((void *)(appInfo->fastTransData));
    }
    SoftBusFree(appInfo);
}

void TransFreeLane(uint32_t laneHandle, bool isQosLane, bool isAsync)
{
    TRANS_LOGI(TRANS_CTRL, "Trans free lane laneHandle=%{public}u, isQosLane=%{public}d, isAsync=%{public}d",
        laneHandle, isQosLane, isAsync);
    if (laneHandle == INVALID_LANE_REQ_ID) {
        return;
    }
    if (isQosLane) {
        TransFreeLaneByLaneHandle(laneHandle, isAsync);
        return;
    }
    LnnFreeLane(laneHandle);
}

void TransReportBadKeyEvent(int32_t errCode, uint32_t connectionId, int64_t seq, int32_t len)
{
    TransAuditExtra extra = {
        .hostPkg = NULL,
        .localIp = NULL,
        .localPort = NULL,
        .localDevId = NULL,
        .localSessName = NULL,
        .peerIp = NULL,
        .peerPort = NULL,
        .peerDevId = NULL,
        .peerSessName = NULL,
        .result = TRANS_AUDIT_DISCONTINUE,
        .errcode = errCode,
        .auditType = AUDIT_EVENT_PACKETS_ERROR,
        .connId = connectionId,
        .dataSeq = seq,
        .dataLen = len,
    };
    TRANS_AUDIT(AUDIT_SCENE_SEND_MSG, extra);
}

bool IsPeerDeviceLegacyOs(int32_t osType)
{
    // peer device legacyOs when osType is not OH_OS_TYPE
    return (osType == OH_OS_TYPE) ? false : true;
}

static bool TransGetNetCapability(const char *networkId, uint32_t *local, uint32_t *remote)
{
    int32_t ret = LnnGetLocalNumU32Info(NUM_KEY_NET_CAP, local);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "LnnGetLocalNumInfo err, ret=%{public}d, local=%{public}u", ret, *local);
        return false;
    }
    ret = LnnGetRemoteNumU32Info(networkId, NUM_KEY_NET_CAP, remote);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "LnnGetRemoteNumInfo err, ret=%{public}d, remote=%{public}u", ret, *remote);
        return false;
    }
    TRANS_LOGD(TRANS_CTRL, "trans get net capability success, local=%{public}u, remote=%{public}u", *local, *remote);
    return true;
}

TransDeviceState TransGetDeviceState(const char *networkId)
{
    if (networkId == NULL) {
        TRANS_LOGE(TRANS_CTRL, "networkId err.");
        return DEVICE_STATE_INVALID;
    }
    SoftBusWifiDetailState wifiState = SoftBusGetWifiState();
    if (wifiState == SOFTBUS_WIFI_STATE_SEMIACTIVATING || wifiState == SOFTBUS_WIFI_STATE_SEMIACTIVE) {
        return DEVICE_STATE_LOCAL_WIFI_HALF_OFF;
    }
    uint32_t local = 0;
    uint32_t remote = 0;
    if (!TransGetNetCapability(networkId, &local, &remote)) {
        return DEVICE_STATE_INVALID;
    }
    if ((local & (1 << BIT_BLE)) && !(local & (1 << BIT_BR))) {
        return DEVICE_STATE_LOCAL_BT_HALF_OFF;
    }
    if ((remote & (1 << BIT_BLE)) && !(remote & (1 << BIT_BR))) {
        return DEVICE_STATE_REMOTE_BT_HALF_OFF;
    }
    if ((remote & (1 << BIT_WIFI_P2P)) && !(remote & (1 << BIT_WIFI)) &&
        !(remote & (1 << BIT_WIFI_24G)) && !(remote & (1 << BIT_WIFI_5G))) {
        return DEVICE_STATE_REMOTE_WIFI_HALF_OFF;
    }
    return DEVICE_STATE_NOT_CARE;
}

static int32_t GetSinkRelation(const AppInfo *appInfo, CollabInfo *sinkInfo)
{
    int32_t ret = TransGetTokenIdBySessionName(appInfo->myData.sessionName, &sinkInfo->tokenId);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get tokenId failed.");
        return ret;
    }
    ret = LnnGetLocalStrInfo(STRING_KEY_DEV_UDID, sinkInfo->deviceId, UDID_BUF_LEN);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "LnnGetLocalStrInfo failed.");
        return ret;
    }
    ret = GetCurrentAccount(&sinkInfo->accountId);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGW(TRANS_CTRL, "get current account failed.");
        sinkInfo->accountId = INVALID_ACCOUNT_ID;
    }
    sinkInfo->pid = appInfo->myData.pid;
    sinkInfo->userId = TransGetForegroundUserId();
    if (sinkInfo->userId == INVALID_USER_ID) {
        TRANS_LOGE(TRANS_CTRL, "get userId failed.");
        return SOFTBUS_TRANS_GET_LOCAL_UID_FAIL;
    }
    return SOFTBUS_OK;
}

static void GetSourceRelation(const AppInfo *appInfo, CollabInfo *sourceInfo)
{
    sourceInfo->tokenId = appInfo->callingTokenId;
    sourceInfo->pid = appInfo->peerData.pid;
    sourceInfo->accountId = appInfo->peerData.accountId;
    sourceInfo->userId = appInfo->peerData.userId;
    char netWorkId[NETWORK_ID_BUF_LEN] = { 0 };
    (void)LnnGetNetworkIdByUuid(appInfo->peerData.deviceId, netWorkId, NETWORK_ID_BUF_LEN);
    (void)LnnGetRemoteStrInfo(netWorkId, STRING_KEY_DEV_UDID, sourceInfo->deviceId, UDID_BUF_LEN);
}

int32_t CheckCollabRelation(const AppInfo *appInfo, int32_t channelId, int32_t channelType)
{
    if (appInfo == NULL) {
        TRANS_LOGE(TRANS_CTRL, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }

    CollabInfo sourceInfo;
    (void)memset_s(&sourceInfo, sizeof(CollabInfo), 0, sizeof(CollabInfo));
    GetSourceRelation(appInfo, &sourceInfo);
    if (sourceInfo.userId == INVALID_USER_ID) {
        TRANS_LOGW(TRANS_CTRL, "userId is invalid.");
        return SOFTBUS_TRANS_NOT_NEED_CHECK_RELATION;
    }

    CollabInfo sinkInfo;
    (void)memset_s(&sinkInfo, sizeof(CollabInfo), 0, sizeof(CollabInfo));
    int32_t ret = GetSinkRelation(appInfo, &sinkInfo);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get sink relation failed.");
        return ret;
    }
    if (!SoftBusCheckIsApp(sinkInfo.tokenId, appInfo->myData.sessionName)) {
        TRANS_LOGE(TRANS_CTRL, "check is not app.");
        return SOFTBUS_TRANS_NOT_NEED_CHECK_RELATION;
    }

    int32_t pid = 0;
    char pkgName[PKG_NAME_SIZE_MAX] = { 0 };
    ret = TransGetPidAndPkgName(DMS_SESSIONNAME, DMS_UID, &pid, pkgName, PKG_NAME_SIZE_MAX);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "TransGetPidAndPkgName fail ret=%{public}d.", ret);
        return ret;
    }

    TransInfo transInfo = { .channelId = channelId, .channelType = channelType };
    ret = ClientIpcCheckCollabRelation(pkgName, pid, &sourceInfo, &sinkInfo, &transInfo);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL,
            "channelId=%{public}d check Collaboration relation fail, ret=%{public}d.", transInfo.channelId, ret);
        return ret;
    }
    TRANS_LOGI(TRANS_CTRL, "channelId=%{public}d check Collaboration relationship success.", transInfo.channelId);
    return SOFTBUS_OK;
}
