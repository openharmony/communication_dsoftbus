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
#include "lnn_lane_interface.h"
#include "lnn_network_manager.h"
#include "softbus_adapter_mem.h"
#include "softbus_config_type.h"
#include "softbus_errcode.h"
#include "softbus_feature_config.h"
#include "softbus_hisysevt_transreporter.h"
#include "softbus_proxychannel_manager.h"
#include "softbus_qos.h"
#include "trans_auth_manager.h"
#include "trans_event.h"
#include "trans_lane_manager.h"
#include "trans_log.h"
#include "trans_session_manager.h"
#include "trans_tcp_direct_manager.h"
#include "trans_tcp_direct_sessionconn.h"
#include "trans_udp_channel_manager.h"
#include "trans_udp_negotiation.h"
#include "wifi_direct_manager.h"

typedef struct {
    int32_t channelType;
    int32_t businessType;
    ConfigType configType;
} ConfigTypeMap;

static const ConfigTypeMap G_CONFIG_TYPE_MAP[] = {
    { CHANNEL_TYPE_AUTH,       BUSINESS_TYPE_BYTE,    SOFTBUS_INT_AUTH_MAX_BYTES_LENGTH  },
    { CHANNEL_TYPE_AUTH,       BUSINESS_TYPE_MESSAGE, SOFTBUS_INT_AUTH_MAX_MESSAGE_LENGTH},
    { CHANNEL_TYPE_PROXY,      BUSINESS_TYPE_BYTE,    SOFTBUS_INT_MAX_BYTES_NEW_LENGTH   },
    { CHANNEL_TYPE_PROXY,      BUSINESS_TYPE_MESSAGE, SOFTBUS_INT_MAX_MESSAGE_NEW_LENGTH },
    { CHANNEL_TYPE_TCP_DIRECT, BUSINESS_TYPE_BYTE,    SOFTBUS_INT_MAX_BYTES_NEW_LENGTH   },
    { CHANNEL_TYPE_TCP_DIRECT, BUSINESS_TYPE_MESSAGE, SOFTBUS_INT_MAX_MESSAGE_NEW_LENGTH },
};

static int32_t FindConfigType(int32_t channelType, int32_t businessType)
{
    for (uint32_t i = 0; i < sizeof(G_CONFIG_TYPE_MAP) / sizeof(ConfigTypeMap); i++) {
        if ((G_CONFIG_TYPE_MAP[i].channelType == channelType) && (G_CONFIG_TYPE_MAP[i].businessType == businessType)) {
            return G_CONFIG_TYPE_MAP[i].configType;
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
    } else if ((transType == LANE_T_MSG) && (type != LANE_P2P) && (type != LANE_P2P_REUSE) && (type != LANE_HML)) {
        return CHANNEL_TYPE_PROXY;
    }
    return CHANNEL_TYPE_TCP_DIRECT;
}

void FillAppInfo(AppInfo *appInfo, const SessionParam *param, TransInfo *transInfo, LaneConnInfo *connInfo)
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
            return SOFTBUS_ERR;
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
    return SOFTBUS_OK;
}

AppInfo *TransCommonGetAppInfo(const SessionParam *param)
{
    TRANS_CHECK_AND_RETURN_RET_LOGE(param != NULL, NULL, TRANS_CTRL, "Invalid param");
    char *tmpId = NULL;
    Anonymize(param->peerDeviceId, &tmpId);
    TRANS_LOGI(TRANS_CTRL, "GetAppInfo, deviceId=%{public}s", tmpId);
    AnonymizeFree(tmpId);
    AppInfo *appInfo = (AppInfo *)SoftBusCalloc(sizeof(AppInfo));
    if (appInfo == NULL) {
        return NULL;
    }
    appInfo->appType = APP_TYPE_NORMAL;
    appInfo->myData.apiVersion = API_V2;
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
    if (LnnGetLocalStrInfo(STRING_KEY_UUID, appInfo->myData.deviceId, sizeof(appInfo->myData.deviceId)) != SOFTBUS_OK) {
        goto EXIT_ERR;
    }
    if (CopyAppInfoFromSessionParam(appInfo, param) != SOFTBUS_OK) {
        goto EXIT_ERR;
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
    appInfo->firstTokenId = TransACLGetFirstTokenID();

    TRANS_LOGD(TRANS_CTRL, "GetAppInfo ok");
    return appInfo;
EXIT_ERR:
    if (appInfo != NULL) {
        if (appInfo->fastTransData != NULL) {
            SoftBusFree((void*)appInfo->fastTransData);
        }
        SoftBusFree(appInfo);
    }
    return NULL;
}

void TransOpenChannelSetModule(int32_t channelType, ConnectOption *connOpt)
{
    if (connOpt->type != CONNECT_TCP || connOpt->socketOption.protocol != LNN_PROTOCOL_NIP) {
        TRANS_LOGE(TRANS_CTRL, "param err.");
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
    int32_t ret = SOFTBUS_ERR;
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

int32_t TransCommonCloseChannel(int32_t channelId, int32_t channelType)
{
    TRANS_LOGI(TRANS_CTRL, "close channel: channelId=%{public}d, channelType=%{public}d", channelId, channelType);
    int32_t ret = SOFTBUS_ERR;
    switch (channelType) {
        case CHANNEL_TYPE_PROXY:
            (void)TransLaneMgrDelLane(channelId, channelType);
            ret = TransProxyCloseProxyChannel(channelId);
            break;
        case CHANNEL_TYPE_TCP_DIRECT:
            (void)TransLaneMgrDelLane(channelId, channelType);
            ret = SOFTBUS_OK;
            break;
        case CHANNEL_TYPE_UDP:
            (void)NotifyQosChannelClosed(channelId, channelType);
            (void)TransLaneMgrDelLane(channelId, channelType);
            ret = TransCloseUdpChannel(channelId);
            break;
        case CHANNEL_TYPE_AUTH:
            ret = TransCloseAuthChannel(channelId);
            break;
        default:
            break;
    }
    TransEventExtra extra = { .socketName = NULL,
        .peerNetworkId = NULL,
        .calleePkg = NULL,
        .callerPkg = NULL,
        .channelId = channelId,
        .channelType = channelType,
        .errcode = ret,
        .result = (ret == SOFTBUS_OK) ? EVENT_STAGE_RESULT_OK : EVENT_STAGE_RESULT_FAILED };
    TRANS_EVENT(EVENT_SCENE_CLOSE_CHANNEL_ACTIVE, EVENT_STAGE_CLOSE_CHANNEL, extra);
    return ret;
}

void ReportTransOpenChannelEndEvent(TransEventExtra extra, TransInfo *transInfo, int64_t timeStart, int32_t ret)
{
    extra.channelId = transInfo->channelId;
    extra.errcode = ret;
    extra.costTime = GetSoftbusRecordTimeMillis() - timeStart;
    extra.result = EVENT_STAGE_RESULT_FAILED;
    TRANS_EVENT(EVENT_SCENE_OPEN_CHANNEL, EVENT_STAGE_OPEN_CHANNEL_END, extra);
}

void ReportTransAlarmEvent(AppInfo *appInfo, int32_t ret)
{
    TransAlarmExtra extraAlarm = {
        .conflictName = NULL,
        .conflictedName = NULL,
        .occupyedName = NULL,
        .permissionName = NULL,
        .errcode = ret,
        .sessionName = appInfo->myData.sessionName,
    };
    TRANS_ALARM(OPEN_SESSION_FAIL_ALARM, CONTROL_ALARM_TYPE, extraAlarm);
}