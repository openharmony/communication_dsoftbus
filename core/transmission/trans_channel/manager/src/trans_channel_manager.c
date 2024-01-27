/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "trans_channel_manager.h"

#include <securec.h>

#include "anonymizer.h"
#include "bus_center_manager.h"
#include "lnn_lane_qos.h"
#include "session.h"
#include "softbus_adapter_mem.h"
#include "softbus_conn_interface.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_feature_config.h"
#include "softbus_hisysevt_transreporter.h"
#include "softbus_proxychannel_manager.h"
#include "softbus_proxychannel_session.h"
#include "softbus_qos.h"
#include "softbus_utils.h"
#include "trans_auth_manager.h"
#include "trans_channel_callback.h"
#include "trans_lane_manager.h"
#include "trans_lane_pending_ctl.h"
#include "trans_link_listener.h"
#include "trans_log.h"
#include "trans_session_manager.h"
#include "trans_tcp_direct_manager.h"
#include "trans_udp_channel_manager.h"
#include "trans_udp_negotiation.h"
#include "trans_tcp_direct_sessionconn.h"
#include "lnn_network_manager.h"
#include "trans_event.h"
#include "wifi_direct_manager.h"

#define MIGRATE_ENABLE 2
#define MIGRATE_SUPPORTED 1
#define MAX_PROXY_CHANNEL_ID 0x00000800
#define MAX_TDC_CHANNEL_ID 0x7FFFFFFF
#define MAX_FD_ID 1025
#define MAX_PROXY_CHANNEL_ID_COUNT 1024
#define ID_NOT_USED 0
#define ID_USED 1UL
#define BIT_NUM 8

static int32_t g_allocTdcChannelId = MAX_PROXY_CHANNEL_ID;
static SoftBusMutex g_myIdLock;
static unsigned long g_proxyChanIdBits[MAX_PROXY_CHANNEL_ID_COUNT / BIT_NUM / sizeof(long)] = {0};
static uint32_t g_proxyIdMark = 0;
static uint32_t g_channelIdCount = 0;

typedef struct {
    int32_t channelType;
    int32_t businessType;
    ConfigType configType;
} ConfigTypeMap;

static int32_t GenerateTdcChannelId()
{
    int32_t channelId;
    if (SoftBusMutexLock(&g_myIdLock) != 0) {
        TRANS_LOGE(TRANS_CTRL, "lock mutex fail!");
        return SOFTBUS_ERR;
    }
    channelId = g_allocTdcChannelId++;
    if (g_allocTdcChannelId >= MAX_TDC_CHANNEL_ID) {
        g_allocTdcChannelId = MAX_PROXY_CHANNEL_ID;
    }
    SoftBusMutexUnlock(&g_myIdLock);
    return channelId;
}

static int32_t GenerateProxyChannelId()
{
    if (SoftBusMutexLock(&g_myIdLock) != 0) {
        TRANS_LOGE(TRANS_CTRL, "lock mutex fail!");
        return SOFTBUS_ERR;
    }

    if (g_channelIdCount >= MAX_PROXY_CHANNEL_ID_COUNT) {
        TRANS_LOGE(TRANS_CTRL, "No more channel Ids(1024) can be applied");
        return INVALID_CHANNEL_ID;
    }

    for (uint32_t id = g_proxyIdMark + 1; id != g_proxyIdMark; id++) {
        id = id % MAX_PROXY_CHANNEL_ID_COUNT;
        uint32_t index = id / (BIT_NUM * sizeof(long));
        uint32_t bit = id % (BIT_NUM * sizeof(long));
        if ((g_proxyChanIdBits[index] & (ID_USED << bit)) == ID_NOT_USED) {
            g_proxyChanIdBits[index] |= (ID_USED << bit);
            g_proxyIdMark = id;
            g_channelIdCount++;
            SoftBusMutexUnlock(&g_myIdLock);
            return (int32_t)id + MAX_FD_ID;
        }
    }
    SoftBusMutexUnlock(&g_myIdLock);
    return INVALID_CHANNEL_ID;
}

void ReleaseProxyChannelId(int32_t channelId)
{
    if (channelId == INVALID_CHANNEL_ID) {
        return;
    }
    if (SoftBusMutexLock(&g_myIdLock) != 0) {
        TRANS_LOGE(TRANS_CTRL, "lock mutex fail");
        return;
    }
    if (g_channelIdCount >= ID_USED) {
        g_channelIdCount--;
    } else {
        TRANS_LOGE(TRANS_CTRL, "g_channelIdCount error");
    }
    uint32_t id = (uint32_t)channelId - MAX_FD_ID;
    uint32_t dex = id / (8 * sizeof(long));
    uint32_t bit = id % (8 * sizeof(long));
    g_proxyChanIdBits[dex] &= (~(ID_USED << bit));
    SoftBusMutexUnlock(&g_myIdLock);
}

int32_t GenerateChannelId(bool isTdcChannel)
{
    return isTdcChannel ? GenerateTdcChannelId() : GenerateProxyChannelId();
}

int32_t TransChannelInit(void)
{
    IServerChannelCallBack *cb = TransServerGetChannelCb();
    if (cb == NULL) {
        TRANS_LOGE(TRANS_INIT, "cd is null.");
        return SOFTBUS_ERR;
    }

    if (TransLaneMgrInit() != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_INIT, "trans lane manager init failed.");
        return SOFTBUS_ERR;
    }

    if (TransAuthInit(cb) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_INIT, "trans auth init failed.");
        return SOFTBUS_ERR;
    }

    if (TransProxyManagerInit(cb) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_INIT, "trans proxy manager init failed.");
        return SOFTBUS_ERR;
    }

    if (TransTcpDirectInit(cb) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_INIT, "trans tcp direct init failed.");
        return SOFTBUS_ERR;
    }

    if (TransUdpChannelInit(cb) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_INIT, "trans udp channel init failed.");
        return SOFTBUS_ERR;
    }

    if (TransReqLanePendingInit() != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_INIT, "trans req lane pending init failed.");
        return SOFTBUS_ERR;
    }

    ReqLinkListener();

    if (SoftBusMutexInit(&g_myIdLock, NULL) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_INIT, "init lock failed");
        return SOFTBUS_ERR;
    }

    return SOFTBUS_OK;
}

void TransChannelDeinit(void)
{
    TransLaneMgrDeinit();
    TransAuthDeinit();
    TransProxyManagerDeinit();
    TransTcpDirectDeinit();
    TransUdpChannelDeinit();
    TransReqLanePendingDeinit();
    SoftBusMutexDestroy(&g_myIdLock);
}

static int32_t CopyAppInfoFromSessionParam(AppInfo* appInfo, const SessionParam* param)
{
    if (param == NULL || param->attr == NULL) {
        TRANS_LOGE(TRANS_CTRL, "parm is null");
        return SOFTBUS_ERR;
    }
    if (param->attr->fastTransData != NULL && param->attr->fastTransDataSize > 0 &&
        param->attr->fastTransDataSize <= MAX_FAST_DATA_LEN) {
        if (appInfo->businessType == BUSINESS_TYPE_FILE || appInfo->businessType == BUSINESS_TYPE_STREAM) {
            TRANS_LOGE(TRANS_CTRL, "not support send fast data");
            return SOFTBUS_ERR;
        }
        appInfo->fastTransData = (uint8_t*)SoftBusCalloc(param->attr->fastTransDataSize);
        if (appInfo->fastTransData == NULL) {
            return SOFTBUS_ERR;
        }
        if (memcpy_s((char *)appInfo->fastTransData, param->attr->fastTransDataSize,
            (const char *)param->attr->fastTransData, param->attr->fastTransDataSize) != EOK) {
            TRANS_LOGE(TRANS_CTRL, "memcpy_s err");
            return SOFTBUS_ERR;
        }
    }
    appInfo->fastTransDataSize = param->attr->fastTransDataSize;
    if (TransGetUidAndPid(param->sessionName, &appInfo->myData.uid, &appInfo->myData.pid) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    if (strcpy_s(appInfo->groupId, sizeof(appInfo->groupId), param->groupId) != EOK) {
        return SOFTBUS_ERR;
    }
    if (strcpy_s(appInfo->myData.sessionName, sizeof(appInfo->myData.sessionName), param->sessionName) != EOK) {
        return SOFTBUS_ERR;
    }
    if (strcpy_s(appInfo->peerNetWorkId, sizeof(appInfo->peerNetWorkId), param->peerDeviceId) != EOK) {
        return SOFTBUS_ERR;
    }
    if (TransGetPkgNameBySessionName(param->sessionName, appInfo->myData.pkgName, PKG_NAME_SIZE_MAX) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    if (strcpy_s(appInfo->peerData.sessionName, sizeof(appInfo->peerData.sessionName), param->peerSessionName) != 0) {
        return SOFTBUS_ERR;
    }
    if (LnnGetRemoteStrInfo(param->peerDeviceId, STRING_KEY_UUID,
        appInfo->peerData.deviceId, sizeof(appInfo->peerData.deviceId)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get remote node uuid err");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static AppInfo *GetAppInfo(const SessionParam *param)
{
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
    if (LnnGetLocalStrInfo(STRING_KEY_UUID, appInfo->myData.deviceId,
        sizeof(appInfo->myData.deviceId)) != SOFTBUS_OK) {
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

static ChannelType TransGetChannelType(const SessionParam *param, const int32_t type)
{
    LaneTransType transType = TransGetLaneTransTypeBySession(param);
    if (transType == LANE_T_BUTT) {
        return CHANNEL_TYPE_BUTT;
    }

    if (type == LANE_BR || type == LANE_BLE || type == LANE_BLE_DIRECT ||
        type == LANE_COC || type == LANE_COC_DIRECT) {
        return CHANNEL_TYPE_PROXY;
    } else if (transType == LANE_T_FILE || transType == LANE_T_COMMON_VIDEO || transType == LANE_T_COMMON_VOICE ||
        transType == LANE_T_RAW_STREAM) {
        return CHANNEL_TYPE_UDP;
    } else if ((transType == LANE_T_MSG) && (type != LANE_P2P) && (type != LANE_P2P_REUSE) &&
        (type != LANE_HML)) {
        return CHANNEL_TYPE_PROXY;
    }
    return CHANNEL_TYPE_TCP_DIRECT;
}

static int32_t TransOpenChannelProc(ChannelType type, AppInfo *appInfo, const ConnectOption *connOpt,
    int32_t *channelId)
{
    if (type == CHANNEL_TYPE_BUTT) {
        TRANS_LOGE(TRANS_CTRL, "open invalid channel type.");
        return SOFTBUS_TRANS_INVALID_CHANNEL_TYPE;
    }
    int32_t ret = SOFTBUS_ERR;
    if (type == CHANNEL_TYPE_UDP) {
        ret = TransOpenUdpChannel(appInfo, connOpt, channelId);
        if (ret != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_CTRL, "open udp channel err");
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

static const ConfigTypeMap g_configTypeMap[] = {
    {CHANNEL_TYPE_AUTH, BUSINESS_TYPE_BYTE, SOFTBUS_INT_AUTH_MAX_BYTES_LENGTH},
    {CHANNEL_TYPE_AUTH, BUSINESS_TYPE_MESSAGE, SOFTBUS_INT_AUTH_MAX_MESSAGE_LENGTH},
    {CHANNEL_TYPE_PROXY, BUSINESS_TYPE_BYTE, SOFTBUS_INT_MAX_BYTES_NEW_LENGTH},
    {CHANNEL_TYPE_PROXY, BUSINESS_TYPE_MESSAGE, SOFTBUS_INT_MAX_MESSAGE_NEW_LENGTH},
    {CHANNEL_TYPE_TCP_DIRECT, BUSINESS_TYPE_BYTE, SOFTBUS_INT_MAX_BYTES_NEW_LENGTH},
    {CHANNEL_TYPE_TCP_DIRECT, BUSINESS_TYPE_MESSAGE, SOFTBUS_INT_MAX_MESSAGE_NEW_LENGTH},
};

static int32_t FindConfigType(int32_t channelType, int32_t businessType)
{
    for (uint32_t i = 0; i < sizeof(g_configTypeMap) / sizeof(ConfigTypeMap); i++) {
        if ((g_configTypeMap[i].channelType == channelType) && (g_configTypeMap[i].businessType == businessType)) {
            return g_configTypeMap[i].configType;
        }
    }
    return SOFTBUS_CONFIG_TYPE_MAX;
}

static int TransGetLocalConfig(int32_t channelType, int32_t businessType, uint32_t *len)
{
    ConfigType configType = (ConfigType)FindConfigType(channelType, businessType);
    if (configType == SOFTBUS_CONFIG_TYPE_MAX) {
        TRANS_LOGE(TRANS_CTRL, "Invalid channelType=%{public}d businessType=%{public}d",
            channelType, businessType);
        return SOFTBUS_INVALID_PARAM;
    }
    uint32_t maxLen;
    if (SoftbusGetConfig(configType, (unsigned char *)&maxLen, sizeof(maxLen)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get fail configType=%{public}d", configType);
        return SOFTBUS_GET_CONFIG_VAL_ERR;
    }
    *len = maxLen;
    TRANS_LOGI(TRANS_CTRL, "get appinfo local config len=%{public}d", *len);
    return SOFTBUS_OK;
}

static void FillAppInfo(AppInfo *appInfo, const SessionParam *param,
    TransInfo *transInfo, LaneConnInfo *connInfo)
{
    transInfo->channelType = TransGetChannelType(param, connInfo->type);
    appInfo->linkType = connInfo->type;
    appInfo->channelType = transInfo->channelType;
    (void)TransGetLocalConfig(appInfo->channelType, appInfo->businessType, &appInfo->myData.dataConfig);
    if (connInfo->type == LANE_P2P || connInfo->type == LANE_HML) {
        if (strcpy_s(appInfo->myData.addr, IP_LEN, connInfo->connInfo.p2p.localIp) != EOK) {
            TRANS_LOGE(TRANS_CTRL, "copy local ip failed");
        }
    } else if (connInfo->type == LANE_P2P_REUSE) {
        if (GetWifiDirectManager()->getLocalIpByRemoteIp(connInfo->connInfo.wlan.addr, appInfo->myData.addr, IP_LEN) !=
            SOFTBUS_OK) {
            TRANS_LOGE(TRANS_CTRL, "get local ip failed");
        }
    }
}

static void TransOpenChannelSetModule(int32_t channelType, ConnectOption *connOpt)
{
    if (connOpt->type != CONNECT_TCP || connOpt->socketOption.protocol != LNN_PROTOCOL_NIP) {
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

int32_t TransOpenChannel(const SessionParam *param, TransInfo *transInfo)
{
    if (param == NULL || transInfo == NULL) {
        TRANS_LOGE(TRANS_CTRL, "param invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    TRANS_LOGI(TRANS_CTRL, "server TransOpenChannel");
    int64_t timeStart = GetSoftbusRecordTimeMillis();
    transInfo->channelId = INVALID_CHANNEL_ID;
    transInfo->channelType = CHANNEL_TYPE_BUTT;
    LaneConnInfo connInfo;
    uint32_t laneId = 0;
    ConnectOption connOpt;
    (void)memset_s(&connOpt, sizeof(ConnectOption), 0, sizeof(ConnectOption));
    int32_t ret = INVALID_CHANNEL_ID;
    int32_t errCode = INVALID_CHANNEL_ID;

    AppInfo *appInfo = GetAppInfo(param);
    TRANS_CHECK_AND_RETURN_RET_LOGW(!(appInfo == NULL), INVALID_CHANNEL_ID, TRANS_CTRL, "GetAppInfo is null.");
    TransEventExtra extra = {
        .calleePkg = NULL,
        .callerPkg = appInfo->myData.pkgName,
        .socketName = appInfo->myData.sessionName,
        .dataType = appInfo->businessType,
        .peerNetworkId = appInfo->peerNetWorkId,
        .result = EVENT_STAGE_RESULT_OK
    };
    TRANS_EVENT(EVENT_SCENE_OPEN_CHANNEL, EVENT_STAGE_OPEN_CHANNEL_START, extra);
    errCode = TransGetLaneInfo(param, &connInfo, &laneId);
    char *tmpName = NULL;
    if (errCode != SOFTBUS_OK) {
        SoftbusReportTransErrorEvt(SOFTBUS_TRANS_GET_LANE_INFO_ERR);
        ret = errCode;
        goto EXIT_ERR;
    }
    Anonymize(param->sessionName, &tmpName);
    TRANS_LOGI(TRANS_CTRL,
        "sessionName=%{public}s, laneId=%{public}u, linkType=%{public}u.", tmpName, laneId, connInfo.type);
    AnonymizeFree(tmpName);
    errCode = TransGetConnectOptByConnInfo(&connInfo, &connOpt);
    if (errCode != SOFTBUS_OK) {
        ret = errCode;
        SoftbusRecordOpenSessionKpi(appInfo->myData.pkgName, connInfo.type,
            SOFTBUS_EVT_OPEN_SESSION_FAIL, GetSoftbusRecordTimeMillis() - timeStart);
        goto EXIT_ERR;
    }
    appInfo->connectType = connOpt.type;
    extra.linkType = connOpt.type;
    FillAppInfo(appInfo, param, transInfo, &connInfo);
    TransOpenChannelSetModule(transInfo->channelType, &connOpt);
    TRANS_LOGI(TRANS_CTRL, "laneId=%{public}u, channelType=%{public}u", laneId, transInfo->channelType);
    errCode = TransOpenChannelProc((ChannelType)transInfo->channelType, appInfo, &connOpt,
        &(transInfo->channelId));
    if (errCode != SOFTBUS_OK) {
        ret = errCode;
        SoftbusReportTransErrorEvt(SOFTBUS_TRANS_CREATE_CHANNEL_ERR);
        SoftbusRecordOpenSessionKpi(appInfo->myData.pkgName,
            appInfo->linkType, SOFTBUS_EVT_OPEN_SESSION_FAIL, GetSoftbusRecordTimeMillis() - timeStart);
        goto EXIT_ERR;
    }

    if (((ChannelType)transInfo->channelType == CHANNEL_TYPE_TCP_DIRECT) && (connOpt.type != CONNECT_P2P)) {
        LnnFreeLane(laneId);
    } else if (TransLaneMgrAddLane(transInfo->channelId, transInfo->channelType,
        &connInfo, laneId, &appInfo->myData) != SOFTBUS_OK) {
        SoftbusRecordOpenSessionKpi(appInfo->myData.pkgName,
            appInfo->linkType, SOFTBUS_EVT_OPEN_SESSION_FAIL, GetSoftbusRecordTimeMillis() - timeStart);
        TransCloseChannel(transInfo->channelId, transInfo->channelType);
        goto EXIT_ERR;
    }

    if (appInfo->fastTransData != NULL) {
        SoftBusFree((void*)appInfo->fastTransData);
    }
    SoftBusFree(appInfo);
    TRANS_LOGI(TRANS_CTRL, "server TransOpenChannel ok: channelId=%{public}d, channelType=%{public}d",
        transInfo->channelId, transInfo->channelType);
    return SOFTBUS_OK;
EXIT_ERR:
    extra.channelId = transInfo->channelId;
    extra.errcode = ret;
    extra.costTime = GetSoftbusRecordTimeMillis() - timeStart;
    extra.result = EVENT_STAGE_RESULT_FAILED;
    TRANS_EVENT(EVENT_SCENE_OPEN_CHANNEL, EVENT_STAGE_OPEN_CHANNEL_END, extra);
    TransAlarmExtra extraAlarm = {
        .conflictName = NULL,
        .conflictedName = NULL,
        .occupyedName = NULL,
        .permissionName = NULL,
        .errcode = ret,
        .sessionName = appInfo->myData.sessionName,
    };
    TRANS_ALARM(OPEN_SESSION_FAIL_ALARM, CONTROL_ALARM_TYPE, extraAlarm);
    if (appInfo->fastTransData != NULL) {
        SoftBusFree((void*)appInfo->fastTransData);
    }
    SoftBusFree(appInfo);
    if (laneId != 0) {
        LnnFreeLane(laneId);
    }
    TRANS_LOGE(TRANS_CTRL, "server TransOpenChannel err");
    return ret;
}

static AppInfo *GetAuthAppInfo(const char *mySessionName)
{
    TRANS_LOGD(TRANS_CTRL, "enter.");
    AppInfo *appInfo = (AppInfo *)SoftBusCalloc(sizeof(AppInfo));
    if (appInfo == NULL) {
        return NULL;
    }
    appInfo->appType = APP_TYPE_AUTH;
    appInfo->myData.apiVersion = API_V2;
    appInfo->autoCloseTime = 0;
    appInfo->businessType = BUSINESS_TYPE_BYTE;
    appInfo->channelType = CHANNEL_TYPE_AUTH;
    appInfo->timeStart = GetSoftbusRecordTimeMillis();
    if (TransGetUidAndPid(mySessionName, &appInfo->myData.uid, &appInfo->myData.pid) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "GetAuthAppInfo GetUidAndPid failed");
        goto EXIT_ERR;
    }
    if (LnnGetLocalStrInfo(STRING_KEY_DEV_UDID, appInfo->myData.deviceId,
        sizeof(appInfo->myData.deviceId)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "GetAuthAppInfo get deviceId failed");
        goto EXIT_ERR;
    }
    if (strcpy_s(appInfo->myData.sessionName, sizeof(appInfo->myData.sessionName), mySessionName) != EOK) {
        TRANS_LOGE(TRANS_CTRL, "GetAuthAppInfo strcpy_s mySessionName failed");
        goto EXIT_ERR;
    }
    if (strcpy_s(appInfo->peerData.sessionName, sizeof(appInfo->peerData.sessionName), mySessionName) != EOK) {
        TRANS_LOGE(TRANS_CTRL, "GetAuthAppInfo strcpy_s peerSessionName failed");
        goto EXIT_ERR;
    }
    if (TransGetPkgNameBySessionName(mySessionName, appInfo->myData.pkgName, PKG_NAME_SIZE_MAX) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "GetAuthAppInfo get PkgName failed");
        goto EXIT_ERR;
    }
    if (TransGetLocalConfig(appInfo->channelType, appInfo->businessType, &appInfo->myData.dataConfig) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "GetAuthAppInfo get local data config failed");
        goto EXIT_ERR;
    }

    TRANS_LOGD(TRANS_CTRL, "ok");
    return appInfo;
EXIT_ERR:
    if (appInfo != NULL) {
        SoftBusFree(appInfo);
    }
    return NULL;
}

int32_t TransOpenAuthChannel(const char *sessionName, const ConnectOption *connOpt,
    const char *reqId)
{
    TransEventExtra extra = {
        .calleePkg = NULL,
        .callerPkg = NULL,
        .socketName = NULL,
        .peerNetworkId = NULL,
        .channelType = CHANNEL_TYPE_AUTH,
        .result = EVENT_STAGE_RESULT_OK
    };
    TRANS_EVENT(EVENT_SCENE_OPEN_CHANNEL, EVENT_STAGE_OPEN_CHANNEL_START, extra);
    int32_t channelId = INVALID_CHANNEL_ID;
    if (!IsValidString(sessionName, SESSION_NAME_SIZE_MAX) || connOpt == NULL) {
        goto EXIT_ERR;
    }
    extra.socketName = sessionName;
    extra.linkType = connOpt->type;
    if (connOpt->type == CONNECT_TCP) {
        if (TransOpenAuthMsgChannel(sessionName, connOpt, &channelId, reqId) != SOFTBUS_OK) {
            goto EXIT_ERR;
        }
    } else if (connOpt->type == CONNECT_BR || connOpt->type == CONNECT_BLE) {
        AppInfo *appInfo = GetAuthAppInfo(sessionName);
        if (appInfo == NULL) {
            TRANS_LOGE(TRANS_CTRL, "GetAuthAppInfo failed");
            goto EXIT_ERR;
        }
        appInfo->connectType = connOpt->type;
        if (strcpy_s(appInfo->reqId, REQ_ID_SIZE_MAX, reqId) != EOK) {
            TRANS_LOGE(TRANS_CTRL, "strcpy_s reqId failed");
            SoftBusFree(appInfo);
            goto EXIT_ERR;
        }
        if (TransProxyOpenProxyChannel(appInfo, connOpt, &channelId) != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_CTRL, "proxy channel err");
            SoftBusFree(appInfo);
            goto EXIT_ERR;
        }
        SoftBusFree(appInfo);
    } else {
        goto EXIT_ERR;
    }
    return channelId;
EXIT_ERR:
    extra.result = EVENT_STAGE_RESULT_FAILED;
    extra.errcode = SOFTBUS_ERR;
    TRANS_EVENT(EVENT_SCENE_OPEN_CHANNEL, EVENT_STAGE_OPEN_CHANNEL_END, extra);
    return INVALID_CHANNEL_ID;
}

static uint32_t MergeStatsInterval(const uint32_t *data, uint32_t left, uint32_t right)
{
    uint32_t result = 0;
    while (left <= right) {
        result += data[left];
        left++;
    }
    return result;
}

static void ConvertStreamStats(const StreamSendStats *src, FrameSendStats *dest)
{
    uint32_t *srcCostCnt = (uint32_t *)(src->costTimeStatsCnt);
    uint32_t *srcBitRate = (uint32_t *)(src->sendBitRateStatsCnt);
    uint32_t *destCostCnt = dest->costTimeStatsCnt;
    uint32_t *destBitRate = dest->sendBitRateStatsCnt;
    destCostCnt[FRAME_COST_TIME_SMALL] = srcCostCnt[FRAME_COST_LT10MS];
    destCostCnt[FRAME_COST_TIME_MEDIUM] = MergeStatsInterval(srcCostCnt, FRAME_COST_LT30MS, FRAME_COST_LT100MS);
    destCostCnt[FRAME_COST_TIME_LARGE] = srcCostCnt[FRAME_COST_LT120MS] + srcCostCnt[FRAME_COST_GE120MS];
    destBitRate[FRAME_BIT_RATE_SMALL] = srcBitRate[FRAME_BIT_RATE_LT3M];
    destBitRate[FRAME_BIT_RATE_MEDIUM] = MergeStatsInterval(srcBitRate, FRAME_BIT_RATE_LT6M, FRAME_BIT_RATE_LT30M);
    destBitRate[FRAME_BIT_RATE_LARGE] = srcBitRate[FRAME_BIT_RATE_GE30M];
}

int32_t TransStreamStats(int32_t channelId, int32_t channelType, const StreamSendStats *data)
{
    (void)channelType;
    if (data == NULL) {
        TRANS_LOGE(TRANS_STREAM, "streamStats data is null");
        return SOFTBUS_INVALID_PARAM;
    }
    uint32_t laneId;
    int32_t ret = TransGetLaneIdByChannelId(channelId, &laneId);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_STREAM, "get laneId fail, streamStatsInfo cannot be processed");
        return SOFTBUS_ERR;
    }
    TRANS_LOGI(TRANS_STREAM, "transStreamStats channelId=%{public}d, laneId=0x%{public}x", channelId, laneId);
    LaneIdStatsInfo info;
    (void)memset_s(&info, sizeof(info), 0, sizeof(info));
    info.laneId = laneId;
    info.statsType = LANE_T_COMMON_VIDEO;
    FrameSendStats *stats = &info.statsInfo.stream.frameStats;
    ConvertStreamStats(data, stats);
    LnnReportLaneIdStatsInfo(&info, 1); /* only report stream stats */
    return SOFTBUS_OK;
}

int32_t TransRequestQos(int32_t channelId, int32_t chanType, int32_t appType, int32_t quality)
{
    (void)chanType;
    (void)appType;
    uint32_t laneId;
    int32_t ret = TransGetLaneIdByChannelId(channelId, &laneId);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_QOS, "get laneId fail, transRequestQos cannot be processed");
        return SOFTBUS_ERR;
    }
    int32_t result = 0;
    if (quality == QOS_IMPROVE) {
        TRANS_LOGI(TRANS_QOS, "trans requestQos");
        ret = LnnRequestQosOptimization(&laneId, 1, &result, 1);
    } else if (quality == QOS_RECOVER) {
        TRANS_LOGI(TRANS_QOS, "trans cancel Qos");
        LnnCancelQosOptimization(&laneId, 1);
        ret = SOFTBUS_OK;
    } else {
        TRANS_LOGE(TRANS_QOS, "requestQos invalid. quality=%{public}d", quality);
        ret = SOFTBUS_ERR;
    }

    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_QOS, "request Qos fail, quality=%{public}d, ret=%{public}d", quality, ret);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t TransRippleStats(int32_t channelId, int32_t channelType, const TrafficStats *data)
{
    (void)channelType;
    if (data == NULL) {
        TRANS_LOGE(TRANS_CTRL, "rippleStats data is null");
        return SOFTBUS_INVALID_PARAM;
    }
    uint32_t laneId;
    int32_t ret = TransGetLaneIdByChannelId(channelId, &laneId);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get laneId fail, streamStatsInfo cannot be processed");
        return SOFTBUS_ERR;
    }
    TRANS_LOGI(TRANS_CTRL, "transRippleStats channelId=%{public}d, laneId=0x%{public}x", channelId, laneId);
    LnnRippleData rptdata;
    (void)memset_s(&rptdata, sizeof(rptdata), 0, sizeof(rptdata));
    if (memcpy_s(&rptdata.stats, sizeof(rptdata.stats), data->stats, sizeof(data->stats)) != EOK) {
        TRANS_LOGE(TRANS_CTRL, "memcpy fail");
        return SOFTBUS_ERR;
    }
    LnnReportRippleData(laneId, &rptdata);
    return SOFTBUS_OK;
}

int32_t TransNotifyAuthSuccess(int32_t channelId, int32_t channelType)
{
    int32_t ret = SOFTBUS_ERR;
    ConnectOption connOpt;
    switch (channelType) {
        case CHANNEL_TYPE_AUTH:
            ret = TransAuthGetConnOptionByChanId(channelId, &connOpt);
            break;
        case CHANNEL_TYPE_PROXY:
            ret = TransProxyGetConnOptionByChanId(channelId, &connOpt);
            break;
        default:
            ret = SOFTBUS_ERR;
            TRANS_LOGE(TRANS_CTRL, "invalid. channelId=%{public}d, channelType=%{public}d.", channelId, channelType);
    }
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL,
            "notfiy auth success. channelId=%{public}d, channelType=%{public}d, ret=%{public}d",
            channelId, channelType, ret);
        return ret;
    }
    return TransNotifyAuthDataSuccess(channelId, &connOpt);
}

int32_t TransCloseChannel(int32_t channelId, int32_t channelType)
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
    TransEventExtra extra = {
        .socketName = NULL,
        .peerNetworkId = NULL,
        .calleePkg = NULL,
        .callerPkg = NULL,
        .channelId = channelId,
        .channelType = channelType,
        .errcode = ret,
        .result = (ret == SOFTBUS_OK) ? EVENT_STAGE_RESULT_OK : EVENT_STAGE_RESULT_FAILED
    };
    TRANS_EVENT(EVENT_SCENE_CLOSE_CHANNEL_ACTIVE, EVENT_STAGE_CLOSE_CHANNEL, extra);
    return ret;
}

int32_t TransSendMsg(int32_t channelId, int32_t channelType, const void *data, uint32_t len,
    int32_t msgType)
{
    TRANS_LOGI(TRANS_MSG, "send msg: channelId=%{public}d, channelType=%{public}d", channelId, channelType);
    int32_t ret = SOFTBUS_OK;
    switch (channelType) {
        case CHANNEL_TYPE_AUTH:
            ret = TransSendAuthMsg(channelId, (char*)data, (int32_t)len);
            break;
        case CHANNEL_TYPE_PROXY:
            ret = TransProxyPostSessionData(channelId, (unsigned char*)data, len, (SessionPktType)msgType);
            break;
        default:
            TRANS_LOGE(TRANS_MSG,
                "send msg invalid channelType. channelId=%{public}d, channelType=%{public}d", channelId, channelType);
            ret = SOFTBUS_TRANS_CHANNEL_TYPE_INVALID;
            break;
    }
    return ret;
}

void TransChannelDeathCallback(const char *pkgName, int32_t pid)
{
    TransProxyDeathCallback(pkgName, pid);
    TransTdcDeathCallback(pkgName, pid);
    TransLaneMgrDeathCallback(pkgName, pid);
    TransUdpDeathCallback(pkgName, pid);
}

int32_t TransGetNameByChanId(const TransInfo *info, char *pkgName, char *sessionName,
    uint16_t pkgLen, uint16_t sessionNameLen)
{
    if (info == NULL || pkgName == NULL || sessionName == NULL) {
        TRANS_LOGE(TRANS_CTRL, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    switch ((ChannelType)info->channelType) {
        case CHANNEL_TYPE_PROXY:
            return TransProxyGetNameByChanId(info->channelId, pkgName, sessionName, pkgLen, sessionNameLen);
        case CHANNEL_TYPE_UDP:
            return TransUdpGetNameByChanId(info->channelId, pkgName, sessionName, pkgLen, sessionNameLen);
        case CHANNEL_TYPE_AUTH:
            return TransAuthGetNameByChanId(info->channelId, pkgName, sessionName, pkgLen, sessionNameLen);
        default:
            return SOFTBUS_INVALID_PARAM;
    }
}

int32_t TransGetAppInfoByChanId(int32_t channelId, int32_t channelType, AppInfo* appInfo)
{
    if (appInfo == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    switch ((ChannelType)channelType) {
        case CHANNEL_TYPE_TCP_DIRECT:
            return TcpTranGetAppInfobyChannelId(channelId, appInfo);
        case CHANNEL_TYPE_PROXY:
            return TransProxyGetAppInfoByChanId(channelId, appInfo);
        case CHANNEL_TYPE_UDP:
            return TransGetUdpAppInfoByChannelId(channelId, appInfo);
        case CHANNEL_TYPE_AUTH:
            return TransAuthGetAppInfoByChanId(channelId, appInfo);
        default:
            return SOFTBUS_INVALID_PARAM;
    }
}

int32_t TransGetConnByChanId(int32_t channelId, int32_t channelType, int32_t* connId)
{
    int32_t ret;

    switch (channelType) {
        case CHANNEL_TYPE_PROXY:
            ret = TransProxyGetConnIdByChanId(channelId, connId);
            break;
        case CHANNEL_TYPE_AUTH:
            ret = TransAuthGetConnIdByChanId(channelId, connId);
            break;
        default:
            TRANS_LOGE(TRANS_CTRL, "channelType=%{public}d error", channelType);
            ret = SOFTBUS_ERR;
    }
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_MSG, "get connId failed, channelId=%{public}d, channelType=%{public}d",
            channelId, channelType);
    }

    return ret;
}