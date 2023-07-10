/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "bus_center_manager.h"
#include "lnn_lane_qos.h"
#include "session.h"
#include "softbus_adapter_mem.h"
#include "softbus_conn_interface.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_hisysevt_transreporter.h"
#include "softbus_log.h"
#include "softbus_proxychannel_manager.h"
#include "softbus_proxychannel_session.h"
#include "softbus_qos.h"
#include "softbus_utils.h"
#include "trans_auth_manager.h"
#include "trans_channel_callback.h"
#include "trans_lane_manager.h"
#include "trans_lane_pending_ctl.h"
#include "trans_link_listener.h"
#include "trans_session_manager.h"
#include "trans_tcp_direct_manager.h"
#include "trans_udp_channel_manager.h"
#include "trans_udp_negotiation.h"
#include "trans_tcp_direct_sessionconn.h"
#include "lnn_network_manager.h"

#define MIGRATE_ENABLE 2
#define MIGRATE_SUPPORTED 1
#define MAX_PROXY_CHANNEL_ID 0x00008000
#define MAX_TDC_CHANNEL_ID 0x7FFFFFFF
#define MAX_FD_ID 1025

static int32_t g_allocProxyChannelId = MAX_FD_ID;
static int32_t g_allocTdcChannelId = MAX_PROXY_CHANNEL_ID;
static SoftBusMutex g_myIdLock;

static int32_t GenerateTdcChannelId()
{
    int32_t channelId;
    if (SoftBusMutexLock(&g_myIdLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock mutex fail!");
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
    int32_t channelId;
    if (SoftBusMutexLock(&g_myIdLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock mutex fail!");
        return SOFTBUS_ERR;
    }
    channelId = g_allocProxyChannelId++;
    if (g_allocProxyChannelId >= MAX_PROXY_CHANNEL_ID) {
        g_allocProxyChannelId = MAX_FD_ID;
    }
    SoftBusMutexUnlock(&g_myIdLock);
    return channelId;
}

int32_t GenerateChannelId(bool isTdcChannel)
{
    return isTdcChannel ? GenerateTdcChannelId() : GenerateProxyChannelId();
}

int32_t TransChannelInit(void)
{
    IServerChannelCallBack *cb = TransServerGetChannelCb();
    if (cb == NULL) {
        return SOFTBUS_ERR;
    }

    if (TransLaneMgrInit() != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "trans lane manager init failed.");
        return SOFTBUS_ERR;
    }

    if (TransAuthInit(cb) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }

    if (TransProxyManagerInit(cb) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }

    if (TransTcpDirectInit(cb) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }

    if (TransUdpChannelInit(cb) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }

    if (TransReqLanePendingInit() != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }

    ReqLinkListener();

    if (SoftBusMutexInit(&g_myIdLock, NULL) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "init lock failed");
        return SOFTBUS_ERR;
    }

    return SOFTBUS_OK;
}

NO_SANITIZE("cfi") void TransChannelDeinit(void)
{
    TransLaneMgrDeinit();
    TransAuthDeinit();
    TransProxyManagerDeinit();
    TransTcpDirectDeinit();
    TransUdpChannelDeinit();
    TransReqLanePendingDeinit();
    SoftBusMutexDestroy(&g_myIdLock);
}

static int32_t TransGetRemoteInfo(const SessionParam* param, AppInfo* appInfo)
{
    if (param == NULL || appInfo == NULL) {
        return SOFTBUS_ERR;
    }
    if (LnnGetRemoteStrInfo(param->peerDeviceId, STRING_KEY_UUID,
        appInfo->peerData.deviceId, sizeof(appInfo->peerData.deviceId)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "direct get remote node uuid err");
        char peerNetworkId[NETWORK_ID_BUF_LEN];
        (void)memset_s(peerNetworkId, NETWORK_ID_BUF_LEN, 0, NETWORK_ID_BUF_LEN);
        if (LnnGetNetworkIdByUuid(param->peerDeviceId, peerNetworkId, NETWORK_ID_BUF_LEN) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get remote node networkId err by uuid");
        } else {
            if (strcpy_s(appInfo->peerData.deviceId, sizeof(appInfo->peerData.deviceId), param->peerDeviceId) != SOFTBUS_OK) {
                return SOFTBUS_ERR;
            }
            if (strcpy_s((char *)param->peerDeviceId, sizeof(peerNetworkId), peerNetworkId) != SOFTBUS_OK) {
                return SOFTBUS_ERR;
            }
            return SOFTBUS_OK;
        }
        if (LnnGetNetworkIdByUdid(param->peerDeviceId, peerNetworkId, NETWORK_ID_BUF_LEN) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get remote node networkId err by udid");
            return SOFTBUS_ERR;
        }
        if (strcpy_s((char *)param->peerDeviceId, sizeof(peerNetworkId), peerNetworkId) != SOFTBUS_OK) {
            return SOFTBUS_ERR;
        }
        if (LnnGetRemoteStrInfo(param->peerDeviceId, STRING_KEY_UUID,
            appInfo->peerData.deviceId, sizeof(appInfo->peerData.deviceId)) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get remote node uuid err");
            return SOFTBUS_ERR;
        }
    }
    return SOFTBUS_OK;
}

static int32_t CopyAppInfoFromSessionParam(AppInfo* appInfo, const SessionParam* param)
{
    if (param->attr->fastTransData != NULL && param->attr->fastTransDataSize > 0 &&
        param->attr->fastTransDataSize <= MAX_FAST_DATA_LEN) {
        if (appInfo->businessType == BUSINESS_TYPE_FILE || appInfo->businessType == BUSINESS_TYPE_STREAM) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "not support send fast data");
            return SOFTBUS_ERR;
        }
        appInfo->fastTransData = (uint8_t*)SoftBusCalloc(param->attr->fastTransDataSize);
        if (appInfo->fastTransData == NULL) {
            return SOFTBUS_ERR;
        }
        if (memcpy_s((char *)appInfo->fastTransData, param->attr->fastTransDataSize,
            (const char *)param->attr->fastTransData, param->attr->fastTransDataSize) != EOK) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "memcpy_s err");
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
    if (TransGetRemoteInfo(param, appInfo) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get remote node info err");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static AppInfo *GetAppInfo(const SessionParam *param)
{
    char *anoyDevId = NULL;
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "GetAppInfo, deviceId=%s",
        ToSecureStrDeviceID(param->peerDeviceId, &anoyDevId));
    SoftBusFree(anoyDevId);
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

    appInfo->peerData.apiVersion = API_V2;
    appInfo->encrypt = APP_INFO_FILE_FEATURES_SUPPORT;
    appInfo->algorithm = APP_INFO_ALGORITHM_AES_GCM_256;
    appInfo->crc = APP_INFO_FILE_FEATURES_SUPPORT;
    appInfo->autoCloseTime = 0;
    appInfo->myHandleId = -1;
    appInfo->peerHandleId = -1;

    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "GetAppInfo ok");
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

static ChannelType TransGetChannelType(const SessionParam *param, const LaneConnInfo *connInfo)
{
    LaneTransType transType = TransGetLaneTransTypeBySession(param);
    if (transType == LANE_T_BUTT) {
        return CHANNEL_TYPE_BUTT;
    }

    if (connInfo->type == LANE_BR || connInfo->type == LANE_BLE || connInfo->type == LANE_BLE_DIRECT ||
        connInfo->type == LANE_COC || connInfo->type == LANE_COC_DIRECT) {
        return CHANNEL_TYPE_PROXY;
    } else if (transType == LANE_T_FILE || transType == LANE_T_COMMON_VIDEO || transType == LANE_T_COMMON_VOICE ||
        transType == LANE_T_RAW_STREAM) {
        return CHANNEL_TYPE_UDP;
    } else if ((transType == LANE_T_MSG) && (connInfo->type != LANE_P2P) && (connInfo->type != LANE_P2P_REUSE)) {
        return CHANNEL_TYPE_PROXY;
    }
    return CHANNEL_TYPE_TCP_DIRECT;
}

static int32_t TransOpenChannelProc(ChannelType type, AppInfo *appInfo, const ConnectOption *connOpt,
    int32_t *channelId)
{
    if (type == CHANNEL_TYPE_BUTT) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "open invalid channel type.");
        return SOFTBUS_ERR;
    }
    if (type == CHANNEL_TYPE_UDP) {
        if (TransOpenUdpChannel(appInfo, connOpt, channelId) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "open udp channel err");
            return SOFTBUS_ERR;
        }
    } else if (type == CHANNEL_TYPE_PROXY) {
        if (TransProxyOpenProxyChannel(appInfo, connOpt, channelId) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "open proxy channel err");
            return SOFTBUS_ERR;
        }
    } else {
        if (TransOpenDirectChannel(appInfo, connOpt, channelId) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "open direct channel err");
            return SOFTBUS_ERR;
        }
    }
    return SOFTBUS_OK;
}

NO_SANITIZE("cfi") static void FillAppInfo(AppInfo *appInfo, ConnectOption *connOpt, const SessionParam *param,
    TransInfo *transInfo, LaneConnInfo *connInfo)
{
    transInfo->channelType = TransGetChannelType(param, connInfo);
    appInfo->linkType = connInfo->type;
    appInfo->channelType = transInfo->channelType;
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
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "set nip module = %d", connOpt->socketOption.moduleId);
}

NO_SANITIZE("cfi") int32_t TransOpenChannel(const SessionParam *param, TransInfo *transInfo)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "server TransOpenChannel");
    int64_t timeStart = GetSoftbusRecordTimeMillis();
    transInfo->channelId = INVALID_CHANNEL_ID;
    transInfo->channelType = CHANNEL_TYPE_BUTT;
    LaneConnInfo connInfo;
    uint32_t laneId = 0;
    ConnectOption connOpt;
    (void)memset_s(&connOpt, sizeof(ConnectOption), 0, sizeof(ConnectOption));

    AppInfo *appInfo = GetAppInfo(param);
    TRAN_CHECK_AND_RETURN_RET_LOG(!(appInfo == NULL), INVALID_CHANNEL_ID, "GetAppInfo is null.");
    if (TransGetLaneInfo(param, &connInfo, &laneId) != SOFTBUS_OK) {
        SoftbusReportTransErrorEvt(SOFTBUS_TRANS_GET_LANE_INFO_ERR);
        goto EXIT_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO,
        "sessionName[%s], get laneId[%u], link type[%u].", param->sessionName, laneId, connInfo.type);

    if (TransGetConnectOptByConnInfo(&connInfo, &connOpt) != SOFTBUS_OK) {
        SoftbusRecordOpenSessionKpi(appInfo->myData.pkgName, connInfo.type,
            SOFTBUS_EVT_OPEN_SESSION_FAIL, GetSoftbusRecordTimeMillis() - timeStart);
        goto EXIT_ERR;
    }
    FillAppInfo(appInfo, &connOpt, param, transInfo, &connInfo);
    TransOpenChannelSetModule(transInfo->channelType, &connOpt);
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "lane[%u] get channel type[%u].", laneId, transInfo->channelType);
    if (TransOpenChannelProc((ChannelType)transInfo->channelType, appInfo, &connOpt,
        &(transInfo->channelId)) != SOFTBUS_OK) {
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
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "server TransOpenChannel ok: channelId=%d, channelType=%d",
        transInfo->channelId, transInfo->channelType);
    return SOFTBUS_OK;
EXIT_ERR:
    if (appInfo->fastTransData != NULL) {
        SoftBusFree((void*)appInfo->fastTransData);
    }
    SoftBusFree(appInfo);
    if (laneId != 0) {
        LnnFreeLane(laneId);
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "server TransOpenChannel err");
    return INVALID_CHANNEL_ID;
}

static AppInfo *GetAuthAppInfo(const char *mySessionName)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "GetAuthAppInfo");
    AppInfo *appInfo = (AppInfo *)SoftBusCalloc(sizeof(AppInfo));
    if (appInfo == NULL) {
        return NULL;
    }
    appInfo->appType = APP_TYPE_AUTH;
    appInfo->myData.apiVersion = API_V2;
    appInfo->autoCloseTime = 0;
    if (TransGetUidAndPid(mySessionName, &appInfo->myData.uid, &appInfo->myData.pid) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "GetAuthAppInfo GetUidAndPid failed");
        goto EXIT_ERR;
    }
    if (LnnGetLocalStrInfo(STRING_KEY_DEV_UDID, appInfo->myData.deviceId,
        sizeof(appInfo->myData.deviceId)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "GetAuthAppInfo get deviceId failed");
        goto EXIT_ERR;
    }
    if (strcpy_s(appInfo->myData.sessionName, sizeof(appInfo->myData.sessionName), mySessionName) != EOK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "GetAuthAppInfo strcpy_s mySessionName failed");
        goto EXIT_ERR;
    }
    if (strcpy_s(appInfo->peerData.sessionName, sizeof(appInfo->peerData.sessionName), mySessionName) != EOK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "GetAuthAppInfo strcpy_s peerSessionName failed");
        goto EXIT_ERR;
    }
    if (TransGetPkgNameBySessionName(mySessionName, appInfo->myData.pkgName, PKG_NAME_SIZE_MAX) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "GetAuthAppInfo get PkgName failed");
        goto EXIT_ERR;
    }

    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "GetAuthAppInfo ok");
    return appInfo;
EXIT_ERR:
    if (appInfo != NULL) {
        SoftBusFree(appInfo);
    }
    return NULL;
}

NO_SANITIZE("cfi") int32_t TransOpenAuthChannel(const char *sessionName, const ConnectOption *connOpt,
    const char *reqId)
{
    int32_t channelId = INVALID_CHANNEL_ID;
    if (!IsValidString(sessionName, SESSION_NAME_SIZE_MAX) || connOpt == NULL) {
        return channelId;
    }

    if (connOpt->type == CONNECT_TCP) {
        if (TransOpenAuthMsgChannel(sessionName, connOpt, &channelId, reqId) != SOFTBUS_OK) {
            return INVALID_CHANNEL_ID;
        }
    } else if (connOpt->type == CONNECT_BR || connOpt->type == CONNECT_BLE) {
        AppInfo *appInfo = GetAuthAppInfo(sessionName);
        if (appInfo == NULL) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "GetAuthAppInfo failed");
            return INVALID_CHANNEL_ID;
        }
        if (strcpy_s(appInfo->reqId, REQ_ID_SIZE_MAX, reqId) != EOK) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "TransOpenAuthChannel strcpy_s reqId failed");
            return INVALID_CHANNEL_ID;
        }
        if (TransProxyOpenProxyChannel(appInfo, connOpt, &channelId) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "TransOpenAuthChannel proxy channel err");
            SoftBusFree(appInfo);
            return INVALID_CHANNEL_ID;
        }
        SoftBusFree(appInfo);
    }
    return channelId;
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

NO_SANITIZE("cfi") int32_t TransStreamStats(int32_t channelId, int32_t channelType, const StreamSendStats *data)
{
    (void)channelType;
    if (data == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "streamStats data is null");
        return SOFTBUS_INVALID_PARAM;
    }
    uint32_t laneId;
    int32_t ret = TransGetLaneIdByChannelId(channelId, &laneId);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get laneId fail, streamStatsInfo cannot be processed");
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "transStreamStats channelId:%d, laneId:0x%x", channelId, laneId);
    LaneIdStatsInfo info;
    (void)memset_s(&info, sizeof(info), 0, sizeof(info));
    info.laneId = laneId;
    info.statsType = LANE_T_COMMON_VIDEO;
    FrameSendStats *stats = &info.statsInfo.stream.frameStats;
    ConvertStreamStats(data, stats);
    LnnReportLaneIdStatsInfo(&info, 1); /* only report stream stats */
    return SOFTBUS_OK;
}

NO_SANITIZE("cfi") int32_t TransRequestQos(int32_t channelId, int32_t chanType, int32_t appType, int32_t quality)
{
    (void)chanType;
    (void)appType;
    uint32_t laneId;
    int32_t ret = TransGetLaneIdByChannelId(channelId, &laneId);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get laneId fail, transRequestQos cannot be processed");
        return SOFTBUS_ERR;
    }
    int32_t result = 0;
    if (quality == QOS_IMPROVE) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "trans requestQos");
        ret = LnnRequestQosOptimization(&laneId, 1, &result, 1);
    } else if (quality == QOS_RECOVER) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "trans cancel Qos");
        LnnCancelQosOptimization(&laneId, 1);
        ret = SOFTBUS_OK;
    } else {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "requestQos quality[%d] invalid", quality);
        ret = SOFTBUS_ERR;
    }

    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "request Qos fail,type:%d, err:%d", quality, ret);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

NO_SANITIZE("cfi") int32_t TransRippleStats(int32_t channelId, int32_t channelType, const TrafficStats *data)
{
    (void)channelType;
    if (data == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "rippleStats data is null");
        return SOFTBUS_INVALID_PARAM;
    }
    uint32_t laneId;
    int32_t ret = TransGetLaneIdByChannelId(channelId, &laneId);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get laneId fail, streamStatsInfo cannot be processed");
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "transRippleStats channelId:%d, laneId:0x%x", channelId, laneId);
    LnnRippleData rptdata;
    (void)memset_s(&rptdata, sizeof(rptdata), 0, sizeof(rptdata));
    if (memcpy_s(&rptdata.stats, sizeof(rptdata.stats), data->stats, sizeof(data->stats)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "memcpy fail");
        return SOFTBUS_ERR;
    }
    LnnReportRippleData(laneId, &rptdata);
    return SOFTBUS_OK;
}

NO_SANITIZE("cfi") int32_t TransNotifyAuthSuccess(int32_t channelId, int32_t channelType)
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
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "channel=%d, type=%d invalid.", channelId, channelType);
    }
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR,
            "channel=%d, type=%d,notfiy auth success error=%d.", channelId, channelType, ret);
        return ret;
    }
    return TransNotifyAuthDataSuccess(channelId, &connOpt);
}

NO_SANITIZE("cfi") int32_t TransCloseChannel(int32_t channelId, int32_t channelType)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "close channel: id=%d, type=%d", channelId, channelType);
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
    return ret;
}

NO_SANITIZE("cfi") int32_t TransSendMsg(int32_t channelId, int32_t channelType, const void *data, uint32_t len,
    int32_t msgType)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "send msg: id=%d, type=%d", channelId, channelType);
    int32_t ret = SOFTBUS_OK;
    switch (channelType) {
        case CHANNEL_TYPE_AUTH:
            ret = TransSendAuthMsg(channelId, (char*)data, (int32_t)len);
            break;
        case CHANNEL_TYPE_PROXY:
            ret = TransProxyPostSessionData(channelId, (unsigned char*)data, len, (SessionPktType)msgType);
            break;
        default:
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "send msg: id=%d invalid type=%d", channelId, channelType);
            ret = SOFTBUS_TRANS_CHANNEL_TYPE_INVALID;
            break;
    }
    return ret;
}

NO_SANITIZE("cfi") void TransChannelDeathCallback(const char *pkgName, int32_t pid)
{
    TransProxyDeathCallback(pkgName, pid);
    TransTdcDeathCallback(pkgName, pid);
    TransLaneMgrDeathCallback(pkgName, pid);
    TransUdpDeathCallback(pkgName, pid);
}

NO_SANITIZE("cfi") int32_t TransGetNameByChanId(const TransInfo *info, char *pkgName, char *sessionName,
    uint16_t pkgLen, uint16_t sessionNameLen)
{
    if (info == NULL || pkgName == NULL || sessionName == NULL) {
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

NO_SANITIZE("cfi") int32_t TransGetAppInfoByChanId(int32_t channelId, int32_t channelType, AppInfo* appInfo)
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

NO_SANITIZE("cfi") int32_t TransGetConnByChanId(int32_t channelId, int32_t channelType, int32_t* connId)
{
    if (channelType != CHANNEL_TYPE_PROXY) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "channelType:%d error", channelType);
        return SOFTBUS_ERR;
    }
    if (TransProxyGetConnIdByChanId(channelId, connId) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get proxy connId, channelId: %d", channelId);
        return SOFTBUS_TRANS_PROXY_SEND_CHANNELID_INVALID;
    }
    return SOFTBUS_OK;
}