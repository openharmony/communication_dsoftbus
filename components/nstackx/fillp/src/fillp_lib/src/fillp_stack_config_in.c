/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include "fillp_stack_config_in.h"


/**********************************************************************************
  Function      : FtSetConfigStack
  Description   : Api is used to set Individual FILLP stack configuration
              item.
  Calls         :
  Called By     :
  Input         : FILLP_UINT32    name : Name of the config item to configure
                      (FILLP_CONFIG_LIST_ENUM)
            void *value  : This will contain the value for the config item.

            void *param  : this is optional. only required for config items
            which requires additional information to configure.
                for ex:
                For SOCKET option this will store the Socket index.
  Output        :
  Return        : FILLP_UINT32 SUCCESS/FAILURE
  Others        :
******************************************************************************************/
FILLP_INT32 FtConfigSetRxBurst(IN FILLP_CONST void *value)
{
    FILLP_UINT16 configValue = *(FILLP_UINT16 *)value;
    if ((configValue == 0)
        || (configValue > FILLP_MAX_TX_RX_BURST)) {
        FILLP_LOGERR(" rxBurst %u is invalid parameter!!!", configValue);

        return ERR_FAILURE;
    }

    g_resource.udp.rxBurst = configValue;

    return FILLP_SUCCESS;
}


FILLP_INT32 FtConfigSetRecvCachePktNumBufferSize(IN FILLP_CONST void *value)
{
    FILLP_UINT32 configValue = *(FILLP_UINT32 *)value;
    if ((configValue == 0) || (configValue > FILLP_MAX_STACK_RECV_CACHE_PKT_NUM_BUFF_SIZE)) {
        FILLP_LOGERR(" recvCachePktNumBufferSize %u is invalid parameter!!!", configValue);
        return ERR_FAILURE;
    }

    g_resource.common.recvCachePktNumBufferSize = configValue;


    return FILLP_SUCCESS;
}


FILLP_INT32 FtConfigSetOutOfOrderCacheFeature(IN FILLP_CONST void *value)
{
    FILLP_BOOL val = *(FILLP_BOOL *)value;
    if ((val != FILLP_TRUE) && (val != FILLP_FALSE)) {
        FILLP_LOGERR(" outOfOrderCacheFeature %u is invalid parameter!!!", val);
        return ERR_FAILURE;
    }
    g_resource.common.outOfOrderCacheEnable = val;

    return FILLP_SUCCESS;
}

FILLP_INT32 FtConfigSetCpuCoreUse(IN FILLP_CONST void *value)
{
    FILLP_UINT8 val;
    if ((g_spunge != FILLP_NULL_PTR) && (g_spunge->hasInited == FILLP_TRUE)) {
        FILLP_LOGERR("Cannot Set cpuCoreUse after stack initialization!!!");
        return ERR_FAILURE;
    }
    val = *(FILLP_UINT8 *)value;
    g_resource.common.cpuCoreUse = val;

    return FILLP_SUCCESS;
}

FILLP_INT32 FtConfigSetMaxSockNum(IN FILLP_CONST void *value)
{
    FILLP_UINT16 configValue;

    if ((g_spunge != FILLP_NULL_PTR) && (g_spunge->hasInited == FILLP_TRUE)) {
        FILLP_LOGERR("Cannot Set maxSockNum after stack initialization!!!");
        return ERR_FAILURE;
    }
    configValue = *(FILLP_UINT16 *)value;

    if ((configValue == 0) || (configValue > FILLP_MAX_SOCK_NUMBER)) {
        FILLP_LOGERR("maxSockNum %u is invalid parameter!!!", configValue);

        return ERR_FAILURE;
    }

    g_resource.common.maxSockNum = configValue;

    return FILLP_SUCCESS;
}


FILLP_INT32 FtConfigSetMaxConnectionNum(IN FILLP_CONST void *value)
{
    FILLP_UINT16 configValue;

    if ((g_spunge != FILLP_NULL_PTR) && (g_spunge->hasInited == FILLP_TRUE)) {
        FILLP_LOGERR("Cannot Set value after stack initialization!!!");
        return ERR_FAILURE;
    }

    configValue = *(FILLP_UINT16 *)value;
    if ((configValue == 0)
        || (configValue > FILLP_MAX_CONN_NUMBER)) {
        FILLP_LOGERR("maxConnectionNum %u is invalid parameter!!!", configValue);

        return ERR_FAILURE;
    }

    g_resource.common.maxConnNum = configValue;

    return FILLP_SUCCESS;
}

FILLP_INT32 FtConfigSetFullCpu(IN FILLP_CONST void *value)
{
    FILLP_BOOL val = *(FILLP_BOOL *)value;
    if ((val != FILLP_TRUE) && (val != FILLP_FALSE)) {
        FILLP_LOGERR(" fullCpu %u is invalid parameter!!!", val);
        return ERR_FAILURE;
    }

    g_resource.common.fullCpuEnable = val;

    return FILLP_SUCCESS;
}

FILLP_INT32 FtConfigSetFullCpuUseThresholdRate(IN FILLP_CONST void *value)
{
    FILLP_UINT32 configValue = *(FILLP_UINT32 *)value;

    if ((FILLP_NULL != configValue) && (configValue <= FILLP_MAX_STACK_RATE)) {
        g_resource.fullCpuUseThresholdRate = configValue;
    } else {
        FILLP_LOGERR(" fullCpuUseThresholdRate %u is invalid parameter!!!", configValue);
        return ERR_FAILURE;
    }

    return FILLP_SUCCESS;
}

FILLP_INT32 FtConfigSetOppositeSetPercentage(IN FILLP_CONST void *value)
{
    FILLP_UINT16 configValue = *(FILLP_UINT16 *)value;
    if ((configValue > FILLP_NULL) && (configValue <= FILLP_MAX_STACK_OPPOSITE_SET_PERCENTAGE)) {
        g_resource.flowControl.oppositeSetPercentage = configValue;
    } else {
        FILLP_LOGERR("oppositeSetPercentage %u is invalid parameter!!!", configValue);
        return ERR_FAILURE;
    }

    return FILLP_SUCCESS;
}

FILLP_INT32 FtConfigSetNackRepeatTimes(IN FILLP_CONST void *value)
{
    FILLP_UINT16 configValue = *(FILLP_UINT16 *)value;
    if ((configValue > FILLP_NULL) && (configValue <= FILLP_MAX_STACK_NACK_REPEAT_TIMES)) {
        g_resource.flowControl.nackRepeatTimes = configValue;
    } else {
        FILLP_LOGERR("nackRepeatTimes %u is invalid parameter!!!", configValue);
        return ERR_FAILURE;
    }

    return FILLP_SUCCESS;
}

FILLP_INT32 FtConfigSetAlg(IN FILLP_CONST void *value)
{
    FILLP_UINT8 val = *(FILLP_UINT8 *)value;
    if ((val == FILLP_ALG_ONE) || (val == FILLP_ALG_TWO) || (val == FILLP_ALG_THREE) ||
        (val == FILLP_ALG_MSG) || (val == FILLP_ALG_BASE)) {
        g_resource.flowControl.fcAlg = val;
    } else {
        FILLP_LOGERR("alg %u is invalid parameter!!!", val);
        return ERR_FAILURE;
    }

    return FILLP_SUCCESS;
}

FILLP_INT32 FtConfigSetPktLossAllow(IN FILLP_CONST void *value)
{
    FILLP_UINT16 configValue = *(FILLP_UINT16 *)value;
    if ((configValue > FILLP_NULL) && (configValue < FILLP_MAX_STACK_PACKET_LOSS_ALLOWED)) {
        g_resource.flowControl.pktLossAllow = configValue;
    } else {
        FILLP_LOGERR("pktLossAllow %u is invalid parameter!!!", configValue);
        return ERR_FAILURE;
    }

    return FILLP_SUCCESS;
}


FILLP_INT32 FtConfigSetInitialRate(IN FILLP_CONST void *value)
{
    FILLP_UINT32 configValue = *(FILLP_UINT32 *)value;

    if ((configValue > FILLP_NULL)
        && (configValue <= g_resource.flowControl.maxRate)
        && (configValue <= g_resource.flowControl.maxRecvRate)) {
        g_resource.flowControl.initialRate = configValue;
    } else {
        FILLP_LOGERR("initialRate %u is invalid parameter!!! ", configValue);
        return ERR_FAILURE;
    }

    return FILLP_SUCCESS;
}


FILLP_INT32 FtConfigSetMaxRatePercentage(IN FILLP_CONST void *value)
{
    FILLP_UINT16 configValue = *(FILLP_UINT16 *)value;

    if ((configValue > FILLP_NULL) && (configValue <= FILLP_MAX_STACK_RATE_PERCENTAGE)) {
        g_resource.flowControl.maxRatePercentage = configValue;
    } else {
        FILLP_LOGERR("maxRatePercentage %u is invalid parameter!!!", configValue);
        return ERR_FAILURE;
    }

    return FILLP_SUCCESS;
}


FILLP_INT32 FtConfigSetSupportFairness(IN FILLP_CONST void *value)
{
    FILLP_UINT8 val = *(FILLP_UINT8 *)value;
    if (val < FILLP_FAIRNESS_TYPE_END) {
        g_resource.flowControl.supportFairness = val;
    } else {
        FILLP_LOGERR("supportFairness %u is invalid parameter!!!", val);
        return ERR_FAILURE;
    }

    return FILLP_SUCCESS;
}

FILLP_INT32 FtConfigSetMaxRate(IN FILLP_CONST void *value)
{
    if ((*(FILLP_UINT32 *)value != FILLP_NULL) && (*(FILLP_UINT32 *)value <= FILLP_MAX_STACK_RATE) &&
        (*(FILLP_UINT32 *)value >= g_resource.flowControl.initialRate)) {
        g_resource.flowControl.maxRate = *(FILLP_UINT32 *)value;
    } else {
        FILLP_LOGERR("maxRate:%u is invalid parameter!!!", *(FILLP_UINT32 *)value);
        return ERR_FAILURE;
    }

    return FILLP_SUCCESS;
}

FILLP_INT32 FtConfigSetLimitRate(IN FILLP_CONST void *value)
{
    if (*(FILLP_UINT32 *)value <= FILLP_MAX_STACK_RATE) {
        g_resource.flowControl.limitRate = *(FILLP_UINT32 *)value;
        FILLP_LOGINF("limitRate:%u", g_resource.flowControl.limitRate);
    } else {
        FILLP_LOGERR("limitRate:%u is invalid parameter!!!", *(FILLP_UINT32 *)value);
        return ERR_FAILURE;
    }
    return FILLP_SUCCESS;
}

FILLP_INT32 FtConfigSetMaxRecvRate(IN FILLP_CONST void *value)
{
    if ((*(FILLP_UINT32 *)value != FILLP_NULL) && (*(FILLP_UINT32 *)value <= FILLP_MAX_STACK_RECV_RATE) &&
        (*(FILLP_UINT32 *)value >= g_resource.flowControl.initialRate)) {
        g_resource.flowControl.maxRecvRate = *(FILLP_UINT32 *)value;
    } else {
        FILLP_LOGERR("maxRecvRate:%u is invalid parameter!!!", *(FILLP_UINT32 *)value);
        return ERR_FAILURE;
    }

    return FILLP_SUCCESS;
}

FILLP_INT32 FtConfigSetSendCache(IN FILLP_CONST void *value)
{
    FILLP_UINT32 configValue = *(FILLP_UINT32 *)value;
    if ((configValue == FILLP_NULL) || (configValue > FILLP_MAX_ALLOW_SEND_RECV_CACHE)) {
        FILLP_LOGERR("sendCache  invalid parameter!! %u", configValue);
        return ERR_FAILURE;
    }

    g_resource.common.sendCache = configValue;
    FILLP_LOGINF("stack sendCache:%u", configValue);
    return FILLP_SUCCESS;
}

FILLP_INT32 FtConfigSetRecvCache(IN FILLP_CONST void *value)
{
    FILLP_UINT32 configValue = *(FILLP_UINT32 *)value;
    if ((configValue == FILLP_NULL) || (configValue > FILLP_MAX_ALLOW_SEND_RECV_CACHE)) {
        FILLP_LOGERR("recvCache  invalid parameter!!! %u", configValue);
        return ERR_FAILURE;
    }

    g_resource.common.recvCache = configValue;
    FILLP_LOGINF("stack recvCache:%u", configValue);
    return FILLP_SUCCESS;
}

static FILLP_INT32 FtValidateConfigParamsInner(IN FILLP_CONST FillpGlobalConfigsSt *resource)
{
    if ((resource->flowControl.oppositeSetPercentage == 0) ||
        (resource->flowControl.oppositeSetPercentage > FILLP_MAX_STACK_OPPOSITE_SET_PERCENTAGE)) {
        FILLP_LOGERR("oppositeSetPercentage %u is invalid parameter!!!",
                     resource->flowControl.oppositeSetPercentage);
        return ERR_FAILURE;
    }

    if ((resource->flowControl.nackRepeatTimes == 0) ||
        (resource->flowControl.nackRepeatTimes > FILLP_MAX_STACK_NACK_REPEAT_TIMES)) {
        FILLP_LOGERR("nackRepeatTimes %u is invalid parameter!!!", resource->flowControl.nackRepeatTimes);
        return ERR_FAILURE;
    }

    if ((resource->flowControl.pktLossAllow == 0) ||
        (resource->flowControl.pktLossAllow >= FILLP_MAX_STACK_PACKET_LOSS_ALLOWED)) {
        FILLP_LOGERR("pktLossAllow %u is invalid parameter!!!", resource->flowControl.pktLossAllow);
        return ERR_FAILURE;
    }

    return ERR_OK;
}

static FILLP_INT32 FtValidateUdpConfigParamsInner(IN FILLP_CONST FillpGlobalConfigsSt *resource)
{
    if ((resource->udp.rxBurst == 0) || (resource->udp.rxBurst > FILLP_MAX_TX_RX_BURST)) {
        FILLP_LOGERR("rxBurst %u is invalid parameter!!!", resource->udp.rxBurst);
        return ERR_FAILURE;
    }

    return ERR_OK;
}

static FILLP_INT32 FtValidateCommonConfigParamsInner(IN FILLP_CONST FillpGlobalConfigsSt *resource)
{
    if ((resource->common.maxSockNum == 0) ||
        (resource->common.maxSockNum > FILLP_MAX_SOCK_NUMBER)) {
        FILLP_LOGERR("maxSockNum %u is invalid parameter!!!", resource->common.maxSockNum);
        return ERR_FAILURE;
    }

    if ((resource->common.maxConnectionNum == 0) ||
        (resource->common.maxConnectionNum > FILLP_MAX_CONN_NUMBER)) {
        FILLP_LOGERR("maxConnectionNum is invalid parameter maxConnectionNum = %u, maxSockNum = %u!!!",
                     resource->common.maxConnectionNum, resource->common.maxSockNum);
        return ERR_FAILURE;
    }

    if ((resource->common.fullCpu != FILLP_FALSE) && (resource->common.fullCpu != FILLP_TRUE)) {
        FILLP_LOGERR("fullCpu %u is invalid parameter!!!", resource->common.fullCpu);
        return ERR_FAILURE;
    }

    if ((resource->common.recvCachePktNumBufferSize == 0) ||
        (resource->common.recvCachePktNumBufferSize > FILLP_MAX_STACK_RECV_CACHE_PKT_NUM_BUFF_SIZE)) {
        FILLP_LOGERR("recvCachePktNumBufferSize %u is invalid parameter!!!",
                     resource->common.recvCachePktNumBufferSize);
        return (ERR_FAILURE);
    }

    if ((resource->common.outOfOrderCacheFeature != FILLP_TRUE) &&
        (resource->common.outOfOrderCacheFeature != FILLP_FALSE)) {
        FILLP_LOGERR("outOfOrderCacheFeature %u is invalid parameter!!!",
                     resource->common.outOfOrderCacheFeature);
        return ERR_FAILURE;
    }

    return ERR_OK;
}

static FILLP_INT32 FtValidateTimersConfigParamsInner(IN FILLP_CONST FillpGlobalConfigsSt *resource)
{
    if ((resource->timers.recvCachePktNumBufferTimeout < FILLP_MIN_TIMER_RECV_CACHE_PKT_NUMBUFF) ||
        (resource->timers.recvCachePktNumBufferTimeout > FILLP_MAX_TIMER_RECV_CACHE_PKT_NUMBUFF)) {
        FILLP_LOGERR("recvCachePktNumBufferTimeout %u is invalid parameter!!!",
                     resource->timers.recvCachePktNumBufferTimeout);
        return (ERR_FAILURE);
    }

    return ERR_OK;
}

static FILLP_INT32 FtValidateFlowcontorMaxRateMaxRecvRate(IN FILLP_CONST FillpGlobalConfigsSt *resource)
{
    if ((resource->flowControl.maxRate > FILLP_MAX_STACK_RATE) ||
        (resource->flowControl.maxRate == FILLP_NULL)) {
        FILLP_LOGERR("maxRate %u is invalid parameter!!!", resource->flowControl.maxRate);
        return ERR_FAILURE;
    }

    if ((resource->flowControl.maxRecvRate > FILLP_MAX_STACK_RECV_RATE) ||
        (resource->flowControl.maxRecvRate == FILLP_NULL)) {
        FILLP_LOGERR("maxRecvRate %u is invalid parameter!!!", resource->flowControl.maxRecvRate);
        return ERR_FAILURE;
    }

    return ERR_OK;
}

static FILLP_INT32 FtValidateFlowcontorRateConfigParamsInner(IN FILLP_CONST FillpGlobalConfigsSt *resource)
{
    if ((resource->flowControl.initialRate == 0) ||
        (resource->flowControl.initialRate > resource->flowControl.maxRate) ||
        (resource->flowControl.initialRate > resource->flowControl.maxRecvRate)) {
        FILLP_LOGERR("initialRate %u is invalid parameter!!!", resource->flowControl.initialRate);
        return ERR_FAILURE;
    }


    if ((resource->flowControl.maxRatePercentage == 0) ||
        (resource->flowControl.maxRatePercentage > FILLP_MAX_STACK_RATE_PERCENTAGE)) {
        FILLP_LOGERR("maxRatePercentage %u is invalid parameter!!!", resource->flowControl.maxRatePercentage);
        return ERR_FAILURE;
    }

    return FtValidateFlowcontorMaxRateMaxRecvRate(resource);
}

static FILLP_INT32 FtValidateFlowcontorFairnessConfigParamsInner(IN FILLP_CONST FillpGlobalConfigsSt *resource)
{
    if (resource->flowControl.supportFairness >= FILLP_FAIRNESS_TYPE_END) {
        FILLP_LOGERR("supportFairness %u is invalid parameter!!!", resource->flowControl.supportFairness);
        return ERR_FAILURE;
    }

    return ERR_OK;
}

/*******************************************************************
  Function      : FtValidateConfigParams
  Description   : function to validate the Config parameter of FillpGlobalConfigsSt structure.
  Calls         :
  Called By     :
  Input         : resource : structure of type FillpGlobalConfigsSt
  Output        :
  Return        : ERR_OK on SUCCESS/ Error code on FAILURE
  Others        :
********************************************************************/
FILLP_INT32 FtValidateConfigParams(IN FILLP_CONST FillpGlobalConfigsSt *resource)
{
    FILLP_INT32 ret;

    ret = FtValidateUdpConfigParamsInner(resource);
    if (ret != ERR_OK) {
        return ret;
    }

    ret = FtValidateCommonConfigParamsInner(resource);
    if (ret != ERR_OK) {
        return ret;
    }

    ret = FtValidateTimersConfigParamsInner(resource);
    if (ret != ERR_OK) {
        return ret;
    }

    ret = FtValidateFlowcontorRateConfigParamsInner(resource);
    if (ret != ERR_OK) {
        return ret;
    }

    ret = FtValidateConfigParamsInner(resource);
    if (ret != ERR_OK) {
        return ret;
    }

    return FtValidateFlowcontorFairnessConfigParamsInner(resource);
}

