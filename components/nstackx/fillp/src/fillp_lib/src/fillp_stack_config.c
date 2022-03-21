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

#include "fillp_stack_config.h"
#include "fillp_stack_app_config_in.h"
#include "fillp_stack_config_in.h"
#include "res.h"
#include "spunge.h"

#ifdef __cplusplus
extern "C" {
#endif

static FILLP_INT FtSetCopyPreinitConfigs(IN FILLP_CONST FillpGlobalPreinitExtConfigsSt *globalPreinitConfig)
{
    if ((g_spunge != FILLP_NULL_PTR) && (g_spunge->hasInited == FILLP_TRUE)) {
        FILLP_LOGERR("Cannot Set value after stack initialization!!!");
        return ERR_FAILURE;
    }

    g_resource.pktLossThresHoldMax = globalPreinitConfig->pktLossThresHoldMax;
    g_resource.timingWheelAccuracy = globalPreinitConfig->timingWheelAccuracy;
    g_resource.maximalAckNumLimit = globalPreinitConfig->maximalAckNumLimit;
    g_resource.sendOneAckNum = globalPreinitConfig->sendOneAckNum;
    g_resource.cpuPauseTime = globalPreinitConfig->cpuPauseTime;
    g_resource.retransmitCmpTime = globalPreinitConfig->retransmitCmpTime;
    g_resource.minRate = globalPreinitConfig->minRate;
    g_resource.minPackInterval = globalPreinitConfig->minPackInterval;
    g_resource.unsendBoxLoopCheckBurst = globalPreinitConfig->unsendBoxLoopCheckBurst;
    g_resource.instUnsendBoxSize = globalPreinitConfig->instUnsendBoxSize;
    g_resource.nackRetryLen = globalPreinitConfig->nackRetryLen;

    return FILLP_SUCCESS;
}

static void FtGetCopyPreinitConfigs(IN FillpGlobalPreinitExtConfigsSt *globalPreinitConfig)
{
    globalPreinitConfig->pktLossThresHoldMax = g_resource.pktLossThresHoldMax;
    globalPreinitConfig->timingWheelAccuracy = g_resource.timingWheelAccuracy;
    globalPreinitConfig->maximalAckNumLimit = g_resource.maximalAckNumLimit;
    globalPreinitConfig->sendOneAckNum = g_resource.sendOneAckNum;
    globalPreinitConfig->cpuPauseTime = g_resource.cpuPauseTime;
    globalPreinitConfig->retransmitCmpTime = g_resource.retransmitCmpTime;
    globalPreinitConfig->minRate = g_resource.minRate;
    globalPreinitConfig->minPackInterval = g_resource.minPackInterval;
    globalPreinitConfig->unsendBoxLoopCheckBurst = g_resource.unsendBoxLoopCheckBurst;
    globalPreinitConfig->instUnsendBoxSize = g_resource.instUnsendBoxSize;
    globalPreinitConfig->nackRetryLen = g_resource.nackRetryLen;

    return;
}


/*******************************************************************
  Function      : FtInitConfigSet
  Description   : Api is used to set all the FILLP global stack configuration. please refer FillpGlobalConfigsSt
              for parameter details.
  Calls         :
  Called By     :
  Input         : structure of type FILLP_GLOBAL_RESOURCE
  Output        :
  Return        : FILLP_UINT32 SUCCESS/FAILURE
  Others        :
********************************************************************/
static FILLP_INT32 FtInitConfigSet(IN FILLP_CONST FillpGlobalConfigsSt *globalResource)
{
    FILLP_INT32 ret;

    if ((g_spunge != FILLP_NULL_PTR) && (g_spunge->hasInited == FILLP_TRUE)) {
        FILLP_LOGERR("Cannot Set value after stack initialization!!!");
        return ERR_FAILURE;
    }

    ret = FtValidateConfigParams(globalResource);
    if (ret == ERR_FAILURE) {
        return ERR_PARAM;
    }

    g_resource.udp.rxBurst = globalResource->udp.rxBurst;

    g_resource.common.maxSockNum = globalResource->common.maxSockNum;
    g_resource.common.maxConnNum = globalResource->common.maxConnectionNum;
    g_resource.common.fullCpuEnable = globalResource->common.fullCpu;
    g_resource.common.recvCachePktNumBufferSize = globalResource->common.recvCachePktNumBufferSize;
    g_resource.common.outOfOrderCacheEnable = globalResource->common.outOfOrderCacheFeature;
    g_resource.common.recvCachePktNumBufferTimeout = globalResource->timers.recvCachePktNumBufferTimeout;
    /* Currently this will not be allowed to configure and is always 1. */
    g_resource.common.maxInstNum = FILLP_DEFAULT_INST_NUM;

    g_resource.flowControl.initialRate = globalResource->flowControl.initialRate;
#ifdef FILLP_SERVER_SUPPORT
    g_resource.flowControl.oppositeSetPercentage = globalResource->flowControl.oppositeSetPercentage;
    g_resource.flowControl.maxRecvRate = globalResource->flowControl.maxRecvRate;
#endif
    g_resource.flowControl.maxRate = globalResource->flowControl.maxRate;

    g_resource.flowControl.nackRepeatTimes = globalResource->flowControl.nackRepeatTimes;
    g_resource.flowControl.pktLossAllow = globalResource->flowControl.pktLossAllow;
    g_resource.flowControl.fcAlg = globalResource->flowControl.fcAlg;
    g_resource.flowControl.maxRatePercentage = globalResource->flowControl.maxRatePercentage;
    g_resource.flowControl.supportFairness = globalResource->flowControl.supportFairness;

    return ERR_OK;
}


/*******************************************************************
  Function      : FtInitConfigGet
  Description   : Api is used to Querry the existing configuration values for all the
              FILLP global stack configurations. please refer FillpGlobalConfigsSt
              for parameter details.
  Calls         :
  Called By     :
  Input         : structure of type FILLP_GLOBAL_RESOURCE
  Output        : updated globalResource with current configuration values.
  Return        : FILLP_UINT32 SUCCESS/FAILURE
  Others        :
********************************************************************/
static FILLP_INT32 FtInitConfigGet(IO FillpGlobalConfigsSt *globalResource)
{
    globalResource->udp.rxBurst = (FILLP_UINT16)g_resource.udp.rxBurst;
    globalResource->common.maxSockNum = g_resource.common.maxSockNum;
    globalResource->common.maxConnectionNum = g_resource.common.maxConnNum;
    globalResource->common.fullCpu = g_resource.common.fullCpuEnable;
    globalResource->common.recvCachePktNumBufferSize = g_resource.common.recvCachePktNumBufferSize;
    globalResource->common.outOfOrderCacheFeature = g_resource.common.outOfOrderCacheEnable;
    globalResource->timers.recvCachePktNumBufferTimeout = g_resource.common.recvCachePktNumBufferTimeout;

    globalResource->flowControl.maxRate = g_resource.flowControl.maxRate;
#ifdef FILLP_SERVER_SUPPORT
    globalResource->flowControl.maxRecvRate = g_resource.flowControl.maxRecvRate;
    globalResource->flowControl.oppositeSetPercentage = g_resource.flowControl.oppositeSetPercentage;
#endif
    globalResource->flowControl.nackRepeatTimes = g_resource.flowControl.nackRepeatTimes;
    globalResource->flowControl.pktLossAllow = g_resource.flowControl.pktLossAllow;
    globalResource->flowControl.fcAlg = g_resource.flowControl.fcAlg;

    globalResource->flowControl.initialRate = g_resource.flowControl.initialRate;
    globalResource->flowControl.maxRatePercentage = g_resource.flowControl.maxRatePercentage;
    globalResource->flowControl.supportFairness = g_resource.flowControl.supportFairness;

    return ERR_OK;
}

static FILLP_INT32 FtGetConfigStackHalf1(IN FILLP_UINT32 name, IO void *value)
{
    switch (name) {
        case FT_CONF_RECV_CACHE_PKT_NUM_BUFF_SIZE:
            *(FILLP_UINT32 *)value = g_resource.common.recvCachePktNumBufferSize;
            break;

        case FT_CONF_RX_BURST:
            *(FILLP_UINT16 *)value = g_resource.udp.rxBurst;
            break;

        case FT_CONF_OUT_OF_ORDER_CATCHE_FEATURE:
            *(FILLP_BOOL *)value = g_resource.common.outOfOrderCacheEnable;
            break;

        case FT_CONF_CPU_CORE_USE:
            *(FILLP_UINT8 *)value = g_resource.common.cpuCoreUse;
            break;

        /* FLOW CONTROL */
        case FT_CONF_MAX_SOCK_NUM:
            *(FILLP_UINT16 *)value = g_resource.common.maxSockNum;
            break;

        case FT_CONF_MAX_CONNECTION_NUM:
            *(FILLP_UINT16 *)value = g_resource.common.maxConnNum;
            break;

        case FT_CONF_FULL_CPU:
            *(FILLP_BOOL *)value = g_resource.common.fullCpuEnable;
            break;

        case FT_CONF_OPPOSITE_SET_PERCENTAGE:
#ifdef FILLP_SERVER_SUPPORT
            *(FILLP_UINT16 *)value = g_resource.flowControl.oppositeSetPercentage;
#else
            FILLP_LOGERR("Server feature Not enabled :"
                         "FT_CONF_OPPOSITE_SET_PERCENTAGE is server only option so cannot GET !!!");
            return ERR_FEATURE_MACRO_NOT_ENABLED;
#endif
            break;

        case FT_CONF_NACK_REPEAT_TIMES:
            *(FILLP_UINT16 *)value = g_resource.flowControl.nackRepeatTimes;
            break;

        case FT_CONF_ALG:
            *(FILLP_UINT8 *) value = g_resource.flowControl.fcAlg;
            break;

        case FT_CONF_PACKET_LOSS_ALLOWED:
            *(FILLP_UINT16 *)value = g_resource.flowControl.pktLossAllow;
            break;

        default:
            return ERR_PARAM;
    }

    return ERR_OK;
}

static FILLP_INT32 FtGetConfigStackHalf2(IN FILLP_UINT32 name, IO void *value)
{
    switch (name) {
        case FT_CONF_SUPPORT_FAIRNESS:
            *(FILLP_UINT8 *)value = g_resource.flowControl.supportFairness;
            break;

        case FT_CONF_MAX_RATE_PERCENTAGE:
            *(FILLP_UINT16 *)value = g_resource.flowControl.maxRatePercentage;
            break;

        case FT_CONF_INITIAL_RATE:
            *(FILLP_UINT32 *)value = g_resource.flowControl.initialRate;
            break;
        case FT_CONF_CORE_MAX_RATE:
            *(FILLP_UINT32 *)value = g_resource.flowControl.maxRate;
            break;
        case FT_CONF_CORE_MAX_RECV_RATE:
#ifdef FILLP_SERVER_SUPPORT
            *(FILLP_UINT32 *)value = g_resource.flowControl.maxRecvRate;
            break;
#else
            FILLP_LOGERR("Server feature Not enabled :"
                         "FT_CONF_CORE_MAX_RECV_RATE is server only option so cannot GET !!!");
            return ERR_FEATURE_MACRO_NOT_ENABLED;
#endif

        case FT_CONF_TIMER_RECV_CACHE_PKT_NUMBUFF:
            *(FILLP_UINT16 *)value = g_resource.common.recvCachePktNumBufferTimeout;
            break;

        case FT_CONF_BFULL_CPU_USE_THRESHOLD_RATE:
            *(FILLP_UINT32 *)value = g_resource.fullCpuUseThresholdRate;
            break;

        case FT_CONF_STACK_CORE_LIMIT_RATE:
            *(FILLP_UINT32 *)value = g_resource.flowControl.limitRate;
            break;

        case FT_CONF_STACK_CORE_SEND_CACHE:
            *(FILLP_UINT32 *)value = g_resource.common.sendCache;
            break;

        case FT_CONF_STACK_CORE_RECV_CACHE:
            *(FILLP_UINT32 *)value = g_resource.common.recvCache;
            break;

        default:
            return ERR_PARAM;
    }

    return ERR_OK;
}

/*******************************************************************
  Function      : FtGetConfigStack
  Description   : Api is used to get Individual FILLP stack configuration
              item.
  Calls         :
  Called By     :
  Input         : FILLP_UINT32    name : Name of the config item to querry
                      (FILLP_CONFIG_LISTENUM)
            void *value  : FILLP will store the current value for the config item.

            void *param  : this is optional. only required for config items
            which requires additional information to get the configuration value.
                for ex:
                For SOCKET option this will store the Socket index.
  Output        :
  Return        : FILLP_UINT32 SUCCESS/FAILURE
  Others        :
********************************************************************/
static FILLP_INT32 FtGetConfigStack(
    IN FILLP_UINT32 name,
    IO void *value,
    IN FILLP_CONST void *param)
{
    FILLP_INT32 ret;

    FILLP_UNUSED_PARA(param);

    ret = FtGetConfigStackHalf1(name, value);
    if (ret != ERR_PARAM) {
        return ret;
    }

    ret = FtGetConfigStackHalf2(name, value);
    if (ret != ERR_PARAM) {
        return ret;
    }

    FILLP_LOGERR("invalid name %u!!!", name);

    return ERR_PARAM;
}

static FILLP_INT32 FtSetConfigStackHalf1(
    IN FILLP_UINT32 name,
    IN FILLP_CONST void *value)
{
    switch (name) {
        case FT_CONF_RX_BURST:
            return FtConfigSetRxBurst(value);

        case FT_CONF_RECV_CACHE_PKT_NUM_BUFF_SIZE:
            return FtConfigSetRecvCachePktNumBufferSize(value);

        case FT_CONF_OUT_OF_ORDER_CATCHE_FEATURE:
            return FtConfigSetOutOfOrderCacheFeature(value);

        case FT_CONF_CPU_CORE_USE:
            return FtConfigSetCpuCoreUse(value);

        /* FLOW CONTROL */
        case FT_CONF_MAX_SOCK_NUM:
            return FtConfigSetMaxSockNum(value);

        case FT_CONF_MAX_CONNECTION_NUM:
            return FtConfigSetMaxConnectionNum(value);

        case FT_CONF_FULL_CPU:
            return FtConfigSetFullCpu(value);

        case FT_CONF_OPPOSITE_SET_PERCENTAGE:
#ifdef FILLP_SERVER_SUPPORT
            return FtConfigSetOppositeSetPercentage(value);
#else
            FILLP_LOGERR("Server feature Not enabled :"
                         "FT_CONF_OPPOSITE_SET_PERCENTAGE is server only option so cannot SET !!!");
            return ERR_FEATURE_MACRO_NOT_ENABLED;
#endif

        case FT_CONF_NACK_REPEAT_TIMES:
            return FtConfigSetNackRepeatTimes(value);

        case FT_CONF_ALG:
            return FtConfigSetAlg(value);

        case FT_CONF_PACKET_LOSS_ALLOWED:
            return FtConfigSetPktLossAllow(value);

        case FT_CONF_SUPPORT_FAIRNESS:
            return FtConfigSetSupportFairness(value);

        default:
            return -1;
    }
}

static FILLP_INT32 FtSetConfigStackHalf2(
    IN FILLP_UINT32 name,
    IN FILLP_CONST void *value)
{
    switch (name) {
        case FT_CONF_INITIAL_RATE:
            return FtConfigSetInitialRate(value);

        case FT_CONF_MAX_RATE_PERCENTAGE:
            return FtConfigSetMaxRatePercentage(value);

        case FT_CONF_CORE_MAX_RATE:
            return FtConfigSetMaxRate(value);

        case FT_CONF_CORE_MAX_RECV_RATE:
#ifdef FILLP_SERVER_SUPPORT
            return FtConfigSetMaxRecvRate(value);
#else
            FILLP_LOGERR("Server feature Not enabled :"
                         "FT_CONF_CORE_MAX_RECV_RATE is server only option so cannot SET!!!");
            return ERR_FEATURE_MACRO_NOT_ENABLED;
#endif
        case FT_CONF_TIMER_RECV_CACHE_PKT_NUMBUFF: {
            FILLP_UINT16 usTempTimerValue = *(FILLP_UINT16 *)value;
            if ((usTempTimerValue < FILLP_MIN_TIMER_RECV_CACHE_PKT_NUMBUFF) ||
                (usTempTimerValue > FILLP_MAX_TIMER_RECV_CACHE_PKT_NUMBUFF)) {
                FILLP_LOGERR("recvCachePktNumBufferTimeout timer %u is invalid !!!", usTempTimerValue);
                return ERR_FAILURE;
            }

            g_resource.common.recvCachePktNumBufferTimeout = usTempTimerValue;
            return FILLP_SUCCESS;
        }

        case FT_CONF_BFULL_CPU_USE_THRESHOLD_RATE:
            return FtConfigSetFullCpuUseThresholdRate(value);

        case FT_CONF_STACK_CORE_LIMIT_RATE:
            return FtConfigSetLimitRate(value);

        case FT_CONF_STACK_CORE_SEND_CACHE:
            return FtConfigSetSendCache(value);

        case FT_CONF_STACK_CORE_RECV_CACHE:
            return FtConfigSetRecvCache(value);

        default:
            return -1;
    }
}

static FILLP_INT32 FtSetConfigStack(
    IN FILLP_UINT32 name,
    IN FILLP_CONST void *value,
    IN FILLP_CONST void *param)
{
    FILLP_INT32 ret;

    FILLP_UNUSED_PARA(param);
    FILLP_LOGINF("name:%u", name);

    ret = FtSetConfigStackHalf1(name, value);
    if (ret != -1) {
        return ret;
    }

    ret = FtSetConfigStackHalf2(name, value);
    if (ret != -1) {
        return ret;
    }

    FILLP_LOGERR("invalid name %u!!!", name);
    return ERR_FAILURE;
}

FILLP_INT32 FtConfigGet(IN FILLP_UINT32 name,
    IO void *value, IN FILLP_CONST void *param)
{
    if (value == FILLP_NULL_PTR) {
        FILLP_LOGERR("value is NULL!!!");
        return ERR_NULLPTR;
    }

    if (name == FT_CONF_INIT_APP) {
        if (param == FILLP_NULL_PTR) {
            FILLP_LOGERR("Parameter Error!");
            return ERR_NULLPTR;
        }
        return FtAppInitConfigGet((FillpAppGlobalConfigsSt *)value, *((FILLP_INT *)param));
    } else if (name == FT_CONF_INIT_STACK) {
        return FtInitConfigGet((FillpGlobalConfigsSt *)value);
    } else if (name == FT_CONF_INIT_STACK_EXT) {
        FtGetCopyPreinitConfigs((FillpGlobalPreinitExtConfigsSt *)value);
        return FILLP_SUCCESS;
    } else if (name < FT_CONF_APP_CONFIG_BOUNDARY) {
        return FtGetConfigApp(name, value, param);
    } else {
        return FtGetConfigStack(name, value, param);
    }
}

FILLP_INT32 FtConfigSet(IN FILLP_UINT32 name, IN FILLP_CONST void *value,
    IN FILLP_CONST void *param)
{
    if (value == FILLP_NULL_PTR) {
        FILLP_LOGERR("value is NULL!!!");
        return ERR_NULLPTR;
    }

    if (name == FT_CONF_INIT_APP) {
        if (param == FILLP_NULL_PTR) {
            FILLP_LOGERR("Parameter Error!");
            return ERR_NULLPTR;
        }

        return FtAppInitConfigSet((FILLP_CONST FillpAppGlobalConfigsSt *)value, *((FILLP_INT *)param));
    } else if (name == FT_CONF_INIT_STACK) {
        return FtInitConfigSet((FILLP_CONST FillpGlobalConfigsSt *)value);
    } else if (name == FT_CONF_INIT_STACK_EXT) {
        return FtSetCopyPreinitConfigs((FILLP_CONST FillpGlobalPreinitExtConfigsSt *)value);
    } else if (name < FT_CONF_APP_CONFIG_BOUNDARY) {
        return FtSetConfigApp(name, value, param);
    } else {
        return FtSetConfigStack(name, value, param);
    }
}

#ifdef __cplusplus
}
#endif

