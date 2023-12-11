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

#include "fillp_stack_app_config_in.h"

static FILLP_INT32 FtAppValidateFlowConfig(IN FILLP_CONST FillpAppGlobalConfigsSt *globalResource)
{
#ifdef FILLP_SERVER_SUPPORT
    if ((globalResource->flowControl.oppositeSetRate > FILLP_MAX_STACK_OPPOSITE_SET_RATE) ||
        (globalResource->flowControl.oppositeSetRate > g_resource.flowControl.maxRate)) {
        FILLP_LOGERR("oppositeSetRate is invalid parameter oppositeSetRate = %u maxRate = %u !!!",
                     globalResource->flowControl.oppositeSetRate, g_resource.flowControl.maxRate);
        return ERR_FAILURE;
    }
#endif

    if ((globalResource->flowControl.maxRate == 0) || (globalResource->flowControl.maxRate > FILLP_MAX_STACK_RATE)) {
        FILLP_LOGERR("maxRate: %u Kbps is invalid parameter!!!", globalResource->flowControl.maxRate);
        return ERR_FAILURE;
    }

    if ((globalResource->flowControl.maxRecvRate == 0) ||
        (globalResource->flowControl.maxRecvRate > FILLP_MAX_STACK_RECV_RATE)) {
        FILLP_LOGERR("maxRecvRate: %u Kbps is invalid parameter!!!", globalResource->flowControl.maxRecvRate);
        return ERR_FAILURE;
    }

    if ((globalResource->flowControl.pktSize == 0) ||
        (globalResource->flowControl.pktSize > (FILLP_FRAME_MTU - (FILLP_HLEN + UDP_HLEN + IP_HLEN)))) {
        FILLP_LOGERR("pktSize %u is invalid parameter!!!", globalResource->flowControl.pktSize);
        return ERR_FAILURE;
    }

    if ((globalResource->flowControl.slowStart != FILLP_TRUE) &&
        (globalResource->flowControl.slowStart != FILLP_FALSE)) {
        FILLP_LOGERR("slowStart %u is invalid parameter!!!", globalResource->flowControl.slowStart);
        return ERR_FAILURE;
    }

    if ((globalResource->flowControl.constRateEnbale != FILLP_TRUE) &&
        (globalResource->flowControl.constRateEnbale != FILLP_FALSE)) {
        FILLP_LOGERR("constRateEnbale %u is invalid parameter!!!", globalResource->flowControl.constRateEnbale);
        return ERR_FAILURE;
    }

    return ERR_OK;
}

static FILLP_INT32 FtAppValidateUdpParams(IN FILLP_CONST FillpAppGlobalConfigsSt *globalResource)
{
    if ((globalResource->udp.txBurst == 0) || (globalResource->udp.txBurst > FILLP_MAX_TX_RX_BURST)) {
        FILLP_LOGERR(" txBurst is invalid parameter txBurst = %u", globalResource->udp.txBurst);
        return ERR_FAILURE;
    }

    return ERR_OK;
}

static FILLP_INT32 FtAppValidateCommParams(IN FILLP_CONST FillpAppGlobalConfigsSt *globalResource)
{
#ifdef FILLP_SERVER_SUPPORT

    if ((globalResource->common.maxServerAllowSendCache == 0) ||
        (globalResource->common.maxServerAllowSendCache > FILLP_MAX_SERVER_ALLOW_SEND_RECV_CACHE)) {
        FILLP_LOGERR("maxServerAllowSendCache %u is invalid parameter!!!",
                     globalResource->common.maxServerAllowSendCache);
        return ERR_FAILURE;
    }

    if ((globalResource->common.maxServerAllowRecvCache == 0) ||
        (globalResource->common.maxServerAllowRecvCache > FILLP_MAX_SERVER_ALLOW_SEND_RECV_CACHE)) {
        FILLP_LOGERR("maxServerAllowRecvCache %u is invalid parameter!!!",
                     globalResource->common.maxServerAllowRecvCache);
        return ERR_FAILURE;
    }

#endif

    if (globalResource->common.udpSendBufSize < FILLP_FRAME_MTU) {
        FILLP_LOGERR("send_bufSize %u is invalid parameter!!!", globalResource->common.udpSendBufSize);
        return ERR_FAILURE;
    }

    if (globalResource->common.recvBufSize < FILLP_FRAME_MTU) {
        FILLP_LOGERR("recvBufSize %u is invalid parameter!!!", globalResource->common.recvBufSize);
        return ERR_FAILURE;
    }

    if ((globalResource->common.sendCache == FILLP_NULL) ||
        (globalResource->common.sendCache > FILLP_MAX_ALLOW_SEND_RECV_CACHE)) {
        FILLP_LOGERR("sendCache %u is invalid parameter!!!", globalResource->common.sendCache);
        return ERR_FAILURE;
    }

    if ((globalResource->common.recvCache == FILLP_NULL) ||
        (globalResource->common.recvCache > FILLP_MAX_ALLOW_SEND_RECV_CACHE)) {
        FILLP_LOGERR("recvCache %u is invalid parameter!!!", globalResource->common.recvCache);
        return ERR_FAILURE;
    }

    if ((globalResource->common.nackDelayTimeout < (FILLP_MAX_SEND_INTERVAL >> 3)) ||
        (globalResource->common.nackDelayTimeout > FILLP_MAX_INT_VALUE)) {
        FILLP_LOGERR("nackDelayTimeout %lld is invalid parameter!!! \r\n", globalResource->common.nackDelayTimeout);
        return ERR_FAILURE;
    }

    if ((globalResource->common.enableNackDelay != FILLP_TRUE) &&
        (globalResource->common.enableNackDelay != FILLP_FALSE)) {
        FILLP_LOGERR("enableNackDelay %u is invalid parameter!!!", globalResource->common.enableNackDelay);
        return ERR_FAILURE;
    }

    return ERR_OK;
}

static FILLP_INT32 FtAppValidateTimerParams(IN FILLP_CONST FillpAppGlobalConfigsSt *globalResource)
{
    /* connectTimeout is in seconds. */
    if ((globalResource->timers.connectTimeout == FILLP_NULL) ||
        (globalResource->timers.connectTimeout > FILLP_MAX_CONNECT_TIMEOUT)) {
        FILLP_LOGERR("connectTimeout %u is invalid parameter", globalResource->timers.connectTimeout);
        return ERR_FAILURE;
    }

    if ((globalResource->timers.keepAliveTime < FILLP_MIN_KEEP_ALIVE_TIMER) ||
        (globalResource->timers.keepAliveTime > FILLP_MAX_KEEP_ALIVE_TIME)) {
        FILLP_LOGERR("keepAliveTime %u is invalid parameter", globalResource->timers.keepAliveTime);
        return ERR_FAILURE;
    }

    /* connRetryTimeout is in milliseconds */
    if ((globalResource->timers.connRetrytimeout == FILLP_NULL) ||
        (globalResource->timers.connRetrytimeout > FILLP_MAX_CONNECT_RETRY_TIMER_INTERVAL)) {
        FILLP_LOGERR("connRetryTimeout %u is invalid parameter", globalResource->timers.connRetrytimeout);
        return (ERR_FAILURE);
    }

    /* disconnectRetrytimeout is in milliseconds */
    if ((globalResource->timers.disconnectRetrytimeout == FILLP_NULL) ||
        (globalResource->timers.disconnectRetrytimeout > FILLP_MAX_DISCONNECT_TIMER_INTERVAL)) {
        FILLP_LOGERR("disconnectRetrytimeout %u is invalid parameter", globalResource->timers.disconnectRetrytimeout);
        return (ERR_FAILURE);
    }

    return ERR_OK;
}

/**********************************************************************************
  Function      : FtAppValidateConfigParams
  Description   : This API is used to validate application. This is refer as a validation function.
  Input         : resource This is the pointer to FillpAppGlobalConfigsSt structure.
  Return        : On success - FillP_SUCCESS
                  On Failure - ERROR CODES
******************************************************************************************/
FILLP_INT32 FtAppValidateConfigParams(IN FILLP_CONST FillpAppGlobalConfigsSt *globalResource)
{
    FILLP_INT32 ret;

    ret = FtAppValidateUdpParams(globalResource);
    if (ret != ERR_OK) {
        return ret;
    }

    ret = FtAppValidateCommParams(globalResource);
    if (ret != ERR_OK) {
        return ret;
    }

    ret = FtAppValidateTimerParams(globalResource);
    if (ret != ERR_OK) {
        return ret;
    }

    return FtAppValidateFlowConfig(globalResource);
}

/*******************************************************************
  Function      : FtAppTimerConfigSet
  Description   : Api is used to Set individual FILLP stack Timer lengths
                  Currently 5 timers are handled.
                  1. Connect timeout timer
                  2. Disconnect timeout
                  3. Keep Alive timer
                  4. pack timer
                  5. close pending
  Input         : FILLP_UINT32    name: Timer name which user wants to change the timeout value (FILLP_TIMER_LIST).
                  FILLP_UINT32 *value : Will specify the timeout value in milliseconds
  Output        : NA
  Return        : FILLP_UINT32 SUCCESS/FAILURE
********************************************************************/
static FILLP_INT32 FtAppTimerConfigSet(
    IN FILLP_CONST void *value,
    struct GlobalAppResource *resource,
    IN FILLP_INT sockIndex)
{
    FILLP_UINT32 timerValue;

    timerValue = *(FILLP_UINT32 *)value;
    if ((timerValue == 0) || (timerValue > FILLP_MAX_CONNECT_TIMEOUT)) {
        FILLP_LOGERR("fillp_sock_id:%d connectTimeout timer is invalid", sockIndex);
        return ERR_FAILURE;
    }

    resource->common.connectTimeout = timerValue;

    FILLP_LOGINF("set connect timeout fillp_sock_id:%d, value:%u", sockIndex, timerValue);

    FILLP_UNUSED_PARA(sockIndex);
    return FILLP_SUCCESS;
}

static FILLP_INT32 FtAppSetKeepAliveTime(
    IN FILLP_CONST void *value,
    struct GlobalAppResource *resource,
    IN FILLP_INT sockIndex)
{
    FILLP_UINT32 timerValue;

    timerValue = *(FILLP_UINT32 *)value;
    if ((timerValue < FILLP_MIN_KEEP_ALIVE_TIMER) || (timerValue > FILLP_MAX_KEEP_ALIVE_TIME)) {
        FILLP_LOGERR("fillp_sock_id:%d keepAliveTime timer  is invalid!!!", sockIndex);
        return ERR_FAILURE;
    }

    struct FtSocket *sock = FILLP_NULL_PTR;
    if (sockIndex != FILLP_MAX_UNSHORT_VAL) {
        sock = SockGetSocket(sockIndex);
        if (sock == FILLP_NULL_PTR) {
            FILLP_LOGERR("invalid sock: %d", sockIndex);
            return ERR_FAILURE;
        }

        resource->common.keepAliveTime = timerValue;
        if ((sock->netconn != FILLP_NULL_PTR) && (sock->netconn->state == CONN_STATE_CONNECTED)) {
            FillpErrorType ret = SpungePostMsg(sock->inst, (void *)sock, MSG_TYPE_SET_KEEP_ALIVE, FILLP_TRUE);
            if (ret != ERR_OK) {
                FILLP_LOGERR("fillp_sock_id:%d Failed to set the keep alive time for system socket", sockIndex);
                return ret;
            }

            if (sock->coreErrType[MSG_TYPE_SET_KEEP_ALIVE] != ERR_OK) {
                FILLP_LOGERR("fillp_sock_id:%d Failed to set the keep alive time for system socket", sockIndex);
                return sock->coreErrType[MSG_TYPE_SET_KEEP_ALIVE];
            }
        }
    } else {
        resource->common.keepAliveTime = timerValue;
    }

    FILLP_LOGBUTT("fillp_sock_id: %d, set keepalive time to %u", sockIndex, timerValue);
    return FILLP_SUCCESS;
}

static FILLP_INT32 FtAppSetConnRetryTimeout(
    IN FILLP_CONST void *value,
    struct GlobalAppResource *resource,
    IN FILLP_INT sockIndex)
{
    FILLP_UINT16 usTempTimerValue;

    usTempTimerValue = *(FILLP_UINT16 *)value;
    if ((usTempTimerValue == FILLP_NULL) || (usTempTimerValue > FILLP_MAX_CONNECT_RETRY_TIMER_INTERVAL)) {
        FILLP_LOGERR("fillp_sock_id:%d connRetryTimeout timer  is invalid!!!", sockIndex);
        return ERR_FAILURE;
    }

    resource->common.connRetryTimeout = usTempTimerValue;
    FILLP_UNUSED_PARA(sockIndex);
    return FILLP_SUCCESS;
}

static FILLP_INT32 FtAppSetDisconnectRetryTimeout(
    IN FILLP_CONST void *value,
    struct GlobalAppResource *resource,
    IN FILLP_INT sockIndex)
{
    FILLP_UINT32 timerValue;

    timerValue = *(FILLP_UINT32 *)value;
    if ((timerValue == FILLP_NULL) || (timerValue > FILLP_MAX_DISCONNECT_TIMER_INTERVAL)) {
        FILLP_LOGERR("fillp_sock_id:%d disconnectRetrytimeout timer  is invalid!!!", sockIndex);
        return ERR_FAILURE;
    }

    resource->common.disconnectRetryTimeout = timerValue;
    FILLP_UNUSED_PARA(sockIndex);
    return FILLP_SUCCESS;
}

/**********************************************************************************
  Function      : FtSetConfigStack
  Description   : Api is used to set Individual FILLP stack configuration item.
  Input         : FILLP_UINT32    name : Name of the config item to configure
                      (FILLP_CONFIG_LIST_ENUM)
                  void *value  : This will contain the value for the config item.
                  void *param  : this is optional. only required for config items
                       which requires additional information to configure.
                  for ex:
                       For SOCKET option this will store the Socket index.
  Output        : NA
  Return        : FILLP_UINT32 SUCCESS/FAILURE
******************************************************************************************/
static FILLP_INT32 FtAppConfigSetTxBurst(
    IN FILLP_CONST void *value,
    struct GlobalAppResource *resource,
    FILLP_INT sockIndex)
{
    FILLP_UINT16 configValue;

    configValue = *(FILLP_UINT16 *)value;
    if ((configValue == 0) || (configValue > FILLP_MAX_TX_RX_BURST)) {
        FILLP_LOGERR("fillp_sock_id:%d txBurst is invalid parameter!!!", sockIndex);
        return ERR_FAILURE;
    }

    resource->udp.txBurst = (FILLP_UINT32)(configValue);
    FILLP_UNUSED_PARA(sockIndex);
    return FILLP_SUCCESS;
}

static FILLP_INT32 FtAppConfigSetSendCache(
    IN FILLP_CONST void *value,
    struct GlobalAppResource *resource,
    FILLP_INT sockIndex)
{
    FILLP_UINT32 configValue;
    struct FtSocket *sock = FILLP_NULL_PTR;

    configValue = *(FILLP_UINT32 *)value;
    if ((configValue == FILLP_NULL) || (configValue > FILLP_MAX_ALLOW_SEND_RECV_CACHE)) {
        FILLP_LOGERR("fillp_sock_id:%d sendCache  invalid parameter!!!", sockIndex);
        return ERR_FAILURE;
    }
    resource->common.sendCache = configValue;
    if (sockIndex != FILLP_CONFIG_ALL_SOCKET) {
        sock = SockGetSocket(sockIndex);
        if ((sock != FILLP_NULL_PTR) && (sock->netconn != FILLP_NULL_PTR) &&
            (sock->netconn->pcb != FILLP_NULL_PTR) && (sock->netconn->state == CONN_STATE_IDLE)) {
            NetconnSetSendCacheSize(sock->netconn, configValue);
        } else {
            return ERR_FAILURE;
        }
    }

    return FILLP_SUCCESS;
}

static FILLP_INT32 FtAppConfigSetRecvCache(
    IN FILLP_CONST void *value,
    struct GlobalAppResource *resource,
    FILLP_INT sockIndex)
{
    FILLP_UINT32 configValue;
    struct FtSocket *sock = FILLP_NULL_PTR;
    configValue = *(FILLP_UINT32 *)value;
    if ((configValue == FILLP_NULL) || (configValue > FILLP_MAX_ALLOW_SEND_RECV_CACHE)) {
        FILLP_LOGERR("fillp_sock_id:%d recvCache  invalid parameter!!!", sockIndex);
        return ERR_FAILURE;
    }

    resource->common.recvCache = configValue;
    if (sockIndex != FILLP_CONFIG_ALL_SOCKET) {
        sock = SockGetSocket(sockIndex);
        if ((sock != FILLP_NULL_PTR) && (sock->netconn != FILLP_NULL_PTR) &&
            (sock->netconn->pcb != FILLP_NULL_PTR) && (sock->netconn->state == CONN_STATE_IDLE)) {
            NetconnSetRecvCacheSize(sock->netconn, configValue);
        } else {
            return ERR_FAILURE;
        }
    }

    return FILLP_SUCCESS;
}

static FILLP_INT32 FtAppSetMaxServerSendCache(
    IN FILLP_CONST void *value,
    struct GlobalAppResource *resource,
    FILLP_INT sockIndex)
{
    FILLP_UINT32 configValue;

    configValue = *(FILLP_UINT32 *)value;
    if ((configValue == FILLP_NULL) || (configValue > FILLP_MAX_SERVER_ALLOW_SEND_RECV_CACHE)) {
        FILLP_LOGERR("fillp_sock_id:%d maxServerAllowSendCache is  invalid parameter!!!", sockIndex);
        return ERR_FAILURE;
    }

    resource->common.maxServerAllowSendCache = configValue;
    FILLP_UNUSED_PARA(sockIndex);
    return FILLP_SUCCESS;
}

static FILLP_INT32 FtAppSetMaxServeRecvCache(
    IN FILLP_CONST void *value,
    struct GlobalAppResource *resource,
    FILLP_INT sockIndex)
{
    FILLP_UINT32 configValue;

    configValue = *(FILLP_UINT32 *)value;

    if ((configValue == FILLP_NULL) || (configValue > FILLP_MAX_SERVER_ALLOW_SEND_RECV_CACHE)) {
        FILLP_LOGERR("fillp_sock_id:%d maxServerAllowRecvCache is invalid parameter!!!", sockIndex);
        return ERR_FAILURE;
    }

    resource->common.maxServerAllowRecvCache = configValue;
    FILLP_UNUSED_PARA(sockIndex);
    return FILLP_SUCCESS;
}

static FILLP_INT32 FtAppConfigSetOppositeSetRate(
    IN FILLP_CONST void *value,
    struct GlobalAppResource *resource,
    FILLP_INT sockIndex)
{
    FILLP_UINT32 configValue;
    struct FtSocket *sock = FILLP_NULL_PTR;

    configValue = *(FILLP_UINT32 *)value;
    if ((configValue > FILLP_NULL) && (configValue <= FILLP_MAX_STACK_OPPOSITE_SET_RATE) &&
        (configValue <= g_resource.flowControl.maxRate)
        /* if fairness is set, then we should not allow user to set opposite set rate */
        && (g_resource.flowControl.supportFairness == FILLP_FAIRNESS_TYPE_NONE)) {
        resource->flowControl.oppositeSetRate = configValue;
        if (sockIndex != FILLP_MAX_UNSHORT_VAL) {
            sock = SockGetSocket(sockIndex);
            if ((sock != FILLP_NULL_PTR) && (sock->netconn != FILLP_NULL_PTR) &&
                (sock->netconn->pcb != FILLP_NULL_PTR)) {
                NetconnSetOpersiteRate(sock->netconn, configValue);
            }
        }
    } else {
        FILLP_LOGERR("fillp_sock_id:%d oppositeSetRate is invalid parameter %u, maxRate = %u, "
            "supportFairness = %u!!!",
            sockIndex, configValue, g_resource.flowControl.maxRate, g_resource.flowControl.supportFairness);
        return ERR_FAILURE;
    }

    return FILLP_SUCCESS;
}

static FILLP_INT32 FtAppConfigSetPktSize(
    IN FILLP_CONST void *value,
    struct GlobalAppResource *resource,
    FILLP_INT sockIndex)
{
    FILLP_UINT16 configValue;
    struct FtSocket *sock = FILLP_NULL_PTR;

    configValue = *(FILLP_UINT16 *)value;
    if ((configValue > 0) && (configValue <= (FILLP_FRAME_MTU - FILLP_HLEN - UDP_HLEN - IP_HLEN))) {
        if (sockIndex != FILLP_CONFIG_ALL_SOCKET) {
            FILLP_UINT16 dataOptionAreaSize = 0;
            sock = SockGetSocket(sockIndex);
            if ((sock != FILLP_NULL_PTR) && (sock->dataOptionFlag != FILLP_NULL)) {
                dataOptionAreaSize = (FILLP_UINT16)(sock->dataOptionSize + FILLP_DATA_OFFSET_LEN);
            }
            if ((sock != FILLP_NULL_PTR) && (dataOptionAreaSize >= configValue)) {
                FILLP_LOGERR("fillp_sock_id:%d pktSize is invalid parameter!!!", sockIndex);
                return ERR_FAILURE;
            }

            if ((sock != FILLP_NULL_PTR) && (sock->netconn != FILLP_NULL_PTR) &&
                (sock->netconn->pcb != FILLP_NULL_PTR) && (sock->netconn->state <= CONN_STATE_LISTENING)) {
                resource->flowControl.pktSize = configValue;
                NetconnSetPktSize(sock->netconn, configValue);
            } else {
                FILLP_LOGERR("fillp_sock_id:%d pktSize cannot be set if state is not listening or idle", sockIndex);
                return ERR_FAILURE;
            }
        } else {
            resource->flowControl.pktSize = configValue;
        }
    } else {
        FILLP_LOGERR("fillp_sock_id:%d pktSize is invalid parameter!!!", sockIndex);
        return ERR_FAILURE;
    }

    return FILLP_SUCCESS;
}

static FILLP_INT32 FtAppConfigSetSendBufSize(
    IN FILLP_CONST void *value,
    struct GlobalAppResource *resource,
    FILLP_INT sockIndex,
    struct FtSocket *sock)
{
    FILLP_UINT32 configValue;
    FillpErrorType ret;

    configValue = *(FILLP_UINT32 *)value;
    if (configValue < FILLP_FRAME_MTU) {
        FILLP_LOGERR("fillp_sock_id:%d send_bufSize is invalid parameter!!!", sockIndex);
        return ERR_FAILURE;
    }

    resource->common.udpSendBufSize = configValue;
    if (sock != FILLP_NULL_PTR) {
        ret = SpungePostMsg(sock->inst, (void *)sock, MSG_TYPE_SET_SEND_BUF, FILLP_TRUE);
        if (ret != ERR_OK) {
            FILLP_LOGERR("fillp_sock_id:%d Failed to set the send Buffer size for system socket", sockIndex);

            return ret;
        }

        if (sock->coreErrType[MSG_TYPE_SET_SEND_BUF] != ERR_OK) {
            FILLP_LOGERR("fillp_sock_id:%d Failed to set the send Buffer size for system socket", sockIndex);
        }

        return sock->coreErrType[MSG_TYPE_SET_SEND_BUF];
    }

    FILLP_UNUSED_PARA(sockIndex);
    return FILLP_SUCCESS;
}

static FILLP_INT32 FtAppConfigSetRecvBufSize(
    IN FILLP_CONST void *value,
    struct GlobalAppResource *resource,
    FILLP_INT sockIndex,
    struct FtSocket *sock)
{
    FILLP_UINT32 configValue;
    FillpErrorType ret;

    configValue = *(FILLP_UINT32 *)value;
    if (configValue < FILLP_FRAME_MTU) {
        FILLP_LOGERR("fillp_sock_id:%d recvBufSize is invalid parameter!!!", sockIndex);
        return ERR_FAILURE;
    }

    resource->common.recvBufSize = configValue;
    if (sock != FILLP_NULL_PTR) {
        ret = SpungePostMsg(sock->inst, (void *)sock, MSG_TYPE_SET_RECV_BUF, FILLP_TRUE);
        if (ret != ERR_OK) {
            FILLP_LOGERR("fillp_sock_id:%d Failed to set the receive Buffer size for system socket", sockIndex);

            return ret;
        }

        if (sock->coreErrType[MSG_TYPE_SET_RECV_BUF] != ERR_OK) {
            FILLP_LOGERR("fillp_sock_id:%d Failed to set the receive Buffer size for system socket", sockIndex);
        }

        return sock->coreErrType[MSG_TYPE_SET_RECV_BUF];
    }

    FILLP_UNUSED_PARA(sockIndex);
    return FILLP_SUCCESS;
}

static FILLP_INT32 FtAppConfigSetSlowStart(
    IN FILLP_CONST void *value,
    struct GlobalAppResource *resource,
    FILLP_INT sockIndex)
{
    FILLP_BOOL val;
    struct FtSocket *sock = FILLP_NULL_PTR;
    val = *(FILLP_BOOL *)value;
    if ((val == FILLP_FALSE) || (val == FILLP_TRUE)) {
        resource->flowControl.slowStart = val;
        if (sockIndex != FILLP_MAX_UNSHORT_VAL) {
            sock = SockGetSocket(sockIndex);
            if ((sock != FILLP_NULL_PTR) && (sock->netconn != FILLP_NULL_PTR) &&
                (sock->netconn->pcb != FILLP_NULL_PTR)) {
                NetconnSetSlowStart(sock->netconn, val);
            }
        }
    } else {
        FILLP_LOGERR("fillp_sock_id:%d slowStart is invalid parameter!!!", sockIndex);
        return ERR_FAILURE;
    }

    return FILLP_SUCCESS;
}

static FILLP_INT32 FtAppConfigSetMaxRate(
    IN FILLP_CONST void *value,
    struct GlobalAppResource *resource,
    FILLP_INT sockIndex)
{
    FILLP_UINT32 configValue;

    configValue = *(FILLP_UINT32 *)value;
    if ((configValue >= FILLP_DEFAULT_MIN_RATE) && (configValue <= FILLP_MAX_STACK_RATE)) {
        resource->flowControl.maxRate = configValue;
        if (sockIndex != FILLP_CONFIG_ALL_SOCKET) {
            struct FtSocket *sock = SockGetSocket(sockIndex);
            if (FILLP_INVALID_PTR(sock) || FILLP_INVALID_PTR(sock->netconn)) {
                FILLP_LOGERR("Invalid fillp_sock_id:%d", sockIndex);
                return ERR_FAILURE;
            }
        }
    } else {
        FILLP_LOGERR("fillp_sock_id:%d max_rat(%u) Kbps is invalid parameter!!!", sockIndex, configValue);
        return ERR_FAILURE;
    }

    return FILLP_SUCCESS;
}

static FILLP_INT32 FtAppConfigSetConstRate(
    IN FILLP_CONST void *value,
    struct GlobalAppResource *resource,
    FILLP_INT sockIndex)
{
    FILLP_BOOL val;

    val = *(FILLP_BOOL *)value;
    if ((val != FILLP_FALSE) && (val != FILLP_TRUE)) {
        FILLP_LOGERR("fillp_sock_id:%d constRateEnbale is invalid parameter!!!", sockIndex);
        return ERR_FAILURE;
    }

    resource->flowControl.constRateEnbale = val;
    FILLP_UNUSED_PARA(sockIndex);
    return FILLP_SUCCESS;
}

static FILLP_INT32 FtAppConfigSetMaxRecvRate(
    IN FILLP_CONST void *value,
    struct GlobalAppResource *resource,
    FILLP_INT sockIndex)
{
    FILLP_UINT32 configValue;

    configValue = *(FILLP_UINT32 *)value;
    if ((configValue != FILLP_NULL) && (configValue <= FILLP_MAX_STACK_RECV_RATE)) {
        resource->flowControl.maxRecvRate = configValue;
    } else {
        FILLP_LOGERR("fillp_sock_id:%d maxRecvRate(%u) Kbps is invalid parameter!!!", sockIndex, configValue);
        return ERR_FAILURE;
    }

    FILLP_UNUSED_PARA(sockIndex);
    return FILLP_SUCCESS;
}

static FILLP_INT32 FtAppEnlargePackInterval(
    IN FILLP_CONST void *value,
    struct GlobalAppResource *resource,
    FILLP_INT sockIndex,
    struct FtSocket *sock)
{
    FILLP_BOOL configValue;

    FILLP_UNUSED_PARA(sock);

    configValue = *(FILLP_BOOL *)value;
    if ((configValue != FILLP_TRUE) && (configValue != FILLP_FALSE)) {
        FILLP_LOGERR("fillp_sock_id:%d enlargePackIntervalFlag %u passed is invalid parameter!!!", sockIndex,
            configValue);
        return ERR_FAILURE;
    }
    resource->common.enlargePackIntervalFlag = configValue;
    FILLP_UNUSED_PARA(sockIndex);
    return FILLP_SUCCESS;
}

FILLP_INT FtAppConfigInitNackDelayCfg(
    FILLP_INT sockIndex,
    struct GlobalAppResource *resource)
{
    FILLP_INT ret;

    if ((sockIndex == FILLP_MAX_UNSHORT_VAL) && (g_spunge != FILLP_NULL_PTR) && (g_spunge->hasInited == FILLP_TRUE)) {
        struct NackDelayCfg *cfg =
            (struct NackDelayCfg *)SpungeAlloc(1, sizeof(struct NackDelayCfg), SPUNGE_ALLOC_TYPE_MALLOC);
        if (cfg == FILLP_NULL_PTR) {
            FILLP_LOGERR("fillp_sock_id:%d unable to set the parameter due to system error", sockIndex);
            return ERR_FAILURE;
        }

        cfg->nackCfgVal = resource->common.enableNackDelay;
        cfg->nackDelayTimeout = resource->common.nackDelayTimeout;
        cfg->sockIndex = sockIndex;

        ret = SpungePostMsg(SPUNGE_GET_CUR_INSTANCE(), (void *)cfg, MSG_TYPE_SET_NACK_DELAY, FILLP_TRUE);
        if (ret != ERR_OK) {
            FILLP_LOGERR("fillp_sock_id:%d Failed to set the nack delay for affected connections", sockIndex);
            SpungeFree(cfg, SPUNGE_ALLOC_TYPE_MALLOC);
            return ret;
        }
    }

    return ERR_OK;
}

static FILLP_INT32 FtAppConfigSetEnableNackDelay(
    IN FILLP_CONST void *value,
    struct GlobalAppResource *resource,
    FILLP_INT sockIndex)
{
    FILLP_BOOL configValue;
    FillpErrorType ret;

    configValue = *(FILLP_BOOL *)value;
    if ((configValue != FILLP_TRUE) && (configValue != FILLP_FALSE)) {
        FILLP_LOGERR("fillp_sock_id:%d enableNackDelay %u passed is invalid parameter!!!", sockIndex,
                     configValue);
        return ERR_FAILURE;
    }

    resource->common.enableNackDelay = configValue;

    /* need to post in 2 cases:
    a) if the config is being set for a particular socket
    b) if set for global after stack init, since it needs to be updated on all
    the existing socket.
    So, if the stack is not init and it is being set globally, then no need
    to post it, since there are no sockets for which it needs to be set */
    ret = FtAppConfigInitNackDelayCfg(sockIndex, resource);
    if (ret != ERR_OK) {
        return ret;
    }

    return FILLP_SUCCESS;
}

static FILLP_INT32 FtAppConfigSetNackDelayTimeout(
    IN FILLP_CONST void *value,
    struct GlobalAppResource *resource,
    FILLP_INT sockIndex)
{
    FILLP_LLONG configValue;
    FillpErrorType ret;

    configValue = *(FILLP_LLONG *)value;

    if ((configValue < (FILLP_MAX_SEND_INTERVAL >> FILLP_RARE_3)) || (configValue > FILLP_MAX_INT_VALUE)) {
        FILLP_LOGERR("fillp_sock_id:%d nackDelayTimeout %lld is invalid parameter!!!", sockIndex, configValue);
        return ERR_FAILURE;
    }
    resource->common.nackDelayTimeout = configValue;

    /* need to post in 2 cases:
    a) if the config is being set for a particular socket
    b) if set for global after stack init, since it needs to be updated on all
    the existing socket.
    So, if the stack is not init and it is being set globally, then no need
    to post it, since there are no sockets for which it needs to be set */
    ret = FtAppConfigInitNackDelayCfg(sockIndex, resource);
    if (ret != ERR_OK) {
        return ret;
    }

    return FILLP_SUCCESS;
}

static FILLP_INT32 FtAppSetFcStatInterval(
    IN FILLP_CONST void *value,
    struct GlobalAppResource *resource,
    FILLP_INT sockIndex)
{
    FILLP_UINT32 configValue;

    configValue = *(FILLP_UINT32 *)value;
    if ((configValue < resource->flowControl.packInterval) ||
        (configValue > FILLP_APP_FC_STASTICS_MAX_INTERVAL)) {
        FILLP_LOGERR("fillp_sock_id:%d maxServerAllowSendCache is  invalid parameter!!!", sockIndex);
        return ERR_FAILURE;
    }

    resource->common.fcStasticsInterval = configValue;
    FILLP_UNUSED_PARA(sockIndex);
    return FILLP_SUCCESS;
}

static FILLP_INT32 FtAppConfigSetPackInterval(IN FILLP_CONST void *value, struct GlobalAppResource *resource,
    FILLP_INT sockIndex)
{
    FILLP_UINT32 val = *(FILLP_UINT32 *)value;
    struct FtSocket *sock = FILLP_NULL_PTR;

    if (val < FILLP_MIN_APP_PACK_INTERVAL || val > FILLP_MAX_APP_PACK_INTERVAL) {
        FILLP_LOGERR("fillp_sock_id:%d pack interval(%u) is invalid parameter!!!", sockIndex, val);
        return ERR_FAILURE;
    }

    if (sockIndex != FILLP_MAX_UNSHORT_VAL) {
        sock = SockGetSocket(sockIndex);
        if ((sock != FILLP_NULL_PTR) && (sock->netconn != FILLP_NULL_PTR) && (sock->netconn->pcb != FILLP_NULL_PTR) &&
            (sock->netconn->state <= CONN_STATE_LISTENING)) {
            FILLP_LOGBUTT("set the pack interval of the socket %d to %u us", sockIndex, val);
            resource->flowControl.packInterval = val;
            NetconnSetPackInterval(sock->netconn, val);
        } else {
            FILLP_LOGERR("cannot set the pack interval when the sock is not in idle or listen state");
            return ERR_FAILURE;
        }
    } else {
        FILLP_LOGBUTT("set the pack interval of all the sockets to %u us", val);
        resource->flowControl.packInterval = val;
    }

    return FILLP_SUCCESS;
}

static FILLP_INT32 FtInnerAppConfigSetHelper(
    IN FILLP_UINT32 name,
    IN FILLP_CONST void *value,
    IN struct GlobalAppResource *resource,
    IN FILLP_INT sockIndex,
    IN struct FtSocket *sock)
{
    switch (name) {
        case FT_CONF_MAX_RATE:
            return FtAppConfigSetMaxRate(value, resource, sockIndex);

        case FT_CONF_MAX_RECV_RATE:
            return FtAppConfigSetMaxRecvRate(value, resource, sockIndex);

        case FT_CONF_ENABLE_NACK_DELAY:
            return FtAppConfigSetEnableNackDelay(value, resource, sockIndex);

        case FT_CONF_NACK_DELAY_TIMEOUT:
            return FtAppConfigSetNackDelayTimeout(value, resource, sockIndex);

        case FT_CONF_ENLARGE_PACK_INTERVAL:
            return FtAppEnlargePackInterval(value, resource, sockIndex, sock);

        case FT_CONF_TIMER_CONNECT:
            return FtAppTimerConfigSet(value, resource, sockIndex);

        case FT_CONF_TIMER_KEEP_ALIVE:
            return FtAppSetKeepAliveTime(value, resource, sockIndex);

        /* This timer value is in milliseconds */
        case FT_CONF_TIMER_CONNECTION_RETRY:
            return FtAppSetConnRetryTimeout(value, resource, sockIndex);

        /* This timer value is in milliseconds */
        case FT_CONF_TIMER_DISCONNECT_RETRY_TIMEOUT:
            return FtAppSetDisconnectRetryTimeout(value, resource, sockIndex);

        case FT_CONF_CONST_RATE:
            return FtAppConfigSetConstRate(value, resource, sockIndex);

        case FT_CONF_APP_FC_STASTICS_INTERVAL:
            return FtAppSetFcStatInterval(value, resource, sockIndex);

        case FT_CONF_APP_PACK_INTERVAL:
            return FtAppConfigSetPackInterval(value, resource, sockIndex);

        default:
            FILLP_LOGERR("invalid name %u!!!", name);
            return ERR_FAILURE;
    }
    return ERR_OK;
}

FILLP_INT32 FtInnerAppConfigSet(
    IN FILLP_UINT32 name,
    IN FILLP_CONST void *value,
    IN struct GlobalAppResource *resource,
    IN FILLP_INT sockIndex,
    IN struct FtSocket *sock)
{
    switch (name) {
        case FT_CONF_TX_BURST:
            return FtAppConfigSetTxBurst(value, resource, sockIndex);

        case FT_CONF_MAX_SERVER_ALLOW_SEND_CACHE:
#ifdef FILLP_SERVER_SUPPORT
            return FtAppSetMaxServerSendCache(value, resource, sockIndex);
#else
            FILLP_LOGERR("Server feature Not enabled : FT_CONF_MAX_SERVER_ALLOW_SEND_CACHE is server only option !!!");
            return ERR_FEATURE_MACRO_NOT_ENABLED;
#endif

        case FT_CONF_MAX_SERVER_ALLOW_RECV_CACHE:
#ifdef FILLP_SERVER_SUPPORT
            return FtAppSetMaxServeRecvCache(value, resource, sockIndex);
#else
            FILLP_LOGERR("Server feature Not enabled : FT_CONF_MAX_SERVER_ALLOW_RECV_CACHE is server only option !!!");
            return ERR_FEATURE_MACRO_NOT_ENABLED;
#endif

        case FT_CONF_SEND_CACHE:
            return FtAppConfigSetSendCache(value, resource, sockIndex);

        case FT_CONF_RECV_CACHE:
            return FtAppConfigSetRecvCache(value, resource, sockIndex);

        case FT_CONF_SEND_BUFFER_SIZE:
            return FtAppConfigSetSendBufSize(value, resource, sockIndex, sock);

        case FT_CONF_RECV_BUFFER_SIZE:
            return FtAppConfigSetRecvBufSize(value, resource, sockIndex, sock);

        case FT_CONF_OPPOSITE_SET_RATE:
#ifdef FILLP_SERVER_SUPPORT
            return FtAppConfigSetOppositeSetRate(value, resource, sockIndex);
#else
            FILLP_LOGERR("Server feature Not enabled : FT_CONF_OPPOSITE_SET_RATE is server only option !!!");
            return ERR_FEATURE_MACRO_NOT_ENABLED;
#endif

        case FT_CONF_PACKET_SIZE:
            return FtAppConfigSetPktSize(value, resource, sockIndex);

        case FT_CONF_SLOW_START:
            return FtAppConfigSetSlowStart(value, resource, sockIndex);

        default:  /* name bigger than FT_CONF_SLOW_START handle in FtInnerAppConfigSetHelper */
            return FtInnerAppConfigSetHelper(name, value, resource, sockIndex, sock);
    }
    return ERR_OK;
}

static FILLP_INT32 FtInnerAppConfigGetHelper(FILLP_UINT32 name, void *value,
    FILLP_CONST struct GlobalAppResource *resource)
{
    switch (name) {
        case FT_CONF_SLOW_START:
            *(FILLP_BOOL *)value = resource->flowControl.slowStart;
            break;

        case FT_CONF_MAX_RATE:
            *(FILLP_UINT32 *)value = resource->flowControl.maxRate;
            break;

        case FT_CONF_MAX_RECV_RATE:
            *(FILLP_UINT32 *)value = resource->flowControl.maxRecvRate;
            break;

        case FT_CONF_ENABLE_NACK_DELAY:
            *(FILLP_BOOL *)value = resource->common.enableNackDelay;
            break;

        case FT_CONF_NACK_DELAY_TIMEOUT:
            *(FILLP_LLONG *)value = resource->common.nackDelayTimeout;
            break;

        case FT_CONF_ENLARGE_PACK_INTERVAL:
            *(FILLP_BOOL *)value = resource->common.enlargePackIntervalFlag;
            break;

        case FT_CONF_TIMER_CONNECT:
            *(FILLP_UINT32 *)value = resource->common.connectTimeout;
            break;

        case FT_CONF_TIMER_CONNECTION_RETRY:
            *(FILLP_UINT16 *)value = resource->common.connRetryTimeout;
            break;

        case FT_CONF_TIMER_DISCONNECT_RETRY_TIMEOUT:
            *(FILLP_UINT32 *)value = resource->common.disconnectRetryTimeout;
            break;

        case FT_CONF_TIMER_KEEP_ALIVE:
            *(FILLP_UINT32 *)value = resource->common.keepAliveTime;
            break;

        case FT_CONF_CONST_RATE:
            *(FILLP_BOOL *)value = resource->flowControl.constRateEnbale;
            break;

        case FT_CONF_APP_FC_STASTICS_INTERVAL:
            *(FILLP_UINT32 *)value = resource->common.fcStasticsInterval;
            break;

        default:
            FILLP_LOGERR("invalid name %u!!!", name);
            return ERR_PARAM;
    }
    return ERR_OK;
}

static inline FILLP_INT32 FtAppGetMaxServerSendCache(void *value, FILLP_CONST struct GlobalAppResource *resource)
{
#ifdef FILLP_SERVER_SUPPORT
    *(FILLP_UINT32 *)value = resource->common.maxServerAllowSendCache;
    return ERR_OK;
#else
    FILLP_UNUSED_PARA(value);
    FILLP_UNUSED_PARA(resource);
    FILLP_LOGERR("Server feature Not enabled : FT_CONF_MAX_SERVER_ALLOW_SEND_CACHE is "
        "server only option so cannot GET !!!");
    return ERR_FEATURE_MACRO_NOT_ENABLED;
#endif
}

static inline FILLP_INT32 FtAppGetMaxServeRecvCache(void *value, FILLP_CONST struct GlobalAppResource *resource)
{
#ifdef FILLP_SERVER_SUPPORT
    *(FILLP_UINT32 *)value = resource->common.maxServerAllowRecvCache;
    return ERR_OK;
#else
    FILLP_UNUSED_PARA(value);
    FILLP_UNUSED_PARA(resource);
    FILLP_LOGERR("Server feature Not enabled : FT_CONF_MAX_SERVER_ALLOW_RECV_CACHE is "
        "server only option so cannot GET !!!");
    return ERR_FEATURE_MACRO_NOT_ENABLED;
#endif
}

static inline FILLP_INT32 FtAppConfigGetOppositeSetRate(void *value, FILLP_CONST struct GlobalAppResource *resource)
{
#ifdef FILLP_SERVER_SUPPORT
    *(FILLP_UINT32 *)value = resource->flowControl.oppositeSetRate;
    return ERR_OK;
#else
    FILLP_UNUSED_PARA(value);
    FILLP_UNUSED_PARA(resource);
    FILLP_LOGERR("Server feature Not enabled : FT_CONF_OPPOSITE_SET_RATE is "
        "server only option so cannot GET !!!");
    return ERR_FEATURE_MACRO_NOT_ENABLED;
#endif
}

/*******************************************************************
  Function      : FtInnerAppConfigGet
  Description   : Api is used to get Individual FILLP stack configuration item.
  Input         : FILLP_UINT32    name : Name of the config item to querry
                      (FILLP_CONFIG_LISTENUM)
                  void *value  : FILLP will store the current value for the config item.
                  void *param  : this is optional. only required for config items
                      which requires additional information to get the configuration value.
                  for ex:
                      For SOCKET option this will store the Socket index.
  Output        : NA
  Return        : FILLP_UINT32 SUCCESS/FAILURE
********************************************************************/
FILLP_INT32 FtInnerAppConfigGet(IN FILLP_UINT32 name, IO void *value,
    IN FILLP_CONST struct GlobalAppResource *resource)
{
    switch (name) {
        case FT_CONF_TX_BURST:
            *(FILLP_UINT16 *)value = (FILLP_UINT16)resource->udp.txBurst;
            break;

        case FT_CONF_SEND_CACHE:
            *(FILLP_UINT32 *)value = resource->common.sendCache;
            break;

        case FT_CONF_RECV_CACHE:
            *(FILLP_UINT32 *)value = resource->common.recvCache;
            break;

        case FT_CONF_MAX_SERVER_ALLOW_SEND_CACHE:
            return FtAppGetMaxServerSendCache(value, resource);

        case FT_CONF_MAX_SERVER_ALLOW_RECV_CACHE:
            return FtAppGetMaxServeRecvCache(value, resource);

        case FT_CONF_SEND_BUFFER_SIZE:
            *(FILLP_UINT32 *)value = resource->common.udpSendBufSize;
            break;

        case FT_CONF_RECV_BUFFER_SIZE:
            *(FILLP_UINT32 *)value = resource->common.recvBufSize;
            break;

        case FT_CONF_OPPOSITE_SET_RATE:
            return FtAppConfigGetOppositeSetRate(value, resource);

        case FT_CONF_PACKET_SIZE:
            *(FILLP_UINT16 *)value = resource->flowControl.pktSize;
            break;

        default: /* name bigger than FT_CONF_OPPOSITE_SET_RATE handle in FtInnerAppConfigGetHelper */
            return FtInnerAppConfigGetHelper(name, value, resource);
    }
    return ERR_OK;
}
