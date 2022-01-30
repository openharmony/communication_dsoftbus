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

#ifdef __cplusplus
extern "C" {
#endif

static FILLP_INT FillpValidateSockAllocStateWithRdwaitAcquired(struct FtSocket *sock, FILLP_INT sockIndex)
{
    if ((sock)->allocState != SOCK_ALLOC_STATE_COMM) {
        FILLP_LOGERR("Invalid socket Type. This function allowed only for communication socket = %d", sockIndex);
        (void)SYS_ARCH_RWSEM_RDPOST(&((sock)->sockConnSem));
        SET_ERRNO(FILLP_ENOTSOCK);
        return -1;
    }
    return 0;
}

static FILLP_INT FtGetRightAppResourceByIndex(struct GlobalAppResource **resource, FILLP_INT sockIndex)
{
    struct FtSocket *sock = FILLP_NULL_PTR;
    if (sockIndex != FILLP_MAX_UNSHORT_VAL) {
        sock = SockGetSocket(sockIndex);
        if (sock == FILLP_NULL_PTR) {
            FILLP_LOGERR("Invalid fillp_sock_id:%d", sockIndex);
            return ERR_PARAM;
        }

        /* All configuration changes are not write protected, so other thread can read old value when this
        function is getting executed. but this is ok as per fillp design. */
        if (SYS_ARCH_RWSEM_TRYRDWAIT(&sock->sockConnSem) != ERR_OK) {
            FILLP_LOGERR("Socket-%d state is changing,maybe closing", sockIndex);
            return ERR_FAILURE;
        }

        if (FillpValidateSockAllocStateWithRdwaitAcquired(sock, sockIndex)) {
            return -1;
        }

        *resource = &sock->resConf;
    } else {
        *resource = &g_appResource;
    }

    return ERR_OK;
}

static FILLP_INT32 FtCheckCofigPar(FILLP_CONST FillpAppGlobalConfigsSt *resource, FILLP_INT sockIndex)
{
    if ((sockIndex != FILLP_MAX_UNSHORT_VAL) && ((g_spunge == FILLP_NULL_PTR) ||
        (g_spunge->hasInited == FILLP_FALSE))) {
        FILLP_LOGERR("Cannot Set Socket level config value before stack initialization fillp_sock_id:%d !!!",
                     sockIndex);
        return ERR_PARAM;
    }
    FILLP_INT32 ret = FtAppValidateConfigParams(resource);
    if (ret == ERR_FAILURE) {
        return ERR_PARAM;
    }
    return ERR_OK;
}

static void CopyGlobalConfig(FILLP_CONST FillpAppGlobalConfigsSt *globalConfig, struct GlobalAppResource *resource)
{
    if (globalConfig == FILLP_NULL_PTR || resource == FILLP_NULL_PTR) {
        return;
    }
    resource->udp.txBurst = globalConfig->udp.txBurst;

#ifdef FILLP_SERVER_SUPPORT
    resource->common.maxServerAllowSendCache = globalConfig->common.maxServerAllowSendCache;
    resource->common.maxServerAllowRecvCache = globalConfig->common.maxServerAllowRecvCache;
#endif

    resource->common.connectTimeout = globalConfig->timers.connectTimeout;
    resource->common.keepAliveTime = globalConfig->timers.keepAliveTime;
    resource->common.udpSendBufSize = globalConfig->common.udpSendBufSize;
    resource->common.recvBufSize = globalConfig->common.recvBufSize;

    resource->common.enlargePackIntervalFlag = globalConfig->common.enlargePackIntervalFlag;
    resource->common.enableNackDelay = globalConfig->common.enableNackDelay;
    resource->common.nackDelayTimeout = globalConfig->common.nackDelayTimeout;
    resource->common.sendCache = globalConfig->common.sendCache;
    resource->common.recvCache = globalConfig->common.recvCache;
    resource->common.connRetryTimeout = globalConfig->timers.connRetrytimeout;
    resource->common.disconnectRetryTimeout = globalConfig->timers.disconnectRetrytimeout;

    resource->flowControl.constRateEnbale = globalConfig->flowControl.constRateEnbale;
    resource->flowControl.maxRate = globalConfig->flowControl.maxRate;
    resource->flowControl.maxRecvRate = globalConfig->flowControl.maxRecvRate;

    /* Implementing Fair Bandwidth sharing among sockets */
#ifdef FILLP_SERVER_SUPPORT
    resource->flowControl.oppositeSetRate = globalConfig->flowControl.oppositeSetRate;
#endif

    resource->flowControl.pktSize = globalConfig->flowControl.pktSize;
    resource->flowControl.slowStart = globalConfig->flowControl.slowStart;
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
FILLP_INT32 FtAppInitConfigSet(IN FILLP_CONST FillpAppGlobalConfigsSt *globalConfig, IN FILLP_INT sockIndex)
{
    struct FtSocket *sock = FILLP_NULL_PTR;
    struct GlobalAppResource *resource = FILLP_NULL_PTR;
    FILLP_INT32 ret = FtCheckCofigPar(globalConfig, sockIndex);
    if (ret != ERR_OK) {
        return ret;
    }

    ret = FtGetRightAppResourceByIndex(&resource, sockIndex);
    if (ret != ERR_OK) {
        return ret;
    }

    CopyGlobalConfig(globalConfig, resource);

    /* need to post in 2 cases:
    a) if the config is being set for a particular socket
    b) if set for global after stack init, since it needs to be updated on all
    the existing socket.
    So, if the stack is not init and it is being set globally, then no need
    to post it, since there are no sockets for which it needs to be set */
    ret = FtAppConfigInitNackDelayCfg(sockIndex, resource);
    if (ret != ERR_OK) {
        if (sockIndex != FILLP_MAX_UNSHORT_VAL) {
            sock = SockGetSocket(sockIndex);
            (void)SYS_ARCH_RWSEM_RDPOST(&sock->sockConnSem);
        }

        return ret;
    }

    if (sockIndex != FILLP_MAX_UNSHORT_VAL) {
        sock = SockGetSocket(sockIndex);
        (void)SYS_ARCH_RWSEM_RDPOST(&sock->sockConnSem);
    }

    return ERR_OK;
}

static void CopySockConfig(FillpAppGlobalConfigsSt *gresource, struct GlobalAppResource *resource)
{
    if (gresource == FILLP_NULL_PTR || resource == FILLP_NULL_PTR) {
        return;
    }
    gresource->udp.txBurst = (FILLP_UINT16)resource->udp.txBurst;

#ifdef FILLP_SERVER_SUPPORT
    gresource->common.maxServerAllowSendCache = resource->common.maxServerAllowSendCache;
    gresource->common.maxServerAllowRecvCache = resource->common.maxServerAllowRecvCache;
#endif

    gresource->common.udpSendBufSize = resource->common.udpSendBufSize;
    gresource->common.recvBufSize = resource->common.recvBufSize;
    gresource->timers.connectTimeout = resource->common.connectTimeout;
    gresource->timers.keepAliveTime = resource->common.keepAliveTime;

    gresource->common.enlargePackIntervalFlag = resource->common.enlargePackIntervalFlag;
    gresource->common.enableNackDelay = resource->common.enableNackDelay;
    gresource->common.nackDelayTimeout = resource->common.nackDelayTimeout;
    gresource->common.sendCache = resource->common.sendCache;
    gresource->common.recvCache = resource->common.recvCache;
    gresource->timers.connRetrytimeout = resource->common.connRetryTimeout;
    gresource->timers.disconnectRetrytimeout = resource->common.disconnectRetryTimeout;

    gresource->flowControl.constRateEnbale = resource->flowControl.constRateEnbale;
    gresource->flowControl.maxRate = resource->flowControl.maxRate;
    gresource->flowControl.maxRecvRate = resource->flowControl.maxRecvRate;

#ifdef FILLP_SERVER_SUPPORT
    gresource->flowControl.oppositeSetRate = resource->flowControl.oppositeSetRate;
#endif
    gresource->flowControl.pktSize = resource->flowControl.pktSize;
    gresource->flowControl.slowStart = resource->flowControl.slowStart;
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
FILLP_INT32 FtAppInitConfigGet(IO FillpAppGlobalConfigsSt *globalResource, IN FILLP_INT sockIndex)
{
    struct FtSocket *sock = FILLP_NULL_PTR;
    struct GlobalAppResource *resource = FILLP_NULL_PTR;
    FILLP_INT ret;

    if ((sockIndex != FILLP_MAX_UNSHORT_VAL) && ((g_spunge == FILLP_NULL_PTR) ||
        (g_spunge->hasInited == FILLP_FALSE))) {
        FILLP_LOGERR("Cannot Get Socket level config value before stack initialization fillp_sock_id:%d!!!",
                     sockIndex);
        return ERR_PARAM;
    }

    ret = FtGetRightAppResourceByIndex(&resource, sockIndex);
    if (ret != ERR_OK) {
        return ret;
    }
    CopySockConfig(globalResource, resource);
    if (sockIndex != FILLP_MAX_UNSHORT_VAL) {
        sock = SockGetSocket(sockIndex);
        if (sock == FILLP_NULL_PTR) {
            FILLP_LOGERR("Invalid fillp_sock_id:%d", sockIndex);
            return ERR_PARAM;
        }

        (void)SYS_ARCH_RWSEM_RDPOST(&sock->sockConnSem);
    }

    return ERR_OK;
}

static FILLP_INT32 FtInnerValidateAppConfigSet(FILLP_UINT32 name, struct FtSocket *sock, FILLP_INT sockIndex)
{
    if ((name == FT_CONF_MAX_SERVER_ALLOW_SEND_CACHE) || (name == FT_CONF_MAX_SERVER_ALLOW_RECV_CACHE)) {
        if (sock->isListenSock != FILLP_TRUE) {
            FILLP_LOGERR("Cannot set option name = %u for non-server socket, isListenSock= %u. fillp_sock_id:%d",
                         name, sock->isListenSock, sockIndex);
            return ERR_PARAM;
        }
    }

    if ((name == FT_CONF_SEND_CACHE) || (name == FT_CONF_RECV_CACHE) || (name == FT_CONF_PACKET_SIZE)) {
        if (sock->netconn != FILLP_NULL_PTR) {
            if (sock->netconn->state == CONN_STATE_CONNECTING) {
                FILLP_LOGERR("Cannot set option name = %u during connection, state= %u. fillp_sock_id:%d", name,
                             sock->netconn->state, sockIndex);

                return ERR_PARAM;
            }
        }
    }

    if ((name == FT_CONF_ENABLE_NACK_DELAY) && (sockIndex != FILLP_MAX_UNSHORT_VAL)) {
        FILLP_LOGERR("Cannot set option name = %u for individual sockets. fillp_sock_id:%d", name, sockIndex);
        return ERR_PARAM;
    }

    return FILLP_SUCCESS;
}

FILLP_INT32 FtSetConfigApp(IN FILLP_UINT32 name, IN FILLP_CONST void *value, IN FILLP_CONST void *param)
{
    struct FtSocket *sock = FILLP_NULL_PTR;
    struct GlobalAppResource *resource = FILLP_NULL_PTR;
    FILLP_INT sockIndex;
    FILLP_INT32 ret;

    FILLP_LOGINF("name:%u", name);

    if (param == FILLP_NULL_PTR) {
        FILLP_LOGERR("Parameter Error!");
        return ERR_NULLPTR;
    }

    sockIndex = *(FILLP_INT *)param;
    if (sockIndex != FILLP_CONFIG_ALL_SOCKET) {
        if ((g_spunge == FILLP_NULL_PTR) || (g_spunge->hasInited == FILLP_FALSE)) {
            FILLP_LOGERR("Cannot set Socket level config value before stack initialization fillp_sock_id:%d",
                         sockIndex);
            return ERR_PARAM;
        }

        sock = SockGetSocket(sockIndex);
        if (sock == FILLP_NULL_PTR) {
            FILLP_LOGERR("Invalid fillp_sock_id:%d", sockIndex);
            return ERR_PARAM;
        }

        /* All configuration changes are not write protected, so other thread can read old value when this
        function is getting executed. but this is ok as per fillp design. */
        if (SYS_ARCH_RWSEM_TRYRDWAIT(&sock->sockConnSem) != ERR_OK) {
            FILLP_LOGERR("Socket-%d State is changing,maybe closing", sockIndex);
            return ERR_FAILURE;
        }

        if (FillpValidateSockAllocStateWithRdwaitAcquired(sock, sockIndex)) {
            return -1;
        }

        ret = FtInnerValidateAppConfigSet(name, sock, sockIndex);
        if (ret != FILLP_SUCCESS) {
            (void)SYS_ARCH_RWSEM_RDPOST(&sock->sockConnSem);
            return ret; /* No need to log, already error is logged inside FtInnerValidateAppConfigSet */
        }

        resource = &sock->resConf;
        ret = FtInnerAppConfigSet(name, value, resource, sockIndex, sock);
        (void)SYS_ARCH_RWSEM_RDPOST(&sock->sockConnSem);
    } else {
        resource = &g_appResource;
        ret = FtInnerAppConfigSet(name, value, resource, sockIndex, sock);
    }
    FILLP_LOGINF("name:%u,fillp_sock_id:%d,ret:%d", name, sockIndex, ret);
    return ret;
}

static FILLP_INT32 FtCheckSockValid(struct FtSocket *sock)
{
    struct FtNetconn *netconn = FILLP_NULL_PTR;
    if ((sock->netconn == FILLP_NULL_PTR) || (sock->allocState == SOCK_ALLOC_STATE_FREE)) {
        FILLP_LOGERR("ERR_NULLPTR sock->netconn or sock->allocState is SOCK_ALLOC_STATE_FREE");
        return ERR_NULLPTR;
    }

    netconn = (struct FtNetconn *)(sock->netconn);
    if (netconn->pcb == FILLP_NULL_PTR) {
        FILLP_LOGERR("ERR_NULLPTR netconn->pcb");
        return ERR_NULLPTR;
    }

    return ERR_OK;
}

static FILLP_INT32 FtGetAppFcPeriodRecvRate(struct FtSocket *sock, FILLP_UINT32 *value)
{
    struct FtNetconn *netconn = FILLP_NULL_PTR;
    struct FillpStatisticsPcb *statisticsPcb = FILLP_NULL_PTR;
    if (FtCheckSockValid(sock) != ERR_OK) {
        return -1;
    }
    netconn = (struct FtNetconn *)(sock->netconn);
    statisticsPcb = &(netconn->pcb->fpcb.statistics);
    *value = statisticsPcb->appFcStastics.periodRecvRate;

    return ERR_OK;
}

static FILLP_INT32 FtGetAppFcPeriodRecvRateBps(struct FtSocket *sock, FILLP_ULLONG *value)
{
    struct FtNetconn *netconn = FILLP_NULL_PTR;
    struct FillpStatisticsPcb *statisticsPcb = FILLP_NULL_PTR;
    if (FtCheckSockValid(sock) != ERR_OK) {
        return -1;
    }
    netconn = (struct FtNetconn *)(sock->netconn);
    statisticsPcb = &(netconn->pcb->fpcb.statistics);
    *value = statisticsPcb->appFcStastics.periodRecvRateBps;
    return ERR_OK;
}

static FILLP_INT32 FtGetAppFcPeriodRecvPktLost(struct FtSocket *sock, FILLP_UINT32 *value)
{
    struct FtNetconn *netconn = FILLP_NULL_PTR;
    struct FillpStatisticsPcb *statisticsPcb = FILLP_NULL_PTR;
    if (FtCheckSockValid(sock) != ERR_OK) {
        return -1;
    }
    netconn = (struct FtNetconn *)(sock->netconn);
    statisticsPcb = &(netconn->pcb->fpcb.statistics);
    *value = statisticsPcb->appFcStastics.periodRecvPktLoss;

    return ERR_OK;
}

static FILLP_INT32 FtGetAppFcPeriodStastics(struct FtSocket *sock, void *value)
{
    struct FtNetconn *netconn = FILLP_NULL_PTR;
    struct FillAppFcStastics *appFcStastics = FILLP_NULL_PTR;
    FillpAppFcStasticsSt *app_fc_stastics_out = (FillpAppFcStasticsSt *)value;

    if (FtCheckSockValid(sock) != ERR_OK) {
        return -1;
    }

    netconn = (struct FtNetconn *)(sock->netconn);
    appFcStastics = &(netconn->pcb->fpcb.statistics.appFcStastics);

    app_fc_stastics_out->periodRtt = appFcStastics->periodRtt;
    app_fc_stastics_out->periodRecvPktLoss = appFcStastics->periodRecvPktLoss;
    app_fc_stastics_out->periodRecvRate = appFcStastics->periodRecvRate;
    app_fc_stastics_out->periodRecvPktLossHighPrecision = appFcStastics->periodRecvPktLossHighPrecision;
    app_fc_stastics_out->periodSendPktLossHighPrecision = appFcStastics->periodSendPktLossHighPrecision;
    app_fc_stastics_out->periodRecvRateBps = appFcStastics->periodRecvRateBps;
    app_fc_stastics_out->periodSendRateBps = appFcStastics->periodSendRateBps;
    app_fc_stastics_out->jitter = FILLP_UTILS_US2MS(sock->jitter);

    return ERR_OK;
}

static FILLP_INT32 FtGetSockValue(void *value, struct FtSocket *sock, FILLP_UINT32 name)
{
    struct GlobalAppResource *resource = FILLP_NULL_PTR;
    FILLP_INT32 ret;
    switch (name) {
        case FT_CONF_RECV_JITTER:
            *(FILLP_LLONG *)value = sock->jitter;
            ret = ERR_OK;
            break;
        case FT_CONF_APP_FC_RECV_RATE:
            ret = FtGetAppFcPeriodRecvRate(sock, value);
            break;
        case FT_CONF_APP_FC_RECV_RATE_BPS:
            ret = FtGetAppFcPeriodRecvRateBps(sock, value);
            break;
        case FT_CONF_APP_FC_RECV_PKT_LOSS:
            ret = FtGetAppFcPeriodRecvPktLost(sock, value);
            break;
        case FT_CONF_APP_FC_STATISTICS:
            ret = FtGetAppFcPeriodStastics(sock, value);
            break;
        default:
            resource = &sock->resConf;
            ret = FtInnerAppConfigGet(name, value, resource);
            break;
    }
    return ret;
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
FILLP_INT32 FtGetConfigApp(IN FILLP_UINT32 name, IO void *value, IN FILLP_CONST void *param)
{
    struct FtSocket *sock = FILLP_NULL_PTR;
    FILLP_INT sockIndex;
    FILLP_INT32 ret;

    if (param == FILLP_NULL_PTR) {
        FILLP_LOGERR("Invalid parameter");
        return ERR_NULLPTR;
    }

    sockIndex = *(FILLP_INT *)param;
    if (sockIndex != FILLP_MAX_UNSHORT_VAL) {
        if ((g_spunge == FILLP_NULL_PTR) || (g_spunge->hasInited == FILLP_FALSE)) {
            FILLP_LOGERR("Cannot set Socket level config value before stack initialization fillp_sock_id:%d",
                         sockIndex);
            return ERR_PARAM;
        }

        sock = SockGetSocket(sockIndex);
        if (sock == FILLP_NULL_PTR) {
            FILLP_LOGERR("Invalid fillp_sock_id:%d", sockIndex);
            return ERR_PARAM;
        }

        /* All configuration changes are not write protected, so other thread can read old value when this
        function is getting executed. but this is ok as per fillp design. */
        if (SYS_ARCH_RWSEM_TRYRDWAIT(&sock->sockConnSem) != ERR_OK) {
            FILLP_LOGERR("Socket-%d state is changing,maybe closing", sockIndex);
            return ERR_FAILURE;
        }

        if (FillpValidateSockAllocStateWithRdwaitAcquired(sock, sockIndex)) {
            return -1;
        }
        ret = FtGetSockValue(value, sock, name);
        (void)SYS_ARCH_RWSEM_RDPOST(&sock->sockConnSem);
    } else {
        struct GlobalAppResource *resource = &g_appResource;
        ret = FtInnerAppConfigGet(name, value, resource);
    }

    FILLP_LOGINF("name:%u,fillp_sock_id:%d,ret:%d", name, sockIndex, ret);
    return ret;
}

#ifdef __cplusplus
}
#endif
