/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef TRANS_EVENT_CONVERTER_H
#define TRANS_EVENT_CONVERTER_H

#include "softbus_event_converter.h"

#ifdef __cplusplus
extern "C" {
#endif

#define TRANS_ASSIGNER(type, filedName, filed)                                                                \
    static inline bool TransAssigner##filedName(                                                              \
        const char eventName[], HiSysEventParamType paramType, SoftbusEventForm form, HiSysEventParam *param) \
    {                                                                                                         \
        if (Assigner##type(form.transExtra.filed, &param) && CopyString(param->name, eventName)) {            \
            param->t = paramType;                                                                             \
            return true;                                                                                      \
        }                                                                                                     \
        return false;                                                                                         \
    }

TRANS_ASSIGNER(Errcode, Result, result)
TRANS_ASSIGNER(Errcode, Errcode, errcode)
TRANS_ASSIGNER(String, SocketName, socketName)
TRANS_ASSIGNER(Int32, DataType, dataType)
TRANS_ASSIGNER(Int32, ChannelType, channelType)
TRANS_ASSIGNER(Int32, LaneId, laneId)
TRANS_ASSIGNER(Int32, PreferLinkType, preferLinkType)
TRANS_ASSIGNER(Int32, LaneTransType, laneTransType)
TRANS_ASSIGNER(Int32, ChannelId, channelId)
TRANS_ASSIGNER(Int32, RequestId, requestId)
TRANS_ASSIGNER(Int32, ConnectionId, connectionId)
TRANS_ASSIGNER(Int32, LinkType, linkType)
TRANS_ASSIGNER(Int32, AuthId, authId)
TRANS_ASSIGNER(Int32, SocketFd, socketFd)
TRANS_ASSIGNER(Int32, CostTime, costTime)
TRANS_ASSIGNER(Int32, ChannelScore, channelScore)
TRANS_ASSIGNER(Int32, PeerChannelId, peerChannelId)
TRANS_ASSIGNER(String, PeerNetworkId, peerNetworkId)
TRANS_ASSIGNER(String, CallerPkg, callerPkg)
TRANS_ASSIGNER(String, CalleePkg, calleePkg)

#define TRANS_ASSIGNER_SIZE 20 // Size of g_transAssigners
static const HiSysEventParamAssigner g_transAssigners[] = {
    {"STAGE_RES",         HISYSEVENT_INT32,  TransAssignerResult        },
    { "ERROR_CODE",       HISYSEVENT_INT32,  TransAssignerErrcode       },
    { "SOCKET_NAME",      HISYSEVENT_STRING, TransAssignerSocketName    },
    { "DATA_TYPE",        HISYSEVENT_INT32,  TransAssignerDataType      },
    { "LOGIC_CHAN_TYPE",  HISYSEVENT_INT32,  TransAssignerChannelType   },
    { "LANE_ID",          HISYSEVENT_INT32,  TransAssignerLaneId        },
    { "PREFER_LINK_TYPE", HISYSEVENT_INT32,  TransAssignerPreferLinkType},
    { "LANE_TRANS_TYPE",  HISYSEVENT_INT32,  TransAssignerLaneTransType },
    { "CHAN_ID",          HISYSEVENT_INT32,  TransAssignerChannelId     },
    { "REQ_ID",           HISYSEVENT_INT32,  TransAssignerRequestId     },
    { "CONN_ID",          HISYSEVENT_INT32,  TransAssignerConnectionId  },
    { "LINK_TYPE",        HISYSEVENT_INT32,  TransAssignerLinkType      },
    { "AUTH_ID",          HISYSEVENT_INT32,  TransAssignerAuthId        },
    { "SOCKET_FD",        HISYSEVENT_INT32,  TransAssignerSocketFd      },
    { "COST_TIME",        HISYSEVENT_INT32,  TransAssignerCostTime      },
    { "CHAN_SCORE",       HISYSEVENT_INT32,  TransAssignerChannelScore  },
    { "PEER_CHAN_ID",     HISYSEVENT_INT32,  TransAssignerPeerChannelId },
    { "PEER_NET_ID",      HISYSEVENT_STRING, TransAssignerPeerNetworkId },
    { "HOST_PKG",         HISYSEVENT_STRING, TransAssignerCallerPkg     },
    { "TO_CALL_PKG",      HISYSEVENT_STRING, TransAssignerCalleePkg     },
 // Modification Note: remember updating TRANS_ASSIGNER_SIZE
};

static inline void ConvertTransForm2Param(HiSysEventParam params[], size_t size, SoftbusEventForm form)
{
    for (size_t i = 0; i < size; ++i) {
        HiSysEventParamAssigner assigner = g_transAssigners[i];
        if (!assigner.Assign(assigner.name, assigner.type, form, &params[i])) {
            COMM_LOGE(COMM_DFX, "assign event fail, name=%s", assigner.name);
        }
    }
}

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif // TRANS_EVENT_CONVERTER_H
