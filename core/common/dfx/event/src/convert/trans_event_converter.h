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

#define TRANS_ASSIGNER(dataType, fieldName, filed)                                                    \
    static inline bool TransAssigner##fieldName(                                                      \
        const char name[], HiSysEventParamType type, SoftbusEventForm form, SoftbusEventParam *param) \
    {                                                                                                 \
        if (!Assigner##dataType(form.transExtra.filed, &param->value)) {                              \
            return false;                                                                             \
        }                                                                                             \
        param->value.t = type;                                                                        \
        return CopyString(param->value.name, name);                                                   \
    }

TRANS_ASSIGNER(Int32, DataType, dataType)
TRANS_ASSIGNER(Int32, PeerNetworkId, peerNetworkId)
TRANS_ASSIGNER(Int32, LinkType, linkType)
TRANS_ASSIGNER(Int32, ChannelType, channelType)
TRANS_ASSIGNER(Int32, ChannelId, channelId)
TRANS_ASSIGNER(Int32, PeerChannelId, peerChannelId)
TRANS_ASSIGNER(Int32, RequestId, requestId)
TRANS_ASSIGNER(Int32, ConnectionId, connectionId)
TRANS_ASSIGNER(Int32, CostTime, costTime)
TRANS_ASSIGNER(Int32, Result, result)
TRANS_ASSIGNER(Int32, Errcode, errcode)
TRANS_ASSIGNER(String, CallerPkg, callerPkg)
TRANS_ASSIGNER(String, CalleePkg, calleePkg)
TRANS_ASSIGNER(String, SocketName, socketName)

#define TRANS_ASSIGNER_SIZE 14 // Size of g_transAssigners
static const SoftbusEventParamAssigner g_transAssigners[] = {
    {"DATA_TYPE",        HISYSEVENT_INT32,  TransAssignerDataType     },
    { "PEER_NETID",      HISYSEVENT_INT32,  TransAssignerPeerNetworkId},
    { "LINK_TYPE",       HISYSEVENT_INT32,  TransAssignerLinkType     },
    { "LOCAL_CHAN_TYPE", HISYSEVENT_INT32,  TransAssignerChannelType  },
    { "CHAN_ID",         HISYSEVENT_INT32,  TransAssignerChannelId    },
    { "PEER_CHAN_ID",    HISYSEVENT_INT32,  TransAssignerPeerChannelId},
    { "REQ_ID",          HISYSEVENT_INT32,  TransAssignerRequestId    },
    { "CONN_ID",         HISYSEVENT_INT32,  TransAssignerConnectionId },
    { "COST_TIME",       HISYSEVENT_INT32,  TransAssignerCostTime     },
    { "STAGE_RES",       HISYSEVENT_INT32,  TransAssignerResult       },
    { "ERROR_CODE",      HISYSEVENT_INT32,  TransAssignerErrcode      },
    { "HOST_PKG",        HISYSEVENT_STRING, TransAssignerCallerPkg    },
    { "TO_CALL_PKG",     HISYSEVENT_STRING, TransAssignerCalleePkg    },
    { "SOCKET_NAME",     HISYSEVENT_STRING, TransAssignerSocketName   },
 // Modification Note: remember updating TRANS_ASSIGNER_SIZE
};

static inline void ConvertTransForm2Param(SoftbusEventParam params[], size_t size, SoftbusEventForm form)
{
    for (size_t i = 0; i < size; ++i) {
        SoftbusEventParamAssigner assigner = g_transAssigners[i];
        if (assigner.Assign(assigner.name, assigner.type, form, &params[i])) {
            params[i].isValid = true;
            continue;
        }
        params[i].isValid = false;
    }
}

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif // TRANS_EVENT_CONVERTER_H
