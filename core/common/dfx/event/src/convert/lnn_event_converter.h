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

#ifndef LNN_EVENT_CONVERTER_H
#define LNN_EVENT_CONVERTER_H

#include "softbus_event_converter.h"

#ifdef __cplusplus
extern "C" {
#endif

#define LNN_ASSIGNER(type, filedName, filed)                                                                  \
    static inline bool LnnAssigner##filedName(                                                                \
        const char eventName[], HiSysEventParamType paramType, SoftbusEventForm form, HiSysEventParam *param) \
    {                                                                                                         \
        if (Assigner##type(form.lnnExtra.filed, &param) && CopyString(param->name, eventName)) {             \
            param->t = paramType;                                                                             \
            return true;                                                                                      \
        }                                                                                                     \
        return false;                                                                                         \
    }

LNN_ASSIGNER(Int32, PeerNetworkId, peerNetworkId)
LNN_ASSIGNER(Int32, ConnectionId, connectionId)
LNN_ASSIGNER(Int32, AuthType, authType)
LNN_ASSIGNER(Int32, AuthId, authId)
LNN_ASSIGNER(Int32, PeerDeviceType, peerDeviceType)
LNN_ASSIGNER(Int32, PeerDeviceAbility, peerDeviceAbility)
LNN_ASSIGNER(Int32, PeerDeviceInfo, peerDeviceInfo)
LNN_ASSIGNER(Int32, OnlineNum, onlineNum)
LNN_ASSIGNER(Int32, Result, result)
LNN_ASSIGNER(Errcode, Errcode, errcode)
LNN_ASSIGNER(String, CallerPkg, callerPkg)
LNN_ASSIGNER(String, CalleePkg, calleePkg)
LNN_ASSIGNER(String, PeerBrMac, peerBrMac)
LNN_ASSIGNER(String, PeerBleMac, peerBleMac)
LNN_ASSIGNER(String, PeerWifiMac, peerWifiMac)
LNN_ASSIGNER(String, PeerIp, peerIp)
LNN_ASSIGNER(String, PeerPort, peerPort)

#define LNN_ASSIGNER_SIZE 17 // Size of g_connAssigners
static const HiSysEventParamAssigner g_lnnAssigners[] = {
    {"PEER_NETID",        HISYSEVENT_INT32,  LnnAssignerPeerNetworkId    },
    { "CONN_ID",          HISYSEVENT_INT32,  LnnAssignerConnectionId     },
    { "AUTH_TYPE",        HISYSEVENT_INT32,  LnnAssignerAuthType         },
    { "AUTH_ID",          HISYSEVENT_INT32,  LnnAssignerAuthId           },
    { "PEER_DEV_TYPE",    HISYSEVENT_INT32,  LnnAssignerPeerDeviceType   },
    { "PEER_DEV_ABILITY", HISYSEVENT_INT32,  LnnAssignerPeerDeviceAbility},
    { "PEER_DEV_INFO",    HISYSEVENT_INT32,  LnnAssignerPeerDeviceInfo   },
    { "ONLINE_NUM",       HISYSEVENT_INT32,  LnnAssignerOnlineNum        },
    { "STAGE_RES",        HISYSEVENT_INT32,  LnnAssignerResult           },
    { "ERROR_CODE",       HISYSEVENT_INT32,  LnnAssignerErrcode          },
    { "HOST_PKG",         HISYSEVENT_STRING, LnnAssignerCallerPkg        },
    { "TO_CALL_PKG",      HISYSEVENT_STRING, LnnAssignerCalleePkg        },
    { "PEER_BR_MAC",      HISYSEVENT_STRING, LnnAssignerPeerBrMac        },
    { "PEER_BLE_MAC",     HISYSEVENT_STRING, LnnAssignerPeerBleMac       },
    { "PEER_WIFI_MAC",    HISYSEVENT_STRING, LnnAssignerPeerWifiMac      },
    { "PEER_IP",          HISYSEVENT_STRING, LnnAssignerPeerIp           },
    { "PEER_PORT",        HISYSEVENT_STRING, LnnAssignerPeerPort         },
 // Modification Note: remember updating LNN_ASSIGNER_SIZE
};

static inline void ConvertLnnForm2Param(HiSysEventParam params[], size_t size, SoftbusEventForm form)
{
    for (size_t i = 0; i < size; ++i) {
        HiSysEventParamAssigner assigner = g_lnnAssigners[i];
        if (!assigner.Assign(assigner.name, assigner.type, form, &params[i])) {
            COMM_LOGE(COMM_DFX, "assign event fail, name=%s", assigner.name);
        }
    }
}
#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif // LNN_EVENT_CONVERTER_H
