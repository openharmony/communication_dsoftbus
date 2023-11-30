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
        const char *eventName, HiSysEventParamType paramType, SoftbusEventForm *form, HiSysEventParam *param) \
    {                                                                                                         \
        if (Assigner##type(form->lnnExtra->filed, &param) && CopyString(param->name, eventName)) {            \
            param->t = paramType;                                                                             \
            return true;                                                                                      \
        }                                                                                                     \
        return false;                                                                                         \
    }

LNN_ASSIGNER(Errcode, Result, result)
LNN_ASSIGNER(Errcode, Errcode, errcode)
LNN_ASSIGNER(Int32, ConnectionId, connectionId)
LNN_ASSIGNER(Int32, AuthType, authType)
LNN_ASSIGNER(Int32, AuthId, authId)
LNN_ASSIGNER(Int32, LnnType, lnnType)
LNN_ASSIGNER(Int32, OnlineNum, onlineNum)
LNN_ASSIGNER(Int32, PeerDeviceAbility, peerDeviceAbility)
LNN_ASSIGNER(String, PeerDeviceInfo, peerDeviceInfo)
LNN_ASSIGNER(String, PeerIp, peerIp)
LNN_ASSIGNER(String, PeerBrMac, peerBrMac)
LNN_ASSIGNER(String, PeerBleMac, peerBleMac)
LNN_ASSIGNER(String, PeerWifiMac, peerWifiMac)
LNN_ASSIGNER(String, PeerPort, peerPort)
LNN_ASSIGNER(String, PeerUdid, peerUdid)
LNN_ASSIGNER(String, PeerNetworkId, peerNetworkId)
LNN_ASSIGNER(String, PeerDeviceType, peerDeviceType)
LNN_ASSIGNER(String, CallerPkg, callerPkg)
LNN_ASSIGNER(String, CalleePkg, calleePkg)

#define LNN_ASSIGNER_SIZE 19 // Size of g_connAssigners
static const HiSysEventParamAssigner g_lnnAssigners[] = {
    { "STAGE_RES",        HISYSEVENT_INT32,  LnnAssignerResult           },
    { "ERROR_CODE",       HISYSEVENT_INT32,  LnnAssignerErrcode          },
    { "CONN_ID",          HISYSEVENT_INT32,  LnnAssignerConnectionId     },
    { "AUTH_TYPE",        HISYSEVENT_INT32,  LnnAssignerAuthType         },
    { "AUTH_ID",          HISYSEVENT_INT32,  LnnAssignerAuthId           },
    { "LNN_TYPE",         HISYSEVENT_INT32,  LnnAssignerLnnType          },
    { "ONLINE_NUM",       HISYSEVENT_INT32,  LnnAssignerOnlineNum        },
    { "PEER_DEV_ABILITY", HISYSEVENT_INT32,  LnnAssignerPeerDeviceAbility},
    { "PEER_DEV_INFO",    HISYSEVENT_STRING, LnnAssignerPeerDeviceInfo   },
    { "PEER_IP",          HISYSEVENT_STRING, LnnAssignerPeerIp           },
    { "PEER_BR_MAC",      HISYSEVENT_STRING, LnnAssignerPeerBrMac        },
    { "PEER_BLE_MAC",     HISYSEVENT_STRING, LnnAssignerPeerBleMac       },
    { "PEER_WIFI_MAC",    HISYSEVENT_STRING, LnnAssignerPeerWifiMac      },
    { "PEER_PORT",        HISYSEVENT_INT32,  LnnAssignerPeerPort         },
    { "PEER_UDID",        HISYSEVENT_STRING, LnnAssignerPeerUdid         },
    { "PEER_NET_ID",      HISYSEVENT_STRING, LnnAssignerPeerNetworkId    },
    { "PEER_DEV_TYPE",    HISYSEVENT_INT32,  LnnAssignerPeerDeviceType   },
    { "HOST_PKG",         HISYSEVENT_STRING, LnnAssignerCallerPkg        },
    { "TO_CALL_PKG",      HISYSEVENT_STRING, LnnAssignerCalleePkg        },
    // Modification Note: remember updating LNN_ASSIGNER_SIZE
};


#define LNN_ALARM_ASSIGNER(type, filedName, filed)                                                            \
    static inline bool LnnAssigner##filedName(                                                                \
        const char *eventName, HiSysEventParamType paramType, SoftbusEventForm *form, HiSysEventParam *param) \
    {                                                                                                         \
        if (Assigner##type(form->lnnAlarmExtra->filed, &param) && CopyString(param->name, eventName)) {       \
            param->t = paramType;                                                                             \
            return true;                                                                                      \
        }                                                                                                     \
        return false;                                                                                         \
    }

LNN_ALARM_ASSIGNER(Errcode, AlarmResult, result)

#define LNN_ALARM_ASSIGNER_SIZE 1 // Size of g_lnnAlarmAssigners
static const HiSysEventParamAssigner g_lnnAlarmAssigners[] = {
    { "STAGE_RES",        HISYSEVENT_INT32,  LnnAssignerAlarmResult        },
    // Modification Note: remember updating LNN_ALARM_ASSIGNER_SIZE
};

static inline size_t ConvertLnnForm2Param(HiSysEventParam params[], size_t size, SoftbusEventForm *form)
{
    size_t validSize = 0;
    if (form == NULL || form->lnnExtra == NULL) {
        return validSize;
    }
    for (size_t i = 0; i < size; ++i) {
        HiSysEventParamAssigner assigner = g_lnnAssigners[i];
        if (assigner.Assign(assigner.name, assigner.type, form, &params[validSize])) {
            ++validSize;
        }
    }
    return validSize;
}

static inline size_t ConvertLnnAlarmForm2Param(HiSysEventParam params[], size_t size, SoftbusEventForm *form)
{
    size_t validSize = 0;
    if (form == NULL || form->lnnAlarmExtra == NULL) {
        return validSize;
    }
    for (size_t i = 0; i < size; ++i) {
        HiSysEventParamAssigner assigner = g_lnnAlarmAssigners[i];
        if (assigner.Assign(assigner.name, assigner.type, form, &params[validSize])) {
            ++validSize;
        }
    }
    return validSize;
}

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif // LNN_EVENT_CONVERTER_H
