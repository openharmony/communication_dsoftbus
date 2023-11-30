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

#ifndef CONN_EVENT_CONVERTER_H
#define CONN_EVENT_CONVERTER_H

#include "softbus_event_converter.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CONN_ASSIGNER(type, filedName, filed)                                                                 \
    static inline bool ConnAssigner##filedName(                                                               \
        const char *eventName, HiSysEventParamType paramType, SoftbusEventForm *form, HiSysEventParam *param) \
    {                                                                                                         \
        if (Assigner##type(form->connExtra->filed, &param) && CopyString(param->name, eventName)) {           \
            param->t = paramType;                                                                             \
            return true;                                                                                      \
        }                                                                                                     \
        return false;                                                                                         \
    }

CONN_ASSIGNER(Errcode, Result, result)
CONN_ASSIGNER(Errcode, Errcode, errcode)
CONN_ASSIGNER(Int32, ConnectionId, connectionId)
CONN_ASSIGNER(Int32, RequestId, requestId)
CONN_ASSIGNER(Int32, LinkType, linkType)
CONN_ASSIGNER(Int32, AuthType, authType)
CONN_ASSIGNER(Int32, AuthId, authId)
CONN_ASSIGNER(String, LnnType, lnnType)
CONN_ASSIGNER(Int32, ExpectRole, expectRole)
CONN_ASSIGNER(Int32, CostTime, costTime)
CONN_ASSIGNER(Int32, Rssi, rssi)
CONN_ASSIGNER(Int32, Load, load)
CONN_ASSIGNER(Int32, Frequency, frequency)
CONN_ASSIGNER(String, PeerIp, peerIp)
CONN_ASSIGNER(String, PeerBrMac, peerBrMac)
CONN_ASSIGNER(String, PeerBleMac, peerBleMac)
CONN_ASSIGNER(String, PeerWifiMac, peerWifiMac)
CONN_ASSIGNER(String, PeerPort, peerPort)
CONN_ASSIGNER(String, CallerPkg, callerPkg)
CONN_ASSIGNER(String, CalleePkg, calleePkg)

#define CONN_ASSIGNER_SIZE 20 // Size of g_connAssigners
static HiSysEventParamAssigner g_connAssigners[] = {
    { "STAGE_RES",     HISYSEVENT_INT32,  ConnAssignerResult      },
    { "ERROR_CODE",    HISYSEVENT_INT32,  ConnAssignerErrcode     },
    { "CONN_ID",       HISYSEVENT_INT32,  ConnAssignerConnectionId},
    { "REQ_ID",        HISYSEVENT_INT32,  ConnAssignerRequestId   },
    { "LINK_TYPE",     HISYSEVENT_INT32,  ConnAssignerLinkType    },
    { "AUTH_TYPE",     HISYSEVENT_INT32,  ConnAssignerAuthType    },
    { "AUTH_ID",       HISYSEVENT_INT32,  ConnAssignerAuthId      },
    { "LNN_TYPE",      HISYSEVENT_STRING, ConnAssignerLnnType     },
    { "EXPECT_ROLE",   HISYSEVENT_INT32,  ConnAssignerExpectRole  },
    { "COST_TIME",     HISYSEVENT_INT32,  ConnAssignerCostTime    },
    { "RSSI",          HISYSEVENT_INT32,  ConnAssignerRssi        },
    { "CHLOAD",        HISYSEVENT_INT32,  ConnAssignerLoad        },
    { "FREQ",          HISYSEVENT_INT32,  ConnAssignerFrequency   },
    { "PEER_IP",       HISYSEVENT_STRING, ConnAssignerPeerIp      },
    { "PEER_BR_MAC",   HISYSEVENT_STRING, ConnAssignerPeerBrMac   },
    { "PEER_BLE_MAC",  HISYSEVENT_STRING, ConnAssignerPeerBleMac  },
    { "PEER_WIFI_MAC", HISYSEVENT_STRING, ConnAssignerPeerWifiMac },
    { "PEER_PORT",     HISYSEVENT_STRING, ConnAssignerPeerPort    },
    { "HOST_PKG",      HISYSEVENT_STRING, ConnAssignerCallerPkg   },
    { "TO_CALL_PKG",   HISYSEVENT_STRING, ConnAssignerCalleePkg   },
    // Modification Note: remember updating CONN_ASSIGNER_SIZE
};

#define CONN_ALARM_ASSIGNER(type, filedName, filed)                                                           \
    static inline bool ConnAssigner##filedName(                                                               \
        const char *eventName, HiSysEventParamType paramType, SoftbusEventForm *form, HiSysEventParam *param) \
    {                                                                                                         \
        if (Assigner##type(form->connAlarmExtra->filed, &param) && CopyString(param->name, eventName)) {      \
            param->t = paramType;                                                                             \
            return true;                                                                                      \
        }                                                                                                     \
        return false;                                                                                         \
    }

CONN_ALARM_ASSIGNER(Errcode, AlarmResult, result)
CONN_ALARM_ASSIGNER(Errcode, AlarmErrcode, errcode)
CONN_ALARM_ASSIGNER(Int32, AlarmLinkType, linkType)
CONN_ALARM_ASSIGNER(Int32, Duration, duration)
CONN_ALARM_ASSIGNER(Int32, NetType, netType)

#define CONN_ALARM_ASSIGNER_SIZE 5 // Size of g_transAlarmAssigners
static const HiSysEventParamAssigner g_connAlarmAssigners[] = {
    { "STAGE_RES",     HISYSEVENT_INT32,  ConnAssignerAlarmResult      },
    { "ERROR_CODE",    HISYSEVENT_INT32,  ConnAssignerAlarmErrcode     },
    { "LINK_TYPE",     HISYSEVENT_INT32,  ConnAssignerAlarmLinkType    },
    { "DURATION",      HISYSEVENT_INT32,  ConnAssignerDuration         },
    { "NET_TYPE",      HISYSEVENT_INT32,  ConnAssignerNetType     },
    // Modification Note: remember updating CONN_ALARM_ASSIGNER_SIZE
};

static inline size_t ConvertConnForm2Param(HiSysEventParam params[], size_t size, SoftbusEventForm *form)
{
    size_t validSize = 0;
    if (form == NULL || form->connExtra == NULL) {
        return validSize;
    }
    for (size_t i = 0; i < size; ++i) {
        HiSysEventParamAssigner assigner = g_connAssigners[i];
        if (assigner.Assign(assigner.name, assigner.type, form, &params[validSize])) {
            ++validSize;
        }
    }
    return validSize;
}

static inline size_t ConvertConnAlarmForm2Param(HiSysEventParam params[], size_t size, SoftbusEventForm *form)
{
    size_t validSize = 0;
    if (form == NULL || form->connAlarmExtra == NULL) {
        return validSize;
    }
    for (size_t i = 0; i < size; ++i) {
        HiSysEventParamAssigner assigner = g_connAlarmAssigners[i];
        if (assigner.Assign(assigner.name, assigner.type, form, &params[validSize])) {
            ++validSize;
        }
    }
    return validSize;
}

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif // CONN_EVENT_CONVERTER_H
