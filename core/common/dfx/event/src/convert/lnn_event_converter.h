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

#define LNN_ASSIGNER(type, fieldName, field)                                                                  \
    static inline bool LnnAssigner##fieldName(                                                                \
        const char *eventName, HiSysEventParamType paramType, SoftbusEventForm *form, HiSysEventParam *param) \
    {                                                                                                         \
        if (Assigner##type(form->lnnExtra->field, &param) &&                                                  \
            CopyString(param->name, eventName, MAX_LENGTH_OF_PARAM_NAME)) {                                   \
            param->t = paramType;                                                                             \
            return true;                                                                                      \
        }                                                                                                     \
        return false;                                                                                         \
    }

LNN_ASSIGNER(Errcode, Result, result)
LNN_ASSIGNER(Errcode, Errcode, errcode)
LNN_ASSIGNER(Errcode, AuthId, authId)
LNN_ASSIGNER(Int32, DiscServerType, discServerType)
LNN_ASSIGNER(Int32, GearCycle, gearCycle)
LNN_ASSIGNER(Int32, GearDuration, gearDuration)
LNN_ASSIGNER(Int32, ConnectionId, connectionId)
LNN_ASSIGNER(Int32, AuthLinkType, authLinkType)
LNN_ASSIGNER(Int32, AuthCostTime, authCostTime)
LNN_ASSIGNER(Int32, LnnType, lnnType)
LNN_ASSIGNER(Int32, OnlineNum, onlineNum)
LNN_ASSIGNER(Int32, PeerDeviceAbility, peerDeviceAbility)
LNN_ASSIGNER(String, PeerDeviceInfo, peerDeviceInfo)
LNN_ASSIGNER(AnonymizeString, PeerIp, peerIp)
LNN_ASSIGNER(AnonymizeString, PeerBrMac, peerBrMac)
LNN_ASSIGNER(AnonymizeString, PeerBleMac, peerBleMac)
LNN_ASSIGNER(AnonymizeString, PeerWifiMac, peerWifiMac)
LNN_ASSIGNER(String, PeerPort, peerPort)
LNN_ASSIGNER(AnonymizeString, PeerUdid, peerUdid)
LNN_ASSIGNER(AnonymizeString, PeerNetworkId, peerNetworkId)
LNN_ASSIGNER(String, PeerDeviceType, peerDeviceType)
LNN_ASSIGNER(String, CallerPkg, callerPkg)
LNN_ASSIGNER(String, CalleePkg, calleePkg)

#define LNN_ASSIGNER_SIZE 23 // Size of g_connAssigners
static const HiSysEventParamAssigner g_lnnAssigners[] = {
    { "STAGE_RES",        HISYSEVENT_INT32,  LnnAssignerResult           },
    { "ERROR_CODE",       HISYSEVENT_INT32,  LnnAssignerErrcode          },
    { "AUTH_ID",          HISYSEVENT_INT32,  LnnAssignerAuthId           },
    { "DISC_SERVER_TYPE", HISYSEVENT_INT32,  LnnAssignerDiscServerType   },
    { "GEAR_CYCLE",       HISYSEVENT_INT32,  LnnAssignerGearCycle        },
    { "GEAR_DURATION",    HISYSEVENT_INT32,  LnnAssignerGearDuration     },
    { "CONN_ID",          HISYSEVENT_INT32,  LnnAssignerConnectionId     },
    { "AUTH_LINK_TYPE",   HISYSEVENT_INT32,  LnnAssignerAuthLinkType     },
    { "AUTH_COST_TIME",   HISYSEVENT_INT32,  LnnAssignerAuthCostTime     },
    { "LNN_TYPE",         HISYSEVENT_INT32,  LnnAssignerLnnType          },
    { "ONLINE_NUM",       HISYSEVENT_INT32,  LnnAssignerOnlineNum        },
    { "PEER_DEV_ABILITY", HISYSEVENT_INT32,  LnnAssignerPeerDeviceAbility},
    { "PEER_DEV_INFO",    HISYSEVENT_STRING, LnnAssignerPeerDeviceInfo   },
    { "PEER_IP",          HISYSEVENT_STRING, LnnAssignerPeerIp           },
    { "PEER_BR_MAC",      HISYSEVENT_STRING, LnnAssignerPeerBrMac        },
    { "PEER_BLE_MAC",     HISYSEVENT_STRING, LnnAssignerPeerBleMac       },
    { "PEER_WIFI_MAC",    HISYSEVENT_STRING, LnnAssignerPeerWifiMac      },
    { "PEER_PORT",        HISYSEVENT_STRING, LnnAssignerPeerPort         },
    { "PEER_UDID",        HISYSEVENT_STRING, LnnAssignerPeerUdid         },
    { "PEER_NET_ID",      HISYSEVENT_STRING, LnnAssignerPeerNetworkId    },
    { "PEER_DEV_TYPE",    HISYSEVENT_STRING, LnnAssignerPeerDeviceType   },
    { "HOST_PKG",         HISYSEVENT_STRING, LnnAssignerCallerPkg        },
    { "TO_CALL_PKG",      HISYSEVENT_STRING, LnnAssignerCalleePkg        },
    // Modification Note: remember updating LNN_ASSIGNER_SIZE
};

#define LNN_ALARM_ASSIGNER(type, fieldName, field)                                                            \
    static inline bool LnnAssigner##fieldName(                                                                \
        const char *eventName, HiSysEventParamType paramType, SoftbusEventForm *form, HiSysEventParam *param) \
    {                                                                                                         \
        if (Assigner##type(form->lnnAlarmExtra->field, &param) &&                                             \
            CopyString(param->name, eventName, MAX_LENGTH_OF_PARAM_NAME)) {                                   \
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
