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
LNN_ASSIGNER(Int32, AuthRequestId, authRequestId)
LNN_ASSIGNER(Int32, AuthCostTime, authCostTime)
LNN_ASSIGNER(Int32, LnnType, lnnType)
LNN_ASSIGNER(Int32, OnlineNum, onlineNum)
LNN_ASSIGNER(Int32, PeerDeviceAbility, peerDeviceAbility)
LNN_ASSIGNER(Int32, OnlineType, onlineType)
LNN_ASSIGNER(Errcode, OsType, osType)
LNN_ASSIGNER(Errcode, ConnOnlineReason, connOnlineReason)
LNN_ASSIGNER(Int32, LaneId, laneId)
LNN_ASSIGNER(Int32, ChanReqId, chanReqId)
LNN_ASSIGNER(Int32, ConnReqId, connReqId)
LNN_ASSIGNER(Int32, Strategy, strategy)
LNN_ASSIGNER(Uint64, TimeLatency, timeLatency)
LNN_ASSIGNER(Errcode, TriggerReason, triggerReason)
LNN_ASSIGNER(Int64, AuthSeq, authSeq)
LNN_ASSIGNER(Errcode, OnlineDevCnt, onlineDevCnt)
LNN_ASSIGNER(Int32, Interval, interval)
LNN_ASSIGNER(Errcode, LaneLinkType, laneLinkType)
LNN_ASSIGNER(Int32, HmlChannelId, hmlChannelId)
LNN_ASSIGNER(Int32, P2pChannelId, p2pChannelId)
LNN_ASSIGNER(Int32, StaChannelId, staChannelId)
LNN_ASSIGNER(Int32, ApChannelId, apChannelId)
LNN_ASSIGNER(Int32, LaneReqId, laneReqId)
LNN_ASSIGNER(Int32, MinBW, minBW)
LNN_ASSIGNER(Int32, MaxLaneLatency, maxLaneLatency)
LNN_ASSIGNER(Int32, MinLaneLatency, minLaneLatency)
LNN_ASSIGNER(Errcode, IsWifiDirectReuse, isWifiDirectReuse)
LNN_ASSIGNER(Errcode, BandWidth, bandWidth)
LNN_ASSIGNER(Errcode, GuideType, guideType)
LNN_ASSIGNER(String, PeerDeviceInfo, peerDeviceInfo)
LNN_ASSIGNER(AnonymizeString, PeerIp, peerIp)
LNN_ASSIGNER(AnonymizeString, PeerBrMac, peerBrMac)
LNN_ASSIGNER(AnonymizeString, PeerBleMac, peerBleMac)
LNN_ASSIGNER(AnonymizeString, PeerWifiMac, peerWifiMac)
LNN_ASSIGNER(String, PeerPort, peerPort)
LNN_ASSIGNER(AnonymizeString, PeerUdid, peerUdid)
LNN_ASSIGNER(AnonymizeString, PeerNetworkId, peerNetworkId)
LNN_ASSIGNER(String, LocalDeviceType, localDeviceType)
LNN_ASSIGNER(String, PeerDeviceType, peerDeviceType)
LNN_ASSIGNER(AnonymizeString, LocalUdidHash, localUdidHash)
LNN_ASSIGNER(AnonymizeString, PeerUdidHash, peerUdidHash)
LNN_ASSIGNER(String, CallerPkg, callerPkg)
LNN_ASSIGNER(String, CalleePkg, calleePkg)

#define LNN_ASSIGNER_SIZE 51 // Size of g_connAssigners
static const HiSysEventParamAssigner g_lnnAssigners[] = {
    { "STAGE_RES",            HISYSEVENT_INT32,  LnnAssignerResult           },
    { "ERROR_CODE",           HISYSEVENT_INT32,  LnnAssignerErrcode          },
    { "AUTH_ID",              HISYSEVENT_INT32,  LnnAssignerAuthId           },
    { "DISC_SERVER_TYPE",     HISYSEVENT_INT32,  LnnAssignerDiscServerType   },
    { "GEAR_CYCLE",           HISYSEVENT_INT32,  LnnAssignerGearCycle        },
    { "GEAR_DURATION",        HISYSEVENT_INT32,  LnnAssignerGearDuration     },
    { "CONN_ID",              HISYSEVENT_INT32,  LnnAssignerConnectionId     },
    { "AUTH_LINK_TYPE",       HISYSEVENT_INT32,  LnnAssignerAuthLinkType     },
    { "AUTH_REQUEST_ID",      HISYSEVENT_INT32,  LnnAssignerAuthRequestId    },
    { "AUTH_COST_TIME",       HISYSEVENT_INT32,  LnnAssignerAuthCostTime     },
    { "LNN_TYPE",             HISYSEVENT_INT32,  LnnAssignerLnnType          },
    { "ONLINE_NUM",           HISYSEVENT_INT32,  LnnAssignerOnlineNum        },
    { "PEER_DEV_ABILITY",     HISYSEVENT_INT32,  LnnAssignerPeerDeviceAbility},
    { "ONLINE_TYPE",          HISYSEVENT_INT32,  LnnAssignerOnlineType       },
    { "OS_TYPE",              HISYSEVENT_INT32,  LnnAssignerOsType           },
    { "CONN_ONLINE_REAS",     HISYSEVENT_INT32,  LnnAssignerConnOnlineReason },
    { "LANE_ID",              HISYSEVENT_INT32,  LnnAssignerLaneId           },
    { "CHAN_REQ_ID",          HISYSEVENT_INT32,  LnnAssignerChanReqId        },
    { "CONN_REQ_ID",          HISYSEVENT_INT32,  LnnAssignerConnReqId        },
    { "STRATEGY_FOR_LNN_BLE", HISYSEVENT_INT32,  LnnAssignerStrategy         },
    { "TIME_LATENCY",         HISYSEVENT_UINT64, LnnAssignerTimeLatency      },
    { "TRIGGER_REASON",       HISYSEVENT_INT32,  LnnAssignerTriggerReason    },
    { "AUTH_SEQ",             HISYSEVENT_INT64,  LnnAssignerAuthSeq          },
    { "ONLINE_DEV_CNT",       HISYSEVENT_INT32,  LnnAssignerOnlineDevCnt     },
    { "INTERVAL",             HISYSEVENT_INT32,  LnnAssignerInterval         },
    { "LANE_LINK_TYPE",       HISYSEVENT_INT32,  LnnAssignerLaneLinkType     },
    { "HML_CHANNEL_ID",       HISYSEVENT_INT32,  LnnAssignerHmlChannelId     },
    { "P2P_CHANNEL_ID",       HISYSEVENT_INT32,  LnnAssignerP2pChannelId     },
    { "STA_CHANNEL_ID",       HISYSEVENT_INT32,  LnnAssignerStaChannelId     },
    { "AP_CHANNEL_ID",        HISYSEVENT_INT32,  LnnAssignerApChannelId      },
    { "LANE_REQ_ID",          HISYSEVENT_INT32,  LnnAssignerLaneReqId        },
    { "MIN_BW",               HISYSEVENT_INT32,  LnnAssignerMinBW            },
    { "MAX_LANE_LATENCY",     HISYSEVENT_INT32,  LnnAssignerMaxLaneLatency   },
    { "MIN_LANE_LATENCY",     HISYSEVENT_INT32,  LnnAssignerMinLaneLatency   },
    { "IS_WIFI_DIRECT_REUSE", HISYSEVENT_INT32,  LnnAssignerIsWifiDirectReuse},
    { "BAND_WIDTH",           HISYSEVENT_INT32,  LnnAssignerBandWidth        },
    { "GUIDE_TYPE",           HISYSEVENT_INT32,  LnnAssignerGuideType        },
    { "PEER_DEV_INFO",        HISYSEVENT_STRING, LnnAssignerPeerDeviceInfo   },
    { "PEER_IP",              HISYSEVENT_STRING, LnnAssignerPeerIp           },
    { "PEER_BR_MAC",          HISYSEVENT_STRING, LnnAssignerPeerBrMac        },
    { "PEER_BLE_MAC",         HISYSEVENT_STRING, LnnAssignerPeerBleMac       },
    { "PEER_WIFI_MAC",        HISYSEVENT_STRING, LnnAssignerPeerWifiMac      },
    { "PEER_PORT",            HISYSEVENT_STRING, LnnAssignerPeerPort         },
    { "PEER_UDID",            HISYSEVENT_STRING, LnnAssignerPeerUdid         },
    { "PEER_NET_ID",          HISYSEVENT_STRING, LnnAssignerPeerNetworkId    },
    { "LOCAL_DEV_TYPE",       HISYSEVENT_STRING, LnnAssignerLocalDeviceType  },
    { "PEER_DEV_TYPE",        HISYSEVENT_STRING, LnnAssignerPeerDeviceType   },
    { "LOCAL_UDID_HASH",      HISYSEVENT_STRING, LnnAssignerLocalUdidHash    },
    { "PEER_UDID_HASH",       HISYSEVENT_STRING, LnnAssignerPeerUdidHash     },
    { "HOST_PKG",             HISYSEVENT_STRING, LnnAssignerCallerPkg        },
    { "TO_CALL_PKG",          HISYSEVENT_STRING, LnnAssignerCalleePkg        },
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
