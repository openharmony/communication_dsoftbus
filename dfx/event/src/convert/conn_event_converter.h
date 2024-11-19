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

#define CONN_ASSIGNER(type, fieldName, field)                                                                 \
    static inline bool ConnAssigner##fieldName(                                                               \
        const char *eventName, HiSysEventParamType paramType, SoftbusEventForm *form, HiSysEventParam *param) \
    {                                                                                                         \
        if (Assigner##type(form->connExtra->field, &param) &&                                                 \
            CopyString(param->name, eventName, MAX_LENGTH_OF_PARAM_NAME)) {                                   \
            param->t = paramType;                                                                             \
            return true;                                                                                      \
        }                                                                                                     \
        return false;                                                                                         \
    }

CONN_ASSIGNER(Errcode, Result, result)
CONN_ASSIGNER(Errcode, Errcode, errcode)
CONN_ASSIGNER(Int32, ConnectionId, connectionId)
CONN_ASSIGNER(Errcode, ConnReqId, requestId)
CONN_ASSIGNER(Int32, LinkType, linkType)
CONN_ASSIGNER(Int32, AuthType, authType)
CONN_ASSIGNER(Int32, AuthId, authId)
CONN_ASSIGNER(String, LnnType, lnnType)
CONN_ASSIGNER(Int32, ExpectRole, expectRole)
CONN_ASSIGNER(Int32, CostTime, costTime)
CONN_ASSIGNER(Int32, Rssi, rssi)
CONN_ASSIGNER(Int32, Load, load)
CONN_ASSIGNER(Int32, Frequency, frequency)
CONN_ASSIGNER(Int32, ConnProtocol, connProtocol)
CONN_ASSIGNER(Int32, ConnRole, connRole)
CONN_ASSIGNER(Int32, ConnRcDelta, connRcDelta)
CONN_ASSIGNER(Int32, ConnRc, connRc)
CONN_ASSIGNER(Int32, SupportFeature, supportFeature)
CONN_ASSIGNER(Int32, ModuleId, moduleId)
CONN_ASSIGNER(Uint32, ProtocolType, proType)
CONN_ASSIGNER(Int32, Fd, fd)
CONN_ASSIGNER(Int32, Cfd, cfd)
CONN_ASSIGNER(String, ChallengeCode, challengeCode)
CONN_ASSIGNER(AnonymizeString, PeerIp, peerIp)
CONN_ASSIGNER(AnonymizeString, PeerBrMac, peerBrMac)
CONN_ASSIGNER(AnonymizeString, PeerBleMac, peerBleMac)
CONN_ASSIGNER(AnonymizeString, PeerWifiMac, peerWifiMac)
CONN_ASSIGNER(String, PeerPort, peerPort)
CONN_ASSIGNER(AnonymizeString, PeerNetworkId, peerNetworkId)
CONN_ASSIGNER(AnonymizeString, PeerUdid, peerUdid)
CONN_ASSIGNER(String, PeerDeviceType, peerDeviceType)
CONN_ASSIGNER(AnonymizeString, LocalNetworkId, localNetworkId)
CONN_ASSIGNER(String, CallerPkg, callerPkg)
CONN_ASSIGNER(String, CalleePkg, calleePkg)
CONN_ASSIGNER(Errcode, BootLinkType, bootLinkType)
CONN_ASSIGNER(Errcode, IsRenegotiate, isRenegotiate)
CONN_ASSIGNER(Errcode, IsReuse, isReuse)
CONN_ASSIGNER(Uint64, NegotiateTime, negotiateTime)
CONN_ASSIGNER(Uint64, LinkTime, linkTime)
CONN_ASSIGNER(Errcode, OsType, osType)
CONN_ASSIGNER(String, LocalDeviceType, localDeviceType)
CONN_ASSIGNER(String, RemoteDeviceType, remoteDeviceType)
CONN_ASSIGNER(Errcode, P2pChannel, p2pChannel)
CONN_ASSIGNER(Errcode, HmlChannel, hmlChannel)
CONN_ASSIGNER(Errcode, StaChannel, staChannel)
CONN_ASSIGNER(Errcode, ApChannel, apChannel)
CONN_ASSIGNER(String, PeerDevVer, peerDevVer)
CONN_ASSIGNER(Errcode, RemoteScreenStatus, remoteScreenStatus)
CONN_ASSIGNER(Errcode, BusinessType, businessType)
CONN_ASSIGNER(Int32, BusinessId, businessId)
CONN_ASSIGNER(Errcode, Timeout, timeout)
CONN_ASSIGNER(Errcode, FastestConnectEnable, fastestConnectEnable)
CONN_ASSIGNER(Errcode, CoapDataChannel, coapDataChannel)
CONN_ASSIGNER(Errcode, EnableWideBandwidth, enableWideBandwidth)
CONN_ASSIGNER(Errcode, P2pRole, p2pRole)
CONN_ASSIGNER(Errcode, NeedHmlConnect, needHmlConnect)
CONN_ASSIGNER(String, BusinessTag, businessTag)

#define CONN_ASSIGNER_SIZE 57 // Size of g_connAssigners
static HiSysEventParamAssigner g_connAssigners[] = {
    { "STAGE_RES",         HISYSEVENT_INT32,  ConnAssignerResult        },
    { "ERROR_CODE",        HISYSEVENT_INT32,  ConnAssignerErrcode       },
    { "CONN_ID",           HISYSEVENT_INT32,  ConnAssignerConnectionId  },
    { "CONN_REQ_ID",       HISYSEVENT_INT32,  ConnAssignerConnReqId     },
    { "LINK_TYPE",         HISYSEVENT_INT32,  ConnAssignerLinkType      },
    { "AUTH_TYPE",         HISYSEVENT_INT32,  ConnAssignerAuthType      },
    { "AUTH_ID",           HISYSEVENT_INT32,  ConnAssignerAuthId        },
    { "LNN_TYPE",          HISYSEVENT_STRING, ConnAssignerLnnType       },
    { "EXPECT_ROLE",       HISYSEVENT_INT32,  ConnAssignerExpectRole    },
    { "COST_TIME",         HISYSEVENT_INT32,  ConnAssignerCostTime      },
    { "RSSI",              HISYSEVENT_INT32,  ConnAssignerRssi          },
    { "CHLOAD",            HISYSEVENT_INT32,  ConnAssignerLoad          },
    { "FREQ",              HISYSEVENT_INT32,  ConnAssignerFrequency     },
    { "CONN_PROTOCOL",     HISYSEVENT_INT32,  ConnAssignerConnProtocol  },
    { "CONN_ROLE",         HISYSEVENT_INT32,  ConnAssignerConnRole      },
    { "CONN_RC_DELTA",     HISYSEVENT_INT32,  ConnAssignerConnRcDelta   },
    { "CONN_RC",           HISYSEVENT_INT32,  ConnAssignerConnRc        },
    { "SUPT_FEATURE",      HISYSEVENT_INT32,  ConnAssignerSupportFeature},
    { "MODULE_ID",         HISYSEVENT_INT32,  ConnAssignerModuleId      },
    { "PROTOCOL_TYPE",     HISYSEVENT_UINT32, ConnAssignerProtocolType  },
    { "FD",                HISYSEVENT_INT32,  ConnAssignerFd            },
    { "CFD",               HISYSEVENT_INT32,  ConnAssignerCfd           },
    { "CHALLENGE_CODE",    HISYSEVENT_STRING, ConnAssignerChallengeCode },
    { "PEER_IP",           HISYSEVENT_STRING, ConnAssignerPeerIp        },
    { "PEER_BR_MAC",       HISYSEVENT_STRING, ConnAssignerPeerBrMac     },
    { "PEER_BLE_MAC",      HISYSEVENT_STRING, ConnAssignerPeerBleMac    },
    { "PEER_WIFI_MAC",     HISYSEVENT_STRING, ConnAssignerPeerWifiMac   },
    { "PEER_PORT",         HISYSEVENT_STRING, ConnAssignerPeerPort      },
    { "PEER_NET_ID",       HISYSEVENT_STRING, ConnAssignerPeerNetworkId },
    { "PEER_UDID",         HISYSEVENT_STRING, ConnAssignerPeerUdid      },
    { "PEER_DEV_TYPE",     HISYSEVENT_STRING, ConnAssignerPeerDeviceType},
    { "LOCAL_NET_ID",      HISYSEVENT_STRING, ConnAssignerLocalNetworkId},
    { "HOST_PKG",          HISYSEVENT_STRING, ConnAssignerCallerPkg     },
    { "TO_CALL_PKG",       HISYSEVENT_STRING, ConnAssignerCalleePkg     },
    { "BOOT_LINK_TYPE",    HISYSEVENT_INT32,  ConnAssignerBootLinkType  },
    { "IS_RENEGOTIATE",    HISYSEVENT_INT32,  ConnAssignerIsRenegotiate },
    { "IS_REUSE",          HISYSEVENT_INT32,  ConnAssignerIsReuse       },
    { "NEGOTIATE_TIME",    HISYSEVENT_UINT64, ConnAssignerNegotiateTime },
    { "LINK_TIME",         HISYSEVENT_UINT64, ConnAssignerLinkTime      },
    { "OS_TYPE",           HISYSEVENT_INT32,  ConnAssignerOsType          },
    { "LOCAL_DEV_TYPE",         HISYSEVENT_STRING, ConnAssignerLocalDeviceType     },
    { "PEER_DEV_TYPE",          HISYSEVENT_STRING, ConnAssignerRemoteDeviceType    },
    { "P2P_CHANNEL",       HISYSEVENT_INT32,  ConnAssignerP2pChannel      },
    { "HML_CHANNEL",       HISYSEVENT_INT32,  ConnAssignerHmlChannel      },
    { "STA_CHANNEL",       HISYSEVENT_INT32,  ConnAssignerStaChannel      },
    { "AP_CHANNEL",        HISYSEVENT_INT32,  ConnAssignerApChannel       },
    { "PEER_DEV_VER",         HISYSEVENT_STRING, ConnAssignerPeerDevVer        },
    { "REMOTE_SCREEN_STATUS", HISYSEVENT_INT32,  ConnAssignerRemoteScreenStatus},
    { "BUSINESS_TYPE",          HISYSEVENT_INT32,  ConnAssignerBusinessType        },
    { "BUSINESS_ID",            HISYSEVENT_INT32,  ConnAssignerBusinessId          },
    { "TIME_OUT",               HISYSEVENT_INT32,  ConnAssignerTimeout             },
    { "FASTEST_CONNECT_ENABLE", HISYSEVENT_INT32,  ConnAssignerFastestConnectEnable},
    { "COAP_DATA_CHANNEL",      HISYSEVENT_INT32,  ConnAssignerCoapDataChannel     },
    { "ENABLE_WIDE_BANDWIDTH",  HISYSEVENT_INT32,  ConnAssignerEnableWideBandwidth },
    { "P2P_ROLE",               HISYSEVENT_INT32,  ConnAssignerP2pRole             },
    { "NEED_HML_CONNECT",       HISYSEVENT_INT32,  ConnAssignerNeedHmlConnect      },
    { "BUSINESS_TAG",           HISYSEVENT_STRING, ConnAssignerBusinessTag         },
 // Modification Note: remember updating CONN_ASSIGNER_SIZE
};

#define CONN_ALARM_ASSIGNER(type, fieldName, field)                                                           \
    static inline bool ConnAssigner##fieldName(                                                               \
        const char *eventName, HiSysEventParamType paramType, SoftbusEventForm *form, HiSysEventParam *param) \
    {                                                                                                         \
        if (Assigner##type(form->connAlarmExtra->field, &param) &&                                            \
            CopyString(param->name, eventName, MAX_LENGTH_OF_PARAM_NAME)) {                                   \
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
