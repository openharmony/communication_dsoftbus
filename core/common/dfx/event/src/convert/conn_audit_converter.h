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

#ifndef CONN_AUDIT_CONVERTER_H
#define CONN_AUDIT_CONVERTER_H

#include "softbus_event_converter.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CONN_AUDIT_ASSIGNER(type, fieldName, field)                                                           \
    static inline bool ConnAuditAssigner##fieldName(                                                          \
        const char *eventName, HiSysEventParamType paramType, SoftbusEventForm *form, HiSysEventParam *param) \
    {                                                                                                         \
        if (Assigner##type(form->connAuditExtra->field, &param) &&                                            \
            CopyString(param->name, eventName, MAX_LENGTH_OF_PARAM_NAME)) {                                   \
            param->t = paramType;                                                                             \
            return true;                                                                                      \
        }                                                                                                     \
        return false;                                                                                         \
    }

CONN_AUDIT_ASSIGNER(Errcode, Errcode, errcode)
CONN_AUDIT_ASSIGNER(Int32, AuditType, auditType)
CONN_AUDIT_ASSIGNER(Int32, ConnectionId, connectionId)
CONN_AUDIT_ASSIGNER(Int32, RequestId, requestId)
CONN_AUDIT_ASSIGNER(Int32, LinkType, linkType)
CONN_AUDIT_ASSIGNER(Int32, ExpectRole, expectRole)
CONN_AUDIT_ASSIGNER(Int32, CostTime, costTime)
CONN_AUDIT_ASSIGNER(String, Frequency, frequency)
CONN_AUDIT_ASSIGNER(String, ChallengeCode, challengeCode)
CONN_AUDIT_ASSIGNER(String, PeerBrMac, peerBrMac)
CONN_AUDIT_ASSIGNER(String, PeerBleMac, peerBleMac)
CONN_AUDIT_ASSIGNER(String, PeerWifiMac, peerWifiMac)
CONN_AUDIT_ASSIGNER(String, PeerDeviceType, peerDeviceType)
CONN_AUDIT_ASSIGNER(String, PeerUdid, peerUdid)
CONN_AUDIT_ASSIGNER(String, ConnPayload, connPayload)
CONN_AUDIT_ASSIGNER(String, LocalDeviceName, localDeviceName)
CONN_AUDIT_ASSIGNER(String, PeerIp, peerIp)
CONN_AUDIT_ASSIGNER(String, CallerPkg, callerPkg)
CONN_AUDIT_ASSIGNER(String, CalleePkg, calleePkg)
CONN_AUDIT_ASSIGNER(Int32, ConnectTimes, connectTimes)
CONN_AUDIT_ASSIGNER(String, LocalBrMac, localBrMac)
CONN_AUDIT_ASSIGNER(String, LocalBleMac, localBleMac)
CONN_AUDIT_ASSIGNER(String, LocalUdid, localUdid)
CONN_AUDIT_ASSIGNER(String, LocalIp, localIp)
CONN_AUDIT_ASSIGNER(String, PeerPort, peerPort)
CONN_AUDIT_ASSIGNER(String, LocalPort, localPort)

#define CONN_AUDIT_ASSIGNER_SIZE 26 // Size of g_connAuditAssigners
static HiSysEventParamAssigner g_connAuditAssigners[] = {
    { "ERROR_CODE",     HISYSEVENT_INT32,  ConnAuditAssignerErrcode        },
    { "AUDIT_TYPE",     HISYSEVENT_INT32,  ConnAuditAssignerAuditType      },
    { "CONN_ID",        HISYSEVENT_INT32,  ConnAuditAssignerConnectionId   },
    { "REQ_ID",         HISYSEVENT_INT32,  ConnAuditAssignerRequestId      },
    { "LINK_TYPE",      HISYSEVENT_INT32,  ConnAuditAssignerLinkType       },
    { "EXPECT_ROLE",    HISYSEVENT_INT32,  ConnAuditAssignerExpectRole     },
    { "COST_TIME",      HISYSEVENT_INT32,  ConnAuditAssignerCostTime       },
    { "CONN_TIMES",     HISYSEVENT_INT32,  ConnAuditAssignerConnectTimes   },
    { "FREQ",           HISYSEVENT_STRING, ConnAuditAssignerFrequency      },
    { "CHALLENGE_CODE", HISYSEVENT_STRING, ConnAuditAssignerChallengeCode  },
    { "PEER_BR_MAC",    HISYSEVENT_STRING, ConnAuditAssignerPeerBrMac      },
    { "LOCAL_BR_MAC",   HISYSEVENT_STRING, ConnAuditAssignerLocalBrMac     },
    { "PEER_BLE_MAC",   HISYSEVENT_STRING, ConnAuditAssignerPeerBleMac     },
    { "LOCAL_BLE_MAC",  HISYSEVENT_STRING, ConnAuditAssignerLocalBleMac    },
    { "PEER_DEV_TYPE",  HISYSEVENT_STRING, ConnAuditAssignerPeerDeviceType },
    { "PEER_UDID",      HISYSEVENT_STRING, ConnAuditAssignerPeerUdid       },
    { "LOCAL_UDID",     HISYSEVENT_STRING, ConnAuditAssignerLocalUdid      },
    { "CONN_PAYLOAD",   HISYSEVENT_STRING, ConnAuditAssignerConnPayload    },
    { "LOCAL_DEV_NAME", HISYSEVENT_STRING, ConnAuditAssignerLocalDeviceName},
    { "PEER_IP",        HISYSEVENT_STRING, ConnAuditAssignerPeerIp         },
    { "LOCAL_IP",       HISYSEVENT_STRING, ConnAuditAssignerLocalIp        },
    { "HOST_PKG",       HISYSEVENT_STRING, ConnAuditAssignerCallerPkg      },
    { "TO_CALL_PKG",    HISYSEVENT_STRING, ConnAuditAssignerCalleePkg      },
    { "PEER_PORT",      HISYSEVENT_STRING, ConnAuditAssignerPeerPort       },
    { "LOCAL_PORT",     HISYSEVENT_STRING, ConnAuditAssignerLocalPort      },
    { "PEER_WIFI_MAC",  HISYSEVENT_STRING, ConnAuditAssignerPeerWifiMac    },
    // Modification Note: remember updating CONN_AUDIT_ASSIGNER_SIZE
};

static inline size_t ConvertConnAuditForm2Param(HiSysEventParam params[], SoftbusEventForm *form)
{
    size_t validSize = 0;
    if (form == NULL || form->connExtra == NULL) {
        return validSize;
    }
    for (size_t i = 0; i < sizeof(g_connAuditAssigners) / sizeof(g_connAuditAssigners[0]); ++i) {
        HiSysEventParamAssigner assigner = g_connAuditAssigners[i];
        if (assigner.Assign(assigner.name, assigner.type, form, &params[validSize])) {
            ++validSize;
        }
    }
    return validSize;
}

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif // CONN_AUDIT_CONVERTER_H
