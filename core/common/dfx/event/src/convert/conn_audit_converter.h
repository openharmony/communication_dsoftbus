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

#define CONN_AUDIT_ASSIGNER(type, filedName, filed)                                                           \
    static inline bool ConnAuditAssigner##filedName(                                                          \
        const char *eventName, HiSysEventParamType paramType, SoftbusEventForm *form, HiSysEventParam *param) \
    {                                                                                                         \
        if (Assigner##type(form->connAuditExtra->filed, &param) && CopyString(param->name, eventName)) {      \
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
CONN_AUDIT_ASSIGNER(String, PeerBrMac, peerBrMac)
CONN_AUDIT_ASSIGNER(String, PeerBleMac, peerBleMac)
CONN_AUDIT_ASSIGNER(String, PeerDeviceType, peerDeviceType)
CONN_AUDIT_ASSIGNER(String, PeerWifiMac, peerWifiMac)
CONN_AUDIT_ASSIGNER(String, PeerUdid, peerUdid)
CONN_AUDIT_ASSIGNER(String, ConnPaload, connPaload)
CONN_AUDIT_ASSIGNER(String, LocalDeviceName, localDeviceName)
CONN_AUDIT_ASSIGNER(String, PeerIp, peerIp)
CONN_AUDIT_ASSIGNER(String, CallerPkg, callerPkg)
CONN_AUDIT_ASSIGNER(String, CalleePkg, calleePkg)

#define CONN_AUDIT_ASSIGNER_SIZE 20 // Size of g_connAuditAssigners
static HiSysEventParamAssigner g_connAuditAssigners[] = {
    { "ERROR_CODE",     HISYSEVENT_INT32,  ConnAuditAssignerErrcode        },
    { "AUDIT_TYPE",     HISYSEVENT_INT32,  ConnAuditAssignerAuditType      },
    { "CONN_ID",        HISYSEVENT_INT32,  ConnAuditAssignerConnectionId   },
    { "REQ_ID",         HISYSEVENT_INT32,  ConnAuditAssignerRequestId      },
    { "LINK_TYPE",      HISYSEVENT_INT32,  ConnAuditAssignerLinkType       },
    { "EXPECT_ROLE",    HISYSEVENT_INT32,  ConnAuditAssignerExpectRole     },
    { "COST_TIME",      HISYSEVENT_INT32,  ConnAuditAssignerCostTime       },
    { "FREQ",           HISYSEVENT_STRING, ConnAuditAssignerFrequency      },
    { "PEER_BR_MAC",    HISYSEVENT_STRING, ConnAuditAssignerPeerBrMac      },
    { "PEER_BLE_MAC",   HISYSEVENT_STRING, ConnAuditAssignerPeerBleMac     },
    { "PEER_DEV_TYPE",  HISYSEVENT_STRING, ConnAuditAssignerPeerDeviceType },
    { "PEER_WIFI_MAC",  HISYSEVENT_STRING, ConnAuditAssignerPeerWifiMac    },
    { "PEER_IP",        HISYSEVENT_STRING, ConnAuditAssignerPeerIp         },
    { "LOCAL_DEV_NAME", HISYSEVENT_STRING, ConnAuditAssignerLocalDeviceName},
    { "PEER_IP",        HISYSEVENT_STRING, ConnAuditAssignerPeerIp         },
    { "HOST_PKG",       HISYSEVENT_STRING, ConnAuditAssignerCallerPkg      },
    { "TO_CALL_PKG",    HISYSEVENT_STRING, ConnAuditAssignerCalleePkg      },
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
#endif // CONN_EVENT_CONVERTER_H
