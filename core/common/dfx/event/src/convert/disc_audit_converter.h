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

#ifndef DISC_AUDIT_CONVERTER_H
#define DISC_AUDIT_CONVERTER_H

#include "softbus_event_converter.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DISC_AUDIT_ASSIGNER(type, filedName, filed)                                                           \
    static inline bool DiscAuditAssigner##filedName(                                                          \
        const char *eventName, HiSysEventParamType paramType, SoftbusEventForm *form, HiSysEventParam *param) \
    {                                                                                                         \
        if (Assigner##type(form->discAuditExtra->filed, &param) && CopyString(param->name, eventName)) {      \
            param->t = paramType;                                                                             \
            return true;                                                                                      \
        }                                                                                                     \
        return false;                                                                                         \
    }

DISC_AUDIT_ASSIGNER(Errcode, Errcode, errcode)
DISC_AUDIT_ASSIGNER(Int32, AuditType, auditType)
DISC_AUDIT_ASSIGNER(Int32, BroadcastType, broadcastType)
DISC_AUDIT_ASSIGNER(Int32, BroadcastFreq, broadcastFreq)
DISC_AUDIT_ASSIGNER(Int32, AdvChannel, advChannel)
DISC_AUDIT_ASSIGNER(Int32, ScanType, scanType)
DISC_AUDIT_ASSIGNER(String, ScanCycle, scanCycle)
DISC_AUDIT_ASSIGNER(Int32, ScanId, scanId)
DISC_AUDIT_ASSIGNER(Int32, ScanListhenerId, scanListhenerId)
DISC_AUDIT_ASSIGNER(Int32, ScanInterval, scanInterval)
DISC_AUDIT_ASSIGNER(Int32, ScanWindow, scanWindow)
DISC_AUDIT_ASSIGNER(Int32, DiscType, discType)
DISC_AUDIT_ASSIGNER(Int32, DiscMode, discMode)
DISC_AUDIT_ASSIGNER(Int32, FirstDisCoverytime, firstDisCoverytime)
DISC_AUDIT_ASSIGNER(String, LocalNetworkId, localNetworkId)
DISC_AUDIT_ASSIGNER(String, LocalUdid, localUdid)
DISC_AUDIT_ASSIGNER(String, LocalDeviceType, localDeviceType)
DISC_AUDIT_ASSIGNER(String, LocalDeviceName, localDeviceName)
DISC_AUDIT_ASSIGNER(Int32, LocalCapabilityBitmap, localCapabilityBitmap)
DISC_AUDIT_ASSIGNER(String, LocalAccountHash, localAccountHash)
DISC_AUDIT_ASSIGNER(String, LocalCustTime, localCustTime)
DISC_AUDIT_ASSIGNER(String, PeerIp, peerIp)
DISC_AUDIT_ASSIGNER(String, PeerBrMac, peerBrMac)
DISC_AUDIT_ASSIGNER(String, PeerBleMac, peerBleMac)
DISC_AUDIT_ASSIGNER(String, PeerWifiMac, peerWifiMac)
DISC_AUDIT_ASSIGNER(String, PeerPort, peerPort)
DISC_AUDIT_ASSIGNER(String, PeerUdid, peerUdid)
DISC_AUDIT_ASSIGNER(String, PeerNetworkId, peerNetworkId)
DISC_AUDIT_ASSIGNER(String, PeerDeviceType, peerDeviceType)
DISC_AUDIT_ASSIGNER(String, PeerDeviceName, peerDeviceName)
DISC_AUDIT_ASSIGNER(Int32, PeerCapabilityBitmap, peerCapabilityBitmap)
DISC_AUDIT_ASSIGNER(String, PeerAccountHash, peerAccountHash)
DISC_AUDIT_ASSIGNER(String, PeerCustTime, peerCustTime)
DISC_AUDIT_ASSIGNER(String, ErrMsg, errMsg)
DISC_AUDIT_ASSIGNER(Int32, Extra, extra)
DISC_AUDIT_ASSIGNER(String, CallerPkg, callerPkg)

#define DISC_AUDIT_ASSIGNER_SIZE 21 // Size of g_discAssigners
static HiSysEventParamAssigner g_discAuditAssigners[] = {
    { "ERROR_CODE",              HISYSEVENT_INT32,  DiscAuditAssignerErrcode              },
    { "AUDIT_TYPE",              HISYSEVENT_INT32,  DiscAuditAssignerAuditType            },
    { "BROADCAST_TYPE",          HISYSEVENT_INT32,  DiscAuditAssignerBroadcastType        },
    { "BROADCAST_FREQ",          HISYSEVENT_INT32,  DiscAuditAssignerBroadcastFreq        },
    { "ADV_CHANNEL",             HISYSEVENT_INT32,  DiscAuditAssignerAdvChannel           },
    { "SCAN_TYPE",               HISYSEVENT_INT32,  DiscAuditAssignerScanType             },
    { "SCAN_CYCLE",              HISYSEVENT_STRING, DiscAuditAssignerScanCycle            },
    { "SCAN_ID",                 HISYSEVENT_INT32,  DiscAuditAssignerScanId               },
    { "SCAN_LISTENER_ID",        HISYSEVENT_INT32,  DiscAuditAssignerScanListhenerId      },
    { "SCAN_INTERCAL",           HISYSEVENT_INT32,  DiscAuditAssignerScanIntercal         },
    { "SCAN_WINDOW",             HISYSEVENT_INT32,  DiscAuditAssignerScanWindow           },
    { "DISC_TYPE",               HISYSEVENT_INT32,  DiscAuditAssignerDiscType             },
    { "DISC_MODE",               HISYSEVENT_INT32,  DiscAuditAssignerDiscMode             },
    { "FIRST_DISCOVERY_TIME",    HISYSEVENT_INT32,  DiscAuditAssignerFirstDisCoverytime   },
    { "LOCAL_NET_ID",            HISYSEVENT_STRING, DiscAuditAssignerLocalNetworkId       },
    { "LOCAL_UDID",              HISYSEVENT_STRING, DiscAuditAssignerLocalUdid            },
    { "LOCAL_DEV_TYPE",          HISYSEVENT_STRING, DiscAuditAssignerLocalDeviceType      },
    { "LOCAL_DEV_NAME",          HISYSEVENT_STRING, DiscAuditAssignerLocalDeviceName      },
    { "LOCAL_CAPABILITY_BITMAP", HISYSEVENT_INT32,  DiscAuditAssignerLocalCapabilityBitmap},
    { "LOCAL_CUST_DATA",         HISYSEVENT_STRING, DiscAuditAssignerLocalCustData        },
    { "PEER_IP",                 HISYSEVENT_STRING, DiscAuditAssignerPeerIp               },
    { "PEER_BR_MAC",             HISYSEVENT_STRING, DiscAuditAssignerPeerBrMac            },
    { "PEER_BLE_MAC",            HISYSEVENT_STRING, DiscAuditAssignerPeerBleMac           },
    { "PEER_WIFI_MAC",           HISYSEVENT_STRING, DiscAuditAssignerPeerWifiMac          },
    { "PEER_PORT",               HISYSEVENT_INT32,  DiscAuditAssignerPeerPort             },
    { "PEER_UDID",               HISYSEVENT_STRING, DiscAuditAssignerPeerUdid             },
    { "PEER_NET_ID",             HISYSEVENT_STRING, DiscAuditAssignerPeerNetworkId        },
    { "PEER_DEV_TYPE",           HISYSEVENT_STRING, DiscAuditAssignerPeerDeviceType       },
    { "PEER_DEV_NAME",           HISYSEVENT_STRING, DiscAuditAssignerPeerDeviceName       },
    { "PEER_CAPABILITY_BITMAP",  HISYSEVENT_INT32,  DiscAuditAssignerPeerCapabilityBitmap },
    { "PEER_CUST_DATA",          HISYSEVENT_STRING, DiscAuditAssignerPeerCustData         },
    { "PEER_MSG",                HISYSEVENT_STRING, DiscAuditAssignerErrorMsg             },
    { "EXTRA",                   HISYSEVENT_INT32,  DiscAuditAssignerExtra                },
    { "HOST_PKG",                HISYSEVENT_STRING, DiscAuditAssignerCallerPkg            },
    // Modification Note: remember updating DISC_AUDIT_ASSIGNER_SIZE
};

static inline size_t ConvertDiscAuditForm2Param(HiSysEventParam params[], SoftbusEventForm *form)
{
    size_t validSize = 0;
    if (form == NULL || form->discExtra == NULL) {
        return validSize;
    }
    for (size_t i = 0; i < sizeof(g_discAuditAssigners) / sizeof(g_discAuditAssigners[0]); ++i) {
        HiSysEventParamAssigner assigner = g_discAuditAssigners[i];
        if (assigner.Assign(assigner.name, assigner.type, form, &params[validSize])) {
            ++validSize;
        }
    }
    return validSize;
}

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif // DISC_EVENT_CONVERTER_H
