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

#define DISC_AUDIT_ASSIGNER(type, fieldName, field)                                                           \
    static inline bool DiscAuditAssigner##fieldName(                                                          \
        const char *eventName, HiSysEventParamType paramType, SoftbusEventForm *form, HiSysEventParam *param) \
    {                                                                                                         \
        if (Assigner##type(form->discAuditExtra->field, &param) &&                                            \
            CopyString(param->name, eventName, MAX_LENGTH_OF_PARAM_NAME)) {                                   \
            param->t = paramType;                                                                             \
            return true;                                                                                      \
        }                                                                                                     \
        return false;                                                                                         \
    }

DISC_AUDIT_ASSIGNER(String, CallerPkg, callerPkg)
DISC_AUDIT_ASSIGNER(Int32, Result, result)
DISC_AUDIT_ASSIGNER(Errcode, Errcode, errcode)
DISC_AUDIT_ASSIGNER(Int32, AuditType, auditType)
DISC_AUDIT_ASSIGNER(Int32, BroadcastType, broadcastType)
DISC_AUDIT_ASSIGNER(Int32, BroadcastFreq, broadcastFreq)
DISC_AUDIT_ASSIGNER(Int32, AdvCount, advCount)
DISC_AUDIT_ASSIGNER(Int32, AdvDuration, advDuration)
DISC_AUDIT_ASSIGNER(Int32, ScanInterval, scanInterval)
DISC_AUDIT_ASSIGNER(Int32, ScanWindow, scanWindow)
DISC_AUDIT_ASSIGNER(Int32, DiscMode, discMode)
DISC_AUDIT_ASSIGNER(Int32, MediumType, mediumType)
DISC_AUDIT_ASSIGNER(Int32, AdvChannel, advChannel)
DISC_AUDIT_ASSIGNER(Int32, ScanType, scanType)
DISC_AUDIT_ASSIGNER(Int32, ScanId, scanId)
DISC_AUDIT_ASSIGNER(Int32, ScanListenerId, scanListenerId)
DISC_AUDIT_ASSIGNER(String, LocalUdid, localUdid)
DISC_AUDIT_ASSIGNER(String, LocalDeviceName, localDeviceName)
DISC_AUDIT_ASSIGNER(String, LocalDeviceType, localDeviceType)
DISC_AUDIT_ASSIGNER(String, LocalAccountHash, localAccountHash)
DISC_AUDIT_ASSIGNER(Int32, LocalCapabilityBitmap, localCapabilityBitmap)
DISC_AUDIT_ASSIGNER(String, LocalCustData, localCustData)
DISC_AUDIT_ASSIGNER(String, LocalIp, localIp)
DISC_AUDIT_ASSIGNER(Int32, LocalPort, localPort)
DISC_AUDIT_ASSIGNER(String, LocalBrMac, localBrMac)
DISC_AUDIT_ASSIGNER(String, LocalBleMac, localBleMac)
DISC_AUDIT_ASSIGNER(String, PeerUdid, peerUdid)
DISC_AUDIT_ASSIGNER(String, PeerDeviceName, peerDeviceName)
DISC_AUDIT_ASSIGNER(String, PeerDeviceType, peerDeviceType)
DISC_AUDIT_ASSIGNER(String, PeerAccountHash, peerAccountHash)
DISC_AUDIT_ASSIGNER(Int32, PeerCapabilityBitmap, peerCapabilityBitmap)
DISC_AUDIT_ASSIGNER(String, PeerCustData, peerCustData)
DISC_AUDIT_ASSIGNER(String, PeerIp, peerIp)
DISC_AUDIT_ASSIGNER(Int32, PeerPort, peerPort)
DISC_AUDIT_ASSIGNER(String, PeerBrMac, peerBrMac)
DISC_AUDIT_ASSIGNER(String, PeerBleMac, peerBleMac)
DISC_AUDIT_ASSIGNER(String, ErrMsg, errMsg)
DISC_AUDIT_ASSIGNER(String, AdditionalInfo, additionalInfo)

static HiSysEventParamAssigner g_discAuditAssigners[] = {
    { "HOST_PKG",                   HISYSEVENT_STRING,      DiscAuditAssignerCallerPkg              },
    { "RESULT",                     HISYSEVENT_INT32,       DiscAuditAssignerResult                 },
    { "ERROR_CODE",                 HISYSEVENT_INT32,       DiscAuditAssignerErrcode                },
    { "AUDIT_TYPE",                 HISYSEVENT_INT32,       DiscAuditAssignerAuditType              },
    { "BROADCAST_TYPE",             HISYSEVENT_INT32,       DiscAuditAssignerBroadcastType          },
    { "BROADCAST_FREQ",             HISYSEVENT_INT32,       DiscAuditAssignerBroadcastFreq          },
    { "ADV_COUNT",                  HISYSEVENT_INT32,       DiscAuditAssignerAdvCount               },
    { "ADV_DURATION",               HISYSEVENT_INT32,       DiscAuditAssignerAdvDuration            },
    { "SCAN_INTERVAL",              HISYSEVENT_INT32,       DiscAuditAssignerScanInterval           },
    { "SCAN_WINDOW",                HISYSEVENT_INT32,       DiscAuditAssignerScanWindow             },
    { "DISC_MODE",                  HISYSEVENT_INT32,       DiscAuditAssignerDiscMode               },
    { "MEDIUM_TYPE",                HISYSEVENT_INT32,       DiscAuditAssignerMediumType             },
    { "ADV_CHANNEL",                HISYSEVENT_INT32,       DiscAuditAssignerAdvChannel             },
    { "SCAN_TYPE",                  HISYSEVENT_INT32,       DiscAuditAssignerScanType               },
    { "SCAN_ID",                    HISYSEVENT_INT32,       DiscAuditAssignerScanId                 },
    { "SCAN_LISTENER_ID",           HISYSEVENT_INT32,       DiscAuditAssignerScanListenerId         },
    { "LOCAL_UDID",                 HISYSEVENT_STRING,      DiscAuditAssignerLocalUdid              },
    { "LOCAL_DEV_NAME",             HISYSEVENT_STRING,      DiscAuditAssignerLocalDeviceName        },
    { "LOCAL_DEV_TYPE",             HISYSEVENT_STRING,      DiscAuditAssignerLocalDeviceType        },
    { "LOCAL_ACCOUNT_HASH",         HISYSEVENT_STRING,      DiscAuditAssignerLocalAccountHash       },
    { "LOCAL_CAPABILITY_BITMAP",    HISYSEVENT_INT32,       DiscAuditAssignerLocalCapabilityBitmap  },
    { "LOCAL_CUST_DATA",            HISYSEVENT_STRING,      DiscAuditAssignerLocalCustData          },
    { "LOCAL_IP",                   HISYSEVENT_STRING,      DiscAuditAssignerLocalIp                },
    { "LOCAL_PORT",                 HISYSEVENT_INT32,       DiscAuditAssignerLocalPort              },
    { "LOCAL_BR_MAC",               HISYSEVENT_STRING,      DiscAuditAssignerLocalBrMac             },
    { "LOCAL_BLE_MAC",              HISYSEVENT_STRING,      DiscAuditAssignerLocalBleMac            },
    { "PEER_UDID",                  HISYSEVENT_STRING,      DiscAuditAssignerPeerUdid               },
    { "PEER_DEV_NAME",              HISYSEVENT_STRING,      DiscAuditAssignerPeerDeviceName         },
    { "PEER_DEV_TYPE",              HISYSEVENT_STRING,      DiscAuditAssignerPeerDeviceType         },
    { "PEER_ACCOUNT_HASH",          HISYSEVENT_STRING,      DiscAuditAssignerPeerAccountHash        },
    { "PEER_CAPABILITY_BITMAP",     HISYSEVENT_INT32,       DiscAuditAssignerPeerCapabilityBitmap   },
    { "PEER_CUST_DATA",             HISYSEVENT_STRING,      DiscAuditAssignerPeerCustData           },
    { "PEER_IP",                    HISYSEVENT_STRING,      DiscAuditAssignerPeerIp                 },
    { "PEER_PORT",                  HISYSEVENT_INT32,       DiscAuditAssignerPeerPort               },
    { "PEER_BR_MAC",                HISYSEVENT_STRING,      DiscAuditAssignerPeerBrMac              },
    { "PEER_BLE_MAC",               HISYSEVENT_STRING,      DiscAuditAssignerPeerBleMac             },
    { "ERR_MSG",                    HISYSEVENT_STRING,      DiscAuditAssignerErrMsg                 },
    { "ADDITIONAL_INFO",            HISYSEVENT_STRING,      DiscAuditAssignerAdditionalInfo         },
    // Modification Note: remember updating DISC_AUDIT_ASSIGNER_SIZE
};

#define DISC_AUDIT_ASSIGNER_SIZE 38 // Array size of g_discAuditAssigners

static const size_t DISC_AUDIT_ASSIGNER_COUNT = sizeof(g_discAuditAssigners) / sizeof(HiSysEventParamAssigner);

static inline size_t ConvertDiscAuditForm2Param(HiSysEventParam params[], SoftbusEventForm *form)
{
    size_t validSize = 0;
    if (form == NULL || form->discExtra == NULL) {
        return validSize;
    }
    for (size_t i = 0; i < DISC_AUDIT_ASSIGNER_COUNT; ++i) {
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
#endif // DISC_AUDIT_CONVERTER_H
