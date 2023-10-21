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

#include "wifi_direct_role_negotiator.h"
#include <string.h>
#include "softbus_error_code.h"
#include "softbus_log.h"
#include "utils/wifi_direct_utils.h"
#include "utils/wifi_direct_anonymous.h"

#define LOG_LABEL "[WifiDirect] WifiDirectRoleNegotiator: "

static enum WifiDirectRole GetFinalRoleAsGo(enum WifiDirectRole peerRole, enum WifiDirectRole expectedRole,
                                            const char *localGoMac, const char *remoteGoMac)
{
    if (peerRole == WIFI_DIRECT_ROLE_GO) {
        CLOGE(LOG_LABEL "ERROR_P2P_BOTH_GO");
        return ERROR_P2P_BOTH_GO;
    }
    if (peerRole == WIFI_DIRECT_ROLE_GC) {
        if (remoteGoMac == NULL || strlen(remoteGoMac) == 0 ||
            GetWifiDirectUtils()->strCompareIgnoreCase(remoteGoMac, localGoMac) != 0) {
            return ERROR_P2P_PEER_GC_CONNECTED_TO_ANOTHER_DEVICE;
        }
        if (expectedRole == WIFI_DIRECT_ROLE_GO) {
            CLOGE(LOG_LABEL "mismatched role, remote expect GO");
            return ERROR_P2P_GC_AVAILABLE_WITH_MISMATCHED_ROLE;
        }
        return WIFI_DIRECT_ROLE_GO;
    }
    if (peerRole == WIFI_DIRECT_ROLE_NONE) {
        if (expectedRole == WIFI_DIRECT_ROLE_GO) {
            CLOGE(LOG_LABEL "mismatched role, remote expect GO");
            return ERROR_P2P_GC_AVAILABLE_WITH_MISMATCHED_ROLE;
        }
        return WIFI_DIRECT_ROLE_GO;
    }

    CLOGE(LOG_LABEL "peeRole=%d invalid", peerRole);
    return ERROR_INVALID_INPUT_PARAMETERS;
}

static enum WifiDirectRole GetFinalRoleAsGc(enum WifiDirectRole peerRole, enum WifiDirectRole expectedRole,
                                            const char *localGoMac, const char *remoteGoMac)
{
    if (peerRole == WIFI_DIRECT_ROLE_GO) {
        if (localGoMac != NULL && strlen(localGoMac) != 0 &&
            GetWifiDirectUtils()->strCompareIgnoreCase(localGoMac, remoteGoMac) == 0) {
            return WIFI_DIRECT_ROLE_GC;
        }
        CLOGE(LOG_LABEL "ERROR_P2P_GC_CONNECTED_TO_ANOTHER_DEVICE");
        return ERROR_P2P_GC_CONNECTED_TO_ANOTHER_DEVICE;
    }
    if (peerRole == WIFI_DIRECT_ROLE_NONE) {
        CLOGE(LOG_LABEL "ERROR_WIFI_DIRECT_NO_AVAILABLE_INTERFACE");
        return ERROR_WIFI_DIRECT_NO_AVAILABLE_INTERFACE;
    }
    CLOGE(LOG_LABEL "ERROR_P2P_GC_CONNECTED_TO_ANOTHER_DEVICE");
    return ERROR_P2P_GC_CONNECTED_TO_ANOTHER_DEVICE;
}

static enum WifiDirectRole GetFinalRoleAsNone(enum WifiDirectRole peerRole, enum WifiDirectRole expectedRole)
{
    if (peerRole == WIFI_DIRECT_ROLE_GO) {
        if (expectedRole == WIFI_DIRECT_ROLE_GC) {
            CLOGE(LOG_LABEL "mismatched role, peerRole=%d expectRole=", peerRole, expectedRole);
            return ERROR_P2P_GC_AVAILABLE_WITH_MISMATCHED_ROLE;
        }
        return WIFI_DIRECT_ROLE_GC;
    }
    if (peerRole == WIFI_DIRECT_ROLE_GC) {
        if (expectedRole == WIFI_DIRECT_ROLE_GO) {
            CLOGE(LOG_LABEL "mismatched role, remote expect GO");
            return ERROR_P2P_GC_AVAILABLE_WITH_MISMATCHED_ROLE;
        }
        return ERROR_P2P_GC_CONNECTED_TO_ANOTHER_DEVICE;
    }
    if (peerRole == WIFI_DIRECT_ROLE_NONE) {
        if (expectedRole == WIFI_DIRECT_ROLE_GC) {
            return WIFI_DIRECT_ROLE_GO;
        }
        return WIFI_DIRECT_ROLE_GC;
    }

    CLOGE(LOG_LABEL "peeRole=%d invalid", peerRole);
    return SOFTBUS_INVALID_PARAM;
}

static enum WifiDirectRole GetFinalRoleWithPeerExpectedRole(enum WifiDirectRole myRole, enum WifiDirectRole peerRole,
                                                            enum WifiDirectRole expectedRole, const char *localGoMac,
                                                            const char *remoteGoMac)
{
    CLOGI(LOG_LABEL "myRole=%d peerRole=%d expectedRole=%d localGoMac=%s remoteGoMac=%s",
          myRole, peerRole, expectedRole, WifiDirectAnonymizeMac(localGoMac), WifiDirectAnonymizeMac(remoteGoMac));
    if (myRole == WIFI_DIRECT_ROLE_GO) {
        return GetFinalRoleAsGo(peerRole, expectedRole, localGoMac, remoteGoMac);
    } else if (myRole == WIFI_DIRECT_ROLE_GC) {
        return GetFinalRoleAsGc(peerRole, expectedRole, localGoMac, remoteGoMac);
    } else if (myRole == WIFI_DIRECT_ROLE_NONE) {
        return GetFinalRoleAsNone(peerRole, expectedRole);
    } else {
        CLOGE(LOG_LABEL "myRole=%d invalid", myRole);
        return SOFTBUS_INVALID_PARAM;
    }
}

static struct WifiDirectRoleNegotiator g_roleNegotiator = {
    .getFinalRoleWithPeerExpectedRole = GetFinalRoleWithPeerExpectedRole,
};

struct WifiDirectRoleNegotiator *GetRoleNegotiator(void)
{
    return &g_roleNegotiator;
}