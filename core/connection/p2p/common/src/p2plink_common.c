/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#include <stdbool.h>

#include "p2plink_adapter.h"
#include "p2plink_type.h"
#include "securec.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_log.h"

static P2pLinkRole g_role = ROLE_NONE;
static char g_myIp[P2P_IP_LEN] = {0};
static char g_myMac[P2P_MAC_LEN] = {0};
static char g_goIp[P2P_IP_LEN] = {0};
static char g_goMac[P2P_MAC_LEN] = {0};
int32_t g_goPort = 0;
int32_t g_gcPort = 0;
static bool g_isDisconnect = false;
bool g_macExpired = true;

static char g_interface[P2PLINK_INTERFACE_LEN] = {0};
static bool g_p2plinkState = false;
static bool g_p2plinkDhcp = false;

P2pLinkRole P2pLinkGetRole(void)
{
    return g_role;
}

void P2pLinkSetRole(P2pLinkRole role)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "set my role %d", role);
    g_role = role;
}

void P2pLinkSetMyIp(const char *ip)
{
    int32_t ret = strcpy_s(g_myIp, sizeof(g_myIp), ip);
    if (ret != EOK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "strcpy error");
    }
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "set my ip.");
}

char* P2pLinkGetMyIp(void)
{
    return g_myIp;
}

char* P2pLinkGetMyMac(void)
{
    char myMac[P2P_MAC_LEN] = {0};

    if (g_macExpired == true) {
        int32_t ret = P2pLinkGetBaseMacAddress(myMac, sizeof(myMac));
        if (ret == SOFTBUS_OK) {
            ret = strcpy_s(g_myMac, sizeof(g_myMac), myMac);
            if (ret != EOK) {
                SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "strcpy error");
            }
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "get my mac");
        }
    }
    return g_myMac;
}

void P2pLinkSetGoIp(const char *ip)
{
    int32_t ret = strcpy_s(g_goIp, sizeof(g_goIp), ip);
    if (ret != EOK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "strcpy error");
    }
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "set go ip");
}

void P2pLinkSetGoMac(const char *mac)
{
    if (strcpy_s(g_goMac, sizeof(g_goMac), mac) != EOK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "strcpy error");
    }
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "set go mac");
}

void P2pLinkSetGoPort(int32_t port)
{
    g_goPort = port;
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "set go port %d", g_goPort);
}

void P2pLinkSetGcPort(int32_t port)
{
    g_gcPort = port;
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "set gc port %d", g_goPort);
}

int32_t P2pLinkGetGcPort(void)
{
    return g_gcPort;
}

char* P2pLinkGetGoIp(void)
{
    if (g_role == ROLE_GO) {
        return P2pLinkGetMyIp();
    }
    return g_goIp;
}

char* P2pLinkGetGoMac(void)
{
    if (g_role == ROLE_GO) {
        return P2pLinkGetMyMac();
    }
    return g_goMac;
}

int32_t P2pLinkGetGoPort(void)
{
    return g_goPort;
}

void P2pLinkSetMyMacExpired(bool isExpired)
{
    g_macExpired = isExpired;
}

void P2pLinkSetState(bool state)
{
    g_p2plinkState = state;
}

bool P2pLinkIsEnable(void)
{
    return g_p2plinkState;
}

void P2pLinkSetDhcpState(bool isNeedDhcp)
{
    g_p2plinkDhcp = isNeedDhcp;
}

bool P2pLinkGetDhcpState(void)
{
    return g_p2plinkDhcp;
}

bool P2pLinkIsDisconnectState(void)
{
    return g_isDisconnect;
}

void P2pLinkSetDisconnectState(bool state)
{
    g_isDisconnect = state;
}

void P2pLinkCommonInit(void)
{
    g_macExpired = true;
    g_role = ROLE_NONE;
    return;
}

void P2pLinkCommonClean(void)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "P2pLinkCommonClean");
    g_role = ROLE_NONE;
    g_myIp[0] = 0;
    g_myMac[0] = 0;
    g_goIp[0] = 0;
    g_goMac[0] = 0;
    g_p2plinkDhcp = false;
    g_interface[0] = 0;
    g_macExpired = true;
    P2pLinkSetDisconnectState(false);
}