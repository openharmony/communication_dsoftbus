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

#include "auth_socket.h"

#include <securec.h>

#include "auth_connection.h"
#include "bus_center_manager.h"
#include "softbus_base_listener.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_mem_interface.h"
#include "softbus_tcp_socket.h"

#define AUTH_DEFAULT_PORT (-1)
#define AUTH_HEART_TIME (10 * 60)

#ifdef __cplusplus
extern "C" {
#endif

static SoftbusBaseListener g_ethListener = {0};

int32_t HandleIpVerifyDevice(AuthManager *auth, const ConnectOption *option)
{
    if (auth == NULL || option == NULL) {
        LOG_ERR("invalid parameter");
        return SOFTBUS_ERR;
    }
    char localIp[IP_MAX_LEN] = {0};
    if (LnnGetLocalStrInfo(STRING_KEY_WLAN_IP, localIp, IP_MAX_LEN) != SOFTBUS_OK) {
        LOG_ERR("auth get local ip failed");
        return SOFTBUS_ERR;
    }
    int fd = OpenTcpClientSocket(option->info.ipOption.ip, localIp, option->info.ipOption.port);
    if (fd < 0) {
        LOG_ERR("auth OpenTcpClientSocket failed");
        return SOFTBUS_ERR;
    }
    auth->fd = fd;
    if (AddTrigger(AUTH, fd, RW_TRIGGER) != SOFTBUS_OK) {
        LOG_ERR("auth AddTrigger failed");
        return SOFTBUS_ERR;
    }
    if (SetTcpKeepAlive(fd, AUTH_HEART_TIME) != SOFTBUS_OK) {
        LOG_ERR("auth set tcp keep alive failed");
        return SOFTBUS_ERR;
    }
    if (AuthSyncDeviceUuid(auth) != SOFTBUS_OK) {
        LOG_ERR("AuthSyncDeviceUuid failed");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static void AuthIpOnDataReceived(int32_t fd, const ConnPktHead *head, char *data, int len)
{
    if (head == NULL || data == NULL) {
        LOG_ERR("invalid parameter");
        return;
    }
    AuthManager *auth = NULL;
    auth = AuthGetManagerByFd(fd);
    if (auth == NULL) {
        LOG_ERR("ip get auth failed");
        return;
    }
    if (auth->authId != head->seq && auth->authId != 0 && head->module != MODULE_UDP_INFO) {
        if (head->seq != 0 || head->module != MODULE_AUTH_CONNECTION) {
            return;
        }
    }
    LOG_INFO("auth ip data module is %d", head->module);
    switch (head->module) {
        case MODULE_TRUST_ENGINE: {
            if (auth->side == SERVER_SIDE_FLAG && head->flag == 0 && auth->authId == 0) {
                auth->authId = head->seq;
                LOG_INFO("server ip authId is %lld", auth->authId);
            }
            HandleReceiveDeviceId(auth, (uint8_t *)data);
            break;
        }
        case MODULE_AUTH_SDK: {
            HandleReceiveAuthData(auth, head->module, (uint8_t *)data, head->len);
            break;
        }
        case MODULE_AUTH_CONNECTION: {
            AuthHandlePeerSyncDeviceInfo(auth, (uint8_t *)data, head->len);
            break;
        }
        case MODULE_UDP_INFO: {
            AuthHandleTransInfo(auth, head, data, head->len);
            break;
        }
        default: {
            LOG_ERR("unknown data type");
            break;
        }
    }
}

static void AuthNotifyLnnDisconn(int32_t fd)
{
    AuthManager *auth = NULL;
    auth = AuthGetManagerByFd(fd);
    if (auth == NULL) {
        LOG_ERR("ip get auth failed");
        return;
    }
    LOG_INFO("auth disconnect");
    AuthNotifyLnnDisconnByIp(auth->option.info.ipOption.ip);
}

static void AuthIpDataProcess(int32_t fd, const ConnPktHead *head)
{
    char *data = NULL;
    int32_t remainLen;
    ssize_t len;

    char *ipData = (char *)SoftBusMalloc(head->len);
    if (ipData == NULL) {
        LOG_ERR("SoftBusMalloc failed");
        return;
    }
    data = ipData;
    remainLen = head->len;
    do {
        len = RecvTcpData(fd, data, remainLen, 0);
        if (len <= 0) {
            LOG_ERR("auth recv data len not correct, len %d", len);
            break;
        } else if (len < remainLen) {
            data = data + len;
            remainLen = remainLen - len;
        } else {
            AuthIpOnDataReceived(fd, head, ipData, head->len);
            remainLen = 0;
        }
    } while (remainLen > 0);
    SoftBusFree(ipData);
}

static int32_t AuthOnDataEvent(int32_t events, int32_t fd)
{
    if (events != SOFTBUS_SOCKET_IN) {
        return SOFTBUS_ERR;
    }
    uint32_t headSize = sizeof(ConnPktHead);
    ssize_t len;

    ConnPktHead head = {0};
    len = RecvTcpData(fd, (void *)&head, headSize, 0);
    if (len < (int32_t)headSize) {
        if (len < 0) {
            LOG_ERR("auth RecvTcpData failed, DelTrigger");
            (void)DelTrigger(AUTH, fd, RW_TRIGGER);
            AuthNotifyLnnDisconn(fd);
        }
        LOG_ERR("auth recv data head len not correct, len is %d", len);
        return SOFTBUS_ERR;
    }

    LOG_INFO("auth recv eth data, head len is %d, module = %d, flag = %d, seq = %lld",
        head.len, head.module, head.flag, head.seq);
    if (head.len > AUTH_MAX_DATA_LEN) {
        LOG_ERR("auth head len is out of size");
        return SOFTBUS_ERR;
    }
    AuthIpDataProcess(fd, &head);

    return SOFTBUS_OK;
}

int32_t AuthSocketSendData(AuthManager *auth, const AuthDataHead *head, const uint8_t *data, uint32_t len)
{
    if (auth == NULL || head == NULL || data == NULL) {
        LOG_ERR("invalid parameter");
        return SOFTBUS_ERR;
    }
    ConnPktHead ethHead;
    uint32_t postDataLen;
    char *connPostData = NULL;
    ethHead.magic = MAGIC_NUMBER;
    ethHead.module = head->module;
    if (head->module == MODULE_UDP_INFO) {
        ethHead.seq = head->seq;
        ethHead.flag = head->flag;
    } else {
        ethHead.seq = auth->authId;
        ethHead.flag = auth->side;
    }
    ethHead.len = len;
    postDataLen = sizeof(ConnPktHead) + len;
    char *buf = (char *)SoftBusMalloc(postDataLen);
    if (buf == NULL) {
        LOG_ERR("SoftBusMalloc failed");
        return SOFTBUS_ERR;
    }
    connPostData = buf;
    if (memcpy_s(buf, sizeof(ConnPktHead), &ethHead, sizeof(ConnPktHead)) != EOK) {
        LOG_ERR("memcpy_s failed");
        SoftBusFree(connPostData);
        return SOFTBUS_ERR;
    }
    buf += sizeof(ConnPktHead);
    if (memcpy_s(buf, len, data, len) != EOK) {
        LOG_ERR("memcpy_s failed");
        SoftBusFree(connPostData);
        return SOFTBUS_ERR;
    }
    LOG_INFO("auth start post eth data, authId is %lld, moduleId is %d, len is %u",
        auth->authId, head->module, len);
    ssize_t byte = SendTcpData(auth->fd, connPostData, postDataLen, 0);
    if (byte != (ssize_t)postDataLen) {
        LOG_ERR("SendTcpData failed");
        SoftBusFree(connPostData);
        return SOFTBUS_ERR;
    }
    SoftBusFree(connPostData);
    return SOFTBUS_OK;
}

static int32_t AuthOnConnectEvent(int32_t events, int32_t cfd, const char *ip)
{
    if (events == SOFTBUS_SOCKET_EXCEPTION) {
        LOG_ERR("auth Exception occurred");
        return SOFTBUS_ERR;
    }
    if (cfd < 0 || ip == NULL) {
        LOG_ERR("invalid parameter");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t port = GetTcpSockPort(cfd);
    if (port <= 0) {
        LOG_ERR("auth GetTcpSockPort failed");
        return SOFTBUS_ERR;
    }
    if (AddTrigger(AUTH, cfd, RW_TRIGGER) != SOFTBUS_OK) {
        LOG_ERR("auth AddTrigger failed");
        return SOFTBUS_ERR;
    }
    if (CreateServerIpAuth(cfd, ip, port) != SOFTBUS_OK) {
        LOG_ERR("auth CreateServerIpAuth failed");
        AuthCloseTcpFd(cfd);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t OpenAuthServer(void)
{
    int32_t localPort;
    g_ethListener.onConnectEvent = AuthOnConnectEvent;
    g_ethListener.onDataEvent = AuthOnDataEvent;
    if (SetSoftbusBaseListener(AUTH, &g_ethListener) != SOFTBUS_OK) {
        LOG_ERR("auth SetSoftbusBaseListener failed");
        return AUTH_ERROR_CODE;
    }
    char localIp[IP_MAX_LEN] = {0};
    if (LnnGetLocalStrInfo(STRING_KEY_WLAN_IP, localIp, IP_MAX_LEN) != SOFTBUS_OK) {
        LOG_ERR("auth LnnGetLocalStrInfo failed");
        return AUTH_ERROR_CODE;
    }
    localPort = StartBaseListener(AUTH, localIp, 0, SERVER_MODE);
    if (localPort <= 0) {
        LOG_ERR("auth StartBaseListener failed!");
        return AUTH_ERROR_CODE;
    }
    return localPort;
}

void AuthCloseTcpFd(int32_t fd)
{
    (void)DelTrigger(AUTH, fd, RW_TRIGGER);
    CloseTcpFd(fd);
}

void CloseAuthServer(void)
{
    LOG_INFO("close auth listener");
    if (StopBaseListener(AUTH) != SOFTBUS_OK) {
        LOG_ERR("auth StopBaseListener failed");
    }
    DestroyBaseListener(AUTH);
}

#ifdef __cplusplus
}
#endif
