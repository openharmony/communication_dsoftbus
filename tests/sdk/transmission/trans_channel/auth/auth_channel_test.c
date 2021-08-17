#include <stdio.h>

#include "securec.h"
#include "softbus_errcode.h"
#include "discovery_service.h"
#include "pthread.h"
#include "session.h"
#include "softbus_common.h"
#include "softbus_json_utils.h"
#include "softbus_def.h"

#define TEST_AUTH_SUBSCRIBE_ID 10
#define TEST_CAP "ddmpCapability"
#define AUTH_INFO_LEN 128
#define TEST_DEVICE_ID "ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00"
#define LOCAL_IP "192.168.101.8"
#define LOCAL_PORT 6688


const static char *g_pkgName = "com.huawei.plrdtest.dsoftbus";
const static char *g_authSessionName = "com.huawei.plrdtest.dsoftbus";
const static char *g_sessionName = "com.huawei.plrdtest.dsoftbus.JtAuthMsgService";

static int AuthOnSessionOpened(int sessionId, int result)
{
    printf("AuthOnSessionOpened sessionId=%d, result=%d\n", sessionId, result);
    return 0;
}

static void AuthOnSessionClosed(int sessionId)
{
    printf("AuthOnSessionClosed sessionId=%d\n", sessionId);
}

static void AuthOnBytesReceived(int sessionId, const void *data, unsigned int dataLen)
{
    printf("AuthOnBytesReceived sessionId=%d dataLen=%d\n", sessionId, dataLen);
}

static void AuthOnMessageReceived(int sessionId, const void *data, unsigned int dataLen)
{
    printf("AuthOnMessageReceived sessionId=%d dataLen=%d\n", sessionId, dataLen);
}

static ISessionListener g_authSessionListener = {
    .OnSessionOpened = AuthOnSessionOpened,
    .OnSessionClosed = AuthOnSessionClosed,
    .OnBytesReceived = AuthOnBytesReceived,
    .OnMessageReceived = AuthOnMessageReceived,
    .OnStreamReceived = NULL
};

static int g_dcSessionId = -1;

static int OnSessionOpened(int sessionId, int result)
{
    printf("OnSessionOpened sessionId=%d, result=%d\n", sessionId, result);
    if (result == 0) {
        g_dcSessionId = sessionId;
    }
    return 0;
}

static void OnSessionClosed(int sessionId)
{
    printf("OnSessionClosed sessionId=%d\n", sessionId);
    g_dcSessionId = -1;
}

static void OnBytesReceived(int sessionId, const void *data, unsigned int dataLen)
{
    printf("OnBytesReceived sessionId=%d dataLen=%d\n", sessionId, dataLen);
}

static void OnMessageReceived(int sessionId, const void *data, unsigned int dataLen)
{
    printf("OnMessageReceived sessionId=%d dataLen=%d\n", sessionId, dataLen);
}

static ISessionListener g_dcSessionListener = {
    .OnSessionOpened = OnSessionOpened,
    .OnSessionClosed = OnSessionClosed,
    .OnBytesReceived = OnBytesReceived,
    .OnMessageReceived = OnMessageReceived,
    .OnStreamReceived = NULL
};

static char g_ip[IP_STR_MAX_LEN];
static int g_port = -1;
static pthread_mutex_t g_lock;
static pthread_cond_t g_cond;

static void TestOnDeviceFound(const DeviceInfo *device)
{
    (void)memcpy_s(g_ip, IP_STR_MAX_LEN, device->addr[0].info.ip.ip, IP_STR_MAX_LEN);
    g_port = device->addr[0].info.ip.port;
    printf("TestOnDeviceFound ip:%s port:%d\n", g_ip, g_port);
    pthread_cond_signal(&g_cond);
}

static void TestOnDiscoverFailed(int subscribeId, DiscoveryFailReason failReason)
{
    printf("TestOnDiscoverFailed subscribeId=%d failReason=%d\n", subscribeId, failReason);
}

static void TestOnDiscoverySuccess(int subsribeId)
{
    printf("TestOnDiscoverySuccess subsribeId=%d", subsribeId);
}

static IDiscoveryCallback g_discCb = {
    .OnDeviceFound = TestOnDeviceFound,
    .OnDiscoverFailed = TestOnDiscoverFailed,
    .OnDiscoverySuccess = TestOnDiscoverySuccess
};

static SubscribeInfo g_discInfo = {
    .subscribeId = TEST_AUTH_SUBSCRIBE_ID,
    .mode = DISCOVER_MODE_ACTIVE,
    .medium = COAP,
    .freq = HIGH,
    .capability = TEST_CAP,
    .capabilityData = "12345",
    .dataLen = sizeof("12345"),
};

static int CreateAuthInfo(char *authInfo)
{
    if (authInfo == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    cJSON *obj = cJSON_CreateObject();
    if (obj == NULL) {
        return SOFTBUS_MALLOC_ERR;
    }
    if (!AddStringToJsonObject(obj, "WIFI_IP", LOCAL_IP) ||
        !AddNumberToJsonObject(obj, "WIFI_PORT", LOCAL_PORT)) {
        cJSON_Delete(obj);
        return SOFTBUS_PARSE_JSON_ERR;
    }
    char *data = cJSON_PrintUnformatted(obj);
    if (memcpy_s(authInfo, AUTH_INFO_LEN, data, strlen(data)) != EOK) {
        return SOFTBUS_MEM_ERR;
    }
    cJSON_Delete(obj);
    return SOFTBUS_OK;
}

static int Init()
{
    (void)pthread_mutex_init(&g_lock, NULL);
    (void)pthread_cond_init(&g_cond, NULL);
    pthread_mutex_lock(&g_lock);
    int ret = StartDiscovery(g_pkgName, &g_discInfo, &g_discCb);
    if (ret < 0) {
        return ret;
    }
    ret = CreateSessionServer(g_pkgName, g_sessionName, &g_dcSessionListener);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    return CreateSessionServer(g_pkgName, g_authSessionName, &g_authSessionListener);
}

static int TestOpenAuthSession1(const char *ip, int port)
{
    ConnectionAddr addr;
    addr.type = CONNECTION_ADDR_ETH;
    addr.info.ip.port = port;
    (void)memcpy_s(addr.info.ip.ip, IP_STR_MAX_LEN, ip, IP_STR_MAX_LEN);
    return OpenAuthSession(g_authSessionName, &addr);
}

static int TestOpenAuthSession2(const char *ip, int port)
{
    ConnectionAddr addr;
    addr.type = CONNECTION_ADDR_MIX;
    sprintf(addr.info.mixAddr.addr, "{\"WIFI_IP\":\"%s\",\"WIFI_PORT\":%d}", ip, port);
    return OpenAuthSession(g_authSessionName, &addr);
}

int main(int argc, char **argv)
{
    if (Init() != 0) {
        printf("Init failed");
        return 0;
    }
    
    pthread_cond_wait(&g_cond, &g_lock);
    pthread_mutex_unlock(&g_lock);
    int cmd;
    int authSessionId;
    int sessionId;
    int side;
    char deviceId[DEVICE_ID_SIZE_MAX];
    const char *authTestMsg = "Hello";
    char authInfo[AUTH_INFO_LEN] = {0};
    if (CreateAuthInfo(authInfo) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    while (1) {
        scanf("%d %d", &cmd, &authSessionId);
        switch (cmd) {
            case 1:
                // TestOpenAuthSession1(argv[1], atoi(argv[2]));
                TestOpenAuthSession1(g_ip, g_port);
                break;
            case 2:
                // TestOpenAuthSession1(argv[1], atoi(argv[2]));
                TestOpenAuthSession2(g_ip, g_port);
                break;
            case 3:
                SendMessage(authSessionId, authTestMsg, strlen(authTestMsg));
                break;
            case 4:
                CloseSession(authSessionId);
                break;
            case 5:
                SendMessage(g_dcSessionId, authInfo, strlen(authInfo));
                break;
            case 6:
                side = GetSessionSide(authSessionId);
                printf("GetSessionSide: %d\n", side);
                break;
            case 7:
                if (GetPeerDeviceId(authSessionId, deviceId, DEVICE_ID_SIZE_MAX) != SOFTBUS_OK) {
                    printf("GetPeerDeviceId failed\n");
                } else {
                    printf("GetPeerDeviceId: %s\n", deviceId);
                }
                break;
            default:
                break;
        }
    }
    return 0;
}