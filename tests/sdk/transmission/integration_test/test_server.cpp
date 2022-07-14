#include "test_suite.h"

#include <getopt.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/time.h>
#include <sys/times.h>
#include <time.h>
#include <unistd.h>
#include <inttypes.h>

#include "transport/session.h"
#include "softbus_error_code.h"


typedef struct {
    const char *targetUdid;
    SessionType dataType;
    uint32_t packageSize;
    uint32_t sampleSize;
} TestConfig;

double g_aveRtt = 0;
double g_maxRtt = 0;

volatile bool g_sessionEnabled = false;
volatile uint32_t g_recvSeq = 0;
volatile clock_t g_responseTime = 0;
int g_sessionId = -1;

void CalcRTT(uint32_t seq, clock_t sendTime, clock_t rspTime)
{
    double rtt = (double)(rspTime - sendTime);
    LOG("%s:[RTT for %u] %lf", __func__, seq, rtt);
    if(rtt < 0) {
        LOG("%s:bad rtt %lf", __func__, rtt);
        return;
    }
    if (seq == 0 || seq == 1) {
        g_aveRtt = rtt;
        g_maxRtt = rtt;
        return;
    }

    g_aveRtt = g_aveRtt * (((double)(seq - 1)) / seq) + (rtt / seq);
    if (rtt > g_maxRtt) {
        g_maxRtt = rtt;
    }
    LOG("%s:[RTT]ave=%lf,max=%lf", __func__, g_aveRtt, g_maxRtt);
}

void ShowTestResult(void)
{
    LOG("average RTT:%lf", g_aveRtt / 2);
    LOG("max RTT:%lf", g_maxRtt / 2);
}

int EsOnSessionOpened(int sessionId, int result)
{
    LOG("%s:enter", __func__);
    if(result != SOFTBUS_OK) {
        LOG("%s:OpenSession failed!errCode=%d", __func__, result);
        return 0;
    }
    if (sessionId == g_sessionId) {
        LOG("%s:Session %d opened!", __func__, sessionId);
        g_sessionEnabled = true;
    }
    LOG("%s:Unexpected session %d opened!", __func__, sessionId);
    return 0;
}
void EsOnSessionClosed(int sessionId)
{
    LOG("%s:enter", __func__);
    if (sessionId == g_sessionId) {
        g_sessionEnabled = false;
        g_sessionId = -1;
    }
}

void EsOnDataReceived(int sessionId, const void *data, unsigned int dataLen)
{
    LOG("%s:enter", __func__);
}

void EsOnStreamReceived(int sessionId, const StreamData *data, const StreamData *ext, const StreamFrameInfo *param)
{
    LOG("%s:enter", __func__);
}
void EsOnQosEvent(int sessionId, int eventId, int tvCount, const QosTv *tvList)
{
    LOG("%s:enter", __func__);
}

static int TsOnReceiveFileStarted(int sessionId, const char *files, int fileCnt) {
    LOG("%s:session=%d, files=%s, count=%d", __func__, sessionId, files, fileCnt);
    return 0;
}

static int TsOnReceiveFileProcess(int sessionId, const char *firstFile, uint64_t bytesUpload, uint64_t bytesTotal) {
    LOG("%s:session=%d, firstFile=%s, bytesUpload=%" PRIu64 ", bytesTotal=%" PRIu64, __func__, sessionId, firstFile, bytesUpload, bytesTotal);
    return 0;
}
static void TsOnReceiveFileFinished(int sessionId, const char *files, int fileCnt) {
    LOG("%s:session=%d, files=%s, count=%d", __func__, sessionId, files, fileCnt);
}
static void TsOnFileTransError(int sessionId) {
    LOG("%s:session=%d", __func__, sessionId);
}

static int ExecTestSuite(const TestConfig *config)
{
    static ISessionListener listener = {
        .OnSessionOpened = EsOnSessionOpened,
        .OnSessionClosed = EsOnSessionClosed,
        .OnBytesReceived = EsOnDataReceived,
        .OnMessageReceived = EsOnDataReceived,
        .OnStreamReceived = EsOnStreamReceived,
        .OnQosEvent = EsOnQosEvent};

    int ret = CreateSessionServer(ECHO_SERVICE_PKGNAME, ECHO_SERVICE_SESSION_NAME, &listener);
    if (ret != 0) {
        LOG("%s:create session server failed!ret=%d", __func__, ret);
        return ret;
    }

    static IFileReceiveListener fileRecvListener = {
        .OnReceiveFileStarted = TsOnReceiveFileStarted,
        .OnReceiveFileProcess = TsOnReceiveFileProcess,
        .OnReceiveFileFinished = TsOnReceiveFileFinished,
        .OnFileTransError = TsOnFileTransError,
    };

    ret = SetFileReceiveListener(ECHO_SERVICE_PKGNAME, ECHO_SERVICE_SESSION_NAME, &fileRecvListener, "/data/recv_files");

    LOG("type x to exit:");
    char c = '0';
    do {
        c = getchar();
    } while (c != 'x');

    ret = RemoveSessionServer(ECHO_SERVICE_PKGNAME, ECHO_SERVICE_SESSION_NAME);
    if(ret != 0) {
        LOG("%s: remove session server failed! ret= %d", __func__, ret);
    }

    return ret;
}

int main(int argc, char * const *argv)
{
    TestConfig config = {.targetUdid = NULL, .dataType = TYPE_MESSAGE, .packageSize = 1000, .sampleSize = 1000};

    const char *optStr = "t:MB:P:S";
    static struct option options[] = {
        {"target",      required_argument, NULL, 't'},
        {"message",     no_argument,       NULL, 'M'},
        {"bytes",       no_argument,       NULL, 'B'},
        {"packageSize", required_argument, NULL, 'P'},
        {"sampleSize",  required_argument, NULL, 'S'},
        {0,             0,                 0,    0  },
    };
    int opt = 0;
    while ((opt = getopt_long(argc, argv, optStr, options, NULL)) != -1) {
        switch (opt) {
            case 't': {
                config.targetUdid = optarg;
                break;
            }
            case 'M': {
                config.dataType = TYPE_MESSAGE;
                break;
            }
            case 'B': {
                config.dataType = TYPE_BYTES;
                break;
            }
            case 'P': {
                config.packageSize = atoi(optarg);
                break;
            }
            case 'S': {
                config.sampleSize = atoi(optarg);
                break;
            }
            default: {
                break;
            }
        };
    }

    LOG("%s:send test", __func__);

    int ret = ExecTestSuite(&config);
    if (ret != 0) {
        LOG("%s:test failed!ret=%d", __func__, ret);
    } else {
        ShowTestResult();
    }
    return ret;
}