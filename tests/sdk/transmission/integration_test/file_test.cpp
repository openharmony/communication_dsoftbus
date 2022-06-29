#include <gtest/gtest.h>

#include <inttypes.h>
#include "test_suite.h"
#include "transport/session.h"

#include "device_manager.h"

const char *groupId = "echo";

using namespace testing::ext;

namespace OHOS {

class FileTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown() {};
};

int g_sessionId = -1;
bool g_sessionEnabled = false;

static inline int WaitConnectionReady(int sessionId, uint32_t timeout)
{
    while (!g_sessionEnabled && (timeout--) > 0) {
        sleep(1);
    }

    if (!g_sessionEnabled) {
        LOG("%s:OpenSession timeout!", __func__);
        return -1;
    }
    return 0;
}

int FtOnSendFileProcess(int sessionId, uint64_t bytesUpload, uint64_t bytesTotal) {
    LOG("%s:sessionId=%d,bytesUpload=%" PRIu64 ", bytesTotal=%" PRIu64, __func__, sessionId, bytesUpload, bytesTotal);
    return 0;
}
int FtOnSendFileFinished(int sessionId, const char *firstFile) {
    LOG("%s:sessionId=%d,firstfile=%s", __func__, sessionId, firstFile);
    return 0;
}
void FtOnFileTransError(int sessionId) {
    LOG("%s:sessionId=%d", __func__, sessionId);
}

int EsOnSessionOpened(int sessionId, int result)
{
    LOG("%s:enter, sessionId=%d", __func__, sessionId);
    if (sessionId == g_sessionId) {
        g_sessionEnabled = true;
    }
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
}

void EsOnStreamReceived(int sessionId, const StreamData *data, const StreamData *ext, const StreamFrameInfo *param)
{
    LOG("%s:enter", __func__);
}
void EsOnQosEvent(int sessionId, int eventId, int tvCount, const QosTv *tvList)
{
    LOG("%s:enter", __func__);
}

void FileTest::SetUpTestCase()
{
    static ISessionListener sessionListener = {.OnSessionOpened = EsOnSessionOpened,
        .OnSessionClosed = EsOnSessionClosed,
        .OnBytesReceived = EsOnDataReceived,
        .OnMessageReceived = EsOnDataReceived,
        .OnStreamReceived = EsOnStreamReceived,
        .OnQosEvent = EsOnQosEvent};

    ASSERT_EQ(0, CreateSessionServer(ECHO_SERVICE_PKGNAME, ECHO_SERVICE_SESSION_NAME, &sessionListener));

    static IFileSendListener fileSendListener = {
        .OnSendFileProcess = FtOnSendFileProcess,
        .OnSendFileFinished = FtOnSendFileFinished,
        .OnFileTransError = FtOnFileTransError,
    };

    ASSERT_EQ(0, SetFileSendListener(ECHO_SERVICE_PKGNAME, ECHO_SERVICE_SESSION_NAME, &fileSendListener));
}

void FileTest::TearDownTestCase()
{
    EXPECT_EQ(0, RemoveSessionServer(ECHO_SERVICE_PKGNAME, ECHO_SERVICE_SESSION_NAME));
};

static SessionAttribute *GetSessionAttr()
{
    static SessionAttribute attr = {
        .dataType = TYPE_FILE,
        .linkTypeNum = 1,
        .linkType = {LINK_TYPE_BR}
    };
    return &attr;
}

void FileTest::SetUp()
{
    DeviceManager::Instance()->WaitNetworkSizeMoreThan(1);
};

HWTEST_F(FileTest, SendFileDstNULL, TestSize.Level0)
{
    g_sessionId = OpenSession(ECHO_SERVICE_SESSION_NAME, ECHO_SERVICE_SESSION_NAME,
        DeviceManager::Instance()->GetRemoteByIndex(0).c_str(), groupId, GetSessionAttr());
    ASSERT_GT(g_sessionId, 0);

    const char *sFileList[] = {"/data/send_files/test_a.jpg", "/data/send_files/test_b.jpg"};

    ASSERT_EQ(WaitConnectionReady(g_sessionId, 5), 0);
    LOG("SendFile with sessionId %d", g_sessionId);
    EXPECT_EQ(0, SendFile(g_sessionId, sFileList, nullptr, sizeof(sFileList) / sizeof(const char *)));

    CloseSession(g_sessionId);
}

}; // namespace OHOS
