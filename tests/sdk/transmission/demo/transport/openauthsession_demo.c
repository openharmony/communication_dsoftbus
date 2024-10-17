/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

/**
 * @file openauthsession_demo.c
 *
 * @brief Provides the sample code for opening an authentication session.
 *
 * @since 1.0
 * @version 1.0
 */

// Device A:

#include <stdio.h>
#include "inner_session.h"
#include "session.h"

ConnectionAddr g_addrInfo; // Information about the connection between devices
const char *g_pkgNameA = "dms"; // Application bundle name of device A
const char *g_sessionNameA = "ohos.distributedschedule.dms.test";  // Session name of device A

// Notify that the session is set up successfully.
static int32_t OnSessionOpened(int32_t sessionId, int32_t result)
{
    printf("session opened,sesison id = %d\r\n", sessionId);
    return 0;
}

// Notify that the session is closed.
static void OnSessionClosed(int32_t sessionId)
{
    printf("session closed, session id = %d\r\n", sessionId);
}

// Notify that byte data is received.
static void OnBytesReceived(int32_t sessionId, const void *data, unsigned int len)
{
    printf("session bytes received, session id = %d\r\n", sessionId);
}

// Notify that the message is received.
static void OnMessageReceived(int32_t sessionId, const void *data, unsigned int len)
{
    printf("session msg received, session id = %d\r\n", sessionId);
}

static ISessionListener g_sessionlistenerA = {
    .OnSessionOpened = OnSessionOpened,
    .OnSessionClosed = OnSessionClosed,
    .OnBytesReceived = OnBytesReceived,
    .OnMessageReceived = OnMessageReceived,
};

int32_t main(void)
{
    /*
     * 1. Device A calls CreateSessionServer() to create a session server based on
     * the application bundle name and session name, and registers the callbacks for session opened, session closed,
     * byte received, and message received.
     */
    int32_t ret = CreateSessionServer(g_pkgNameA, g_sessionNameA, &g_sessionlistenerA);
    printf("create session server result = %d\n", ret);

    /*
     * 2. Device A calls OpenAuthSession() to create a raw channel for identity negotiation based on the session name
     * and connection information before networking.
     */
    int32_t sessionId = OpenAuthSession(g_sessionNameA, &(g_addrInfo), 1, NULL);
    printf("open auth session result = %d\n", sessionId);

    /*
     * 3. When the identity authentication is complete,
     * NotifyAuthSuccess is called to notify device A of the authentication success.
     */
    NotifyAuthSuccess(sessionId);

    /* 4. After the authentication is successful, device A closes the session and removes the session server. */
    ret = RemoveSessionServer(g_pkgNameB, g_sessionNameB);
    printf("remove session server result = %d\n", ret);
}

// Device B:

#include <stdio.h>
#include "inner_session.h"
#include "session.h"

const char *g_pkgNameB = "dmsB"; // Application bundle name of device B
const char *g_sessionNameB = "ohos.distributedschedule.dms.testB";  // Session name of device B

static int32_t OnSessionOpened(int32_t sessionId, int32_t result)
{
    printf("session opened,sesison id = %d\r\n", sessionId);
    return 0;
}

static void OnSessionClosed(int32_t sessionId)
{
    printf("session closed, session id = %d\r\n", sessionId);
}

static void OnBytesReceived(int32_t sessionId, const void *data, unsigned int len)
{
    printf("session bytes received, session id = %d\r\n", sessionId);
}

static void OnMessageReceived(int32_t sessionId, const void *data, unsigned int len)
{
    printf("session msg received, session id = %d\r\n", sessionId);
}

static ISessionListener g_sessionlistenerB = {
    .OnSessionOpened = OnSessionOpened,
    .OnSessionClosed = OnSessionClosed,
    .OnBytesReceived = OnBytesReceived,
    .OnMessageReceived = OnMessageReceived,
};

int32_t main(void)
{
    /*
     * 1. Device B calls CreateSessionServer to create a session server based on
     * the application bundle name and session name, and registers the callbacks for session opened and session closed.
     */
    int32_t ret = CreateSessionServer(g_pkgNameB, g_sessionNameB, &g_sessionlistenerB);
    printf("create session server result = %d\n", ret);

    /*
     * 2. When device B receives information about the identity authentication session negotiation from device A,
     * OnSessionOpened is called to notify device B that the identity authentication session is successfully opened.
     */

    /* 3. After the authentication is successful, device B closes the session and removes the session server. */
    ret = RemoveSessionServer(g_pkgNameB, g_sessionNameB);
    printf("remove session server result = %d\n", ret);
}
