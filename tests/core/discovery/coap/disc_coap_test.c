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

#include <stdio.h>
#include <sys/time.h>
#include <unistd.h>

#include "disc_coap.h"
#include "securec.h"

#define DISC_TEST_ERR (-1)
#define DISC_TEST_OK 0
#define DISC_COAP_CAP_2 2
#define DISC_COAP_CAP_4 4
#define DISC_COAP_CAP_15 15
#define DISC_MAX_MS_NUM 5000
#define US_PER_MS 1000
#define US_PER_SECOND 1000000

static DiscoveryFuncInterface *g_coapDiscFunc = NULL;
static struct timeval g_startTime;
static struct timeval g_endTime;
static int32_t g_timeDelayFlag = 0;

static void OnDeviceFound(const DeviceInfo *device)
{
    gettimeofday(&g_endTime, NULL);
    g_timeDelayFlag = 1;
    printf("***********OnDeviceFound!!!!!******************************************\n");
    printf("id : %s.\n", device->devId);
    printf("name : %s.\n", device->devName);
    printf("device type : %u.\n", device->devType);
    printf("capNum : %u.\n", device->capabilityBitmapNum);
    for (uint32_t i = 0; i < device->capabilityBitmapNum; i++) {
        printf("capBitmap[%u] : %u.\n", i, device->capabilityBitmap[i]);
    }
    printf("addr num : %u.\n", device->addrNum);
    printf("ip : %s.\n", device->addr[0].addr);
    printf("port : %d.\n", device->addr[0].port);
    printf("connect type : %d.\n", device->addr[0].type);
    printf("hw account hash : %s.\n", device->hwAccountHash);
    printf("**********************************************************************\n");
    return;
}

static DiscInnerCallback g_discInnerCb = {
    .OnDeviceFound = OnDeviceFound
};

static PublishOption g_publishOption = {
    .freq = 0,
    .capabilityBitmap = {1},
    .capabilityData = NULL,
    .dataLen = 0
};

static SubscribeOption g_subscribeOption = {
    .freq = 1,
    .isSameAccount = true,
    .isWakeRemote = false,
    .capabilityBitmap = {2},
    .capabilityData = NULL,
    .dataLen = 0
};

static void SampleHelp()
{
    printf("select the behavior of the test sample.\n");
    printf("1: init coap discovery.\n");
    printf("2: publish service(customable).\n");
    printf("3: unpublish service(customable).\n");
    printf("4: start discovery(customable).\n");
    printf("5: stop discovery(customable).\n");
    printf("6: publish service.\n");
    printf("7: unpublish service.\n");
    printf("8: start discovery.\n");
    printf("9: stop discovery.\n");
    printf("t: test discovery time delay.\n");
    printf("q: quit the test sample.\n");
    return;
}

static int32_t DiscCoapTestInit(void)
{
    g_coapDiscFunc = DiscCoapInit(&g_discInnerCb);
    if (g_coapDiscFunc == NULL) {
        printf("init coap discovery failed.\n");
        return DISC_TEST_ERR;
    }
    return DISC_TEST_OK;
}

static void DiscCoapTestDeinit(void)
{
    if (g_coapDiscFunc == NULL) {
        return;
    }

    DiscCoapDeinit();
    g_coapDiscFunc = NULL;
    return;
}

static int32_t DiscCoapPulbishService(uint32_t pubCapBitmap, uint32_t publishMode)
{
    if (g_coapDiscFunc == NULL) {
        printf("g_coapDiscFunc is NULL.\n");
        return DISC_TEST_ERR;
    }

    g_publishOption.capabilityBitmap[0] = pubCapBitmap;
    switch (publishMode) {
        case 0:
            if (g_coapDiscFunc->StartScan(&g_publishOption) != 0) {
                printf("passive publish failed.\n");
                return DISC_TEST_ERR;
            }
            break;
        case 1:
            if (g_coapDiscFunc->Publish(&g_publishOption) != 0) {
                printf("active publish failed.\n");
                return DISC_TEST_ERR;
            }
            break;
        default:
            printf("unsupport mode.\n");
            return DISC_TEST_ERR;
    }
    return DISC_TEST_OK;
}

static int32_t DiscCoapUnpulbishService(uint32_t pubCapBitmap, uint32_t publishMode)
{
    if (g_coapDiscFunc == NULL) {
        printf("g_coapDiscFunc is NULL.\n");
        return DISC_TEST_ERR;
    }

    g_publishOption.capabilityBitmap[0] = pubCapBitmap;
    switch (publishMode) {
        case 0:
            if (g_coapDiscFunc->StopScan(&g_publishOption) != 0) {
                printf("passive unpublish failed.\n");
                return DISC_TEST_ERR;
            }
            break;
        case 1:
            if (g_coapDiscFunc->Unpublish(&g_publishOption) != 0) {
                printf("active unpublish failed.\n");
                return DISC_TEST_ERR;
            }
            break;
        default:
            printf("unsupport mode.\n");
            return DISC_TEST_ERR;
    }
    return DISC_TEST_OK;
}

static int32_t DiscCoapStartDiscovery(uint32_t filterCapBitmap, uint32_t discMode)
{
    if (g_coapDiscFunc == NULL) {
        printf("g_coapDiscFunc is NULL.\n");
        return DISC_TEST_ERR;
    }

    g_subscribeOption.capabilityBitmap[0] = filterCapBitmap;
    switch (discMode) {
        case 0:
            if (g_coapDiscFunc->Subscribe(&g_subscribeOption) != 0) {
                printf("passivce start discvoery failed.\n");
                return DISC_TEST_ERR;
            }
            break;
        case 1:
            if (g_coapDiscFunc->StartAdvertise(&g_subscribeOption) != 0) {
                printf("active start discvoery failed.\n");
                return DISC_TEST_ERR;
            }
            break;
        default:
            printf("unsupport mode.\n");
            return DISC_TEST_ERR;
    }
    return DISC_TEST_OK;
}

static int32_t DiscCoapStopDiscovery(uint32_t filterCapBitmap, uint32_t discMode)
{
    if (g_coapDiscFunc == NULL) {
        printf("g_coapDiscFunc is NULL.\n");
        return DISC_TEST_ERR;
    }

    g_subscribeOption.capabilityBitmap[0] = filterCapBitmap;
    switch (discMode) {
        case 0:
            if (g_coapDiscFunc->Unsubscribe(&g_subscribeOption) != 0) {
                printf("passivce stop discvoery failed.\n");
                return DISC_TEST_ERR;
            }
            break;
        case 1:
            if (g_coapDiscFunc->StopAdvertise(&g_subscribeOption) != 0) {
                printf("active stop discvoery failed.\n");
                return DISC_TEST_ERR;
            }
            break;
        default:
            printf("unsupport mode.\n");
            return DISC_TEST_ERR;
    }
    return DISC_TEST_OK;
}

static int32_t DiscCoapTestPulbishService()
{
    if (g_coapDiscFunc == NULL) {
        printf("g_coapDiscFunc is NULL.\n");
        return DISC_TEST_ERR;
    }

    printf("input the register capbility and publish mode(0-passive, 1-active).format[capability mode]: ");
    uint32_t pubCapBitmap;
    uint32_t publishMode;
    int32_t ret = scanf_s("%u %u", &pubCapBitmap, &publishMode);
    /* 2: read num */
    if (ret != 2) {
        printf("scanf_s failed.");
        return DISC_TEST_ERR;
    }
    getchar();
    if (DiscCoapPulbishService(pubCapBitmap, publishMode) != DISC_TEST_OK) {
        return DISC_TEST_ERR;
    }
    return DISC_TEST_OK;
}

static int32_t DiscCoapTestUnpulbishService()
{
    if (g_coapDiscFunc == NULL) {
        printf("g_coapDiscFunc is NULL.\n");
        return DISC_TEST_ERR;
    }

    printf("input the unregister capbility and publish mode(0-passive, 1-active).format[capability mode]: ");
    uint32_t pubCapBitmap;
    uint32_t publishMode;
    int32_t ret = scanf_s("%u %u", &pubCapBitmap, &publishMode);
    /* 2: read num */
    if (ret != 2) {
        printf("scanf_s failed.");
        return DISC_TEST_ERR;
    }
    getchar();
    if (DiscCoapUnpulbishService(pubCapBitmap, publishMode) != DISC_TEST_OK) {
        return DISC_TEST_ERR;
    }
    return DISC_TEST_OK;
}

static int32_t DiscCoapTestStartDiscovery()
{
    if (g_coapDiscFunc == NULL) {
        printf("g_coapDiscFunc is NULL.\n");
        return DISC_TEST_ERR;
    }

    printf("input the register filter capbility and discovery mode(0-passive, 1-active).format[capability mode]: ");
    uint32_t filterCapBitmap;
    uint32_t discMode;
    int32_t ret = scanf_s("%u %u", &filterCapBitmap, &discMode);
    /* 2: read num */
    if (ret != 2) {
        printf("scanf_s failed.");
        return DISC_TEST_ERR;
    }
    getchar();
    if (DiscCoapStartDiscovery(filterCapBitmap, discMode) != DISC_TEST_OK) {
        return DISC_TEST_ERR;
    }
    return DISC_TEST_OK;
}

static int32_t DiscCoapTestStopDiscovery()
{
    if (g_coapDiscFunc == NULL) {
        printf("g_coapDiscFunc is NULL.\n");
        return DISC_TEST_ERR;
    }

    printf("input the unregister filter capbility and discovery mode(0-passive, 1-active).format[capability mode]: ");
    uint32_t filterCapBitmap;
    uint32_t discMode;
    int32_t ret = scanf_s("%u %u", &filterCapBitmap, &discMode);
    /* 2: read num */
    if (ret != 2) {
        printf("scanf_s failed.");
        return DISC_TEST_ERR;
    }
    getchar();
    if (DiscCoapStopDiscovery(filterCapBitmap, discMode) != DISC_TEST_OK) {
        return DISC_TEST_ERR;
    }
    return DISC_TEST_OK;
}

static int32_t CoapPulblish001(void)
{
    DiscCoapTestDeinit();
    if (DiscCoapTestInit() != DISC_TEST_OK) {
        return DISC_TEST_ERR;
    }

    if (DiscCoapPulbishService(1, 1) != DISC_TEST_OK) {
        return DISC_TEST_ERR;
    }
    return DISC_TEST_OK;
}

static int32_t CoapPulblish002(void)
{
    DiscCoapTestDeinit();
    if (DiscCoapTestInit() != DISC_TEST_OK) {
        return DISC_TEST_ERR;
    }
    if (DiscCoapPulbishService(1, 1) != DISC_TEST_OK) {
        return DISC_TEST_ERR;
    }
    if (DiscCoapPulbishService(DISC_COAP_CAP_2, 1) != DISC_TEST_OK) {
        return DISC_TEST_ERR;
    }
    return DISC_TEST_OK;
}

static int32_t CoapStartScan001(void)
{
    DiscCoapTestDeinit();
    if (DiscCoapTestInit() != DISC_TEST_OK) {
        return DISC_TEST_ERR;
    }

    if (DiscCoapPulbishService(1, 0) != DISC_TEST_OK) {
        return DISC_TEST_ERR;
    }
    if (DiscCoapStartDiscovery(DISC_COAP_CAP_15, 1) != DISC_TEST_OK) {
        return DISC_TEST_ERR;
    }
    return DISC_TEST_OK;
}

static int32_t CoapStartScan002(void)
{
    DiscCoapTestDeinit();
    if (DiscCoapTestInit() != DISC_TEST_OK) {
        return DISC_TEST_ERR;
    }

    if (DiscCoapPulbishService(1, 0) != DISC_TEST_OK) {
        return DISC_TEST_ERR;
    }
    if (DiscCoapPulbishService(DISC_COAP_CAP_4, 0) != DISC_TEST_OK) {
        return DISC_TEST_ERR;
    }
    if (DiscCoapStartDiscovery(DISC_COAP_CAP_15, 1) != DISC_TEST_OK) {
        return DISC_TEST_ERR;
    }
    return DISC_TEST_OK;
}

static int32_t CoapUnpulblish001(void)
{
    DiscCoapTestDeinit();
    if (DiscCoapTestInit() != DISC_TEST_OK) {
        return DISC_TEST_ERR;
    }

    if (DiscCoapPulbishService(1, 1) != DISC_TEST_OK) {
        return DISC_TEST_ERR;
    }
    if (DiscCoapUnpulbishService(1, 1) != DISC_TEST_OK) {
        return DISC_TEST_ERR;
    }
    if (DiscCoapStartDiscovery(DISC_COAP_CAP_15, 1) != DISC_TEST_OK) {
        return DISC_TEST_ERR;
    }
    return DISC_TEST_OK;
}

static int32_t CoapUnpulblish002(void)
{
    DiscCoapTestDeinit();
    if (DiscCoapTestInit() != DISC_TEST_OK) {
        return DISC_TEST_ERR;
    }

    if (DiscCoapPulbishService(1, 1) != DISC_TEST_OK) {
        return DISC_TEST_ERR;
    }
    if (DiscCoapPulbishService(1, 1) != DISC_TEST_OK) {
        return DISC_TEST_ERR;
    }
    if (DiscCoapUnpulbishService(1, 1) != DISC_TEST_OK) {
        return DISC_TEST_ERR;
    }
    if (DiscCoapStartDiscovery(DISC_COAP_CAP_15, 1) != DISC_TEST_OK) {
        return DISC_TEST_ERR;
    }
    return DISC_TEST_OK;
}

static int32_t CoapStopScan001(void)
{
    DiscCoapTestDeinit();
    if (DiscCoapTestInit() != DISC_TEST_OK) {
        return DISC_TEST_ERR;
    }

    if (DiscCoapPulbishService(1, 0) != DISC_TEST_OK) {
        return DISC_TEST_ERR;
    }
    if (DiscCoapUnpulbishService(1, 0) != DISC_TEST_OK) {
        return DISC_TEST_ERR;
    }
    if (DiscCoapStartDiscovery(DISC_COAP_CAP_15, 1) != DISC_TEST_OK) {
        return DISC_TEST_ERR;
    }
    return DISC_TEST_OK;
}

static int32_t CoapStopScan002(void)
{
    DiscCoapTestDeinit();
    if (DiscCoapTestInit() != DISC_TEST_OK) {
        return DISC_TEST_ERR;
    }

    if (DiscCoapPulbishService(1, 0) != DISC_TEST_OK) {
        return DISC_TEST_ERR;
    }
    if (DiscCoapPulbishService(1, 0) != DISC_TEST_OK) {
        return DISC_TEST_ERR;
    }
    if (DiscCoapUnpulbishService(1, 0) != DISC_TEST_OK) {
        return DISC_TEST_ERR;
    }
    if (DiscCoapStartDiscovery(DISC_COAP_CAP_15, 1) != DISC_TEST_OK) {
        return DISC_TEST_ERR;
    }
    return DISC_TEST_OK;
}

static int32_t CoapStartAdvertise001(void)
{
    DiscCoapTestDeinit();
    if (DiscCoapTestInit() != DISC_TEST_OK) {
        return DISC_TEST_ERR;
    }

    if (DiscCoapStartDiscovery(1, 1) != DISC_TEST_OK) {
        return DISC_TEST_ERR;
    }
    return DISC_TEST_OK;
}

static int32_t CoapStartAdvertise002(void)
{
    DiscCoapTestDeinit();
    if (DiscCoapTestInit() != DISC_TEST_OK) {
        return DISC_TEST_ERR;
    }

    if (DiscCoapStartDiscovery(DISC_COAP_CAP_4, 1) != DISC_TEST_OK) {
        return DISC_TEST_ERR;
    }
    return DISC_TEST_OK;
}

static int32_t CoapStopAdvertise001(void)
{
    DiscCoapTestDeinit();
    if (DiscCoapTestInit() != DISC_TEST_OK) {
        return DISC_TEST_ERR;
    }

    if (DiscCoapStartDiscovery(1, 1) != DISC_TEST_OK) {
        return DISC_TEST_ERR;
    }
    if (DiscCoapStopDiscovery(1, 1) != DISC_TEST_OK) {
        return DISC_TEST_ERR;
    }
    return DISC_TEST_OK;
}

static int32_t CoapStopAdvertise002(void)
{
    DiscCoapTestDeinit();
    if (DiscCoapTestInit() != DISC_TEST_OK) {
        return DISC_TEST_ERR;
    }

    if (DiscCoapStartDiscovery(1, 1) != DISC_TEST_OK) {
        return DISC_TEST_ERR;
    }
    if (DiscCoapStartDiscovery(1, 1) != DISC_TEST_OK) {
        return DISC_TEST_ERR;
    }
    if (DiscCoapStopDiscovery(1, 1) != DISC_TEST_OK) {
        return DISC_TEST_ERR;
    }
    return DISC_TEST_OK;
}

static int32_t CoapSubscribe001(void)
{
    DiscCoapTestDeinit();
    if (DiscCoapTestInit() != DISC_TEST_OK) {
        return DISC_TEST_ERR;
    }

    if (DiscCoapStartDiscovery(1, 0) != DISC_TEST_OK) {
        return DISC_TEST_ERR;
    }
    return DISC_TEST_OK;
}

static int32_t CoapSubscribe002(void)
{
    DiscCoapTestDeinit();
    if (DiscCoapTestInit() != DISC_TEST_OK) {
        return DISC_TEST_ERR;
    }

    if (DiscCoapStartDiscovery(DISC_COAP_CAP_4, 0) != DISC_TEST_OK) {
        return DISC_TEST_ERR;
    }
    return DISC_TEST_OK;
}

static int32_t CoapUnsubscribe001(void)
{
    DiscCoapTestDeinit();
    if (DiscCoapTestInit() != DISC_TEST_OK) {
        return DISC_TEST_ERR;
    }

    if (DiscCoapStartDiscovery(1, 0) != DISC_TEST_OK) {
        return DISC_TEST_ERR;
    }
    if (DiscCoapStopDiscovery(1, 0) != DISC_TEST_OK) {
        return DISC_TEST_ERR;
    }
    return DISC_TEST_OK;
}

static int32_t CoapUnsubscribe002(void)
{
    DiscCoapTestDeinit();
    if (DiscCoapTestInit() != DISC_TEST_OK) {
        return DISC_TEST_ERR;
    }

    if (DiscCoapStartDiscovery(1, 0) != DISC_TEST_OK) {
        return DISC_TEST_ERR;
    }
    if (DiscCoapStartDiscovery(1, 0) != DISC_TEST_OK) {
        return DISC_TEST_ERR;
    }
    if (DiscCoapStopDiscovery(1, 0) != DISC_TEST_OK) {
        return DISC_TEST_ERR;
    }
    return DISC_TEST_OK;
}

static int32_t DiscCoapTestPulbishServiceCase()
{
    printf("input the testcase num=");
    char input = getchar();
    getchar();
    switch (input) {
        case '1':
            if (CoapPulblish001() != DISC_TEST_OK) {
                return DISC_TEST_ERR;
            }
            break;
        case '2':
            if (CoapPulblish002() != DISC_TEST_OK) {
                return DISC_TEST_ERR;
            }
            break;
        case '3':
            if (CoapStartScan001() != DISC_TEST_OK) {
                return DISC_TEST_ERR;
            }
            break;
        case '4':
            if (CoapStartScan002() != DISC_TEST_OK) {
                return DISC_TEST_ERR;
            }
            break;
        default:
            printf("invalid test case num.");
            break;
    }
    return DISC_TEST_OK;
}

static int32_t DiscCoapTestUnpulbishServiceCase()
{
    printf("input the testcase num=");
    char input = getchar();
    getchar();
    switch (input) {
        case '1':
            if (CoapUnpulblish001() != DISC_TEST_OK) {
                return DISC_TEST_ERR;
            }
            break;
        case '2':
            if (CoapUnpulblish002() != DISC_TEST_OK) {
                return DISC_TEST_ERR;
            }
            break;
        case '3':
            if (CoapStopScan001() != DISC_TEST_OK) {
                return DISC_TEST_ERR;
            }
            break;
        case '4':
            if (CoapStopScan002() != DISC_TEST_OK) {
                return DISC_TEST_ERR;
            }
            break;
        default:
            printf("invalid test case num.");
            break;
    }
    return DISC_TEST_OK;
}

static int32_t DiscCoapTestStartDiscoveryCase()
{
    printf("input the testcase num=");
    char input = getchar();
    getchar();
    switch (input) {
        case '1':
            if (CoapStartAdvertise001() != DISC_TEST_OK) {
                return DISC_TEST_ERR;
            }
            break;
        case '2':
            if (CoapStartAdvertise002() != DISC_TEST_OK) {
                return DISC_TEST_ERR;
            }
            break;
        case '3':
            if (CoapSubscribe001() != DISC_TEST_OK) {
                return DISC_TEST_ERR;
            }
            break;
        case '4':
            if (CoapSubscribe002() != DISC_TEST_OK) {
                return DISC_TEST_ERR;
            }
            break;
        default:
            printf("invalid test case num.");
            break;
    }
    return DISC_TEST_OK;
}

static int32_t DiscCoapTestStopDiscoveryCase()
{
    printf("input the testcase num=");
    char input = getchar();
    getchar();
    switch (input) {
        case '1':
            if (CoapStopAdvertise001() != DISC_TEST_OK) {
                return DISC_TEST_ERR;
            }
            break;
        case '2':
            if (CoapStopAdvertise002() != DISC_TEST_OK) {
                return DISC_TEST_ERR;
            }
            break;
        case '3':
            if (CoapUnsubscribe001() != DISC_TEST_OK) {
                return DISC_TEST_ERR;
            }
            break;
        case '4':
            if (CoapUnsubscribe002() != DISC_TEST_OK) {
                return DISC_TEST_ERR;
            }
            break;
        default:
            printf("invalid test case num.");
            break;
    }
    return DISC_TEST_OK;
}

static int32_t DiscCoapTestTimeDelay(void)
{
    DiscCoapTestDeinit();
    if (DiscCoapTestInit() != DISC_TEST_OK) {
        return DISC_TEST_ERR;
    }

    gettimeofday(&g_startTime, NULL);
    if (DiscCoapStartDiscovery(1, 1) != DISC_TEST_OK) {
        return DISC_TEST_ERR;
    }
    uint32_t i = 0;
    g_timeDelayFlag = 0;
    while ((i < DISC_MAX_MS_NUM) && (g_timeDelayFlag == 0)) {
        i++;
        usleep(US_PER_MS);
    }
    if (g_timeDelayFlag == 0) {
        printf("test discovery time delay failed(reach max wait time 5s).\n");
        return DISC_TEST_ERR;
    }
    uint64_t delayTime = US_PER_SECOND * (g_endTime.tv_sec - g_startTime.tv_sec) +
        (g_endTime.tv_usec - g_startTime.tv_usec);
    printf("discovery delay time(ms) = %" PRIu64 ".\n", delayTime / US_PER_MS);
    return DISC_TEST_OK;
}

int main()
{
    printf("**************start coap discovery test sample!!!!!!***************\n");
    SampleHelp();
    while (1) {
        sleep(1);
        printf("input=");
        char input = getchar();
        getchar();
        switch (input) {
            case '1': {
                if (DiscCoapTestInit() != DISC_TEST_OK) {
                    goto EXIT;
                }
                break;
            }
            case '2': {
                if (DiscCoapTestPulbishService() != DISC_TEST_OK) {
                    goto EXIT;
                }
                break;
            }
            case '3': {
                if (DiscCoapTestUnpulbishService() != DISC_TEST_OK) {
                    goto EXIT;
                }
                break;
            }
            case '4': {
                if (DiscCoapTestStartDiscovery() != DISC_TEST_OK) {
                    goto EXIT;
                }
                break;
            }
            case '5': {
                if (DiscCoapTestStopDiscovery() != DISC_TEST_OK) {
                    goto EXIT;
                }
                break;
            }
            case '6': {
                if (DiscCoapTestPulbishServiceCase() != DISC_TEST_OK) {
                    goto EXIT;
                }
                break;
            }
            case '7': {
                if (DiscCoapTestUnpulbishServiceCase() != DISC_TEST_OK) {
                    goto EXIT;
                }
                break;
            }
            case '8': {
                if (DiscCoapTestStartDiscoveryCase() != DISC_TEST_OK) {
                    goto EXIT;
                }
                break;
            }
            case '9': {
                if (DiscCoapTestStopDiscoveryCase() != DISC_TEST_OK) {
                    goto EXIT;
                }
                break;
            }
            case 't': {
                if (DiscCoapTestTimeDelay() != DISC_TEST_OK) {
                    goto EXIT;
                }
                break;
            }
            case 'q':
                goto EXIT;
            default:
                SampleHelp();
                break;
        }
    }

EXIT:
    printf("*************quit the coap discovery test sample!!!!!************\n");
    DiscCoapTestDeinit();
    return 0;
}
