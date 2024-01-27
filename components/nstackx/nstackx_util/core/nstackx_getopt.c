/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include "nstackx_getopt.h"
#include "nstackx_error.h"
#include "nstackx_log.h"

#define TAG "nStackXGetOpt"
#define NSTACK_GETOPT_MAX_ARGC 100

int32_t NstackInitGetOptMsg(NstackGetOptMsg *optMsg)
{
    if (optMsg == NULL) {
        LOGE(TAG, "optMsg is NULL");
        return NSTACKX_EFAILED;
    }
    optMsg->argvIdx = 1;
    optMsg->argvOffset = 1;
    optMsg->attachArg = NULL;
    return NSTACKX_EOK;
}

static int32_t GetOptCheckInputArg(NstackGetOptMsg *optMsg, int argc, const char *const *argv)
{
    if (optMsg->argvIdx >= argc || argv[optMsg->argvIdx][0] != '-' || argv[optMsg->argvIdx][1] == '\0') {
        return NSTACKX_EFAILED;
    } else if (!strcmp(argv[optMsg->argvIdx], "--")) {
        optMsg->argvIdx++;
        return NSTACKX_EFAILED;
    }
    return NSTACKX_EOK;
}

static int32_t GetOptCheckCurrentOpt(NstackGetOptMsg *optMsg, int32_t currentOpt,
    char *currentOptIdxInOpts, char nextChar)
{
    if (currentOpt == ':' || currentOptIdxInOpts == NULL) {
        LOGE(TAG, ": illegal option -- %c", currentOpt);
        optMsg->argvOffset++;
        if (nextChar == '\0') {
            optMsg->argvIdx++;
            optMsg->argvOffset = 1;
        }
        return NSTACKX_EFAILED;
    }
    return NSTACKX_EOK;
}

static int32_t GetOptParseAttachArg(NstackGetOptMsg *optMsg, int32_t argc, const char *const *argv,
    char currentOpt, const char *currentOptIdxInOpts)
{
    if (*(currentOptIdxInOpts + 1) == ':') {
        if (argv[optMsg->argvIdx][optMsg->argvOffset + 1] != '\0') {
            optMsg->attachArg = &argv[optMsg->argvIdx++][optMsg->argvOffset + 1];
        } else if (++optMsg->argvIdx >= argc) {
            LOGE(TAG, ": option requires an argument -- %c", currentOpt);
            optMsg->argvOffset = 1;
            return NSTACKX_EFAILED;
        } else {
            optMsg->attachArg = argv[optMsg->argvIdx++];
        }
        optMsg->argvOffset = 1;
    } else {
        if (argv[optMsg->argvIdx][++(optMsg->argvOffset)] == '\0') {
            optMsg->argvOffset = 1;
            optMsg->argvIdx++;
        }
        optMsg->attachArg = NULL;
    }
    return NSTACKX_EOK;
}

static int32_t NstackCheckArg(const NstackGetOptMsg *optMsg, int32_t argc, const char *const *argv)
{
    if (optMsg == NULL) {
        LOGE(TAG, "optMsg is NULL");
        return NSTACKX_EFAILED;
    }
    if (argc <= 1 || argc > NSTACK_GETOPT_MAX_ARGC) {
        LOGE(TAG, "argc is invalid %u", argc);
        return NSTACKX_EFAILED;
    }
    if (argv == NULL) {
        LOGE(TAG, "argv is NULL");
        return NSTACKX_EFAILED;
    }
    int32_t i;
    for (i = 0; i < argc; i++) {
        if (argv[i] == NULL) {
            LOGE(TAG, "argv[%d] is NULL", i);
            return NSTACKX_EFAILED;
        }
    }
    return NSTACKX_EOK;
}

int32_t NstackGetOpt(NstackGetOptMsg *optMsg, int32_t argc, const char *const *argv, const char *opts)
{
    if (NstackCheckArg(optMsg, argc, argv) != NSTACKX_EOK) {
        return NSTACK_GETOPT_END_OF_STR;
    }
    int32_t currentOpt;
    if (optMsg->argvOffset == 1 && GetOptCheckInputArg(optMsg, argc, argv) != NSTACKX_EOK) {
        return NSTACK_GETOPT_END_OF_STR;
    }
    currentOpt = argv[optMsg->argvIdx][optMsg->argvOffset];
    char *currentOptIdxInOpts = strchr(opts, currentOpt);
    if (GetOptCheckCurrentOpt(optMsg, currentOpt, currentOptIdxInOpts,
        argv[optMsg->argvIdx][optMsg->argvOffset + 1]) != NSTACKX_EOK) {
        return NSTACK_GETOPT_UNKNOW_OPT;
    }
    if (GetOptParseAttachArg(optMsg, argc, argv, currentOpt, currentOptIdxInOpts) != NSTACKX_EOK) {
        return NSTACK_GETOPT_UNKNOW_OPT;
    }
    return currentOpt;
}

const char *NstackGetOptArgs(const NstackGetOptMsg *optMsg)
{
    if (optMsg == NULL) {
        LOGE(TAG, "optMsg is NULL");
        return NULL;
    }
    return optMsg->attachArg;
}

