/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: the types of dfinder hidump
 * Author: NA
 * Create: 2022-07-21
 */

#ifndef NSTACKX_DFINDER_HIDUMP_H
#define NSTACKX_DFINDER_HIDUMP_H
#include "nstackx.h"

#ifdef NSTACKX_DFINDER_HIDUMP
int DFinderDump(const char **argv, uint32_t argc, void *softObj, DFinderDumpFunc dump);
#endif

#endif