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

#include "nstackx_util.h"
#include "nstackx_timer.h"
#include "nstackx_error.h"
#include "nstackx_log.h"
#include "securec.h"

#define TAG "nStackXUtil"
#define DEFAULT_NEW_PATH_AUTHORITY 0750

int32_t GetTargetFileSize(const char *dir, uint64_t *size)
{
    struct stat statbuf;

    if (dir == NULL || size == NULL) {
        LOGE(TAG, "Invalid dir or size");
        return NSTACKX_EINVAL;
    }

    if (stat(dir, &statbuf) != 0 || statbuf.st_size < 0) {
        LOGE(TAG, "stat error: %d", GetErrno());
        return NSTACKX_EFAILED;
    }

    *size = (uint64_t)statbuf.st_size;
    return NSTACKX_EOK;
}

int32_t CheckPathSeprator(const char *path)
{
    if (strlen(path) > 0 && path[strlen(path) - 1] == PATH_SEPARATOR) {
        return NSTACKX_TRUE;
    }
    return NSTACKX_FALSE;
}

int32_t CheckFilenameSeprator(const char *fileName)
{
    if (strlen(fileName) > 0 && fileName[0] == PATH_SEPARATOR) {
        return NSTACKX_TRUE;
    }
    return NSTACKX_FALSE;
}

/*
 * return value includes the length of terminator '\0'
 * return value 0 means the input dir is null or it's last char is PATH_SEPARATOR
 */
uint32_t GetFileNameLen(const char *dir)
{
    int32_t i;

    if (dir == NULL || strlen(dir) < 1 || dir[strlen(dir) - 1] == PATH_SEPARATOR) {
        LOGE(TAG, "Invalid input param");
        return 0;
    }

    int32_t dirLen = (int32_t)strlen(dir);
    for (i = dirLen - 1; i >= 0; i--) {
        if (dir[i] == PATH_SEPARATOR) {
            i++;
            break;
        }
        if (i == 0) {
            break;
        }
    }
    return (uint32_t)(dirLen + 1 - i);
}

int32_t GetFileName(const char *dir, char *name, uint32_t nameLen)
{
    uint32_t fileNameLen, startIdx;

    if (dir == NULL || name == NULL) {
        LOGE(TAG, "Invalid dir or name");
        return NSTACKX_EINVAL;
    }

    fileNameLen = GetFileNameLen(dir);
    if (fileNameLen == 0 || fileNameLen > nameLen) {
        LOGE(TAG, "Invalid fileNameLen dir: %s", dir);
        return NSTACKX_EINVAL;
    }
    startIdx = (uint32_t)(strlen(dir) + 1 - fileNameLen);
    if (strcpy_s(name, nameLen, dir + startIdx) != EOK) {
        LOGE(TAG, "strcpy_s name error");
        return NSTACKX_EFAILED;
    }
    return NSTACKX_EOK;
}

uint8_t IsAccessiblePath(const char *pathName, int32_t mode, uint32_t fileType)
{
    struct stat statbuf;
    if (pathName == NULL) {
        LOGE(TAG, "invalid input");
        return NSTACKX_FALSE;
    }
    if (stat(pathName, &statbuf) != 0) {
        LOGE(TAG, "can't get file stat.error: %d", GetErrno());
        return NSTACKX_FALSE;
    }
    if (((statbuf.st_mode) & S_IFMT) != fileType) {
        LOGE(TAG, "this path name is not target file type");
        return NSTACKX_FALSE;
    }

    if (access(pathName, F_OK) != 0) {
        return NSTACKX_FALSE;
    }

    if (access(pathName, mode) != 0) {
        return NSTACKX_FALSE;
    }
    return NSTACKX_TRUE;
}

uint8_t IsExistingFile(const char *fileName)
{
    if (access(fileName, F_OK) != 0) {
        return NSTACKX_FALSE;
    }
    return NSTACKX_TRUE;
}

int32_t TestAndCreateDirectory(const char *path)
{
    uint32_t len, i;
    char *tmp = NULL;
    int32_t ret;

    if (path == NULL || strlen(path) == 0) {
        return NSTACKX_EINVAL;
    }

    len = (uint32_t)strlen(path);

    tmp = (char *)calloc(len + 1, sizeof(char));
    if (tmp == NULL) {
        LOGE(TAG, "tmp calloc error");
        return NSTACKX_EFAILED;
    }

    for (i = 0; i < len; i++) {
        tmp[i] = path[i];
        if (tmp[i] != PATH_SEPARATOR) {
            continue;
        }
        if (access(tmp, 0) == -1) {
            ret = mkdir(tmp, DEFAULT_NEW_PATH_AUTHORITY);
            if (ret == -1 && errno != EEXIST) {
                LOGI(TAG, "mkdir failed(%d)", errno);
                free(tmp);
                return NSTACKX_EFAILED;
            }
        }
    }
    free(tmp);
    return NSTACKX_EOK;
}

#define UCHAR2_TO_UINT16(_buf) (((uint16_t)((_buf)[0]) << 8u) | (uint16_t)((_buf)[1]))

int32_t IpAddrAnonymousFormat(char *buf, size_t len, const struct sockaddr *addr, size_t addrLen)
{
    if (buf == NULL || len == 0 || addr == NULL) {
        return NSTACKX_EFAILED;
    }

    int32_t ret = NSTACKX_EFAILED;
    if (addr->sa_family == AF_INET && addrLen >= sizeof(struct sockaddr_in)) {
        uint32_t ip4 = ((const struct sockaddr_in *)addr)->sin_addr.s_addr;
        ret = snprintf_s(buf, len, len - 1, "%hhu.%hhu.%hhu.*",
            ((uint8_t *)&ip4)[0], ((uint8_t *)&ip4)[1], ((uint8_t *)&ip4)[2]); /* print the first 3 bytes */
    } else if (addr->sa_family == AF_INET6 && addrLen >= sizeof(struct sockaddr_in6)) {
        const uint8_t *ip6 = ((const struct sockaddr_in6 *)addr)->sin6_addr.s6_addr;
        ret = snprintf_s(buf, len, len - 1, "%x:%x:%x*:*:*:*:*:*",
            UCHAR2_TO_UINT16(ip6), UCHAR2_TO_UINT16(ip6 + 2), ip6[4]); /* print the first 5 bytes */
    }

    return ret;
}
