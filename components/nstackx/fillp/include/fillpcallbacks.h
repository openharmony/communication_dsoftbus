/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#ifndef FILLP_CALLBACKS_H
#define FILLP_CALLBACKS_H

#include "fillptypes.h"
#ifdef __cplusplus
extern "C" {
#endif

/**
 * @ingroup Callbacks
 * @brief
 * This callback is for calloc system function to allocate the requested memory.
 *
 * @param[in] items Indicates the number of elements to be allocated.
 * @param[in] size size of elements.
 * @return
 * This function returns a pointer to the allocated memory or return NULL in case of failure of the request.
 */
typedef void  *(*FillpMemCallocFunc)(IN FILLP_UINT32 items, IN FILLP_UINT32 size);

/**
 * @ingroup Callbacks
 * @brief
 * This callback is for malloc system function to allocate the requested memory.
 *
 * @param[in] size Indicates the memory size to be allocated.
 * @return
 * This function returns a pointer to the allocated memory or returns NULL if the request fails.
 */
typedef void *(*FillpMemAllocFunc)(IN FILLP_UINT32 size);

/**
 * @ingroup Callbacks
 * @brief
 * This callback is for free system function to free the memory block.
 *
 * @param[in] addr Indicates the address of the memory to be freed.
 * @return
 * On success : FILLP_SUCCESS
 * On failure : other error codes.
 */
typedef void (*FillpMemFreeFunc)(IN void *addr);

/**
 * @ingroup Callbacks
 * @brief
 * This is a callback for memset_s system function to fill the specified memory block with the specified characters.
 *
 * @param[in] dest Pointer to destination memory buffer.
 * @param[in] destMax Length of destination memory buffer.
 * @param[in] character Character to be set.
 * @param[in] count Number of bytes to set.
 * @return
 * On success : FILLP_SUCCESS
 * On failure : other error codes.
 */
typedef FILLP_INT (*FillpMemSetFunc)(void *dest, size_t destMax, int c, size_t count);

/**
 * @ingroup Callbacks
 * @brief
 * This callback is for memcpy_s system function to copy memory.
 *
 * @param[out] dest Indicates a pointer to the destination memory buffer.
 * @param[in] destMax Indicates the size of the destination memory buffer.
 * @param[in] src Indicates a pointer to the source memory buffer.
 * @param[in] count Indicates the number of bytes to copy.
 * @return
 * On success : FILLP_SUCCESS
 * On failure : other error codes.
 */
typedef FILLP_INT (*FillpMemCopyFunc)(void *dest, size_t destMax, const void *src, size_t count);

/**
 * @ingroup Callbacks
 * @brief
 * This callback is for string concatenations system function to concatenate strings.
 *
 * @param[out] dest Indicates a pointer to the destination memory buffer.
 * @param[in] destMax Indicates the length of the destination memory buffer.
 * @param[in] src Indicates a pointer to the source memory buffer.
 * @param[in] count Indicates the number of bytes to be copy.
 * @return
 * On success : 0
 * On failure : other error codes.
 */
typedef FILLP_INT (*FillpStrncatFunc)(char *strDest, size_t destMax, const char *strSrc, size_t count);

/**
 * @ingroup Callbacks
 * @brief
 * Callback for string copy system function.
 *
 * @param[out] dest Indicates a pointer to  the  destination memory buffer.
 * @param[in] destMax Indicates the length of the destination memory buffer.
 * @param[in] src Indicates a pointer to the source memory buffer.
 * @param[in] count Indicates the number of bytes to be copied.
 * @return
 * On success : 0
 * On truncation : STRUNCATE
 * On failure : other error codes.
 */
typedef FILLP_INT (*FillpStrncpyFunc)(char *strDest, size_t destMax, const char *strSrc, size_t count);

/**
 * @ingroup Callbacks
 * @brief
 * This is a callback for strlen system function to get the length of a string.
 *
 * @param[in] str Pointer to string.
 * @return
 * This returns length of the string.
 */
typedef FILLP_UINT32 (*FillpStrLenFunc)(IN FILLP_CHAR *str);

/**
 * @ingroup Callbacks
 * @brief
 * This is a callback for select system function to allow a program to check multiple file descriptors.
 *
 * @param[in] maxFd Indicates the fd value to be selected.
 * @param[in] readFds Indicates the fd for read.
 * @param[in] writeFds Indicates the fd for write.
 * @param[out] exceptFds Indicates the fd for errors.
 * @param[in] timeVal Indicates the max time for select to wait.
 * @return
 * On success : Total number of socket handles that are ready.
 * On failure : other error codes.
 */
typedef FILLP_INT (*FillpSelectFunc)(IN FILLP_INT maxFd, IN void *readFds,
    IN void *writeFds, IO void *exceptFds, IN void *timeVal);

/**
 * @ingroup Callbacks
 * @brief
 * This callback is for the ioctl socket to control the I/O mode of a socket.
 *
 * @param[in] fd Indicates the connection fd.
 * @param[in] cmd Indicates the command to perform on socket.
 * @param[in] args Indicates arguments for socket.
 * @return
 * On success : 0
 * On failure : other error codes.
 */
typedef FILLP_INT (*FillpIoctlFunc)(IN FILLP_INT fd, IN FILLP_INT cmd, IN FILLP_ULONG *args);

/**
 * @ingroup Callbacks
 * @brief
 * This callback is for the fcntl system function to manipulate file descriptor.
 *
 * @param[in] fd Indicates a connection file descriptor.
 * @param[in] cmd Indicates the command to perform on socket.
 * @param[in] val Indicates the arguments for socket.
 * @return
 * On success : value based on command
 * On failure : other error codes.
 */
typedef FILLP_INT (*FillpFcntlFunc)(IN FILLP_INT fd, IN FILLP_INT cmd, IN FILLP_INT val);

/**
 * @ingroup Callbacks
 * @brief
 * This callback is to set the socket option.
 *
 * @param[in] fd Indicates the socket file descriptor.
 * @param[in] level Indicates the socket level.
 * @param[in] optName Indicates the socket option name.
 * @param[in] optVal Indicates the socket option value.
 * @param[in] optLen Indicates the socket option length.
 * @return
 * On success : FILLP_SUCCESS
 * On failure : other error codes.
 */
typedef FILLP_INT (*FillpSetSockOptFunc)(IN FILLP_INT fd, IN FILLP_INT level,
    IN FILLP_INT optName, IN FILLP_CONST void *optVal, IN FILLP_INT optLen);

/**
 * @ingroup Callbacks
 * @brief
 * This callback is to get the socket options.
 *
 * @param[in] fd Indicates the socket file descriptor.
 * @param[in] level Indicates the socket level.
 * @param[in] optName Indicates the socket option name.
 * @param[out] optVal Indicates the socket option value.
 * @param[out] optLen Indicates the socket option length.
 * @return
 * On success : FILLP_SUCCESS
 * On failure : other error codes.
 */
typedef FILLP_INT (*FillpGetSockOptFunc)(IN FILLP_INT fd, IN FILLP_INT level,
    IN FILLP_INT optName, IO void *optVal, IO FILLP_INT *optLen);

/**
 * @ingroup Callbacks
 * @brief
 * This callback is for the rand system function to generate random number.
 *
 * @return
 * On success : integer value between 0 and RAND_MAX
 * On failure : other error codes.
 */
typedef FILLP_UINT32 (*FillpRandFunc)(IN void);

/**
 * @ingroup Callbacks
 * @brief
 * This callback is for generating the cryptographic quality random number.
 *
 * @return
 * On success : integer value between 0 and RAND_MAX
 * On failure : other error codes.
 */
typedef FILLP_UINT32 (*FillpCryptoRandFunc)(IN void);

/**
 * @ingroup Callbacks
 * @brief
 * This callback is for memchr system function to search the first occurrence of the character
 * in the first n bytes of the string.
 *
 * @param[in] fd Indicates the pointer to the block of memory where the search is performed.
 * @param[in] c Indicates the value to be passed as an int, but the function performs a
 * byte by per byte search using the unsigned char conversion of this value.
 * @param[in] n Indicates the number of bytes to be analyzed.
 * @return
 * This returns a pointer to the matching byte or FILLP_NULL_PTR if the character does not
 * occur in the given memory area.
 */
typedef void *(*FillpMemChrFunc)(IN FILLP_CONST void *fd, IN FILLP_INT c, IN FILLP_SIZE_T n);

/**
 * @ingroup Callbacks
 * @brief
 * This callback is to create the thread.
 *
 * @param[in] param Indicates a pointer to the ThreadParam struct.
 * @param[out] threadId O|Indicates the thread ID.
 * @return
 * On success : 0
 * On failure : other error codes.
 */
typedef FILLP_INT (*FillpCreateThreadFunc)(IN void *param, IO void *threadId);

/**
 * @ingroup Callbacks
 * @brief
 * This is a callback for the system architecture initialization function.
 *
 * @return
 * On success : ERR_OK
 * On failure : ERR_FAILURE.
 */
typedef FILLP_INT (*FillpSysArcInitFunc)(IN void);

/**
 * @ingroup Callbacks
 * @brief
 * This callback is to get the system current time in long format.
 *
 * @return
 * On success : FILLP_SUCCESS
 * On failure : error.
 */
typedef FILLP_LLONG (*FillpSysArcGetCurTimeFunc)(IN void);

/**
 * @ingroup Callbacks
 * @brief
 * This callback is to increment(increases by 1) the value of the specified variable as an atomic operation.
 *
 * @param[in,out] var Indicates the variable to increment.
 * @param[in] val Indicates the value of the variable.
 * @return
 * Returns the resulting incremented value.
 */
typedef FILLP_INT (*FillpSysArchAtomicIncFunc)(IO SysArchAtomic *var, FILLP_INT val);

/**
 * @ingroup Callbacks
 * @brief
 * This callback is to increment(increases by 1) the value of the specified variable and
 * test whether the resulting incremented value is 0 as an atomic operation.
 *
 * @param[in,out] var Indicates the variable to increment.
 * @return
 * Returns the checking result whether the resulting incremented value is 0 or not.
 */
typedef FILLP_BOOL (*FillpSysArchAtomicIncAndTestFunc)(IO SysArchAtomic *var);

/**
 * @ingroup Callbacks
 * @brief
 * This callback is to decrement(decreases by 1) the value of the specified variable as an atomic operation.
 *
 * @param[in,out] var Indicates the variable to decrement.
 * @param[in] val Indicates the value of the variable.
 * @return
 * It returns the resulting decremented value.
 */
typedef FILLP_INT (*FillpSysArchAtomicDecFunc)(IO SysArchAtomic *var, FILLP_INT val);

/**
 * @ingroup Callbacks
 * @brief
 * This callback is to decrement(decreases by 1) the value of the specified variable and
 * test whether the resulting decremented value is 0 as an atomic operation.
 *
 * @param[in,out] var Indicates the variable to increment.
 * @return
 * Returns the checking result whether the resulting decremented value is 0 or not.
 */
typedef FILLP_BOOL (*FillpSysArchAtomicDecAndTestFunc)(IO SysArchAtomic *var);

/**
 * @ingroup Callbacks
 * @brief
 * This callback is to read the value of the specified variable as an atomic operation.
 *
 * @param[out] var Variable to read.
 * @return
 * This return the read atomic variable.
 */
typedef FILLP_INT (*FillpSysArchAtomicReadFunc)(IO SysArchAtomic *var);

/**
 * @ingroup Callbacks
 * @brief
 * This callback is to set the value of the specified variable as an atomic operation.
 *
 * @param[in] var A pointer to the value to be exchanged.
 * @param[in] newValue The value to be exchanged with the value pointed to by var.
 * @return
 * It return the initial value of var parameter.
 */
typedef FILLP_INT (*FillpSysArchAtomicSetFunc)(IN SysArchAtomic *var, IN FILLP_INT newValue);

/**
 * @ingroup Callbacks
 * @brief
 * This callback is to perform an atomic compare-and-exchange operation on the specified values.
 *
 * @param[out] sem Indicates a pointer to the destination value.
 * @param[in] oldValue Indicates the exchange value.
 * @param[in] newValue Indicates the value to compare to sem.
 * @return
 * This returns the initial value of sem parameter.
 */
typedef FILLP_INT (*FillpSysArchCompAndSwapFunc)(IO volatile FILLP_ULONG *sem,
    IN volatile FILLP_ULONG oldValue, IN volatile FILLP_ULONG newValue);

/**
 * @ingroup Callbacks
 * @brief
 * This callback is for sleep system function.
 *
 * @param[in] time The time interval(in milliseconds)for which execution is to be suspended.
 * @return
 * void
 */
typedef void (*FillpSysSleepMsFunc)(IN FILLP_UINT time); /* In Millseconds */

/**
 * @ingroup Callbacks
 * @brief
 * This callback for the usleep system function to suspend execution for microsecond intervals.
 *
 * @param[in] time The time interval for which execution is to be suspended, in microseconds.
 * @return
 * It returns 0 on success or -1 on error.
 */
typedef FILLP_INT (*FillpSysUSleepFunc)(IN FILLP_UINT time); /* us */

/**
 * @ingroup Callbacks
 * @brief
 * This callback is for _mm_pause function to PAUSE instruction for tight loops (avoid busy waiting).
 *
 * @return
 * void
 */
typedef void (*FillpRtePauseFunc)(void);

/**
 * @ingroup Callbacks
 * @brief
 * This callback is for init_sem system function to initialize the semaphore.
 *
 * @param[in] sem Indicates a pointer to semaphore.
 * @param[in] value Indicates the value of the initialized semaphore.
 * @return
 * Initialize the semaphore in sem on successful or error on failure.
 */
typedef FILLP_INT (*FillpSemFunc)(IO SYS_ARCH_SEM *sem, IN FILLP_ULONG value);

/**
 * @ingroup Callbacks
 * @brief
 * This callback is to lock the semaphore referenced by sem only if the semaphore is currently not locked.
 *
 * @param[out] sem Indicates a pointer to a semaphore to be locked.
 * @return
 * On success : FILLP_SUCCESS
 * On failure : error.
 */
typedef FILLP_INT (*FillpSemTryWaitFunc)(IN SYS_ARCH_SEM *sem);

/**
 * @ingroup Callbacks
 * @brief
 * This callback is to lock the semaphore referenced by sem by performing a semaphore lock operation on that semaphore.
 *
 * @param[in] sem Indicates a pointer to a semaphore to be locked.
 * @return
 * On success : FILLP_SUCCESS
 * On failure : error.
 *
 */
typedef FILLP_INT (*FillpSemWaitFunc)(IN SYS_ARCH_SEM *sem);

/**
 * @ingroup Callbacks
 * @brief
 * This callback unlocks the semaphore referenced by the sem parameter by performing a semaphore
 * unlock operation on that semaphore.
 *
 * @param[in] sem Indicates a pointer to the semaphore to be unlocked.
 * @return
 * On success : FILLP_SUCCESS
 * On failure : error.
 */
typedef FILLP_INT (*FillpSemPostFunc)(IN SYS_ARCH_SEM *sem);

/**
 * @ingroup Callbacks
 * @brief
 * This callback is to destroy the unnamed semaphore indicated by sem.
 *
 * @param[in] sem Indicates a pointer to the semaphore to be destroyed.
 * @return
 * On success : FILLP_SUCCESS
 * On failure : error.
 */
typedef FILLP_INT (*FillpSemDestroyFunc)(IN SYS_ARCH_SEM *sem);

/**
 * @ingroup Callbacks
 * @brief
 * This is a callback for SYS_ARCH_SEM_CLOSE.
 *
 * @param[in] sem Indicates a pointer to SYS_ARCH_RW_SEM.
 *
 * @return
 * On success : zero
 * On failure : error.
 *
 */
typedef FILLP_INT (*FillpRWSemInitFunc)(IO SYS_ARCH_RW_SEM *sem);

/**
 * @ingroup Callbacks
 * @brief
 * This callback is to lock the read semaphore referenced by sem only if the semaphore is currently not locked.
 *
 * @param[in] *sem Indicates a pointer to semaphore to be locked.
 *
 * @return
 * On success : zero
 * On failure : error.
 */
typedef FILLP_INT (*FillpRWSemTryRDWaitFunc)(IN SYS_ARCH_RW_SEM *sem);

/**
 * @ingroup Callbacks
 * @brief
 * This callback is used to lock the write semaphore referenced by sem only if the semaphore is currently not locked.
 *
 * @param[in] *sem Indicates a pointer to the semaphore to be locked.
 * @return
 * On success : zero
 * On failure : error.
 */
typedef FILLP_INT (*FillpRWSemTryWRWaitFunc)(IN SYS_ARCH_RW_SEM *sem);

/**
 * @ingroup Callbacks
 * @brief
 * This callback for sem_wait system function.
 *
 * @param[in] *sem Indicates a pointer to SYS_ARCH_RW_SEM.
 * @return
 * On success : zero
 * On failure : error.
 */
typedef FILLP_INT (*FillpRWSemWRWaitFunc)(IN SYS_ARCH_RW_SEM *sem);

/**
 * @ingroup Callbacks
 * @brief
 * Callback for sem_post system function.
 *
 * @param[in] *sem Indicates a pointer to SYS_ARCH_RW_SEM.
 * @return
 * On success : zero
 * On failure : error.
 */
typedef FILLP_INT (*FillpRWSemRDPostFunc)(IN SYS_ARCH_RW_SEM *sem);

/**
 * @ingroup Callbacks
 * @brief
 * Callback for sem_post system function.
 *
 * @param[in] *sem Indicates a pointer to SYS_ARCH_RW_SEM.
 * @return
 * On success : zero
 * On failure : error.
 */
typedef FILLP_INT (*FillpRWSemWRPostFunc)(IN SYS_ARCH_RW_SEM *sem);

/**
 * @ingroup Callbacks
 * @brief
 * Callback for sem_destroy system function.
 *
 * @param[in] *sem Indicates a pointer to SYS_ARCH_RW_SEM.
 * @return
 * On success : zero
 * On failure : error.
 */
typedef FILLP_INT (*FillpRWSemDestroyFunc)(IN SYS_ARCH_RW_SEM *sem);

/**
 * @ingroup Callbacks
 * @brief
 * This is a callback for creating a socket.
 *
 * @param[in] domain Indicates the address family.
 * @param[in] type Indicates the new socket.
 * @param[in] protocol Indicates the protocol to be used.
 * @return
 * On success : zero
 * On failure : error.
 */
typedef FILLP_INT32 (*FillpCreateSocketFunc)(IN FILLP_INT32 domain, IN FILLP_INT32 type, IN FILLP_INT32 protocol);

/**
 * @ingroup Callbacks
 * @brief
 * This callback associates(bind) a local address with a socket.
 *
 * @param[in] fd Specifies the file descriptor of the socket to be bound.
 * @param[in] myAddr Points to a SockAddr structure containing the address to be bound to the socket.
 * @param[in] addrLen Specifies the length of the SockAddr structure pointed to by the pvMyaddr argument.
 * @return
 * On success : zero
 * On failure : error.
 */
typedef FILLP_INT32 (*FillpBindSocketFunc)(IN FILLP_INT32 fd, IN FILLP_CONST void *myAddr, IN FILLP_INT32 addrLen);

/**
 * @ingroup Callbacks
 * @brief
 * This callback is to close an existing socket.
 *
 * @param[in] ifd Indicates the descriptor identifying the socket to close.
 * @return
 * On success : zero
 * On failure : error.
 */
typedef FILLP_INT32 (*FillpCloseSocketFunc)(IN FILLP_INT32 fd);

/**
 * @ingroup Callbacks
 * @brief
 * This callback is used to send system function to send messages on socket.
 *
 * @param[in] fd Specifies the socket file descriptor.
 * @param[in] buf Points to a buffer containing the message to be sent.
 * @param[in] len Specifies the buffer length.
 * @param[in] flags Specifies the type of message transmission.
 * @param[in] to Points to a SockAddr structure containing the destination address.
 * @param[in] toLen Specifies the length of the SockAddr structure.
 * @return
 * On success :  Number of bytes sent
 * On failure : error.
 */
typedef FILLP_INT (*FillpSendtoFunc)(IN FILLP_INT fd, IN FILLP_CONST void *buf,
    IN FILLP_SIZE_T len, IN FILLP_INT flags, IN FILLP_CONST void *to, IN FILLP_SIZE_T toLen);

/**
 * @ingroup Callbacks
 * @brief
 * This is a callback for the send system function to send a message on a socket.
 *
 * @param[in] fd Specifies the socket file descriptor.
 * @param[in] buffer Points to the buffer containing the message to send.
 * @param[in] bytes Specifies the length of the message in bytes.
 * @param[in] flags Specifies the type of message transmission.
 * @return
 * On success :  Number of bytes sent
 * On failure : error.
 */
typedef FILLP_INT (*FillpSendFunc)(IN FILLP_INT fd, IN FILLP_CONST void *buffer,
    IN FILLP_INT bytes, IN FILLP_INT flags);

/**
 * @ingroup Callbacks
 * @brief
 * This is a callback for for sending multiple messages on a socket in a single
 * system call. Equivalent to sendmmsg() in kernel.
 *
 * @param[in] fd Specifies the socket file descriptor.
 * @param[in] buffer Points to the buffer containing the message to send.
 * @param[in] size Specifies the number of elements sent out.
 * @param[in] flags Indicates the flags.
 * @return
 * On success : Number of data elements sent
 * On failure : error.
 */
typedef FILLP_INT (*FillpSendFuncmmsg)(IN FILLP_INT fd, IN FILLP_CONST void *buffer,
    IN FILLP_UINT32 size, IN FILLP_UINT32 flags);

/**
 * @ingroup Callbacks
 * @brief
 * This is a callback for the receiving multiple messages on a socket in a
 * single system call. equivalent to recvmmsg( ) in kernel.
 *
 * @param[in] fd Specifies the socket file descriptor.
 * @param[in] buffer Points to the buffer containing the message to receive.
 * @param[in] size Specifies the number of elements which can be received.
 * @param[in] flags Indicates the flags.
 * @param[in] timeout Indicates the timeout value.
 * @return
 * On success : Number of data elements received.
 * On failure : error.
 */
typedef FILLP_INT (*FillpRecvmmsgFunc)(IN FILLP_INT fd, IN FILLP_CONST void *buffer,
    IN FILLP_UINT32 size, IN FILLP_UINT32 flags, IN void *timeout);

/**
 * @ingroup Callbacks
 * @brief
 * This is a callback for the getsockname system function to get the socket name.
 *
 * @param[in] fd Indicates the socket file descriptor.
 * @param[in] myAddr Indicates the address which the socket is bound to.
 * @param[out] addrLen Indicates the address length.
 * @return
 * On success :  Number of bytes sent
 * On failure : error.
 */
typedef FILLP_INT32 (*FillpGetSockNameFunc)(IN FILLP_INT32 fd, IN void *myAddr, IO void *addrLen);

/**
 * @ingroup Callbacks
 * @brief
 * This is a callback to connect system function to initiate a connection on a socket.
 *
 * @param[in] fd Indicates the socket file descriptor.
 * @param[in] myAddr Indicates the address which the socket is bound to.
 * @param[out] addrLen Indicates the address length.
 * @return
 * On success : Number of bytes sent
 * On failure : error.
 */
typedef FILLP_INT32 (*FillpConnectFunc)(IN FILLP_INT32 fd, IN FILLP_CONST void *myAddr,
    IN FILLP_INT32 addrLen);

typedef void *FT_FD_SET;

/**
 * @ingroup Callbacks
 * @brief
 * This callback is to clear the file descriptor set.
 *
 * @param[in] fd socket fd.
 * @param[in] socketDescriptorSet socket descriptor set
 * @return
 */
typedef void (*FillpFdClrFunc)(IN FILLP_UINT fd, IN FT_FD_SET socketDescriptorSet);

/**
 * @ingroup Callbacks
 * @brief
 * This callback is set the socket in the file descriptor set.
 *
 * @param[in] fd Indicates the socket file descriptor.
 * @param[in] socketDescriptorSet Indicates the socket descriptor set.
 * @return
 */
typedef void (*FillpFdSetFunc)(IN FILLP_UINT fd, IN FT_FD_SET socketDescriptorSet);

/**
 * @ingroup Callbacks
 * @brief
 * This callback is check if this socket ID is already set in the file descriptor set.
 *
 * @param[in] fd Indicates the socket file descriptor.
 * @param[in] socketDescriptorSet Indicates the socket descriptor set.
 * @return
 */
typedef FILLP_INT (*FillpFdIsSetFunc)(IN FILLP_INT fd, IN FT_FD_SET socketDescriptorSet);

/**
 * @ingroup Callbacks
 * @brief
 * This callback is to create a file descriptor set.
 *
 * @return
 * FT_FD_SET File Descriptor set
 *
 */
typedef FT_FD_SET (*FillpCreateFdSetFunc)(void);

/**
 * @ingroup Callbacks
 * @brief
 * This callback is to free the file descriptor set which was created using the
 * callback function FillpCreateFdSetFunc.
 *
 * @return
 */
typedef void (*FillpDestroyFdSetFunc)(IN FT_FD_SET destroySocketFdSet);

/**
 * @ingroup Callbacks
 * @brief
 * This callback is to copy from one file descriptor set to another
 *
 * @param[out] dstFdSet Indicates the destination file descriptor set to which it is copied.
 * @param[in] srcFdSet Indicates the source file descriptor set from which it is being copied.
 * @return
 */
typedef FILLP_INT32 (*FillpCopyFdSetFunc)(IO FT_FD_SET dstFdSet, IN FT_FD_SET srcFdSet);

/**
 * @ingroup Callbacks
 * @brief
 * This callback to receive from system callback to receive a message from a socket.
 *
 * @param[in] fd Specifies the socket file descriptor.
 * @param[out] *buf Points to the buffer where the message should be stored.
 * @param[in] len Specifies the length in bytes of the buffer pointed to by the buff argument.
 * @param[in] flags Specifies the type of message reception.
 * @param[out] *from Points to a SockAddr structure in which the sending address is to be stored.
 * @param[in] *fromLen Specifies the length of the SockAddr structure pointed to by the from argument.
 * @return
 * On success : Length of the message in bytes.
 * On failure : error.
 */
typedef FILLP_INT (*FillpRecvfromFunc)(IN FILLP_INT fd, OUT void *buf,
    IN FILLP_SIZE_T len, IN FILLP_INT flags, OUT void *from, IO FILLP_SIZE_T *fromLen);

/**
 * @ingroup Callbacks
 * @brief
 * This callback is to send a message to a socket.
 *
 * @param[in] fd Indicates a socket ID.
 * @param[in] *msg Specifies the message which needs to be sent.
 * @param[in] flags Specifies the type of message.
 * @return
 * On success : Sends the message.
 * On failure : error code.
 */
typedef FILLP_INT (*FillpSendFuncmsg)(IN FILLP_INT fd,
    IN FILLP_CONST void *msg, IN FILLP_INT flags);

/**
 * @ingroup Callbacks
 * @brief
 * This callback is to receive a message from a socket.
 *
 * @param[in] fd Indicates a socket file descriptor.
 * @param[in] *msg Indicates a message received.
 * @param[in] flags Specifies the type of message.
 * @return
 * On success : Receives the message.
 * On failure : error code.
 */
typedef FILLP_INT (*FillpRecvmsgFunc)(IN FILLP_INT fd, IN void *msg, IN FILLP_INT flags);

/**
 * @ingroup Callbacks
 * @brief
 * This callback is for sys_arch_sem_close.
 *
 * @param[in] sem Indicates the shared memory.
 * @return
 * On success : FILLP_SUCCESS
 * On failure : FILLP_FAILURE
 */
typedef FILLP_INT (*FillpSysArchSemCloseFunc)(SYS_ARCH_SEM *sem);

/**
 * @ingroup Callbacks
 * @brief
 * This callback is to lock the semaphore referenced by the sem parameter as in the semaphore wait function.
 * However, if the semaphore cannot be locked without waiting for another process or *thread to unlock the semaphore
 * by performing a semaphore post  function, this wait shall be terminated when the specified timeout expires.
 *
 * @param[in] sem Pointer to named semaphore structure.
 * @param[in] timeout Indicates the time to wait.
 * @return
 * On success : Zero
 * On failure : FILLP_FAILURE
 * @note Application must provide functionality which does not have impact with system time change.
 */
 /* callback for SYS_ARCH_SEM_WAIT_TIMEOUT */
typedef FILLP_INT (*FillpSysArchSemWaitTimeoutFunc)(SYS_ARCH_SEM *sem, FILLP_SLONG timeout);

/**
 * @ingroup Callbacks
 * @brief
 * This callback is for sched_yield system function to yield the processor.
 *
 * @return
 * Zero on success OR Error code on failure.
 */
 /* callback for SYS_ARCH_SCHED_YIELD */
typedef FILLP_INT (*FillpSysArchSchedYieldFunc)(void);

/* lower layer call back function structure */
typedef struct FillpSysLibSockCallbackFuncStruct {
    /* Function pointer variable to register the create socket callback function. */
    FillpCreateSocketFunc socketCallbackFunc;
    /* Function pointer variable to register bind socket callback function. */
    FillpBindSocketFunc bindCallbackFunc;
    /* Function pointer variable to register close socket callback function. */
    FillpCloseSocketFunc closeSocketCallbackFunc;
    /* Indicates a variable to register select callback function. */
    FillpSelectFunc select;
    /* Indicates a variable to register ioctl callback function. */
    FillpIoctlFunc ioctl;
    /* Indicates a variable to register fcntl callback function. */
    FillpFcntlFunc fcntl;
    /* Indicates a variable to register fcntl callback function. */
    FillpSetSockOptFunc setSockOpt;
    /* Indicates a variable to register fcntl callback function. */
    FillpGetSockOptFunc getSockOpt;
    /* Indicates a pointer to a variable to register  set socket option. */
    FillpRecvfromFunc recvFromCallbackFunc;
    /* Indicates a pointer to a variable to register  get socket option. */
    FillpSendtoFunc sendtoCallbackFunc;
    /* Indicates a function pointer variable to register  Sendto callback function. */
    FillpSendFunc sendCallbackFunc;
    /* Indicates a function pointer variable to register get socket name callback function. */
    FillpGetSockNameFunc getSockNameCallbackFunc;
    /* Indicates a function pointer variable to register the connect callback function. */
    FillpConnectFunc connectCallbackFunc;
    /* Indicates a function pointer variable to register callback function to call the required FD_CLR macro. */
    FillpFdClrFunc fillpFuncFdClr;
    /* Indicates a function pointer variable to register callback function to call the required FD_SET macro. */
    FillpFdSetFunc fillpFuncFdSet;
    /* Indicates a function pointer variable to register callback function to call the required FD_ISSET macro. */
    FillpFdIsSetFunc fillpFuncFdIsSet;
    /* Indicates a function pointer variable to register callback function to call fd_set. */
    FillpCreateFdSetFunc fillpFuncCreateFdSet;
    /* Indicates a function pointer variable to register callback function to
     * destroy fd_set which was created by FillpCreateFdSetFunc. */
    FillpDestroyFdSetFunc fillpFuncDestroyFdSet;
    /* Indicates a function pointer variable to register callback function to copy fd_set. */
    FillpCopyFdSetFunc fillpFuncCopyFdSet;
} FillpSysLibSockCallbackFuncSt;

/**
 * Provides variables to semaphore callback functions.
 */
typedef struct FillpSysLibSemCallbackFuncStruct {
    /* Function pointer variable to register semaphore close callback function. */
    FillpSysArchSemCloseFunc sysArchSemClose;
    /* Function pointer variable to semaphore Init callback function. */
    FillpSemFunc sysArchSemInit;
    /* Function pointer variable to semaphore try wait callback function. */
    FillpSemTryWaitFunc sysArchSemTryWait;
    /* Function pointer variable to semaphore wait callback function. */
    FillpSemWaitFunc sysArchSemWait;
    /* Function pointer variable to semaphore post callback function. */
    FillpSemPostFunc sysArchSemPost;
    /* Function pointer variable to register semaphore destroy callback function. */
    FillpSemDestroyFunc sysArchSemDestroy;
    /* Function pointer variable to FillpRWSemInitFunc. */
    FillpRWSemInitFunc sysArchRWSemInit;
    /* Function pointer variable to FillpRWSemTryRDWaitFunc. */
    FillpRWSemTryRDWaitFunc sysArchRWSemTryRDWait;
    /* Function pointer variable to FillpRWSemTryWRWaitFunc. */
    FillpRWSemTryWRWaitFunc sysArchRWSemTryWRWait;
    /* Function pointer variable to FillpRWSemRDPostFunc. */
    FillpRWSemRDPostFunc sysArchRWSemRDPost;
    /* Function pointer variable to FillpRWSemWRPostFunc. */
    FillpRWSemWRPostFunc sysArchRWSemWRPost;
    /* Function pointer variable to FillpRWSemDestroyFunc. */
    FillpRWSemDestroyFunc sysArchRWSemDestroy;
    /* Function pointer variable to semaphore wait timeout callback function. */
    FillpSysArchSemWaitTimeoutFunc sysArchSemWaitTimeout;
    /* Function pointer variable to register system shared yield  callback function. */
    FillpSysArchSchedYieldFunc sysArchSchedYield;
} FillpSysLibSemCallbackFuncSt;


/**
* Structure of basic callback functions.
*/
typedef struct FillpSysLibBasicCallbackFuncStruct {
    FillpMemCallocFunc memCalloc; /* Memory  calloc callback function. */
    FillpMemAllocFunc memAlloc; /* Memory  allocation callback function. */
    FillpMemFreeFunc memFree; /* Memory  free callback function. */
    FillpStrLenFunc fillpStrLen; /* String length callback function. */
    FillpRandFunc fillpRand; /* String SprintfS callback function. */
    FillpCreateThreadFunc fillpCreateThread; /* String SprintfS callback function. */
    FillpSysArcInitFunc sysArcInit; /* SYS_ARCH_INIT callback function. */
    FillpSysArcGetCurTimeFunc sysArcGetCurTimeLongLong; /* sys_arch_get_cur_time_longlong callback function. */
    FillpSysArchAtomicIncFunc sysArchAtomicInc; /* SYS_ARCH_ATOMIC_INC callback function. */
    FillpSysArchAtomicIncAndTestFunc sysArchAtomicIncAndTest; /* SYS_ARCH_ATOMIC_INC_AND_TEST callback function. */
    FillpSysArchAtomicDecFunc sysArchAtomicDec; /* SysArchAtomic_DEC callback function. */
    FillpSysArchAtomicDecAndTestFunc sysArchAtomicDecAndTest; /* SYS_ARCH_ATOMIC_DEC_AND_TEST callback function. */
    FillpSysArchAtomicReadFunc sysArchAtomicRead; /* SYS_ARCH_ATOMIC_READ callback function. */
    FillpSysArchAtomicSetFunc sysArchAtomicSet; /* SYS_ARCH_ATOMIC_SET callback function. */
    FillpSysArchCompAndSwapFunc sysArchCompAndSwap; /* SYS_ARCH_SEM_WAIT_TIMEOUT callback function. */
    FillpSysSleepMsFunc sysSleepMs; /* FILLP_SLEEP_MS callback function. */
    FillpSysUSleepFunc sysUsleep; /* sleep in seconds callback function. */
    FillpRtePauseFunc rtePause; /* rte_pause callback function. */
    FillpCryptoRandFunc cryptoRand; /* Cryptographic quality random number callback function. */
    FillpMemChrFunc memChr; /* MemChr callback function. */
} FillpSysLibBasicCallbackFuncSt;

/**
* Provides callbacks for FillP SysLib.
*/
typedef struct FillpSysLibCallbackFuncStruct {
    FillpSysLibBasicCallbackFuncSt sysLibBasicFunc; /* Indicates a callback to SystLibBasicFunc. */
    FillpSysLibSemCallbackFuncSt sysLibSemFunc; /* Indicates a callback to SysLibSemFunc. */
    FillpSysLibSockCallbackFuncSt sysLibSockFunc; /* Indicates a callback to SysLibSockFunc. */
} FillpSysLibCallbackFuncSt;

#ifdef __cplusplus
}
#endif

#endif
