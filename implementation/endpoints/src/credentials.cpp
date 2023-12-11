// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#if defined(__linux__) || defined(ANDROID) || defined(__QNX__)

#include <cerrno>
#include <cstring>
#include <string>
#include <sys/socket.h>

#include "../include/credentials.hpp"
#include "../include/sockcred.hpp"

#include <vsomeip/internal/logger.hpp>
#ifdef ANDROID
#include "../../configuration/include/internal_android.hpp"
#else
#include "../../configuration/include/internal.hpp"
#endif

namespace vsomeip_v3 {

void credentials::activate_credentials(const int _fd) {
#ifndef __QNX__
    int optval = 1;
    if (setsockopt(_fd, SOL_SOCKET, SO_PASSCRED, &optval, sizeof(optval)) == -1) {
        VSOMEIP_ERROR << __func__ << ": vSomeIP Security: Activating socket option for receiving "
                      << "credentials failed.";
    }
#endif
}

void credentials::deactivate_credentials(const int _fd) {
#ifndef __QNX__
    int optval = 0;
    if (setsockopt(_fd, SOL_SOCKET, SO_PASSCRED, &optval, sizeof(optval)) == -1) {
        VSOMEIP_ERROR << __func__ << ": vSomeIP Security: Deactivating socket option for receiving "
                      << "credentials failed.";
    }
#endif
}

boost::optional<credentials::received_t> credentials::receive_credentials(const int _fd) {
    UCRED_T* ucredp = nullptr;
    struct msghdr msgh;
    static constexpr size_t iov_len = 2;
    struct iovec iov[iov_len];
    union {
        struct cmsghdr cmh;
        char   control[CMSG_SIZE];
    } control_un;

    // We don't need address of peer as we using connect
    msgh.msg_name = nullptr;
    msgh.msg_namelen = 0;

    // Set fields of 'msgh' to point to buffer used to receive (real) data read by recvmsg()
    msgh.msg_iov = &iov[0];
    msgh.msg_iovlen = iov_len;

    // Set 'msgh' fields to describe 'control_un'
    msgh.msg_control = control_un.control;
    msgh.msg_controllen = sizeof(control_un.control);

    // Sender client_id and client_host_length will be received as data
    client_t client = VSOMEIP_ROUTING_CLIENT;
    uint8_t client_host_length(0);
    iov[0].iov_base = &client;
    iov[0].iov_len = sizeof(client_t);
    iov[1].iov_base = &client_host_length;
    iov[1].iov_len = sizeof(uint8_t);

    // Set 'control_un' to describe ancillary data that we want to receive
    control_un.cmh.cmsg_len = CMSG_LEN(sizeof(UCRED_T));
    control_un.cmh.cmsg_level = SOL_SOCKET;
    control_un.cmh.cmsg_type = SCM_CRED_TYPE;

    // Receive client_id plus client_host_length plus ancillary data
    auto nr = ::recvmsg(_fd, &msgh, 0);
    if (nr == -1) {
        VSOMEIP_ERROR << __func__ << ": vSomeIP Security: Receiving credentials failed. No data. errno: " << std::strerror(errno);
        return boost::none;
    }

    struct cmsghdr* cmhp = nullptr;
    uid_t uid = ANY_UID;
    gid_t gid = ANY_GID;

#ifndef __QNX__
    cmhp = CMSG_FIRSTHDR(&msgh);
    if (cmhp == nullptr || cmhp->cmsg_len != CMSG_LEN(sizeof(UCRED_T))
            || cmhp->cmsg_level != SOL_SOCKET
            || cmhp->cmsg_type != SCM_CRED_TYPE
    ) {
        VSOMEIP_ERROR << __func__ << ": vSomeIP Security: Receiving credentials failed. Invalid data.";
        return boost::none;
    } else {
        ucredp = reinterpret_cast<UCRED_T*>(CMSG_DATA(cmhp));
        if (nullptr != ucredp)
        {
            uid = UCRED_UID(ucredp);
            gid = UCRED_GID(ucredp);
        } else {
            VSOMEIP_ERROR << __func__ << ": vSomeIP Security: Receiving credentials failed. Invalid data for credential structure.";
        }
    }
#else
    // Find UID / GID
    // This will only work if boost is modified (on QNX) to include the
    // credential information.  In vsomeip 3.1.20, this was done by include
    // overriding socket_ops_ext_local.ipp and adding credential information
    // into:
    //   recv(socket_type s, buf* bufs, size_t count, int flags,
    //   boost::system::error_code& ec, std::uint32_t& uid, std::uint32_t& gid)
    //   -> signed_size_type
    // (which is an overload of recv)
    //
    // Currently we are not concerned with credentials and thus have not added
    // this code.  Note that doing so would also require a modification to the
    // CMake as boost overloads only exist in the current setup for boost 1.66-
    //
    // In any case, the for loop before will see cmsg as nullptr immediately.

    for (auto* cmsg = CMSG_FIRSTHDR(&msgh);
         cmsg != nullptr;
         cmsg = CMSG_NXTHDR(&msgh, cmsg))
    {
        if (
             cmsg->cmsg_level != SOL_SOCKET
          || cmsg->cmsg_type  != SCM_CRED_TYPE
          || cmsg->cmsg_len   != CMSG_LEN(sizeof(UCRED_T))
        )
        {
            continue;
        }
        ucredp = reinterpret_cast<UCRED_T *>(CMSG_DATA(cmsg));
        if (nullptr != ucredp)
        {
            uid = UCRED_UID(ucredp);
            gid = UCRED_GID(ucredp);
        }
    }
#endif

    msgh.msg_iov = iov;
    msgh.msg_iovlen = 1;
    msgh.msg_control = nullptr;
    msgh.msg_controllen = 0;

    // Receive client_host as data
    std::string client_host(client_host_length, '\0');
    iov[0].iov_base = &client_host.front();
    iov[0].iov_len = client_host.length();

    nr = ::recvmsg(_fd, &msgh, 0);
    if (nr == -1) {
        VSOMEIP_ERROR << __func__ << ": vSomeIP Security: Receiving client host failed. No data. errno: " << std::strerror(errno);
        return boost::none;
    }

    return received_t{client, uid, gid, client_host};
}

void credentials::send_credentials(const int _fd, client_t _client, std::string _client_host) {
    struct msghdr msgh;
    static constexpr size_t iov_len = 3;
    struct iovec iov[iov_len];
    auto client_host_length = static_cast<uint8_t>(_client_host.length());

    // data to send
    msgh.msg_iov = &iov[0];
    msgh.msg_iovlen = iov_len;

    iov[0].iov_base = &_client;
    iov[0].iov_len = sizeof(client_t);

    iov[1].iov_base = &client_host_length;
    iov[1].iov_len = sizeof(uint8_t);
    iov[2].iov_base = &_client_host[0];
    iov[2].iov_len = client_host_length;

    // destination not needed as we use connect
    msgh.msg_name = nullptr;
    msgh.msg_namelen = 0;

    // credentials not need to set explicitly
    msgh.msg_control = nullptr;
    msgh.msg_controllen = 0;

    // send client id with credentials
    auto const ns = ::sendmsg(_fd, &msgh, 0);
    if (ns == -1) {
        VSOMEIP_ERROR << __func__ << ": vSomeIP Security: Sending credentials failed. errno: " << std::strerror(errno);
    }
}

} // namespace vsomeip_v3

#endif // __linux__ || ANDROID || __QNX__
