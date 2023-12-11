//
// CONFIDENTIAL - FORD MOTOR COMPANY
//
// This is an unpublished work, which is a trade secret, created in
// 2023.  Ford Motor Company owns all rights to this work and intends
// to maintain it in confidence to preserve its trade secret status.
// Ford Motor Company reserves the right to protect this work as an
// unpublished copyrighted work in the event of an inadvertent or
// deliberate unauthorized publication.  Ford Motor Company also
// reserves its rights under the copyright laws to protect this work
// as a published work.  Those having access to this work may not copy
// it, use it, or disclose the information contained in it without
// the written authorization of Ford Motor Company.
//

#pragma once

#ifdef __QNX__
    #define UCRED_T struct sockcred
    #define UCRED_UID(x) x->sc_uid
    #define UCRED_GID(x) x->sc_gid

    // Reserved memory space to receive credential
    // through ancilliary data.
    #define CMSG_SIZE   512

    #define SCM_CRED_TYPE SCM_CREDS
#else
    #define UCRED_T struct ucred
    #define UCRED_UID(x) x->uid
    #define UCRED_GID(x) x->gid

    #define CMSG_SIZE CMSG_SPACE(sizeof(UCRED_T))

    #define SCM_CRED_TYPE SCM_CREDENTIALS
#endif
