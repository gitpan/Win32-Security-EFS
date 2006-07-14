#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x560
#endif

#include <windows.h>
#include <winefs.h>

MODULE = Win32::Security::EFS   PACKAGE = Win32::Security::EFS

unsigned long
QueryUsersOnEncryptedFile( lpFileName, pUsers )
        LPCWSTR lpFileName
        PENCRYPTION_CERTIFICATE_HASH_LIST *pUsers = NO_INIT
    CODE:
        New(0, pUsers, 1, PENCRYPTION_CERTIFICATE_HASH_LIST);
        RETVAL = QueryUsersOnEncryptedFile( lpFileName, pUsers );
    OUTPUT:
        pUsers
        RETVAL
    CLEANUP:
        Safefree( pUsers );