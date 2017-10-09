#include "MD5.h"
#include <string.h>
#include "HTTPDigest.h"

void CvtHex(
        IN HASH Bin,
        OUT HASHHEX Hex
        )
{
    unsigned short i;
    unsigned char j;
    for (i = 0; i < HASHLEN; i++) {
        j = (Bin[i] >> 4) & 0xf;
        if (j <= 9)
            Hex[i*2] = (j + '0');
        else
            Hex[i*2] = (j + 'a' - 10);
        j = Bin[i] & 0xf;
        if (j <= 9)
            Hex[i*2+1] = (j + '0');
        else
            Hex[i*2+1] = (j + 'a' - 10);
    };
    Hex[HASHHEXLEN] = '\0';
}

/* calculate H(A1) as per spec */
void
DigestCalcHA1 (IN const char *pszAlg,
               IN const char *pszUserName,
               IN const char *pszRealm,
               IN const char *pszPassword,
               IN const char *pszNonce,
               IN const char *pszCNonce,
               OUT HASHHEX SessionKey)
{
    MD5_CTX Md5Ctx;
    HASH HA1;

    MD5Init (&Md5Ctx);
    MD5Update (&Md5Ctx, (unsigned char *) pszUserName, (unsigned int) strlen (pszUserName));
    MD5Update (&Md5Ctx, (unsigned char *) ":", 1);
    MD5Update (&Md5Ctx, (unsigned char *) pszRealm, (unsigned int) strlen (pszRealm));
    MD5Update (&Md5Ctx, (unsigned char *) ":", 1);
    MD5Update (&Md5Ctx, (unsigned char *) pszPassword, (unsigned int) strlen (pszPassword));
    MD5Final ((unsigned char *) HA1, &Md5Ctx);
    if ((pszAlg != NULL) && strcasecmp (pszAlg, "md5-sess") == 0) {
        MD5Init (&Md5Ctx);
        MD5Update (&Md5Ctx, (unsigned char *) HA1, HASHLEN);
        MD5Update (&Md5Ctx, (unsigned char *) ":", 1);
        MD5Update (&Md5Ctx, (unsigned char *) pszNonce, (unsigned int) strlen (pszNonce));
        MD5Update (&Md5Ctx, (unsigned char *) ":", 1);
        MD5Update (&Md5Ctx, (unsigned char *) pszCNonce, (unsigned int) strlen (pszCNonce));
        MD5Final ((unsigned char *) HA1, &Md5Ctx);
    }
    CvtHex (HA1, SessionKey);
}

/* calculate request-digest/response-digest as per HTTP Digest spec */
void
DigestCalcResponse (IN HASHHEX HA1,     /* H(A1) */
                    IN const char *pszNonce,    /* nonce from server */
                    IN const char *pszNonceCount,       /* 8 hex digits */
                    IN const char *pszCNonce,   /* client nonce */
                    IN const char *pszQop,      /* qop-value: "", "auth", "auth-int" */
                    IN int Aka, /* Calculating AKAv1-MD5 response */
                    IN const char *pszMethod,   /* method from the request */
                    IN const char *pszDigestUri,        /* requested URL */
                    IN HASHHEX HEntity, /* H(entity body) if qop="auth-int" */
                    OUT HASHHEX Response
                    /* request-digest or response-digest */ )
{
    MD5_CTX Md5Ctx;
    HASH HA2;
    HASH RespHash;
    HASHHEX HA2Hex;

    /* calculate H(A2) */
    MD5Init (&Md5Ctx);
    MD5Update (&Md5Ctx, (unsigned char *) pszMethod, (unsigned int) strlen (pszMethod));
    MD5Update (&Md5Ctx, (unsigned char *) ":", 1);
    MD5Update (&Md5Ctx, (unsigned char *) pszDigestUri, (unsigned int) strlen (pszDigestUri));

    if (pszQop == NULL) {
        goto auth_withoutqop;
    }
    else if (0 == strcasecmp (pszQop, "auth-int")) {
        goto auth_withauth_int;
    }
    else if (0 == strcasecmp (pszQop, "auth")) {
        goto auth_withauth;
    }

auth_withoutqop:
    MD5Final ((unsigned char *) HA2, &Md5Ctx);
    CvtHex (HA2, HA2Hex);

    /* calculate response */
    MD5Init (&Md5Ctx);
    MD5Update (&Md5Ctx, (unsigned char *) HA1, HASHHEXLEN);
    MD5Update (&Md5Ctx, (unsigned char *) ":", 1);
    MD5Update (&Md5Ctx, (unsigned char *) pszNonce, (unsigned int) strlen (pszNonce));
    MD5Update (&Md5Ctx, (unsigned char *) ":", 1);

    goto end;

auth_withauth_int:

    MD5Update (&Md5Ctx, (unsigned char *) ":", 1);
    MD5Update (&Md5Ctx, (unsigned char *) HEntity, HASHHEXLEN);

auth_withauth:
    MD5Final ((unsigned char *) HA2, &Md5Ctx);
    CvtHex (HA2, HA2Hex);

    /* calculate response */
    MD5Init (&Md5Ctx);
    MD5Update (&Md5Ctx, (unsigned char *) HA1, HASHHEXLEN);
    MD5Update (&Md5Ctx, (unsigned char *) ":", 1);
    MD5Update (&Md5Ctx, (unsigned char *) pszNonce, (unsigned int) strlen (pszNonce));
    MD5Update (&Md5Ctx, (unsigned char *) ":", 1);
    if (Aka == 0) {
        MD5Update (&Md5Ctx, (unsigned char *) pszNonceCount, (unsigned int) strlen (pszNonceCount));
        MD5Update (&Md5Ctx, (unsigned char *) ":", 1);
        MD5Update (&Md5Ctx, (unsigned char *) pszCNonce, (unsigned int) strlen (pszCNonce));
        MD5Update (&Md5Ctx, (unsigned char *) ":", 1);
        MD5Update (&Md5Ctx, (unsigned char *) pszQop, (unsigned int) strlen (pszQop));
        MD5Update (&Md5Ctx, (unsigned char *) ":", 1);
    }
end:
    MD5Update (&Md5Ctx, (unsigned char *) HA2Hex, HASHHEXLEN);
    MD5Final ((unsigned char *) RespHash, &Md5Ctx);
    CvtHex (RespHash, Response);
}
