#include "stdio.h"
#include "string.h"
#include "MD5.h"

#include "HTTPDigest.h"

#if 0
int main(int argc, _TCHAR* argv[])
{
    char *string = "a";
    MD5_CTX context;
    unsigned char digest[16];
    unsigned int len = strlen((const char *)string);
    MD5Init(&context);
    MD5Update(&context,(unsigned  char *)string, len);
    MD5Final(digest,&context);
    printf ("MD%d (\"%s\") = ",5, string);

    printf ("result:%s\n",digest);

    return 0;
}
#endif

#if 0
void main(int argc, char ** argv) {
    char * pszNonce = "dcd98b7102dd2f0e8b11d0f600bfb0c093";
    char * pszCNonce = "0a4f113b";
    char * pszUser = "Mufasa";
    char * pszRealm = "testrealm@host.com";
    char * pszPass = "Circle Of Life";
    char * pszAlg = "md5";
    char szNonceCount[9] = "00000001";
    char * pszMethod = "GET";
    char * pszQop = "auth";
    char * pszURI = "/dir/index.html";
    HASHHEX HA1;
    HASHHEX HA2 = "";
    HASHHEX Response;
    DigestCalcHA1(pszAlg, pszUser, pszRealm, pszPass, pszNonce,
        pszCNonce, HA1);
    DigestCalcResponse(HA1, pszNonce, szNonceCount, pszCNonce, pszQop,
        pszMethod, pszURI, HA2, Response);
    printf("Response = %s\n", Response);
};
#endif


#if 0
void CvtHex(IN HASH Bin,
            OUT HASHHEX Hex);
int main(int argc, char ** argv)
{
    char * pszNonce = "6fe9ba44a76be22a";
    char * pszCNonce = "kk";
    char * pszUser = "64010000002020000001";
    char * pszRealm = "64010000";
    char * pszPass = "12345";
    char * pszAlg = "md5";
    char szNonceCount[9] = "00000001";
    char * pszMethod = "REGISTER";
    char * pszQop = "auth";
    char * pszURI = "sip:64010000002000000001@172.18.16.5:5060";
    HASHHEX HA1;
    //HASHHEX HA2 = "";  //H(entity body) if qop="auth-int"
    HASHHEX Response;
#if 0
    DigestCalcHA1(pszAlg, pszUser, pszRealm, pszPass, pszNonce,
        pszCNonce, HA1);
    DigestCalcResponse(HA1, pszNonce, szNonceCount, pszCNonce, pszQop,
        pszMethod, pszURI, HA2, Response);
#endif

#if 0   //MD5 的计算，一个一个块输入，与整体一起输入，实际上是没有区别的。由下面的实验可以得出结论
    char *string = "64010000002020000001:64010000:12345";
    int len = strlen(string);
    HASH MD5_HA1;
    HASHHEX MD_HA1;
    MD5_CTX context;
    MD5Init(&context);
    MD5Update(&context,(unsigned  char *)string, len);
    MD5Final(MD5_HA1,&context);

    CvtHex(MD5_HA1,MD_HA1);
    printf("MD5Final = %s\n",MD_HA1);
#endif

    DigestCalcHA1(pszAlg, pszUser, pszRealm, pszPass, NULL,
                  NULL, HA1);

    //在下面这个函数里面，已经计算了 H(A2),所以不需要自己计算 H(A2)
    DigestCalcResponse(HA1, pszNonce,NULL,NULL,NULL,0,
                       pszMethod, pszURI,NULL, Response);

    printf("Response = %s\n", Response);
    return 0;
}
#endif
