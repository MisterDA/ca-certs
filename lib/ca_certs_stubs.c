#include <caml/memory.h>

#ifdef _WIN32

#include <caml/alloc.h>
#include <windows.h>

CAMLprim value ca_certs_windows_trust_anchors_der(value vUnit)
{
    CAMLparam1(vUnit);

    CAMLlocal3(vList, vEncodedCert, vNext);
    vList = Val_int(0);

    HCERTSTORE hCertStore = CertOpenSystemStore(0ULL, "ROOT");

    PCCERT_CONTEXT pCertContext = NULL;
    while ((pCertContext = CertEnumCertificatesInStore(hCertStore, pCertContext)) != NULL)
    {
        vEncodedCert = caml_alloc_initialized_string(
            pCertContext->cbCertEncoded,
            pCertContext->pbCertEncoded);
        vNext = caml_alloc(2, 1);
        Store_field(vNext, 0, vEncodedCert);
        Store_field(vNext, 1, vList);
        vList = vNext;
    }

    CertCloseStore(hCertStore, 0);

    CAMLreturn(vList);
}

#else

#include <caml/fail.h>

CAMLprim value ca_certs_windows_trust_anchors_der(value vUnit)
{
    CAMLparam1(vUnit);
    caml_invalid_argument("not implemented");
}

#endif
