#include "caml/alloc.h"
#include "caml/memory.h"

#include <windows.h>

value ca_certs_windows_trust_anchors_der(value vUnit)
{
    CAMLparam1(vUnit);

    CAMLlocal3(vList, vEncodedCert, vNext);
    vList = Val_int(0);

    HCERTSTORE hCertStore = CertOpenSystemStore(0, "ROOT");

    PCCERT_CONTEXT pCertContext = 0;
    while ((pCertContext = CertEnumCertificatesInStore(hCertStore, pCertContext)) != 0)
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