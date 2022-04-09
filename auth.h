/*
    Licensed under the MIT License.
*/

bool
QcGenerateAuthCertificate(
    _In_ const std::string& Password,
    _Out_ std::unique_ptr<uint8_t[]>& Pkcs12,
    _Out_ uint32_t& Pkcs12Length);

bool
QcVerifyCertificate(
    _In_ const std::string& Password,
    _In_ QUIC_CERTIFICATE* Cert);
