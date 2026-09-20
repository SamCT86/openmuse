# Process-separated secret service

`SecretService` keeps vault decryption in a dedicated host process and exposes one authenticated Unix-socket request at a time. The socket is owner-only and the caller authenticates the requested secret name with an HMAC key. Run the service outside tool containers and pass clients only the socket plus scoped authentication material. Hardware-backed master-key providers can implement the existing `MasterKeyProvider` protocol without changing the service API.
