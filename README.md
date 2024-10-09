# ServerClient_TLSv1.3

## Video Demonstration: 
[![Demonstration of my Java Server&Client Programs](https://img.youtube.com/vi/hRHQjegPvOE/maxresdefault.jpg)](https://www.youtube.com/watch?v=hRHQjegPvOE)

This Java Server/Client combination implements TLSv1.3 by:
-Bash script generation of an x509 certificate chain, along with RSA private keys.
-The Server component using Java's SSLServerSocket, SSLContext, KeyStore, X509Certificate and other classes to engage the TLSv1.3 handshake and session.
-The Client component using Java's SSLSocket, SSLContext, TrustManager, X509Certificate and other classes to request a TLSv1.3 handshake and only trust the session if the partial or full chain has been ultimately signed by a valid root authority. During initialisation, my own self-signed root authority is automatically trusted.
