# Threat model

pinpam's threat model can be broadly divided into three seperate malicious threats.

1. An actor with no credentials or root access attempting to guess a users pin.

pinpam protects against threat model one with per user brute force dictionary attack protection. Normally, PINs of short length are trivial to brute force. TPM enforced lockout policy limits the number of attempts that can be made before the credentials are permanently locked. 

2. An actor with root already, through means other than pinpam, attempting to dump pins for credential reuse attacks. 

pinpam protects against this threat model with the same brute force protection. Even a root user cannot bypass this, as pinpam implements a TPM policy limiting the indexes to read-only after being written, preventing an attacker from resetting the failed attempts counter to continue guessing the user's pins. 

3. an actor attempting to lockout a user from their account by spam guessing their pin.

pinpam can be subject to DOS attacks by malicious users. If pinpam is configured as the sole required method for auth, a malicious user could prevent legitamate ones from accessing their account by guessing PINs until triggering a lockout. To mitigate this, pinpam should be configured as a sufficient (meaning not the only option), rather than a required, method for authentication. 

# Sandboxing

As of v0.0.3, pinutil includes sandboxing with Landlock, preventing an attacker from having complete root access to a comprimised system.

Specifically, TCP connections and binds, and filesystem writes are restricted to outside the /dev directory.

# Tips

PAM lets administrators configure different authentication requirements for different services. For example, you could let the user unlock their screen with pinpam, but require a password for sudo or other critical operations. It is recommended to not configure pinpam as the sole method for any authentication service. as it opens up possibilities for DOS lockout attacks.
