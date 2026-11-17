# Identity hardening: stopping AiTM even when the user clicks

luretrace detects and gathers evidence. It does not stop the attack. An adversary-in-the-
middle kit can show a scanner a decoy, burn the link after one use, arm it late, or gate it
on the victim's address. Treat the scanner as a tripwire and an IOC source. The controls that
actually stop the attack live in your identity provider. The list below is written for
Entra ID; Okta and Google Workspace have equivalents.

Apply these in order of impact.

## 1. Phishing-resistant MFA (the one control a proxy cannot defeat)
FIDO2 security keys, passkeys (device-bound), and Windows Hello for Business are bound to the
real login origin, so a proxy on another domain captures nothing replayable.
- Roll out passkeys / FIDO2 to all privileged and high-value users first.
- The attacker's fallback is a **downgrade**: the proxy hides the passkey prompt and asks for
  push or OTP. Defeat it by *removing* the weaker methods for those users, not leaving them as
  backups. Use Authentication Strengths in Conditional Access to require phishing-resistant
  methods for sensitive apps.

## 2. Make a stolen token useless: require a compliant / hybrid-joined device
A captured session cookie is replayed from the attacker's own machine. A Conditional Access
policy that requires a compliant or hybrid Entra-joined device fails that replay.
- Conditional Access > require device to be marked compliant (or hybrid joined) for all users,
  report-only first, then enforce.
- Enable **Token Protection** (sign-in session token binding) for session tokens where
  supported; confirm current app coverage before relying on it.

## 3. Block the persistence step from your incident
The attacker registered a device to gain durable access. Lock that down:
- Conditional Access on the **"Register or join devices"** user action: require phishing-
  resistant MFA.
- Conditional Access on the **"Register security information"** user action: require a
  compliant device or a trusted network, and use Temporary Access Pass for onboarding.
- Restrict who can join devices (Entra > Devices > Device settings) and set MFA-to-join.

## 4. Close the side doors
- **Block the device-code flow** via Conditional Access, except where a named app needs it.
  It is the common next move once AiTM is contained.
- **Restrict OAuth app consent** to admin approval; review existing grants. Token theft is
  often paired with a malicious OAuth grant for persistence.
- **Sign-in risk policy** (Entra ID Protection): require MFA or block on high risk.

## 5. Shrink the token lifetime
- Continuous Access Evaluation on, so revocation takes effect in near real time.
- Tune sign-in frequency for sensitive apps so a stolen cookie expires sooner.

## How this maps to what hit you
A SharePoint lure -> AiTM proxy -> captured post-MFA token -> attacker registered a device for
persistence. Control 1 stops the capture, control 2 makes the captured token unusable, and
control 3 stops the device registration. Any one breaks the chain; together they close it.
