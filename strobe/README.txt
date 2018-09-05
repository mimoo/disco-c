STROBE protocol framework

This is a development release of the STROBE framework.  Although the
specification of the framework is at release level (1.0.0), the code is
development-quality and not yet ready for production use.

STROBE's framework spec versioning (not software versioning) is a little
bit funny.  Every protocol hashes the spec version into the cryptographic
state, so any change to the spec version string breaks interoperability.
However, minor and patch revisions shouldn't break application
compatibility, so protocol specifications that make sense with 1.0.0
should also work with 1.0.1 and 1.1.0.

TODO: Update this README to include worthwhile documentation and use cases
for STROBE.

#############
Side channels
#############

The STROBE code is designed to resist timing side-channels that would
recover secret keys and messages.  Obviously, timing is affected by other
variables such as message lengths.

The compact X25519 code is designed to resist timing side-channels, including
attacks on timing, caching, and branch prediction.  However, the code
is incomplete in that regard, and should be tested on your particular CPU
and compiler.  This warning is mainly in regard to embedded or old processors
such as the Cortex-M0, Cortex-M3, 80386, 80486, Via Nano 2000, PowerPC G3,
PowerPC G4, and RISC-V Rocket.  These processors have a multiplication
instruction which takes a variable amount of time depending on its operands.
Since X25519 uses multiplication on sensitive data, some of that data will
leak to an attacker who can observe timing information. There are per-CPU
workarounds for this problem, but none of them are yet included in STROBE's
X25519 implementation.

Newer CPUs such as the Cortex-M4 and higher, and modern X86 processors, should
be safe.  However, the test suite does not currently test resistance to timing
attacks (TODO).

On vulnerable processors, I expect that ephemeral Curve25519 is safe, and that
signature verification leaks information that's public in most threat models
(eg, the signer, signature and hashed message).  Signing and long-term X25519
are probably vulnerable to key compromise.

I would like to eventually place a warning on the X25519 code for this, but
there are so many CPUs affected that it would be difficult to test the warning
code.

None of this code is designed to resist physically invasive attacks such as
power side channels, electromagnetic side channels, or fault attacks.

Remember of course that this is alpha-quality software, and probably contains
bugs which are more serious than timing attacks.

#############
Mailing lists
#############

If you use STROBE, please subscribe to at least the strobe-security mailing
list:
     strobe-security@lists.sourceforge.net
     https://lists.sourceforge.net/lists/listinfo/strobe-security

This mailing list is moderated and low-volume.  It will be used only to
announce security issues in STROBE, should they arise.
    
You may also be interested in the strobe-announce and strobe-discuss
mailing lists.

     strobe-discuss@lists.sourceforge.net
     https://lists.sourceforge.net/lists/listinfo/strobe-discuss

     strobe-announce@lists.sourceforge.net
     https://lists.sourceforge.net/lists/listinfo/strobe-announce

###########################
Export control notification
###########################

Downloading of this software may constitute an export or re-export of
cryptographic software from the United States of America. The U.S.
government prohibits export of encryption source code to certain countries
and individuals, including, but not limited to, the countries of Cuba, Iran,
North Korea, Sudan, Syria, and residents and nationals of those countries.
Other countries may also have restrictions on the import, possession, use,
and/or re-export to another country, of encryption software. BEFORE using
any encryption software, please check your country's laws, regulations and
policies concerning the import, possession, or use, and re-export of
encryption software, to see if this is permitted.
