matasano-elixir
===============

Solutions to the [Matasano Crypto Challenges](http://cryptopals.com/),
written in [Elixir](http://elixir-lang.org/).

[![Build Status](https://travis-ci.org/elasticdog/matasano-elixir.svg?branch=master)](https://travis-ci.org/elasticdog/matasano-elixir)

Set 1: Basics
-------------

- [x] 1. Convert hex to base64
- [x] 2. Fixed XOR
- [x] 3. Single-byte XOR cipher
- [x] 4. Detect single-character XOR
- [x] 5. Implement repeating-key XOR
- [x] 6. Break repeating-key XOR
- [ ] 7. AES in ECB mode
- [ ] 8. Detect AES in ECB mode

Set 2: Block crypto
-------------------

- [ ] 9. Implement PKCS#7 padding
- [ ] 10. Implement CBC mode
- [ ] 11. An ECB/CBC detection oracle
- [ ] 12. Byte-at-a-time ECB decryption (Simple)
- [ ] 13. ECB cut-and-paste
- [ ] 14. Byte-at-a-time ECB decryption (Harder)
- [ ] 15. PKCS#7 padding validation
- [ ] 16. CBC bitflipping attacks

Set 3: Block & stream crypto
----------------------------

- [ ] 17. The CBC padding oracle
- [ ] 18. Implement CTR, the stream cipher mode
- [ ] 19. Break fixed-nonce CTR mode using substitions
- [ ] 20. Break fixed-nonce CTR statistically
- [ ] 21. Implement the MT19937 Mersenne Twister RNG
- [ ] 22. Crack an MT19937 seed
- [ ] 23. Clone an MT19937 RNG from its output
- [ ] 24. Create the MT19937 stream cipher and break it

Set 4: Stream and crypto randomness
-----------------------------------

- [ ] 25. Break "random access read/write" AES CTR
- [ ] 26. CTR bitflipping
- [ ] 27. Recover the key from CBC with IV=Key
- [ ] 28. Implement a SHA-1 keyed MAC
- [ ] 29. Break a SHA-1 keyed MAC using length extension
- [ ] 30. Break an MD4 keyed MAC using length extension
- [ ] 31. Implement and break HMAC-SHA1 with an artificial timing leak
- [ ] 32. Break HMAC-SHA1 with a slightly less artificial timing leak

Set 5: Diffie-Hellman and friends
---------------------------------

- [ ] 33. Implement Diffie-Hellman
- [ ] 34. Implement a MITM key-fixing attack on Diffie-Hellman with parameter injection
- [ ] 35. Implement DH with negotiated groups, and break with malicious "g" parameters
- [ ] 36. Implement Secure Remote Password (SRP)
- [ ] 37. Break SRP with a zero key
- [ ] 38. Offline dictionary attack on simplified SRP
- [ ] 39. Implement RSA
- [ ] 40. Implement an E=3 RSA Broadcast attack

Set 6: RSA and DSA
------------------

- [ ] 41. Implement unpadded message recovery oracle
- [ ] 42. Bleichenbacher's e=3 RSA Attack
- [ ] 43. DSA key recovery from nonce
- [ ] 44. DSA nonce recovery from repeated nonce
- [ ] 45. DSA parameter tampering
- [ ] 46. RSA parity oracle
- [ ] 47. Bleichenbacher's PKCS 1.5 Padding Oracle (Simple Case)
- [ ] 48. Bleichenbacher's PKCS 1.5 Padding Oracle (Complete Case)

Set 7: Hashes
-------------

- [ ] 49. CBC-MAC Message Forgery
- [ ] 50. Hashing with CBC-MAC
- [ ] 51. Compression Ratio Side-Channel Attacks
- [ ] 52. Iterated Hash Function Multicollisions
- [ ] 53. Kelsey and Schneier's Expandable Messages
- [ ] 54. Kelsey and Kohno's Nostradamus Attack
- [ ] 55. MD4 Collisions
- [ ] 56. RC4 Single-Byte Biases

License
=======

matasano-elixir is provided under the terms of the
[MIT License](http://www.opensource.org/licenses/MIT).

Copyright &copy; 2015 [Aaron Bull Schaefer](mailto:aaron@elasticdog.com)
