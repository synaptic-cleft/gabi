# Notes
## Order of how to approach the code base
- understand simple flow for disclosure proof (skip revocation and range proof parts)
- understand verification of a proof: (p *ProofD) Verify
- issuance (NewCredentialBuilder in builder.go)
- key generation
- keyshare protocol
- range proof
- revocation
- keyproof

## Selective disclosure
`Credential`'s CreateDisclosureProof method in [credential.go](../credential.go)

2 steps:
1. randomize issuer's signature
2. create ZK proof

> Note: For basic Idemix, you can ignore all details about range proof and revocation.

### randomize issuer's signature
Function to randomize A so disclosures won't be linkable to users.
`Credential`'s CreateDisclosureProofBuilder method in [credential.go](../credential.go)

#### Idemix
Input:  
(A, e, v)  
(n, S, Z, R...)

```
r <- RANDOM()
A' <- A * S^r mod n
v' <- v - e*r
```
Output:  
(A', e, v')

#### Implementation
`Credential`'s CreateDisclosureProofBuilder method does more than just the randomization. The real randomization is done in:  
`CLSignature`'s Randomize method in [clsignature.go](../clsignature.go)

`CLSignature` already contains (A, e, v), the public key (n, S, Z, R...) will be passed as method argument and a new `CLSignature` will be returned.

`Credential`'s CreateDisclosureProofBuilder method this randomized signature is assigned to the `DisclosureProofBuilder`'s field `randomizedSignature`.


### create ZK proof

Why do we also need to hide v'?
probably cause if A' and v' is known, there might be a possibility for linkability. And only disclose what you really need to disclose.

(A', e, v')
(A'', e, v'')
...
// TODO: can at a certain point be further investigated

## Selective disclosure verification
see (p *ProofD) Verify

When verifying, we need to check if the signature (A, e, v) is correct, if the challenge used was correct and if the response sizes are correct.
The check if the signature is correct is nested in the challenge check as Z is computed with the signature provided in the proof and used as input for the challenge calculation.


## issuance
> note on issuance: v created as v' from client + v'' from issuer. v needs a minimum value, issuer can make sure that this minimum is reached

