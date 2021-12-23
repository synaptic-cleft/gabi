# Selective disclosure
`Credential`'s CreateDisclosureProof method in [credential.go](../credential.go)

2 steps:
1. randomize issuer's signature
2. create ZK proof

> Note: For basic Idemix, you can ignore all details about range proof and revocation.

## randomize issuer's signature
Function to randomize A so disclosures won't be linkable to users.
`Credential`'s CreateDisclosureProofBuilder method in [credential.go](../credential.go)

### Idemix
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

### Implementation
`Credential`'s CreateDisclosureProofBuilder method does more than just the randomization. The real randomization is done in:  
`CLSignature`'s Randomize method in [clsignature.go](../clsignature.go)

`CLSignature` already contains (A, e, v), the public key (n, S, Z, R...) will be passed as method argument and a new `CLSignature` will be returned.

`Credential`'s CreateDisclosureProofBuilder method this randomized signature is assigned to the `DisclosureProofBuilder`'s field `randomizedSignature`.


## create ZK proof

Why do we also need to hide v'?
probably cause if A' and v' is known, there might be a possibility for linkability. And only disclose what you really need to disclose.

(A', e, v')
(A'', e, v'')
...
// TODO: can at a certain point be further investigated




# issuance
> note on issuance: v created as v' from client + v'' from issuer. v needs a minimum value, issuer can make sure that this minimum is reached

