# Proving Transaction Inclusion

This is a simple demo application that demonstrates how to prove a transaction
has been included in a block and what its execution result was.

The demo targets a specific transaction on Sapphire Testnet.

## Build

```
go build
```

## Use

```
./demo-prove-tx
```

## Output

```
Consensus height:          23286817
Consensus state root hash: e0c22bba6c58ff55c63fd4593596a6d6362e4d95bd0b440287f0e1da7ea64f1a
Runtime height:            8391175
Runtime IO root hash:      ffb5de8fe986a7eceb4f75578666136de1cbc123f2d5daa539c230bfe60d8f07
Transaction hash:          f947a92965797c77c2e0240be1cca3cc167faa4f3163edcaec2fda70f1354780
Eth transaction hash:      0x12b535a1752a81184c26cc6497cc3f6cb449b0c611d68c8c7c2b5382bb6d373b
Transaction status:        ok
            data:          0x40
```
