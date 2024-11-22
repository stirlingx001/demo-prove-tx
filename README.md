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
Consensus height:          24002573
Consensus state root hash: 7b79526a20d4914e9df57a1acae377f7ffd9939b320da9dc6231eb7174955cfb
Runtime height:            9106088
Runtime IO root hash:      1a1e1c613b792fb4b4e1bd99faa2cb3fff55ff43d34a9cdd3178139bdd25eb55
Transaction hash:          9e8f32ff98ca4d835281886d8e4041bce3cdce714d488c63b9202c65e1a4531a
Eth transaction hash:      0xf3d49f4e387ff1f28bfa52b2464376ddcc70c56256ab963047d2e9e7398a479f
Transaction status:        ok
            data:          0x58200000000000000000000000000000000000000000000000000000000000000001
EVM events:
- Address: 0x4CC8C97ECE381B6FD56B891FC1F4B67B04A8D7F4
  Topics:
    - 0x8C5BE1E5EBEC7D5BD14F71427D1E84F3DD0314C0F7B2291E5B200AC8C7C3B925
    - 0x0000000000000000000000009BC693E82C34BD12DDFDFF5FBDFBCB4A3B98754F
    - 0x000000000000000000000000C93E28B974AAD2454D7598021EBE16778F4BF16C
  Data: 0x00000000000000000000000000000000000000000000003635C9ADC5DEA00000
```
