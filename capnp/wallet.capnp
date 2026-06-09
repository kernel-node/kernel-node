@0xb5d3a2f1e8c47690;

interface Wallet {
    importKeys @0 (scanKey :Data, spendKey :Data) -> (ok :Bool, message :Text);
    getBalance  @1 () -> (sats :UInt64, scanHeight :UInt32, utxoCount :UInt32);
    getHistory  @2 () -> (entries :Text);
    receive     @3 () -> (address :Text);
    broadcastRawTx @4 (tx :Data) -> (txid :Text);
    sendToAddress @5 (address :Text, amountSat :UInt64, feeRateSatPerVb :Float64) -> (txid :Text);
}
