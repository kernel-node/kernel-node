@0xc2e20cc9503cf68f;

using Wallet = import "wallet.capnp";
using Chain = import "chain.capnp";

interface Server {
    echo @0 (msg :Text) -> (reply :Text);
    shutdown @1 () -> ();
    makeWallet @2 () -> (wallet :Wallet.Wallet);
    makeChain @3 () -> (chain :Chain.Chain);
    network @4 () -> (network :Text);
}
