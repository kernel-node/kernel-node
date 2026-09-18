mod common;

use std::time::Duration;

use common::{peer_addrs, start_bitcoind, start_mirror, wait_for_height, TestNode};

const SYNC_TIMEOUT: Duration = Duration::from_secs(60);
const BLOCKS: usize = 100;

#[test]
fn finishes_after_a_peer_drops() {
    let core = start_bitcoind();
    let mut mirror = start_mirror(&core);
    println!("step 1/5: two bitcoinds started on regtest");

    let address = core.client.new_address().expect("new address");
    core.client
        .generate_to_address(BLOCKS, &address)
        .expect("mine blocks");
    let height = core.client.get_block_count().expect("block count").0;
    let hash = core.client.best_block_hash().expect("best block hash");
    println!("step 2/5: mined {BLOCKS} blocks to height {height}");

    assert_eq!(
        wait_for_height(&mirror, height, SYNC_TIMEOUT),
        hash,
        "peers disagree on the tip"
    );
    println!("step 3/5: both peers agree on the tip at height {height}");

    let node = TestNode::start_connected_to(&peer_addrs([&core, &mirror]), None);
    mirror.stop().expect("stop mirror peer");
    println!("step 4/5: node started against both peers, then one was stopped");

    node.wait_for_tip(height, hash, SYNC_TIMEOUT);
    println!("step 5/5: node reached height {height} from the remaining peer");

    node.stop();
}
