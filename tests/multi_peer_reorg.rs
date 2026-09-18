mod common;

use std::time::Duration;

use bitcoin::BlockHash;
use common::{peer_addrs, start_bitcoind, start_mirror, wait_for_height, TestNode};

const SYNC_TIMEOUT: Duration = Duration::from_secs(60);
const REORG_TIMEOUT: Duration = Duration::from_secs(60);
const INITIAL_BLOCKS: usize = 30;
const FORK_HEIGHT: u64 = 20;
const NEW_BLOCKS: usize = 15;

#[test]
fn follows_a_reorg_from_two_peers() {
    let core = start_bitcoind();
    let mirror = start_mirror(&core);
    println!("step 1/5: two bitcoinds started on regtest");

    let address = core.client.new_address().expect("new address");
    core.client
        .generate_to_address(INITIAL_BLOCKS, &address)
        .expect("mine initial blocks");
    let initial_height = core.client.get_block_count().expect("block count").0;
    let initial_hash = core.client.best_block_hash().expect("best block hash");
    wait_for_height(&mirror, initial_height, SYNC_TIMEOUT);
    println!("step 2/5: both peers at height {initial_height}");

    let node = TestNode::start_connected_to(&peer_addrs([&core, &mirror]), None);
    node.wait_for_tip(initial_height, initial_hash, SYNC_TIMEOUT);
    println!("step 3/5: node synced to height {initial_height} from both peers");

    let fork_block = core
        .client
        .get_block_hash(FORK_HEIGHT)
        .expect("block hash at fork height")
        .0
        .parse::<BlockHash>()
        .expect("parse fork block hash");
    core.client
        .invalidate_block(fork_block)
        .expect("invalidate block");
    let reorg_address = core.client.new_address().expect("new address");
    core.client
        .generate_to_address(NEW_BLOCKS, &reorg_address)
        .expect("mine competing branch");
    let reorg_height = core.client.get_block_count().expect("block count").0;
    let reorg_hash = core.client.best_block_hash().expect("best block hash");
    assert!(reorg_height > initial_height);
    assert_ne!(reorg_hash, initial_hash);
    assert_eq!(
        wait_for_height(&mirror, reorg_height, REORG_TIMEOUT),
        reorg_hash,
        "peers disagree after the reorg"
    );
    println!(
        "step 4/5: invalidated height {FORK_HEIGHT}, both peers now on a branch to height {reorg_height}"
    );

    node.wait_for_tip(reorg_height, reorg_hash, REORG_TIMEOUT);
    println!("step 5/5: node followed the reorg to height {reorg_height}");

    node.stop();
}
