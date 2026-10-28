mod common;

use std::time::Duration;

use common::{start_bitcoind, TestNode};

const SYNC_TIMEOUT: Duration = Duration::from_secs(60);
const BLOCKS: usize = 10;

#[test]
fn follows_bitcoin_core_chain() {
    let core = start_bitcoind();
    let address = core.client.new_address().expect("new address");
    core.client
        .generate_to_address(BLOCKS, &address)
        .expect("mine blocks");

    let core_height = core.client.get_block_count().expect("block count").0;
    let core_hash = core.client.best_block_hash().expect("best block hash");
    assert_eq!(core_height, BLOCKS as u64);

    let p2p = core.params.p2p_socket.expect("bitcoind p2p socket");
    let node = TestNode::start_connected(p2p, None);

    node.wait_for_tip(core_height, core_hash, SYNC_TIMEOUT);

    node.stop();
}

#[test]
fn keeps_chain_across_restart() {
    let core = start_bitcoind();
    let address = core.client.new_address().expect("new address");
    core.client
        .generate_to_address(BLOCKS, &address)
        .expect("mine blocks");

    let core_height = core.client.get_block_count().expect("block count").0;
    let core_hash = core.client.best_block_hash().expect("best block hash");

    let p2p = core.params.p2p_socket.expect("bitcoind p2p socket");
    let node = TestNode::start_connected(p2p, None);
    node.wait_for_tip(core_height, core_hash, SYNC_TIMEOUT);
    let datadir = node.stop();
    drop(core);

    let node = TestNode::start_in(datadir, &[], None);
    let (height, hash) = node.tip();
    assert_eq!((u64::from(height), hash), (core_height, core_hash));

    node.stop();
}
