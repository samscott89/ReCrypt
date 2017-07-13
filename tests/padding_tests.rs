extern crate recrypt;

mod helpers;

use recrypt::*;
use recrypt::common::*;

use helpers::*;

#[test]
fn pad_empty_block() {
    let empty : Vec<u8> = vec!();
    for len in 2..256 {
        let mut block = empty.clone();
        pad(&mut block, len);
        assert_eq!(vec![len as u8;len], block);
    }
}

#[test]
fn pad_rt_empty_block() {
    let empty : Vec<u8> = vec!();
    for len in 2..256 {
        let mut block = empty.clone();
        pad(&mut block, len);
        block = remove_padding(block).unwrap();
        assert!(block.is_empty());
    }
}

#[test]
fn remove_pad_empty_block() {
    for len in 2..256 {
        let mut block = vec![len as u8; len];
        block = remove_padding(block).unwrap();
        assert!(block.is_empty());
    }
}

// Tests add/remove with random inputs of various sizes.
#[test]
fn padding_rt_random_full_block() {
    // Tests each block length.
    for len in 2..(31*2+10) {
        // Tests a bunch of different blocks for each length.
        for _ in 0..10 {
            let block = random_vec(len);
            let mut _block = block.clone();
            pad(&mut _block, len);
            _block = remove_padding(_block).unwrap();
            assert_eq!(block, _block);
        }
    }
}

#[test] #[should_panic]
fn illegal_block_len_0() {
    pad(&mut random_vec(4), 0);
}

#[test] #[should_panic]
fn illegal_block_len_1() {
    pad(&mut random_vec(4), 1);
}

#[test] #[should_panic]
fn illegal_block_len_256() {
    pad(&mut random_vec(4), 256);
}

#[test] #[should_panic]
fn illegal_block_len_huge() {
    let max = !0 as usize;
    pad(&mut random_vec(4), max);
}

// Test possibly problematic encoding.
#[test]
fn pad_rt_matching_bytes() {
    let msg = vec![100; 100];
    let mut all_same = msg.clone();
    pad(&mut all_same, 200);
    assert_eq!(all_same.len(), 200);
    assert_eq!(*all_same.last().unwrap(), 100);
    let _result = remove_padding(all_same).unwrap();
    assert_eq!(msg, _result);
}

#[test]
fn invalid_pad_block_too_small() {
    // Build a vector with 1 byte of message, and 98 bytes of pad
    // claiming there are 100 bytes of pad.
    let mut block = vec![100; 98];
    block.insert(0, 33);

    // Verify this is our intended test case.
    assert_eq!(99, block.len());
    assert_eq!(33, block[0]);
    assert_eq!(100, *block.last().unwrap());

    // Verify that padding fails.
    assert!(remove_padding(block).is_none());
}
