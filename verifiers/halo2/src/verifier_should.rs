#![cfg(test)]

use super::*;
use crate::utils::prepare_test_circuit;
use halo2_proofs::halo2curves::bn256::Fr;
use halo2_proofs::SerdeFormat;
use serial_test::serial;
use vm_circuit::{prove_circuit, setup_circuit};

struct MockRuntime;
impl Config for MockRuntime {
    type MaxPubs = sp_core::ConstU32<1>;
}

#[test]
#[serial]
fn verify_proof() {
    let (circuit, instances, k) = prepare_test_circuit::<Fr>().expect("Failed to get VM circuit");
    let params = load_params(k).expect("Failed to load params");
    let (vk, pk) = setup_circuit(&circuit, &params).expect("Failed to setup circuit");
    let proof = prove_circuit(circuit, &instances.as_ref(), &params, &pk)
        .expect("proof generation should not fail");

    let vk_bytes = vk.to_bytes(SerdeFormat::Processed);
    let vk = Vk::new(vk_bytes, CircuitType::ZkMove, k);
    let pubs = instances.to_bytes();

    let result = Halo2::<MockRuntime>::verify_proof(&vk, &proof, &pubs);
    assert!(
        result.is_ok(),
        "Valid proof verification failed: {:?}",
        result.err()
    );
}
