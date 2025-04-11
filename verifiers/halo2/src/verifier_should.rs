#![cfg(test)]

use super::*;
use crate::test_circuit::get_test_circuit;
use halo2_proofs::halo2curves::bn256::Fr;
use halo2_proofs::halo2curves::ff::PrimeField;
use halo2_proofs::SerdeFormat;
use serial_test::serial;

struct MockRuntime;
impl Config for MockRuntime {
    type MaxPubs = sp_core::ConstU32<1>;
}

#[test]
#[serial]
fn verify_simple_proof() {
    let (circuit, instances) = get_test_circuit::<Fr>();
    let params = load_params(4).expect("Failed to load params");
    let (vk, pk) = proofs::setup_circuit(&circuit, &params).expect("Failed to setup circuit");
    let proof = proofs::prove_circuit(circuit, &[&instances], &params, pk)
        .expect("Failed to generate Proof");

    let vk_bytes = vk.to_bytes(SerdeFormat::Processed);

    let vk = Vk::new(vk_bytes);
    let pi = instances
        .into_iter()
        .map(|i| {
            let mut bytes = i.to_repr().as_ref().to_vec();
            bytes.resize(PUBS_SIZE, 0);
            bytes
                .try_into()
                .expect("Failed to convert instance to PUBS_SIZE array")
        })
        .collect();

    let result = Halo2::<MockRuntime>::verify_proof(&vk, &proof, &pi);
    assert!(
        result.is_ok(),
        "Valid proof verification failed: {:?}",
        result.err()
    );
}
