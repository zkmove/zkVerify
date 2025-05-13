#![cfg_attr(not(feature = "std"), no_std)]

use ::vm_circuit::circuit_v2::VmCircuit;
use codec::{Decode, Encode, MaxEncodedLen};
use frame_support::pallet_prelude::TypeInfo;
use frame_support::{ensure, weights::Weight};
use halo2_proofs::SerdeFormat;
use halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    plonk::VerifyingKey,
    poly::kzg::commitment::ParamsKZG,
};
use hp_verifiers::{Cow, Verifier, VerifyError};
use sp_core::{Get, H256};
use sp_std::{marker::PhantomData, vec::Vec};
use vm_circuit::{verify_circuit, InstanceFields, NUM_INSTANCE_COLUMNS};

pub const PUBS_SIZE: usize = 1024;
pub const VK_SIZE: usize = 1024;

pub type Proof = Vec<u8>;
pub type Pubs = Vec<u8>;

#[derive(Clone, Debug, PartialEq, Encode, Decode, TypeInfo)]
pub enum CircuitType {
    ZkMove,
}
#[derive(Clone, Debug, PartialEq, Encode, Decode, TypeInfo)]
pub struct Vk {
    pub vk: Vec<u8>,
    pub circuit: CircuitType,
    pub k: u32,
}

impl Vk {
    pub fn new(vk: Vec<u8>, circuit: CircuitType, k: u32) -> Self {
        Vk { vk, circuit, k }
    }

    pub fn get_vk(&self) -> &Vec<u8> {
        &self.vk
    }

    pub fn circuit(&self) -> &CircuitType {
        &self.circuit
    }

    pub fn get_k(&self) -> u32 {
        self.k
    }
}

impl MaxEncodedLen for Vk {
    fn max_encoded_len() -> usize {
        codec::Compact::<u32>::max_encoded_len() + VK_SIZE
    }
}

mod utils;
pub(crate) mod verifier_should;
mod weight;

pub trait Config {
    type MaxPubs: Get<u32>;
}

#[pallet_verifiers::verifier]
pub struct Halo2<T>;

impl<T: Config> Verifier for Halo2<T> {
    type Proof = Proof;
    type Pubs = Pubs;
    type Vk = Vk;

    fn hash_context_data() -> &'static [u8] {
        b"halo2"
    }

    fn verify_proof(
        vk: &Self::Vk,
        proof: &Self::Proof,
        pubs: &Self::Pubs,
    ) -> Result<Option<Weight>, VerifyError> {
        log::trace!("Verifying Halo2 proof");
        // ensure!(
        //     pubs.len() <= T::MaxPubs::get() as usize,
        //     VerifyError::InvalidInput
        // );

        let params = load_params(vk.get_k()).expect("Failed to load params");
        let vk = deserialize_vk(vk)?;
        let instances = InstanceFields::<Fr, NUM_INSTANCE_COLUMNS>::from_bytes(pubs);
        verify_circuit(&instances.as_ref(), &params, &vk, proof)
            .expect("verify proof should be ok");

        Ok(None)
    }

    fn validate_vk(vk: &Self::Vk) -> Result<(), VerifyError> {
        deserialize_vk(vk)
            .map(|_| ())
            .map_err(|_| VerifyError::InvalidVerificationKey)?;
        Ok(())
    }

    fn vk_hash(vk: &Self::Vk) -> H256 {
        sp_io::hashing::sha2_256(&Self::vk_bytes(vk)).into()
    }

    fn vk_bytes(vk: &Self::Vk) -> Cow<[u8]> {
        Cow::Borrowed(vk.get_vk()) //we don't need to hash the whole vk
    }

    fn pubs_bytes(pubs: &Self::Pubs) -> Cow<[u8]> {
        Cow::Borrowed(pubs)
    }
}

fn deserialize_vk(vk: &Vk) -> Result<VerifyingKey<G1Affine>, VerifyError> {
    match vk.circuit() {
        CircuitType::ZkMove => {
            VerifyingKey::<G1Affine>::from_bytes::<VmCircuit<Fr>>(vk.get_vk(), SerdeFormat::Processed)
                .map_err(|e| {
                    log::debug!("VK deserialization failed: {:?}", e);
                    VerifyError::InvalidVerificationKey
                })
        }
    }
}

#[cfg(feature = "std")]
fn load_params(k: u32) -> Result<ParamsKZG<Bn256>, VerifyError> {
    //TODO: load params from file or chain
    let rng = rand::rngs::mock::StepRng::new(0, 1);
    let params = ParamsKZG::<Bn256>::setup(k, rng);
    Ok(params)
}

#[cfg(not(feature = "std"))]
fn load_params(k: u32) -> Result<ParamsKZG<Bn256>, VerifyError> {
    // In a no_std environment, parameters should be preloaded or obtained from the chain.
    // Example parameters are used here, they should be replaced with real parameters in practice.
    let params = ParamsKZG::<Bn256>::new(k);
    Ok(params)
}

pub struct Halo2Weight<W: weight::WeightInfo>(PhantomData<W>);

impl<T: Config, W: weight::WeightInfo> pallet_verifiers::WeightInfo<Halo2<T>> for Halo2Weight<W> {
    fn verify_proof(_proof: &Proof, _pubs: &Pubs) -> Weight {
        W::verify_proof()
    }

    fn register_vk(_vk: &Vk) -> Weight {
        W::register_vk()
    }

    fn unregister_vk() -> Weight {
        W::unregister_vk()
    }

    fn get_vk() -> Weight {
        W::get_vk()
    }

    fn validate_vk(_vk: &Vk) -> Weight {
        W::validate_vk()
    }

    fn compute_statement_hash(_proof: &Proof, _pubs: &Pubs) -> Weight {
        W::compute_statement_hash()
    }
}
