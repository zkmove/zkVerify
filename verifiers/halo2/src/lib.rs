#![cfg_attr(not(feature = "std"), no_std)]

use crate::test_circuit::{get_test_circuit, TestCircuit};
use codec::{Decode, Encode, MaxEncodedLen};
use educe::Educe;
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

pub const PUBS_SIZE: usize = 32;
pub const VK_SIZE: usize = 1024;

pub type Proof = Vec<u8>;
pub type Pubs = Vec<[u8; PUBS_SIZE]>;

#[derive(Educe, Encode, Decode, TypeInfo)]
#[educe(Clone, Debug, PartialEq)]
pub struct Vk {
    pub vk: Vec<u8>,
}

impl Vk {
    pub fn new(vk: Vec<u8>) -> Self {
        Vk { vk }
    }

    pub fn get_vk(&self) -> &Vec<u8> {
        &self.vk
    }
}

impl MaxEncodedLen for Vk {
    fn max_encoded_len() -> usize {
        codec::Compact::<u32>::max_encoded_len() + VK_SIZE
    }
}

mod proofs;
mod test_circuit;
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
        let params = load_params(4).expect("Failed to load params");

        ensure!(
            pubs.len() <= T::MaxPubs::get() as usize,
            VerifyError::InvalidInput
        );

        let vk_deserialized = deserialize_vk(&vk.get_vk())?;

        let instances: Vec<Fr> = pubs
            .iter()
            .map(|pub_bytes| {
                let mut fr_bytes = [0u8; 32];
                fr_bytes.copy_from_slice(pub_bytes);
                let fr_opt = Fr::from_bytes(&fr_bytes);
                if fr_opt.is_some().into() {
                    Ok(fr_opt.unwrap())
                } else {
                    Err(VerifyError::InvalidInput)
                }
            })
            .collect::<Result<Vec<_>, VerifyError>>()?;
        let instances_refs: Vec<&[Fr]> =
            instances.iter().map(|v| std::slice::from_ref(v)).collect();

        proofs::verify_circuit(&instances_refs, &params, &vk_deserialized, proof.clone()).map_err(
            |e| {
                log::debug!("Cannot verify proof: {:?}", e);
                VerifyError::VerifyError
            },
        )?;

        Ok(None)
    }

    fn validate_vk(vk: &Self::Vk) -> Result<(), VerifyError> {
        deserialize_vk(vk.get_vk())
            .map(|_| ())
            .map_err(|_| VerifyError::InvalidVerificationKey)?;
        Ok(())
    }

    fn vk_hash(vk: &Self::Vk) -> H256 {
        sp_io::hashing::sha2_256(&Self::vk_bytes(vk)).into()
    }

    fn vk_bytes(vk: &Self::Vk) -> Cow<[u8]> {
        Cow::Borrowed(vk.get_vk())
    }

    fn pubs_bytes(pubs: &Self::Pubs) -> Cow<[u8]> {
        let data = pubs
            .iter()
            .flat_map(|s| s.iter().cloned())
            .collect::<Vec<_>>();
        Cow::Owned(data)
    }
}

fn deserialize_vk(vk: &[u8]) -> Result<VerifyingKey<G1Affine>, VerifyError> {
    VerifyingKey::<G1Affine>::from_bytes::<TestCircuit<Fr>>(vk, SerdeFormat::Processed).map_err(
        |e| {
            log::debug!("VK deserialization failed: {:?}", e);
            VerifyError::InvalidVerificationKey
        },
    )
}

#[cfg(feature = "std")]
fn load_params(k: u32) -> Result<ParamsKZG<Bn256>, VerifyError> {
    let params = ParamsKZG::<Bn256>::new(k);
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
