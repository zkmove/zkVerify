use halo2_proofs::{
    arithmetic::CurveAffine,
    halo2curves::{
        ff::{FromUniformBytes, WithSmallOrderMulGroup},
        pairing::{Engine, MultiMillerLoop},
        serde::SerdeObject,
        CurveExt,
    },
    plonk::{
        create_proof, keygen_pk, keygen_vk, verify_proof, Circuit, Error, ProvingKey, VerifyingKey,
    },
    poly::{
        commitment::{CommitmentScheme, Params, ParamsProver, Prover, Verifier},
        kzg::strategy::SingleStrategy,
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::{ProverSHPLONK, VerifierSHPLONK},
        },
        VerificationStrategy,
    },
    transcript::{
        Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
    },
};
use log::debug;
use rand::{prelude::StdRng, SeedableRng};
use std::fmt::Debug;

/// Sets up a circuit by generating verification and proving keys.
///
/// # Arguments
/// - `circuit`: The circuit to generate keys for.
/// - `params`: The KZG parameters for the curve.
///
/// # Returns
/// A tuple containing the `VerifyingKey` and `ProvingKey` if successful.
pub fn setup_circuit<'params, C, P, ConcreteCircuit>(
    circuit: &ConcreteCircuit,
    params: &P,
) -> Result<(VerifyingKey<C>, ProvingKey<C>), Error>
where
    C: CurveAffine,
    P: Params<'params, C>,
    ConcreteCircuit: Circuit<C::ScalarExt>,
    C::ScalarExt: FromUniformBytes<64>,
{
    debug!("Generate vk");
    let vk = keygen_vk(params, circuit)?;
    debug!("Generate pk");
    let pk = keygen_pk(params, vk.clone(), circuit)?;
    Ok((vk, pk))
}

/// Proves a circuit using the SHPLONK multi-opening scheme with KZG commitments.
///
/// # Arguments
/// - `circuit`: The circuit to prove.
/// - `instance`: The public inputs for the circuit.
/// - `params`: The KZG parameters for the curve.
/// - `pk`: The proving key.
///
/// # Returns
/// The proof as a byte vector if successful.
pub fn prove_circuit<E, ConcreteCircuit>(
    circuit: ConcreteCircuit,
    instance: &[&[E::Fr]],
    params: &ParamsKZG<E>,
    pk: ProvingKey<E::G1Affine>,
) -> Result<Vec<u8>, Error>
where
    E: Engine + Debug + MultiMillerLoop,
    E::G1Affine:
        SerdeObject + CurveAffine<ScalarExt = <E as Engine>::Fr, CurveExt = <E as Engine>::G1>,
    E::G1: CurveExt<AffineExt = E::G1Affine>,
    E::G2Affine: SerdeObject + CurveAffine,
    ConcreteCircuit: Circuit<E::Fr>,
    <E as Engine>::Fr: Ord + WithSmallOrderMulGroup<3> + FromUniformBytes<64>,
{
    prove_circuit_inner::<KZGCommitmentScheme<E>, ProverSHPLONK<E>, _>(
        circuit, instance, params, pk,
    )
}

/// Verifies a circuit proof using the SHPLONK multi-opening scheme with KZG commitments.
///
/// # Arguments
/// - `instance`: The public inputs for the circuit.
/// - `params`: The KZG parameters for the curve.
/// - `vk`: The verification key.
/// - `proof`: The proof bytes to verify.
///
/// # Returns
/// `Ok(())` if the proof is valid, or an error if verification fails.
pub fn verify_circuit<E>(
    instance: &[&[E::Fr]],
    params: &ParamsKZG<E>,
    vk: &VerifyingKey<E::G1Affine>,
    proof: Vec<u8>,
) -> Result<(), Error>
where
    E: Engine + Debug + MultiMillerLoop,
    E::G1Affine:
        SerdeObject + CurveAffine<ScalarExt = <E as Engine>::Fr, CurveExt = <E as Engine>::G1>,
    E::G1: CurveExt<AffineExt = E::G1Affine>,
    E::G2Affine: SerdeObject + CurveAffine,
    <E as Engine>::Fr: Ord + WithSmallOrderMulGroup<3> + FromUniformBytes<64>,
{
    verify_circuit_inner::<KZGCommitmentScheme<E>, VerifierSHPLONK<E>, SingleStrategy<E>>(
        instance, params, vk, proof,
    )
}

/// Internal function to prove a circuit with specified scheme and prover.
///
/// # Arguments
/// - `circuit`: The circuit to prove.
/// - `instance`: The public inputs.
/// - `params`: The prover parameters.
/// - `pk`: The proving key.
///
/// # Returns
/// The proof as a byte vector if successful.
fn prove_circuit_inner<
    'params,
    Scheme: CommitmentScheme,
    P: Prover<'params, Scheme>,
    ConcreteCircuit: Circuit<Scheme::Scalar>,
>(
    circuit: ConcreteCircuit,
    instance: &[&[Scheme::Scalar]],
    params: &'params Scheme::ParamsProver,
    pk: ProvingKey<Scheme::Curve>,
) -> Result<Vec<u8>, Error>
where
    <Scheme as CommitmentScheme>::ParamsVerifier: 'params,
    <Scheme as CommitmentScheme>::Scalar: WithSmallOrderMulGroup<3> + FromUniformBytes<64>,
{
    let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
    // Create a proof
    let rng = StdRng::from_entropy();
    create_proof::<Scheme, P, _, _, _, _>(
        params,
        &pk,
        &[circuit],
        &[instance],
        rng,
        &mut transcript,
    )?;
    let proof: Vec<u8> = transcript.finalize();
    debug!("proof size {} bytes", proof.len());

    Ok(proof)
}

/// Internal function to verify a circuit proof with specified scheme and verifier.
///
/// # Arguments
/// - `instance`: The public inputs.
/// - `params`: The prover parameters.
/// - `vk`: The verification key.
/// - `proof`: The proof bytes.
///
/// # Returns
/// `Ok(())` if the proof is valid, or an error if verification fails.
fn verify_circuit_inner<
    'params,
    Scheme: CommitmentScheme,
    V: Verifier<'params, Scheme>,
    Strategy: VerificationStrategy<'params, Scheme, V>,
>(
    instance: &[&[Scheme::Scalar]],
    params: &'params Scheme::ParamsProver,
    vk: &VerifyingKey<Scheme::Curve>,
    proof: Vec<u8>,
) -> Result<(), Error>
where
    <Scheme as CommitmentScheme>::ParamsVerifier: 'params,
    <Scheme as CommitmentScheme>::Scalar: WithSmallOrderMulGroup<3> + FromUniformBytes<64>,
{
    let verifier_params = params.verifier_params();
    let strategy = Strategy::new(verifier_params);
    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
    verify_proof(verifier_params, vk, strategy, &[instance], &mut transcript)?;

    Ok(())
}
