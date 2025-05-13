#![cfg(test)]

use anyhow::{anyhow, Result};
use move_package::compilation::compiled_package::OnDiskCompiledPackage;
use move_package::compilation::package_layout::CompiledPackageLayout;
use std::fs;
use std::path::Path;
use types::Field;
use vm_circuit::{
    best_k, CircuitConfigV2, Footprints, InstanceFields, SubCircuit, VmCircuit,
    NUM_INSTANCE_COLUMNS,
};

pub const TEST_PACKAGE_NAME: &str = "example";
pub fn prepare_test_circuit<F: Field>() -> Result<(
    VmCircuit<F>,
    InstanceFields<F, NUM_INSTANCE_COLUMNS>,
    /*k*/ u32,
)> {
    let package_path = Path::new(env!("CARGO_MANIFEST_DIR")).join(TEST_PACKAGE_NAME);
    let build_path = package_path
        .join(CompiledPackageLayout::Root.path())
        .join(TEST_PACKAGE_NAME);
    let package =
        OnDiskCompiledPackage::from_path(build_path.as_path())?.into_compiled_package()?;
    let witness_dir = package_path.join("witnesses");

    let footprints = fs::read_dir(&witness_dir)?
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "json") {
                Some(path)
            } else {
                None
            }
        })
        .next()
        .ok_or_else(|| anyhow!("witness .json cannot be found"))?;
    let traces = Footprints::load(&footprints)?;
    let entry = traces.entry().expect("Entry not found");
    let pubs_indices = vec![0]; // argument "n" is public input

    let circuit = VmCircuit::<F>::new(
        &package,
        &traces,
        pubs_indices.as_slice(),
        CircuitConfigV2::default(),
    );
    let instances =
        InstanceFields::<_, NUM_INSTANCE_COLUMNS>::new(&entry.args, pubs_indices.as_slice());
    let k = best_k(&circuit);
    Ok((circuit, instances, k))
}
