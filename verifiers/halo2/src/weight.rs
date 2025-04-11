use frame_support::weights::{constants::RocksDbWeight, Weight};

pub trait WeightInfo {
    fn verify_proof() -> Weight;
    fn get_vk() -> Weight;
    fn validate_vk() -> Weight;
    fn compute_statement_hash() -> Weight;
    fn register_vk() -> Weight;
    fn unregister_vk() -> Weight;
}

// fake value, need update with benchmark
impl WeightInfo for () {
    fn verify_proof() -> Weight {
        Weight::from_parts(2_500_000_000, 0)
    }

    fn get_vk() -> Weight {
        Weight::from_parts(5_500_000, 5137).saturating_add(RocksDbWeight::get().reads(1_u64))
    }

    fn validate_vk() -> Weight {
        Weight::from_parts(35_000_000, 0)
    }

    fn compute_statement_hash() -> Weight {
        Weight::from_parts(8_500_000, 0)
    }

    fn register_vk() -> Weight {
        Weight::from_parts(90_000_000, 5137)
            .saturating_add(RocksDbWeight::get().reads(4_u64))
            .saturating_add(RocksDbWeight::get().writes(3_u64))
    }

    fn unregister_vk() -> Weight {
        Weight::from_parts(50_000_000, 5137)
            .saturating_add(RocksDbWeight::get().reads(3_u64))
            .saturating_add(RocksDbWeight::get().writes(3_u64))
    }
}
