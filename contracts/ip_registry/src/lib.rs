#![no_std]
use soroban_sdk::{
    contract, contractimpl, contracttype, symbol_short, Address, BytesN, Bytes, Env, Error, Vec,
};

#[cfg(test)]
mod test;

// ── Error Codes ────────────────────────────────────────────────────────────

#[repr(u32)]
pub enum ContractError {
    IpNotFound = 1,
    ZeroCommitmentHash = 2,
    CommitmentAlreadyRegistered = 3,
    IpAlreadyRevoked = 4,
    UnauthorizedUpgrade = 5,
}

// ── TTL ───────────────────────────────────────────────────────────────────────

/// Minimum ledger TTL bump applied to every persistent storage write.
/// ~1 year at ~5s per ledger: 365 * 24 * 3600 / 5 ≈ 6_307_200 ledgers.
pub const LEDGER_BUMP: u32 = 6_307_200;

// ── Storage Keys ────────────────────────────────────────────────────────────

#[contracttype]
#[derive(Debug, PartialEq)]
pub enum DataKey {
    IpRecord(u64),
    OwnerIps(Address),
    NextId,
    CommitmentOwner(BytesN<32>), // tracks which address holds which commitment hash
    Admin,
}

// ── Types ────────────────────────────────────────────────────────────────────

#[contracttype]
#[derive(Clone)]
pub struct IpRecord {
    pub ip_id: u64,
    pub owner: Address,
    pub commitment_hash: BytesN<32>,
    pub timestamp: u64,
    pub revoked: bool,
}

// ── Contract ─────────────────────────────────────────────────────────────────

#[contract]
pub struct IpRegistry;

#[contractimpl]
impl IpRegistry {
    /// Timestamp a new IP commitment. Returns the assigned IP ID.
    pub fn commit_ip(env: Env, owner: Address, commitment_hash: BytesN<32>) -> u64 {
        owner.require_auth();

        let storage = env.storage();
        
        // Initialize admin on first call if not set
        if !storage.instance().has(&DataKey::Admin) {
            let admin = env.deployer();
            storage.instance().set(&DataKey::Admin, &admin);
        }

        // Reject zero-byte commitment hash (Issue #40)
        if commitment_hash == BytesN::from_array(&env, &[0u8; 32]) {
            env.panic_with_error(Error::from_contract_error(
                ContractError::ZeroCommitmentHash as u32,
            ));
        }

        // Reject duplicate commitment hash globally
        if storage.persistent().has(&DataKey::CommitmentOwner(commitment_hash.clone())) {
            env.panic_with_error(Error::from_contract_error(
                ContractError::CommitmentAlreadyRegistered as u32,
            ));
        }

        // NextId lives in instance storage for efficiency and auto-renewal.
        let id: u64 = storage.instance().get(&DataKey::NextId).unwrap_or(1);

        let record = IpRecord {
            ip_id: id,
            owner: owner.clone(),
            commitment_hash: commitment_hash.clone(),
            timestamp: env.ledger().timestamp(),
            revoked: false,
        };

        // Persist IP record
        storage.persistent().set(&DataKey::IpRecord(id), &record);
        storage.persistent().extend_ttl(&DataKey::IpRecord(id), LEDGER_BUMP, LEDGER_BUMP);

        // Update owner index
        let mut ids: Vec<u64> = storage.persistent().get(&DataKey::OwnerIps(owner.clone())).unwrap_or(Vec::new(&env));
        ids.push_back(id);
        storage.persistent().set(&DataKey::OwnerIps(owner.clone()), &ids);
        storage.persistent().extend_ttl(&DataKey::OwnerIps(owner.clone()), LEDGER_BUMP, LEDGER_BUMP);

        // Track commitment ownership
        storage.persistent().set(&DataKey::CommitmentOwner(commitment_hash.clone()), &owner);
        storage.persistent().extend_ttl(&DataKey::CommitmentOwner(commitment_hash.clone()), LEDGER_BUMP, LEDGER_BUMP);

        // Increment ID
        storage.instance().set(&DataKey::NextId, &(id + 1));

        env.events().publish(
            (symbol_short!("ip_commit"), owner.clone()),
            (id, record.timestamp),
        );

        id
    }

    /// Batch commit multiple IP hashes from the same owner in a single transaction.
    pub fn batch_commit_ip(env: Env, owner: Address, hashes: Vec<BytesN<32>>) -> Vec<u64> {
        owner.require_auth();

        let storage = env.storage();
        
        // Admin init
        if !storage.instance().has(&DataKey::Admin) {
            let admin = env.deployer();
            storage.instance().set(&DataKey::Admin, &admin);
        }

        let mut next_id: u64 = storage.instance().get(&DataKey::NextId).unwrap_or(1);
        let mut result_ids = Vec::new(&env);
        let mut owner_ids: Vec<u64> = storage.persistent().get(&DataKey::OwnerIps(owner.clone())).unwrap_or(Vec::new(&env));

        for hash in hashes.iter() {
            let commitment_hash = hash.clone();

            if commitment_hash == BytesN::from_array(&env, &[0u8; 32]) {
                env.panic_with_error(Error::from_contract_error(ContractError::ZeroCommitmentHash as u32));
            }

            if storage.persistent().has(&DataKey::CommitmentOwner(commitment_hash.clone())) {
                env.panic_with_error(Error::from_contract_error(ContractError::CommitmentAlreadyRegistered as u32));
            }

            let record = IpRecord {
                ip_id: next_id,
                owner: owner.clone(),
                commitment_hash: commitment_hash.clone(),
                timestamp: env.ledger().timestamp(),
                revoked: false,
            };

            storage.persistent().set(&DataKey::IpRecord(next_id), &record);
            storage.persistent().extend_ttl(&DataKey::IpRecord(next_id), LEDGER_BUMP, LEDGER_BUMP);

            storage.persistent().set(&DataKey::CommitmentOwner(commitment_hash.clone()), &owner);
            storage.persistent().extend_ttl(&DataKey::CommitmentOwner(commitment_hash.clone()), LEDGER_BUMP, LEDGER_BUMP);

            owner_ids.push_back(next_id);
            result_ids.push_back(next_id);

            env.events().publish(
                (symbol_short!("ip_commit"), owner.clone()),
                (next_id, record.timestamp),
            );

            next_id += 1;
        }

        // Finalize state updates
        storage.persistent().set(&DataKey::OwnerIps(owner.clone()), &owner_ids);
        storage.persistent().extend_ttl(&DataKey::OwnerIps(owner.clone()), LEDGER_BUMP, LEDGER_BUMP);

        storage.instance().set(&DataKey::NextId, &next_id);

        result_ids
    }

    /// Transfer IP ownership to a new address.
    pub fn transfer_ip(env: Env, ip_id: u64, new_owner: Address) {
        let storage = env.storage();
        let mut record: IpRecord = storage.persistent().get(&DataKey::IpRecord(ip_id)).unwrap_or_else(|| {
            env.panic_with_error(Error::from_contract_error(ContractError::IpNotFound as u32))
        });

        record.owner.require_auth();
        let old_owner = record.owner.clone();

        // Remove from old owner's index
        let mut old_ids: Vec<u64> = storage.persistent().get(&DataKey::OwnerIps(old_owner.clone())).unwrap_or(Vec::new(&env));
        if let Some(pos) = old_ids.iter().position(|x| x == ip_id) {
            old_ids.remove(pos as u32);
        }
        storage.persistent().set(&DataKey::OwnerIps(old_owner.clone()), &old_ids);
        storage.persistent().extend_ttl(&DataKey::OwnerIps(old_owner), LEDGER_BUMP, LEDGER_BUMP);

        // Add to new owner's index
        let mut new_ids: Vec<u64> = storage.persistent().get(&DataKey::OwnerIps(new_owner.clone())).unwrap_or(Vec::new(&env));
        new_ids.push_back(ip_id);
        storage.persistent().set(&DataKey::OwnerIps(new_owner.clone()), &new_ids);
        storage.persistent().extend_ttl(&DataKey::OwnerIps(new_owner.clone()), LEDGER_BUMP, LEDGER_BUMP);

        // Update commitment index
        storage.persistent().set(&DataKey::CommitmentOwner(record.commitment_hash.clone()), &new_owner);
        storage.persistent().extend_ttl(&DataKey::CommitmentOwner(record.commitment_hash.clone()), LEDGER_BUMP, LEDGER_BUMP);

        // Update IP record
        record.owner = new_owner;
        storage.persistent().set(&DataKey::IpRecord(ip_id), &record);
        storage.persistent().extend_ttl(&DataKey::IpRecord(ip_id), LEDGER_BUMP, LEDGER_BUMP);
    }

    /// Revoke an IP record, marking it as invalid.
    pub fn revoke_ip(env: Env, ip_id: u64) {
        let storage = env.storage();
        let mut record: IpRecord = storage.persistent().get(&DataKey::IpRecord(ip_id)).unwrap_or_else(|| {
            env.panic_with_error(Error::from_contract_error(ContractError::IpNotFound as u32))
        });

        record.owner.require_auth();

        if record.revoked {
            env.panic_with_error(Error::from_contract_error(ContractError::IpAlreadyRevoked as u32));
        }

        record.revoked = true;
        storage.persistent().set(&DataKey::IpRecord(ip_id), &record);
        storage.persistent().extend_ttl(&DataKey::IpRecord(ip_id), LEDGER_BUMP, LEDGER_BUMP);
    }

    /// Admin-only contract upgrade.
    pub fn upgrade(env: Env, new_wasm_hash: Bytes) {
        let admin_opt = env.storage().instance().get(&DataKey::Admin);
        if admin_opt.is_none() {
            env.panic_with_error(Error::from_contract_error(ContractError::UnauthorizedUpgrade as u32));
        }
        let admin: Address = admin_opt.unwrap();
        admin.require_auth();
        env.deployer().update_current_contract_wasm(new_wasm_hash);
    }

    /// Retrieve an IP record by ID.
    pub fn get_ip(env: Env, ip_id: u64) -> IpRecord {
        env.storage().persistent().get(&DataKey::IpRecord(ip_id)).unwrap_or_else(|| {
            env.panic_with_error(Error::from_contract_error(ContractError::IpNotFound as u32))
        })
    }

    /// Verify a commitment.
    pub fn verify_commitment(env: Env, ip_id: u64, secret: BytesN<32>, blinding_factor: BytesN<32>) -> bool {
        let record: IpRecord = env.storage().persistent().get(&DataKey::IpRecord(ip_id)).unwrap_or_else(|| {
            env.panic_with_error(Error::from_contract_error(ContractError::IpNotFound as u32))
        });

        let mut preimage = soroban_sdk::Bytes::new(&env);
        preimage.append(&secret.into());
        preimage.append(&blinding_factor.into());
        let computed_hash: BytesN<32> = env.crypto().sha256(&preimage).into();

        record.commitment_hash == computed_hash
    }

    /// List all IP IDs owned by an address.
    pub fn list_ip_by_owner(env: Env, owner: Address) -> Vec<u64> {
        env.storage().persistent().get(&DataKey::OwnerIps(owner)).unwrap_or(Vec::new(&env))
    }

    /// Check if an address owns a specific IP.
    pub fn is_ip_owner(env: Env, ip_id: u64, address: Address) -> bool {
        if let Some(record) = env.storage().persistent().get::<DataKey, IpRecord>(&DataKey::IpRecord(ip_id)) {
            record.owner == address
        } else {
            false
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Env, IntoVal, BytesN};

    #[test]
    #[should_panic]
    fn test_non_owner_cannot_commit() {
        let env = Env::default();
        let contract_id = env.register(IpRegistry, ());
        let client = IpRegistryClient::new(&env, &contract_id);

        let alice = Address::generate(&env);
        let bob = Address::generate(&env);

        let hash = BytesN::from_array(&env, &[0u8; 32]);

        env.mock_auths(&[soroban_sdk::testutils::MockAuth {
            address: &alice,
            invoke: &soroban_sdk::testutils::MockAuthInvoke {
                contract: &contract_id,
                fn_name: "commit_ip",
                args: (bob.clone(), hash.clone()).into_val(&env),
                sub_invokes: &[],
            },
        }]);

        client.commit_ip(&bob, &hash);
    }

    #[test]
    fn test_non_owner_commit_succeeds_with_mock_all_auths() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register(IpRegistry, ());
        let client = IpRegistryClient::new(&env, &contract_id);

        let alice = Address::generate(&env);
        let bob = Address::generate(&env);

        let hash = BytesN::from_array(&env, &[1u8; 32]);

        let ip_id = client.commit_ip(&bob, &hash);

        let record = client.get_ip(&ip_id);
        assert_eq!(record.owner, bob);
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #3)")]
    fn test_duplicate_commitment_hash_rejected() {
        let env = Env::default();
        env.mock_all_auths();

        let contract_id = env.register(IpRegistry, ());
        let client = IpRegistryClient::new(&env, &contract_id);

        let alice = Address::generate(&env);
        let bob = Address::generate(&env);

        // Same commitment hash used twice
        let hash = BytesN::from_array(&env, &[0x42u8; 32]);

        // First commit succeeds
        client.commit_ip(&alice, &hash);

        // Second commit with same hash should panic with CommitmentAlreadyRegistered (code 3)
        client.commit_ip(&bob, &hash);
    }
}
