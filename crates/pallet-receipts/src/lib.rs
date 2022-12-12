// Copyright (C) 2022 Subspace Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! # Pallet Receipt track all the execution receipt related onchain state for both primary
//! chain (tracking the system domain execution receipt) and system domain (tracking the core
//! domains execution receipt)

#![cfg_attr(not(feature = "std"), no_std)]

use frame_support::traits::Get;
pub use pallet::*;
use sp_domains::fraud_proof::FraudProof;
use sp_domains::state_root_tracker::CoreDomainTracker;
use sp_domains::{DomainId, ExecutionReceipt};
use sp_runtime::traits::{CheckedSub, One, Saturating, Zero};
use sp_std::vec::Vec;

#[frame_support::pallet]
mod pallet {
    use frame_support::pallet_prelude::{StorageMap, StorageNMap, *};
    use sp_core::H256;
    use sp_domains::state_root_tracker::CoreDomainTracker;
    use sp_domains::{DomainId, ExecutionReceipt};
    use sp_runtime::traits::{CheckEqual, MaybeDisplay, MaybeMallocSizeOf, SimpleBitOps};
    use sp_std::fmt::Debug;

    #[pallet::config]
    pub trait Config: frame_system::Config {
        /// Domain block hash type.
        type DomainHash: Parameter
            + Member
            + MaybeSerializeDeserialize
            + Debug
            + MaybeDisplay
            + SimpleBitOps
            + Ord
            + Default
            + Copy
            + CheckEqual
            + sp_std::hash::Hash
            + AsRef<[u8]>
            + AsMut<[u8]>
            + MaybeMallocSizeOf
            + MaxEncodedLen;

        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;

        /// Maximum execution receipt drift.
        ///
        /// If the primary number of an execution receipt plus the maximum drift is bigger than the
        /// best execution chain number, this receipt will be rejected as being too far in the
        /// future.
        #[pallet::constant]
        type MaximumReceiptDrift: Get<Self::BlockNumber>;

        /// Number of execution receipts kept in the state.
        #[pallet::constant]
        type ReceiptsPruningDepth: Get<Self::BlockNumber>;

        /// Core domain tracker that tracks the state roots of the core domains.
        type CoreDomainTracker: CoreDomainTracker<Self::BlockNumber, Self::DomainHash>;
    }

    #[pallet::pallet]
    #[pallet::generate_store(pub(super) trait Store)]
    #[pallet::without_storage_info]
    pub struct Pallet<T>(_);

    /// Map of primary block number to primary block hash for tracking bounded receipts per domain.
    ///
    /// NOTE: This storage item is extended on adding a new non-system receipt since each receipt
    /// is validated to point to a valid primary block on the primary chain.
    ///
    /// The oldest block hash will be pruned once the oldest receipt is pruned. However, if a
    /// core domain stalls, i.e., no receipts are included in the system domain for a long time,
    /// the corresponding entry will grow indefinitely.
    #[pallet::storage]
    #[pallet::getter(fn primary_hash)]
    pub type BlockHash<T: Config> = StorageDoubleMap<
        _,
        Twox64Concat,
        DomainId,
        Twox64Concat,
        T::BlockNumber,
        T::Hash,
        ValueQuery,
    >;

    /// A pair of (block_hash, block_number) of the latest execution receipt of a domain.
    #[pallet::storage]
    pub(super) type ReceiptHead<T: Config> =
        StorageMap<_, Twox64Concat, DomainId, (T::Hash, T::BlockNumber), ValueQuery>;

    /// Block number of the oldest receipt stored in the state.
    #[pallet::storage]
    pub(super) type OldestReceiptNumber<T: Config> =
        StorageMap<_, Twox64Concat, DomainId, T::BlockNumber, ValueQuery>;

    /// Mapping from the receipt hash to the corresponding verified execution receipt.
    ///
    /// The capacity of receipts stored in the state is [`Config::ReceiptsPruningDepth`], the older
    /// ones will be pruned once the size of receipts exceeds this number.
    #[pallet::storage]
    #[pallet::getter(fn receipts)]
    pub(super) type Receipts<T: Config> = StorageDoubleMap<
        _,
        Twox64Concat,
        DomainId,
        Twox64Concat,
        H256,
        ExecutionReceipt<T::BlockNumber, T::Hash, T::DomainHash>,
        OptionQuery,
    >;

    /// Mapping for tracking the receipt votes.
    ///
    /// (primary_block_hash, receipt_hash, receipt_count) -> vote_count
    #[pallet::storage]
    pub type ReceiptVotes<T: Config> = StorageNMap<
        _,
        (
            NMapKey<Twox64Concat, DomainId>,
            NMapKey<Twox64Concat, T::Hash>,
            NMapKey<Twox64Concat, H256>,
        ),
        u32,
        ValueQuery,
    >;

    /// Mapping for tracking the secondary state roots.
    ///
    /// (core_domain_id, core_block_number, core_block_hash, core_state_root) -> state_root
    #[pallet::storage]
    #[pallet::getter(fn state_root)]
    pub(super) type StateRoots<T: Config> = StorageNMap<
        _,
        (
            NMapKey<Twox64Concat, DomainId>,
            NMapKey<Twox64Concat, T::BlockNumber>,
            NMapKey<Twox64Concat, T::DomainHash>,
        ),
        T::DomainHash,
        OptionQuery,
    >;

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// A new domain receipt have processed
        NewDomainReceipt {
            domain_id: DomainId,
            primary_number: T::BlockNumber,
            primary_hash: T::Hash,
        },
        /// A fraud proof was processed.
        FraudProofProcessed {
            domain_id: DomainId,
            new_best_number: T::BlockNumber,
            new_best_hash: T::Hash,
        },
    }
}

pub enum Error {
    /// The parent execution receipt is missing.
    MissingParent,
}

impl<T: Config> Pallet<T> {
    /// Returns the block number of the latest receipt.
    pub fn head_receipt_number(domain_id: DomainId) -> T::BlockNumber {
        let (_, best_number) = <ReceiptHead<T>>::get(domain_id);
        best_number
    }

    /// Returns the block number of the oldest receipt still being tracked in the state.
    pub fn oldest_receipt_number(domain_id: DomainId) -> T::BlockNumber {
        Self::finalized_receipt_number(domain_id) + One::one()
    }

    /// Returns the block number of latest _finalized_ receipt.
    pub fn finalized_receipt_number(domain_id: DomainId) -> T::BlockNumber {
        let (_, best_number) = <ReceiptHead<T>>::get(domain_id);
        best_number.saturating_sub(T::ReceiptsPruningDepth::get())
    }

    pub fn point_to_valid_primary_block(
        domain_id: DomainId,
        receipt: &ExecutionReceipt<T::BlockNumber, T::Hash, T::DomainHash>,
    ) -> bool {
        Self::primary_hash(domain_id, receipt.primary_number) == receipt.primary_hash
    }

    /// Initialize the genesis execution receipt
    pub fn initialize_genesis_receipt(domain_id: DomainId, genesis_hash: T::Hash) {
        let genesis_receipt = ExecutionReceipt {
            primary_number: Zero::zero(),
            primary_hash: genesis_hash,
            domain_hash: T::DomainHash::default(),
            trace: Vec::new(),
            trace_root: Default::default(),
        };
        Self::apply_new_best_receipt(domain_id, &genesis_receipt);
        // Explicitly initialize the oldest receipt number even not necessary as ValueQuery is used.
        <OldestReceiptNumber<T>>::insert::<_, T::BlockNumber>(domain_id, Zero::zero());
    }

    /// Track the execution receipts for the domain
    pub fn track_receipts(
        domain_id: DomainId,
        receipts: &[ExecutionReceipt<T::BlockNumber, T::Hash, T::DomainHash>],
    ) -> Result<(), Error> {
        let oldest_receipt_number = <OldestReceiptNumber<T>>::get(domain_id);
        let (_, mut best_number) = <ReceiptHead<T>>::get(domain_id);

        for receipt in receipts {
            // Ignore the receipt if it has already been pruned.
            if receipt.primary_number < oldest_receipt_number {
                continue;
            }

            if receipt.primary_number <= best_number {
                // Either increase the vote for a known receipt or add a fork receipt at this height.
                Self::apply_non_new_best_receipt(domain_id, receipt);
            } else if receipt.primary_number == best_number + One::one() {
                Self::apply_new_best_receipt(domain_id, receipt);
                Self::remove_expired_receipts(domain_id, receipt.primary_number);
                best_number += One::one();
            } else {
                // Reject the entire Bundle due to the missing receipt(s) between [best_number, .., receipt.primary_number].
                return Err(Error::MissingParent);
            }
        }
        Ok(())
    }

    /// Submit fraud proof that targetted a given domain
    pub fn process_fraud_proof(domain_id: DomainId, fraud_proof: FraudProof) {
        // Revert the execution chain.
        let (_, mut to_remove) = <ReceiptHead<T>>::get(domain_id);

        let new_best_number: T::BlockNumber = fraud_proof.parent_number.into();
        let new_best_hash = BlockHash::<T>::get(domain_id, new_best_number);

        <ReceiptHead<T>>::insert(domain_id, (new_best_hash, new_best_number));

        while to_remove > new_best_number {
            let block_hash = BlockHash::<T>::get(domain_id, to_remove);
            for (receipt_hash, _) in <ReceiptVotes<T>>::drain_prefix((domain_id, block_hash)) {
                <Receipts<T>>::remove(domain_id, receipt_hash);
            }
            to_remove -= One::one();
        }
        // TODO: slash the executor accordingly.
        Self::deposit_event(Event::FraudProofProcessed {
            domain_id,
            new_best_number,
            new_best_hash,
        });
    }
}

impl<T: Config> Pallet<T> {
    /// Remove the expired receipts once the receipts cache is full.
    fn remove_expired_receipts(domain_id: DomainId, primary_number: T::BlockNumber) {
        if let Some(to_prune) = primary_number.checked_sub(&T::ReceiptsPruningDepth::get()) {
            BlockHash::<T>::mutate_exists(domain_id, to_prune, |maybe_block_hash| {
                if let Some(block_hash) = maybe_block_hash.take() {
                    for (receipt_hash, _) in
                        <ReceiptVotes<T>>::drain_prefix((domain_id, block_hash))
                    {
                        <Receipts<T>>::remove(domain_id, receipt_hash);
                    }
                }
            });
            <OldestReceiptNumber<T>>::insert(domain_id, to_prune + One::one());
            let _ = <StateRoots<T>>::clear_prefix((domain_id, to_prune), u32::MAX, None);
        }
    }

    fn apply_new_best_receipt(
        domain_id: DomainId,
        execution_receipt: &ExecutionReceipt<T::BlockNumber, T::Hash, T::DomainHash>,
    ) {
        let primary_hash = execution_receipt.primary_hash;
        let primary_number = execution_receipt.primary_number;
        let receipt_hash = execution_receipt.hash();

        // (primary_number, primary_hash) has been verified on the primary chain, thus it
        // can be used directly.
        if domain_id.is_core() {
            <BlockHash<T>>::insert(domain_id, primary_number, primary_hash);
        }

        // Apply the new best receipt.
        <Receipts<T>>::insert(domain_id, receipt_hash, execution_receipt);
        <ReceiptHead<T>>::insert(domain_id, (primary_hash, primary_number));
        <ReceiptVotes<T>>::mutate((domain_id, primary_hash, receipt_hash), |count| {
            *count += 1;
        });

        if !primary_number.is_zero() {
            let state_root = execution_receipt
                .trace
                .last()
                .expect("There are at least 2 elements in trace after the genesis block; qed");

            <StateRoots<T>>::insert(
                (domain_id, primary_number, execution_receipt.domain_hash),
                state_root,
            );

            if domain_id.is_core() {
                T::CoreDomainTracker::add_core_domain_state_root(
                    domain_id,
                    primary_number,
                    *state_root,
                );
            }
        }

        Self::deposit_event(Event::NewDomainReceipt {
            domain_id,
            primary_number,
            primary_hash,
        });
    }

    fn apply_non_new_best_receipt(
        domain_id: DomainId,
        execution_receipt: &ExecutionReceipt<T::BlockNumber, T::Hash, T::DomainHash>,
    ) {
        let primary_hash = execution_receipt.primary_hash;
        let primary_number = execution_receipt.primary_number;
        let receipt_hash = execution_receipt.hash();

        // Track the fork receipt if it's not seen before.
        if !<Receipts<T>>::contains_key(domain_id, receipt_hash) {
            <Receipts<T>>::insert(domain_id, receipt_hash, execution_receipt);
            if !primary_number.is_zero() {
                let state_root = execution_receipt
                    .trace
                    .last()
                    .expect("There are at least 2 elements in trace after the genesis block; qed");

                <StateRoots<T>>::insert(
                    (domain_id, primary_number, execution_receipt.domain_hash),
                    state_root,
                );
            }
            Self::deposit_event(Event::NewDomainReceipt {
                domain_id,
                primary_number,
                primary_hash,
            });
        }
        <ReceiptVotes<T>>::mutate((domain_id, primary_hash, receipt_hash), |count| {
            *count += 1;
        });
    }
}
