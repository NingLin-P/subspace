// Copyright (C) 2021 Subspace Labs, Inc.
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

//! Pallet Domains

#![cfg_attr(not(feature = "std"), no_std)]
#![feature(is_sorted)]

#[cfg(test)]
mod tests;

use codec::{Decode, Encode};
use frame_support::ensure;
use frame_support::traits::Get;
use frame_system::offchain::SubmitTransaction;
pub use pallet::*;
use sp_core::H256;
use sp_domains::bundle_election::{verify_system_bundle_solution, verify_vrf_proof};
use sp_domains::fraud_proof::{BundleEquivocationProof, FraudProof, InvalidTransactionProof};
use sp_domains::transaction::InvalidTransactionCode;
use sp_domains::{DomainId, ExecutionReceipt, ProofOfElection, SignedOpaqueBundle};
use sp_runtime::traits::{BlockNumberProvider, One, Saturating, Zero};
use sp_runtime::transaction_validity::TransactionValidityError;
use sp_runtime::RuntimeAppPublic;

#[frame_support::pallet]
mod pallet {
    use frame_support::pallet_prelude::*;
    use frame_support::PalletError;
    use frame_system::pallet_prelude::*;
    use pallet_receipts::Error as ReceiptError;
    use sp_core::H256;
    use sp_domains::fraud_proof::{BundleEquivocationProof, FraudProof, InvalidTransactionProof};
    use sp_domains::transaction::InvalidTransactionCode;
    use sp_domains::{DomainId, ExecutorPublicKey, SignedOpaqueBundle};
    use sp_runtime::traits::{One, Zero};
    use sp_std::fmt::Debug;

    #[pallet::config]
    pub trait Config: frame_system::Config + pallet_receipts::Config {
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;

        /// Same with `pallet_subspace::Config::ConfirmationDepthK`.
        type ConfirmationDepthK: Get<Self::BlockNumber>;
    }

    #[pallet::pallet]
    #[pallet::generate_store(pub(super) trait Store)]
    #[pallet::without_storage_info]
    pub struct Pallet<T>(_);

    #[derive(TypeInfo, Encode, Decode, PalletError, Debug)]
    pub enum BundleError {
        /// The signer of bundle is unexpected.
        UnexpectedSigner,
        /// Invalid bundle signature.
        BadSignature,
        /// Invalid vrf proof.
        BadVrfProof,
        /// State of a system domain block is missing.
        StateRootNotFound,
        /// Invalid state root in the proof of election.
        BadStateRoot,
        /// The type of state root is not H256.
        StateRootNotH256,
        /// Invalid system bundle election solution.
        BadElectionSolution,
        /// An invalid execution receipt found in the bundle.
        Receipt(ExecutionReceiptError),
    }

    impl<T> From<BundleError> for Error<T> {
        fn from(e: BundleError) -> Self {
            Self::Bundle(e)
        }
    }

    #[derive(TypeInfo, Encode, Decode, PalletError, Debug)]
    pub enum ExecutionReceiptError {
        /// The parent execution receipt is unknown.
        MissingParent,
        /// The execution receipt has been pruned.
        Pruned,
        /// The execution receipt points to a block unknown to the history.
        UnknownBlock,
        /// The execution receipt is too far in the future.
        TooFarInFuture,
        /// Receipts are not in ascending order.
        Unsorted,
        /// Receipts in a bundle can not be empty.
        Empty,
    }

    impl From<ReceiptError> for ExecutionReceiptError {
        fn from(error: ReceiptError) -> Self {
            match error {
                ReceiptError::MissingParent => Self::MissingParent,
            }
        }
    }

    #[derive(TypeInfo, Encode, Decode, PalletError, Debug)]
    pub enum FraudProofError {
        /// Fraud proof is expired as the execution receipt has been pruned.
        ExecutionReceiptPruned,
        /// Trying to prove an receipt from the future.
        ExecutionReceiptInFuture,
        /// Unexpected hash type.
        WrongHashType,
        /// The execution receipt points to a block unknown to the history.
        UnknownBlock,
    }

    impl<T> From<FraudProofError> for Error<T> {
        fn from(e: FraudProofError) -> Self {
            Self::FraudProof(e)
        }
    }

    #[pallet::error]
    pub enum Error<T> {
        /// Invalid bundle.
        Bundle(BundleError),
        /// Invalid fraud proof.
        FraudProof(FraudProofError),
    }

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        // TODO: We do not rely on this event to collect the receipts included in a block, perhaps can be removed later.
        /// A new system domain receipt was backed.
        NewSystemDomainReceipt {
            domain_id: DomainId,
            primary_number: T::BlockNumber,
            primary_hash: T::Hash,
        },
        /// A domain bundle was included.
        BundleStored {
            domain_id: DomainId,
            bundle_hash: H256,
            bundle_author: ExecutorPublicKey,
        },
        /// A fraud proof was processed.
        FraudProofProcessed,
        /// A bundle equivocation proof was processed.
        BundleEquivocationProofProcessed,
        /// An invalid transaction proof was processed.
        InvalidTransactionProofProcessed,
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        // TODO: proper weight
        #[pallet::weight((10_000, Pays::No))]
        pub fn submit_bundle(
            origin: OriginFor<T>,
            signed_opaque_bundle: SignedOpaqueBundle<T::BlockNumber, T::Hash, T::DomainHash>,
        ) -> DispatchResult {
            ensure_none(origin)?;

            log::trace!(target: "runtime::domains", "Processing bundle: {signed_opaque_bundle:?}");

            let domain_id = signed_opaque_bundle.domain_id();

            // Only process the system domain receipts.
            if domain_id.is_system() {
                pallet_receipts::Pallet::<T>::track_receipts(
                    domain_id,
                    signed_opaque_bundle.bundle.receipts.as_slice(),
                )
                .map_err(|err| Error::<T>::Bundle(BundleError::Receipt(err.into())))?;
            }

            Self::deposit_event(Event::BundleStored {
                domain_id,
                bundle_hash: signed_opaque_bundle.hash(),
                bundle_author: signed_opaque_bundle
                    .bundle_solution
                    .proof_of_election()
                    .executor_public_key
                    .clone(),
            });

            Ok(())
        }

        // TODO: proper weight
        #[pallet::weight((10_000, Pays::No))]
        pub fn submit_fraud_proof(origin: OriginFor<T>, fraud_proof: FraudProof) -> DispatchResult {
            ensure_none(origin)?;

            log::trace!(target: "runtime::domains", "Processing fraud proof: {fraud_proof:?}");

            // FIXME: currently core domain fraud proof will also submit into primary chain and
            // handled by this extrinsic incorrectly
            pallet_receipts::Pallet::<T>::process_fraud_proof(DomainId::SYSTEM, fraud_proof);

            Self::deposit_event(Event::FraudProofProcessed);

            Ok(())
        }

        // TODO: proper weight
        #[pallet::weight((10_000, Pays::No))]
        pub fn submit_bundle_equivocation_proof(
            origin: OriginFor<T>,
            bundle_equivocation_proof: BundleEquivocationProof<T::Hash>,
        ) -> DispatchResult {
            ensure_none(origin)?;

            log::trace!(target: "runtime::domains", "Processing bundle equivocation proof: {bundle_equivocation_proof:?}");

            // TODO: slash the executor accordingly.

            Self::deposit_event(Event::BundleEquivocationProofProcessed);

            Ok(())
        }

        // TODO: proper weight
        #[pallet::weight((10_000, Pays::No))]
        pub fn submit_invalid_transaction_proof(
            origin: OriginFor<T>,
            invalid_transaction_proof: InvalidTransactionProof,
        ) -> DispatchResult {
            ensure_none(origin)?;

            log::trace!(target: "runtime::domains", "Processing invalid transaction proof: {invalid_transaction_proof:?}");

            // TODO: slash the executor accordingly.

            Self::deposit_event(Event::InvalidTransactionProofProcessed);

            Ok(())
        }
    }

    #[pallet::hooks]
    impl<T: Config> Hooks<T::BlockNumber> for Pallet<T> {
        fn on_initialize(block_number: T::BlockNumber) -> Weight {
            let parent_number = block_number - One::one();
            let parent_hash = frame_system::Pallet::<T>::block_hash(parent_number);

            pallet_receipts::BlockHash::<T>::insert(DomainId::SYSTEM, parent_number, parent_hash);

            // The genesis block hash is not finalized until the genesis block building is done,
            // hence the genesis receipt is initialized after the genesis building.
            if parent_number.is_zero() {
                pallet_receipts::Pallet::<T>::initialize_genesis_receipt(
                    DomainId::SYSTEM,
                    parent_hash,
                );
            }

            T::DbWeight::get().writes(1)
        }
    }

    /// Constructs a `TransactionValidity` with pallet-executor specific defaults.
    fn unsigned_validity(prefix: &'static str, tag: impl Encode) -> TransactionValidity {
        ValidTransaction::with_tag_prefix(prefix)
            .priority(TransactionPriority::MAX)
            .and_provides(tag)
            .longevity(TransactionLongevity::MAX)
            // We need this extrinsic to be propagated to the farmer nodes.
            .propagate(true)
            .build()
    }

    #[pallet::validate_unsigned]
    impl<T: Config> ValidateUnsigned for Pallet<T> {
        type Call = Call<T>;
        fn pre_dispatch(call: &Self::Call) -> Result<(), TransactionValidityError> {
            match call {
                Call::submit_bundle {
                    signed_opaque_bundle,
                } => Self::pre_dispatch_submit_bundle(signed_opaque_bundle),
                Call::submit_fraud_proof { .. } => Ok(()),
                Call::submit_bundle_equivocation_proof { .. } => Ok(()),
                Call::submit_invalid_transaction_proof { .. } => Ok(()),
                _ => Err(InvalidTransaction::Call.into()),
            }
        }

        fn validate_unsigned(_source: TransactionSource, call: &Self::Call) -> TransactionValidity {
            match call {
                Call::submit_bundle {
                    signed_opaque_bundle,
                } => {
                    if let Err(e) = Self::validate_bundle(signed_opaque_bundle) {
                        log::error!(
                            target: "runtime::domains",
                            "Bad bundle: {signed_opaque_bundle:?}, error: {e:?}",
                        );
                        if let BundleError::Receipt(_) = e {
                            return InvalidTransactionCode::ExecutionReceipt.into();
                        } else {
                            return InvalidTransactionCode::Bundle.into();
                        }
                    }

                    ValidTransaction::with_tag_prefix("SubspaceSubmitBundle")
                        .priority(TransactionPriority::MAX)
                        .longevity(T::ConfirmationDepthK::get().try_into().unwrap_or_else(|_| {
                            panic!("Block number always fits in TransactionLongevity; qed")
                        }))
                        .and_provides(signed_opaque_bundle.hash())
                        .propagate(true)
                        .build()
                }
                Call::submit_fraud_proof { fraud_proof } => {
                    if let Err(e) = Self::validate_fraud_proof(fraud_proof) {
                        log::error!(
                            target: "runtime::domains",
                            "Bad fraud proof: {fraud_proof:?}, error: {e:?}",
                        );
                        return InvalidTransactionCode::FraudProof.into();
                    }

                    // TODO: proper tag value.
                    unsigned_validity("SubspaceSubmitFraudProof", fraud_proof)
                }
                Call::submit_bundle_equivocation_proof {
                    bundle_equivocation_proof,
                } => {
                    if let Err(e) =
                        Self::validate_bundle_equivocation_proof(bundle_equivocation_proof)
                    {
                        log::error!(
                            target: "runtime::domains",
                            "Bad bundle equivocation proof: {bundle_equivocation_proof:?}, error: {e:?}",
                        );
                        return InvalidTransactionCode::BundleEquivicationProof.into();
                    }

                    unsigned_validity(
                        "SubspaceSubmitBundleEquivocationProof",
                        bundle_equivocation_proof.hash(),
                    )
                }
                Call::submit_invalid_transaction_proof {
                    invalid_transaction_proof,
                } => {
                    if let Err(e) =
                        Self::validate_invalid_transaction_proof(invalid_transaction_proof)
                    {
                        log::error!(
                            target: "runtime::domains",
                            "Bad invalid transaction proof: {invalid_transaction_proof:?}, error: {e:?}",
                        );
                        return InvalidTransactionCode::TrasactionProof.into();
                    }

                    unsigned_validity(
                        "SubspaceSubmitInvalidTransactionProof",
                        invalid_transaction_proof,
                    )
                }

                _ => InvalidTransaction::Call.into(),
            }
        }
    }
}

impl<T: Config> Pallet<T> {
    /// Returns the block number of the latest receipt.
    pub fn head_receipt_number() -> T::BlockNumber {
        pallet_receipts::Pallet::<T>::head_receipt_number(DomainId::SYSTEM)
    }

    /// Returns the block number of the oldest receipt still being tracked in the state.
    pub fn oldest_receipt_number() -> T::BlockNumber {
        pallet_receipts::Pallet::<T>::oldest_receipt_number(DomainId::SYSTEM)
    }

    fn pre_dispatch_submit_bundle(
        signed_opaque_bundle: &SignedOpaqueBundle<T::BlockNumber, T::Hash, T::DomainHash>,
    ) -> Result<(), TransactionValidityError> {
        let execution_receipts = &signed_opaque_bundle.bundle.receipts;

        if !execution_receipts
            .iter()
            .map(|r| r.primary_number)
            .is_sorted()
        {
            return Err(TransactionValidityError::Invalid(
                InvalidTransactionCode::ExecutionReceipt.into(),
            ));
        }

        if signed_opaque_bundle.domain_id().is_system() {
            let mut best_number = Self::head_receipt_number();

            for receipt in execution_receipts {
                // Non-best receipt
                if receipt.primary_number <= best_number {
                    if !pallet_receipts::Pallet::<T>::point_to_valid_primary_block(
                        DomainId::SYSTEM,
                        receipt,
                    ) {
                        return Err(TransactionValidityError::Invalid(
                            InvalidTransactionCode::ExecutionReceipt.into(),
                        ));
                    }
                    continue;
                // New nest receipt.
                } else if receipt.primary_number == best_number + One::one() {
                    if !pallet_receipts::Pallet::<T>::point_to_valid_primary_block(
                        DomainId::SYSTEM,
                        receipt,
                    ) {
                        return Err(TransactionValidityError::Invalid(
                            InvalidTransactionCode::ExecutionReceipt.into(),
                        ));
                    }
                    best_number += One::one();
                // Missing receipt.
                } else {
                    return Err(TransactionValidityError::Invalid(
                        InvalidTransactionCode::ExecutionReceipt.into(),
                    ));
                }
            }
        } else {
            for receipt in execution_receipts {
                if !pallet_receipts::Pallet::<T>::point_to_valid_primary_block(
                    DomainId::SYSTEM,
                    receipt,
                ) {
                    return Err(TransactionValidityError::Invalid(
                        InvalidTransactionCode::ExecutionReceipt.into(),
                    ));
                }
            }
        }

        Ok(())
    }

    fn validate_system_bundle_solution(
        receipts: &[ExecutionReceipt<T::BlockNumber, T::Hash, T::DomainHash>],
        proof_of_election: &ProofOfElection<T::DomainHash>,
    ) -> Result<(), BundleError> {
        let ProofOfElection {
            state_root,
            block_number,
            block_hash,
            ..
        } = proof_of_election;

        let block_number = T::BlockNumber::from(*block_number);

        let new_best_receipt_number = receipts
            .iter()
            .map(|receipt| receipt.primary_number)
            .max()
            .unwrap_or_default()
            .max(Self::head_receipt_number());

        let state_root_verifiable = block_number <= new_best_receipt_number;

        if !block_number.is_zero() && state_root_verifiable {
            let maybe_state_root = receipts.iter().find_map(|receipt| {
                receipt.trace.last().and_then(|state_root| {
                    if (receipt.primary_number, receipt.domain_hash) == (block_number, *block_hash)
                    {
                        Some(*state_root)
                    } else {
                        None
                    }
                })
            });

            let expected_state_root = match maybe_state_root {
                Some(v) => v,
                None => pallet_receipts::Pallet::<T>::state_root((
                    DomainId::SYSTEM,
                    block_number,
                    block_hash,
                ))
                .ok_or(BundleError::StateRootNotFound)?,
            };

            if expected_state_root != *state_root {
                return Err(BundleError::BadStateRoot);
            }
        }

        let state_root = H256::decode(&mut state_root.encode().as_slice())
            .map_err(|_| BundleError::StateRootNotH256)?;

        verify_system_bundle_solution(proof_of_election, state_root)
            .map_err(|_| BundleError::BadElectionSolution)?;

        Ok(())
    }

    /// Common validation of receipts in all kinds of domain bundle.
    fn validate_execution_receipts(
        execution_receipts: &[ExecutionReceipt<T::BlockNumber, T::Hash, T::DomainHash>],
    ) -> Result<(), ExecutionReceiptError> {
        let current_block_number = frame_system::Pallet::<T>::current_block_number();

        // Genesis block receipt is initialized on primary chain, the first block has no receipts,
        // but any block after the first one requires at least one receipt.
        if current_block_number > One::one() && execution_receipts.is_empty() {
            return Err(ExecutionReceiptError::Empty);
        }

        if !execution_receipts
            .iter()
            .map(|r| r.primary_number)
            .is_sorted()
        {
            return Err(ExecutionReceiptError::Unsorted);
        }

        for execution_receipt in execution_receipts {
            // Due to `initialize_block` is skipped while calling the runtime api, the block
            // hash mapping for last block is unknown to the transaction pool, but this info
            // is already available in System.
            let point_to_parent_block = execution_receipt.primary_number
                == current_block_number - One::one()
                && execution_receipt.primary_hash == frame_system::Pallet::<T>::parent_hash();

            if !point_to_parent_block
                && !pallet_receipts::Pallet::<T>::point_to_valid_primary_block(
                    DomainId::SYSTEM,
                    execution_receipt,
                )
            {
                return Err(ExecutionReceiptError::UnknownBlock);
            }
        }

        Ok(())
    }

    fn validate_bundle(
        SignedOpaqueBundle {
            bundle,
            bundle_solution,
            signature,
        }: &SignedOpaqueBundle<T::BlockNumber, T::Hash, T::DomainHash>,
    ) -> Result<(), BundleError> {
        let proof_of_election = bundle_solution.proof_of_election();

        if !proof_of_election
            .executor_public_key
            .verify(&bundle.hash(), signature)
        {
            return Err(BundleError::BadSignature);
        }

        verify_vrf_proof(
            &proof_of_election.executor_public_key,
            &proof_of_election.vrf_output,
            &proof_of_election.vrf_proof,
            &proof_of_election.global_challenge,
        )
        .map_err(|_| BundleError::BadVrfProof)?;

        Self::validate_execution_receipts(&bundle.receipts).map_err(BundleError::Receipt)?;

        if proof_of_election.domain_id.is_system() {
            Self::validate_system_bundle_solution(&bundle.receipts, proof_of_election)?;

            let current_block_number = frame_system::Pallet::<T>::current_block_number();

            let best_number = Self::head_receipt_number();
            let max_allowed = best_number + T::MaximumReceiptDrift::get();

            for execution_receipt in &bundle.receipts {
                let primary_number = execution_receipt.primary_number;

                // Ensure the receipt is not too new.
                if primary_number == current_block_number || primary_number > max_allowed {
                    return Err(BundleError::Receipt(ExecutionReceiptError::TooFarInFuture));
                }
            }
        }

        Ok(())
    }

    fn validate_fraud_proof(fraud_proof: &FraudProof) -> Result<(), FraudProofError> {
        let best_number = Self::head_receipt_number();
        let to_prove: T::BlockNumber = (fraud_proof.parent_number + 1u32).into();
        ensure!(
            to_prove > best_number.saturating_sub(T::ReceiptsPruningDepth::get()),
            FraudProofError::ExecutionReceiptPruned
        );

        ensure!(
            to_prove <= best_number,
            FraudProofError::ExecutionReceiptInFuture
        );

        let parent_hash = T::Hash::decode(&mut fraud_proof.parent_hash.encode().as_slice())
            .map_err(|_| FraudProofError::WrongHashType)?;
        let parent_number: T::BlockNumber = fraud_proof.parent_number.into();
        ensure!(
            pallet_receipts::Pallet::<T>::primary_hash(DomainId::SYSTEM, parent_number)
                == parent_hash,
            FraudProofError::UnknownBlock
        );

        // TODO: prevent the spamming of fraud proof transaction.

        Ok(())
    }

    // TODO: Checks if the bundle equivocation proof is valid.
    fn validate_bundle_equivocation_proof(
        _bundle_equivocation_proof: &BundleEquivocationProof<T::Hash>,
    ) -> Result<(), Error<T>> {
        Ok(())
    }

    // TODO: Checks if the invalid transaction proof is valid.
    fn validate_invalid_transaction_proof(
        _invalid_transaction_proof: &InvalidTransactionProof,
    ) -> Result<(), Error<T>> {
        Ok(())
    }
}

impl<T> Pallet<T>
where
    T: Config + frame_system::offchain::SendTransactionTypes<Call<T>>,
{
    /// Submits an unsigned extrinsic [`Call::submit_bundle`].
    pub fn submit_bundle_unsigned(
        signed_opaque_bundle: SignedOpaqueBundle<T::BlockNumber, T::Hash, T::DomainHash>,
    ) {
        let call = Call::submit_bundle {
            signed_opaque_bundle,
        };

        match SubmitTransaction::<T, Call<T>>::submit_unsigned_transaction(call.into()) {
            Ok(()) => {
                log::info!(target: "runtime::domains", "Submitted bundle");
            }
            Err(()) => {
                log::error!(target: "runtime::domains", "Error submitting bundle");
            }
        }
    }

    /// Submits an unsigned extrinsic [`Call::submit_fraud_proof`].
    pub fn submit_fraud_proof_unsigned(fraud_proof: FraudProof) {
        let call = Call::submit_fraud_proof { fraud_proof };

        match SubmitTransaction::<T, Call<T>>::submit_unsigned_transaction(call.into()) {
            Ok(()) => {
                log::info!(target: "runtime::domains", "Submitted fraud proof");
            }
            Err(()) => {
                log::error!(target: "runtime::domains", "Error submitting fraud proof");
            }
        }
    }

    /// Submits an unsigned extrinsic [`Call::submit_bundle_equivocation_proof`].
    pub fn submit_bundle_equivocation_proof_unsigned(
        bundle_equivocation_proof: BundleEquivocationProof<T::Hash>,
    ) {
        let call = Call::submit_bundle_equivocation_proof {
            bundle_equivocation_proof,
        };

        match SubmitTransaction::<T, Call<T>>::submit_unsigned_transaction(call.into()) {
            Ok(()) => {
                log::info!(target: "runtime::domains", "Submitted bundle equivocation proof");
            }
            Err(()) => {
                log::error!(target: "runtime::domains", "Error submitting bundle equivocation proof");
            }
        }
    }

    /// Submits an unsigned extrinsic [`Call::submit_invalid_transaction_proof`].
    pub fn submit_invalid_transaction_proof_unsigned(
        invalid_transaction_proof: InvalidTransactionProof,
    ) {
        let call = Call::submit_invalid_transaction_proof {
            invalid_transaction_proof,
        };

        match SubmitTransaction::<T, Call<T>>::submit_unsigned_transaction(call.into()) {
            Ok(()) => {
                log::info!(target: "runtime::domains", "Submitted invalid transaction proof")
            }
            Err(()) => {
                log::error!(target: "runtime::domains", "Error submitting invalid transaction proof");
            }
        }
    }
}
