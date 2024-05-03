#[cfg(not(feature = "std"))]
extern crate alloc;

use crate::fraud_proof::{
    BundleEquivocationProofV2, InvalidBundlesFraudProof, InvalidBundlesProofData,
    InvalidBundlesProofV2, InvalidExtrinsicsRootProof, InvalidExtrinsicsRootProofV2,
    InvalidStateTransitionProofV2, InvalidTransfersProof, ValidBundleProofV2, VerificationError,
};
use crate::fraud_proof_runtime_interface::{
    get_fraud_proof_verification_info, get_fraud_proof_verification_info_v2,
};
use crate::storage_proof::{self, *};
use crate::{
    fraud_proof_runtime_interface, DomainChainAllowlistUpdateExtrinsic, DomainInherentExtrinsic,
    DomainStorageKeyRequest, FraudProofVerificationInfoRequest,
    FraudProofVerificationInfoRequestV2, FraudProofVerificationInfoResponse,
    FraudProofVerificationInfoResponseV2, SetCodeExtrinsic, StatelessDomainRuntimeCall,
    StorageKeyRequest,
};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use codec::{Decode, Encode};
use domain_runtime_primitives::BlockNumber;
use hash_db::Hasher;
use sp_core::storage::StorageKey;
use sp_core::H256;
use sp_domains::bundle_producer_election::{check_proof_of_election, ProofOfElectionError};
use sp_domains::extrinsics::{deduplicate_and_shuffle_extrinsics, extrinsics_shuffling_seed};
use sp_domains::proof_provider_and_verifier::StorageProofVerifier;
use sp_domains::valued_trie::valued_ordered_trie_root;
use sp_domains::{
    BlockFees, BundleValidity, DomainId, ExecutionReceipt, ExtrinsicDigest,
    FraudProofStorageKeyProvider as StorageKeyProvider, HeaderHashFor, HeaderHashingFor,
    HeaderNumberFor, InboxedBundle, InvalidBundleType, OperatorPublicKey, RuntimeId,
    SealedBundleHeader, Transfers, INITIAL_DOMAIN_TX_RANGE,
};
use sp_runtime::generic::Digest;
use sp_runtime::traits::{
    Block as BlockT, Hash, Header as HeaderT, NumberFor, UniqueSaturatedInto,
};
use sp_runtime::{OpaqueExtrinsic, RuntimeAppPublic, SaturatedConversion};
use sp_subspace_mmr::{ConsensusChainMmrLeafProof, MmrProofVerifier as MmrProofVerifierT};
use sp_trie::{LayoutV1, StorageProof};
use subspace_core_primitives::{Randomness, U256};
use trie_db::node::Value;

/// Verifies invalid domain extrinsic root fraud proof.
pub fn verify_invalid_domain_extrinsics_root_fraud_proof<
    CBlock,
    Balance,
    DomainHeader,
    Hashing,
    SKP,
>(
    bad_receipt: ExecutionReceipt<
        NumberFor<CBlock>,
        CBlock::Hash,
        HeaderNumberFor<DomainHeader>,
        HeaderHashFor<DomainHeader>,
        Balance,
    >,
    fraud_proof: &InvalidExtrinsicsRootProofV2<DomainHeader::Hash>,
    domain_id: DomainId,
    runtime_id: RuntimeId,
    state_root: CBlock::Hash,
    domain_runtime_code: Vec<u8>,
) -> Result<(), VerificationError<DomainHeader::Hash>>
where
    CBlock: BlockT,
    DomainHeader: HeaderT,
    DomainHeader::Hash: Into<H256> + PartialEq + Copy,
    Hashing: Hasher<Out = CBlock::Hash>,
    SKP: StorageKeyProvider,
{
    let consensus_block_hash = bad_receipt.consensus_block_hash;
    let consensus_block_number = bad_receipt.consensus_block_number;
    let InvalidExtrinsicsRootProofV2 {
        valid_bundle_digests,
        block_randomness_proof,
        domain_inherent_extrinsic_data_proof,
        ..
    } = fraud_proof;

    let domain_inherent_extrinsic_data = domain_inherent_extrinsic_data_proof
        .verify::<CBlock, SKP>(domain_id, runtime_id, &state_root)?;

    let block_randomness = <BlockRandomnessProof as BasicStorageProof<CBlock>>::verify::<SKP>(
        block_randomness_proof.clone(),
        (),
        &state_root,
    )?;

    let DomainInherentExtrinsic {
        domain_timestamp_extrinsic,
        maybe_domain_chain_allowlist_extrinsic,
        consensus_chain_byte_fee_extrinsic,
        maybe_domain_set_code_extrinsic,
    } = get_fraud_proof_verification_info_v2(
        Some(domain_runtime_code),
        FraudProofVerificationInfoRequestV2::ConstructDomainInherentExtrinsic(
            domain_inherent_extrinsic_data,
        ),
    )
    .and_then(|resp| resp.into_construct_domain_inherent_extrinsic())
    .ok_or(VerificationError::FailedToDeriveDomainInherentExtrinsic)?;

    let bad_receipt_valid_bundle_digests = bad_receipt.valid_bundle_digests();
    if valid_bundle_digests.len() != bad_receipt_valid_bundle_digests.len() {
        return Err(VerificationError::InvalidBundleDigest);
    }

    let mut bundle_extrinsics_digests = Vec::new();
    for (bad_receipt_valid_bundle_digest, bundle_digest) in bad_receipt_valid_bundle_digests
        .into_iter()
        .zip(valid_bundle_digests)
    {
        let bundle_digest_hash =
            HeaderHashingFor::<DomainHeader>::hash_of(&bundle_digest.bundle_digest);
        if bundle_digest_hash != bad_receipt_valid_bundle_digest {
            return Err(VerificationError::InvalidBundleDigest);
        }

        bundle_extrinsics_digests.extend(bundle_digest.bundle_digest.clone());
    }

    let shuffling_seed =
        H256::from_slice(extrinsics_shuffling_seed::<Hashing>(block_randomness).as_ref());

    let mut ordered_extrinsics = deduplicate_and_shuffle_extrinsics(
        bundle_extrinsics_digests,
        Randomness::from(shuffling_seed.to_fixed_bytes()),
    );

    // NOTE: the order of the inherent extrinsic MUST aligned with the
    // pallets order defined in `construct_runtime` macro for domains.
    // currently this is the following order
    // - timestamp extrinsic
    // - executive set_code extrinsic
    // - messenger update_domain_allowlist extrinsic
    // - block_fees transaction_byte_fee_extrinsic
    // since we use `push_front` the extrinsic should be pushed in reversed order
    // TODO: this will not be valid once we have a different runtime. To achive consistency across
    //  domains, we should define a runtime api for each domain that should order the extrinsics
    //  like inherent are derived while domain block is being built

    let transaction_byte_fee_extrinsic = ExtrinsicDigest::new::<
        LayoutV1<HeaderHashingFor<DomainHeader>>,
    >(consensus_chain_byte_fee_extrinsic);
    ordered_extrinsics.push_front(transaction_byte_fee_extrinsic);

    if let Some(domain_chain_allowlist_extrinsic) = maybe_domain_chain_allowlist_extrinsic {
        let domain_set_code_extrinsic = ExtrinsicDigest::new::<
            LayoutV1<HeaderHashingFor<DomainHeader>>,
        >(domain_chain_allowlist_extrinsic);
        ordered_extrinsics.push_front(domain_set_code_extrinsic);
    }

    if let Some(domain_set_code_extrinsic) = maybe_domain_set_code_extrinsic {
        let domain_set_code_extrinsic = ExtrinsicDigest::new::<
            LayoutV1<HeaderHashingFor<DomainHeader>>,
        >(domain_set_code_extrinsic);
        ordered_extrinsics.push_front(domain_set_code_extrinsic);
    }

    let timestamp_extrinsic = ExtrinsicDigest::new::<LayoutV1<HeaderHashingFor<DomainHeader>>>(
        domain_timestamp_extrinsic,
    );
    ordered_extrinsics.push_front(timestamp_extrinsic);

    let ordered_trie_node_values = ordered_extrinsics
        .iter()
        .map(|ext_digest| match ext_digest {
            ExtrinsicDigest::Data(data) => Value::Inline(data),
            ExtrinsicDigest::Hash(hash) => Value::Node(hash.0.as_slice()),
        })
        .collect();

    let extrinsics_root = valued_ordered_trie_root::<LayoutV1<HeaderHashingFor<DomainHeader>>>(
        ordered_trie_node_values,
    );
    if bad_receipt.domain_block_extrinsic_root == extrinsics_root {
        return Err(VerificationError::InvalidProof);
    }

    Ok(())
}

pub fn verify_mmr_proof_and_extract_state_root<CBlock, DomainHeader, MmrHash, MmrProofVerifier>(
    mmr_leaf_proof: ConsensusChainMmrLeafProof<NumberFor<CBlock>, CBlock::Hash, MmrHash>,
    expected_block_number: NumberFor<CBlock>,
) -> Result<CBlock::Hash, VerificationError<DomainHeader::Hash>>
where
    CBlock: BlockT,
    DomainHeader: HeaderT,
    MmrProofVerifier: MmrProofVerifierT<MmrHash, NumberFor<CBlock>, CBlock::Hash>,
{
    let leaf_data = MmrProofVerifier::verify_proof_and_extract_leaf(mmr_leaf_proof)
        .ok_or(VerificationError::BadMmrProof)?;

    // Ensure it is a proof of the exact block that we expected
    if expected_block_number != leaf_data.block_number() {
        return Err(VerificationError::UnexpectedMmrProof);
    }

    Ok(leaf_data.state_root())
}

/// Verifies valid bundle fraud proof.
pub fn verify_valid_bundle_fraud_proof<CBlock, DomainHeader, Balance, SKP>(
    bad_receipt: ExecutionReceipt<
        NumberFor<CBlock>,
        CBlock::Hash,
        HeaderNumberFor<DomainHeader>,
        HeaderHashFor<DomainHeader>,
        Balance,
    >,
    fraud_proof: &ValidBundleProofV2<NumberFor<CBlock>, CBlock::Hash, DomainHeader>,
    domain_id: DomainId,
    state_root: CBlock::Hash,
) -> Result<(), VerificationError<DomainHeader::Hash>>
where
    CBlock: BlockT,
    CBlock::Hash: Into<H256>,
    DomainHeader: HeaderT,
    DomainHeader::Hash: Into<H256> + PartialEq + Copy,
    SKP: StorageKeyProvider,
{
    let ValidBundleProofV2 {
        bundle_with_proof, ..
    } = fraud_proof;

    let _ = bundle_with_proof.verify::<CBlock, SKP>(domain_id, &state_root)?;
    let OpaqueBundleWithProof {
        bundle,
        bundle_index,
        ..
    } = bundle_with_proof;

    // TODO: get domain runtime code from storage proof
    let valid_bundle_digest = fraud_proof_runtime_interface::derive_bundle_digest(
        bad_receipt.consensus_block_hash.into(),
        domain_id,
        bundle.extrinsics.clone(),
    )
    .ok_or(VerificationError::FailedToDeriveBundleDigest)?;

    let bad_valid_bundle_digest = bad_receipt
        .valid_bundle_digest_at(*bundle_index as usize)
        .ok_or(VerificationError::TargetValidBundleNotFound)?;

    if bad_valid_bundle_digest.into() == valid_bundle_digest {
        Err(VerificationError::InvalidProof)
    } else {
        Ok(())
    }
}

/// Verifies invalid state transition fraud proof.
pub fn verify_invalid_state_transition_fraud_proof<CBlock, DomainHeader, Balance>(
    bad_receipt: ExecutionReceipt<
        NumberFor<CBlock>,
        <CBlock as BlockT>::Hash,
        DomainHeader::Number,
        DomainHeader::Hash,
        Balance,
    >,
    bad_receipt_parent: ExecutionReceipt<
        NumberFor<CBlock>,
        <CBlock as BlockT>::Hash,
        DomainHeader::Number,
        DomainHeader::Hash,
        Balance,
    >,
    fraud_proof: &InvalidStateTransitionProofV2<HeaderHashFor<DomainHeader>>,
    domain_id: DomainId,
    domain_runtime_code: Vec<u8>,
) -> Result<(), VerificationError<DomainHeader::Hash>>
where
    CBlock: BlockT,
    CBlock::Hash: Into<H256>,
    DomainHeader: HeaderT,
    DomainHeader::Hash: Into<H256> + From<H256>,
    DomainHeader::Number: UniqueSaturatedInto<BlockNumber> + From<BlockNumber>,
{
    let InvalidStateTransitionProofV2 {
        execution_proof,
        execution_phase,
        ..
    } = fraud_proof;

    let (pre_state_root, post_state_root) = execution_phase
        .pre_post_state_root::<CBlock, DomainHeader, Balance>(&bad_receipt, &bad_receipt_parent)?;

    let call_data = execution_phase
        .call_data::<CBlock, DomainHeader, Balance>(&bad_receipt, &bad_receipt_parent)?;

    let execution_result = fraud_proof_runtime_interface::execution_proof_check(
        (
            bad_receipt_parent.domain_block_number.saturated_into(),
            bad_receipt_parent.domain_block_hash.into(),
        ),
        pre_state_root,
        execution_proof.encode(),
        execution_phase.execution_method(),
        call_data.as_ref(),
        domain_runtime_code,
    )
    .ok_or(VerificationError::BadExecutionProof)?;

    let valid_post_state_root = execution_phase
        .decode_execution_result::<DomainHeader>(execution_result)?
        .into();

    let is_mismatch = valid_post_state_root != post_state_root;

    // If there is mismatch and execution phase indicate state root mismatch then the fraud proof is valid
    // If there is no mismatch and execution phase indicate non state root mismatch (i.e the trace is either long or short) then
    // the fraud proof is valid.
    let is_valid = is_mismatch == execution_phase.is_state_root_mismatch();

    if is_valid {
        Ok(())
    } else {
        Err(VerificationError::InvalidProof)
    }
}

/// Verifies invalid domain block hash fraud proof.
pub fn verify_invalid_domain_block_hash_fraud_proof<CBlock, Balance, DomainHeader>(
    bad_receipt: ExecutionReceipt<
        NumberFor<CBlock>,
        CBlock::Hash,
        DomainHeader::Number,
        DomainHeader::Hash,
        Balance,
    >,
    digest_storage_proof: StorageProof,
    parent_domain_block_hash: DomainHeader::Hash,
) -> Result<(), VerificationError<DomainHeader::Hash>>
where
    CBlock: BlockT,
    Balance: PartialEq + Decode,
    DomainHeader: HeaderT,
{
    let state_root = bad_receipt.final_state_root;
    let digest_storage_key = StorageKey(sp_domains::system_digest_final_key());

    let digest = StorageProofVerifier::<DomainHeader::Hashing>::get_decoded_value::<Digest>(
        &state_root,
        digest_storage_proof,
        digest_storage_key,
    )
    .map_err(|_| VerificationError::InvalidStorageProof)?;

    let derived_domain_block_hash = sp_domains::derive_domain_block_hash::<DomainHeader>(
        bad_receipt.domain_block_number,
        bad_receipt.domain_block_extrinsic_root,
        state_root,
        parent_domain_block_hash,
        digest,
    );

    if bad_receipt.domain_block_hash == derived_domain_block_hash {
        return Err(VerificationError::InvalidProof);
    }

    Ok(())
}

/// Verifies invalid block fees fraud proof.
pub fn verify_invalid_block_fees_fraud_proof<
    CBlock,
    DomainNumber,
    DomainHash,
    Balance,
    DomainHashing,
>(
    bad_receipt: ExecutionReceipt<
        NumberFor<CBlock>,
        CBlock::Hash,
        DomainNumber,
        DomainHash,
        Balance,
    >,
    storage_proof: &StorageProof,
    domain_runtime_code: Vec<u8>,
) -> Result<(), VerificationError<DomainHash>>
where
    CBlock: BlockT,
    Balance: PartialEq + Decode,
    DomainHashing: Hasher<Out = DomainHash>,
{
    let storage_key = get_fraud_proof_verification_info_v2(
        Some(domain_runtime_code),
        FraudProofVerificationInfoRequestV2::DomainStorageKey(DomainStorageKeyRequest::BlockFees),
    )
    .and_then(|resp| resp.into_domain_storage_key())
    .ok_or(VerificationError::FailedToGetDomainStorageKey)?;

    let block_fees =
        StorageProofVerifier::<DomainHashing>::get_decoded_value::<BlockFees<Balance>>(
            &bad_receipt.final_state_root,
            storage_proof.clone(),
            StorageKey(storage_key),
        )
        .map_err(|_| VerificationError::InvalidStorageProof)?;

    // if the rewards matches, then this is an invalid fraud proof since rewards must be different.
    if bad_receipt.block_fees == block_fees {
        return Err(VerificationError::InvalidProof);
    }

    Ok(())
}

/// Verifies invalid transfers fraud proof.
pub fn verify_invalid_transfers_fraud_proof<
    CBlock,
    DomainNumber,
    DomainHash,
    Balance,
    DomainHashing,
>(
    bad_receipt: ExecutionReceipt<
        NumberFor<CBlock>,
        CBlock::Hash,
        DomainNumber,
        DomainHash,
        Balance,
    >,
    storage_proof: &StorageProof,
    domain_runtime_code: Vec<u8>,
) -> Result<(), VerificationError<DomainHash>>
where
    CBlock: BlockT,
    CBlock::Hash: Into<H256>,
    Balance: PartialEq + Decode,
    DomainHashing: Hasher<Out = DomainHash>,
{
    let storage_key = get_fraud_proof_verification_info_v2(
        Some(domain_runtime_code),
        FraudProofVerificationInfoRequestV2::DomainStorageKey(DomainStorageKeyRequest::Transfers),
    )
    .and_then(|resp| resp.into_domain_storage_key())
    .ok_or(VerificationError::FailedToGetDomainStorageKey)?;

    let transfers = StorageProofVerifier::<DomainHashing>::get_decoded_value::<Transfers<Balance>>(
        &bad_receipt.final_state_root,
        storage_proof.clone(),
        StorageKey(storage_key),
    )
    .map_err(|_| VerificationError::InvalidStorageProof)?;

    // if the rewards matches, then this is an invalid fraud proof since rewards must be different.
    if bad_receipt.transfers == transfers {
        return Err(VerificationError::InvalidProof);
    }

    Ok(())
}

/// This function checks if this fraud proof is expected against the inboxed bundle entry it is targeting.
/// If the entry is expected then it will be returned
/// In any other cases VerificationError will be returned
fn check_expected_bundle_entry<CBlock, DomainHeader, Balance>(
    bad_receipt: &ExecutionReceipt<
        NumberFor<CBlock>,
        CBlock::Hash,
        HeaderNumberFor<DomainHeader>,
        HeaderHashFor<DomainHeader>,
        Balance,
    >,
    bundle_index: u32,
    invalid_bundle_type: InvalidBundleType,
    is_true_invalid_fraud_proof: bool,
) -> Result<InboxedBundle<HeaderHashFor<DomainHeader>>, VerificationError<DomainHeader::Hash>>
where
    CBlock: BlockT,
    DomainHeader: HeaderT,
{
    let targeted_invalid_bundle_entry = bad_receipt
        .inboxed_bundles
        .get(bundle_index as usize)
        .ok_or(VerificationError::BundleNotFound)?;

    let is_expected = if !is_true_invalid_fraud_proof {
        // `FalseInvalid`
        // The proof trying to prove `bad_receipt_bundle`'s `invalid_bundle_type` is wrong,
        // so the proof should contains the same `invalid_bundle_type`
        targeted_invalid_bundle_entry.bundle == BundleValidity::Invalid(invalid_bundle_type.clone())
    } else {
        // `TrueInvalid`
        match &targeted_invalid_bundle_entry.bundle {
            // The proof trying to prove the bundle is invalid due to `invalid_type_of_proof` while `bad_receipt_bundle`
            // think it is valid
            BundleValidity::Valid(_) => true,
            BundleValidity::Invalid(invalid_type) => {
                // The proof trying to prove there is an invalid extrinsic that the `bad_receipt_bundle` think is valid,
                // so the proof should point to an extrinsic that in front of the `bad_receipt_bundle`'s
                invalid_bundle_type.extrinsic_index() < invalid_type.extrinsic_index() ||
                    // The proof trying to prove the invalid extrinsic can not pass a check that the `bad_receipt_bundle` think it can,
                    // so the proof should point to the same extrinsic and a check that perform before the `bad_receipt_bundle`'s
                    (invalid_bundle_type.extrinsic_index() == invalid_type.extrinsic_index()
                        && invalid_bundle_type.checking_order() < invalid_type.checking_order())
            }
        }
    };

    if !is_expected {
        return Err(VerificationError::UnexpectedTargetedBundleEntry {
            bundle_index,
            fraud_proof_invalid_type_of_proof: invalid_bundle_type,
            targeted_entry_bundle: targeted_invalid_bundle_entry.bundle.clone(),
        });
    }

    Ok(targeted_invalid_bundle_entry.clone())
}

fn get_extrinsic_from_proof<DomainHeader: HeaderT>(
    extrinsic_index: u32,
    extrinsics_root: <HeaderHashingFor<DomainHeader> as Hasher>::Out,
    proof_data: StorageProof,
) -> Result<OpaqueExtrinsic, VerificationError<DomainHeader::Hash>> {
    let storage_key =
        StorageProofVerifier::<HeaderHashingFor<DomainHeader>>::enumerated_storage_key(
            extrinsic_index,
        );
    StorageProofVerifier::<HeaderHashingFor<DomainHeader>>::get_decoded_value(
        &extrinsics_root,
        proof_data,
        storage_key,
    )
    .map_err(|_e| VerificationError::InvalidProof)
}

pub fn verify_invalid_bundles_fraud_proof<CBlock, DomainHeader, Balance, SKP>(
    bad_receipt: ExecutionReceipt<
        NumberFor<CBlock>,
        CBlock::Hash,
        HeaderNumberFor<DomainHeader>,
        HeaderHashFor<DomainHeader>,
        Balance,
    >,
    bad_receipt_parent: ExecutionReceipt<
        NumberFor<CBlock>,
        CBlock::Hash,
        HeaderNumberFor<DomainHeader>,
        HeaderHashFor<DomainHeader>,
        Balance,
    >,
    invalid_bundles_fraud_proof: &InvalidBundlesProofV2<
        NumberFor<CBlock>,
        <CBlock as BlockT>::Hash,
        DomainHeader,
    >,
    domain_id: DomainId,
    state_root: CBlock::Hash,
    domain_runtime_code: Vec<u8>,
) -> Result<(), VerificationError<DomainHeader::Hash>>
where
    CBlock: BlockT,
    DomainHeader: HeaderT,
    CBlock::Hash: Into<H256>,
    DomainHeader::Hash: Into<H256>,
    SKP: StorageKeyProvider,
{
    let InvalidBundlesProofV2 {
        bundle_index,
        invalid_bundle_type,
        is_true_invalid_fraud_proof,
        proof_data,
        ..
    } = invalid_bundles_fraud_proof;
    let (bundle_index, is_true_invalid_fraud_proof) = (*bundle_index, *is_true_invalid_fraud_proof);

    let invalid_bundle_entry = check_expected_bundle_entry::<CBlock, DomainHeader, Balance>(
        &bad_receipt,
        bundle_index,
        invalid_bundle_type.clone(),
        is_true_invalid_fraud_proof,
    )?;

    match &invalid_bundle_type {
        InvalidBundleType::OutOfRangeTx(extrinsic_index) => {
            let bundle = match proof_data {
                InvalidBundlesProofData::Bundle(bundle_with_proof)
                    if bundle_with_proof.bundle_index == bundle_index =>
                {
                    let _ = bundle_with_proof.verify::<CBlock, SKP>(domain_id, &state_root)?;
                    bundle_with_proof.bundle.clone()
                }
                _ => return Err(VerificationError::UnexpectedInvalidBundleProofData),
            };

            let opaque_extrinsic = bundle
                .extrinsics
                .get(*extrinsic_index as usize)
                .cloned()
                .ok_or(VerificationError::ExtrinsicNotFound)?;

            let domain_tx_range = U256::MAX / INITIAL_DOMAIN_TX_RANGE;
            let bundle_vrf_hash =
                U256::from_be_bytes(bundle.sealed_header.header.proof_of_election.vrf_hash());

            let is_tx_in_range = get_fraud_proof_verification_info_v2(
                Some(domain_runtime_code),
                FraudProofVerificationInfoRequestV2::DomainRuntimeCall {
                    call: StatelessDomainRuntimeCall::IsTxInRange {
                        domain_tx_range,
                        bundle_vrf_hash,
                    },
                    opaque_extrinsic,
                },
            )
            .and_then(FraudProofVerificationInfoResponseV2::into_domain_runtime_call)
            .ok_or(VerificationError::FailedToGetDomainRuntimeCallResponse)?;

            // If it is true invalid fraud proof then tx must not be in range and
            // if it is false invalid fraud proof then tx must be in range for fraud
            // proof to be considered valid.
            if is_tx_in_range == is_true_invalid_fraud_proof {
                return Err(VerificationError::InvalidProof);
            }
            Ok(())
        }
        InvalidBundleType::InherentExtrinsic(extrinsic_index) => {
            let opaque_extrinsic = {
                let extrinsic_storage_proof = match proof_data {
                    InvalidBundlesProofData::Extrinsic(p) => p.clone(),
                    _ => return Err(VerificationError::UnexpectedInvalidBundleProofData),
                };
                get_extrinsic_from_proof::<DomainHeader>(
                    *extrinsic_index,
                    invalid_bundle_entry.extrinsics_root,
                    extrinsic_storage_proof,
                )?
            };
            let is_inherent = get_fraud_proof_verification_info_v2(
                Some(domain_runtime_code),
                FraudProofVerificationInfoRequestV2::DomainRuntimeCall {
                    call: StatelessDomainRuntimeCall::IsInherentExtrinsic,
                    opaque_extrinsic,
                },
            )
            .and_then(FraudProofVerificationInfoResponseV2::into_domain_runtime_call)
            .ok_or(VerificationError::FailedToGetDomainRuntimeCallResponse)?;

            // Proof to be considered valid only,
            // If it is true invalid fraud proof then extrinsic must be an inherent and
            // If it is false invalid fraud proof then extrinsic must not be an inherent
            if is_inherent == is_true_invalid_fraud_proof {
                Ok(())
            } else {
                Err(VerificationError::InvalidProof)
            }
        }
        InvalidBundleType::IllegalTx(extrinsic_index) => {
            let (mut bundle, execution_proof) = match proof_data {
                InvalidBundlesProofData::BundleAndExecution {
                    bundle_with_proof,
                    execution_proof,
                } if bundle_with_proof.bundle_index == bundle_index => {
                    let _ = bundle_with_proof.verify::<CBlock, SKP>(domain_id, &state_root)?;
                    (bundle_with_proof.bundle.clone(), execution_proof.clone())
                }
                _ => return Err(VerificationError::UnexpectedInvalidBundleProofData),
            };

            let extrinsics = bundle
                .extrinsics
                .drain(..)
                .take((*extrinsic_index + 1) as usize)
                .collect();

            // Make host call for check extrinsic in single context
            let check_extrinsic_result = get_fraud_proof_verification_info_v2(
                Some(domain_runtime_code),
                FraudProofVerificationInfoRequestV2::CheckExtrinsicsInSingleContext {
                    domain_id,
                    domain_block_number: bad_receipt_parent.domain_block_number.saturated_into(),
                    domain_block_hash: bad_receipt_parent.domain_block_hash.into(),
                    domain_block_state_root: bad_receipt_parent.final_state_root.into(),
                    extrinsics,
                    storage_proof: execution_proof,
                },
            )
            .and_then(FraudProofVerificationInfoResponseV2::into_single_context_extrinsic_check)
            .ok_or(VerificationError::FailedToCheckExtrinsicsInSingleContext)?;

            let is_extrinsic_invalid = check_extrinsic_result == Some(*extrinsic_index);

            // Proof to be considered valid only,
            // If it is true invalid fraud proof then extrinsic must be an invalid extrinsic and
            // If it is false invalid fraud proof then extrinsic must not be an invalid extrinsic
            if is_extrinsic_invalid == is_true_invalid_fraud_proof {
                Ok(())
            } else {
                Err(VerificationError::InvalidProof)
            }
        }
        InvalidBundleType::UndecodableTx(extrinsic_index) => {
            let opaque_extrinsic = {
                let extrinsic_storage_proof = match proof_data {
                    InvalidBundlesProofData::Extrinsic(p) => p.clone(),
                    _ => return Err(VerificationError::UnexpectedInvalidBundleProofData),
                };
                get_extrinsic_from_proof::<DomainHeader>(
                    *extrinsic_index,
                    invalid_bundle_entry.extrinsics_root,
                    extrinsic_storage_proof,
                )?
            };
            let is_decodable = get_fraud_proof_verification_info_v2(
                Some(domain_runtime_code),
                FraudProofVerificationInfoRequestV2::DomainRuntimeCall {
                    call: StatelessDomainRuntimeCall::IsDecodableExtrinsic,
                    opaque_extrinsic,
                },
            )
            .and_then(FraudProofVerificationInfoResponseV2::into_domain_runtime_call)
            .ok_or(VerificationError::FailedToGetDomainRuntimeCallResponse)?;

            if is_decodable == is_true_invalid_fraud_proof {
                return Err(VerificationError::InvalidProof);
            }
            Ok(())
        }
        // TODO: Is it already cover by IllegalTx?
        InvalidBundleType::InvalidXDM(extrinsic_index) => {
            let opaque_extrinsic = {
                let extrinsic_storage_proof = match proof_data {
                    InvalidBundlesProofData::Extrinsic(p) => p.clone(),
                    _ => return Err(VerificationError::UnexpectedInvalidBundleProofData),
                };
                get_extrinsic_from_proof::<DomainHeader>(
                    *extrinsic_index,
                    invalid_bundle_entry.extrinsics_root,
                    extrinsic_storage_proof,
                )?
            };

            let maybe_is_valid_xdm = get_fraud_proof_verification_info(
                H256::from_slice(bad_receipt.consensus_block_hash.as_ref()),
                FraudProofVerificationInfoRequest::XDMValidationCheck {
                    domain_id,
                    opaque_extrinsic,
                },
            )
            .and_then(FraudProofVerificationInfoResponse::into_xdm_validation_check);

            if let Some(is_valid_xdm) = maybe_is_valid_xdm {
                // Proof to be considered valid only,
                // If it is true invalid fraud proof then extrinsic must be an invalid xdm and
                // If it is false invalid fraud proof then extrinsic must be a valid xdm
                if is_valid_xdm != is_true_invalid_fraud_proof {
                    Ok(())
                } else {
                    Err(VerificationError::InvalidProof)
                }
            } else {
                // If this extrinsic is not an XDM,
                // If it is false invalid, then bad receipt marked this extrinsic as InvalidXDM
                // even though it is not an XDM, if so accept the fraud proof
                if !is_true_invalid_fraud_proof {
                    Ok(())
                } else {
                    // If this is a true invalid but the extrinsic is not an XDM, then reject fraud proof.
                    // this can happen if there is a bug in the challenger node implementation.
                    Err(VerificationError::InvalidProof)
                }
            }
        }
    }
}

/// Represents error for invalid bundle equivocation proof.
#[derive(Debug)]
#[cfg_attr(feature = "thiserror", derive(thiserror::Error))]
pub enum InvalidBundleEquivocationError {
    /// Bundle signature is invalid.
    #[cfg_attr(feature = "thiserror", error("Invalid bundle signature."))]
    BadBundleSignature,
    /// Bundle slot mismatch.
    #[cfg_attr(feature = "thiserror", error("Bundle slot mismatch."))]
    BundleSlotMismatch,
    /// Same bundle hash.
    #[cfg_attr(feature = "thiserror", error("Same bundle hash."))]
    SameBundleHash,
    /// Invalid Proof of election.
    #[cfg_attr(feature = "thiserror", error("Invalid Proof of Election: {0:?}"))]
    InvalidProofOfElection(ProofOfElectionError),
    /// Failed to get domain total stake.
    #[cfg_attr(feature = "thiserror", error("Failed to get domain total stake."))]
    FailedToGetDomainTotalStake,
    /// Failed to get operator stake.
    #[cfg_attr(feature = "thiserror", error("Failed to get operator stake"))]
    FailedToGetOperatorStake,
    /// Mismatched operatorId and Domain.
    #[cfg_attr(feature = "thiserror", error("Mismatched operatorId and Domain."))]
    MismatchedOperatorAndDomain,
    /// Bad MMR proof
    #[cfg_attr(feature = "thiserror", error("Bad mmr prof"))]
    BadMmrProof,
    #[cfg_attr(feature = "thiserror", error("Failed to verify storage proof"))]
    StorageProof(storage_proof::VerificationError),
}

/// Verifies Bundle equivocation fraud proof.
pub fn verify_bundle_equivocation_fraud_proof<CBlock, DomainHeader, SKP>(
    fraud_proof: &BundleEquivocationProofV2<
        NumberFor<CBlock>,
        <CBlock as BlockT>::Hash,
        DomainHeader,
    >,
    domain_id: DomainId,
    state_root: CBlock::Hash,
) -> Result<(), InvalidBundleEquivocationError>
where
    CBlock: BlockT,
    DomainHeader: HeaderT,
    SKP: StorageKeyProvider,
{
    let BundleEquivocationProofV2 {
        bundle_producion_proof,
        first_header,
        second_header,
        ..
    } = fraud_proof;
    let operator_id = first_header.header.proof_of_election.operator_id;

    let BundleProductionData {
        domain_total_stake,
        operator_total_stake,
        operator_signing_key,
        bundle_slot_probability,
    } = bundle_producion_proof
        .verify::<CBlock, SKP>(domain_id, operator_id, &state_root)
        .map_err(InvalidBundleEquivocationError::StorageProof)?;

    if !operator_signing_key.verify(&first_header.pre_hash(), &first_header.signature) {
        return Err(InvalidBundleEquivocationError::BadBundleSignature);
    }

    if !operator_signing_key.verify(&second_header.pre_hash(), &second_header.signature) {
        return Err(InvalidBundleEquivocationError::BadBundleSignature);
    }

    let operator_set_1 = (
        first_header.header.proof_of_election.operator_id,
        first_header.header.proof_of_election.domain_id,
    );
    let operator_set_2 = (
        second_header.header.proof_of_election.operator_id,
        second_header.header.proof_of_election.domain_id,
    );

    // Operator and the domain the proof of election targeted should be same
    if operator_set_1 != operator_set_2 {
        return Err(InvalidBundleEquivocationError::MismatchedOperatorAndDomain);
    }

    check_proof_of_election(
        &operator_signing_key,
        bundle_slot_probability,
        &first_header.header.proof_of_election,
        operator_total_stake,
        domain_total_stake,
    )
    .map_err(InvalidBundleEquivocationError::InvalidProofOfElection)?;

    check_proof_of_election(
        &operator_signing_key,
        bundle_slot_probability,
        &second_header.header.proof_of_election,
        operator_total_stake,
        domain_total_stake,
    )
    .map_err(InvalidBundleEquivocationError::InvalidProofOfElection)?;

    if first_header.header.proof_of_election.slot_number
        != second_header.header.proof_of_election.slot_number
    {
        return Err(InvalidBundleEquivocationError::BundleSlotMismatch);
    }

    if first_header.hash() == second_header.hash() {
        return Err(InvalidBundleEquivocationError::SameBundleHash);
    }

    Ok(())
}
