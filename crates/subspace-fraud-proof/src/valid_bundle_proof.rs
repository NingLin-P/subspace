//! Invalid transaction proof.

use crate::domain_runtime_code::retrieve_domain_runtime_code;
use crate::verifier_api::VerifierApi;
use codec::{Decode, Encode};
use domain_block_preprocessor::runtime_api_light::RuntimeApiLight;
use domain_runtime_primitives::opaque::Block;
use domain_runtime_primitives::{Balance, DomainCoreApi, Hash};
use frame_support::storage::generator::{StorageDoubleMap, StorageMap};
use sc_client_api::StorageProof;
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_core::storage::StorageKey;
use sp_core::traits::CodeExecutor;
use sp_core::H256;
use sp_domains::fraud_proof::{
    BlockTreeStorage, SuccessfulBundlesStorage, ValidBundleProof, VerificationError,
};
use sp_domains::storage_proof::{OpaqueBundleWithProof, StorageProofVerifier};
use sp_domains::{DomainId, DomainsApi, OpaqueBundle, OpaqueBundleOf, ReceiptHash};
use sp_runtime::traits::{
    BlakeTwo256, Block as BlockT, Hash as HashT, HashingFor, Header as HeaderT, NumberFor,
};
use sp_runtime::{OpaqueExtrinsic, Storage};
use sp_trie::{read_trie_value, LayoutV1};
use std::borrow::Cow;
use std::collections::btree_set::BTreeSet;
use std::collections::BTreeMap;
use std::marker::PhantomData;
use std::sync::Arc;

/// Invalid transaction proof verifier.
pub struct ValidBundleProofVerifier<CBlock, CClient, Hash, Exec> {
    consensus_client: Arc<CClient>,
    executor: Arc<Exec>,
    _phantom: PhantomData<(CBlock, Hash)>,
}

impl<CBlock, CClient, Hash, Exec> Clone for ValidBundleProofVerifier<CBlock, CClient, Hash, Exec> {
    fn clone(&self) -> Self {
        Self {
            consensus_client: self.consensus_client.clone(),
            executor: self.executor.clone(),
            _phantom: self._phantom,
        }
    }
}

impl<CBlock, CClient, Hash, Exec> ValidBundleProofVerifier<CBlock, CClient, Hash, Exec>
where
    CBlock: BlockT,
    Hash: Encode + Decode,
    H256: Into<CBlock::Hash>,
    CClient: HeaderBackend<CBlock> + ProvideRuntimeApi<CBlock> + Send + Sync,
    CClient::Api: DomainsApi<CBlock, domain_runtime_primitives::BlockNumber, Hash>,
    Exec: CodeExecutor + 'static,
{
    /// Constructs a new instance of [`ValidBundleProofVerifier`].
    pub fn new(consensus_client: Arc<CClient>, executor: Arc<Exec>) -> Self {
        Self {
            consensus_client,
            executor,
            _phantom: Default::default(),
        }
    }

    fn compile_bundle_digest(
        &self,
        domain_runtime_code: Vec<u8>,
        bundle: OpaqueBundleOf<Block, CBlock, Balance>,
    ) -> Result<H256, VerificationError> {
        let mut runtime_api_light =
            RuntimeApiLight::new(self.executor.clone(), domain_runtime_code.into());

        let mut extrinsics = Vec::with_capacity(bundle.extrinsics.len());
        for opaque_extrinsic in bundle.extrinsics {
            let ext =
                <<Block as BlockT>::Extrinsic>::decode(&mut opaque_extrinsic.encode().as_slice())?;
            extrinsics.push(ext);
        }

        let bundle_digest: Vec<_> =
            <RuntimeApiLight<Exec> as DomainCoreApi<Block>>::extract_signer(
                &runtime_api_light,
                // `extract_signer` is a stateless runtime api thus it is okay to use
                // default block hash
                Default::default(),
                extrinsics,
            )?
            .into_iter()
            .map(|(signer, tx)| (signer, BlakeTwo256::hash_of(&tx)))
            .collect();

        Ok(BlakeTwo256::hash_of(&bundle_digest))
    }

    pub fn verify(
        &self,
        valid_bundle_proof: &ValidBundleProof<
            NumberFor<CBlock>,
            CBlock::Hash,
            NumberFor<Block>,
            <Block as BlockT>::Hash,
            Balance,
        >,
    ) -> Result<(), VerificationError> {
        let consensus_block_header = {
            let consensus_block_hash = valid_bundle_proof.bad_receipt.consensus_block_hash;
            self.consensus_client
                .header(consensus_block_hash)?
                .ok_or_else(|| {
                    sp_blockchain::Error::Backend(format!(
                        "Header for {consensus_block_hash} not found"
                    ))
                })?
        };
        let parent_consensus_block_header = {
            let parent_hash = consensus_block_header.parent_hash();
            self.consensus_client.header(*parent_hash)?.ok_or_else(|| {
                sp_blockchain::Error::Backend(format!("Header for {parent_hash} not found"))
            })?
        };

        let ValidBundleProof {
            domain_id,
            bad_receipt,
            bundle_with_proof,
            runtime_code_with_proof,
        } = valid_bundle_proof;

        // Verify the existence of the `bundle` in the consensus chain
        bundle_with_proof.verify::<CBlock>(*domain_id, &consensus_block_header.state_root())?;
        let OpaqueBundleWithProof {
            bundle,
            bundle_index,
            ..
        } = bundle_with_proof;

        // Verify the existence of the `domain_runtime_code` in the consensus chain
        //
        // NOTE: we use the state root of the parent block to verify here, see the comment
        // of `DomainRuntimeCodeWithProof` for more detail.
        let domain_runtime_code = runtime_code_with_proof
            .verify::<CBlock>(*domain_id, parent_consensus_block_header.state_root())?;

        let valid_bundle_digest =
            self.compile_bundle_digest(domain_runtime_code, bundle.clone())?;

        let bad_bundle_digest = bad_receipt
            .valid_bundles
            .iter()
            .find(|vb| vb.bundle_index == *bundle_index)
            .ok_or(VerificationError::DomainBundleNotFound)?
            .bundle_digest;

        if bad_bundle_digest == valid_bundle_digest {
            Err(VerificationError::SameBundleDigest)
        } else {
            Ok(())
        }
    }
}

/// Verifies valid bundle proof.
pub trait VerifyValidBundleProof<CBlock: BlockT> {
    /// Returns `Ok(())` if given `valid_bundle_proof` is legitimate.
    fn verify_valid_bundle_proof(
        &self,
        valid_bundle_proof: &ValidBundleProof<
            NumberFor<CBlock>,
            CBlock::Hash,
            NumberFor<Block>,
            <Block as BlockT>::Hash,
            Balance,
        >,
    ) -> Result<(), VerificationError>;
}

impl<CBlock, Client, Hash, Exec> VerifyValidBundleProof<CBlock>
    for ValidBundleProofVerifier<CBlock, Client, Hash, Exec>
where
    CBlock: BlockT,
    Hash: Encode + Decode,
    H256: Into<CBlock::Hash>,
    Client: HeaderBackend<CBlock> + ProvideRuntimeApi<CBlock> + Send + Sync,
    Client::Api: DomainsApi<CBlock, domain_runtime_primitives::BlockNumber, Hash>,
    Exec: CodeExecutor + 'static,
{
    fn verify_valid_bundle_proof(
        &self,
        valid_bundle_proof: &ValidBundleProof<
            NumberFor<CBlock>,
            CBlock::Hash,
            NumberFor<Block>,
            <Block as BlockT>::Hash,
            Balance,
        >,
    ) -> Result<(), VerificationError> {
        self.verify(valid_bundle_proof)
    }
}
