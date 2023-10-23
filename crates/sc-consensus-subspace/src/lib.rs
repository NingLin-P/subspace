// Copyright (C) 2019-2021 Parity Technologies (UK) Ltd.
// Copyright (C) 2021 Subspace Labs, Inc.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

#![doc = include_str!("../README.md")]
#![feature(let_chains, try_blocks)]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod archiver;
pub mod aux_schema;
pub mod notification;
mod slot_worker;
#[cfg(test)]
mod tests;
pub mod verifier;

use crate::archiver::{SegmentHeadersStore, FINALIZATION_DEPTH_IN_SEGMENTS};
use crate::notification::{SubspaceNotificationSender, SubspaceNotificationStream};
use crate::slot_worker::SubspaceSlotWorker;
pub use crate::slot_worker::SubspaceSyncOracle;
use crate::verifier::VerificationError;
use futures::channel::mpsc;
use futures::StreamExt;
use log::{debug, info, warn};
use lru::LruCache;
use parking_lot::Mutex;
use sc_client_api::backend::AuxStore;
use sc_client_api::{BlockBackend, BlockchainEvents, ProvideUncles, UsageProvider};
use sc_consensus::block_import::{
    BlockCheckParams, BlockImport, BlockImportParams, ForkChoiceStrategy, ImportResult,
};
use sc_consensus::{JustificationSyncLink, SharedBlockImport};
use sc_consensus_slots::{BackoffAuthoringBlocksStrategy, InherentDataProviderExt, SlotProportion};
use sc_proof_of_time::source::PotSlotInfoStream;
use sc_proof_of_time::verifier::PotVerifier;
use sc_telemetry::TelemetryHandle;
use sc_transaction_pool_api::OffchainTransactionPoolFactory;
use sc_utils::mpsc::TracingUnboundedSender;
use sp_api::{ApiError, ApiExt, BlockT, HeaderT, NumberFor, ProvideRuntimeApi};
use sp_block_builder::BlockBuilder as BlockBuilderApi;
use sp_blockchain::{Error as ClientError, HeaderBackend, HeaderMetadata, Result as ClientResult};
use sp_consensus::{Environment, Error as ConsensusError, Proposer, SelectChain, SyncOracle};
use sp_consensus_slots::{Slot, SlotDuration};
use sp_consensus_subspace::digests::{
    extract_pre_digest, extract_subspace_digest_items, Error as DigestError, SubspaceDigestItems,
};
use sp_consensus_subspace::{
    ChainConstants, FarmerPublicKey, FarmerSignature, PotNextSlotInput, SubspaceApi,
    SubspaceJustification,
};
use sp_core::H256;
use sp_inherents::{CreateInherentDataProviders, InherentDataProvider};
use sp_runtime::traits::One;
use sp_runtime::Justifications;
use std::future::Future;
use std::marker::PhantomData;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::Arc;
use subspace_archiving::archiver::NewArchivedSegment;
use subspace_core_primitives::crypto::kzg::Kzg;
use subspace_core_primitives::{
    BlockNumber, HistorySize, PublicKey, Randomness, SectorId, SegmentHeader, SegmentIndex,
    Solution, SolutionRange, REWARD_SIGNING_CONTEXT,
};
use subspace_proof_of_space::Table;
use subspace_verification::{
    calculate_block_weight, Error as VerificationPrimitiveError, PieceCheckParams,
    VerifySolutionParams,
};

/// Information about new slot that just arrived
#[derive(Debug, Copy, Clone)]
pub struct NewSlotInfo {
    /// Slot
    pub slot: Slot,
    /// Global randomness
    pub global_randomness: Randomness,
    /// Acceptable solution range for block authoring
    pub solution_range: SolutionRange,
    /// Acceptable solution range for voting
    pub voting_solution_range: SolutionRange,
}

/// New slot notification with slot information and sender for solution for the slot.
#[derive(Debug, Clone)]
pub struct NewSlotNotification {
    /// New slot information.
    pub new_slot_info: NewSlotInfo,
    /// Sender that can be used to send solutions for the slot.
    pub solution_sender: mpsc::Sender<Solution<FarmerPublicKey, FarmerPublicKey>>,
}

/// Notification with a hash that needs to be signed to receive reward and sender for signature.
#[derive(Debug, Clone)]
pub struct RewardSigningNotification {
    /// Hash to be signed.
    pub hash: H256,
    /// Public key of the plot identity that should create signature.
    pub public_key: FarmerPublicKey,
    /// Sender that can be used to send signature for the header.
    pub signature_sender: TracingUnboundedSender<FarmerSignature>,
}

/// Notification with block header hash that needs to be signed and sender for signature.
#[derive(Debug, Clone)]
pub struct ArchivedSegmentNotification {
    /// Archived segment.
    pub archived_segment: Arc<NewArchivedSegment>,
    /// Sender that signified the fact of receiving archived segment by farmer.
    ///
    /// This must be used to send a message or else block import pipeline will get stuck.
    pub acknowledgement_sender: TracingUnboundedSender<()>,
}

/// Notification with number of the block that is about to be imported and acknowledgement sender
/// that can be used to pause block production if desired.
///
/// NOTE: Block is not fully imported yet!
#[derive(Debug, Clone)]
pub struct BlockImportingNotification<Block>
where
    Block: BlockT,
{
    /// Block number
    pub block_number: NumberFor<Block>,
    /// Sender for pausing the block import when operator is not fast enough to process
    /// the consensus block.
    pub acknowledgement_sender: mpsc::Sender<()>,
}

/// Errors encountered by the Subspace authorship task.
#[derive(Debug, thiserror::Error)]
pub enum Error<Header: HeaderT> {
    /// Error during digest item extraction
    #[error("Digest item error: {0}")]
    DigestItemError(#[from] DigestError),
    /// Parent unavailable. Cannot import
    #[error("Parent ({0}) of {1} unavailable. Cannot import")]
    ParentUnavailable(Header::Hash, Header::Hash),
    /// Genesis block unavailable. Cannot import
    #[error("Genesis block unavailable. Cannot import")]
    GenesisUnavailable,
    /// Slot number must increase
    #[error("Slot number must increase: parent slot: {0}, this slot: {1}")]
    SlotMustIncrease(Slot, Slot),
    /// Header has a bad seal
    #[error("Header {0:?} has a bad seal")]
    HeaderBadSeal(Header::Hash),
    /// Header is unsealed
    #[error("Header {0:?} is unsealed")]
    HeaderUnsealed(Header::Hash),
    /// Bad reward signature
    #[error("Bad reward signature on {0:?}")]
    BadRewardSignature(Header::Hash),
    /// Missing Subspace justification
    #[error("Missing Subspace justification")]
    MissingSubspaceJustification,
    /// Invalid Subspace justification
    #[error("Invalid Subspace justification: {0}")]
    InvalidSubspaceJustification(codec::Error),
    /// Invalid Subspace justification contents
    #[error("Invalid Subspace justification contents")]
    InvalidSubspaceJustificationContents,
    /// Invalid proof of time
    #[error("Invalid proof of time")]
    InvalidProofOfTime,
    /// Solution is outside of solution range
    #[error(
        "Solution distance {solution_distance} is outside of solution range \
        {half_solution_range} (half of actual solution range) for slot {slot}"
    )]
    OutsideOfSolutionRange {
        /// Time slot
        slot: Slot,
        /// Half of solution range
        half_solution_range: SolutionRange,
        /// Solution distance
        solution_distance: SolutionRange,
    },
    /// Invalid proof of space
    #[error("Invalid proof of space")]
    InvalidProofOfSpace,
    /// Invalid audit chunk offset
    #[error("Invalid audit chunk offset")]
    InvalidAuditChunkOffset,
    /// Invalid chunk witness
    #[error("Invalid chunk witness")]
    InvalidChunkWitness,
    /// Piece verification failed
    #[error("Piece verification failed")]
    InvalidPieceOffset {
        /// Time slot
        slot: Slot,
        /// Index of the piece that failed verification
        piece_offset: u16,
        /// How many pieces one sector is supposed to contain (max)
        max_pieces_in_sector: u16,
    },
    /// Piece verification failed
    #[error("Piece verification failed for slot {0}")]
    InvalidPiece(Slot),
    /// Parent block has no associated weight
    #[error("Parent block of {0} has no associated weight")]
    ParentBlockNoAssociatedWeight(Header::Hash),
    /// Block has invalid associated solution range
    #[error("Invalid solution range for block {0}")]
    InvalidSolutionRange(Header::Hash),
    /// Invalid set of segment headers
    #[error("Invalid set of segment headers")]
    InvalidSetOfSegmentHeaders,
    /// Stored segment header extrinsic was not found
    #[error("Stored segment header extrinsic was not found: {0:?}")]
    SegmentHeadersExtrinsicNotFound(Vec<SegmentHeader>),
    /// Different segment commitment found
    #[error(
        "Different segment commitment for segment index {0} was found in storage, likely fork \
        below archiving point"
    )]
    DifferentSegmentCommitment(SegmentIndex),
    /// Farmer in block list
    #[error("Farmer {0} is in block list")]
    FarmerInBlockList(FarmerPublicKey),
    /// Segment commitment not found
    #[error("Segment commitment for segment index {0} not found")]
    SegmentCommitmentNotFound(SegmentIndex),
    /// Sector expired
    #[error("Sector expired")]
    SectorExpired {
        /// Expiration history size
        expiration_history_size: HistorySize,
        /// Current history size
        current_history_size: HistorySize,
    },
    /// Invalid history size
    #[error("Invalid history size")]
    InvalidHistorySize,
    /// Only root plot public key is allowed
    #[error("Only root plot public key is allowed")]
    OnlyRootPlotPublicKeyAllowed,
    /// Check inherents error
    #[error("Checking inherents failed: {0}")]
    CheckInherents(sp_inherents::Error),
    /// Unhandled check inherents error
    #[error("Checking inherents unhandled error: {}", String::from_utf8_lossy(.0))]
    CheckInherentsUnhandled(sp_inherents::InherentIdentifier),
    /// Create inherents error.
    #[error("Creating inherents failed: {0}")]
    CreateInherents(sp_inherents::Error),
    /// Client error
    #[error(transparent)]
    Client(#[from] sp_blockchain::Error),
    /// Runtime Api error.
    #[error(transparent)]
    RuntimeApi(#[from] ApiError),
}

impl<Header> From<VerificationError<Header>> for Error<Header>
where
    Header: HeaderT,
{
    #[inline]
    fn from(error: VerificationError<Header>) -> Self {
        match error {
            VerificationError::HeaderBadSeal(block_hash) => Error::HeaderBadSeal(block_hash),
            VerificationError::HeaderUnsealed(block_hash) => Error::HeaderUnsealed(block_hash),
            VerificationError::BadRewardSignature(block_hash) => {
                Error::BadRewardSignature(block_hash)
            }
            VerificationError::MissingSubspaceJustification => Error::MissingSubspaceJustification,
            VerificationError::InvalidSubspaceJustification(error) => {
                Error::InvalidSubspaceJustification(error)
            }
            VerificationError::InvalidSubspaceJustificationContents => {
                Error::InvalidSubspaceJustificationContents
            }
            VerificationError::InvalidProofOfTime => Error::InvalidProofOfTime,
            VerificationError::VerificationError(slot, error) => match error {
                VerificationPrimitiveError::InvalidPieceOffset {
                    piece_offset,
                    max_pieces_in_sector,
                } => Error::InvalidPieceOffset {
                    slot,
                    piece_offset,
                    max_pieces_in_sector,
                },
                VerificationPrimitiveError::InvalidPiece => Error::InvalidPiece(slot),
                VerificationPrimitiveError::OutsideSolutionRange {
                    half_solution_range,
                    solution_distance,
                } => Error::OutsideOfSolutionRange {
                    slot,
                    half_solution_range,
                    solution_distance,
                },
                VerificationPrimitiveError::InvalidProofOfSpace => Error::InvalidProofOfSpace,
                VerificationPrimitiveError::InvalidAuditChunkOffset => {
                    Error::InvalidAuditChunkOffset
                }
                VerificationPrimitiveError::InvalidChunkWitness => Error::InvalidChunkWitness,
                VerificationPrimitiveError::SectorExpired {
                    expiration_history_size,
                    current_history_size,
                } => Error::SectorExpired {
                    expiration_history_size,
                    current_history_size,
                },
                VerificationPrimitiveError::InvalidHistorySize => Error::InvalidHistorySize,
            },
        }
    }
}

impl<Header> From<Error<Header>> for String
where
    Header: HeaderT,
{
    #[inline]
    fn from(error: Error<Header>) -> String {
        error.to_string()
    }
}

/// Read configuration from the runtime state at current best block.
pub fn slot_duration<Block: BlockT, Client>(client: &Client) -> ClientResult<SlotDuration>
where
    Block: BlockT,
    Client: AuxStore + ProvideRuntimeApi<Block> + UsageProvider<Block>,
    Client::Api: SubspaceApi<Block, FarmerPublicKey>,
{
    let block_hash = if client.usage_info().chain.finalized_state.is_some() {
        client.usage_info().chain.best_hash
    } else {
        debug!(target: "subspace", "No finalized state is available. Reading config from genesis");
        client.usage_info().chain.genesis_hash
    };

    Ok(client.runtime_api().slot_duration(block_hash)?)
}

/// Parameters for Subspace.
pub struct SubspaceParams<Block, Client, SC, E, SO, L, CIDP, BS, AS>
where
    Block: BlockT,
    SO: SyncOracle + Send + Sync,
{
    /// The client to use
    pub client: Arc<Client>,

    /// The SelectChain Strategy
    pub select_chain: SC,

    /// The environment we are producing blocks for.
    pub env: E,

    /// The underlying block-import object to supply our produced blocks to.
    /// This must be a `SubspaceBlockImport` or a wrapper of it, otherwise
    /// critical consensus logic will be omitted.
    pub block_import: SharedBlockImport<Block>,

    /// A sync oracle
    pub sync_oracle: SubspaceSyncOracle<SO>,

    /// Hook into the sync module to control the justification sync process.
    pub justification_sync_link: L,

    /// Something that can create the inherent data providers.
    pub create_inherent_data_providers: CIDP,

    /// Force authoring of blocks even if we are offline
    pub force_authoring: bool,

    /// Strategy and parameters for backing off block production.
    pub backoff_authoring_blocks: Option<BS>,

    /// The source of timestamps for relative slots
    pub subspace_link: SubspaceLink<Block>,

    /// Persistent storage of segment headers
    pub segment_headers_store: SegmentHeadersStore<AS>,

    /// The proportion of the slot dedicated to proposing.
    ///
    /// The block proposing will be limited to this proportion of the slot from the starting of the
    /// slot. However, the proposing can still take longer when there is some lenience factor applied,
    /// because there were no blocks produced for some slots.
    pub block_proposal_slot_portion: SlotProportion,

    /// The maximum proportion of the slot dedicated to proposing with any lenience factor applied
    /// due to no blocks being produced.
    pub max_block_proposal_slot_portion: Option<SlotProportion>,

    /// Handle use to report telemetries.
    pub telemetry: Option<TelemetryHandle>,

    /// The offchain transaction pool factory.
    ///
    /// Will be used when sending equivocation reports and votes.
    pub offchain_tx_pool_factory: OffchainTransactionPoolFactory<Block>,

    /// Proof of time verifier
    pub pot_verifier: PotVerifier,

    /// Stream with proof of time slots.
    pub pot_slot_info_stream: PotSlotInfoStream,
}

/// Start the Subspace worker.
pub fn start_subspace<PosTable, Block, Client, SC, E, SO, CIDP, BS, L, AS, Error>(
    SubspaceParams {
        client,
        select_chain,
        env,
        block_import,
        sync_oracle,
        justification_sync_link,
        create_inherent_data_providers,
        force_authoring,
        backoff_authoring_blocks,
        subspace_link,
        segment_headers_store,
        block_proposal_slot_portion,
        max_block_proposal_slot_portion,
        telemetry,
        offchain_tx_pool_factory,
        pot_verifier,
        pot_slot_info_stream,
    }: SubspaceParams<Block, Client, SC, E, SO, L, CIDP, BS, AS>,
) -> Result<SubspaceWorker, sp_consensus::Error>
where
    PosTable: Table,
    Block: BlockT,
    Client: ProvideRuntimeApi<Block>
        + ProvideUncles<Block>
        + BlockchainEvents<Block>
        + HeaderBackend<Block>
        + HeaderMetadata<Block, Error = ClientError>
        + AuxStore
        + Send
        + Sync
        + 'static,
    Client::Api: SubspaceApi<Block, FarmerPublicKey>,
    SC: SelectChain<Block> + 'static,
    E: Environment<Block, Error = Error> + Send + Sync + 'static,
    E::Proposer: Proposer<Block, Error = Error>,
    SO: SyncOracle + Send + Sync + Clone + 'static,
    L: JustificationSyncLink<Block> + 'static,
    CIDP: CreateInherentDataProviders<Block, ()> + Send + Sync + 'static,
    CIDP::InherentDataProviders: InherentDataProviderExt + Send,
    BS: BackoffAuthoringBlocksStrategy<NumberFor<Block>> + Send + Sync + 'static,
    AS: AuxStore + Send + Sync + 'static,
    Error: std::error::Error + Send + From<ConsensusError> + 'static,
    BlockNumber: From<<<Block as BlockT>::Header as HeaderT>::Number>,
{
    let worker = SubspaceSlotWorker {
        client: client.clone(),
        block_import,
        env,
        sync_oracle: sync_oracle.clone(),
        justification_sync_link,
        force_authoring,
        backoff_authoring_blocks,
        subspace_link: subspace_link.clone(),
        reward_signing_context: schnorrkel::context::signing_context(REWARD_SIGNING_CONTEXT),
        block_proposal_slot_portion,
        max_block_proposal_slot_portion,
        telemetry,
        offchain_tx_pool_factory,
        chain_constants: client
            .runtime_api()
            .chain_constants(client.info().best_hash)
            .map_err(|error| sp_consensus::Error::ChainLookup(error.to_string()))?,
        segment_headers_store,
        pending_solutions: Default::default(),
        pot_checkpoints: Default::default(),
        pot_verifier,
        _pos_table: PhantomData::<PosTable>,
    };

    info!(target: "subspace", "🧑‍🌾 Starting Subspace Authorship worker");
    let inner = sc_proof_of_time::start_slot_worker(
        subspace_link.slot_duration(),
        client,
        select_chain,
        worker,
        sync_oracle,
        create_inherent_data_providers,
        pot_slot_info_stream,
    );

    Ok(SubspaceWorker {
        inner: Box::pin(inner),
    })
}

/// Worker for Subspace which implements `Future<Output=()>`. This must be polled.
#[must_use]
pub struct SubspaceWorker {
    inner: Pin<Box<dyn Future<Output = ()> + Send + 'static>>,
}

impl Future for SubspaceWorker {
    type Output = ();

    fn poll(
        mut self: Pin<&mut Self>,
        cx: &mut futures::task::Context,
    ) -> futures::task::Poll<Self::Output> {
        self.inner.as_mut().poll(cx)
    }
}

/// State that must be shared between the import queue and the authoring logic.
#[derive(Clone)]
pub struct SubspaceLink<Block: BlockT> {
    slot_duration: SlotDuration,
    new_slot_notification_sender: SubspaceNotificationSender<NewSlotNotification>,
    new_slot_notification_stream: SubspaceNotificationStream<NewSlotNotification>,
    reward_signing_notification_sender: SubspaceNotificationSender<RewardSigningNotification>,
    reward_signing_notification_stream: SubspaceNotificationStream<RewardSigningNotification>,
    archived_segment_notification_sender: SubspaceNotificationSender<ArchivedSegmentNotification>,
    archived_segment_notification_stream: SubspaceNotificationStream<ArchivedSegmentNotification>,
    block_importing_notification_sender:
        SubspaceNotificationSender<BlockImportingNotification<Block>>,
    block_importing_notification_stream:
        SubspaceNotificationStream<BlockImportingNotification<Block>>,
    /// Segment headers that are expected to appear in the corresponding blocks, used for block
    /// production and validation
    segment_headers: Arc<Mutex<LruCache<NumberFor<Block>, Vec<SegmentHeader>>>>,
    kzg: Kzg,
}

impl<Block: BlockT> SubspaceLink<Block> {
    /// Get the slot duration from this link.
    pub fn slot_duration(&self) -> SlotDuration {
        self.slot_duration
    }

    /// Get stream with notifications about new slot arrival with ability to send solution back.
    pub fn new_slot_notification_stream(&self) -> SubspaceNotificationStream<NewSlotNotification> {
        self.new_slot_notification_stream.clone()
    }

    /// A stream with notifications about headers that need to be signed with ability to send
    /// signature back.
    pub fn reward_signing_notification_stream(
        &self,
    ) -> SubspaceNotificationStream<RewardSigningNotification> {
        self.reward_signing_notification_stream.clone()
    }

    /// Get stream with notifications about archived segment creation
    pub fn archived_segment_notification_stream(
        &self,
    ) -> SubspaceNotificationStream<ArchivedSegmentNotification> {
        self.archived_segment_notification_stream.clone()
    }

    /// Get stream with notifications about each imported block right BEFORE import actually
    /// happens.
    ///
    /// NOTE: all Subspace checks have already happened for this block, but block can still
    /// potentially fail to import in Substrate's internals.
    pub fn block_importing_notification_stream(
        &self,
    ) -> SubspaceNotificationStream<BlockImportingNotification<Block>> {
        self.block_importing_notification_stream.clone()
    }

    /// Get blocks that are expected to be included at specified block number.
    pub fn segment_headers_for_block(&self, block_number: NumberFor<Block>) -> Vec<SegmentHeader> {
        self.segment_headers
            .lock()
            .peek(&block_number)
            .cloned()
            .unwrap_or_default()
    }

    /// Access KZG instance
    pub fn kzg(&self) -> &Kzg {
        &self.kzg
    }
}

/// A block-import handler for Subspace.
pub struct SubspaceBlockImport<PosTable, Block, Client, I, CIDP, AS>
where
    Block: BlockT,
{
    inner: I,
    client: Arc<Client>,
    subspace_link: SubspaceLink<Block>,
    create_inherent_data_providers: CIDP,
    chain_constants: ChainConstants,
    segment_headers_store: SegmentHeadersStore<AS>,
    pot_verifier: PotVerifier,
    _pos_table: PhantomData<PosTable>,
}

impl<PosTable, Block, I, Client, CIDP, AS> Clone
    for SubspaceBlockImport<PosTable, Block, Client, I, CIDP, AS>
where
    Block: BlockT,
    I: Clone,
    CIDP: Clone,
{
    fn clone(&self) -> Self {
        SubspaceBlockImport {
            inner: self.inner.clone(),
            client: self.client.clone(),
            subspace_link: self.subspace_link.clone(),
            create_inherent_data_providers: self.create_inherent_data_providers.clone(),
            chain_constants: self.chain_constants,
            segment_headers_store: self.segment_headers_store.clone(),
            pot_verifier: self.pot_verifier.clone(),
            _pos_table: PhantomData,
        }
    }
}

impl<PosTable, Block, Client, I, CIDP, AS> SubspaceBlockImport<PosTable, Block, Client, I, CIDP, AS>
where
    PosTable: Table,
    Block: BlockT,
    Client: ProvideRuntimeApi<Block> + BlockBackend<Block> + HeaderBackend<Block> + AuxStore,
    Client::Api: BlockBuilderApi<Block> + SubspaceApi<Block, FarmerPublicKey> + ApiExt<Block>,
    CIDP: CreateInherentDataProviders<Block, SubspaceLink<Block>> + Send + Sync + 'static,
    AS: AuxStore + Send + Sync + 'static,
    BlockNumber: From<<<Block as BlockT>::Header as HeaderT>::Number>,
{
    fn new(
        client: Arc<Client>,
        block_import: I,
        subspace_link: SubspaceLink<Block>,
        create_inherent_data_providers: CIDP,
        chain_constants: ChainConstants,
        segment_headers_store: SegmentHeadersStore<AS>,
        pot_verifier: PotVerifier,
    ) -> Self {
        Self {
            client,
            inner: block_import,
            subspace_link,
            create_inherent_data_providers,
            chain_constants,
            segment_headers_store,
            pot_verifier,
            _pos_table: PhantomData,
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn block_import_verification(
        &self,
        block_hash: Block::Hash,
        header: Block::Header,
        extrinsics: Option<Vec<Block::Extrinsic>>,
        root_plot_public_key: &Option<FarmerPublicKey>,
        subspace_digest_items: &SubspaceDigestItems<
            FarmerPublicKey,
            FarmerPublicKey,
            FarmerSignature,
        >,
        justifications: &Option<Justifications>,
        skip_runtime_access: bool,
    ) -> Result<(), Error<Block::Header>> {
        let block_number = *header.number();
        let parent_hash = *header.parent_hash();

        let pre_digest = &subspace_digest_items.pre_digest;
        if let Some(root_plot_public_key) = root_plot_public_key {
            if &pre_digest.solution().public_key != root_plot_public_key {
                // Only root plot public key is allowed.
                return Err(Error::OnlyRootPlotPublicKeyAllowed);
            }
        }

        // Check if farmer's plot is burned.
        if self
            .client
            .runtime_api()
            .is_in_block_list(parent_hash, &pre_digest.solution().public_key)
            .or_else(|error| {
                if skip_runtime_access {
                    Ok(false)
                } else {
                    Err(Error::<Block::Header>::RuntimeApi(error))
                }
            })?
        {
            warn!(
                target: "subspace",
                "Ignoring block with solution provided by farmer in block list: {}",
                pre_digest.solution().public_key
            );

            return Err(Error::FarmerInBlockList(
                pre_digest.solution().public_key.clone(),
            ));
        }

        let parent_header = self
            .client
            .header(parent_hash)?
            .ok_or(Error::ParentUnavailable(parent_hash, block_hash))?;

        let parent_slot = extract_pre_digest(&parent_header).map(|d| d.slot())?;

        // Make sure that slot number is strictly increasing
        if pre_digest.slot() <= parent_slot {
            return Err(Error::SlotMustIncrease(parent_slot, pre_digest.slot()));
        }

        let parent_subspace_digest_items = if block_number.is_one() {
            None
        } else {
            Some(extract_subspace_digest_items::<
                _,
                FarmerPublicKey,
                FarmerPublicKey,
                FarmerSignature,
            >(&parent_header)?)
        };

        let correct_solution_range = if block_number.is_one() {
            slot_worker::extract_solution_ranges_for_block(self.client.as_ref(), parent_hash)?.0
        } else {
            let parent_subspace_digest_items = parent_subspace_digest_items
                .as_ref()
                .expect("Always Some for non-first block; qed");

            match parent_subspace_digest_items.next_solution_range {
                Some(solution_range) => solution_range,
                None => parent_subspace_digest_items.solution_range,
            }
        };

        if subspace_digest_items.solution_range != correct_solution_range {
            return Err(Error::InvalidSolutionRange(block_hash));
        }

        // For PoT justifications we only need to check the seed and number of checkpoints, the rest
        // was already checked during stateless block verification.
        {
            let Some(subspace_justification) = justifications
                .as_ref()
                .and_then(|justifications| {
                    justifications
                        .iter()
                        .find_map(SubspaceJustification::try_from_justification)
                })
                .transpose()
                .map_err(Error::InvalidSubspaceJustification)?
            else {
                return Err(Error::MissingSubspaceJustification);
            };

            let SubspaceJustification::PotCheckpoints { seed, checkpoints } =
                subspace_justification;

            let future_slot = pre_digest.slot() + self.chain_constants.block_authoring_delay();

            if block_number.is_one() {
                // In case of first block seed must match genesis seed
                if seed != self.pot_verifier.genesis_seed() {
                    return Err(Error::InvalidSubspaceJustificationContents);
                }

                // Number of checkpoints must match future slot number
                if checkpoints.len() as u64 != *future_slot {
                    return Err(Error::InvalidSubspaceJustificationContents);
                }
            } else {
                let parent_subspace_digest_items = parent_subspace_digest_items
                    .as_ref()
                    .expect("Always Some for non-first block; qed");

                let parent_future_slot = parent_slot + self.chain_constants.block_authoring_delay();

                let correct_input_parameters = PotNextSlotInput::derive(
                    subspace_digest_items.pot_slot_iterations,
                    parent_future_slot,
                    parent_subspace_digest_items
                        .pre_digest
                        .pot_info()
                        .future_proof_of_time(),
                    &subspace_digest_items.pot_parameters_change,
                );

                if seed != correct_input_parameters.seed {
                    return Err(Error::InvalidSubspaceJustificationContents);
                }

                // Number of checkpoints must match number of proofs that were not yet seen on chain
                if checkpoints.len() as u64 != (*future_slot - *parent_future_slot) {
                    return Err(Error::InvalidSubspaceJustificationContents);
                }
            }
        }

        let sector_id = SectorId::new(
            PublicKey::from(&pre_digest.solution().public_key).hash(),
            pre_digest.solution().sector_index,
        );

        // TODO: Below `skip_runtime_access` has no impact on this, but ideally it
        //  should (though we don't support fast sync yet, so doesn't matter in
        //  practice)
        let max_pieces_in_sector = self
            .client
            .runtime_api()
            .max_pieces_in_sector(parent_hash)?;
        let piece_index = sector_id.derive_piece_index(
            pre_digest.solution().piece_offset,
            pre_digest.solution().history_size,
            max_pieces_in_sector,
            self.chain_constants.recent_segments(),
            self.chain_constants.recent_history_fraction(),
        );
        let segment_index = piece_index.segment_index();

        let segment_commitment = self
            .segment_headers_store
            .get_segment_header(segment_index)
            .map(|segment_header| segment_header.segment_commitment())
            .ok_or(Error::SegmentCommitmentNotFound(segment_index))?;

        let sector_expiration_check_segment_commitment = self
            .segment_headers_store
            .get_segment_header(
                subspace_digest_items
                    .pre_digest
                    .solution()
                    .history_size
                    .sector_expiration_check(self.chain_constants.min_sector_lifetime())
                    .ok_or(Error::InvalidHistorySize)?
                    .segment_index(),
            )
            .map(|segment_header| segment_header.segment_commitment());

        // Piece is not checked during initial block verification because it requires access to
        // segment header and runtime, check it now.
        subspace_verification::verify_solution::<PosTable, _, _>(
            pre_digest.solution(),
            // Slot was already checked during initial block verification
            pre_digest.slot().into(),
            &VerifySolutionParams {
                proof_of_time: subspace_digest_items.pre_digest.pot_info().proof_of_time(),
                solution_range: subspace_digest_items.solution_range,
                piece_check_params: Some(PieceCheckParams {
                    max_pieces_in_sector,
                    segment_commitment,
                    recent_segments: self.chain_constants.recent_segments(),
                    recent_history_fraction: self.chain_constants.recent_history_fraction(),
                    min_sector_lifetime: self.chain_constants.min_sector_lifetime(),
                    // TODO: Below `skip_runtime_access` has no impact on this, but ideally it
                    //  should (though we don't support fast sync yet, so doesn't matter in
                    //  practice)
                    current_history_size: self.client.runtime_api().history_size(parent_hash)?,
                    sector_expiration_check_segment_commitment,
                }),
            },
            &self.subspace_link.kzg,
        )
        .map_err(|error| VerificationError::VerificationError(pre_digest.slot(), error))?;

        if !skip_runtime_access {
            // If the body is passed through, we need to use the runtime to check that the
            // internally-set timestamp in the inherents actually matches the slot set in the seal
            // and segment headers in the inherents are set correctly.
            if let Some(extrinsics) = extrinsics {
                let create_inherent_data_providers = self
                    .create_inherent_data_providers
                    .create_inherent_data_providers(parent_hash, self.subspace_link.clone())
                    .await
                    .map_err(|error| Error::Client(sp_blockchain::Error::from(error)))?;

                let inherent_data = create_inherent_data_providers
                    .create_inherent_data()
                    .await
                    .map_err(Error::CreateInherents)?;

                let inherent_res = self.client.runtime_api().check_inherents(
                    parent_hash,
                    Block::new(header, extrinsics),
                    inherent_data,
                )?;

                if !inherent_res.ok() {
                    for (i, e) in inherent_res.into_errors() {
                        match create_inherent_data_providers
                            .try_handle_error(&i, &e)
                            .await
                        {
                            Some(res) => res.map_err(Error::CheckInherents)?,
                            None => return Err(Error::CheckInherentsUnhandled(i)),
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

#[async_trait::async_trait]
impl<PosTable, Block, Client, Inner, CIDP, AS> BlockImport<Block>
    for SubspaceBlockImport<PosTable, Block, Client, Inner, CIDP, AS>
where
    PosTable: Table,
    Block: BlockT,
    Inner: BlockImport<Block, Error = ConsensusError> + Send + Sync,
    Inner::Error: Into<ConsensusError>,
    Client: ProvideRuntimeApi<Block>
        + BlockBackend<Block>
        + HeaderBackend<Block>
        + AuxStore
        + Send
        + Sync,
    Client::Api: BlockBuilderApi<Block> + SubspaceApi<Block, FarmerPublicKey> + ApiExt<Block>,
    CIDP: CreateInherentDataProviders<Block, SubspaceLink<Block>> + Send + Sync + 'static,
    AS: AuxStore + Send + Sync + 'static,
    BlockNumber: From<<<Block as BlockT>::Header as HeaderT>::Number>,
{
    type Error = ConsensusError;

    async fn import_block(
        &mut self,
        mut block: BlockImportParams<Block>,
    ) -> Result<ImportResult, Self::Error> {
        let block_hash = block.post_hash();
        let block_number = *block.header.number();

        // Early exit if block already in chain
        match self.client.status(block_hash) {
            Ok(sp_blockchain::BlockStatus::InChain) => {
                block.fork_choice = Some(ForkChoiceStrategy::Custom(false));
                return self.inner.import_block(block).await.map_err(Into::into);
            }
            Ok(sp_blockchain::BlockStatus::Unknown) => {}
            Err(error) => return Err(ConsensusError::ClientImport(error.to_string())),
        }

        let subspace_digest_items = extract_subspace_digest_items(&block.header)
            .map_err(|error| ConsensusError::ClientImport(error.to_string()))?;
        let skip_execution_checks = block.state_action.skip_execution_checks();

        let root_plot_public_key = self
            .client
            .runtime_api()
            .root_plot_public_key(*block.header.parent_hash())
            .map_err(Error::<Block::Header>::RuntimeApi)
            .map_err(|e| ConsensusError::ClientImport(e.to_string()))?;

        self.block_import_verification(
            block_hash,
            block.header.clone(),
            block.body.clone(),
            &root_plot_public_key,
            &subspace_digest_items,
            &block.justifications,
            skip_execution_checks,
        )
        .await
        .map_err(|error| ConsensusError::ClientImport(error.to_string()))?;

        let parent_weight = if block_number.is_one() {
            0
        } else {
            aux_schema::load_block_weight(self.client.as_ref(), block.header.parent_hash())
                .map_err(|e| ConsensusError::ClientImport(e.to_string()))?
                .ok_or_else(|| {
                    ConsensusError::ClientImport(
                        Error::<Block::Header>::ParentBlockNoAssociatedWeight(block_hash)
                            .to_string(),
                    )
                })?
        };

        let added_weight = calculate_block_weight(subspace_digest_items.solution_range);
        let total_weight = parent_weight + added_weight;

        aux_schema::write_block_weight(block_hash, total_weight, |values| {
            block
                .auxiliary
                .extend(values.iter().map(|(k, v)| (k.to_vec(), Some(v.to_vec()))))
        });

        for (&segment_index, segment_commitment) in &subspace_digest_items.segment_commitments {
            let found_segment_commitment = self
                .segment_headers_store
                .get_segment_header(segment_index)
                .ok_or_else(|| {
                    ConsensusError::ClientImport(format!(
                        "Segment header for index {segment_index} not found"
                    ))
                })?
                .segment_commitment();

            if &found_segment_commitment != segment_commitment {
                warn!(
                    target: "subspace",
                    "Different segment commitment for segment index {} was found in storage, \
                    likely fork below archiving point. expected {:?}, found {:?}",
                    segment_index,
                    segment_commitment,
                    found_segment_commitment
                );
                return Err(ConsensusError::ClientImport(
                    Error::<Block::Header>::DifferentSegmentCommitment(segment_index).to_string(),
                ));
            }
        }

        // The fork choice rule is that we pick the heaviest chain (i.e. smallest solution range),
        // if there's a tie we go with the longest chain
        let fork_choice = {
            let info = self.client.info();

            let last_best_weight = if &info.best_hash == block.header.parent_hash() {
                // the parent=genesis case is already covered for loading parent weight, so we don't
                // need to cover again here
                parent_weight
            } else {
                aux_schema::load_block_weight(&*self.client, info.best_hash)
                    .map_err(|e| ConsensusError::ChainLookup(e.to_string()))?
                    .ok_or_else(|| {
                        ConsensusError::ChainLookup(
                            "No block weight for parent header.".to_string(),
                        )
                    })?
            };

            ForkChoiceStrategy::Custom(total_weight > last_best_weight)
        };
        block.fork_choice = Some(fork_choice);

        let (acknowledgement_sender, mut acknowledgement_receiver) = mpsc::channel(0);

        self.subspace_link
            .block_importing_notification_sender
            .notify(move || BlockImportingNotification {
                block_number,
                acknowledgement_sender,
            });

        while (acknowledgement_receiver.next().await).is_some() {
            // Wait for all the acknowledgements to finish.
        }

        self.inner.import_block(block).await
    }

    async fn check_block(
        &self,
        block: BlockCheckParams<Block>,
    ) -> Result<ImportResult, Self::Error> {
        self.inner.check_block(block).await.map_err(Into::into)
    }
}

/// Produce a Subspace block-import object to be used later on in the construction of an
/// import-queue.
///
/// Also returns a link object used to correctly instantiate the import queue and background worker.
#[allow(clippy::type_complexity)]
pub fn block_import<PosTable, Client, Block, I, CIDP, AS>(
    slot_duration: SlotDuration,
    block_import_inner: I,
    client: Arc<Client>,
    kzg: Kzg,
    create_inherent_data_providers: CIDP,
    segment_headers_store: SegmentHeadersStore<AS>,
    pot_verifier: PotVerifier,
) -> Result<
    (
        SubspaceBlockImport<PosTable, Block, Client, I, CIDP, AS>,
        SubspaceLink<Block>,
    ),
    sp_blockchain::Error,
>
where
    PosTable: Table,
    Block: BlockT,
    Client: ProvideRuntimeApi<Block> + BlockBackend<Block> + HeaderBackend<Block> + AuxStore,
    Client::Api: BlockBuilderApi<Block> + SubspaceApi<Block, FarmerPublicKey>,
    CIDP: CreateInherentDataProviders<Block, SubspaceLink<Block>> + Send + Sync + 'static,
    AS: AuxStore + Send + Sync + 'static,
    BlockNumber: From<<<Block as BlockT>::Header as HeaderT>::Number>,
{
    let (new_slot_notification_sender, new_slot_notification_stream) =
        notification::channel("subspace_new_slot_notification_stream");
    let (reward_signing_notification_sender, reward_signing_notification_stream) =
        notification::channel("subspace_reward_signing_notification_stream");
    let (archived_segment_notification_sender, archived_segment_notification_stream) =
        notification::channel("subspace_archived_segment_notification_stream");
    let (block_importing_notification_sender, block_importing_notification_stream) =
        notification::channel("subspace_block_importing_notification_stream");

    let chain_constants = client
        .runtime_api()
        .chain_constants(client.info().best_hash)?;

    let link = SubspaceLink {
        slot_duration,
        new_slot_notification_sender,
        new_slot_notification_stream,
        reward_signing_notification_sender,
        reward_signing_notification_stream,
        archived_segment_notification_sender,
        archived_segment_notification_stream,
        block_importing_notification_sender,
        block_importing_notification_stream,
        // TODO: Consider making `confirmation_depth_k` non-zero
        segment_headers: Arc::new(Mutex::new(LruCache::new(
            NonZeroUsize::new(
                (FINALIZATION_DEPTH_IN_SEGMENTS + 1)
                    .max(chain_constants.confirmation_depth_k() as usize),
            )
            .expect("Confirmation depth of zero is not supported"),
        ))),
        kzg,
    };

    let import = SubspaceBlockImport::new(
        client,
        block_import_inner,
        link.clone(),
        create_inherent_data_providers,
        chain_constants,
        segment_headers_store,
        pot_verifier,
    );

    Ok((import, link))
}
