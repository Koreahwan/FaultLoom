mod persistence;
mod reconciliation_matching;

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::io;
use std::sync::{Arc, Mutex};

use crate::Digest;
use crate::ipc::{DenialCode, DispatchReceipt, DispatchRequest};
use crate::lease::LeaseAuthority;
use crate::policy::{CompiledAction, LeaseApproval, PreEgressBarrier, PreEgressBarrierError};

use self::persistence::empty_snapshot;
use self::reconciliation_matching::prepared_matches_receipt;
use super::supervisor_journal::{
    AcknowledgedResponseTombstone, JournalClient, JournalSnapshot, MAX_DURABLE_RESPONSE_SLOTS,
    PendingInnerResponse, PreparedDispatchBinding,
};
use super::supervisor_protocol::{
    ControlEgressDisposition, SupervisorControlReceipt, SupervisorReconciliation,
    SupervisorResponse,
};

#[derive(Debug)]
#[must_use]
pub(crate) enum DurableReconciliationError {
    Rejected {
        response_slot: ReservedResponseSlot,
        reason: DenialCode,
    },
    Terminal(io::Error),
}

#[derive(Debug)]
#[must_use]
pub(crate) enum ReconciliationAdmission {
    Ready(ReconciliationResponseSlot),
    Rejected {
        response_slot: ReservedResponseSlot,
        reason: DenialCode,
    },
}

#[derive(Debug)]
#[must_use]
pub(crate) enum ReconciliationResponseSlot {
    Fresh(ReservedResponseSlot),
    PreparedTransfer(PreparedResponseSlot),
}

#[must_use]
pub(crate) struct PreparedResponseSlot {
    state: Arc<Mutex<DurableState>>,
    request_envelope_id: Digest,
    prepared_control_envelope_id: Digest,
}

impl Drop for PreparedResponseSlot {
    fn drop(&mut self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state
            .claimed_prepared_response_slots
            .get(&self.prepared_control_envelope_id)
            == Some(&self.request_envelope_id)
        {
            state
                .claimed_prepared_response_slots
                .remove(&self.prepared_control_envelope_id);
        }
    }
}

impl fmt::Debug for PreparedResponseSlot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedResponseSlot")
            .field("request_envelope_id", &self.request_envelope_id)
            .field(
                "prepared_control_envelope_id",
                &self.prepared_control_envelope_id,
            )
            .finish_non_exhaustive()
    }
}

enum ReconciliationClassification {
    FreshReady,
    FreshRejected(DenialCode),
    PreparedTransfer(Digest),
}

struct DurableState {
    anchor: Option<Digest>,
    snapshot: Option<JournalSnapshot>,
    transient_response_reservations: HashSet<Digest>,
    claimed_prepared_response_slots: HashMap<Digest, Digest>,
}

#[must_use]
pub(crate) struct ReservedResponseSlot {
    state: Arc<Mutex<DurableState>>,
    request_envelope_id: Digest,
}

impl ReservedResponseSlot {
    pub(crate) const fn request_envelope_id(&self) -> Digest {
        self.request_envelope_id
    }

    fn belongs_to(&self, state: &Arc<Mutex<DurableState>>) -> bool {
        Arc::ptr_eq(&self.state, state)
    }
}

impl fmt::Debug for ReservedResponseSlot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReservedResponseSlot")
            .field("request_envelope_id", &self.request_envelope_id)
            .finish_non_exhaustive()
    }
}

impl Drop for ReservedResponseSlot {
    fn drop(&mut self) {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .transient_response_reservations
            .remove(&self.request_envelope_id);
    }
}

pub(crate) struct DurableSupervisorState {
    lease: Arc<LeaseAuthority>,
    journal: JournalClient,
    state: Arc<Mutex<DurableState>>,
}

impl DurableSupervisorState {
    pub(crate) fn new(
        lease: Arc<LeaseAuthority>,
        journal: JournalClient,
        anchor: Option<Digest>,
        snapshot: Option<JournalSnapshot>,
    ) -> Result<Self, DenialCode> {
        if anchor.is_some() != snapshot.is_some()
            || anchor == Some(Digest::ZERO)
            || snapshot.as_ref().is_some_and(|value| {
                value
                    .snapshot_digest()
                    .map_or(true, |digest| digest == Digest::ZERO)
            })
        {
            return Err(DenialCode::DurabilityAnchorMismatch);
        }
        Ok(Self {
            lease,
            journal,
            state: Arc::new(Mutex::new(DurableState {
                anchor,
                snapshot,
                transient_response_reservations: HashSet::new(),
                claimed_prepared_response_slots: HashMap::new(),
            })),
        })
    }

    pub(crate) fn reserve_fresh_response(
        &self,
        request_envelope_id: Digest,
    ) -> io::Result<ReservedResponseSlot> {
        if request_envelope_id == Digest::ZERO {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid response reservation identity",
            ));
        }
        let mut state = self.lock_state()?;
        if self.journal.is_terminal() {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "journal channel is terminal",
            ));
        }
        if state
            .snapshot
            .as_ref()
            .is_some_and(|snapshot| snapshot_contains_response_id(snapshot, request_envelope_id))
            || state
                .transient_response_reservations
                .contains(&request_envelope_id)
            || state
                .claimed_prepared_response_slots
                .values()
                .any(|claimed| *claimed == request_envelope_id)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "response reservation identity already exists",
            ));
        }
        let occupied = state
            .snapshot
            .as_ref()
            .map_or(Some(0), durable_response_slot_count)
            .and_then(|count| count.checked_add(state.transient_response_reservations.len()))
            .ok_or_else(|| io::Error::other("durable response slot count overflow"))?;
        if occupied >= MAX_DURABLE_RESPONSE_SLOTS {
            return Err(io::Error::other("durable response capacity exhausted"));
        }
        state
            .transient_response_reservations
            .insert(request_envelope_id);
        Ok(ReservedResponseSlot {
            state: Arc::clone(&self.state),
            request_envelope_id,
        })
    }

    pub(crate) fn admit_reconciliation(
        &self,
        request_envelope_id: Digest,
        reconciliation: &SupervisorReconciliation,
    ) -> io::Result<ReconciliationAdmission> {
        if request_envelope_id == Digest::ZERO {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid reconciliation response identity",
            ));
        }
        let classification = {
            let mut state = self.lock_state()?;
            if self.journal.is_terminal() {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "journal channel is terminal",
                ));
            }
            if state.snapshot.as_ref().is_some_and(|snapshot| {
                snapshot_contains_response_id(snapshot, request_envelope_id)
            }) || state
                .transient_response_reservations
                .contains(&request_envelope_id)
                || state
                    .claimed_prepared_response_slots
                    .values()
                    .any(|claimed| *claimed == request_envelope_id)
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "reconciliation response identity already exists",
                ));
            }
            if state
                .snapshot
                .as_ref()
                .is_some_and(|snapshot| !snapshot.pending_responses.is_empty())
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "pending response must be acknowledged before reconciliation",
                ));
            }
            match state.snapshot.as_ref() {
                Some(snapshot) if state.anchor.is_some() => {
                    match self.inspect_reconciliation(snapshot, reconciliation) {
                        Ok((_, matches)) => match matches.as_slice() {
                            [index] => {
                                let prepared_control_envelope_id =
                                    snapshot.prepared_dispatches[*index].control_envelope_id;
                                if state
                                    .claimed_prepared_response_slots
                                    .contains_key(&prepared_control_envelope_id)
                                {
                                    return Err(io::Error::new(
                                        io::ErrorKind::WouldBlock,
                                        "prepared response slot is already claimed",
                                    ));
                                }
                                state
                                    .claimed_prepared_response_slots
                                    .insert(prepared_control_envelope_id, request_envelope_id);
                                ReconciliationClassification::PreparedTransfer(
                                    prepared_control_envelope_id,
                                )
                            }
                            [] => ReconciliationClassification::FreshReady,
                            _ => ReconciliationClassification::FreshRejected(
                                DenialCode::RecoveryCheckpointInvalid,
                            ),
                        },
                        Err(reason) => ReconciliationClassification::FreshRejected(reason),
                    }
                }
                _ => ReconciliationClassification::FreshRejected(
                    DenialCode::DurabilityAnchorMismatch,
                ),
            }
        };
        match classification {
            ReconciliationClassification::FreshReady => self
                .reserve_fresh_response(request_envelope_id)
                .map(ReconciliationResponseSlot::Fresh)
                .map(ReconciliationAdmission::Ready),
            ReconciliationClassification::FreshRejected(reason) => self
                .reserve_fresh_response(request_envelope_id)
                .map(|response_slot| ReconciliationAdmission::Rejected {
                    response_slot,
                    reason,
                }),
            ReconciliationClassification::PreparedTransfer(prepared_control_envelope_id) => {
                Ok(ReconciliationAdmission::Ready(
                    ReconciliationResponseSlot::PreparedTransfer(PreparedResponseSlot {
                        state: Arc::clone(&self.state),
                        request_envelope_id,
                        prepared_control_envelope_id,
                    }),
                ))
            }
        }
    }

    pub(crate) fn persist_response(
        &self,
        response_slot: ReservedResponseSlot,
        completed_receipt: Option<&DispatchReceipt>,
        inner_response: Vec<u8>,
    ) -> io::Result<Digest> {
        let original_request_envelope_id = response_slot.request_envelope_id();
        if original_request_envelope_id == Digest::ZERO || inner_response.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid pending response binding",
            ));
        }
        if let Some(receipt) = completed_receipt {
            self.lease
                .verify_dispatch_receipt(receipt)
                .map_err(|reason| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("invalid completed dispatch receipt: {reason:?}"),
                    )
                })?;
        }
        let response_digest = Digest::of(&inner_response);
        if !response_slot.belongs_to(&self.state) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "response reservation belongs to another durable state",
            ));
        }
        let mut state = self.lock_state()?;
        if self.journal.is_terminal() {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "journal channel is terminal",
            ));
        }
        let mut next = state.snapshot.clone().unwrap_or_else(empty_snapshot);
        if snapshot_contains_response_id(&next, original_request_envelope_id) {
            let prepared_match = completed_receipt.is_some_and(|receipt| {
                next.prepared_dispatches.iter().any(|binding| {
                    binding.control_envelope_id == original_request_envelope_id
                        && prepared_matches_receipt(binding, receipt)
                })
            });
            if !prepared_match {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "response reservation identity already became durable",
                ));
            }
        }
        match completed_receipt {
            Some(receipt) => {
                if state
                    .transient_response_reservations
                    .contains(&original_request_envelope_id)
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "completed dispatch response was not prepared",
                    ));
                }
                let matches = next
                    .prepared_dispatches
                    .iter()
                    .enumerate()
                    .filter_map(|(index, binding)| {
                        (binding.control_envelope_id == original_request_envelope_id
                            && prepared_matches_receipt(binding, receipt))
                        .then_some(index)
                    })
                    .collect::<Vec<_>>();
                if matches.len() != 1 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "completed receipt does not match one prepared dispatch",
                    ));
                }
                next.prepared_dispatches.remove(matches[0]);
            }
            None => {
                if !state
                    .transient_response_reservations
                    .contains(&original_request_envelope_id)
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "response was not reserved before mutation",
                    ));
                }
            }
        }
        next.pending_responses.push(PendingInnerResponse {
            original_request_envelope_id,
            inner_response_digest: response_digest,
            inner_response,
        });
        self.commit_next(&mut state, next)?;
        state
            .transient_response_reservations
            .remove(&original_request_envelope_id);
        Ok(response_digest)
    }

    pub(crate) fn reconcile_hold(
        &self,
        response_slot: ReconciliationResponseSlot,
        reconciliation: &SupervisorReconciliation,
    ) -> Result<Vec<u8>, DurableReconciliationError> {
        let (original_request_envelope_id, prepared_control_envelope_id, fresh_slot, prepared_slot) =
            match response_slot {
                ReconciliationResponseSlot::Fresh(response_slot) => (
                    response_slot.request_envelope_id(),
                    None,
                    Some(response_slot),
                    None,
                ),
                ReconciliationResponseSlot::PreparedTransfer(response_slot) => {
                    if !Arc::ptr_eq(&response_slot.state, &self.state) {
                        return Err(DurableReconciliationError::Terminal(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "reconciliation slot belongs to another durable state",
                        )));
                    }
                    (
                        response_slot.request_envelope_id,
                        Some(response_slot.prepared_control_envelope_id),
                        None,
                        Some(response_slot),
                    )
                }
            };
        let mut state = self
            .lock_state()
            .map_err(DurableReconciliationError::Terminal)?;
        if self.journal.is_terminal() {
            return Err(DurableReconciliationError::Terminal(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "journal channel is terminal",
            )));
        }
        let mut next = state.snapshot.clone().ok_or_else(|| {
            DurableReconciliationError::Terminal(io::Error::new(
                io::ErrorKind::InvalidData,
                "reconciliation admission lost its journal snapshot",
            ))
        })?;
        if state.anchor.is_none() {
            return Err(DurableReconciliationError::Terminal(io::Error::new(
                io::ErrorKind::InvalidData,
                "reconciliation admission lost its journal anchor",
            )));
        }
        if !next.pending_responses.is_empty() {
            return Err(DurableReconciliationError::Terminal(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "pending response appeared after reconciliation admission",
            )));
        }
        let (journal_anchor, journal_snapshot) =
            self.journal.open(state.anchor).map_err(|error| {
                self.journal.mark_terminal();
                DurableReconciliationError::Terminal(error)
            })?;
        if journal_anchor != state.anchor || journal_snapshot.as_ref() != state.snapshot.as_ref() {
            self.journal.mark_terminal();
            return Err(DurableReconciliationError::Terminal(io::Error::new(
                io::ErrorKind::InvalidData,
                "journal state is stale",
            )));
        }

        let (reconciliation_id, prepared_matches) = self
            .inspect_reconciliation(&next, reconciliation)
            .map_err(|reason| {
                DurableReconciliationError::Terminal(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("reconciliation changed after admission: {reason:?}"),
                ))
            })?;
        match (prepared_control_envelope_id, prepared_matches.as_slice()) {
            (None, [])
                if fresh_slot.as_ref().is_some_and(|response_slot| {
                    response_slot.belongs_to(&self.state)
                        && state
                            .transient_response_reservations
                            .contains(&original_request_envelope_id)
                }) => {}
            (Some(expected), [index])
                if next.prepared_dispatches[*index].control_envelope_id == expected
                    && prepared_slot.is_some()
                    && state.claimed_prepared_response_slots.get(&expected)
                        == Some(&original_request_envelope_id) => {}
            _ => {
                return Err(DurableReconciliationError::Terminal(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "reconciliation response slot no longer matches durable state",
                )));
            }
        }
        let removed_prepared_dispatches = u64::try_from(prepared_matches.len()).map_err(|_| {
            DurableReconciliationError::Terminal(io::Error::new(
                io::ErrorKind::InvalidData,
                "prepared reconciliation count overflow",
            ))
        })?;
        let response = SupervisorResponse::Control(SupervisorControlReceipt::HoldReconciled {
            reconciliation_id,
            removed_prepared_dispatches,
            egress_disposition: ControlEgressDisposition::NoActiveEgress,
        });
        let inner_response = response.to_bytes().map_err(|reason| {
            DurableReconciliationError::Terminal(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("cannot encode reconciliation response: {reason:?}"),
            ))
        })?;

        let reconciliation_result = match reconciliation {
            SupervisorReconciliation::DispatchReceipt {
                unknown_receipt,
                reconciliation,
            } => self.lease.reconcile(unknown_receipt, reconciliation),
            SupervisorReconciliation::ControlPlane { reconciliation } => {
                self.lease.reconcile_control_plane_hold(reconciliation)
            }
        };
        if let Err(reason) = reconciliation_result {
            drop(state);
            let response_slot = match fresh_slot {
                Some(response_slot) => response_slot,
                None => {
                    drop(prepared_slot);
                    self.reserve_fresh_response(original_request_envelope_id)
                        .map_err(DurableReconciliationError::Terminal)?
                }
            };
            return Err(DurableReconciliationError::Rejected {
                response_slot,
                reason,
            });
        }
        for index in prepared_matches.into_iter().rev() {
            next.prepared_dispatches.remove(index);
        }
        next.pending_responses.push(PendingInnerResponse {
            original_request_envelope_id,
            inner_response_digest: Digest::of(&inner_response),
            inner_response: inner_response.clone(),
        });
        self.commit_next(&mut state, next)
            .map_err(DurableReconciliationError::Terminal)?;
        state
            .transient_response_reservations
            .remove(&original_request_envelope_id);
        if let Some(prepared_control_envelope_id) = prepared_control_envelope_id {
            state
                .claimed_prepared_response_slots
                .remove(&prepared_control_envelope_id);
        }
        Ok(inner_response)
    }

    pub(crate) fn pending_response(
        &self,
        original_request_envelope_id: Digest,
    ) -> io::Result<Option<PendingInnerResponse>> {
        let state = self.lock_state()?;
        Ok(state.snapshot.as_ref().and_then(|snapshot| {
            snapshot
                .pending_responses
                .iter()
                .find(|pending| {
                    pending.original_request_envelope_id == original_request_envelope_id
                })
                .cloned()
        }))
    }

    pub(crate) fn has_pending_responses(&self) -> io::Result<bool> {
        let state = self.lock_state()?;
        Ok(state
            .snapshot
            .as_ref()
            .is_some_and(|snapshot| !snapshot.pending_responses.is_empty()))
    }

    pub(crate) fn acknowledge_response(
        &self,
        original_request_envelope_id: Digest,
        response_digest: Digest,
    ) -> io::Result<()> {
        let mut state = self.lock_state()?;
        if self.journal.is_terminal() {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "journal channel is terminal",
            ));
        }
        let Some(mut next) = state.snapshot.clone() else {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "response acknowledgement binding not found",
            ));
        };
        if let Some(index) = next.pending_responses.iter().position(|pending| {
            pending.original_request_envelope_id == original_request_envelope_id
        }) {
            if next.pending_responses[index].inner_response_digest != response_digest {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "response acknowledgement digest mismatch",
                ));
            }
            if next.acknowledged_responses.len() >= MAX_DURABLE_RESPONSE_SLOTS {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "acknowledged response capacity exhausted",
                ));
            }
            next.pending_responses.remove(index);
            next.acknowledged_responses
                .push(AcknowledgedResponseTombstone {
                    original_request_envelope_id,
                    inner_response_digest: response_digest,
                });
            return self.commit_next(&mut state, next);
        }
        match next.acknowledged_responses.iter().find(|acknowledged| {
            acknowledged.original_request_envelope_id == original_request_envelope_id
        }) {
            Some(acknowledged) if acknowledged.inner_response_digest == response_digest => Ok(()),
            Some(_) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "response acknowledgement digest mismatch",
            )),
            None => Err(io::Error::new(
                io::ErrorKind::NotFound,
                "response acknowledgement binding not found",
            )),
        }
    }

    fn persist_pre_egress(
        &self,
        request: &DispatchRequest,
        request_frame_digest: Digest,
        approval: &LeaseApproval,
        compiled: &CompiledAction,
    ) -> Result<(), PreEgressBarrierError> {
        let mut state = self.lock_state().map_err(PreEgressBarrierError::Terminal)?;
        if self.journal.is_terminal() {
            return Err(PreEgressBarrierError::Terminal(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "journal channel is terminal",
            )));
        }
        let mut next = state.snapshot.clone().unwrap_or_else(empty_snapshot);
        if !state
            .transient_response_reservations
            .contains(&approval.control_envelope_id)
        {
            return Err(PreEgressBarrierError::Terminal(io::Error::new(
                io::ErrorKind::InvalidData,
                "dispatch response was not reserved before pre-egress",
            )));
        }
        if !next.pending_responses.is_empty() {
            return Err(PreEgressBarrierError::Rejected(
                DenialCode::PendingResponseUnacknowledged,
            ));
        }
        if next
            .prepared_dispatches
            .iter()
            .any(|binding| binding.request_frame_digest == request_frame_digest)
        {
            return Err(PreEgressBarrierError::Rejected(
                DenialCode::DurabilityUnavailable,
            ));
        }
        next.prepared_dispatches.push(PreparedDispatchBinding {
            request_frame_digest,
            control_envelope_id: approval.control_envelope_id,
            hold_binding_digest: approval.hold_binding_digest,
            action_id: request.action_id.clone(),
            correlation_id: request.correlation_id.clone(),
            grant_id: request.grant_id.clone(),
            grant_version: request.grant_version,
            scope_epoch: request.scope_epoch,
            lease_id: approval.lease_id.clone(),
            intent_digest: request.intent_digest,
            effect_digest: approval.effect_digest,
            compiled_request_digest: Digest::of(&compiled.bytes),
        });
        self.commit_next(&mut state, next)
            .map_err(PreEgressBarrierError::Terminal)?;
        state
            .transient_response_reservations
            .remove(&approval.control_envelope_id);
        Ok(())
    }

    fn lock_state(&self) -> io::Result<std::sync::MutexGuard<'_, DurableState>> {
        self.state
            .lock()
            .map_err(|_| io::Error::other("durable supervisor state lock poisoned"))
    }
}

fn durable_response_slot_count(snapshot: &JournalSnapshot) -> Option<usize> {
    snapshot
        .prepared_dispatches
        .len()
        .checked_add(snapshot.pending_responses.len())?
        .checked_add(snapshot.acknowledged_responses.len())
}

fn snapshot_contains_response_id(snapshot: &JournalSnapshot, request_envelope_id: Digest) -> bool {
    snapshot
        .prepared_dispatches
        .iter()
        .any(|binding| binding.control_envelope_id == request_envelope_id)
        || snapshot
            .pending_responses
            .iter()
            .any(|pending| pending.original_request_envelope_id == request_envelope_id)
        || snapshot
            .acknowledged_responses
            .iter()
            .any(|acknowledged| acknowledged.original_request_envelope_id == request_envelope_id)
}

#[derive(Clone)]
pub(crate) struct DurablePreEgressBarrier {
    state: Arc<DurableSupervisorState>,
}

impl DurablePreEgressBarrier {
    pub(crate) const fn new(state: Arc<DurableSupervisorState>) -> Self {
        Self { state }
    }
}

impl PreEgressBarrier for DurablePreEgressBarrier {
    fn persist(
        &self,
        request: &DispatchRequest,
        request_frame_digest: Digest,
        approval: &LeaseApproval,
        compiled: &CompiledAction,
    ) -> Result<(), PreEgressBarrierError> {
        self.state
            .persist_pre_egress(request, request_frame_digest, approval, compiled)
    }
}

#[cfg(test)]
#[path = "supervisor_reconciliation_tests.rs"]
mod supervisor_reconciliation_tests;
