use std::sync::Arc;

use super::{
    LeaseApproval, LeaseCompletion, LeaseFinalization, LeaseVerifier, ScopeApproval, ScopeVerifier,
};
use crate::Digest;
use crate::ipc::{DenialCode, DispatchReceipt, DispatchRequest};

impl<T> ScopeVerifier for Arc<T>
where
    T: ScopeVerifier + ?Sized,
{
    fn verify(&self, request: &DispatchRequest) -> Result<ScopeApproval, DenialCode> {
        self.as_ref().verify(request)
    }

    fn register_dispatch(
        &self,
        request: &DispatchRequest,
        approval: &LeaseApproval,
    ) -> Result<(), DenialCode> {
        self.as_ref().register_dispatch(request, approval)
    }

    fn finish_dispatch(&self, approval: &LeaseApproval) -> Result<(), DenialCode> {
        self.as_ref().finish_dispatch(approval)
    }
}

impl<T> LeaseVerifier for Arc<T>
where
    T: LeaseVerifier + ?Sized,
{
    fn reserve(
        &self,
        request: &DispatchRequest,
        now_millis: u64,
    ) -> Result<LeaseApproval, DenialCode> {
        self.as_ref().reserve(request, now_millis)
    }

    fn abandon(&self, approval: &LeaseApproval) -> Result<(), DenialCode> {
        self.as_ref().abandon(approval)
    }

    fn finalize(
        &self,
        approval: &LeaseApproval,
        completion: LeaseCompletion,
    ) -> Result<LeaseFinalization, DenialCode> {
        self.as_ref().finalize(approval, completion)
    }

    fn authenticate_receipt(
        &self,
        approval: &LeaseApproval,
        receipt: &DispatchReceipt,
    ) -> Result<Digest, DenialCode> {
        self.as_ref().authenticate_receipt(approval, receipt)
    }
}
