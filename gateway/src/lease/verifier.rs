use super::*;

impl LeaseVerifier for LeaseAuthority {
    fn reserve(
        &self,
        request: &DispatchRequest,
        now_millis: u64,
    ) -> Result<LeaseApproval, DenialCode> {
        self.reserve_dispatch(request, now_millis)
    }
    fn abandon(&self, approval: &LeaseApproval) -> Result<(), DenialCode> {
        self.abandon_dispatch(approval)
    }

    fn finalize(
        &self,
        approval: &LeaseApproval,
        completion: LeaseCompletion,
    ) -> Result<LeaseFinalization, DenialCode> {
        self.finalize_dispatch(approval, completion)
    }

    fn authenticate_receipt(
        &self,
        approval: &LeaseApproval,
        receipt: &DispatchReceipt,
    ) -> Result<Digest, DenialCode> {
        self.authenticate_dispatch_receipt(approval, receipt)
    }
}
