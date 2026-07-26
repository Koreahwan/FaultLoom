# FaultLoom privileged installation gate

This package is a non-installing handoff. It contains no installer, service registration, elevation request, or host-policy mutation.

Do not install or register these binaries without separate, explicit authorization for the target host, service identity, paths, ACLs, rollback procedure, and operator-visible confirmation.

The packaged manifest records `install_authorized:false`. Package verification does not change that value and does not authorize deployment.
