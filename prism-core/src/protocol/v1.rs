use prost::Message;

use super::{DidStateRc, OperationProcessor, OperationProcessorVariants, ProcessError, ProtocolParameter};
use crate::crypto::Verifiable;
use crate::did::operation::{
    CreateOperation, DeactivateOperation, KeyUsage, PublicKeyData, PublicKeyId, UpdateOperation, UpdateOperationAction,
};
use crate::dlt::OperationMetadata;
use crate::proto::{
    CreateDidOperation, DeactivateDidOperation, ProtocolVersionUpdateOperation, SignedAtalaOperation,
    UpdateDidOperation,
};
use crate::utils::hash::sha256;

#[derive(Debug, Clone, Default)]
pub struct V1Processor {
    parameters: ProtocolParameter,
}

impl OperationProcessor for V1Processor {
    fn check_signature(&self, state: &DidStateRc, signed_operation: &SignedAtalaOperation) -> Result<(), ProcessError> {
        let key_id = PublicKeyId::parse(&signed_operation.signed_with, self.parameters.max_id_size)
            .map_err(|e| ProcessError::InvalidSignature(format!("signed_with key-id is invalid ({})", e)))?;

        let Some(pk) = state.public_keys.get(&key_id) else {
            Err(ProcessError::InvalidSignature(
                "signed_with is invalid (key not found)".to_string(),
            ))?
        };

        match &pk.get().data {
            PublicKeyData::Master { data } => {
                let signature = signed_operation.signature.as_slice();
                let message = signed_operation
                    .operation
                    .as_ref()
                    .ok_or(ProcessError::EmptyOperation)?
                    .encode_to_vec();

                if !data.verify(&message, signature) {
                    Err(ProcessError::InvalidSignature(
                        "signature did not pass verification".to_string(),
                    ))?
                }
            }
            PublicKeyData::Other { .. } => Err(ProcessError::InvalidSignature(
                "signed_with is invalid (key is not MasterKey)".to_string(),
            ))?,
        }

        Ok(())
    }

    fn create_did(
        &self,
        state: &DidStateRc,
        operation: CreateDidOperation,
        metadata: OperationMetadata,
    ) -> Result<DidStateRc, ProcessError> {
        let parsed_operation = CreateOperation::parse(&self.parameters, &operation)?;

        // clone and mutate candidate state
        let mut candidate_state = state.clone();
        candidate_state.with_context(parsed_operation.context);
        candidate_state.with_last_operation_hash(state.did.suffix.clone());
        for pk in parsed_operation.public_keys {
            candidate_state
                .add_public_key(pk, &metadata)
                .map_err(ProcessError::DidStateConflict)?;
        }
        for service in parsed_operation.services {
            candidate_state
                .add_service(service, &metadata)
                .map_err(ProcessError::DidStateConflict)?;
        }

        CreateDidValidator::validate_candidate_state(&self.parameters, &candidate_state)?;
        Ok(candidate_state)
    }

    fn update_did(
        &self,
        state: &DidStateRc,
        operation: UpdateDidOperation,
        metadata: OperationMetadata,
    ) -> Result<DidStateRc, ProcessError> {
        let parsed_operation = UpdateOperation::parse(&self.parameters, &operation)?;
        if parsed_operation.prev_operation_hash != *state.last_operation_hash {
            Err(ProcessError::DidStateConflict(
                "prev_operation_hash is invalid".to_string(),
            ))?
        }

        // clone and mutate candidate state
        let mut candidate_state = state.clone();
        candidate_state.with_last_operation_hash(sha256(operation.encode_to_vec()));
        for action in parsed_operation.actions {
            apply_update_action(&mut candidate_state, action, &metadata).map_err(ProcessError::DidStateConflict)?;
        }

        UpdateDidValidator::validate_candidate_state(&self.parameters, &candidate_state)?;
        Ok(candidate_state)
    }

    fn deactivate_did(
        &self,
        state: &DidStateRc,
        operation: DeactivateDidOperation,
        metadata: OperationMetadata,
    ) -> Result<DidStateRc, ProcessError> {
        let parsed_operation = DeactivateOperation::parse(&operation)?;

        if parsed_operation.prev_operation_hash != *state.last_operation_hash {
            Err(ProcessError::DidStateConflict(
                "prev_operation_hash is invalid".to_string(),
            ))?
        }

        // clone and mutate candidate state
        let mut candidate_state = state.clone();
        candidate_state.with_last_operation_hash(sha256(operation.encode_to_vec()));
        for (id, _) in &state.public_keys {
            candidate_state
                .revoke_public_key(id, &metadata)
                .map_err(ProcessError::DidStateConflict)?;
        }
        for (id, _) in &state.services {
            candidate_state
                .revoke_service(id, &metadata)
                .map_err(ProcessError::DidStateConflict)?;
        }

        DeactivateDidValidator::validate_candidate_state(&self.parameters, &candidate_state)?;
        Ok(candidate_state)
    }

    fn protocol_version_update(
        &self,
        _: ProtocolVersionUpdateOperation,
        _: OperationMetadata,
    ) -> Result<OperationProcessorVariants, ProcessError> {
        // TODO: add support for protocol version update
        log::warn!("Protocol version update is not yet supported");
        Ok(self.clone().into())
    }
}

trait Validator<Op> {
    fn validate_candidate_state(param: &ProtocolParameter, state: &DidStateRc) -> Result<(), ProcessError>;
}

struct CreateDidValidator;
struct UpdateDidValidator;
struct DeactivateDidValidator;

impl Validator<CreateDidOperation> for CreateDidValidator {
    fn validate_candidate_state(_: &ProtocolParameter, _: &DidStateRc) -> Result<(), ProcessError> {
        Ok(())
    }
}

impl Validator<UpdateDidOperation> for UpdateDidValidator {
    fn validate_candidate_state(param: &ProtocolParameter, state: &DidStateRc) -> Result<(), ProcessError> {
        // check at least one master key exists
        let contains_master_key = state
            .public_keys
            .iter()
            .any(|(_, pk)| pk.get().usage() == KeyUsage::MasterKey);
        if !contains_master_key {
            Err(ProcessError::DidStateConflict(
                "At least one master key must exist after update".to_string(),
            ))?
        }

        // check public key count does not exceed limit
        if state.public_keys.len() > param.max_public_keys {
            Err(ProcessError::DidStateConflict(
                "Public key count exceeds limit".to_string(),
            ))?
        }

        // check service count does not exeed limit
        if state.services.len() > param.max_services {
            Err(ProcessError::DidStateConflict(
                "Service count exceeds limit".to_string(),
            ))?
        }

        Ok(())
    }
}

impl Validator<DeactivateDidOperation> for DeactivateDidValidator {
    fn validate_candidate_state(_: &ProtocolParameter, _: &DidStateRc) -> Result<(), ProcessError> {
        Ok(())
    }
}

fn apply_update_action(
    state: &mut DidStateRc,
    action: UpdateOperationAction,
    metadata: &OperationMetadata,
) -> Result<(), String> {
    match action {
        UpdateOperationAction::AddKey(pk) => state.add_public_key(pk, metadata)?,
        UpdateOperationAction::RemoveKey(id) => state.revoke_public_key(&id, metadata)?,
        UpdateOperationAction::AddService(service) => state.add_service(service, metadata)?,
        UpdateOperationAction::RemoveService(id) => state.revoke_service(&id, metadata)?,
        UpdateOperationAction::UpdateService {
            id,
            r#type,
            service_endpoints,
        } => {
            if let Some(t) = r#type {
                state.update_service_type(&id, t)?;
            }
            if let Some(ep) = service_endpoints {
                state.update_service_endpoint(&id, ep)?;
            }
        }
        UpdateOperationAction::PatchContext(ctx) => {
            state.with_context(ctx);
        }
    }

    Ok(())
}
