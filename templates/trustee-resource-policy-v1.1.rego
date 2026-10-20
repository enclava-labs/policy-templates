package policy

import rego.v1

default allow := false

# Template variables are rendered by the signing service only.
# CAP API never writes or edits this file directly.
expected_init_data_hash := "{{init_data_hash}}"
expected_image_digest := "{{image_digest}}"
expected_signer_subject := "{{signer_subject}}"
expected_signer_issuer := "{{signer_issuer}}"
expected_namespace := "{{namespace}}"
expected_service_account := "{{service_account}}"
expected_identity_hash := "{{identity_hash}}"
expected_resource_path := "{{kbs_resource_path}}"

allow if {
  data.plugin == "resource"
  data.method == "GET"
  attested_workload
  requested_resource_path_allowed
}

allow if {
  data.plugin == "workload-resource"
  data.method == "PUT"
  attested_workload
  requested_resource_path_allowed
  data.request.body.operation == "rekey"
  data.request.body.receipt.signature_valid
  data.request.body.receipt.pubkey_hash_matches
  data.request.body.receipt.payload.purpose == "enclava-rekey-v1"
  data.request.body.receipt.payload.resource_path == requested_resource_path
  data.request.body.value_hash_matches
}

allow if {
  data.plugin == "workload-resource"
  data.method == "DELETE"
  attested_workload
  requested_resource_path_allowed
  data.request.body.operation == "teardown"
  data.request.body.receipt.signature_valid
  data.request.body.receipt.pubkey_hash_matches
  data.request.body.receipt.payload.purpose == "enclava-teardown-v1"
  data.request.body.receipt.payload.resource_path == requested_resource_path
}

attested_workload if {
  expected_init_data_hash in claim_init_data_hashes
  expected_image_digest in claim_image_digests
  expected_signer_subject in claim_signer_subjects
  expected_signer_issuer in claim_signer_issuers
  expected_namespace in claim_namespaces
  expected_service_account in claim_service_accounts
  expected_identity_hash in claim_identity_hashes
  affirming_attestation
}

# v1.1: the verifier's appraisal verdict must hold before any release.
# ear.status is the EAR trust tier of a submod ("none", "affirming",
# "warning", "contraindicated"); anything short of affirming — including a
# token with no submods at all — denies. A warning is not good enough: it is
# how a measurement or reported-TCB mismatch is reported.
affirming_attestation if {
  count(object.get(input, "submods", {})) > 0
  every submod in object.get(input, "submods", {}) {
    submod["ear.status"] == "affirming"
  }
}

requested_resource_path := path if {
  rp := data["resource-path"]
  is_array(rp)
  path := concat("/", rp)
}

requested_resource_path := path if {
  rp := data["resource-path"]
  is_string(rp)
  path := trim(rp, "/")
}

requested_resource_path_allowed if {
  requested_resource_path in allowed_resource_paths
}

allowed_resource_paths contains expected_resource_path

allowed_resource_paths contains path if {
  path := owner_seed_sibling_path("seed-encrypted", "seed-sealed")
}

allowed_resource_paths contains path if {
  path := owner_seed_sibling_path("seed-sealed", "seed-encrypted")
}

owner_seed_sibling_path(from_tag, to_tag) := path if {
  parts := split(expected_resource_path, "/")
  count(parts) == 3
  endswith(parts[1], "-owner")
  parts[2] == from_tag
  path := concat("/", [parts[0], parts[1], to_tag])
}

claim_roots contains root if {
  root := input
}

claim_roots contains root if {
  root := object.get(input, "claims", {})
  is_object(root)
}

annotated_evidences contains ev if {
  some root in claim_roots
  cpu0 := object.get(object.get(root, "submods", {}), "cpu0", {})
  ev := object.get(cpu0, "ear.veraison.annotated-evidence", {})
  is_object(ev)
}

claim_init_data_hashes contains hash if {
  some root in claim_roots
  raw := object.get(object.get(root, "snp", {}), "init_data_hash", "")
  non_empty_string(raw)
  hash := lower(raw)
}

claim_init_data_hashes contains hash if {
  some root in claim_roots
  raw := object.get(root, "init_data_hash", "")
  non_empty_string(raw)
  hash := lower(raw)
}

claim_init_data_hashes contains hash if {
  some ev in annotated_evidences
  raw := object.get(ev, "init_data", "")
  non_empty_string(raw)
  hash := lower(raw)
}

claim_init_data_hashes contains hash if {
  some ev in annotated_evidences
  raw := object.get(ev, "init_data_hash", "")
  non_empty_string(raw)
  hash := lower(raw)
}

claim_init_data_hashes contains hash if {
  some root in claim_roots
  cpu0 := object.get(object.get(root, "submods", {}), "cpu0", {})
  raw := object.get(cpu0, "ear.veraison.annotated-evidence.init_data", "")
  non_empty_string(raw)
  hash := lower(raw)
}

init_data_claims_values contains idc if {
  some root in claim_roots
  idc := object.get(root, "init_data_claims", {})
  is_object(idc)
}

init_data_claims_values contains idc if {
  some ev in annotated_evidences
  idc := object.get(ev, "init_data_claims", {})
  is_object(idc)
}

init_data_claims_values contains idc if {
  some root in claim_roots
  cpu0 := object.get(object.get(root, "submods", {}), "cpu0", {})
  idc := object.get(cpu0, "ear.veraison.annotated-evidence.init_data_claims", {})
  is_object(idc)
}

init_data_claims_values contains idc if {
  some root in claim_roots
  cpu0 := object.get(object.get(root, "submods", {}), "cpu0", {})
  idc := object.get(cpu0, "init_data_claims", {})
  is_object(idc)
}

claim_image_digests contains value if {
  some idc in init_data_claims_values
  value := object.get(idc, "image_digest", "")
  non_empty_string(value)
}

claim_image_digests contains digest if {
  some idc in init_data_claims_values
  value := object.get(idc, "image_digest", "")
  non_empty_string(value)
  parts := split(value, "@")
  n := count(parts)
  n > 1
  digest := parts[n - 1]
  startswith(digest, "sha256:")
}

claim_signer_subjects contains value if {
  some idc in init_data_claims_values
  value := object.get(idc, "signer_identity_subject", "")
  non_empty_string(value)
}

claim_signer_subjects contains value if {
  some idc in init_data_claims_values
  signer := object.get(idc, "signer_identity", {})
  value := object.get(signer, "subject", "")
  non_empty_string(value)
}

claim_signer_issuers contains value if {
  some idc in init_data_claims_values
  value := object.get(idc, "signer_identity_issuer", "")
  non_empty_string(value)
}

claim_signer_issuers contains value if {
  some idc in init_data_claims_values
  signer := object.get(idc, "signer_identity", {})
  value := object.get(signer, "issuer", "")
  non_empty_string(value)
}

claim_namespaces contains value if {
  some idc in init_data_claims_values
  value := object.get(idc, "namespace", "")
  non_empty_string(value)
}

claim_service_accounts contains value if {
  some idc in init_data_claims_values
  value := object.get(idc, "service_account", "")
  non_empty_string(value)
}

claim_identity_hashes contains hash if {
  some idc in init_data_claims_values
  raw := object.get(idc, "identity_hash", "")
  non_empty_string(raw)
  hash := lower(raw)
}

non_empty_string(value) if {
  is_string(value)
  value != ""
}
