pub mod authorization;
pub mod canonical;
pub mod descriptor;
pub mod genpolicy;
pub mod keyring;
pub mod owner_store;
pub mod policy;

pub const TEMPLATE_ID: &str = "trustee-resource-policy-v1";
pub const TEMPLATE_TEXT: &str = include_str!("../../templates/trustee-resource-policy-v1.rego");
