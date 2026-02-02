//! Access Control Policy Engine

use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;
use std::collections::HashMap;

/// Access control decision
#[wasm_bindgen]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Decision {
    Allow,
    Deny,
    NotApplicable,
}

/// Subject (user/principal) making the request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subject {
    pub id: String,
    pub roles: Vec<String>,
    pub attributes: HashMap<String, String>,
}

/// Resource being accessed
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Resource {
    pub id: String,
    pub resource_type: String,
    pub owner_id: Option<String>,
    pub attributes: HashMap<String, String>,
}

/// Action being performed
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Action {
    pub name: String,
    pub attributes: HashMap<String, String>,
}

/// Policy rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    pub roles: Vec<String>,
    pub resources: Vec<String>,
    pub actions: Vec<String>,
    pub effect: String,
    pub conditions: Option<HashMap<String, String>>,
}

/// Policy set
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PolicySet {
    pub rules: Vec<PolicyRule>,
    pub default_effect: String,
}

/// Evaluate access control policy
#[wasm_bindgen]
pub fn evaluate_access(subject_json: &str, resource_json: &str, action_json: &str, policy_json: &str) -> Result<i32, JsValue> {
    let subject: Subject = serde_json::from_str(subject_json).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let resource: Resource = serde_json::from_str(resource_json).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let action: Action = serde_json::from_str(action_json).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let policy: PolicySet = serde_json::from_str(policy_json).map_err(|e| JsValue::from_str(&e.to_string()))?;

    let decision = evaluate_policy(&subject, &resource, &action, &policy);
    Ok(match decision {
        Decision::Allow => 1,
        Decision::Deny => 0,
        Decision::NotApplicable => -1,
    })
}

fn evaluate_policy(subject: &Subject, resource: &Resource, action: &Action, policy: &PolicySet) -> Decision {
    for rule in &policy.rules {
        // Check role match
        let role_match = rule.roles.iter().any(|r| r == "*" || subject.roles.contains(r));
        if !role_match { continue; }

        // Check resource match
        let resource_match = rule.resources.iter().any(|r| r == "*" || r == &resource.resource_type);
        if !resource_match { continue; }

        // Check action match
        let action_match = rule.actions.iter().any(|a| a == "*" || a == &action.name);
        if !action_match { continue; }

        // Check owner condition
        if let Some(ref conditions) = rule.conditions {
            if let Some(owner_check) = conditions.get("owner_only") {
                if owner_check == "true" {
                    if resource.owner_id.as_ref() != Some(&subject.id) {
                        continue;
                    }
                }
            }
        }

        return match rule.effect.as_str() {
            "allow" => Decision::Allow,
            "deny" => Decision::Deny,
            _ => Decision::NotApplicable,
        };
    }

    match policy.default_effect.as_str() {
        "allow" => Decision::Allow,
        _ => Decision::Deny,
    }
}

/// Rate limiter state
#[wasm_bindgen]
pub struct RateLimiter {
    requests: HashMap<String, Vec<u64>>,
    limit: u32,
    window_ms: u64,
}

#[wasm_bindgen]
impl RateLimiter {
    #[wasm_bindgen(constructor)]
    pub fn new(limit: u32, window_ms: u64) -> Self {
        Self { requests: HashMap::new(), limit, window_ms }
    }

    pub fn check(&mut self, key: &str, now_ms: u64) -> bool {
        let entry = self.requests.entry(key.to_string()).or_default();
        entry.retain(|&t| now_ms - t < self.window_ms);
        if entry.len() < self.limit as usize {
            entry.push(now_ms);
            true
        } else {
            false
        }
    }

    pub fn reset(&mut self, key: &str) {
        self.requests.remove(key);
    }
}

/// Brute force protection
#[wasm_bindgen]
pub struct BruteForceProtection {
    attempts: HashMap<String, (u32, u64)>,
    max_attempts: u32,
    lockout_ms: u64,
}

#[wasm_bindgen]
impl BruteForceProtection {
    #[wasm_bindgen(constructor)]
    pub fn new(max_attempts: u32, lockout_minutes: u32) -> Self {
        Self {
            attempts: HashMap::new(),
            max_attempts,
            lockout_ms: lockout_minutes as u64 * 60 * 1000,
        }
    }

    pub fn record_failure(&mut self, key: &str, now_ms: u64) -> bool {
        let entry = self.attempts.entry(key.to_string()).or_insert((0, now_ms));
        if now_ms - entry.1 > self.lockout_ms {
            *entry = (1, now_ms);
            true
        } else {
            entry.0 += 1;
            entry.0 < self.max_attempts
        }
    }

    pub fn is_locked(&self, key: &str, now_ms: u64) -> bool {
        if let Some(&(attempts, last_time)) = self.attempts.get(key) {
            attempts >= self.max_attempts && now_ms - last_time < self.lockout_ms
        } else {
            false
        }
    }

    pub fn record_success(&mut self, key: &str) {
        self.attempts.remove(key);
    }
}
