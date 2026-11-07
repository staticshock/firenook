use std::collections::BTreeMap;

use firenook_rules_engine::{
    DocumentAccess, DocumentAccessError, EvaluationRequest, RequestOperation, Resource, Timestamp,
    Value, compile,
};

const RULES: &str = "rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    function m(id) { return /databases/$(database)/documents/m/$(id); }
    match /rosters/{roster} {
      function onTeam(t) { let p = /databases/$(database)/documents/m/$(t); return t != null && exists(p); }
      allow get: if !onTeam(resource.data.team);
    }
    match /nine/{doc} {
      allow get: if f();
      function f() {
        let g = exists(m('k9'));
        return !exists(m('k0')) && !exists(m('k1')) && !exists(m('k2')) && !exists(m('k3'))
          && !exists(m('k4')) && !exists(m('k5')) && !exists(m('k6')) && !exists(m('k7'))
          && !exists(m('k8'));
      }
    }
    match /ten/{doc} {
      allow get: if f();
      function f() {
        let g = exists(m('k10'));
        return !exists(m('k0')) && !exists(m('k1')) && !exists(m('k2')) && !exists(m('k3'))
          && !exists(m('k4')) && !exists(m('k5')) && !exists(m('k6')) && !exists(m('k7'))
          && !exists(m('k8')) && !exists(m('k9'));
      }
    }
  }
}";

struct Stored;
impl DocumentAccess for Stored {
    fn get(&self, path: &str) -> Result<Option<Resource>, DocumentAccessError> {
        Ok((path == "/databases/(default)/documents/m/a")
            .then(|| Resource::new(path, BTreeMap::new())))
    }
    fn get_after(&self, path: &str) -> Result<Option<Resource>, DocumentAccessError> {
        self.get(path)
    }
}

fn allowed(path: &str, data: BTreeMap<String, Value>) -> bool {
    let path = format!("/databases/(default)/documents/{path}");
    let mut request = EvaluationRequest::new(RequestOperation::Get, &path, Timestamp::new(1, 0));
    request.resource = Some(Resource::new(&path, data));
    compile(RULES)
        .expect("rules")
        .evaluate(&request, &Stored)
        .allowed
}

fn team(value: Value) -> BTreeMap<String, Value> {
    BTreeMap::from([("team".to_owned(), value)])
}

// Verdicts measured on the official emulator: a `let` that fails raises its
// error only where the return reads it.
#[test]
fn a_failing_let_errors_only_where_it_is_read() {
    assert!(allowed("rosters/x", team(Value::Null)));
    assert!(!allowed("rosters/x", team(Value::from("a"))));
    assert!(allowed("rosters/x", team(Value::from("b"))));
    let map = Value::Map(BTreeMap::from([("k".to_owned(), Value::from(1))]));
    assert!(!allowed("rosters/x", team(map)));
}

// The official emulator still evaluates a `let` the return never reads: its
// `exists()` counts toward the 10 document accesses of a request.
#[test]
fn an_unread_let_counts_its_document_access() {
    assert!(allowed("nine/x", BTreeMap::new()));
    assert!(!allowed("ten/x", BTreeMap::new()));
}
