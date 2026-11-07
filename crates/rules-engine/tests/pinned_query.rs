use std::collections::BTreeMap;

use firenook_rules_engine::{
    Auth, ConstraintOperator as Op, DocumentAccess, DocumentAccessError, EvaluationRequest,
    FieldConstraint, Query, QueryFilter, QueryScope, RequestOperation, Resource, Timestamp, Value,
    compile,
};

const RULES: &str = "rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /teams/{team} {
      allow list: if exists(/databases/$(database)/documents/members/$(team));
    }
    match /tasks/{task} {
      allow list: if resource.data.owner == request.auth.uid;
    }
    match /notes/{note} {
      allow list: if resource == null;
    }
  }
}";

struct Stored;
impl DocumentAccess for Stored {
    fn get(&self, path: &str) -> Result<Option<Resource>, DocumentAccessError> {
        let data = match path.strip_prefix("/databases/(default)/documents/") {
            Some("members/a" | "teams/a" | "teams/b" | "notes/a") => BTreeMap::new(),
            Some("tasks/mine") => BTreeMap::from([("owner".to_owned(), Value::from("alice"))]),
            _ => return Ok(None),
        };
        Ok(Some(Resource::new(path, data)))
    }
    fn get_after(&self, path: &str) -> Result<Option<Resource>, DocumentAccessError> {
        self.get(path)
    }
}

fn field(field: &str, operator: Op, value: Value) -> QueryFilter {
    QueryFilter::Field(FieldConstraint {
        field: vec![field.to_owned()],
        operator,
        value,
    })
}

fn name(collection: &str, id: &str) -> Value {
    Value::Path(format!(
        "projects/p/databases/(default)/documents/{collection}/{id}"
    ))
}

fn allowed(collection: &str, filter: QueryFilter) -> bool {
    let mut request = EvaluationRequest::new(
        RequestOperation::List,
        format!("/databases/(default)/documents/{collection}/rules-candidate"),
        Timestamp::new(1, 0),
    );
    request.auth = Some(Auth {
        uid: Some("alice".to_owned()),
        token: BTreeMap::new(),
    });
    request.query = Query {
        filter: Some(filter),
        scope: Some(QueryScope::Collection(collection.to_owned())),
        ..Query::default()
    };
    compile(RULES)
        .expect("rules")
        .evaluate(&request, &Stored)
        .allowed
}

// Verdicts measured on the official emulator: each pinned ID is ruled as a
// read of that document, with the wildcard bound and `resource` stored or null.
#[test]
fn a_document_id_pin_binds_the_wildcard_and_reads_the_document() {
    let pin = |collection, id| field("__name__", Op::Equal, name(collection, id));
    let pins = |collection, ids: &[&str]| {
        let ids = ids.iter().map(|id| name(collection, id)).collect();
        field("__name__", Op::In, Value::List(ids))
    };
    assert!(allowed("teams", pin("teams", "a")));
    assert!(allowed("teams", pins("teams", &["a"])));
    assert!(!allowed("teams", pins("teams", &["a", "b"])));
    assert!(!allowed(
        "teams",
        field("__name__", Op::NotEqual, name("teams", "b"))
    ));
    let owned = |id| {
        QueryFilter::And(vec![
            field("owner", Op::Equal, Value::from("alice")),
            pin("tasks", id),
        ])
    };
    assert!(allowed("tasks", owned("mine")));
    assert!(!allowed("tasks", owned("missing")));
    assert!(allowed("notes", pin("notes", "missing")));
    assert!(!allowed("notes", pin("notes", "a")));
}
