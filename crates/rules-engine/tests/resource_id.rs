//! `resource.id` and `request.resource.id` are the document ID, the last
//! segment of the document's name. Every verdict below was recorded from the
//! official emulator (firebase-tools 15.34.0) with
//! `@firebase/rules-unit-testing`.

use std::collections::BTreeMap;

use firenook_rules_engine::{
    EmptyDocumentAccess, EvaluationRequest, Query, QueryScope, RequestOperation, Resource,
    Timestamp, Value, compile,
};

fn allows(operation: &str, condition: &str, request: &EvaluationRequest) -> bool {
    let source = format!(
        "rules_version = '2'; service cloud.firestore {{
           match /databases/{{database}}/documents {{
             match /notes/{{id}} {{ allow {operation}: if {condition}; }}
             match /notes/{{parent}}/sub/{{id}} {{ allow {operation}: if {condition}; }}
           }}
         }}"
    );
    compile(&source)
        .unwrap_or_else(|error| panic!("{condition}: {error:?}"))
        .evaluate(request, &EmptyDocumentAccess)
        .allowed
}

fn request(operation: RequestOperation, path: &str) -> EvaluationRequest {
    EvaluationRequest::new(
        operation,
        format!("/databases/(default)/documents/{path}"),
        Timestamp::new(1, 0),
    )
}

/// A document as the runtime names it (`projects/<p>/databases/...`) or as
/// the request path does (`/databases/...`).
fn document(prefix: &str, path: &str) -> Resource {
    Resource::new(
        format!("{prefix}/databases/(default)/documents/{path}"),
        BTreeMap::from([("id".to_owned(), Value::from("other"))]),
    )
}

#[test]
fn resource_id_is_the_document_id_in_every_single_document_method() {
    for prefix in ["projects/demo-x", ""] {
        for (path, id) in [
            ("notes/a", "a"),
            ("notes/a b", "a b"),
            ("notes/é", "é"),
            ("notes/`x`", "`x`"),
            ("notes/a.b", "a.b"),
            ("notes/x/sub/a", "a"),
        ] {
            let mut get = request(RequestOperation::Get, path);
            get.resource = Some(document(prefix, path));
            let mut create = request(RequestOperation::Create, path);
            create.request_resource = Some(document(prefix, path));
            let mut update = request(RequestOperation::Update, path);
            update.resource = Some(document(prefix, path));
            update.request_resource = Some(document(prefix, path));
            let mut delete = request(RequestOperation::Delete, path);
            delete.resource = Some(document(prefix, path));
            for (operation, request, condition) in [
                ("get", &get, "resource.id == id".to_owned()),
                ("get", &get, format!("resource.id == '{id}'")),
                ("get", &get, "resource.id is string".to_owned()),
                ("get", &get, "resource.data.id == 'other'".to_owned()),
                ("create", &create, "request.resource.id == id".to_owned()),
                ("create", &create, format!("request.resource.id == '{id}'")),
                ("update", &update, "resource.id == id".to_owned()),
                ("update", &update, "request.resource.id == id".to_owned()),
                ("delete", &delete, "resource.id == id".to_owned()),
            ] {
                assert!(
                    allows(operation, &condition, request),
                    "{operation} {prefix}/{path}: {condition}"
                );
            }
            assert!(!allows("get", "resource.id == 'other'", &get), "{path}");
        }
    }
    // In a subcollection the ID is the document's, not its parent's.
    let mut get = request(RequestOperation::Get, "notes/a/sub/a");
    get.resource = Some(document("projects/demo-x", "notes/a/sub/a"));
    assert!(!allows("get", "resource.id != parent", &get));
}

#[test]
fn an_unfiltered_list_does_not_decide_resource_id() {
    let mut list = request(RequestOperation::List, "notes/not-a-row");
    list.query = Query {
        scope: Some(QueryScope::Collection("notes".to_owned())),
        ..Query::default()
    };
    assert!(!allows("list", "resource.id == 'a'", &list));
    assert!(!allows("list", "resource.id != 'zzz'", &list));
    assert!(!allows("list", "resource.id is string", &list));
    assert!(allows("list", "resource.id == 'a' || true", &list));
}
