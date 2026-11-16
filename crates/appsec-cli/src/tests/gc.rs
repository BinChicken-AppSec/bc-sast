use super::*;
#[test]
fn run_gc_run_evicts_a_registered_run() {
    let _guard = ENV_LOCK.blocking_lock();
    let state_dir = tempfile::tempdir().unwrap();
    let prior = std::env::var("BC_STATE_DIR").ok();
    unsafe {
        std::env::set_var("BC_STATE_DIR", state_dir.path());
    }
    let target = tempfile::tempdir().unwrap();
    let run_id = register_run_at(state_dir.path(), target.path());

    let mut c = cli(Path::new("/unused"));
    c.gc_run = Some(target.path().to_path_buf());
    let summary = run_gc(&c);
    restore_env("BC_STATE_DIR", prior);

    let summary = summary.unwrap();
    assert_eq!(summary.findings, 0);
    match summary.gc {
        Some(GcSummary::Evicted {
            found: true,
            dry_run: false,
            run_id: got,
            ..
        }) => assert_eq!(got, run_id),
        other => panic!("unexpected gc summary: {other:?}"),
    }
}
#[test]
fn run_gc_run_reports_not_found_when_no_run_is_registered() {
    let _guard = ENV_LOCK.blocking_lock();
    let state_dir = tempfile::tempdir().unwrap();
    let prior = std::env::var("BC_STATE_DIR").ok();
    unsafe {
        std::env::set_var("BC_STATE_DIR", state_dir.path());
    }
    let target = tempfile::tempdir().unwrap();

    let mut c = cli(Path::new("/unused"));
    c.gc_run = Some(target.path().to_path_buf());
    let summary = run_gc(&c);
    restore_env("BC_STATE_DIR", prior);

    match summary.unwrap().gc {
        Some(GcSummary::Evicted {
            found: false,
            dry_run: false,
            ..
        }) => {}
        other => panic!("unexpected gc summary: {other:?}"),
    }
}
#[test]
fn run_gc_run_dry_run_never_touches_the_database() {
    let _guard = ENV_LOCK.blocking_lock();
    let state_dir = tempfile::tempdir().unwrap();
    let prior = std::env::var("BC_STATE_DIR").ok();
    unsafe {
        std::env::set_var("BC_STATE_DIR", state_dir.path());
    }
    let target = tempfile::tempdir().unwrap();
    let run_id = register_run_at(state_dir.path(), target.path());

    let mut c = cli(Path::new("/unused"));
    c.gc_run = Some(target.path().to_path_buf());
    c.gc_dry_run = true;
    let summary = run_gc(&c).unwrap();

    let store = appsec_checkpoint::SqliteCheckpointStore::open_default().unwrap();
    let still_there = store.delete_run(&run_id).unwrap();
    restore_env("BC_STATE_DIR", prior);

    match summary.gc {
        Some(GcSummary::Evicted {
            found: false,
            dry_run: true,
            ..
        }) => {}
        other => panic!("unexpected gc summary: {other:?}"),
    }
    assert!(
        still_there,
        "dry run must not have actually evicted the registered run"
    );
}
#[test]
fn run_gc_prunes_all_runs_when_keep_runs_is_zero() {
    let _guard = ENV_LOCK.blocking_lock();
    let state_dir = tempfile::tempdir().unwrap();
    let prior = std::env::var("BC_STATE_DIR").ok();
    unsafe {
        std::env::set_var("BC_STATE_DIR", state_dir.path());
    }
    let target = tempfile::tempdir().unwrap();
    let run_id = register_run_at(state_dir.path(), target.path());

    let mut c = cli(Path::new("/unused"));
    c.gc_keep_runs = 0;
    c.gc_max_age_days = 365;
    let summary = run_gc(&c);
    restore_env("BC_STATE_DIR", prior);

    match summary.unwrap().gc {
        Some(GcSummary::Pruned {
            kept: 0,
            deleted,
            dry_run: false,
            ..
        }) => assert_eq!(deleted, vec![run_id]),
        other => panic!("unexpected gc summary: {other:?}"),
    }
}
#[test]
fn run_gc_prune_dry_run_reports_victims_without_deleting() {
    let _guard = ENV_LOCK.blocking_lock();
    let state_dir = tempfile::tempdir().unwrap();
    let prior = std::env::var("BC_STATE_DIR").ok();
    unsafe {
        std::env::set_var("BC_STATE_DIR", state_dir.path());
    }
    let target = tempfile::tempdir().unwrap();
    let run_id = register_run_at(state_dir.path(), target.path());

    let mut c = cli(Path::new("/unused"));
    c.gc_keep_runs = 0;
    c.gc_max_age_days = 365;
    c.gc_dry_run = true;
    let summary = run_gc(&c).unwrap();

    let store = appsec_checkpoint::SqliteCheckpointStore::open_default().unwrap();
    let still_there = store.delete_run(&run_id).unwrap();
    restore_env("BC_STATE_DIR", prior);

    match summary.gc {
        Some(GcSummary::Pruned {
            deleted,
            dry_run: true,
            ..
        }) => assert_eq!(deleted, vec![run_id]),
        other => panic!("unexpected gc summary: {other:?}"),
    }
    assert!(
        still_there,
        "dry run must not have actually pruned the registered run"
    );
}
#[test]
fn run_gc_propagates_an_error_when_the_state_dir_is_unusable() {
    let _guard = ENV_LOCK.blocking_lock();
    let dir = tempfile::tempdir().unwrap();
    let blocker = dir.path().join("blocker");
    std::fs::write(&blocker, b"not a directory").unwrap();
    let prior = std::env::var("BC_STATE_DIR").ok();
    unsafe {
        std::env::set_var("BC_STATE_DIR", &blocker);
    }

    let c = cli(Path::new("/unused"));
    let result = run_gc(&c);
    restore_env("BC_STATE_DIR", prior);

    assert!(result.is_err());
}

#[tokio::test]
async fn main_impl_dispatches_to_gc_when_the_flag_is_set() {
    let _guard = ENV_LOCK.lock().await;
    let state_dir = tempfile::tempdir().unwrap();
    let prior = std::env::var("BC_STATE_DIR").ok();
    unsafe {
        std::env::set_var("BC_STATE_DIR", state_dir.path());
    }
    let mut c = cli(Path::new("/unused"));
    c.gc = true;
    let summary = main_impl(c).await;
    restore_env("BC_STATE_DIR", prior);

    assert!(summary.unwrap().gc.is_some());
}
