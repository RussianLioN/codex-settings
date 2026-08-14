create table database_identity (
  singleton integer primary key check(singleton = 1),
  database_id text not null unique check(
    length(database_id) = 36 and
    substr(database_id, 1, 4) = 'db2_' and
    substr(database_id, 5) not glob '*[^0-9a-f]*'
  ),
  schema_version integer not null check(schema_version = 2),
  schema_fingerprint text not null check(
    length(schema_fingerprint) = 64 and
    schema_fingerprint not glob '*[^0-9a-f]*'
  ),
  schema_artifact_sha256 text not null check(
    length(schema_artifact_sha256) = 64 and
    schema_artifact_sha256 not glob '*[^0-9a-f]*'
  ),
  activation_binding_nonce text not null check(
    length(activation_binding_nonce) = 64 and
    activation_binding_nonce not glob '*[^0-9a-f]*'
  ),
  activation_id text not null unique check(
    length(activation_id) = 69 and
    substr(activation_id, 1, 5) = 'act2_' and
    substr(activation_id, 6) not glob '*[^0-9a-f]*'
  ),
  activation_fingerprint text not null unique check(
    length(activation_fingerprint) = 64 and
    activation_fingerprint not glob '*[^0-9a-f]*'
  ),
  source_shape text not null check(
    source_shape in (
      'fresh-v2',
      'v0-empty',
      'v0-old-base-p1',
      'v0-old-base-p2',
      'v0-old-base-p3',
      'v0-old-base-p4',
      'v0-old-base-p5',
      'v0-old-base-p6',
      'v0-old-base-p7',
      'v0-old-base-p8',
      'v0-old-base-p9',
      'v0-new-base-p1',
      'v0-new-base-p2',
      'v0-new-base-p3',
      'v0-new-base-p4',
      'v0-new-base-p5',
      'v0-new-base-p6',
      'v0-new-base-p7',
      'v0-new-base-p8',
      'v0-new-base-p9',
      'execution-v1',
      'execution-alter-binding-v1',
      'artifacts-table-only-v1',
      'artifacts-v1',
      'artifacts-table-only-alter-binding-v1',
      'artifacts-alter-binding-v1',
      'new-base-embedded-binding-v1',
      'new-runtime-table-only-embedded-binding-v1',
      'new-runtime-embedded-binding-v1',
      'candidate-alter-p1',
      'candidate-alter-p2',
      'candidate-alter-p3',
      'candidate-alter-p4',
      'candidate-alter-p5',
      'candidate-embedded-p1',
      'candidate-embedded-p2',
      'candidate-embedded-p3',
      'candidate-embedded-p4',
      'candidate-embedded-p5'
    )
  ),
  source_schema_fingerprint text check(
    source_schema_fingerprint is null or (
      length(source_schema_fingerprint) = 64 and
      source_schema_fingerprint not glob '*[^0-9a-f]*'
    )
  ),
  source_backup_sha256 text check(
    source_backup_sha256 is null or (
      length(source_backup_sha256) = 64 and
      source_backup_sha256 not glob '*[^0-9a-f]*'
    )
  ),
  created_operation_id text not null,
  created_at text not null,
  check(
    (source_shape = 'fresh-v2' and source_schema_fingerprint is null and source_backup_sha256 is null) or
    (source_shape <> 'fresh-v2' and source_schema_fingerprint is not null and source_backup_sha256 is not null)
  )
);

create table controller_state (
  singleton integer primary key check(singleton = 1),
  database_id text not null references database_identity(database_id) on update restrict on delete restrict,
  protocol_version integer not null check(protocol_version = 2),
  release text not null check(release = '0.2.0'),
  controller_identity text not null check(
    length(controller_identity) = 64 and
    controller_identity not glob '*[^0-9a-f]*'
  ),
  instance_id text check(
    instance_id is null or (
      length(instance_id) = 36 and
      substr(instance_id, 1, 4) = 'ci2_' and
      substr(instance_id, 5) not glob '*[^0-9a-f]*'
    )
  ),
  controller_start_id text check(
    controller_start_id is null or (
      length(controller_start_id) = 36 and
      substr(controller_start_id, 1, 4) = 'cs2_' and
      substr(controller_start_id, 5) not glob '*[^0-9a-f]*'
    )
  ),
  controller_pid integer check(controller_pid is null or controller_pid > 0),
  controller_process_start_marker text check(
    controller_process_start_marker is null or length(controller_process_start_marker) > 0
  ),
  controller_process_group_id integer check(
    controller_process_group_id is null or controller_process_group_id > 0
  ),
  control_epoch integer not null check(control_epoch between 1 and 9007199254740991),
  state text not null check(state in ('ACCEPTING', 'DRAINING', 'MAINTENANCE', 'STOPPED')),
  maintenance_mode text not null check(maintenance_mode in ('NONE', 'DRAIN', 'FREEZE')),
  reason_code text not null,
  operation_id text check(
    operation_id is null or (
      length(operation_id) = 36 and
      substr(operation_id, 1, 4) = 'op2_' and
      substr(operation_id, 5) not glob '*[^0-9a-f]*'
    )
  ),
  activation_id text not null,
  activation_fingerprint text not null check(
    length(activation_fingerprint) = 64 and
    activation_fingerprint not glob '*[^0-9a-f]*'
  ),
  compatibility_fingerprint text not null check(
    length(compatibility_fingerprint) = 64 and
    compatibility_fingerprint not glob '*[^0-9a-f]*'
  ),
  routing_policy_fingerprint text not null check(
    length(routing_policy_fingerprint) = 64 and
    routing_policy_fingerprint not glob '*[^0-9a-f]*'
  ),
  bundled_catalog_fingerprint text not null check(
    length(bundled_catalog_fingerprint) = 64 and
    bundled_catalog_fingerprint not glob '*[^0-9a-f]*'
  ),
  socket_path text,
  socket_device integer check(socket_device is null or socket_device >= 0),
  socket_inode integer check(socket_inode is null or socket_inode >= 0),
  socket_owner_uid integer check(socket_owner_uid is null or socket_owner_uid >= 0),
  socket_owner_gid integer check(socket_owner_gid is null or socket_owner_gid >= 0),
  socket_mode text check(socket_mode is null or (length(socket_mode) = 4 and socket_mode glob '0[0-7][0-7][0-7]')),
  lock_held integer not null check(lock_held in (0, 1)),
  accepting_new_routes integer not null check(accepting_new_routes in (0, 1)),
  quiescent integer not null check(quiescent in (0, 1)),
  updated_at text not null,
  check(
    (state = 'ACCEPTING' and maintenance_mode = 'NONE' and operation_id is null and instance_id is not null and controller_start_id is not null and controller_pid is not null and controller_process_start_marker is not null and controller_process_group_id is not null and socket_path is not null and socket_device is not null and socket_inode is not null and socket_owner_uid is not null and socket_owner_gid is not null and socket_mode is not null and lock_held = 1 and accepting_new_routes = 1 and reason_code = 'NONE') or
    (state = 'DRAINING' and maintenance_mode = 'DRAIN' and operation_id is not null and instance_id is not null and controller_start_id is not null and controller_pid is not null and controller_process_start_marker is not null and controller_process_group_id is not null and socket_path is not null and socket_device is not null and socket_inode is not null and socket_owner_uid is not null and socket_owner_gid is not null and socket_mode is not null and lock_held = 1 and accepting_new_routes = 0) or
    (state = 'MAINTENANCE' and maintenance_mode in ('DRAIN', 'FREEZE') and operation_id is not null and ((instance_id is not null and controller_start_id is not null and controller_pid is not null and controller_process_start_marker is not null and controller_process_group_id is not null and socket_path is not null and socket_device is not null and socket_inode is not null and socket_owner_uid is not null and socket_owner_gid is not null and socket_mode is not null and lock_held = 1 and accepting_new_routes = 0) or (maintenance_mode = 'FREEZE' and reason_code = 'AWAITING_CONTROLLER_ACCEPT' and instance_id is null and controller_start_id is null and controller_pid is null and controller_process_start_marker is null and controller_process_group_id is null and socket_path is null and socket_device is null and socket_inode is null and socket_owner_uid is null and socket_owner_gid is null and socket_mode is null and lock_held = 0 and accepting_new_routes = 0 and quiescent = 1))) or
    (state = 'STOPPED' and maintenance_mode = 'NONE' and operation_id is null and socket_path is null and socket_device is null and socket_inode is null and socket_owner_uid is null and socket_owner_gid is null and socket_mode is null and lock_held = 0 and accepting_new_routes = 0 and quiescent = 1)
  )
);

create table controller_command_receipts (
  command_id text primary key check(
    length(command_id) = 36 and
    substr(command_id, 1, 4) = 'cc2_' and
    substr(command_id, 5) not glob '*[^0-9a-f]*'
  ),
  operation_id text not null check(
    length(operation_id) = 36 and
    substr(operation_id, 1, 4) = 'op2_' and
    substr(operation_id, 5) not glob '*[^0-9a-f]*'
  ),
  method text not null check(method in ('maintenance_begin', 'maintenance_strengthen', 'shutdown', 'controller_accept', 'controller_recover', 'maintenance_resume')),
  request_fingerprint text not null check(length(request_fingerprint) = 64 and request_fingerprint not glob '*[^0-9a-f]*'),
  request_json text not null,
  result_fingerprint text not null check(length(result_fingerprint) = 64 and result_fingerprint not glob '*[^0-9a-f]*'),
  response_json text not null,
  response_fingerprint text not null check(length(response_fingerprint) = 64 and response_fingerprint not glob '*[^0-9a-f]*'),
  controller_identity text not null check(length(controller_identity) = 64 and controller_identity not glob '*[^0-9a-f]*'),
  before_instance_id text check(
    before_instance_id is null or (
      length(before_instance_id) = 36 and
      substr(before_instance_id, 1, 4) = 'ci2_' and
      substr(before_instance_id, 5) not glob '*[^0-9a-f]*'
    )
  ),
  resulting_instance_id text check(
    resulting_instance_id is null or (
      length(resulting_instance_id) = 36 and
      substr(resulting_instance_id, 1, 4) = 'ci2_' and
      substr(resulting_instance_id, 5) not glob '*[^0-9a-f]*'
    )
  ),
  quiescence_proof_json text,
  socket_intent_json text,
  before_epoch integer not null check(before_epoch between 1 and 9007199254740990),
  after_epoch integer not null check(after_epoch between 2 and 9007199254740991 and after_epoch = before_epoch + 1),
  created_at text not null,
  check(
    (method = 'shutdown' and quiescence_proof_json is not null and socket_intent_json is not null and before_instance_id is not null and resulting_instance_id is null) or
    (method <> 'shutdown' and quiescence_proof_json is null and socket_intent_json is null)
  ),
  check(
    method not in ('maintenance_begin', 'maintenance_strengthen', 'maintenance_resume') or
    (before_instance_id is not null and before_instance_id = resulting_instance_id)
  ),
  check(method <> 'controller_accept' or before_instance_id is null)
);

create table turn_bindings (
  token_hash text primary key,
  context_hash text not null,
  context_json text not null,
  created_at text not null,
  expires_at text not null,
  consumed_at text,
  request_key text,
  request_hash text,
  activation_fingerprint text not null check(length(activation_fingerprint) = 64 and activation_fingerprint not glob '*[^0-9a-f]*'),
  compatibility_fingerprint text not null check(length(compatibility_fingerprint) = 64 and compatibility_fingerprint not glob '*[^0-9a-f]*'),
  issued_control_epoch integer not null check(issued_control_epoch between 0 and 9007199254740991)
);

create table routes (
  route_id text primary key,
  request_key text not null,
  request_hash text not null,
  context_hash text not null,
  context_json text not null,
  shell_session_id text not null,
  session_id text not null,
  turn_id text not null,
  codex_home_hash text not null,
  repo_root_hash text not null,
  base_sha text not null,
  worktree_fingerprint text not null,
  catalog_generation text not null,
  algorithm_version text not null,
  disposition text not null,
  startable integer not null check(startable in (0, 1)),
  state text not null check(state in ('DIRECT', 'CLARIFY', 'PLANNED', 'BLOCKED', 'QUEUED', 'LEASED', 'PREPARING', 'RUNNING', 'COLLECTING', 'ATTESTING', 'VALIDATING', 'CANDIDATE_BUILDING', 'SUCCEEDED', 'CANDIDATE_READY', 'QUARANTINED', 'RETRYABLE', 'RECOVERING', 'CANCELLING', 'CANCELLED', 'FAILED', 'STALE', 'SKIPPED', 'SPLIT')),
  expires_at text not null,
  run_id text,
  cancel_reason text,
  plan_output_json text not null,
  terminal_result_json text,
  created_at text not null,
  updated_at text not null,
  activation_fingerprint text not null check(length(activation_fingerprint) = 64 and activation_fingerprint not glob '*[^0-9a-f]*'),
  compatibility_fingerprint text not null check(length(compatibility_fingerprint) = 64 and compatibility_fingerprint not glob '*[^0-9a-f]*'),
  unique(context_hash, request_key),
  check(state not in ('DIRECT', 'CLARIFY') or startable = 0)
);

create table nodes (
  route_id text not null references routes(route_id) on delete cascade,
  node_id text not null,
  ordinal integer not null,
  role text not null,
  mission text not null,
  dependencies_json text not null,
  context_refs_json text not null,
  scope_id text not null,
  artifact_profile_id text not null,
  validation_profile_id text not null,
  assessment_json text not null,
  risk_flags_json text not null,
  selected_model text not null,
  reasoning_effort text not null,
  permission_profile_id text not null,
  disposition text not null,
  state text not null check(state in ('PLANNED', 'BLOCKED', 'QUEUED', 'LEASED', 'PREPARING', 'RUNNING', 'COLLECTING', 'ATTESTING', 'VALIDATING', 'CANDIDATE_BUILDING', 'SUCCEEDED', 'CANDIDATE_READY', 'QUARANTINED', 'RETRYABLE', 'RECOVERING', 'CANCELLING', 'CANCELLED', 'FAILED', 'STALE', 'SKIPPED', 'SPLIT')),
  attempt_count integer not null default 0,
  result_json text,
  updated_at text not null,
  activation_fingerprint text not null check(length(activation_fingerprint) = 64 and activation_fingerprint not glob '*[^0-9a-f]*'),
  account_context_fingerprint text check(account_context_fingerprint is null or (length(account_context_fingerprint) = 64 and account_context_fingerprint not glob '*[^0-9a-f]*')),
  account_catalog_fingerprint text check(account_catalog_fingerprint is null or (length(account_catalog_fingerprint) = 64 and account_catalog_fingerprint not glob '*[^0-9a-f]*')),
  evidence_job_id text,
  admission_id text unique check(admission_id is null or (length(admission_id) = 37 and substr(admission_id, 1, 5) = 'adm2_' and substr(admission_id, 6) not glob '*[^0-9a-f]*')),
  admission_state text check(admission_state is null or admission_state in ('ADMITTED', 'RESERVED', 'GUARDED', 'COMMIT_AUTHORIZED', 'STARTED', 'STALE', 'ABORTED')),
  admission_manifest_semantic_fingerprint text check(admission_manifest_semantic_fingerprint is null or (length(admission_manifest_semantic_fingerprint) = 64 and admission_manifest_semantic_fingerprint not glob '*[^0-9a-f]*')),
  admission_activation_receipt_fingerprint text check(admission_activation_receipt_fingerprint is null or (length(admission_activation_receipt_fingerprint) = 64 and admission_activation_receipt_fingerprint not glob '*[^0-9a-f]*')),
  admission_journal_absence_proof_json text,
  admission_gate_fingerprint text check(admission_gate_fingerprint is null or (length(admission_gate_fingerprint) = 64 and admission_gate_fingerprint not glob '*[^0-9a-f]*')),
  primary key(route_id, node_id),
  foreign key(evidence_job_id) references account_evidence_jobs(evidence_job_id) on update restrict on delete restrict,
  unique(admission_id, route_id, node_id, activation_fingerprint, account_context_fingerprint, account_catalog_fingerprint, selected_model, reasoning_effort, permission_profile_id, admission_manifest_semantic_fingerprint, admission_activation_receipt_fingerprint, admission_journal_absence_proof_json, admission_gate_fingerprint),
  check(
    (admission_state is null and admission_id is null and evidence_job_id is null and account_context_fingerprint is null and account_catalog_fingerprint is null and admission_manifest_semantic_fingerprint is null and admission_activation_receipt_fingerprint is null and admission_journal_absence_proof_json is null and admission_gate_fingerprint is null) or
    (admission_state is not null and admission_id is not null and evidence_job_id is not null and account_context_fingerprint is not null and account_catalog_fingerprint is not null and admission_manifest_semantic_fingerprint is not null and admission_activation_receipt_fingerprint is not null and admission_journal_absence_proof_json is not null and admission_gate_fingerprint is not null)
  )
);

create table events (
  sequence integer primary key autoincrement,
  route_id text not null references routes(route_id) on delete cascade,
  node_id text not null,
  event text not null,
  state text not null,
  code text not null,
  message text not null,
  created_at text not null
);

create index events_route_sequence on events(route_id, sequence);

create table intents (
  intent_id text primary key,
  route_id text not null references routes(route_id) on delete cascade,
  node_id text not null,
  kind text not null,
  payload_hash text not null,
  payload_json text not null,
  state text not null check(state in ('PENDING', 'COMPLETED')),
  created_at text not null,
  completed_at text
);

create table leases (
  route_id text not null references routes(route_id) on delete cascade,
  node_id text not null,
  owner_id text not null,
  token_hash text not null,
  pid integer not null,
  start_marker text not null,
  expires_at text not null,
  heartbeat_at text not null,
  activation_fingerprint text not null check(length(activation_fingerprint) = 64 and activation_fingerprint not glob '*[^0-9a-f]*'),
  acquired_control_epoch integer not null check(acquired_control_epoch between 1 and 9007199254740991),
  primary key(route_id, node_id)
);

create table start_requests (
  start_request_id text primary key check(length(start_request_id) = 36 and substr(start_request_id, 1, 4) = 'sr2_' and substr(start_request_id, 5) not glob '*[^0-9a-f]*'),
  route_id text not null references routes(route_id) on update restrict on delete restrict,
  shell_session_id text not null,
  session_id text not null,
  turn_id text not null,
  state text not null check(state in ('ATTESTING', 'READY', 'STARTED', 'STALE', 'FAILED', 'CANCELLED')),
  evidence_job_id text unique,
  admission_id text unique,
  created_at text not null,
  updated_at text not null,
  terminal_at text,
  failure_code text,
  foreign key(evidence_job_id) references account_evidence_jobs(evidence_job_id) on update restrict on delete restrict,
  foreign key(admission_id) references nodes(admission_id) on update restrict on delete restrict,
  check(
    (state in ('ATTESTING', 'READY') and terminal_at is null and failure_code is null) or
    (state = 'STARTED' and terminal_at is not null and failure_code is null) or
    (state in ('STALE', 'FAILED', 'CANCELLED') and terminal_at is not null and failure_code is not null)
  )
);

create table account_evidence_jobs (
  evidence_job_id text primary key check(length(evidence_job_id) = 37 and substr(evidence_job_id, 1, 5) = 'aej2_' and substr(evidence_job_id, 6) not glob '*[^0-9a-f]*'),
  start_request_id text not null unique references start_requests(start_request_id) on update restrict on delete restrict,
  route_id text not null references routes(route_id) on update restrict on delete restrict,
  boundary_id text not null,
  state text not null check(state in ('QUEUED', 'RUNNING', 'SUCCEEDED', 'FAILED', 'CANCEL_REQUESTED', 'CANCELLED')),
  queue_position integer not null check(queue_position between 1 and 9007199254740991),
  owner_id text,
  deadline_at text not null,
  pid integer check(pid is null or pid > 0),
  process_start_marker text,
  current_stage text check(current_stage is null or current_stage in ('requirements-a', 'catalog-a', 'requirements-b', 'catalog-b', 'requirements-c')),
  account_catalog_fingerprint text check(account_catalog_fingerprint is null or (length(account_catalog_fingerprint) = 64 and account_catalog_fingerprint not glob '*[^0-9a-f]*')),
  account_context_fingerprint text check(account_context_fingerprint is null or (length(account_context_fingerprint) = 64 and account_context_fingerprint not glob '*[^0-9a-f]*')),
  record_fingerprint text check(record_fingerprint is null or (length(record_fingerprint) = 64 and record_fingerprint not glob '*[^0-9a-f]*')),
  failure_code text,
  queued_at text not null,
  started_at text,
  progress_at text,
  cancel_requested_at text,
  completed_at text,
  check(
    (state = 'QUEUED' and owner_id is null and pid is null and process_start_marker is null and current_stage is null and started_at is null and completed_at is null) or
    (state in ('RUNNING', 'CANCEL_REQUESTED') and owner_id is not null and pid is not null and process_start_marker is not null and current_stage is not null and started_at is not null and completed_at is null) or
    (state = 'SUCCEEDED' and completed_at is not null and failure_code is null and account_catalog_fingerprint is not null and account_context_fingerprint is not null and record_fingerprint is not null) or
    (state in ('FAILED', 'CANCELLED') and completed_at is not null and failure_code is not null)
  )
);

create table node_launch_permits (
  permit_id text primary key check(length(permit_id) = 36 and substr(permit_id, 1, 4) = 'lp2_' and substr(permit_id, 5) not glob '*[^0-9a-f]*'),
  admission_id text unique,
  route_id text not null,
  node_id text not null,
  activation_fingerprint text not null check(length(activation_fingerprint) = 64 and activation_fingerprint not glob '*[^0-9a-f]*'),
  account_context_fingerprint text check(account_context_fingerprint is null or (length(account_context_fingerprint) = 64 and account_context_fingerprint not glob '*[^0-9a-f]*')),
  account_catalog_fingerprint text check(account_catalog_fingerprint is null or (length(account_catalog_fingerprint) = 64 and account_catalog_fingerprint not glob '*[^0-9a-f]*')),
  manifest_semantic_fingerprint text check(manifest_semantic_fingerprint is null or (length(manifest_semantic_fingerprint) = 64 and manifest_semantic_fingerprint not glob '*[^0-9a-f]*')),
  activation_receipt_fingerprint text check(activation_receipt_fingerprint is null or (length(activation_receipt_fingerprint) = 64 and activation_receipt_fingerprint not glob '*[^0-9a-f]*')),
  journal_absence_proof_json text,
  activation_gate_fingerprint text check(activation_gate_fingerprint is null or (length(activation_gate_fingerprint) = 64 and activation_gate_fingerprint not glob '*[^0-9a-f]*')),
  controller_identity text not null check(length(controller_identity) = 64 and controller_identity not glob '*[^0-9a-f]*'),
  controller_instance_id text not null,
  reserved_control_epoch integer not null check(reserved_control_epoch between 0 and 9007199254740991),
  model text not null,
  reasoning_effort text not null,
  permission_profile_id text not null,
  argv_fingerprint text not null check(length(argv_fingerprint) = 64 and argv_fingerprint not glob '*[^0-9a-f]*'),
  compatibility_fingerprint text not null check(length(compatibility_fingerprint) = 64 and compatibility_fingerprint not glob '*[^0-9a-f]*'),
  codex_snapshot_sha256 text not null check(length(codex_snapshot_sha256) = 64 and codex_snapshot_sha256 not glob '*[^0-9a-f]*'),
  permit_evidence_fingerprint text not null check(length(permit_evidence_fingerprint) = 64 and permit_evidence_fingerprint not glob '*[^0-9a-f]*'),
  state text not null check(state in ('RESERVED', 'GUARDED', 'COMMIT_AUTHORIZED', 'STARTED', 'ABORTED_FREEZE', 'ABORTED_RECOVERY', 'ABORTED_ACCOUNT_CONTEXT_CHANGED', 'ABORTED_ACCOUNT_EVIDENCE_UNAVAILABLE', 'ABORTED_ACTIVATION_GATE_CHANGED', 'FAILED_BEFORE_START', 'LEGACY_IMPORTED')),
  guard_pid integer check(guard_pid is null or guard_pid > 0),
  guard_start_marker text,
  pid integer check(pid is null or pid > 0),
  start_marker text,
  one_time_token_hash text,
  snapshot_identity_fingerprint text check(snapshot_identity_fingerprint is null or (length(snapshot_identity_fingerprint) = 64 and snapshot_identity_fingerprint not glob '*[^0-9a-f]*')),
  legacy_source_backup_sha256 text check(legacy_source_backup_sha256 is null or (length(legacy_source_backup_sha256) = 64 and legacy_source_backup_sha256 not glob '*[^0-9a-f]*')),
  legacy_attempt_id text,
  reserved_at text not null,
  resolved_at text,
  failure_code text,
  foreign key(route_id, node_id) references nodes(route_id, node_id) on update restrict on delete restrict,
  foreign key(admission_id, route_id, node_id, activation_fingerprint, account_context_fingerprint, account_catalog_fingerprint, model, reasoning_effort, permission_profile_id, manifest_semantic_fingerprint, activation_receipt_fingerprint, journal_absence_proof_json, activation_gate_fingerprint) references nodes(admission_id, route_id, node_id, activation_fingerprint, account_context_fingerprint, account_catalog_fingerprint, selected_model, reasoning_effort, permission_profile_id, admission_manifest_semantic_fingerprint, admission_activation_receipt_fingerprint, admission_journal_absence_proof_json, admission_gate_fingerprint) on update restrict on delete restrict,
  unique(permit_id, permit_evidence_fingerprint, snapshot_identity_fingerprint),
  unique(permit_id, pid, start_marker),
  unique(permit_id, admission_id, route_id, node_id, activation_fingerprint, account_context_fingerprint, account_catalog_fingerprint, reserved_control_epoch, model, reasoning_effort, permission_profile_id, argv_fingerprint, compatibility_fingerprint, codex_snapshot_sha256, snapshot_identity_fingerprint, manifest_semantic_fingerprint, activation_receipt_fingerprint, journal_absence_proof_json, activation_gate_fingerprint),
  unique(legacy_source_backup_sha256, legacy_attempt_id),
  check(
    (state = 'LEGACY_IMPORTED' and admission_id is null and manifest_semantic_fingerprint is null and activation_receipt_fingerprint is null and journal_absence_proof_json is null and activation_gate_fingerprint is null and snapshot_identity_fingerprint is null and reserved_control_epoch = 0 and legacy_source_backup_sha256 is not null and legacy_attempt_id is not null and pid is not null and start_marker is null and resolved_at is not null and failure_code = 'LEGACY_V1') or
    (state <> 'LEGACY_IMPORTED' and admission_id is not null and manifest_semantic_fingerprint is not null and activation_receipt_fingerprint is not null and journal_absence_proof_json is not null and activation_gate_fingerprint is not null and snapshot_identity_fingerprint is not null and reserved_control_epoch between 1 and 9007199254740991 and legacy_source_backup_sha256 is null and legacy_attempt_id is null)
  ),
  check(
    (state = 'RESERVED' and guard_pid is null and guard_start_marker is null and pid is null and start_marker is null and one_time_token_hash is null and resolved_at is null and failure_code is null) or
    (state = 'GUARDED' and guard_pid is not null and guard_start_marker is not null and pid is null and start_marker is null and one_time_token_hash is not null and resolved_at is null and failure_code is null) or
    (state = 'COMMIT_AUTHORIZED' and guard_pid is not null and guard_start_marker is not null and pid = guard_pid and start_marker = guard_start_marker and one_time_token_hash is not null and resolved_at is null and failure_code is null) or
    (state = 'STARTED' and guard_pid is not null and guard_start_marker is not null and pid = guard_pid and start_marker = guard_start_marker and one_time_token_hash is not null and resolved_at is not null and failure_code is null) or
    (state in ('ABORTED_FREEZE', 'ABORTED_RECOVERY', 'ABORTED_ACCOUNT_CONTEXT_CHANGED', 'ABORTED_ACCOUNT_EVIDENCE_UNAVAILABLE', 'ABORTED_ACTIVATION_GATE_CHANGED', 'FAILED_BEFORE_START') and pid is null and start_marker is null and resolved_at is not null and failure_code is not null) or
    state = 'LEGACY_IMPORTED'
  ),
  check(state <> 'ABORTED_ACTIVATION_GATE_CHANGED' or failure_code = 'ABORTED_ACTIVATION_GATE_CHANGED'),
  check(state <> 'ABORTED_ACCOUNT_EVIDENCE_UNAVAILABLE' or (failure_code = 'ABORTED_ACCOUNT_EVIDENCE_UNAVAILABLE' and account_context_fingerprint is null and account_catalog_fingerprint is null)),
  check(state in ('ABORTED_ACCOUNT_EVIDENCE_UNAVAILABLE', 'LEGACY_IMPORTED') or (account_context_fingerprint is not null and account_catalog_fingerprint is not null))
);

create table attempts (
  attempt_id text primary key,
  route_id text not null references routes(route_id) on delete cascade,
  node_id text not null,
  state text not null check(state in ('STARTING', 'RUNNING', 'SUCCEEDED', 'FAILED', 'CANCELLED', 'QUARANTINED')),
  model text not null,
  reasoning_effort text not null,
  permission_profile_id text not null,
  pid integer not null,
  argv_fingerprint text not null,
  permission_probe_id text not null,
  attestation_json text,
  result_json text,
  error_code text,
  error_message text,
  started_at text not null,
  ended_at text,
  launch_permit_id text not null unique,
  activation_fingerprint text not null check(length(activation_fingerprint) = 64 and activation_fingerprint not glob '*[^0-9a-f]*'),
  account_context_fingerprint text not null check(length(account_context_fingerprint) = 64 and account_context_fingerprint not glob '*[^0-9a-f]*'),
  account_catalog_fingerprint text not null check(length(account_catalog_fingerprint) = 64 and account_catalog_fingerprint not glob '*[^0-9a-f]*'),
  launch_control_epoch integer not null check(launch_control_epoch between 0 and 9007199254740991),
  controller_identity text not null,
  controller_instance_id text not null,
  evidence_kind text not null check(evidence_kind in ('V2_ATTESTED', 'V1_LEGACY')),
  codex_binary_sha256 text,
  codex_snapshot_sha256 text,
  compatibility_fingerprint text not null check(length(compatibility_fingerprint) = 64 and compatibility_fingerprint not glob '*[^0-9a-f]*'),
  snapshot_identity_fingerprint text,
  permit_evidence_fingerprint text not null check(length(permit_evidence_fingerprint) = 64 and permit_evidence_fingerprint not glob '*[^0-9a-f]*'),
  admission_id text,
  manifest_semantic_fingerprint text,
  activation_receipt_fingerprint text,
  journal_absence_proof_json text,
  activation_gate_fingerprint text,
  process_start_marker text,
  foreign key(route_id, node_id) references nodes(route_id, node_id) on update restrict on delete restrict,
  foreign key(launch_permit_id, permit_evidence_fingerprint, snapshot_identity_fingerprint) references node_launch_permits(permit_id, permit_evidence_fingerprint, snapshot_identity_fingerprint) on update restrict on delete restrict,
  foreign key(launch_permit_id, pid, process_start_marker) references node_launch_permits(permit_id, pid, start_marker) on update restrict on delete restrict,
  foreign key(launch_permit_id, admission_id, route_id, node_id, activation_fingerprint, account_context_fingerprint, account_catalog_fingerprint, launch_control_epoch, model, reasoning_effort, permission_profile_id, argv_fingerprint, compatibility_fingerprint, codex_snapshot_sha256, snapshot_identity_fingerprint, manifest_semantic_fingerprint, activation_receipt_fingerprint, journal_absence_proof_json, activation_gate_fingerprint) references node_launch_permits(permit_id, admission_id, route_id, node_id, activation_fingerprint, account_context_fingerprint, account_catalog_fingerprint, reserved_control_epoch, model, reasoning_effort, permission_profile_id, argv_fingerprint, compatibility_fingerprint, codex_snapshot_sha256, snapshot_identity_fingerprint, manifest_semantic_fingerprint, activation_receipt_fingerprint, journal_absence_proof_json, activation_gate_fingerprint) on update restrict on delete restrict,
  check(
    (evidence_kind = 'V2_ATTESTED' and launch_control_epoch between 1 and 9007199254740991 and codex_binary_sha256 is not null and codex_snapshot_sha256 is not null and snapshot_identity_fingerprint is not null and admission_id is not null and manifest_semantic_fingerprint is not null and activation_receipt_fingerprint is not null and journal_absence_proof_json is not null and activation_gate_fingerprint is not null and process_start_marker is not null) or
    (evidence_kind = 'V1_LEGACY' and state not in ('STARTING', 'RUNNING') and launch_control_epoch = 0 and codex_binary_sha256 is null and codex_snapshot_sha256 is null and snapshot_identity_fingerprint is null and admission_id is null and manifest_semantic_fingerprint is null and activation_receipt_fingerprint is null and journal_absence_proof_json is null and activation_gate_fingerprint is null and process_start_marker is null)
  )
);

create index attempts_route_started on attempts(route_id, started_at);

create table runtime_artifacts (
  artifact_id text primary key,
  route_id text not null references routes(route_id) on delete cascade,
  node_id text not null,
  kind text not null,
  path text not null unique,
  allowed_root text not null,
  state text not null check(state in ('RESERVED', 'ACTIVE', 'TERMINAL', 'MISSING')),
  device integer,
  inode integer,
  created_at text not null,
  updated_at text not null
);

create index runtime_artifacts_route on runtime_artifacts(route_id, created_at);

create table quarantine_repositories (
  repository_id text primary key check(length(repository_id) = 47),
  source_root text not null unique,
  state_root text not null,
  git_dir text not null unique,
  state text not null check(state in ('ACTIVE')),
  created_at text not null,
  updated_at text not null
);

create table candidate_publication_intents (
  intent_id text primary key check(length(intent_id) = 48),
  route_id text not null,
  node_id text not null,
  repository_id text not null references quarantine_repositories(repository_id),
  artifact_id text not null check(length(artifact_id) = 48),
  ref text not null check(length(ref) between 1 and 512),
  base_source_sha text not null check(length(base_source_sha) = 40),
  base_commit_sha text not null check(length(base_commit_sha) = 40),
  base_tree_sha text not null check(length(base_tree_sha) = 40),
  commit_sha text not null check(length(commit_sha) = 40),
  tree_sha text not null check(length(tree_sha) = 40),
  validation_proof_sha256 text check(validation_proof_sha256 is null or (length(validation_proof_sha256) = 64 and validation_proof_sha256 not glob '*[^0-9a-f]*')),
  state text not null check(state in ('PENDING', 'COMPLETED', 'RECOVERED', 'ABORTED', 'QUARANTINED')),
  created_at text not null,
  updated_at text not null,
  completed_at text,
  foreign key(route_id, node_id) references nodes(route_id, node_id) on delete cascade,
  unique(repository_id, ref)
);

create index candidate_intents_state on candidate_publication_intents(state, created_at);

create table candidate_registry (
  candidate_id text primary key check(length(candidate_id) = 49),
  route_id text,
  node_id text,
  repository_id text not null references quarantine_repositories(repository_id),
  intent_id text unique references candidate_publication_intents(intent_id),
  artifact_id text not null check(length(artifact_id) in (48, 51)),
  ref text not null check(length(ref) between 1 and 512),
  base_source_sha text not null check(length(base_source_sha) in (0, 40)),
  base_commit_sha text not null check(length(base_commit_sha) in (0, 40)),
  base_tree_sha text not null check(length(base_tree_sha) in (0, 40)),
  commit_sha text not null check(length(commit_sha) in (0, 40)),
  tree_sha text not null check(length(tree_sha) in (0, 40)),
  observed_commit_sha text not null check(length(observed_commit_sha) in (0, 40)),
  observed_tree_sha text not null check(length(observed_tree_sha) in (0, 40)),
  state text not null check(state in ('VERIFIED', 'VALIDATION_QUARANTINED', 'RECOVERED_QUARANTINED', 'ORPHANED_QUARANTINED', 'REF_MISSING_QUARANTINED', 'REF_MISMATCH_QUARANTINED')),
  validation_state text not null check(validation_state in ('not_applicable', 'passed', 'failed', 'quarantined')),
  proof_hash text not null check(length(proof_hash) = 64),
  trusted integer not null check(trusted in (0, 1)),
  created_at text not null,
  updated_at text not null,
  foreign key(route_id, node_id) references nodes(route_id, node_id) on delete cascade,
  unique(repository_id, ref)
);

create index candidate_registry_route on candidate_registry(route_id, created_at);

create table schema_migrations (
  operation_id text primary key,
  database_id text not null references database_identity(database_id) on update restrict on delete restrict,
  from_version integer not null check(from_version in (0, 1)),
  to_version integer not null check(to_version = 2),
  source_shape text not null,
  source_schema_fingerprint text not null check(length(source_schema_fingerprint) = 64 and source_schema_fingerprint not glob '*[^0-9a-f]*'),
  source_backup_sha256 text not null check(length(source_backup_sha256) = 64 and source_backup_sha256 not glob '*[^0-9a-f]*'),
  target_schema_fingerprint text not null check(length(target_schema_fingerprint) = 64 and target_schema_fingerprint not glob '*[^0-9a-f]*'),
  target_database_projection_schema_id text not null check(target_database_projection_schema_id = 'database-object-v2'),
  target_database_projection_locator text not null,
  legacy_quiescence_proof_json text not null,
  applied_at text not null,
  unique(source_backup_sha256, to_version)
);

create index routes_state_created on routes(state, created_at);

create index controller_command_receipts_created on controller_command_receipts(created_at);

create index node_launch_permits_state on node_launch_permits(state, reserved_at);

create index node_launch_permits_route on node_launch_permits(route_id, node_id, reserved_at);

create unique index node_launch_permits_one_inflight on node_launch_permits(route_id, node_id) where state in ('RESERVED', 'GUARDED', 'COMMIT_AUTHORIZED');

create index schema_migrations_applied on schema_migrations(applied_at);
