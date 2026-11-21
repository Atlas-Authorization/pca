import { discoveryPack } from '../lib/factory';

// Reviewed Google Cloud rules (verb = gcp.<service>.<resource>.<method>; first match wins).
const IAM_SET = /\.(set_iam_policy|set_iam_policy\w*)$/;
const IAM_READ = /\.(get_iam_policy|test_iam_permissions)$/;
const SECRET_READ = /^gcp\.(secretmanager\.projects\.secrets\.versions\.(access)|iamcredentials\.\w+\.(generate_access_token|generate_id_token|sign_blob|sign_jwt)|cloudkms\.projects\.locations\.key_rings\.crypto_keys\.(decrypt|crypto_key_versions\.(asymmetric_decrypt|get_public_key|mac_sign)))$/;
const SECRET_WRITE = /^gcp\.(secretmanager\.projects\.secrets\.(add_version|versions\.(destroy|disable|enable))|iam\.projects\.service_accounts\.keys\.(create|upload|delete)|cloudkms\.\w+\.crypto_key_versions\.(destroy|create|import)|compute\.instances\.set_metadata)$/;
const EXEC = /^gcp\.(cloudfunctions\.\w+\.functions\.(call|generate_\w+)|run\.projects\.locations\.jobs\.run|workflows\.projects\.locations\.workflows\.(executions\.create)|cloudbuild\.\w+\.builds\.(create|retry|approve)|cloudbuild\.\w+\.triggers\.(run)|dataflow\.\w+\.jobs\.(create|launch)\w*|dataproc\.\w+\.(jobs\.submit\w*|workflow_templates\.(instantiate\w*))|compute\.instances\.(start|reset|resume)|bigquery\.jobs\.insert|bigquery\.jobs\.query|cloudscheduler\.\w+\.jobs\.run|cloudtasks\.\w+\.tasks\.(run|create))$/;
const PROVISION = /^gcp\.(compute\.(instances\.insert|disks\.insert|addresses\.insert|forwarding_rules\.insert|instance_templates\.insert|instance_group_managers\.insert|networks\.insert|subnetworks\.insert|firewalls\.insert|vpn_tunnels\.insert|routers\.insert|reservations\.insert|snapshots\.insert|images\.insert)|container\.\w+\.clusters\.create|container\.\w+\.node_pools\.create|sqladmin\.instances\.(insert|clone)|redis\.\w+\.instances\.create|spanner\.projects\.instances\.create|dataproc\.\w+\.clusters\.create|run\.projects\.locations\.services\.create|cloudfunctions\.\w+\.functions\.create|pubsub\.projects\.(topics|subscriptions)\.create|storage\.buckets\.insert|bigquery\.datasets\.insert|dns\.managed_zones\.create)$/;
const EXPORT = /^gcp\.(sqladmin\.instances\.export|bigquery\.jobs\.insert_extract|firestore\.projects\.databases\.export_documents|logging\.entries\.list|logging\.\w+\.sinks\.create|compute\.images\.export)$/;
const PUBLISH = /^gcp\.(pubsub\.projects\.topics\.publish|storage\.objects\.(insert|compose|copy|rewrite)|storage\.\w+\.make_public)$/;
const DELETE_INFRA = /^gcp\.(compute|container|sqladmin|redis|spanner|dataproc|run|cloudfunctions|dns|storage|bigquery|pubsub)\./;
const PROJECT = /^gcp\.cloudresourcemanager\.(projects|folders|organizations)\.(delete|move|set_iam_policy|undelete)$/;

export default discoveryPack({
  name: 'gcp-core',
  ns: 'gcp',
  redistribution: 'permitted',
  licence_notes: 'Built from Google API discovery documents as published in googleapis/google-api-go-client (BSD-3-Clause). Method ids, parameter names/types/bounds and the first sentence of a method description are carried; the trait review is ours.',
  config_file: __filename,
  disc: () => ({ servicePath: true }),
  build: () => ({
    ns: 'gcp',
    vendorTitles: true,
    rules: [
      { re: PROJECT, on: 'verb', patch: { effects: ['delete', 'privilege'], rev: 'irreversible' } },
      { re: IAM_SET, on: 'verb', patch: { effects: ['privilege'], rev: 'rate_limited' } },
      { re: IAM_READ, on: 'verb', patch: { effects: ['read'], rev: 'reversible' } },
      { re: SECRET_READ, on: 'verb', patch: { effects: ['read'], rev: 'reversible' } },
      { re: EXPORT, on: 'verb', patch: { effects: ['export'], rev: 'irreversible', scope: 'one' } },
      { re: PUBLISH, on: 'verb', patch: { effects: ['publish'], rev: 'irreversible' } },
      { re: EXEC, on: 'verb', patch: { effects: ['exec'], rev: 'irreversible' } },
      { re: /\.(asymmetric_sign|mac_sign)$/, on: 'verb', patch: { effects: ['sign'], rev: 'irreversible', traits: ['pca.credential_access'] } },
      { re: /\.(asymmetric_decrypt|decapsulate|raw_decrypt|decrypt)$/, on: 'verb', patch: { effects: ['read'], rev: 'reversible', traits: ['pca.credential_access'] } },
      { re: /\.export_crypto_key_version$/, on: 'verb', patch: { effects: ['export'], rev: 'irreversible', scope: 'one', traits: ['pca.credential_access'] } },
      { re: /^gcp\.cloudkms\..*proposals\.approve$/, on: 'verb', patch: { effects: ['privilege'], rev: 'irreversible' } },
      { re: /\.(export_metadata|export_image_metadata|export_project_metadata|files\.download)$/, on: 'verb', patch: { effects: ['export'], rev: 'irreversible', scope: 'one' } },
      { re: /^gcp\.(cloudbuild|dataproc)\..*\.(retry|approve|webhook|instantiate\w*|inject_credentials)$/, on: 'verb', patch: { effects: ['exec'], rev: 'irreversible' } },
      { re: /\.(wait|advice\.\w+|calendar_mode|capacity|capacity_history|partition_query|partition_read|streaming_read|begin_transaction|listen|diagnose|analyze|pull|simulate_maintenance_event|export_status|lease|worker_messages|adapt_message|adapter|pre_check_major_version_upgrade|mac_verify|encrypt|raw_encrypt|test_iam_permissions_\d+)$|\.advice\.\w+$/, on: 'verb', patch: { effects: ['read'], rev: 'reversible' } },
      { re: /\.(resize|abandon_instances|recreate_instances|perform_maintenance|switch_to_custom_mode|request_remove_peering|deprecate|invalidate_cache|expand_ip_cidr_range|advance|complete_\w+|rollback\w*|addons|legacy_abac|locations|logging|master|monitoring|resource_labels|autoscaling|commit\w*|acknowledge|seek|buffer|failover|restart|switchover|point_in_time_restore|reencrypt|acquire_ssrs_lease|perform_disk_shrink|changequorum|relocate|advance_relocate_bucket|withdraw|prewarm_artifact|redirect_upgrade_traffic|setup_function_upgrade_config|repair|snapshot)$/, on: 'verb', patch: { effects: ['update'], rev: 'rate_limited' } },
      { re: PROVISION, on: 'verb', patch: { effects: ['provision'], rev: 'rate_limited', traits: ['pca.cost_incurring'] } },
    ],
    declare: (v, _op, verb) => [
      ...(DELETE_INFRA.test(verb) && !v.effects.every((e) => e === 'read') ? ['pca.infra_mutation'] : []),
      ...(SECRET_READ.test(verb) || SECRET_WRITE.test(verb) || /^gcp\.secretmanager\./.test(verb) ? ['pca.credential_access'] : []),
    ],
  }),
});
