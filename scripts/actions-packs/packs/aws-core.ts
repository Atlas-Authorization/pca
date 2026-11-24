import { botocorePack } from '../lib/factory';
import { readSources } from '../lib/source';

// Reviewed AWS rules (verb = aws.<service>.<operation>; first match wins).
const INFRA_SVC = /^aws\.(ec2|ecs|eks|rds|lambda|cloudformation|route53|ecr|iam|kms)\./;
const PROVISION_COST = /^aws\.(ec2\.(run_instances|create_nat_gateway|allocate_address|create_volume|create_fleet|request_spot_instances|create_vpc_endpoint|create_transit_gateway|create_capacity_reservation)|rds\.(create_db_instance|create_db_cluster|create_db_instance_read_replica|restore_db_instance_\w+|restore_db_cluster_\w+)|eks\.create_(cluster|nodegroup|fargate_profile)|ecs\.create_(cluster|service)|cloudformation\.(create_stack|create_stack_set|execute_change_set))$/;
const PAY = /^aws\.ec2\.(purchase_\w+|accept_reserved_instances_exchange_quote)$/;
const EXEC = /^aws\.(lambda\.(invoke|invoke_async|invoke_with_response_stream)|ecs\.(run_task|start_task|execute_command))$/;
const EXPORT = /^aws\.\w+\.(start_export_task|export_\w+|create_instance_export_task|create_store_image_task)$/;
const SEND: [RegExp, string][] = [
  [/^aws\.sns\.(publish|publish_batch)$/, 'TopicArn'],
  [/^aws\.sqs\.(send_message|send_message_batch)$/, 'QueueUrl'],
  [/^aws\.ses\.send_email$/, 'Destination'],
  [/^aws\.ses\.send_bulk_email$/, 'BulkEmailEntries'],
  [/^aws\.ses\.send_custom_verification_email$/, 'EmailAddress'],
];
const CRED_READ = /^aws\.(kms\.(decrypt|generate_data_key\w*|re_encrypt|generate_random)|secrets_manager\.(get_secret_value|batch_get_secret_value)|ec2\.get_password_data|ecr\.get_authorization_token|iam\.get_credential_report|iam\.get_access_key_last_used|s3\.create_session|kms\.(decapsulate|derive_shared_secret)|sts\.(get_session_token|get_federation_token|assume_\w+|get_web_identity_token))$/;
const CRED_WRITE = /^aws\.(secrets_manager\.(create_secret|put_secret_value|update_secret|rotate_secret|delete_secret)|iam\.(create_access_key|create_login_profile|update_login_profile|create_service_specific_credential|reset_service_specific_credential|create_virtual_mfa_device|enable_mfa_device|deactivate_mfa_device)|ec2\.(create_key_pair|import_key_pair)|kms\.(create_key|schedule_key_deletion|import_key_material))$/;

export default botocorePack({
  name: 'aws-core',
  ns: 'aws',
  redistribution: 'permitted',
  licence_notes: 'AWS service models are taken from botocore (Apache-2.0). Operation names, member names/types/bounds are carried; titles are generated from the operation name; the trait review is ours.',
  config_file: __filename,
  nsOf: () => 'aws',
  bc: (id) => ({ service: readSources('aws-core').find((s) => s.id === id)!.opts!.service }),
  build: () => ({
    ns: 'aws',
    vendorTitles: true,
    rules: [
      { re: PAY, on: 'verb', patch: { effects: ['pay'], rev: 'irreversible' } },
      { re: PROVISION_COST, on: 'verb', patch: { effects: ['provision'], rev: 'rate_limited', traits: ['pca.cost_incurring'] } },
      { re: EXEC, on: 'verb', patch: { effects: ['exec'], rev: 'irreversible' } },
      { re: EXPORT, on: 'verb', patch: { effects: ['export'], rev: 'irreversible' } },
      ...SEND.map(([re, recipient]) => ({ re, on: 'verb' as const, patch: { effects: ['send' as const], rev: 'irreversible' as const, recipient } })),
      { re: CRED_READ, on: 'verb', patch: { effects: ['read'], rev: 'reversible' } },
      { re: /^aws\.route53\.change_resource_record_sets$/, on: 'verb', patch: { effects: ['update', 'publish'], rev: 'irreversible' } },
      { re: /^aws\.dynamodb\.transact_write_items$/, on: 'verb', patch: { effects: ['update'], rev: 'rate_limited' } },
      { re: /^aws\.(iam\.simulate_\w+|kms\.(encrypt|encapsulate)|dynamodb\.transact_get_items|cloudformation\.(detect_\w+|test_type)|ses\.test_render_email_template|sts\.decode_authorization_message)$/, on: 'verb', patch: { effects: ['read'], rev: 'reversible' } },
      { re: /^aws\.kms\.(decapsulate|derive_shared_secret)$/, on: 'verb', patch: { effects: ['read'], rev: 'reversible' } },
      { re: /^aws\.kms\.schedule_key_deletion$/, on: 'verb', patch: { effects: ['delete'], rev: 'irreversible' } },
      { re: /^aws\.kms\.retire_grant$/, on: 'verb', patch: { effects: ['privilege'], rev: 'rate_limited' } },
      { re: /^aws\.(s3\.complete_multipart_upload|ecr\.(initiate|complete)_layer_upload)$/, on: 'verb', patch: { effects: ['create'], rev: 'reversible' } },
      { re: /^aws\.ec2\.(request_spot_fleet|allocate_hosts)$/, on: 'verb', patch: { effects: ['provision'], rev: 'rate_limited', traits: ['pca.cost_incurring'] } },
      { re: /^aws\.ec2\.(advertise_byoip_cidr|allocate_ipam_pool_cidr|deprovision_\w+|provision_\w+|withdraw_byoip_cidr|monitor_instances|unmonitor_instances|bundle_instance|confirm_product_instance|batch_policy_registrations)$/, on: 'verb', patch: { effects: ['update'], rev: 'rate_limited' } },
      { re: /^aws\.rds\.(failover_\w+|switchover_\w+|backtrack_db_cluster)$/, on: 'verb', patch: { effects: ['update'], rev: 'irreversible' } },
    ],
    declare: (v, _op, verb) => [
      ...(INFRA_SVC.test(verb) && !v.effects.every((e) => e === 'read') ? ['pca.infra_mutation'] : []),
      ...(CRED_READ.test(verb) || CRED_WRITE.test(verb) ? ['pca.credential_access'] : []),
    ],
  }),
});
