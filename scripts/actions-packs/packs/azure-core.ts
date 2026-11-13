import { openApiPack } from '../lib/factory';
import { snake } from '../lib/naming';

// Azure Resource Manager verbs: azure.<service>.<resource>.<operation>, from operationIds of the form Resource_Operation.
// Platform parameters (subscriptionId, api-version) are external references in these specs and are not exposed.
function rename(_segs: string[], info: { opId?: string; method: string; path: string }): string[] {
  const id = info.opId ?? `${info.method}_${info.path}`;
  const [g, ...rest] = id.split('_');
  return [snake(g!).replace(/_v_ms$/, '_vms'), snake(rest.join('_') || info.method)];
}

const PROVISION = /\.(virtual_machines|virtual_machine_scale_sets|disks|managed_clusters|web_apps|app_service_plans|load_balancers|application_gateways|virtual_network_gateways|azure_firewalls|public_ip_addresses|nat_gateways|storage_accounts|vaults|snapshots|galleries)\.(create_or_update|begin_create_or_update)$/;
const EXEC = /\.(virtual_machines|virtual_machine_scale_sets|virtual_machine_scale_set_vms|dedicated_hosts|network_virtual_appliances)\.(run_command|begin_run_command|power_off|start|restart|redeploy|reimage|reimage_all|reapply|deallocate|perform_maintenance|simulate_eviction|install_patches|assess_patches)$|\.(managed_clusters)\.(run_command|begin_run_command)$|\.web_apps\.(restart|start|stop|swap_slot\w*|sync_repository|sync_function_triggers|run_triggered_web_job|start_web_site_network_trace)$/;
const SECRET_READ = /\.(storage_accounts\.(list_keys|regenerate_key)|managed_clusters\.(list_cluster_admin_credentials|list_cluster_user_credentials|list_cluster_monitoring_user_credentials|rotate_cluster_certificates|rotate_service_account_signing_keys|reset_service_principal_profile|reset_aad_profile)|web_apps\.(list_publishing_credentials|list_application_settings|list_connection_strings|list_publishing_profile_xml_with_secrets|update_application_settings|update_connection_strings|list_sync_function_triggers|list_function_secrets|create_or_update_host_secret|create_or_update_function_secret)|secrets\.\w+|keys\.\w+|vaults\.(purge_deleted|recover_deleted))$/;
const PRIV = /^azure\.(authorization_\w+)\.\w+\.(create|delete|create_by_id|delete_by_id|create_or_update|create_or_update_by_id)$/;

export default openApiPack({
  name: 'azure-core',
  ns: 'azure',
  redistribution: 'permitted',
  licence_notes: 'Azure REST API specifications (Azure/azure-rest-api-specs) are MIT licensed. Operation ids, parameter names/types/bounds and short summaries are carried for a curated set of resource providers; the trait review is ours.',
  config_file: __filename,
  oa: () => ({ naming: 'opid', flatten: true, rename }),
  ops: (id, ops) => ops.map((o) => ({ ...o, path: [id.split('_')[0]!, ...o.path], bindings: { openapi: { ...o.bindings!.openapi!, operationId: `${id}:${o.opId}` } } })),
  build: () => ({
    ns: 'azure',
    vendorTitles: true,
    rules: [
      { re: PRIV, on: 'verb', patch: { effects: ['privilege'], rev: 'rate_limited' } },
      { re: /^azure\.(authorization_\w+)\.\w+\.(delete|delete_by_id)$/, on: 'verb', patch: { effects: ['delete', 'privilege'], rev: 'irreversible' } },
      { re: /\.(list_keys|list_cluster_\w+_credentials|list_publishing_credentials|list_function_secrets|list_application_settings|list_connection_strings|list_publishing_profile_xml_with_secrets|list_sync_function_triggers|get_secret|get_key)$/, on: 'verb', patch: { effects: ['read'], rev: 'reversible', traits: ['pca.credential_access'] } },
      { re: /\.storage_accounts\.regenerate_key$|rotate_\w+|reset_service_principal_profile|reset_aad_profile|\.storage_accounts\.revoke_user_delegation_keys/, on: 'verb', patch: { effects: ['update'], rev: 'irreversible', traits: ['pca.credential_access'] } },
      { re: /^azure\.network\.(put_bastion_shareable_link|delete_bastion_shareable_link|delete_shareable_link_token)\.post$/, on: 'verb', patch: { effects: ['privilege'], rev: 'rate_limited' } },
      { re: /^azure\.network\.get_bastion_shareable_link\.post$/, on: 'verb', patch: { effects: ['read'], rev: 'reversible', traits: ['pca.credential_access'] } },
      { re: /\.(regenerate_password|regenerate_access_key)$/, on: 'verb', patch: { effects: ['update'], rev: 'irreversible', traits: ['pca.credential_access'] } },
      { re: /\.azure_firewalls\.packet_capture$/, on: 'verb', patch: { effects: ['update'], rev: 'rate_limited', traits: ['pca.pii_access'] } },
      { re: /\.(generalize|object_level_worm|failover|customer_initiated_migration|hierarchical_namespace_migration|move\.post)$|^azure\.web\.move\.post$/, on: 'verb', patch: { effects: ['update'], rev: 'irreversible' } },
      { re: /\.(backend_health\w*|health|ddos_protection_status|get_active_sessions\.post|test_\w+|is_cloneable\w*|check_name_availability\.post|regional_check_name_availability\.post|validate\w*\.post|supported_vpn_devices|vpn_device_configuration_script|generatevpnclientpackage|list_assigned_host_name\.post|resolve_private_link_service_id\.post|packet_capture_operation|verify_hosting_environment_vnet\.post)$/, on: 'verb', patch: { effects: ['read'], rev: 'reversible' } },
      { re: /\.(approve_rolling_upgrade|force_update_domain_walk|migrate\w*|scale_out|swap_public_ip_addresses|commit_migration|prepare_migration|reserve_public_ip_address|prepare_network_policies|unprepare_network_policies|lease|reconcile|recycle_managed_instance_worker|restart_web_apps|restart_slot|recover\w*|resubmit|disconnect_active_sessions\.post)$/, on: 'verb', patch: { effects: ['update'], rev: 'rate_limited' } },
      { re: /\.log_analytics\.export_\w+$/, on: 'verb', patch: { effects: ['export'], rev: 'irreversible' } },
      { re: EXEC, on: 'verb', patch: { effects: ['exec'], rev: 'irreversible' } },
      { re: PROVISION, on: 'verb', patch: { effects: ['provision'], rev: 'rate_limited', traits: ['pca.cost_incurring'] } },
    ],
    declare: (v, _op, verb) => [
      ...(!v.effects.every((e) => e === 'read') && !/^azure\.(authorization|resources)/.test(verb) ? ['pca.infra_mutation'] : []),
      ...(/^azure\.keyvault\.(secrets|keys)\./.test(verb) || SECRET_READ.test(verb) ? ['pca.credential_access'] : []),
    ],
  }),
});
