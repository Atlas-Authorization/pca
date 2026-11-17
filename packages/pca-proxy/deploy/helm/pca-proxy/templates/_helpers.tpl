{{- define "pca-proxy.name" -}}{{ default .Chart.Name .Values.nameOverride | trunc 40 | trimSuffix "-" }}{{- end -}}
{{- define "pca-proxy.fullname" -}}{{ printf "%s-%s" .Release.Name (include "pca-proxy.name" .) | trunc 52 | trimSuffix "-" }}{{- end -}}
{{- define "pca-proxy.labels" -}}
app.kubernetes.io/name: {{ include "pca-proxy.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}
{{- define "pca-proxy.selector" -}}
app.kubernetes.io/name: {{ include "pca-proxy.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/* The proxy config the pod runs: the user's `config` with the paths forced to the chart's volumes. */}}
{{- define "pca-proxy.config" -}}
{{- $c := deepCopy .Values.config -}}
{{- $_ := set $c "audit" (mustMergeOverwrite (default (dict) $c.audit) (dict "path" "/var/lib/pca-proxy/audit.jsonl")) -}}
{{- $_ := set $c "state" (mustMergeOverwrite (default (dict) $c.state) (dict "dir" "/var/lib/pca-proxy/state")) -}}
{{- $_ := set $c "approvals" (mustMergeOverwrite (default (dict) $c.approvals) (dict "store" "/var/lib/pca-proxy/approvals.json")) -}}
{{- $a := default (dict) $c.agent -}}
{{- $_ := set $a "principalKeyEnv" "PCA_PRINCIPAL_KEY" -}}
{{- if .Values.agent.goal }}{{ $_ := set $a "goal" .Values.agent.goal }}{{ end -}}
{{- if .Values.agent.revocationFile }}{{ $_ := set $a "revocationFile" .Values.agent.revocationFile }}{{ end -}}
{{- $_ := set $c "agent" $a -}}
{{- if .Values.agent.stateHmacSecret.name }}{{ $_ := set $c.state "hmacKeyEnv" "PCA_STATE_HMAC" }}{{ end -}}
{{- if $c.http -}}
{{- $h := $c.http -}}
{{- $_ := set $h "listen" (dict "host" "0.0.0.0" "port" 8788) -}}
{{- if .Values.openapi }}{{ $_ := set $h "openapi" "/etc/pca-proxy/openapi.yaml" }}{{ end -}}
{{- end -}}
{{ toYaml $c }}
{{- end -}}

{{/* The proxy container, for this chart's Deployment or for a pod you own: {{ include "pca-proxy.container" . | nindent 8 }} */}}
{{- define "pca-proxy.container" -}}
name: pca-proxy
image: "{{ .Values.image.repository }}:{{ default .Chart.AppVersion .Values.image.tag }}"
imagePullPolicy: {{ .Values.image.pullPolicy }}
args: ["http", "--config", "/etc/pca-proxy/pca-proxy.yaml"]
env:
  - name: PCA_PRINCIPAL_KEY
    valueFrom: { secretKeyRef: { name: {{ required "agent.principalKeySecret.name: name the Secret that holds the proxy's principal key" .Values.agent.principalKeySecret.name | quote }}, key: {{ .Values.agent.principalKeySecret.key | quote }} } }
{{- if .Values.agent.stateHmacSecret.name }}
  - name: PCA_STATE_HMAC
    valueFrom: { secretKeyRef: { name: {{ .Values.agent.stateHmacSecret.name | quote }}, key: {{ .Values.agent.stateHmacSecret.key | quote }} } }
{{- end }}
{{- with .Values.upstreamEnv }}
{{ toYaml . | indent 2 }}
{{- end }}
ports: [{ name: http, containerPort: 8788 }]
readinessProbe: { tcpSocket: { port: 8788 }, periodSeconds: 5 }
livenessProbe: { tcpSocket: { port: 8788 }, initialDelaySeconds: 10, periodSeconds: 10 }
resources: {{ toJson .Values.resources }}
securityContext: { allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, runAsNonRoot: true, capabilities: { drop: [ALL] } }
volumeMounts:
  - { name: pca-config, mountPath: /etc/pca-proxy, readOnly: true }
  - { name: pca-state, mountPath: /var/lib/pca-proxy }
{{- end -}}

{{/* The control-plane reporting container. */}}
{{- define "pca-proxy.controlPlaneContainer" -}}
name: control-plane-agent
image: {{ .Values.controlPlane.image | quote }}
command:
  - npx
  - "-y"
  - "@atlasauth/pca-control-plane@{{ .Values.controlPlane.version }}"
  - report
  - "--audit"
  - /var/lib/pca-proxy/audit.jsonl
  - "--source"
  - {{ .Values.controlPlane.source | quote }}
  - "--key"
  - /etc/pca-control-plane/{{ .Values.controlPlane.sourceKeySecret.key }}
  - "--agent"
  - {{ default .Release.Name .Values.controlPlane.agentName | quote }}
  - "--url"
  - {{ required "controlPlane.url is required when controlPlane.enabled" .Values.controlPlane.url | quote }}
  - "--follow"
env:
  - name: ATLAS_SECRET_KEY
    valueFrom: { secretKeyRef: { name: {{ required "controlPlane.apiKeySecret.name is required when controlPlane.enabled" .Values.controlPlane.apiKeySecret.name | quote }}, key: {{ .Values.controlPlane.apiKeySecret.key | quote }} } }
  - { name: npm_config_cache, value: /tmp/.npm }
  - { name: HOME, value: /tmp }
resources: { requests: { cpu: 20m, memory: 64Mi }, limits: { memory: 192Mi } }
securityContext: { allowPrivilegeEscalation: false, runAsNonRoot: true, runAsUser: 1000, capabilities: { drop: [ALL] } }
volumeMounts:
  - { name: pca-state, mountPath: /var/lib/pca-proxy, readOnly: true }
  - { name: cp-key, mountPath: /etc/pca-control-plane, readOnly: true }
  - { name: tmp, mountPath: /tmp }
{{- end -}}

{{/* Volumes the containers above need. */}}
{{- define "pca-proxy.volumes" -}}
- name: pca-config
  configMap: { name: {{ include "pca-proxy.fullname" . }} }
- name: pca-state
{{- if .Values.persistence.enabled }}
  persistentVolumeClaim: { claimName: {{ default (include "pca-proxy.fullname" .) .Values.persistence.existingClaim }} }
{{- else }}
  emptyDir: {}
{{- end }}
{{- if .Values.controlPlane.enabled }}
- name: cp-key
  secret: { secretName: {{ required "controlPlane.sourceKeySecret.name is required when controlPlane.enabled" .Values.controlPlane.sourceKeySecret.name | quote }}, defaultMode: 0440 }
- name: tmp
  emptyDir: {}
{{- end }}
{{- end -}}
