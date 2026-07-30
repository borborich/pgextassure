{{- define "pgextassure.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "pgextassure.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name (include "pgextassure.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "pgextassure.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | quote }}
{{ include "pgextassure.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "pgextassure.selectorLabels" -}}
app.kubernetes.io/name: {{ include "pgextassure.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "pgextassure.gatewayImage" -}}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest -}}
{{- end -}}

{{- define "pgextassure.envoyImage" -}}
{{- printf "%s@%s" .Values.mtls.envoy.repository .Values.mtls.envoy.digest -}}
{{- end -}}

{{- define "pgextassure.validate" -}}
{{- $mode := .Values.ledger.mode -}}
{{- if not (has $mode (list "sqlite" "postgres")) -}}
{{- fail "ledger.mode must be sqlite or postgres" -}}
{{- end -}}
{{- if lt (int .Values.replicaCount) 1 -}}
{{- fail "replicaCount must be at least one" -}}
{{- end -}}
{{- if not (regexMatch "^sha256:[a-f0-9]{64}$" .Values.image.digest) -}}
{{- fail "image.digest must be an independently verified sha256 digest" -}}
{{- end -}}
{{- if not (regexMatch "^sha256:[a-f0-9]{64}$" .Values.mtls.envoy.digest) -}}
{{- fail "mtls.envoy.digest must be a sha256 digest" -}}
{{- end -}}
{{- if empty .Values.mtls.existingSecret -}}
{{- fail "mtls.existingSecret is required" -}}
{{- end -}}
{{- if ne .Values.service.type "ClusterIP" -}}
{{- fail "service.type must remain ClusterIP in the reference profile" -}}
{{- end -}}
{{- if empty .Values.networkPolicy.ingressFrom -}}
{{- fail "networkPolicy.ingressFrom must name at least one trusted caller" -}}
{{- end -}}
{{- if eq $mode "sqlite" -}}
{{- if ne (int .Values.replicaCount) 1 -}}
{{- fail "SQLite ledger mode requires replicaCount=1" -}}
{{- end -}}
{{- else -}}
{{- if empty .Values.ledger.postgres.existingSecret -}}
{{- fail "ledger.postgres.existingSecret is required in PostgreSQL mode" -}}
{{- end -}}
{{- if empty .Values.networkPolicy.postgresEgress -}}
{{- fail "networkPolicy.postgresEgress is required in PostgreSQL mode" -}}
{{- end -}}
{{- end -}}
{{- end -}}
