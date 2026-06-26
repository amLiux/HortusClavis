{{- define "hortus-clavis.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "hortus-clavis.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{- define "hortus-clavis.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "hortus-clavis.labels" -}}
helm.sh/chart: {{ include "hortus-clavis.chart" . }}
{{ include "hortus-clavis.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "hortus-clavis.selectorLabels" -}}
app.kubernetes.io/name: {{ include "hortus-clavis.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "hortus-clavis.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "hortus-clavis.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{- define "hortus-clavis.databaseUrl" -}}
{{- if .Values.secrets.databaseUrl }}
{{- .Values.secrets.databaseUrl }}
{{- else }}
{{- $host := .Values.postgresql.host | required "postgresql.host or secrets.databaseUrl required" }}
{{- $port := .Values.postgresql.port | int }}
{{- $db := .Values.postgresql.database }}
{{- $user := .Values.postgresql.username }}
{{- $pass := .Values.postgresql.password | required "postgresql.password or secrets.databaseUrl required" }}
{{- printf "postgresql+asyncpg://%s:%s@%s:%d/%s" $user $pass $host $port $db }}
{{- end }}
{{- end }}

{{- define "hortus-clavis.redisUrl" -}}
{{- if .Values.secrets.redisUrl }}
{{- .Values.secrets.redisUrl }}
{{- else }}
{{- $host := .Values.redis.host | required "redis.host or secrets.redisUrl required" }}
{{- $port := .Values.redis.port | int }}
{{- $db := .Values.redis.db | int }}
{{- if .Values.redis.password }}
{{- printf "redis://default:%s@%s:%d/%d" .Values.redis.password $host $port $db }}
{{- else if .Values.redis.tls.enabled }}
{{- printf "rediss://%s:%d/%d" $host $port $db }}
{{- else }}
{{- printf "redis://%s:%d/%d" $host $port $db }}
{{- end }}
{{- end }}
{{- end }}
