{{/* Expand the name of the chart. */}}
{{- define "discord-google-sso.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Fullname of the release. */}}
{{- define "discord-google-sso.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/* Common labels. */}}
{{- define "discord-google-sso.labels" -}}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version | replace "+" "_" }}
app.kubernetes.io/name: {{ include "discord-google-sso.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{/* The service account name. */}}
{{- define "discord-google-sso.serviceAccountName" -}}
{{ include "discord-google-sso.fullname" . }}
{{- end -}}

{{/* Discord API base URL with default. */}}
{{- define "discord-google-sso.discordBaseURL" -}}
{{- default "https://discord.com" .Values.discord.baseURL -}}
{{- end -}}

{{/* Google OIDC base URL with default. */}}
{{- define "discord-google-sso.googleBaseURL" -}}
{{- default "https://accounts.google.com" .Values.google.baseURL -}}
{{- end -}}

{{/* Discord callback URL with default. */}}
{{- define "discord-google-sso.discordCallbackURL" -}}
{{- default (printf "%s/callback/discord" .Values.publicBaseURL) .Values.discord.callbackURL -}}
{{- end -}}

{{/* Google callback URL with default. */}}
{{- define "discord-google-sso.googleCallbackURL" -}}
{{- default (printf "%s/callback/google" .Values.publicBaseURL) .Values.google.callbackURL -}}
{{- end -}}

{{/* Comma-joined list helper. */}}
{{- define "discord-google-sso.csv" -}}
{{- join "," . -}}
{{- end -}}
