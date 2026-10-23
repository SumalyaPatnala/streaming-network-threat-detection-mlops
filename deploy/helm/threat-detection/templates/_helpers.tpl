{{- define "threat-detection.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "threat-detection.fullname" -}}
{{- printf "%s-%s" .Release.Name (include "threat-detection.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "threat-detection.namespace" -}}
{{- default .Release.Namespace .Values.namespaceOverride -}}
{{- end -}}

{{- define "threat-detection.image" -}}
{{- if .Values.image.digest -}}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest -}}
{{- else -}}
{{- printf "%s:%s" .Values.image.repository .Values.image.tag -}}
{{- end -}}
{{- end -}}
