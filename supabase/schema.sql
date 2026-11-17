-- WARNING: This schema is for context only and is not meant to be run.
-- Table order and constraints may not be valid for execution.

CREATE TABLE public.organizations (
  id uuid NOT NULL DEFAULT uuid_generate_v4(),
  legal_name character varying NOT NULL,
  tax_id character varying NOT NULL UNIQUE,
  is_essential_service boolean DEFAULT false,
  is_vital_operator boolean DEFAULT false,
  created_at timestamp with time zone DEFAULT timezone('utc'::text, now()),
  CONSTRAINT organizations_pkey PRIMARY KEY (id)
);
CREATE TABLE public.roe_agreements (
  id uuid NOT NULL DEFAULT uuid_generate_v4(),
  organization_id uuid NOT NULL,
  title character varying NOT NULL,
  current_status USER-DEFINED NOT NULL DEFAULT 'DRAFT'::roe_status_enum,
  version integer NOT NULL DEFAULT 1,
  client_poc_id uuid NOT NULL,
  auditor_lead_id uuid NOT NULL,
  execution_start timestamp with time zone NOT NULL,
  execution_end timestamp with time zone NOT NULL,
  target_assets jsonb NOT NULL,
  excluded_assets jsonb NOT NULL DEFAULT '[]'::jsonb,
  auditor_source_ips jsonb NOT NULL,
  traffic_header_token character varying NOT NULL,
  backup_confirmed boolean NOT NULL DEFAULT false,
  cloud_authorization_confirmed boolean NOT NULL DEFAULT false,
  sha256_hash character varying,
  client_signed_at timestamp with time zone,
  auditor_signed_at timestamp with time zone,
  created_at timestamp with time zone DEFAULT timezone('utc'::text, now()),
  updated_at timestamp with time zone DEFAULT timezone('utc'::text, now()),
  CONSTRAINT roe_agreements_pkey PRIMARY KEY (id),
  CONSTRAINT roe_agreements_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES public.organizations(id)
);
CREATE TABLE public.assessment_logs (
  id uuid NOT NULL DEFAULT uuid_generate_v4(),
  agreement_id uuid NOT NULL,
  auditor_id uuid NOT NULL,
  started_at timestamp with time zone NOT NULL DEFAULT timezone('utc'::text, now()),
  ended_at timestamp with time zone,
  source_ip inet NOT NULL,
  target_host text NOT NULL,
  target_port integer CHECK (target_port >= 1 AND target_port <= 65535),
  target_endpoint text,
  http_method character varying,
  injected_header_token text,
  activity_type USER-DEFINED NOT NULL,
  tool_or_technique text NOT NULL,
  description text NOT NULL,
  is_critical_finding boolean DEFAULT false,
  system_impact_observed text,
  record_hash character NOT NULL,
  created_at timestamp with time zone NOT NULL DEFAULT timezone('utc'::text, now()),
  CONSTRAINT assessment_logs_pkey PRIMARY KEY (id),
  CONSTRAINT assessment_logs_agreement_id_fkey FOREIGN KEY (agreement_id) REFERENCES public.roe_agreements(id),
  CONSTRAINT assessment_logs_auditor_id_fkey FOREIGN KEY (auditor_id) REFERENCES auth.users(id)
);
CREATE TABLE public.deconfliction_queries (
  id uuid NOT NULL DEFAULT uuid_generate_v4(),
  agreement_id uuid NOT NULL,
  queried_by uuid NOT NULL,
  incident_timestamp timestamp with time zone NOT NULL,
  observed_attacker_ip inet NOT NULL,
  targeted_asset text NOT NULL,
  internal_ticket_ref text,
  matched_log_id uuid,
  resolution USER-DEFINED NOT NULL,
  justification_notes text,
  created_at timestamp with time zone NOT NULL DEFAULT timezone('utc'::text, now()),
  CONSTRAINT deconfliction_queries_pkey PRIMARY KEY (id),
  CONSTRAINT deconfliction_queries_agreement_id_fkey FOREIGN KEY (agreement_id) REFERENCES public.roe_agreements(id),
  CONSTRAINT deconfliction_queries_queried_by_fkey FOREIGN KEY (queried_by) REFERENCES auth.users(id),
  CONSTRAINT deconfliction_queries_matched_log_id_fkey FOREIGN KEY (matched_log_id) REFERENCES public.assessment_logs(id)
);
CREATE TABLE public.log_evidence_attachments (
  id uuid NOT NULL DEFAULT uuid_generate_v4(),
  log_id uuid NOT NULL,
  file_path text NOT NULL,
  file_hash character NOT NULL,
  mime_type text NOT NULL,
  created_at timestamp with time zone NOT NULL DEFAULT timezone('utc'::text, now()),
  CONSTRAINT log_evidence_attachments_pkey PRIMARY KEY (id),
  CONSTRAINT log_evidence_attachments_log_id_fkey FOREIGN KEY (log_id) REFERENCES public.assessment_logs(id)
);
CREATE TABLE public.vulnerabilities (
  id uuid NOT NULL DEFAULT uuid_generate_v4(),
  roe_agreement_id uuid NOT NULL,
  title character varying NOT NULL,
  cve_id character varying,
  cwe_id character varying,
  severity USER-DEFINED NOT NULL,
  cvss_score numeric NOT NULL,
  cvss_vector character varying NOT NULL,
  affected_asset character varying NOT NULL,
  technical_description text NOT NULL,
  remediation_recommendation text NOT NULL,
  current_status USER-DEFINED NOT NULL DEFAULT 'IDENTIFIED'::vuln_status_enum,
  created_at timestamp with time zone DEFAULT timezone('utc'::text, now()),
  updated_at timestamp with time zone DEFAULT timezone('utc'::text, now()),
  CONSTRAINT vulnerabilities_pkey PRIMARY KEY (id),
  CONSTRAINT vulnerabilities_roe_agreement_id_fkey FOREIGN KEY (roe_agreement_id) REFERENCES public.roe_agreements(id)
);
CREATE TABLE public.remediation_logs (
  id uuid NOT NULL DEFAULT uuid_generate_v4(),
  vulnerability_id uuid NOT NULL,
  changed_by_user_id uuid NOT NULL,
  previous_status USER-DEFINED NOT NULL,
  new_status USER-DEFINED NOT NULL,
  comment text,
  retest_evidence_url character varying,
  created_at timestamp with time zone NOT NULL DEFAULT timezone('utc'::text, now()),
  CONSTRAINT remediation_logs_pkey PRIMARY KEY (id),
  CONSTRAINT remediation_logs_vulnerability_id_fkey FOREIGN KEY (vulnerability_id) REFERENCES public.vulnerabilities(id),
  CONSTRAINT remediation_logs_changed_by_user_id_fkey FOREIGN KEY (changed_by_user_id) REFERENCES auth.users(id)
);