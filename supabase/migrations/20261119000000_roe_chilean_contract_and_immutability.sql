-- Migracion: Metadatos contractuales chilenos e inmutabilidad criptografica (Ley 19.799 y RNF 2)

-- 1. Columna JSONB para almacenar comparecencia legal, PoC titular/suplente, modalidad e historial de reparos
ALTER TABLE public.roe_agreements
ADD COLUMN IF NOT EXISTS contract_metadata JSONB NOT NULL DEFAULT '{}'::jsonb;

-- 2. Trigger de Inmutabilidad para acuerdos sellados con SHA-256 (RNF 2 Guia de Implementacion)
CREATE OR REPLACE FUNCTION public.enforce_sealed_roe_immutability()
RETURNS TRIGGER AS $$
BEGIN
    IF OLD.sha256_hash IS NOT NULL THEN
        -- Una vez sellado con SHA-256, solo se permite cambiar current_status (ej. SIGNED_AND_SEALED -> ACTIVE -> TERMINATED) y updated_at
        IF NEW.title IS DISTINCT FROM OLD.title
           OR NEW.organization_id IS DISTINCT FROM OLD.organization_id
           OR NEW.client_poc_id IS DISTINCT FROM OLD.client_poc_id
           OR NEW.auditor_lead_id IS DISTINCT FROM OLD.auditor_lead_id
           OR NEW.execution_start IS DISTINCT FROM OLD.execution_start
           OR NEW.execution_end IS DISTINCT FROM OLD.execution_end
           OR NEW.target_assets IS DISTINCT FROM OLD.target_assets
           OR NEW.excluded_assets IS DISTINCT FROM OLD.excluded_assets
           OR NEW.auditor_source_ips IS DISTINCT FROM OLD.auditor_source_ips
           OR NEW.traffic_header_token IS DISTINCT FROM OLD.traffic_header_token
           OR NEW.sha256_hash IS DISTINCT FROM OLD.sha256_hash
           OR NEW.client_signed_at IS DISTINCT FROM OLD.client_signed_at
           OR NEW.auditor_signed_at IS DISTINCT FROM OLD.auditor_signed_at
           OR (NEW.current_status <> 'TERMINATED' AND NEW.contract_metadata IS DISTINCT FROM OLD.contract_metadata)
        THEN
            RAISE EXCEPTION 'VIOLACION DE INMUTABILIDAD (Ley 19.799): El acuerdo RoE % ya fue sellado con SHA-256 (%) y su contenido no puede ser alterado.', OLD.id, OLD.sha256_hash;
        END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_enforce_sealed_roe_immutability ON public.roe_agreements;

CREATE TRIGGER trg_enforce_sealed_roe_immutability
BEFORE UPDATE ON public.roe_agreements
FOR EACH ROW
EXECUTE FUNCTION public.enforce_sealed_roe_immutability();
