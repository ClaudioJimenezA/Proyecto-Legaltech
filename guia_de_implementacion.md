Plan de Implementación Técnica y Funcional: Plataforma LexPloit (Versión 2.0)

1. Visión General y Filosofía Arquitectónica

1.1. Propósito y Encuadre Normativo del Sistema

LexPloit es una plataforma integral de informática legal y cumplimiento normativo (compliance) diseñada para dotar de respaldo jurídico vinculante, trazabilidad operacional en tiempo real y certeza probatoria a las auditorías de ciberseguridad, pruebas de penetración (pentesting) y ejercicios de simulación de adversarios en Chile.

El sistema operacionaliza de manera automatizada las exigencias normativas del ordenamiento jurídico chileno en cuatro pilares legislativos complementarios:

1. Ley N° 21.459 sobre Delitos Informáticos: Implementa de forma técnica las cuatro condiciones copulativas del Artículo 2° que eximen de responsabilidad penal por acceso a sistemas (Art. 1°): existencia de autorización o mandato marco previo, ausencia de ánimo de apropiación o daño, sujeción a límites operativos no destructivos y cumplimiento del deber de reporte formal.
2. Ley N° 21.663 (Ley Marco de Ciberseguridad): Proporciona un mecanismo de desconflicto inmediato para operadores de importancia vital y prestadores de servicios esenciales, permitiendo al equipo de Operaciones o al Centro de Operaciones de Seguridad (SOC) del cliente correlacionar incidentes detectados con las pruebas autorizadas del auditor antes de activar reportes de incidentes obligatorios ante la Agencia Nacional de Ciberseguridad (ANCI).
3. Ley N° 21.719 sobre Protección de Datos Personales: Establece protocolos estrictos de minimización de datos, limitación de acceso por necesidad de conocer y purga certificada de evidencias técnicas dentro de plazos perentorios.
4. Ley N° 19.799 sobre Documentos Electrónicos y Firma Electrónica: Asegura la equivalencia funcional probatoria de los acuerdos de alcance y actas de cierre mediante mecanismos de firma digital y sellado criptográfico inmutable con algoritmo SHA-256.

1.2. Filosofía Arquitectónica: "Two Layers, Everywhere"

Inspirada en el rigor técnico documentado en el reporte de RutaHogar, la plataforma LexPloit implementa una estricta separación de dos capas en la totalidad de sus subsistemas:

* Capa Pura (Pure Logic Layer): Módulos deterministas y libres de efectos secundarios (side-effect free). No realizan operaciones de entrada/salida (I/O), llamadas de red ni consultas directas a base de datos. Aloja el motor de evaluación de reglas legales de la Ley N° 21.459, los validadores sintácticos de direccionamiento de red, el generador canonical de hash SHA-256, el algoritmo de correlación espacio-temporal de desconflicto y los serializadores de datos CSAF 2.0. Cada función es idempotente y verificable matemáticamente mediante pruebas unitarias en integración continua.
* Capa de Cableado (Wiring Layer): Módulos encargados de la infraestructura, conectividad y estado. Gestiona los controladores y rutas REST en FastAPI, la autenticación mediante tokens JWT, la persistencia en Supabase (PostgreSQL), la ejecución de políticas de seguridad por fila (Row Level Security), la ingesta de telemetría y el despacho de notificaciones asíncronas hacia los puntos de contacto.

1.3. Esquema de Comunicación y Componentes del Sistema

Componente	Rol en la Arquitectura	Tecnologías Principales	Responsabilidad Central
Cliente Web (Frontend)	Interfaz de usuario desacoplada por roles	React 18, Vite, TailwindCSS	Vistas especializadas para Auditor, Representante Legal y Operador SOC / PoC. Formularios de Scope, consola de logging en vivo y visor de desconflicto.
Servidor de Aplicación (Backend)	API RESTful stateless y lógica de negocio	Python 3.12, FastAPI, Pydantic v2	Exposición de contratos JSON validados, ejecución de la Capa Pura de compliance y orquestación de servicios.
Persistencia y Control de Acceso	Almacenamiento relacional y multi-tenant	PostgreSQL 15 (Supabase), RLS	Tablas estructuradas de acuerdos, bitácoras operativas, hallazgos y evidencias. Control de aislamiento de datos a nivel de fila.
Motor de Correlación y Desconflicto	Cruce espacio-temporal de telemetría	Consultas indexadas PostgreSQL / Capa Pura	Correlación automática entre eventos del SOC y registros del auditor para descartar falsas alarmas antes de denunciar a la ANCI.
Motor Documental y Exportación	Generación de entregables legales y técnicos	Jinja2, WeasyPrint, ElementTree	Producción de contratos y reportes PDF con sellado SHA-256, y serialización en XML/JSON bajo estándar OASIS CSAF 2.0.

2. Especificación del Frontend (React 18 + Vite)

2.1. Estructura de Directorios Modular

El código frontend adopta una estructura modular por dominios funcionales independientes bajo src/features/. Cada módulo mantiene encapsulados sus componentes visuales, hooks y servicios de consumo API, impidiendo dependencias cruzadas directas. La reutilización transversal se canaliza a través de src/lib/ para lógica pura y src/shared/ para componentes visuales comunes.

frontend/
|-- src/
|   |-- assets/                     # Recursos gráficos, marcas y tipografías
|   |-- features/                   # Dominios funcionales desacoplados
|   |   |-- auth/                   # Autenticación, sesión y contexto de roles
|   |   |-- roe_negotiation/        # PASO 1: Formulación de Scope y Doble Firma
|   |   |   |-- components/         # Editor de activos In-Scope, visor de contrato
|   |   |   |-- hooks/              # useRoeWorkflow, useCryptoSignature
|   |   |   \-- services/           # roeApi.js
|   |   |-- live_logger/            # PASO 2: Bitácora en Vivo y Desconflicto SOC
|   |   |   |-- components/         # Formulario de log rápido, consola de eventos,
|   |   |   |                       # buscador de correlación para el SOC
|   |   |   |-- hooks/              # useLiveAssessmentLogger, useDeconflictionSearch
|   |   |   \-- services/           # loggerApi.js, deconflictionApi.js
|   |   \-- vulnerability_tracking/ # PASO 3: Seguimiento de Hitos, Re-test y ANCI
|   |       |-- components/         # Matriz CVSS, modal de re-test, visor CSAF
|   |       |-- hooks/              # useVulnerabilityLifecycle, useExportReports
|   |       \-- services/           # vulnApi.js, exportApi.js
|   |-- lib/                        # CAPA PURA FRONTEND (Cero dependencias JSX)
|   |   |-- cvss_calculator.js      # Algoritmo determinista de score CVSS v3.1
|   |   |-- network_validators.js   # Expresiones regulares para FQDN, IPv4, IPv6, CIDR
|   |   \-- crypto_utils.js         # Funciones criptográficas WebCrypto API
|   |-- shared/                     # Componentes de UI genéricos (Tablas, Modales, Badges)
|   |-- routes/                     # Enrutador react-router con guardias por rol
|   |-- App.jsx                     # Componente raíz y proveedores de contexto
|   \-- main.jsx                    # Punto de entrada de la aplicación Vite
|-- package.json
\-- vite.config.js


2.2. Vistas Diferenciadas por Perfil de Usuario

* Perfil Auditor / Lead Pentester: Redacción de propuesta de RoE con activos macro y ventanas de ejecución; enrolamiento estricto de direcciones IP públicas de origen; consola de registro en tiempo real de pruebas ejecutadas (Live Assessment Logger); carga y estructuración de hallazgos técnicos clasificados por CVSS v3.1; gestión de la fase de re-test y generación del expediente de cierre para la ANCI.
* Perfil Representante Legal / Cliente: Bandeja de entrada para revisión de propuestas contractuales; canal de reparos u observaciones con control de versiones; suscripción de la primera firma digital con sellado temporal; autorización explícita para pruebas en infraestructura de nube de terceros.
* Perfil Punto de Contacto (PoC) y Operador SOC: Consola exclusiva de consulta y desconflicto de incidentes en tiempo real; cruce automatizado entre eventos anómalos detectados por el SIEM/WAF y la bitácora activa del auditor; generación y descarga del Comprobante Digital de Desconflicto para archivar el incidente internamente y fundamentar el descarte de denuncia formal ante la ANCI; panel de seguimiento de hitos de remediación interna.

3. Especificación del Backend (Python 3.12 + FastAPI)

3.1. Arquitectura de Módulos Backend

El backend se diseña bajo un patrón stateless que desacopla la lógica normativa de los mecanismos de entrega web, permitiendo despliegues elásticos en contenedores Docker o plataformas serverless.

backend/
|-- app/
|   |-- api/
|   |   |-- v1/
|   |   |   |-- endpoints/
|   |   |   |   |-- auth.py             # Autenticación y emisión de tokens JWT
|   |   |   |   |-- roe.py              # Negociación asíncrona de Scope y firmas
|   |   |   |   |-- logger.py           # Ingesta y consulta de logs de prueba
|   |   |   |   |-- deconfliction.py    # Motor de correlación y descarte SOC
|   |   |   |   |-- vulnerabilities.py  # Trazabilidad de hitos y re-test
|   |   |   |   \-- exports.py          # Emisión PDF y serialización XML CSAF
|   |   |   \-- api_router.py
|   |-- compliance_engine/              # CAPA PURA BACKEND
|   |   |-- rules_evaluator.py          # Verificación eximente Art. 2° Ley 21.459
|   |   |-- deconfliction_matcher.py    # Algoritmo de correlación temporal (+-2 min)
|   |   |-- scope_validator.py          # Verificación sintáctica y exclusión estatal
|   |   \-- canonical_hasher.py         # Normalización JSON y digest SHA-256
|   |-- core/
|   |   |-- config.py                   # Configuración centralizada vía Pydantic BaseSettings
|   |   |-- security.py                 # Criptografía, hashing y decodificación JWT
|   |   \-- database.py                 # Conexión asíncrona PostgreSQL / Supabase
|   |-- schemas/                        # Contratos Pydantic v2 en frontera
|   |   |-- roe_schema.py               # Modelos de Scope, activos y ventanas
|   |   |-- log_schema.py               # Modelos de telemetría de eventos de prueba
|   |   |-- deconfliction_schema.py     # Solicitud de cruce y resultado de desconflicto
|   |   |-- vulnerability_schema.py     # Hallazgos técnicos y métricas CVSS v3.1
|   |   \-- csaf_schema.py              # Estructura del estándar OASIS CSAF 2.0
|   \-- serializers/
|       |-- pdf_engine.py               # Compilador documental Jinja2 + WeasyPrint
|       \-- csaf_serializer.py          # Generador de árboles XML y JSON CSAF
|-- tests/                              # Suite de aseguramiento de calidad (Tier 1)
|-- Dockerfile
|-- requirements.txt
\-- main.py


3.2. Contratos Estrictos con Pydantic v2 en Frontera

from pydantic import BaseModel, Field, IPvAnyAddress, field_validator
from typing import List, Optional
from datetime import datetime
from enum import Enum
import re

class LogActivityTypeEnum(str, Enum):
    RECON_SCAN = "RECON_SCAN"
    VULN_PROBE = "VULN_PROBE"
    AUTH_ATTEMPT = "AUTH_ATTEMPT"
    EXPLOIT_POC = "EXPLOIT_POC"
    POST_EXPLOIT_VERIF = "POST_EXPLOIT_VERIF"
    OTHER = "OTHER"

class AssessmentLogCreateSchema(BaseModel):
    agreement_id: str = Field(..., description="UUID del acuerdo RoE activo")
    started_at: datetime = Field(..., description="Inicio exacto de la prueba en UTC")
    ended_at: Optional[datetime] = Field(None, description="Termino de la prueba")
    source_ip: IPvAnyAddress = Field(..., description="IP publica de origen del pentester")
    target_host: str = Field(..., min_length=3, max_length=255, description="FQDN o IP atacada")
    target_port: Optional[int] = Field(None, ge=1, le=65535, description="Puerto de red")
    target_endpoint: Optional[str] = Field(None, max_length=512, description="Ruta URL/API atacada")
    http_method: Optional[str] = Field(None, pattern="^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)$")
    injected_header_token: Optional[str] = Field(None, max_length=64, description="Valor del header X-Assessment-Scope")
    activity_type: LogActivityTypeEnum
    tool_or_technique: str = Field(..., min_length=2, max_length=150, description="Herramienta o vector ejecutado")
    description: str = Field(..., min_length=5, description="Detalle del procedimiento realizado")
    is_critical_finding: bool = Field(False, description="Marca si revelo acceso critico")

    @field_validator("ended_at")
    @classmethod
    def validate_log_window(cls, v, values):
        started = values.data.get("started_at")
        if started and v and v < started:
            raise ValueError("La fecha/hora de termino no puede preceder al inicio de la prueba.")
        return v

class DeconflictionQuerySchema(BaseModel):
    agreement_id: str
    incident_timestamp: datetime = Field(..., description="Timestamp de la alarma en el SIEM del cliente")
    observed_attacker_ip: IPvAnyAddress = Field(..., description="IP detectada por el WAF o IDS")
    targeted_asset: str = Field(..., min_length=3, max_length=255, description="Activo afectado")
    internal_ticket_ref: Optional[str] = Field(None, max_length=50, description="Numero de ticket interno SOC")


4. Integración Frontend - Backend - Persistencia (Supabase PostgreSQL)

4.1. Esquema Relacional de Base de Datos (PostgreSQL DDL)

El modelo de datos implementa las relaciones necesarias para gobernar el flujo de 3 pasos (Contrato -> Bitácora de Pruebas -> Trazabilidad de Hallazgos y Cierre), asegurando la integridad referencial y la trazabilidad probatoria requerida por los tribunales y la Agencia Nacional de Ciberseguridad.

-- Extension para generacion de identificadores unicos universales
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- 1. TIPOS Y ENUMERACIONES DEL SISTEMA
CREATE TYPE roe_status_enum AS ENUM (
    'DRAFT', 'UNDER_CLIENT_REVIEW', 'REVISION_REQUESTED', 
    'APPROVED_BY_CLIENT', 'SIGNED_AND_SEALED', 'ACTIVE', 'TERMINATED'
);

CREATE TYPE log_activity_type AS ENUM (
    'RECON_SCAN',          -- Escaneo pasivo o activo de puertos/servicios
    'VULN_PROBE',          -- Prueba de concepto / inyeccion de carga controlada
    'AUTH_ATTEMPT',        -- Evaluacion de mecanismos de autenticacion / fuerza bruta
    'EXPLOIT_POC',         -- Explotacion demostrativa no destructiva
    'POST_EXPLOIT_VERIF',  -- Verificacion de privilegios minimos alcanzados
    'OTHER'
);

CREATE TYPE deconfliction_status AS ENUM (
    'CONFIRMED_AUTHORIZED', -- Coincide con prueba autorizada (descarte de alarma)
    'UNMATCHED_SUSPICIOUS', -- No coincide con ningun log del pentester (alerta real)
    'INDETERMINATE'         -- Coincidencia parcial (requiere contacto manual con PoC)
);

CREATE TYPE vuln_status_enum AS ENUM (
    'IDENTIFIED', 'IN_REMEDIATION', 'READY_FOR_RETEST', 
    'RETEST_PASSED', 'RETEST_FAILED', 'CLOSED'
);

CREATE TYPE vuln_severity_enum AS ENUM (
    'INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
);

-- 2. TABLA DE ORGANIZACIONES Y CLIENTES
CREATE TABLE organizations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    legal_name VARCHAR(255) NOT NULL,
    tax_id VARCHAR(20) NOT NULL UNIQUE,       -- RUT chileno validado
    is_essential_service BOOLEAN DEFAULT FALSE, -- Clasificacion Ley 21.663
    is_vital_operator BOOLEAN DEFAULT FALSE,    -- Operador de Importancia Vital ANCI
    created_at TIMESTAMPTZ DEFAULT TIMEZONE('utc', NOW())
);

-- 3. TABLA DE ACUERDOS DE REGLAS DE COMPROMISO (PASO 1)
CREATE TABLE roe_agreements (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    title VARCHAR(255) NOT NULL,
    current_status roe_status_enum NOT NULL DEFAULT 'DRAFT',
    version INT NOT NULL DEFAULT 1,
    client_poc_id UUID NOT NULL,              -- Usuario PoC designado
    auditor_lead_id UUID NOT NULL,            -- Lead pentester responsable
    execution_start TIMESTAMPTZ NOT NULL,
    execution_end TIMESTAMPTZ NOT NULL,
    target_assets JSONB NOT NULL,             -- Lista estructurada de FQDN/IPs In-Scope
    excluded_assets JSONB NOT NULL DEFAULT '[]'::jsonb, -- Activos Out-of-Scope
    auditor_source_ips JSONB NOT NULL,        -- IPs publicas de salida del auditor
    traffic_header_token VARCHAR(64) NOT NULL,-- Token X-Assessment-Scope
    backup_confirmed BOOLEAN NOT NULL DEFAULT FALSE, -- Prerrequisito de respaldo
    cloud_authorization_confirmed BOOLEAN NOT NULL DEFAULT FALSE,
    sha256_hash VARCHAR(64),                  -- Digest de inmutabilidad
    client_signed_at TIMESTAMPTZ,
    auditor_signed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT TIMEZONE('utc', NOW()),
    updated_at TIMESTAMPTZ DEFAULT TIMEZONE('utc', NOW())
);

-- 4. TABLA DE BITACORA DE PRUEBAS EN VIVO (PASO 2: LIVE LOGGER)
CREATE TABLE assessment_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    agreement_id UUID NOT NULL REFERENCES roe_agreements(id) ON DELETE CASCADE,
    auditor_id UUID NOT NULL REFERENCES auth.users(id),
    started_at TIMESTAMPTZ NOT NULL DEFAULT TIMEZONE('utc', NOW()),
    ended_at TIMESTAMPTZ,                     -- Nulo si la prueba se encuentra en ejecucion
    source_ip INET NOT NULL,                  -- Validada contra auditor_source_ips
    target_host TEXT NOT NULL,                -- Dominio o IP evaluada
    target_port INTEGER CHECK (target_port BETWEEN 1 AND 65535),
    target_endpoint TEXT,                     -- Endpoint URI especifico
    http_method VARCHAR(10),
    injected_header_token TEXT,
    activity_type log_activity_type NOT NULL,
    tool_or_technique TEXT NOT NULL,
    description TEXT NOT NULL,
    is_critical_finding BOOLEAN DEFAULT FALSE,
    system_impact_observed TEXT,
    record_hash CHAR(64) NOT NULL,            -- SHA-256 inmutable del registro
    created_at TIMESTAMPTZ NOT NULL DEFAULT TIMEZONE('utc', NOW())
);

-- Indices de alta velocidad para cruces de desconflicto en tiempo real por el SOC
CREATE INDEX idx_logs_deconfliction ON assessment_logs (
    agreement_id, 
    source_ip, 
    started_at, 
    ended_at
);
CREATE INDEX idx_logs_target ON assessment_logs (target_host, started_at);

-- 5. TABLA DE CONSULTAS Y DESCONFLICTO DEL SOC (PASO 2)
CREATE TABLE deconfliction_queries (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    agreement_id UUID NOT NULL REFERENCES roe_agreements(id) ON DELETE CASCADE,
    queried_by UUID NOT NULL REFERENCES auth.users(id), -- Operador SOC / PoC
    incident_timestamp TIMESTAMPTZ NOT NULL,  -- Timestamp de la alarma SIEM/WAF
    observed_attacker_ip INET NOT NULL,
    targeted_asset TEXT NOT NULL,
    internal_ticket_ref TEXT,                 -- Ticket SOC (ej. INC-2026-904)
    matched_log_id UUID REFERENCES assessment_logs(id),
    resolution deconfliction_status NOT NULL,
    justification_notes TEXT,                 -- Fundamento para desestimar denuncia ANCI
    created_at TIMESTAMPTZ NOT NULL DEFAULT TIMEZONE('utc', NOW())
);

-- 6. TABLA DE ADJUNTOS Y EVIDENCIAS DE LOG
CREATE TABLE log_evidence_attachments (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    log_id UUID NOT NULL REFERENCES assessment_logs(id) ON DELETE CASCADE,
    file_path TEXT NOT NULL,                  -- Ruta en Supabase Storage cifrado
    file_hash CHAR(64) NOT NULL,             -- SHA-256 de la evidencia cruda
    mime_type TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT TIMEZONE('utc', NOW())
);

-- 7. TABLA DE VULNERABILIDADES Y TRAZABILIDAD DE REMEDIACION (PASO 3)
CREATE TABLE vulnerabilities (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    roe_agreement_id UUID NOT NULL REFERENCES roe_agreements(id) ON DELETE CASCADE,
    title VARCHAR(255) NOT NULL,
    cve_id VARCHAR(50),
    cwe_id VARCHAR(50),
    severity vuln_severity_enum NOT NULL,
    cvss_score NUMERIC(3, 1) NOT NULL,
    cvss_vector VARCHAR(100) NOT NULL,
    affected_asset VARCHAR(255) NOT NULL,
    technical_description TEXT NOT NULL,
    remediation_recommendation TEXT NOT NULL,
    current_status vuln_status_enum NOT NULL DEFAULT 'IDENTIFIED',
    created_at TIMESTAMPTZ DEFAULT TIMEZONE('utc', NOW()),
    updated_at TIMESTAMPTZ DEFAULT TIMEZONE('utc', NOW())
);

-- 8. TABLA DE BITACORA DE REMEDIACION Y RE-TEST (PASO 3)
CREATE TABLE remediation_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    vulnerability_id UUID NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    changed_by_user_id UUID NOT NULL REFERENCES auth.users(id),
    previous_status vuln_status_enum NOT NULL,
    new_status vuln_status_enum NOT NULL,
    comment TEXT,
    retest_evidence_url VARCHAR(512),
    created_at TIMESTAMPTZ NOT NULL DEFAULT TIMEZONE('utc', NOW())
);


4.2. Algoritmo SQL de Correlación y Desconflicto en Tiempo Real

Cuando el operador del SOC del cliente detecta una alarma en su consola de monitoreo (SIEM/WAF/EDR) que amenaza con detonar el protocolo de notificación obligatoria a la ANCI (plazo de 3 horas bajo la Ley N° 21.663), el backend ejecuta una consulta de intersección espaciotemporal determinista con una ventana de tolerancia de dos minutos para mitigar desalineaciones de relojes NTP:

SELECT 
    l.id AS matched_log_id,
    l.activity_type,
    l.tool_or_technique,
    l.target_endpoint,
    l.injected_header_token,
    CASE 
        WHEN l.id IS NOT NULL THEN 'CONFIRMED_AUTHORIZED'::deconfliction_status
        ELSE 'UNMATCHED_SUSPICIOUS'::deconfliction_status
    END AS resolution
FROM assessment_logs l
WHERE l.agreement_id = :current_agreement_id
  AND l.source_ip = :observed_attacker_ip
  AND :incident_timestamp BETWEEN (l.started_at - INTERVAL '2 minutes') 
                              AND (COALESCE(l.ended_at, l.started_at) + INTERVAL '2 minutes')
  AND (l.target_host ILIKE :targeted_asset OR :targeted_asset ILIKE ('%' || l.target_host || '%'))
ORDER BY l.started_at DESC
LIMIT 1;


4.3. Políticas de Seguridad por Fila (Row Level Security - RLS)

Para garantizar la confidencialidad estricta entre múltiples clientes y consultoras auditoras:

-- Habilitacion de RLS
ALTER TABLE roe_agreements ENABLE ROW LEVEL SECURITY;
ALTER TABLE assessment_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE deconfliction_queries ENABLE ROW LEVEL SECURITY;
ALTER TABLE vulnerabilities ENABLE ROW LEVEL SECURITY;

-- Politica de visualizacion de acuerdos: solo partes involucradas
CREATE POLICY roe_select_policy ON roe_agreements
    FOR SELECT USING (
        auth.uid() = auditor_lead_id OR auth.uid() = client_poc_id
    );

-- Politica de insercion y lectura en la bitacora de telemetria
CREATE POLICY log_insert_policy ON assessment_logs
    FOR INSERT WITH CHECK (
        auth.uid() = auditor_id AND 
        EXISTS (
            SELECT 1 FROM roe_agreements a 
            WHERE a.id = agreement_id AND a.current_status = 'ACTIVE'
        )
    );

CREATE POLICY log_select_policy ON assessment_logs
    FOR SELECT USING (
        EXISTS (
            SELECT 1 FROM roe_agreements a 
            WHERE a.id = agreement_id AND 
            (a.auditor_lead_id = auth.uid() OR a.client_poc_id = auth.uid())
        )
    );

-- Politica de desconflicto: operada por el PoC o SOC autorizado
CREATE POLICY deconfliction_policy ON deconfliction_queries
    FOR ALL USING (
        EXISTS (
            SELECT 1 FROM roe_agreements a 
            WHERE a.id = agreement_id AND a.client_poc_id = auth.uid()
        )
    );


5. Plan de Implementación de las Tres Funcionalidades Comprometidas

5.1. Funcionalidad Principal (Paso 1 - 25%): Módulo Asíncrono de Formalización de Scope, Reglas de Compromiso y Doble Firma con Hash SHA-256

5.1.1. Máquina de Estados de la Negociación Contractual

El acuerdo transita de forma determinista a través de estados predecibles que impiden el inicio de actividades de intrusión antes de completar la doble firma:

1. Estado DRAFT: El auditor redacta la propuesta definiendo objetivos macro (dominios, APIs, rangos CIDR) sin restringir puertos, asigna el Punto de Contacto titular/suplente y enrola las IPs de salida.
2. Estado UNDER_CLIENT_REVIEW: El cliente recibe la notificación y analiza las cláusulas en su visor web seguro.
3. Estado REVISION_REQUESTED: Si el cliente detecta activos no autorizados o ventanas horarias incompatibles, ingresa observaciones y devuelve el borrador al auditor.
4. Estado APPROVED_BY_CLIENT: El cliente acepta los términos y suscribe el documento mediante su firma digital.
5. Estado SIGNED_AND_SEALED: El auditor contra-firma la versión final. El sistema canonicaliza el documento, computa el hash SHA-256 inmutable y habilita la transición a ACTIVE durante la ventana temporal pactada. Concluida la ventana, pasa a TERMINATED.

5.1.2. Algoritmo de Sellado Criptográfico

El motor canonicaliza los datos del acuerdo ordenando alfabéticamente las claves y calculando:

	ext{Hash} = 	ext{SHA-256}(	ext{CanonicalJSON}(	ext{RoE\_Data}))

Este valor se almacena en roe_agreements.sha256_hash y se estampa de forma visible en el pie de página de cada versión emitida en PDF, garantizando que el texto suscrito no sufra modificaciones posteriores.

5.2. Funcionalidad Secundaria (Paso 2 - 15%): Bitácora de Telemetría en Vivo y Motor de Desconflicto de Incidentes (Live Assessment Logger & Deconfliction Engine)

5.2.1. Dinámica del Live Assessment Logger

Respondiendo a las directrices de Víctor Contreras y a la realidad operativa del pentesting (donde no se alerta a los administradores de infraestructura para preservar el realismo del ejercicio), el auditor registra sus acciones técnicas a medida que las ejecuta:

* Registro rápido manual a través de un panel optimizado para terminal o integración vía webhook desde consolas de ataque (Burp Suite, scripts Python).
* Parámetros capturados: timestamp exacto en UTC, IP de salida, activo y puerto destino, método HTTP, token de cabecera inyectado y tipo de actividad (RECON_SCAN, AUTH_ATTEMPT, EXPLOIT_POC).
* Cada entrada calcula un record_hash inalterable basado en sus atributos y el identificador del acuerdo.

5.2.2. Flujo de Desconflicto SOC y Prevención de Denuncias Erróneas ante la ANCI

1. Detección Anómala: El SIEM del cliente genera una alerta de intrusión o intento de fuerza bruta contra un servidor productivo a las 15:42:10 UTC.
2. Consulta Inmediata: El operador del SOC, antes de iniciar el escalamiento hacia la gerencia y activar el reporte formal a la ANCI (conforme a los artículos 5° y 37 de la Ley N° 21.663), ingresa al módulo de Desconflicto de LexPloit con la IP atacante y el timestamp del evento.
3. Cruce Algorítmico: El sistema consulta la tabla assessment_logs con la ventana de holgura de \pm 2 minutos.
4. Resolución:
  * Si hay coincidencia (CONFIRMED_AUTHORIZED), la pantalla confirma que el tráfico pertenece a la prueba autorizada del auditor. Se emite un Comprobante Digital de Desconflicto firmado que archiva el incidente internamente y desestima la denuncia ante la ANCI.
  * Si no hay coincidencia (UNMATCHED_SUSPICIOUS), el sistema alerta al SOC de que el tráfico proviene de un tercero malicioso real, procediendo de inmediato a la contención defensiva y al reporte formal a la autoridad.

5.3. Funcionalidad Terciaria (Paso 3 - 10%): Portal de Trazabilidad de Hitos, Ciclo de Remediación (Re-test) y Generación del Paquete de Cierre ANCI

5.3.1. Gestión del Ciclo de Vida de Vulnerabilidades

Sustituye la entrega de un documento estático por un tablero interactivo de gobernanza técnica:

1. Registro: El auditor clasifica la falla bajo el estándar CVSS v3.1 e ingresa la descripción técnica y pasos de reproducción no destructivos.
2. Priorización: El PoC revisa los hallazgos validados y traslada internamente el hito al estado IN_REMEDIATION.
3. Solicitud de Re-test: Implementados los parches o reglas de firewall, el PoC cambia el estado a READY_FOR_RETEST.
4. Certificación de Cierre: El auditor re-evalúa el vector. Si la brecha fue subsanada, se certifica como RETEST_PASSED; si subsiste, retorna a RETEST_FAILED.

5.3.2. Paquete de Reporte Dual (PDF Humano + XML CSAF Máquina)

Al término del proceso, el sistema compila dos artefactos:

* Canal Humano (PDF): Informe técnico-legal con resumen ejecutivo, métricas CVSS, evidencias fotográficas controladas y el Certificado de Cumplimiento Normativo del Art. 2° de la Ley N° 21.459, acreditando que la auditoría contó con mandato previo, no causó denegación de servicio y cumplió con el deber de reporte.
* Canal Máquina (XML CSAF 2.0 / JSON): Documento estructurado conforme a las especificaciones técnicas de la Agencia Nacional de Ciberseguridad, listo para ingesta automatizada por plataformas CSIRT.

6. Contratos de API REST

A continuación se definen los contratos formales de comunicación entre el frontend y el backend, estructurados bajo el estándar RESTful con serialización JSON en UTF-8 y autenticación Bearer JWT:

Endpoint	Método	Perfil Autorizado	Descripción Funcional y Reglas de Negocio
/api/v1/roe/proposals	POST	Auditor	Crea el borrador inicial de RoE con validación sintáctica de FQDN e IPs.
/api/v1/roe/{id}/send-to-client	POST	Auditor	Avanza el estado a UNDER_CLIENT_REVIEW y notifica por correo al PoC.
/api/v1/roe/{id}/request-revision	POST	Cliente	Devuelve el acuerdo a estado DRAFT con observaciones específicas.
/api/v1/roe/{id}/client-approve	POST	Cliente	Aprueba propuesta y estampa la primera firma electrónica.
/api/v1/roe/{id}/seal	POST	Auditor	Contra-firma, genera el hash SHA-256 canonical y emite el RoE oficial.
/api/v1/logs	POST	Auditor	Registra en tiempo real una prueba ejecutada en la bitácora (assessment_logs).
/api/v1/logs/active/{agreement_id}	GET	Ambos	Consulta la bitácora activa del proyecto con filtros de tiempo e IP.
/api/v1/deconfliction/match	POST	PoC / SOC	Cruza la alarma del SIEM/WAF con los logs activos (+-2 min) y emite resolución.
/api/v1/deconfliction/{id}/certificate	GET	PoC / SOC	Descarga el Comprobante Digital de Desconflicto firmado para archivar en ANCI.
/api/v1/vulnerabilities	POST	Auditor	Registra un hallazgo técnico estructurado con puntaje y vector CVSS v3.1.
/api/v1/vulnerabilities/{id}/status	PATCH	Ambos	Actualiza el hito en el ciclo de remediación (IN_REMEDIATION, READY_FOR_RETEST, etc.).
/api/v1/exports/pdf/{id}	GET	Ambos	Genera y descarga el reporte legal y técnico oficial en PDF.
/api/v1/exports/csaf/{id}	GET	Ambos	Exporta el paquete interoperable XML/JSON bajo estándar CSAF 2.0 para la ANCI.

7. Estrategia de Seguridad, Datos y Requerimientos No Funcionales

7.1. Cero Retención Prolongada y Purga Certificada (Ley N° 21.719)

En cumplimiento de los principios de minimización de datos, limitación del plazo de conservación y seguridad del tratamiento establecidos en la Ley N° 21.719 sobre Protección de Datos Personales:

* Prohibición de Almacenamiento Permanente de Datos de Prueba: Toda credencial recuperada o dato personal expuesto durante la prueba se procesa en memoria volátil o en almacenamiento temporal fuertemente cifrado mediante AES-256.
* Protocolo de Purga Automática: Los artefactos temporales de prueba, capturas de pantalla de evidencias y bitácoras operativas detalladas se eliminan de forma irreversible dentro del plazo perentorio de 14 días hábiles posteriores a la emisión del informe de cierre, dejando únicamente los metadatos estadísticos anonimizados y el hash de certificación probatoria.

7.2. Requerimientos No Funcionales Clave

* Tiempo de Respuesta (RNF 1): Los endpoints de consulta de desconflicto del SOC y de validación de reglas de negocio deben responder en un tiempo inferior a 3.0 segundos para permitir una toma de decisiones operativa inmediata ante alarmas críticas.
* Inmutabilidad y Cadena de Custodia (RNF 2): Los registros de la bitácora (assessment_logs) y los acuerdos de RoE firmados cuentan con resúmenes criptográficos SHA-256 generados al momento de la inserción, bloqueando cualquier modificación retroactiva mediante triggers de base de datos a nivel de motor PostgreSQL.
* Disponibilidad y Concurrencia (RNF 3): Arquitectura desacoplada y sin estado (stateless) capaz de procesar múltiples consultas simultáneas de desconflicto sin degradación del rendimiento de la base de datos gracias a los índices compuestos implementados.

8. Plan de Pruebas y Pipeline de Calidad (Tier 1 y Tier 2)

El aseguramiento de calidad de LexPloit adopta la estructura de dos niveles probada con éxito en RutaHogar:

8.1. Nivel 1 (Tier 1): Pruebas Automatizadas Unitarias e Invariantes

* Pytest (Backend):
  * test_compliance_rules.py: Comprueba que las 4 causales eximentes del Artículo 2° de la Ley N° 21.459 sean evaluadas estrictamente.
  * test_deconfliction_matcher.py: Valida matemáticamente que eventos ocurridos dentro de la ventana de \pm 2 minutos con la misma IP y activo destino sean resueltos como CONFIRMED_AUTHORIZED, y que eventos fuera de ventana arrojen UNMATCHED_SUSPICIOUS.
  * test_sha256_canonical_hash.py: Asegura que el hash SHA-256 sea determinista e idéntico ante permutaciones no semánticas del JSON.
  * test_supabase_rls_policies.py: Verifica que un usuario de la Organización A no pueda leer acuerdos, logs ni vulnerabilidades de la Organización B.
* Vitest (Frontend):
  * networkValidators.test.js: Validación exhaustiva de expresiones regulares para rangos CIDR, IPv4/IPv6 y dominios FQDN.
  * cvssCalculator.test.js: Evaluación determinista de scores CVSS v3.1 comparando contra vectores oficiales de NIST.

8.2. Nivel 2 (Tier 2): Pruebas de Integración y Extremo a Extremo (E2E)

* Playwright:
  * e2e_roe_negotiation.spec.js: Simula el flujo asíncrono completo: Auditor crea borrador -> Cliente revisa y aprueba -> Auditor sella con SHA-256.
  * e2e_live_logger_and_deconfliction.spec.js: Simula al auditor registrando un evento en la bitácora en vivo y posteriormente al operador del SOC consultando una alarma con timestamp coincidente, verificando la generación del comprobante de descarte para la ANCI.
  * e2e_vulnerability_retest_lifecycle.spec.js: Simula la transición de un hallazgo desde su identificación, paso a remediación, solicitud de re-test y cierre definitivo.
