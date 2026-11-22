"""Pure syntactic and regulatory scope validation for pentesting assets."""

from __future__ import annotations

from dataclasses import dataclass, field
import ipaddress
import re
from typing import Iterable

_FQDN_REGEX = re.compile(
    r"^(?:\*\.)?(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)

RESTRICTED_STATE_SUFFIXES: tuple[str, ...] = (
    ".gob.cl",
    ".gov.cl",
    ".mil.cl",
    ".defensa.cl",
    ".ejercito.cl",
    ".armada.cl",
    ".fach.cl",
    ".carabineros.cl",
    ".pdi.cl",
)


@dataclass(frozen=True)
class ScopeValidationResult:
    """Result of validating a set of scope assets or source IPs."""

    is_valid: bool
    valid_assets: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def normalize_asset(asset: str) -> str:
    """Normalize whitespace, scheme prefixes, and casing for an asset identifier."""
    cleaned = asset.strip().lower()
    if "://" in cleaned:
        cleaned = cleaned.split("://", 1)[1]
    cleaned = cleaned.split("/", 1)[0] if not _looks_like_cidr(cleaned) else cleaned
    return cleaned.rstrip(".")


def _looks_like_cidr(value: str) -> bool:
    if "/" not in value:
        return False
    host_part = value.split("/", 1)[0]
    try:
        ipaddress.ip_address(host_part)
        return True
    except ValueError:
        return False


def parse_ip_or_network(value: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    """Parse an IPv4/IPv6 address or CIDR range into an ip_network object."""
    try:
        return ipaddress.ip_network(value.strip(), strict=False)
    except ValueError:
        return None


def is_valid_fqdn(value: str) -> bool:
    """Return True if value is a syntactically valid FQDN (optionally wildcarded)."""
    cleaned = value.strip().rstrip(".").lower()
    return bool(_FQDN_REGEX.match(cleaned))


def is_valid_ip_or_cidr(value: str) -> bool:
    """Return True if value is a valid IPv4, IPv6, or CIDR network."""
    return parse_ip_or_network(value) is not None


def is_valid_asset(asset: str) -> bool:
    """Return True if asset is a valid FQDN, IP address, or CIDR range."""
    cleaned = asset.strip()
    if not cleaned:
        return False
    return is_valid_ip_or_cidr(cleaned) or is_valid_fqdn(cleaned)


def is_restricted_state_domain(asset: str) -> bool:
    """Check whether an asset belongs to a restricted Chilean state/military domain."""
    cleaned = asset.strip().rstrip(".").lower()
    return any(cleaned.endswith(suffix) or cleaned == suffix.lstrip(".") for suffix in RESTRICTED_STATE_SUFFIXES)


def _assets_overlap(target: str, excluded: str) -> bool:
    """Determine if a target asset overlaps with an excluded asset."""
    t_norm = target.strip().lower().rstrip(".")
    e_norm = excluded.strip().lower().rstrip(".")

    if t_norm == e_norm:
        return True

    t_net = parse_ip_or_network(t_norm)
    e_net = parse_ip_or_network(e_norm)
    if t_net is not None and e_net is not None and t_net.version == e_net.version:
        return t_net.overlaps(e_net)

    if e_norm.startswith("*.") and t_norm.endswith(e_norm[1:]):
        return True

    return False


def is_target_in_scope(
    target: str,
    target_assets: Iterable[str],
    excluded_assets: Iterable[str] = (),
) -> bool:
    """Check if a target host/IP is covered by target_assets and not excluded."""
    t_norm = normalize_asset(target)
    if not t_norm:
        return False

    for excluded in excluded_assets:
        if _assets_overlap(t_norm, excluded):
            return False

    t_net = parse_ip_or_network(t_norm)
    for allowed in target_assets:
        a_norm = allowed.strip().lower().rstrip(".")
        if t_norm == a_norm:
            return True
        if a_norm.startswith("*.") and t_norm.endswith(a_norm[1:]):
            return True
        a_net = parse_ip_or_network(a_norm)
        if t_net is not None and a_net is not None and t_net.version == a_net.version:
            if t_net.subnet_of(a_net):
                return True

    return False


def validate_scope_assets(
    target_assets: list[str],
    excluded_assets: list[str] | None = None,
    allow_state_domains: bool = False,
) -> ScopeValidationResult:
    """Validate syntax, state-domain restrictions, and exclusions for RoE scope assets."""
    excluded = excluded_assets or []
    errors: list[str] = []
    warnings: list[str] = []
    valid_assets: list[str] = []

    if not target_assets:
        return ScopeValidationResult(
            is_valid=False,
            errors=["Debe especificar al menos un activo objetivo (In-Scope)."],
        )

    for raw_excl in excluded:
        if not is_valid_asset(raw_excl):
            errors.append(f"Activo excluido con sintaxis invalida: '{raw_excl}'.")

    for raw_target in target_assets:
        cleaned = raw_target.strip()
        if not is_valid_asset(cleaned):
            errors.append(f"Activo objetivo con sintaxis invalida: '{raw_target}'.")
            continue

        if is_restricted_state_domain(cleaned) and not allow_state_domains:
            errors.append(
                f"Activo '{cleaned}' pertenece a un dominio estatal/defensa restringido "
                "(requiere autorizacion especial)."
            )
            continue

        net = parse_ip_or_network(cleaned)
        if net is not None and (net.is_loopback or net.is_unspecified or net.is_multicast):
            errors.append(f"Activo '{cleaned}' corresponde a un rango reservado no auditable.")
            continue

        if any(_assets_overlap(cleaned, excl) for excl in excluded):
            errors.append(f"Conflicto de alcance: '{cleaned}' coincide con la lista de excluidos.")
            continue

        if net is not None and net.is_private:
            warnings.append(f"El rango '{cleaned}' es una IP privada (RFC 1918); asegure acceso VPN/interno.")

        valid_assets.append(cleaned)

    return ScopeValidationResult(
        is_valid=len(errors) == 0,
        valid_assets=valid_assets,
        errors=errors,
        warnings=warnings,
    )


def validate_auditor_source_ips(source_ips: list[str]) -> ScopeValidationResult:
    """Validate that auditor exit IPs are syntactically valid public IPs or CIDRs."""
    if not source_ips:
        return ScopeValidationResult(
            is_valid=False,
            errors=["Debe enrolar al menos una IP publica de origen del auditor."],
        )

    errors: list[str] = []
    valid_ips: list[str] = []

    for raw_ip in source_ips:
        cleaned = raw_ip.strip()
        net = parse_ip_or_network(cleaned)
        if net is None:
            errors.append(f"IP de origen invalida: '{raw_ip}'.")
            continue
        if net.is_private or net.is_loopback or net.is_link_local or net.is_multicast or net.is_unspecified:
            errors.append(f"IP de origen '{cleaned}' debe ser una direccion publica enrutable.")
            continue
        valid_ips.append(cleaned)

    return ScopeValidationResult(
        is_valid=len(errors) == 0,
        valid_assets=valid_ips,
        errors=errors,
    )
