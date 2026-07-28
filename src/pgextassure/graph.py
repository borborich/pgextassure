"""PostgreSQL extension install/update graph checks."""

from __future__ import annotations

from collections import defaultdict, deque
from pathlib import PurePosixPath
import re
from typing import Iterable

from .models import Finding, Severity
from .rules import ControlDocument


def _artifact(path: str) -> tuple[str, str, str | None] | None:
    name = PurePosixPath(path).name
    if name.endswith(".sql.in"):
        name = name[:-3]
    if not name.endswith(".sql"):
        return None
    parts = name[:-4].split("--")
    if len(parts) == 2 and all(parts):
        return parts[0], parts[1], None
    if len(parts) == 3 and all(parts):
        return parts[0], parts[1], parts[2]
    return None


def _reachable_many(
    starts: Iterable[str],
    edges: dict[str, set[str]],
) -> set[str]:
    seen = set(starts)
    queue = deque(sorted(seen))
    while queue:
        node = queue.popleft()
        for target in sorted(edges.get(node, ())):
            if target not in seen:
                seen.add(target)
                queue.append(target)
    return seen


def _reachable(start: str, edges: dict[str, set[str]]) -> set[str]:
    return _reachable_many((start,), edges)


def _has_cycle(nodes: set[str], edges: dict[str, set[str]]) -> bool:
    indegree = {node: 0 for node in nodes}
    for source in nodes:
        for target in edges.get(source, ()):
            if target in indegree:
                indegree[target] += 1

    queue = deque(sorted(node for node, degree in indegree.items() if degree == 0))
    visited = 0
    while queue:
        node = queue.popleft()
        visited += 1
        for target in sorted(edges.get(node, ())):
            if target not in indegree:
                continue
            indegree[target] -= 1
            if indegree[target] == 0:
                queue.append(target)
    return visited != len(indegree)


def _scoped_control(
    path: str,
    candidates: Iterable[ControlDocument],
    controls_by_prefix: dict[tuple[str, ...], tuple[ControlDocument, ...]],
) -> ControlDocument | None:
    options = tuple(candidates)
    if len(options) == 1:
        return options[0]
    if not options:
        return None

    artifact_parent = PurePosixPath(path).parent.parts
    for depth in range(len(artifact_parent), -1, -1):
        matches = controls_by_prefix.get(artifact_parent[:depth], ())
        if matches:
            same_parent = [
                control
                for control in matches
                if PurePosixPath(control.path).parent.parts == artifact_parent
            ]
            if same_parent:
                return same_parent[0] if len(same_parent) == 1 else None
            ancestors = [
                control
                for control in matches
                if (
                    len(PurePosixPath(control.path).parent.parts)
                    <= len(artifact_parent)
                    and artifact_parent[
                        : len(PurePosixPath(control.path).parent.parts)
                    ]
                    == PurePosixPath(control.path).parent.parts
                )
            ]
            if ancestors:
                deepest = max(
                    len(PurePosixPath(control.path).parent.parts)
                    for control in ancestors
                )
                winners = [
                    control
                    for control in ancestors
                    if len(PurePosixPath(control.path).parent.parts) == deepest
                ]
                return winners[0] if len(winners) == 1 else None
            return matches[0] if len(matches) == 1 else None
    return None


def scan_update_graph(
    sql_paths: Iterable[str],
    controls: Iterable[ControlDocument],
    *,
    max_findings: int | None = None,
) -> list[Finding]:
    ordered_controls = tuple(sorted(controls, key=lambda item: item.path))
    controls_by_extension: dict[str, list[ControlDocument]] = defaultdict(list)
    for control in ordered_controls:
        controls_by_extension[control.extension].append(control)
    scope_indexes: dict[
        str,
        dict[tuple[str, ...], tuple[ControlDocument, ...]],
    ] = {}
    for extension, candidates in controls_by_extension.items():
        grouped: dict[tuple[str, ...], list[ControlDocument]] = defaultdict(list)
        for control in candidates:
            parent = PurePosixPath(control.path).parent.parts
            for depth in range(len(parent) + 1):
                grouped[parent[:depth]].append(control)
        scope_indexes[extension] = {
            parent: tuple(items)
            for parent, items in grouped.items()
        }

    scope_cache: dict[tuple[str, tuple[str, ...]], ControlDocument | None] = {}

    def resolve_scope(extension: str, path: str) -> ControlDocument | None:
        parent = PurePosixPath(path).parent.parts
        key = (extension, parent)
        if key not in scope_cache:
            scope_cache[key] = _scoped_control(
                path,
                controls_by_extension.get(extension, ()),
                scope_indexes.get(extension, {}),
            )
        return scope_cache[key]

    bases: dict[str, dict[str, str]] = defaultdict(dict)
    edges: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    edge_paths: dict[tuple[str, str, str], str] = {}
    plain_install: dict[str, str] = {}
    ambiguous_artifacts: dict[str, tuple[str, tuple[str, ...]]] = {}

    def record_ambiguity(extension: str, path: str) -> None:
        candidates = controls_by_extension.get(extension, ())
        if len(candidates) <= 1:
            return
        ambiguous_artifacts[path] = (
            extension,
            tuple(control.path for control in candidates),
        )

    for path in sorted(sql_paths):
        filename = PurePosixPath(path).name
        normalized = filename[:-3] if filename.endswith(".sql.in") else filename
        if normalized.endswith(".sql"):
            plain_extension = normalized[:-4]
            if plain_extension in controls_by_extension:
                control = resolve_scope(plain_extension, path)
                if control is not None:
                    plain_install[control.path] = path
                else:
                    record_ambiguity(plain_extension, path)
        parsed = _artifact(path)
        if parsed is None:
            continue
        extension, source, target = parsed
        control = resolve_scope(extension, path)
        if control is None:
            record_ambiguity(extension, path)
            continue
        scope = control.path
        if target is None:
            bases[scope][source] = path
        else:
            edges[scope][source].add(target)
            edge_paths[(scope, source, target)] = path

    findings: list[Finding] = []
    for path in sorted(ambiguous_artifacts):
        extension, candidates = ambiguous_artifacts[path]
        findings.append(
            Finding(
                rule_id="update.ambiguous-scope",
                severity=Severity.HIGH,
                title="Extension SQL has an ambiguous control-file scope",
                message=(
                    f"PgExtAssure cannot safely associate this {extension!r} "
                    "artifact with exactly one control file."
                ),
                path=path,
                line=1,
                evidence="candidate controls = " + ", ".join(candidates),
                capability="database.extension-update",
                remediation=(
                    "Keep one control file for an extension in each package scope "
                    "or separate duplicate packages into unambiguous directories."
                ),
            )
        )
        if max_findings is not None and len(findings) >= max_findings:
            return findings

    for control in ordered_controls:
        extension = control.extension
        scope = control.path
        default_version = control.values.get("default_version", "").strip()
        anchor_path = control.path

        graph = edges[scope]
        base_versions = set(bases[scope])
        nodes = set(base_versions)
        incoming: set[str] = set()
        for source, targets in graph.items():
            nodes.add(source)
            nodes.update(targets)
            incoming.update(targets)

        if _has_cycle(nodes, graph):
            findings.append(
                Finding(
                    rule_id="update.cycle",
                    severity=Severity.MEDIUM,
                    title="Extension update graph contains a cycle",
                    message=(
                        f"Update scripts for extension {extension!r} permit a cyclic "
                        "version transition."
                    ),
                    path=anchor_path,
                    line=1,
                    evidence=f"extension = {extension}",
                    capability="database.extension-update",
                    remediation="Remove cyclic transitions and keep update edges monotonic.",
                )
            )
            if max_findings is not None and len(findings) >= max_findings:
                return findings

        # Build templates often leave @VERSION@ placeholders unresolved. Limit
        # this exemption to template control files with a paired placeholder:
        # ``@`` itself is valid in a concrete PostgreSQL version name.
        unresolved_template_version = (
            control.path.casefold().endswith(".control.in")
            and re.search(
                r"@[A-Za-z_][A-Za-z0-9_]*@",
                default_version,
            )
            is not None
        )
        if not default_version or unresolved_template_version:
            continue

        roots = {node for node in nodes if node not in incoming}
        reachable_install_versions = _reachable_many(base_versions, graph)
        has_install_path = (
            scope in plain_install
            or default_version in reachable_install_versions
        )
        if not has_install_path:
            findings.append(
                Finding(
                    rule_id="update.install-script-missing",
                    severity=Severity.MEDIUM,
                    title="Default version has no install path",
                    message=(
                        f"No install script provides default version "
                        f"{default_version!r} for extension {extension!r}, either "
                        "directly or through a complete update path."
                    ),
                    path=anchor_path,
                    line=control.lines.get("default_version", 1),
                    evidence=f"default_version = {default_version}",
                    capability="database.extension-install",
                    remediation=(
                        f"Add {extension}--{default_version}.sql, {extension}.sql, "
                        "or a complete update chain from an installable version."
                    ),
                )
            )
            if max_findings is not None and len(findings) >= max_findings:
                return findings

        reverse_graph: dict[str, set[str]] = defaultdict(set)
        for source, targets in graph.items():
            for target in targets:
                reverse_graph[target].add(source)
        can_reach_default = _reachable(default_version, reverse_graph)
        entry_versions = _reachable_many(roots | base_versions, graph)
        for entry_version in sorted(entry_versions):
            if entry_version == default_version:
                continue
            if entry_version in can_reach_default:
                continue
            if entry_version in bases[scope]:
                evidence_path = bases[scope][entry_version]
            elif graph.get(entry_version):
                first_target = sorted(graph[entry_version])[0]
                evidence_path = edge_paths[
                    (scope, entry_version, first_target)
                ]
            else:
                evidence_path = anchor_path
            findings.append(
                Finding(
                    rule_id="update.missing-path",
                    severity=Severity.HIGH,
                    title="Update branch cannot reach the default version",
                    message=(
                        f"Extension {extension!r} has no update path from "
                        f"{entry_version!r} to default version {default_version!r}."
                    ),
                    path=evidence_path,
                    line=1,
                    evidence=f"{entry_version} -/-> {default_version}",
                    capability="database.extension-update",
                    remediation=(
                        "Add the missing ordered update scripts or intentionally "
                        "remove the unsupported update branch."
                    ),
                )
            )
            if max_findings is not None and len(findings) >= max_findings:
                return findings
    return findings
