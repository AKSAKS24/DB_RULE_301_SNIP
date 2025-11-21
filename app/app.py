from fastapi import FastAPI, Body
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
import re

app = FastAPI(
    title="Rule Arithmetic Modernization (ADD/SUBTRACT/MULTIPLY/DIVIDE)",
    version="2.0",
)

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------
class Finding(BaseModel):
    prog_name: Optional[str] = None
    incl_name: Optional[str] = None
    types: Optional[str] = None
    blockname: Optional[str] = None
    starting_line: Optional[int] = None
    ending_line: Optional[int] = None
    issues_type: Optional[str] = None
    severity: Optional[str] = None
    message: Optional[str] = None
    suggestion: Optional[str] = None
    snippet: Optional[str] = None


class Unit(BaseModel):
    pgm_name: str
    inc_name: str
    type: str
    name: Optional[str] = ""
    class_implementation: Optional[str] = None
    start_line: int = 0
    end_line: int = 0
    code: Optional[str] = ""
    findings: Optional[List[Finding]] = None


# ---------------------------------------------------------------------------
# Regex
# ---------------------------------------------------------------------------
ARITH_RE = re.compile(
    r"""
    ^\s*
    (?P<stmt>
        ADD\s+(?P<add_val>\w+)\s+TO\s+(?P<add_target>\w+)
        |
        SUBTRACT\s+(?P<sub_val>\w+)\s+FROM\s+(?P<sub_target>\w+)
        |
        MULTIPLY\s+(?P<mul_val>\w+)\s+BY\s+(?P<mul_target>\w+)
        |
        DIVIDE\s+(?P<div_val>\w+)\s+BY\s+(?P<div_target>\w+)
    )
    \.
    """,
    re.IGNORECASE | re.MULTILINE | re.VERBOSE,
)


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------
def extract_exact_line(src: str, start: int) -> str:
    line_start = src.rfind("\n", 0, start)
    if line_start == -1:
        line_start = 0
    else:
        line_start += 1
    line_end = src.find("\n", start)
    if line_end == -1:
        line_end = len(src)
    return src[line_start:line_end]


def make_finding(unit, src, start, end, stmt_type, value, target, original_stmt):
    abs_start = unit.start_line + src[:start].count("\n")
    abs_end = abs_start

    snippet = extract_exact_line(src, start).replace("\n", "\\n")

    suggestion = f"Replace '{original_stmt}' with '{target} { {'ADD':'+=', 'SUBTRACT':'-=', 'MULTIPLY':'*=', 'DIVIDE':'/='}[stmt_type] } {value}'."

    return Finding(
        prog_name=unit.pgm_name,
        incl_name=unit.inc_name,
        types=unit.type,
        blockname=unit.name,
        starting_line=abs_start,
        ending_line=abs_end,
        issues_type=f"Obsolete{stmt_type}Usage",
        severity="error",
        message=f"Obsolete '{stmt_type}' statement detected.",
        suggestion=suggestion,
        snippet=snippet,
    )


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------
def scan_unit(unit: Unit) -> Unit:
    src = unit.code or ""
    findings = []

    for m in ARITH_RE.finditer(src):
        stmt = m.group("stmt").strip()
        start, end = m.start(), m.end()

        if stmt.upper().startswith("ADD"):
            stmt_type = "ADD"
            value = m.group("add_val")
            target = m.group("add_target")
        elif stmt.upper().startswith("SUBTRACT"):
            stmt_type = "SUBTRACT"
            value = m.group("sub_val")
            target = m.group("sub_target")
        elif stmt.upper().startswith("MULTIPLY"):
            stmt_type = "MULTIPLY"
            value = m.group("mul_val")
            target = m.group("mul_target")
        elif stmt.upper().startswith("DIVIDE"):
            stmt_type = "DIVIDE"
            value = m.group("div_val")
            target = m.group("div_target")
        else:
            continue

        findings.append(
            make_finding(unit, src, start, end, stmt_type, value, target, stmt)
        )

    out = Unit(**unit.model_dump())
    out.findings = findings if findings else None
    return out


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@app.post("/remediate-array", response_model=List[Unit])
async def arithmetic_array(units: List[Unit] = Body(...)):
    results = []
    for u in units:
        res = scan_unit(u)
        if res.findings:
            results.append(res)
    return results


@app.post("/remediate", response_model=Unit)
async def arithmetic_single(unit: Unit = Body(...)):
    return scan_unit(unit)


@app.get("/health")
async def health():
    return {"ok": True, "rule": "arithmetic-modernization", "version": "2.0"}
