"""Extract ordered, full-text workflow dossiers from a PDF."""

from __future__ import annotations

import collections
import dataclasses
import math
import pathlib
import re
import subprocess
import tempfile


@dataclasses.dataclass
class WorkflowSection:
    phase_id: str
    title: str
    hierarchy_level: int
    page_range: list[int]
    word_count: int
    architectural_summary: str
    technical_entities: list[str]
    effort_weight: float
    body_text: str


HEADING = re.compile(r"^(?:(?:phase|stage|milestone|step|chapter|section)\s*)?(\d+(?:\.\d+)*)(?:[.):]|\s+-)?\s+(.{4,100})$", re.I)
ENTITY = re.compile(r"(?:/[A-Za-z0-9_{}./:-]{3,}|\b[A-Za-z_][\w]*(?:\.[A-Za-z_]\w*)+\b|\b[A-Z][a-z]+(?:[A-Z][a-z]+)+\b|\b[A-Z][A-Z0-9_]{3,}\b|\b(?i:table|model|class|function|endpoint|route|library|package)\s+[A-Za-z_][\w.-]+)")
STOP = {"phase", "stage", "section", "workflow", "implementation", "project", "system", "requirements", "architecture"}
COMMON = STOP | {"about", "after", "before", "between", "build", "create", "define", "describe",
                 "ensure", "following", "from", "into", "must", "should", "their", "these", "this",
                 "through", "using", "which", "with", "without", "each", "then", "where", "when"}


def _clean(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def _ocr_page(pdf_path: pathlib.Path, page: int) -> str:
    with tempfile.TemporaryDirectory(prefix="gitron-ocr-") as folder:
        image = pathlib.Path(folder) / "page"
        try:
            subprocess.run(["pdftoppm", "-f", str(page), "-l", str(page), "-r", "180",
                            "-png", "-singlefile", str(pdf_path), str(image)],
                           capture_output=True, check=True, timeout=45)
            result = subprocess.run(["tesseract", str(image) + ".png", "stdout"],
                                    capture_output=True, text=True, check=True, timeout=60)
        except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            raise ValueError(f"Page {page} needs OCR; install Tesseract and pdftoppm") from exc
    return result.stdout


def _pages(pdf: bytes) -> tuple[list[list[tuple[str, float, bool]]], list[tuple[int, str, int]], list[str]]:
    warnings: list[str] = []
    toc: list[tuple[int, str, int]] = []
    pages: list[list[tuple[str, float, bool]]] = []
    try:
        import pymupdf
    except ImportError:
        pymupdf = None
    with tempfile.TemporaryDirectory(prefix="gitron-pdf-") as folder:
        source = pathlib.Path(folder) / "workflow.pdf"
        source.write_bytes(pdf)
        if pymupdf is not None:
            try:
                with pymupdf.open(stream=pdf, filetype="pdf") as document:
                    toc = [(level, _clean(title), page) for level, title, page in document.get_toc()
                           if level <= 2 and 4 <= len(_clean(title)) <= 120]
                    for number, page in enumerate(document, 1):
                        lines = []
                        for block in page.get_text("dict").get("blocks", []):
                            for line in block.get("lines", []):
                                spans = line.get("spans", [])
                                value = _clean("".join(span.get("text", "") for span in spans))
                                if value:
                                    size = max((float(span.get("size", 0)) for span in spans), default=0)
                                    bold = any("bold" in span.get("font", "").lower() for span in spans)
                                    lines.append((value, size, bold))
                        try:
                            tables = page.find_tables()
                            for table in tables.tables:
                                rows = table.extract()
                                if rows:
                                    width = max(len(row) for row in rows)
                                    normalized = [[_clean(str(cell or "")) for cell in row] +
                                                  [""] * (width - len(row)) for row in rows]
                                    markdown = ["| " + " | ".join(row) + " |" for row in normalized[:40]]
                                    markdown.insert(1, "| " + " | ".join("---" for _ in range(width)) + " |")
                                    lines.append(("\n".join(markdown), 0, False))
                        except (AttributeError, ValueError):
                            pass
                        if sum(len(line[0]) for line in lines) < 30 and page.get_images(full=True):
                            try:
                                textpage = page.get_textpage_ocr(language="eng", dpi=180, full=True)
                                ocr = page.get_text("text", textpage=textpage)
                            except Exception:
                                ocr = _ocr_page(source, number)
                            if _clean(ocr):
                                lines = [(value.strip(), 0, False) for value in ocr.splitlines() if value.strip()]
                                warnings.append(f"OCR used for PDF page {number}")
                        pages.append(lines)
            except ValueError:
                raise
            except Exception as exc:
                raise ValueError("Could not parse workflow PDF") from exc
        else:
            try:
                output = subprocess.run(["pdftotext", "-layout", str(source), "-"],
                                        capture_output=True, text=True, check=True, timeout=45).stdout
            except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
                raise ValueError("Install PyMuPDF or pdftotext to read the workflow PDF") from exc
            extracted_pages = output.split("\f")
            for number, raw in enumerate(extracted_pages, 1):
                if not raw.strip() and number > 1 and number == len(extracted_pages):
                    continue
                if len(_clean(raw)) < 30:
                    try:
                        raw = _ocr_page(source, number)
                        warnings.append(f"OCR used for PDF page {number}")
                    except ValueError:
                        if not _clean(raw):
                            raise
                pages.append([(line.strip(), 0, False) for line in raw.splitlines() if line.strip()])
    return pages, toc, warnings


def extract_workflow(pdf: bytes) -> tuple[list[dict], list[str]]:
    if len(pdf) > 25 * 1024 * 1024 or not pdf.startswith(b"%PDF-"):
        raise ValueError("Expected a PDF under 25 MiB")
    pages, toc, warnings = _pages(pdf)
    if sum(len(text) for page in pages for text, _, _ in page) < 30:
        raise ValueError("Workflow PDF has too little extractable text; OCR it first")
    flat = [(page_number, text, size, bold) for page_number, page in enumerate(pages, 1)
            for text, size, bold in page]
    candidates: list[tuple[int, str, int]] = []
    if toc:
        cursor = 0
        for level, title, page in toc:
            normalized = _clean(title).casefold()
            found = next((i for i in range(cursor, len(flat)) if flat[i][0] >= page and
                          (normalized in flat[i][1].casefold() or flat[i][1].casefold() in normalized)), None)
            if found is None:
                found = next((i for i in range(cursor, len(flat)) if flat[i][0] >= page), None)
            if found is not None and (not candidates or found > candidates[-1][0]):
                candidates.append((found, title, level))
                cursor = found + 1
    sizes = [size for _, text, size, _ in flat if size and len(text.split()) >= 4]
    median = sorted(sizes)[len(sizes) // 2] if sizes else 0
    toc_indices = {index for index, _, _ in candidates}
    for index, (_, value, size, bold) in enumerate(flat):
        match = HEADING.match(value)
        typography = bool(median and size >= max(10, median * 1.20) and
                          (bold or size >= median * 1.35))
        if not (4 <= len(value) <= 120 and len(value.split()) <= 14):
            continue
        # Bookmarks frequently omit subheadings. Accept unlisted headings only
        # when typography supports them, so numbered body lists stay as prose.
        if not (typography or match and not toc):
            continue
        if index in toc_indices:
            continue
        title = match.group(2) if match else value
        level = match.group(1).count(".") + 1 if match else 1
        candidates.append((index, _clean(title), level))
    if not candidates:
        boundaries = sorted({0, len(flat) // 3, 2 * len(flat) // 3})
        labels = ("Project setup", "Core implementation", "Integration and verification")
        candidates = [(index, labels[number], 1) for number, index in enumerate(boundaries)]
        warnings.append("No PDF phase headings found; inferred broad phases from document order")
    candidates = sorted({index: (index, title, level) for index, title, level in candidates[:30]}.values())
    sections: list[WorkflowSection] = []
    weights: list[float] = []
    for number, (start, title, level) in enumerate(candidates, 1):
        end = candidates[number][0] if number < len(candidates) else len(flat)
        body = "\n".join(text for _, text, _, _ in flat[(0 if number == 1 and start > 0 else start + 1):end])
        if not body and len(candidates) == 1:
            body = "\n".join(text for _, text, _, _ in flat)
        tokens = re.findall(r"\b[\w/-]+\b", body)
        entities = list(dict.fromkeys(_clean(match.group()) for match in ENTITY.finditer(title + "\n" + body)))
        keywords = collections.Counter(word.lower() for word in re.findall(r"\b[A-Za-z][A-Za-z0-9]{4,}\b", body)
                                       if word.lower() not in COMMON)
        entities.extend(word for word, _ in keywords.most_common(20) if word not in {item.lower() for item in entities})
        entities = entities[:100]
        sentences = [_clean(part) for part in re.split(r"(?<=[.!?])\s+|\n", body)
                     if _clean(part) and not part.lstrip().startswith("|")]
        action = re.compile(r"\b(?:first|then|next|after|before|build|implement|create|define|add|wire|connect|"
                            r"validate|test|expose|store|deploy|configure|integrate)\b", re.I)
        ranked = sorted(range(len(sentences)), key=lambda index: (
            -len(action.findall(sentences[index])),
            -sum(entity.casefold() in sentences[index].casefold() for entity in entities[:30]),
            index))
        chosen = sorted(ranked[:3]) if ranked and action.search(body) else list(range(min(2, len(sentences))))
        summary = " ".join(sentences[index] for index in chosen)[:450] or title
        start_page = flat[min(start, len(flat) - 1)][0]
        end_page = flat[max(start, min(end - 1, len(flat) - 1))][0]
        score = 1 + math.sqrt(len(tokens)) + 2 * len(entities) + max(0, level == 1)
        weights.append(score)
        sections.append(WorkflowSection(f"phase-{number:02d}", title, level,
                                        [start_page, end_page], len(tokens), summary,
                                        entities, 0, body))
    total = sum(weights)
    for section, score in zip(sections, weights):
        section.effort_weight = score / total
    return [dataclasses.asdict(section) for section in sections], warnings
