"""
PDF PII Redactor
----------------
Finds personal information in a PDF and permanently blacks it out.

Setup (once):   pip install pymupdf
Run:            python pdf_redactor.py my_file.pdf
Output:         my_file_redacted.pdf   (original is never changed)

Or choose the output name:
                python pdf_redactor.py my_file.pdf -o safe_copy.pdf

What it finds: emails, phone numbers, SSNs, credit card numbers, dates of birth,
and labeled fields like "Name: ..." and "Salary: ...".
Limits: it cannot read scanned/image-only PDFs, and free-floating names or
addresses with no label are not detected. Always review the output.
"""

import argparse
import os
import re
import sys

try:
    import fitz  # PyMuPDF
except ImportError:
    fitz = None


# ---------------------------------------------------------------
# STEP 1: Patterns that describe each kind of PII
# Each entry: (label, pattern, group)
#   group 0 = redact the whole match
#   group 1 = redact only the part inside the first (...)  e.g. just the date after "DOB:"
# Order matters: earlier rules win when two matches overlap.
# ---------------------------------------------------------------
PII_RULES = [
    ("Email", re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+"), 0),
    ("SSN", re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)"), 0),
    ("Credit card", re.compile(r"(?<!\d)(?:\d[ -]?){13,16}(?!\d)"), 0),
    ("Phone", re.compile(
        r"(?<!\d)(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}(?!\d)"), 0),
    ("Date of birth", re.compile(
        r"(?i:DOB|date of birth|born)\s*:?\s*"
        r"(\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|[A-Z][a-z]+\.? \d{1,2},? \d{4})"), 1),
    ("Name", re.compile(
        r"(?i:name|employee|candidate|applicant)\s*:\s*"
        r"([A-Z][a-z]+(?:[ \t]+[A-Z][a-z.]+){1,2})"), 1),
    ("Salary", re.compile(
        r"(?i:salary|compensation)\s*:?\s*(\$\s?\d[\d,]*(?:\.\d+)?[kK]?)"), 1),
]


def luhn_ok(number):
    """Credit card sanity check, so random long numbers aren't redacted by mistake."""
    digits = [int(d) for d in re.sub(r"\D", "", number)]
    if not 13 <= len(digits) <= 16:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


# ---------------------------------------------------------------
# STEP 2: Detect PII in a piece of text
# Returns a list of (label, text_to_redact)
# ---------------------------------------------------------------
def detect_pii(text):
    accepted = []  # (start, end, label)

    for label, pattern, group in PII_RULES:
        for m in pattern.finditer(text):
            start, end = m.span(group)
            if start == -1:
                continue
            if label == "Credit card" and not luhn_ok(m.group(0)):
                continue
            # skip if it overlaps something already found by an earlier rule
            if any(start < e and end > s for s, e, _ in accepted):
                continue
            accepted.append((start, end, label))

    return [(label, text[s:e].strip()) for s, e, label in sorted(accepted)]


# ---------------------------------------------------------------
# STEP 3: Redact a PDF
# ---------------------------------------------------------------
def redact_pdf(input_path, output_path):
    if fitz is None:
        sys.exit("PyMuPDF is not installed. Run:  pip install pymupdf")

    doc = fitz.open(input_path)
    summary = {}
    blank_pages = []

    for page_number, page in enumerate(doc, start=1):
        text = page.get_text("text")
        if not text.strip():
            blank_pages.append(page_number)
            continue

        found = detect_pii(text)
        # same value may appear many times; search for each unique value once
        for label, value in dict.fromkeys(found):
            for rect in page.search_for(value):
                page.add_redact_annot(rect, fill=(0, 0, 0))  # black box
            summary[label] = summary.get(label, 0) + sum(
                1 for l, v in found if l == label and v == value)

        # Permanently removes the text underneath the black boxes
        page.apply_redactions()

    # Remove hidden info (author, title, etc.) that could also identify someone
    doc.set_metadata({})
    try:
        doc.del_xml_metadata()
    except Exception:
        pass

    doc.save(output_path, garbage=4, deflate=True)
    doc.close()
    return summary, blank_pages


# ---------------------------------------------------------------
# STEP 4: Run from the terminal
# ---------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Redact PII from a PDF.")
    parser.add_argument("input", help="PDF file to redact")
    parser.add_argument("-o", "--output", help="Name for the redacted PDF")
    args = parser.parse_args()

    if not os.path.isfile(args.input):
        sys.exit(f"Could not find file: {args.input}")

    output = args.output or os.path.splitext(args.input)[0] + "_redacted.pdf"
    if os.path.abspath(output) == os.path.abspath(args.input):
        sys.exit("Output name must be different from the input file.")

    summary, blank_pages = redact_pdf(args.input, output)

    print("\nRedaction report")
    print("-" * 30)
    if summary:
        for label, count in sorted(summary.items()):
            print(f"{label:<14} {count} found")
    else:
        print("No PII detected.")
    if blank_pages:
        print(f"\nWarning: page(s) {blank_pages} have no readable text. They may be "
              "scanned images, which this tool cannot redact.")
    print(f"\nSaved: {output}")
    print("Open it and check it before sharing.")


if __name__ == "__main__":
    main()
