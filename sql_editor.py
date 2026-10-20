"""SQL editor pieces for Room SQL: statement parsing, autocomplete and syntax highlighting."""

import re
import sqlite3
import tkinter as tk
from tkinter import font as tkfont


def split_statements(sql):
    statements, buf = [], ""
    for line in sql.splitlines(keepends=True):
        buf += line
        if sqlite3.complete_statement(buf):
            if buf.strip().rstrip(";").strip():
                statements.append(buf.strip())
            buf = ""
    if buf.strip():
        statements.append(buf.strip())
    return statements


_COMMENT_OR_STRING = re.compile(r"('(?:[^']|'')*'?)|--[^\n]*|/\*[\s\S]*?(?:\*/|$)")


def strip_comments(sql):
    """Remove -- and /* */ comments, leaving string literals alone."""
    return _COMMENT_OR_STRING.sub(lambda m: m.group(1) or " ", sql)


def _without_strings(sql):
    return re.sub(r"'(?:[^']|'')*'?", "''", strip_comments(sql))


def first_keyword(stmt):
    words = strip_comments(stmt).split()
    return words[0].upper().rstrip(";") if words else ""


WRITE_PRAGMAS = {"OPTIMIZE", "INCREMENTAL_VACUUM", "WAL_CHECKPOINT", "SHRINK_MEMORY"}


def is_write(stmt):
    """True if the statement may change the database."""
    kw = first_keyword(stmt)
    code = _without_strings(stmt)
    if kw in ("SELECT", "EXPLAIN", "VALUES"):
        return False
    if kw == "PRAGMA":
        name = re.match(r"\s*PRAGMA\s+(?:\w+\.)?(\w+)", code, re.I)
        return "=" in code or bool(name and name.group(1).upper() in WRITE_PRAGMAS)
    if kw == "WITH":  # a CTE may end in SELECT or in INSERT/UPDATE/DELETE
        return bool(re.search(r"\b(INSERT|UPDATE|DELETE|REPLACE)\b", code, re.I))
    return True


_NOT_ALIAS = r"(?!(?:WHERE|ORDER|LIMIT|GROUP|JOIN|LEFT|INNER|CROSS|NATURAL|UNION|WINDOW|HAVING|OFFSET)\b)"
_SINGLE_TABLE = re.compile(
    r'^\s*SELECT\s+.+?\s+FROM\s+["`\[]?(?P<table>\w+)["`\]]?'
    rf"(?:\s+(?:AS\s+)?{_NOT_ALIAS}(?P<alias>\w+))?"
    r"\s*(?:(?:WHERE|ORDER|LIMIT)\b.*)?;?\s*$", re.I | re.S)


def single_table_select(stmt):
    """For `SELECT … FROM one_table [alias] [WHERE/ORDER/LIMIT …]` return
    (table, select_with_rowid) where the second query also returns the rowid as
    column 0, so result rows can be edited. Otherwise None."""
    sql = strip_comments(stmt).strip()
    code = _without_strings(sql)
    if re.search(r"\b(JOIN|UNION|INTERSECT|EXCEPT|GROUP\s+BY|DISTINCT|WITH)\b", code, re.I):
        return None
    m = _SINGLE_TABLE.match(code)
    if not m:
        return None
    qualifier = m.group("alias") or f'"{m.group("table")}"'
    with_rowid = re.sub(r"^\s*SELECT\s", f'SELECT {qualifier}.rowid AS "__rowid__", ', sql,
                        count=1, flags=re.I)
    return m.group("table"), with_rowid


def parse_value(text, declared_type):
    """Turn what the user typed into a value for a column with the given type."""
    if text == "NULL":
        return None
    t = (declared_type or "").upper()
    if "INT" in t and re.fullmatch(r"[+-]?\d+", text.strip()):
        return int(text)
    if any(x in t for x in ("REAL", "FLOA", "DOUB", "NUM", "DEC")):
        try:
            return float(text) if not re.fullmatch(r"[+-]?\d+", text.strip()) else int(text)
        except ValueError:
            return text
    return text


def sql_literal(value):
    if value is None:
        return "NULL"
    if isinstance(value, (int, float)):
        return repr(value)
    return "'" + str(value).replace("'", "''") + "'"

SQL_KEYWORDS = """SELECT FROM WHERE AND OR NOT NULL IS IN LIKE GLOB BETWEEN EXISTS DISTINCT AS ON
JOIN LEFT INNER CROSS OUTER NATURAL USING GROUP BY ORDER ASC DESC HAVING LIMIT OFFSET UNION ALL
INTERSECT EXCEPT CASE WHEN THEN ELSE END INSERT INTO VALUES REPLACE UPDATE SET DELETE CREATE
TABLE INDEX VIEW TRIGGER DROP ALTER ADD COLUMN RENAME TO PRIMARY KEY FOREIGN REFERENCES DEFAULT
UNIQUE CHECK COLLATE NOCASE WITH RECURSIVE PRAGMA EXPLAIN QUERY PLAN BEGIN COMMIT ROLLBACK
TRANSACTION VACUUM CAST INTEGER TEXT REAL BLOB TRUE FALSE IF CONFLICT IGNORE ABORT MATCH""".split()
SQL_FUNCTIONS = """count sum avg min max total group_concat length lower upper substr trim ltrim
rtrim replace instr abs round random coalesce ifnull nullif typeof hex quote printf date time
datetime julianday strftime unixepoch json json_extract json_array json_object""".split()
TABLE_CONTEXT = {"FROM", "JOIN", "INTO", "UPDATE", "TABLE"}
IDENT = r'["`\[]?(\w+)["`\]]?'


class SqlAutocomplete:
    """Suggestion popup for a Text widget: keywords, functions, tables and columns.

    Opens while typing a word, after "table." / "alias.", or on Ctrl+Space.
    Up/Down to move, Tab/Enter to accept, Esc to close.
    """

    def __init__(self, text):
        self.text = text
        self.schema = {}  # table -> [columns]
        self.items = []   # (insert_text, kind) shown in the listbox
        self.prefix_len = 0
        self.box = tk.Listbox(text.winfo_toplevel(), height=8, width=46, font=("Menlo", 12),
                              activestyle="none", exportselection=False, takefocus=0,
                              relief="solid", borderwidth=1)
        self.box.bind("<ButtonRelease-1>", lambda e: self.accept())
        text.bind("<KeyRelease>", self._on_key_release, add="+")
        text.bind("<Control-space>", lambda e: (self.update(force=True), "break")[1])
        for key, action in (("<Down>", lambda: self.move(1)), ("<Up>", lambda: self.move(-1)),
                            ("<Tab>", self.accept), ("<Return>", self.accept),
                            ("<Escape>", self.hide)):
            text.bind(key, lambda e, a=action: self._if_visible(a))
        text.bind("<FocusOut>", lambda e: self.text.after(150, self._hide_if_unfocused), add="+")
        # Close on anything that moves the text under the popup or happens elsewhere:
        # scrolling, resizing (window or panel dividers), or a click outside the popup.
        # (On macOS, clicking a button doesn't take focus, so FocusOut alone isn't enough.)
        for seq in ("<MouseWheel>", "<Shift-MouseWheel>", "<Button-4>", "<Button-5>", "<Configure>"):
            text.bind(seq, lambda e: self.hide(), add="+")
        top = text.winfo_toplevel()
        top.bind("<Button-1>", lambda e: e.widget is not self.box and self.hide(), add="+")
        top.bind("<Configure>", lambda e: e.widget is top and self.hide(), add="+")

    def visible(self):
        return bool(self.box.winfo_ismapped())

    def _if_visible(self, action):
        if self.visible():
            action()
            return "break"
        return None

    def _hide_if_unfocused(self):
        if self.text.focus_get() is not self.text:
            self.hide()

    def _on_key_release(self, event):
        if event.keysym in ("Up", "Down", "Return", "Tab", "Escape", "Left", "Right",
                            "Shift_L", "Shift_R", "Control_L", "Control_R", "Meta_L", "Meta_R",
                            "Alt_L", "Alt_R", "space"):
            if event.keysym in ("Left", "Right", "space"):
                self.hide()
            return
        if event.char and not (event.char.isalnum() or event.char in "_."):
            self.hide()
            return
        self.update()

    # ----- figuring out what to suggest -----
    def _statement_around_cursor(self):
        before = self.text.get("1.0", "insert")
        after = self.text.get("insert", "end")
        start = before.rfind(";") + 1
        end = after.find(";")
        return before[start:], before[start:] + (after if end < 0 else after[:end])

    def _aliases(self, statement):
        """Map table names and aliases in the statement to real table names."""
        known = {t.lower(): t for t in self.schema}
        found = {}
        not_keyword = r"(?!(?:" + "|".join(SQL_KEYWORDS) + r")\b)"
        pattern = rf"\b(?:FROM|JOIN|UPDATE|INTO)\s+{IDENT}(?:\s+(?:AS\s+)?{not_keyword}(\w+))?"
        for table, alias in re.findall(pattern, statement, re.IGNORECASE):
            real = known.get(table.lower())
            if not real:
                continue
            found[real.lower()] = real
            if alias:
                found[alias.lower()] = real
        return found

    def candidates(self, force=False):
        before, statement = self._statement_around_cursor()
        m = re.search(rf"(?:{IDENT}\.)?[\"`\[]?(\w*)$", before)
        qualifier, prefix = m.group(1), m.group(2)
        aliases = self._aliases(statement)

        if qualifier:  # table.col or alias.col
            table = aliases.get(qualifier.lower()) or {t.lower(): t for t in self.schema}.get(qualifier.lower())
            pool = [(c, f"column · {table}") for c in self.schema.get(table, [])]
        else:
            if not prefix and not force:
                return prefix, []
            words = re.findall(r"[A-Za-z_]+", before[: len(before) - len(prefix)])
            last_kw = next((w.upper() for w in reversed(words) if w.upper() in SQL_KEYWORDS), "")
            tables = [(t, "table") for t in sorted(self.schema)]
            if last_kw in TABLE_CONTEXT:
                pool = tables
            else:
                used = sorted(set(aliases.values()))
                cols = [(c, f"column · {t}") for t in used for c in self.schema[t]]
                pool = (cols + tables + [(k, "keyword") for k in SQL_KEYWORDS]
                        + [(f + "(", "function") for f in SQL_FUNCTIONS])

        p = prefix.lower()
        seen, starts, contains = set(), [], []
        for word, kind in pool:
            if word.lower() in seen:
                continue
            w = word.lower()
            if w.startswith(p):
                starts.append((word, kind)); seen.add(w)
            elif len(p) >= 2 and p in w:
                contains.append((word, kind)); seen.add(w)
        result = starts + contains
        if len(result) == 1 and result[0][0].lower() == p and not force:
            return prefix, []  # already fully typed
        return prefix, result[:200]

    # ----- popup -----
    def update(self, force=False):
        prefix, items = self.candidates(force)
        if not items:
            self.hide()
            return
        self.items, self.prefix_len = items, len(prefix)
        self.box.delete(0, "end")
        for word, kind in items:
            self.box.insert("end", f"{word:<30} {kind}")
        self.box.selection_set(0)
        self.box.see(0)
        self.box.configure(height=min(8, len(items)))
        bbox = self.text.bbox("insert")
        if not bbox:
            return
        top = self.text.winfo_toplevel()
        x = self.text.winfo_rootx() - top.winfo_rootx() + bbox[0]
        y = self.text.winfo_rooty() - top.winfo_rooty() + bbox[1] + bbox[3] + 2
        x = max(0, min(x, top.winfo_width() - self.box.winfo_reqwidth()))
        if y + self.box.winfo_reqheight() > top.winfo_height():
            y -= bbox[3] + self.box.winfo_reqheight() + 4  # flip above the cursor
        self.box.place(x=x, y=y)
        self.box.lift()

    def hide(self):
        self.box.place_forget()

    def move(self, step):
        cur = (self.box.curselection() or (0,))[0]
        new = max(0, min(self.box.size() - 1, cur + step))
        self.box.selection_clear(0, "end")
        self.box.selection_set(new)
        self.box.see(new)

    def accept(self):
        sel = self.box.curselection()
        if not sel or not self.visible():
            return self.hide()
        word, kind = self.items[sel[0]]
        if kind == "keyword":
            typed = self.text.get(f"insert-{self.prefix_len}c", "insert")
            if typed and typed.islower():
                word = word.lower()
        elif kind != "function" and (not re.fullmatch(r"[A-Za-z_]\w*", word) or word.upper() in SQL_KEYWORDS):
            word = f'"{word}"'
        self.text.delete(f"insert-{self.prefix_len}c", "insert")
        self.text.insert("insert", word)
        self.hide()
        self.text.focus_set()


TOKEN_RE = re.compile(r"""
    (?P<comment>--[^\n]*|/\*[\s\S]*?(?:\*/|$))
  | (?P<string>'(?:[^']|'')*'?)
  | (?P<quoted>"[^"\n]*"?|`[^`\n]*`?|\[[^\]\n]*\]?)
  | (?P<number>\b\d+(?:\.\d+)?\b)
  | (?P<word>\b[A-Za-z_]\w*\b)
""", re.VERBOSE)
KEYWORD_SET = set(SQL_KEYWORDS)
FUNCTION_SET = set(SQL_FUNCTIONS)
# (light, dark) colors per token type
PALETTE = {
    "keyword": ("#0033b3", "#7aa2f7"),
    "function": ("#871094", "#c792ea"),
    "string": ("#067d17", "#9ece6a"),
    "number": ("#c45500", "#ff9e64"),
    "comment": ("#8c8c8c", "#737aa2"),
    "table": ("#00807f", "#4fd6be"),
}


class SqlHighlighter:
    """Colors SQL in a Text widget; re-runs after every change (typed or inserted)."""

    def __init__(self, text, get_schema):
        self.text = text
        self.get_schema = get_schema
        self._pending = None
        self._dark = None
        base = tkfont.Font(font=text.cget("font"))
        self.bold = base.copy(); self.bold.configure(weight="bold")
        self.italic = base.copy(); self.italic.configure(slant="italic")
        text.bind("<<Modified>>", self._on_modified, add="+")

    def _on_modified(self, _event):
        self.text.edit_modified(False)
        if self._pending is None:
            self._pending = self.text.after_idle(self.highlight)

    def _configure_tags(self):
        r, g, b = (v / 257 for v in self.text.winfo_rgb(self.text.cget("background")))
        dark = (0.299 * r + 0.587 * g + 0.114 * b) < 128
        if dark == self._dark:
            return
        self._dark = dark
        for name, colors in PALETTE.items():
            self.text.tag_configure(name, foreground=colors[dark])
        self.text.tag_configure("keyword", font=self.bold)
        self.text.tag_configure("comment", font=self.italic)
        self.text.tag_raise("sel")  # keep the selection visible on top of colors

    def highlight(self):
        self._pending = None
        self._configure_tags()
        content = self.text.get("1.0", "end-1c")
        for name in PALETTE:
            self.text.tag_remove(name, "1.0", "end")
        tables = {t.lower() for t in self.get_schema()}
        for m in TOKEN_RE.finditer(content):
            kind = m.lastgroup
            if kind == "quoted":
                kind = "table" if m.group()[1:-1].lower() in tables else None
            elif kind == "word":
                word = m.group()
                upper = word.upper()
                if upper in KEYWORD_SET:
                    kind = "keyword"
                elif word.lower() in FUNCTION_SET and content[m.end():m.end() + 1] == "(":
                    kind = "function"
                elif word.lower() in tables:
                    kind = "table"
                else:
                    kind = None
            if kind:
                self.text.tag_add(kind, f"1.0+{m.start()}c", f"1.0+{m.end()}c")

