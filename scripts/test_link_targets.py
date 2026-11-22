"""Does SECURITY.md link to the Contact URL? Cases checked against GitHub's own Markdown renderer.

Each case is (name, markdown, links). `links` is whether the page GitHub renders shows a link with visible text to
the Contact URL ({U} below), as POST /markdown returned on 2026-11-22. FAIL_CLOSED lists the cases where GitHub
shows a link that link_targets() deliberately does not count: it expects False for them.
REGRESSIONS are random documents that an earlier regex version of the check wrongly accepted. POSITIVES are
random documents where a link renders and is counted.
"""
import signal
import unittest

import check_security_txt as cst

FAIL_CLOSED = {
    'image',
    'link in image-free badge',
    'list continuation paragraph',
    'lone tag cannot interrupt paragraph',
    'reference style',
}

CASES = [
    ('paragraph', 'Report in [ipso]({U}).\n', True),
    ('heading', '## Report in [ipso]({U})\n', True),
    ('bullet item', '- Report in [ipso]({U})\n', True),
    ('ordered item', '1. Report in [ipso]({U})\n', True),
    ('nested bullet', '- a\n  - Report in [ipso]({U})\n', True),
    ('table cell', '| a | b |\n|---|---|\n| x | [ipso]({U}) |\n', True),
    ('blockquote', '> Report in [ipso]({U})\n', True),
    ('blockquote list', '> - Report in [ipso]({U})\n', True),
    ('bold link', '**[ipso]({U})**\n', True),
    ('code text link', '[`ipso`]({U})\n', True),
    ('link text spans lines', '[ipso\nreport]({U})\n', True),
    ('after code block', '```sh\necho hi\n```\n\nReport in [ipso]({U}).\n', True),
    ('after comment', '<!-- note -->\nReport in [ipso]({U}).\n', True),
    ('between code spans', '`a` then [ipso]({U}) then `b`\n', True),
    ('literal comment start in fence then link', '```sh\n# <!--\n```\n\nReport in [ipso]({U}).\n', True),
    ('literal comment start in code span then link', '`<!--`\n\nReport in [ipso]({U}).\n', True),
    ('unpaired backticks in two paragraphs', 'a ` b\n\n[ipso]({U})\n\nc ` d\n', True),
    ('escaped backtick before link', '\\`x [ipso]({U}) y`\n', True),
    ('inline comment then link', 'a <!-- c --> [ipso]({U})\n', True),
    ('unclosed inline comment then link', 'a <!-- c [ipso]({U})\n', True),
    ('single span', '`[x]({U})`\n', False),
    ('double span', '``[x]({U})``\n', False),
    ('span across newline in paragraph', '`a\n[x]({U})`\n', False),
    ('fence backticks', '```\n[x]({U})\n```\n', False),
    ('fence tildes', '~~~\n[x]({U})\n~~~\n', False),
    ('fence with info string', '```sh\n[x]({U})\n```\n', False),
    ('fence info line does not close', '```\n```js\n[x]({U})\n```\n', False),
    ('four backtick fence with three inside', '````\n```\n[x]({U})\n```\n````\n', False),
    ('tilde fence not closed by backticks', '~~~\n```\n[x]({U})\n```\n~~~\n', False),
    ('closing fence longer', '```\n[x]({U})\n````\n\nthen [ipso]({U})\n', True),
    ('closing fence shorter does not close', '````\n```\n[x]({U})\n', False),
    ('unclosed fence', '```\n[x]({U})\n', False),
    ('fence indented 3', '   ```\n   [x]({U})\n   ```\n', False),
    ('indented fence closer 4 spaces is content', '```\n    ```\n[x]({U})\n```\n', False),
    ('fence in blockquote', '> ```\n> [x]({U})\n> ```\n', False),
    ('fence in list item', '- item\n\n  ```\n  [x]({U})\n  ```\n', False),
    ('fence interrupts paragraph', 'text\n```\n[x]({U})\n```\n', False),
    ('backtick fence info with backtick is not a fence', '``` a`b\n[x]({U})\n', True),
    ('indented code after blank', 'para\n\n    [x]({U})\n', False),
    ('indented continuation of paragraph', 'para\n    [x]({U})\n', True),
    ('indented code after heading', '# h\n    [x]({U})\n', False),
    ('indented code at start', '    [x]({U})\n', False),
    ('tab indented code', 'para\n\n\t[x]({U})\n', False),
    ('list continuation paragraph', '- item\n\n    [x]({U})\n', True),
    ('empty text', '[]({U})\n', False),
    ('space text', '[ ]({U})\n', False),
    ('image', '![x]({U})\n', True),
    ('escaped bracket', '\\[x]({U})\n', False),
    ('link in image-free badge', '[![b](https://example.com/b.svg)]({U})\n', True),
    ('reference style', '[x][r]\n\n[r]: {U}\n', True),
    ('angle autolink', '<{U}>\n', False),
    ('bare url', 'see {U}\n', False),
    ('link with title', '[x]({U} "t")\n', True),
    ('comment single line', '<!-- [x]({U}) -->\n', False),
    ('comment multi line', '<!--\n[x]({U})\n-->\n', False),
    ('comment with blank line inside', '<!--\n\n[x]({U})\n\n-->\n', False),
    ('unclosed comment block', '<!-- note\n[x]({U})\n', False),
    ('comment then text on closing line', '<!-- c --> [x]({U})\n', False),
    ('inline comment hides link', 'a <!-- [x]({U}) --> b\n', False),
    ('unclosed inline comment hides', 'a <!-- [x]({U})\n', True),
    ('div block', '<div>\n[x]({U})\n</div>\n', False),
    ('div block with blank then link', '<div>\n\n[x]({U})\n\n</div>\n', True),
    ('details block', '<details>\n<summary>s</summary>\n\n[x]({U})\n\n</details>\n', True),
    ('pre block', '<pre>\n\n[x]({U})\n\n</pre>\n', False),
    ('inline html around link', '<kbd>[x]({U})</kbd>\n', True),
    ('span html around link', 'a <span>[x]({U})</span>\n', True),
    ('paragraph interrupted by div', 'text\n<div>\n[x]({U})\n</div>\n', False),
    ('link in html block line', '<p>[x]({U})</p>\n', False),
    ('kbd line start', '<kbd>[x]({U})</kbd>\n', True),
    ('bold html and link', '<b>bold</b> and [x]({U})\n', True),
    ('anchor html wrapping link', '<a href="https://example.com">[x]({U})</a>\n', True),
    ('lone span tag block', '<span>\n[x]({U})\n</span>\n', False),
    ('lone tag cannot interrupt paragraph', 'text\n<span>\n[x]({U})\n', True),
    ('div interrupts paragraph', 'text\n<div>\n[x]({U})\n', False),
    ('pre one line', '<pre>x</pre>\n\n[x]({U})\n', True),
    ('pre multi line then link', '<pre>\nx\n</pre>\n\n[x]({U})\n', True),
    ('style block', '<style>\n\n[x]({U})\n\n</style>\n', False),
    ('processing instruction', '<?php\n[x]({U})\n?>\n', False),
    ('declaration', '<!DOCTYPE html>\n[x]({U})\n', True),
    ('cdata', '<![CDATA[\n[x]({U})\n]]>\n', False),
    ('closing div tag line', '</div>\n[x]({U})\n', False),
    ('html comment then paragraph', '<!-- a -->\n\n[x]({U})\n', True),
    ('comment ends mid-line then text', '<!-- a\nb --> tail\n[x]({U})\n', True),
    ('setext heading', 'Title\n=====\n\n[x]({U})\n', True),
    ('thematic break', 'a\n\n---\n\n[x]({U})\n', True),
    ('table then paragraph', '| a |\n|---|\n| b |\n\n[x]({U})\n', True),
    ('nested list fence', '- a\n  - b\n\n    ```\n    [x]({U})\n    ```\n', False),
    ('numbered list fence', '1. a\n\n   ```\n   [x]({U})\n   ```\n', False),
    ('blockquote with comment', '> <!-- [x]({U}) -->\n', False),
    ('blockquote paragraph then unclosed fence', '> a\n\n```\n[x]({U})\n', False),
    ('code span with backslash inside', '`a\\`[x]({U})\n`\n', True),
    ('two paragraph spans no cross', '`a\n\n[x]({U})`\n', True),
    ('triple backtick span', '```[x]({U})```\n', False),
    ('span longer opener no match', '``a`[x]({U})\n', True),
    ('html entity in text', '[a &amp; b]({U})\n', True),
    ('link followed by title no space', '[x]({U}"t")\n', False),
]

REGRESSIONS = [
    '<p>\n[x]({U})\n',
    '    [x]({U})\n\n',
    ' ~~~\n[x]({U})\n',
    '</a>\n[x]({U})\n',
    '    [x]({U})\n>\n',
    '<p>\n  [x]({U})\n',
    '<p>\n> [x]({U})\n',
    '<span>\n[x]({U})\n',
    '    [x]({U})\n~~~\n',
    '-\n<pre>\n[x]({U})\n',
    '<div>\n> [x]({U})\n',
    '<div>\n[x]({U}) `\n',
    '<kbd>\n[x]({U}) `\n',
    '<pre>\n  [x]({U})\n',
    '    [x]({U})\n ~~~\n',
    '    [x]({U})\n<p>\n\n',
    '    [x]({U})\ntext\n',
    '   ```\n- [x]({U})\n',
    '</div>\n> [x]({U})\n',
    '</pre>\n  [x]({U})\n',
    '<script>\n[x]({U})\n',
    '    [x]({U})\n> ```\n',
    '    [x]({U})\nc -->\n',
    '    [x]({U})\n~~~js\n',
    '  ```\n    [x]({U})\n',
    '<![CDATA[\n[x]({U})\n',
    '</pre>\n> [x]({U})\n\n',
    '</span>\n[x]({U}) `\n',
    '<?php\n> - [x]({U})\n',
    '<div>\n> - [x]({U})\n',
    '<kbd>\n    [x]({U})\n',
    '<kbd>\n> - [x]({U})\n',
    '<kbd>\n`a` [x]({U})\n',
    '<p>\n> > x\n[x]({U})\n',
    '<pre>\n> - [x]({U})\n',
    '> ```\n    [x]({U})\n',
    '> ```\n> - [x]({U})\n',
    '> ~~~\n> - [x]({U})\n',
    '\n> ~~~\n> - [x]({U})\n',
    '    [x]({U})\n   ```\n',
    '    [x]({U})\n# head\n',
    '    [x]({U})\n+ item\n',
    '    [x]({U})\n- item\n',
    '    [x]({U})\n<!-- c\n',
    '    [x]({U})\n</pre>\n',
    '   ```\n`a` [x]({U})\n',
    '  ```\ntext [x]({U})\n',
    '</a>\n[x]({U})\nc -->\n',
    '<?php\ntext [x]({U})\n',
    '<kbd>\ntext [x]({U})\n',
    '<span>\n`a` [x]({U})\n',
    '``\na ` b\n[x]({U}) `\n',
    '    [x]({U})\n</span>\n',
    '    [x]({U})\n> <div>\n',
    '- <pre>\n    [x]({U})\n',
    '</div>\ntext [x]({U})\n',
    '</script>\n  [x]({U})\n',
    '</span>\n`a` [x]({U})\n',
    '<details>\n  [x]({U})\n',
    '<details>\n[x]({U}) `\n',
    '<kbd>\n---\n- [x]({U})\n',
    '<script>\n1. [x]({U})\n',
    '<script>\n\\`\n[x]({U})\n',
    '<span>\ntext [x]({U})\n',
    '> <div>\n    [x]({U})\n',
    '> <pre>\n> - [x]({U})\n',
    '    [x]({U})\n10) item\n',
    '    [x]({U})\n<b>x</b>\n',
    '    [x]({U})\n<div>\n``\n',
    '    [x]({U})\n<pre>\n\\`\n',
    '```js\n> ```\n[x]({U})\n',
    '`\n=====\n    [x]({U})\n',
    'text\n\n***\n    [x]({U})\n',
    'text\n\n---\n    [x]({U})\n',
    '```js\n> ```\n> quote\n-->\n- [x]({U})\n\n',
    '```js\n=====\n> ```\n1. item\n  [x]({U})\n   ```\n',
    '```js\n> > ```\n10) item\n- [x]({U})\n``\n|---|\n-->\n',
    'a ` b\n- ~~~\n# head\n<!-- c -->\n~~~\n> ~~~\n`a` [x]({U})\n',
    '\\`\n=====\n    [x]({U})\n    indented\n<span>\n``\n',
    '> > x\n***\n    [x]({U})\n',
    '- item\n***\n    [x]({U})\n',
    '---\n    [x]({U})\n> > ```\n',
    '___\n    [x]({U})\n1. item\n',
    '> <!--\n[x]({U})\n',
    '- <!--\n[x]({U})\n',
]

POSITIVES = [
    '\n[x]({U})\n',
    '[x]({U})\n-\n',
    '\n  [x]({U})\n',
    '\n[x]({U}) `\n',
    '> [x]({U})\n\n',
    '[x]({U})\n?>\n',
    '[x]({U})\n``\n',
    '[x]({U}) `\n\n',
    '\\`\n[x]({U})\n',
    '``\n[x]({U})\n',
    '\n1. [x]({U})\n',
    '-\n> [x]({U})\n',
    '- [x]({U})\n-\n',
    '- [x]({U})\n`\n',
    '-->\n[x]({U})\n',
    '> [x]({U})\n`\n',
    '[x]({U})\n-->\n',
    '[x]({U}) `\n-\n',
    '[x]({U}) `\n>\n',
    '[x]({U}) `\n`\n',
    '___\n[x]({U})\n',
    '`\n- [x]({U})\n',
    '\n> - [x]({U})\n',
    '-\n> [x]({U})\n\n',
    '- [x]({U})\n``\n',
    '1. [x]({U})\n>\n',
    '> [x]({U})\n?>\n',
    '?>\n> [x]({U})\n',
    '[x]({U})\n\n***\n',
    '[x]({U})\n ~~~\n',

    '> ```\ntext [x]({U})\n',
    '- ```\n1. [x]({U})\n',
    '- ```\n[x]({U})\n',
    '> ~~~\n[x]({U})\n',
]


def links(markdown):
    return cst.CONTACT in cst.link_targets(markdown.replace("{U}", cst.CONTACT))


class LinkTargets(unittest.TestCase):
    def test_curated_cases_match_github(self):
        for name, markdown, github_links in CASES:
            with self.subTest(name=name):
                self.assertEqual(links(markdown), github_links and name not in FAIL_CLOSED)

    def test_fail_closed_cases_render_a_link_on_github(self):
        for name, markdown, github_links in CASES:
            if name in FAIL_CLOSED:
                with self.subTest(name=name):
                    self.assertTrue(github_links)

    def test_random_documents_github_does_not_render_are_refused(self):
        for index, markdown in enumerate(REGRESSIONS):
            with self.subTest(index=index, markdown=markdown):
                self.assertFalse(links(markdown))

    def test_random_documents_with_a_link_are_accepted(self):
        for index, markdown in enumerate(POSITIVES):
            with self.subTest(index=index, markdown=markdown):
                self.assertTrue(links(markdown))


PATHOLOGICAL = {
    "deeply nested quotes": "> " * 5000 + "x\n",
    "nested quotes then a list marker": "> " * 3000 + "- " * 3000 + "x\n",
    "indented nested quotes": "   > " * 2000 + "- x\n",
    "unclosed link text": "[" + "a " * 60000 + "\n",
    "many fence lines": "```\n" * 20000,
    "one long backtick run": "`" * 60000 + "x",
    "alternating backtick runs": "".join("`" * (n % 40 + 1) + "a" for n in range(3000)),
    "many HTML comment openers": "<!-- " * 20000,
    "long tag with attributes": "<a " + "x=y " * 20000 + "\n",
    "long thematic break": "- " * 30000 + "x\n",
}


class PathologicalInput(unittest.TestCase):
    """A crafted SECURITY.md must not make the check hang. SIGALRM is missing on Windows, so skip it there."""

    @unittest.skipUnless(hasattr(signal, "SIGALRM"), "needs SIGALRM")
    def test_inputs_finish_quickly(self):
        def too_slow(signum, frame):
            raise AssertionError("link_targets took more than 20 seconds")

        previous = signal.signal(signal.SIGALRM, too_slow)
        try:
            for name, markdown in PATHOLOGICAL.items():
                with self.subTest(name=name):
                    signal.alarm(20)
                    try:
                        cst.link_targets(markdown)
                    finally:
                        signal.alarm(0)
        finally:
            signal.signal(signal.SIGALRM, previous)


if __name__ == "__main__":
    unittest.main()
