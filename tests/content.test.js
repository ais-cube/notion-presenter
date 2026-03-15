/**
 * Notion Presenter — Unit Tests
 *
 * Tests cover:
 *  - DOM sanitisation (XSS prevention)
 *  - Input validation and whitelisting
 *  - HTML escaping
 *  - Notion domain verification
 *  - Block type detection
 *  - Slide parsing (divider + heading modes)
 *  - H1/H2 hierarchy tracking
 *  - TOC generation with escaped labels
 *  - Slide content sanitisation
 *  - Duplicate heading removal
 *  - Edge cases
 */

// ─── Bootstrap: extract functions from IIFE for testing ───────────

// We cannot `require()` content.js directly (it's an IIFE that uses
// chrome.runtime).  Instead we eval an instrumented copy that exposes
// internals via `global.__NP`.

const fs = require('fs');
const path = require('path');

let src = fs.readFileSync(
  path.join(__dirname, '..', 'content.js'),
  'utf-8'
);

// Stub chrome API before evaluating
global.chrome = {
  runtime: {
    onMessage: { addListener: jest.fn() },
    lastError: null
  },
  tabs: {
    query: jest.fn(),
    sendMessage: jest.fn()
  }
};

// Replace the closing `})();` with an export block
src = src.replace(
  /\}\)\(\);[\s]*$/,
  `
  // ── Test exports ──
  global.__NP = {
    sanitizeDOM,
    escapeHtml,
    validateMessage,
    isNotionPage,
    getBlockType,
    isH1Block,
    isH2Block,
    isDivider,
    getHeadingText,
    isHeadingMatch,
    buildSlideFromBlocks,
    splitByDivider,
    splitByHeadings,
    buildTocHtml,
    sanitizeSlideContent,
    removeDuplicateHeading,
    parseNotionPage,
    findPageContent,
    getPageTitle,
    ALLOWED_SPLIT_MODES,
    ALLOWED_THEMES,
    DANGEROUS_TAGS,
    MAX_SLIDES
  };
})();
`
);

eval(src);

const NP = global.__NP;

// ───────────────────────────────────────────────────────────────────
// HELPERS
// ───────────────────────────────────────────────────────────────────

/** Create a DOM element from an HTML string. */
function html(str) {
  const t = document.createElement('div');
  t.innerHTML = str.trim();
  return t;
}

/** Create a single element. */
function el(tag, attrs = {}, inner = '') {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === 'className') e.className = v;
    else e.setAttribute(k, v);
  }
  if (inner) e.innerHTML = inner;
  return e;
}

// ───────────────────────────────────────────────────────────────────
// 1. DOM SANITISATION
// ───────────────────────────────────────────────────────────────────

describe('sanitizeDOM', () => {
  test('removes <script> tags', () => {
    const root = html('<p>Hello</p><script>alert("xss")</script><p>World</p>');
    NP.sanitizeDOM(root);
    expect(root.querySelector('script')).toBeNull();
    expect(root.textContent).toContain('Hello');
    expect(root.textContent).toContain('World');
  });

  test('removes <iframe> tags', () => {
    const root = html('<iframe src="https://evil.com"></iframe><p>Safe</p>');
    NP.sanitizeDOM(root);
    expect(root.querySelector('iframe')).toBeNull();
    expect(root.textContent).toContain('Safe');
  });

  test('removes <object> and <embed> tags', () => {
    const root = html('<object data="evil.swf"></object><embed src="evil.swf"><p>OK</p>');
    NP.sanitizeDOM(root);
    expect(root.querySelector('object')).toBeNull();
    expect(root.querySelector('embed')).toBeNull();
  });

  test('removes <form>, <input>, <textarea>, <select>, <button>', () => {
    const root = html(`
      <form action="/steal"><input type="text"><textarea></textarea>
      <select><option>x</option></select><button>Click</button></form>
      <p>Content</p>
    `);
    NP.sanitizeDOM(root);
    expect(root.querySelector('form')).toBeNull();
    expect(root.querySelector('input')).toBeNull();
    expect(root.querySelector('textarea')).toBeNull();
    expect(root.querySelector('select')).toBeNull();
    expect(root.querySelector('button')).toBeNull();
    expect(root.textContent).toContain('Content');
  });

  test('removes <style> tags (CSS injection)', () => {
    const root = html('<style>body{display:none}</style><p>Visible</p>');
    NP.sanitizeDOM(root);
    expect(root.querySelector('style')).toBeNull();
  });

  test('removes <template> tags', () => {
    const root = html('<template><script>alert(1)</script></template><p>OK</p>');
    NP.sanitizeDOM(root);
    expect(root.querySelector('template')).toBeNull();
  });

  test('removes <base> and <meta> tags', () => {
    const root = html('<base href="https://evil.com"><meta http-equiv="refresh" content="0;url=evil"><p>OK</p>');
    NP.sanitizeDOM(root);
    expect(root.querySelector('base')).toBeNull();
    expect(root.querySelector('meta')).toBeNull();
  });

  test('removes <link> tags', () => {
    const root = html('<link rel="stylesheet" href="https://evil.com/steal.css"><p>OK</p>');
    NP.sanitizeDOM(root);
    expect(root.querySelector('link')).toBeNull();
  });

  test('removes <foreignobject> tags (SVG XSS vector)', () => {
    const root = html('<svg><foreignobject><body onload="alert(1)"></body></foreignobject></svg><p>OK</p>');
    NP.sanitizeDOM(root);
    expect(root.querySelector('foreignobject')).toBeNull();
  });

  test('strips onclick handler', () => {
    const root = html('<p onclick="alert(1)">Click me</p>');
    NP.sanitizeDOM(root);
    expect(root.querySelector('p').hasAttribute('onclick')).toBe(false);
  });

  test('strips onerror handler', () => {
    const root = html('<img src="x" onerror="alert(1)">');
    NP.sanitizeDOM(root);
    const img = root.querySelector('img');
    expect(img.hasAttribute('onerror')).toBe(false);
    expect(img.hasAttribute('src')).toBe(true); // src kept (not dangerous)
  });

  test('strips onload handler', () => {
    const root = html('<img src="photo.jpg" onload="steal()">');
    NP.sanitizeDOM(root);
    expect(root.querySelector('img').hasAttribute('onload')).toBe(false);
  });

  test('strips onmouseover handler', () => {
    const root = html('<div onmouseover="evil()">Hover</div>');
    NP.sanitizeDOM(root);
    expect(root.querySelector('div').hasAttribute('onmouseover')).toBe(false);
  });

  test('strips onfocus and onblur handlers', () => {
    const root = html('<div onfocus="x()" onblur="y()">Focus</div>');
    NP.sanitizeDOM(root);
    const d = root.querySelector('div');
    expect(d.hasAttribute('onfocus')).toBe(false);
    expect(d.hasAttribute('onblur')).toBe(false);
  });

  test('blocks javascript: in href', () => {
    const root = html('<a href="javascript:alert(1)">Link</a>');
    NP.sanitizeDOM(root);
    expect(root.querySelector('a').hasAttribute('href')).toBe(false);
  });

  test('blocks javascript: with whitespace padding', () => {
    const root = html('<a href="  javascript:alert(1)">Link</a>');
    NP.sanitizeDOM(root);
    expect(root.querySelector('a').hasAttribute('href')).toBe(false);
  });

  test('blocks vbscript: in href', () => {
    const root = html('<a href="vbscript:MsgBox(1)">Link</a>');
    NP.sanitizeDOM(root);
    expect(root.querySelector('a').hasAttribute('href')).toBe(false);
  });

  test('blocks data:text/html in src', () => {
    const root = html('<img src="data:text/html,<script>alert(1)</script>">');
    NP.sanitizeDOM(root);
    expect(root.querySelector('img').hasAttribute('src')).toBe(false);
  });

  test('allows safe https: href', () => {
    const root = html('<a href="https://notion.so/page">Link</a>');
    NP.sanitizeDOM(root);
    expect(root.querySelector('a').getAttribute('href')).toBe('https://notion.so/page');
  });

  test('allows safe image src', () => {
    const root = html('<img src="https://cdn.notion.so/image.png">');
    NP.sanitizeDOM(root);
    expect(root.querySelector('img').getAttribute('src')).toBe('https://cdn.notion.so/image.png');
  });

  test('blocks CSS expression() in style', () => {
    const root = html('<div style="width: expression(alert(1))">Test</div>');
    NP.sanitizeDOM(root);
    expect(root.querySelector('div').hasAttribute('style')).toBe(false);
  });

  test('blocks @import in style', () => {
    const root = html('<div style="@import url(https://evil.com/steal.css)">Test</div>');
    NP.sanitizeDOM(root);
    expect(root.querySelector('div').hasAttribute('style')).toBe(false);
  });

  test('allows safe inline styles', () => {
    const root = html('<div style="color: red; font-size: 16px;">Styled</div>');
    NP.sanitizeDOM(root);
    expect(root.querySelector('div').hasAttribute('style')).toBe(true);
  });

  test('preserves safe content structure', () => {
    const root = html(`
      <h1>Title</h1>
      <p>Paragraph with <strong>bold</strong> and <em>italic</em></p>
      <ul><li>Item 1</li><li>Item 2</li></ul>
      <pre><code>const x = 1;</code></pre>
      <blockquote>Quote</blockquote>
      <table><tr><td>Cell</td></tr></table>
      <img src="https://example.com/img.png">
    `);
    NP.sanitizeDOM(root);
    expect(root.querySelector('h1')).not.toBeNull();
    expect(root.querySelector('strong')).not.toBeNull();
    expect(root.querySelector('em')).not.toBeNull();
    expect(root.querySelector('ul')).not.toBeNull();
    expect(root.querySelector('pre')).not.toBeNull();
    expect(root.querySelector('blockquote')).not.toBeNull();
    expect(root.querySelector('table')).not.toBeNull();
    expect(root.querySelector('img')).not.toBeNull();
  });

  test('handles nested dangerous elements', () => {
    const root = html('<div><div><script>evil()</script></div></div><p>Safe</p>');
    NP.sanitizeDOM(root);
    expect(root.querySelector('script')).toBeNull();
    expect(root.textContent).toContain('Safe');
  });

  test('handles multiple event handlers on same element', () => {
    const root = html('<div onclick="a()" onmouseover="b()" onkeydown="c()" id="test">OK</div>');
    NP.sanitizeDOM(root);
    const d = root.querySelector('#test');
    expect(d.hasAttribute('onclick')).toBe(false);
    expect(d.hasAttribute('onmouseover')).toBe(false);
    expect(d.hasAttribute('onkeydown')).toBe(false);
    expect(d.getAttribute('id')).toBe('test');
  });

  test('handles empty root', () => {
    const root = document.createElement('div');
    NP.sanitizeDOM(root);
    expect(root.innerHTML).toBe('');
  });
});

// ───────────────────────────────────────────────────────────────────
// 2. HTML ESCAPING
// ───────────────────────────────────────────────────────────────────

describe('escapeHtml', () => {
  test('escapes < and >', () => {
    expect(NP.escapeHtml('<script>alert(1)</script>')).toBe(
      '&lt;script&gt;alert(1)&lt;/script&gt;'
    );
  });

  test('escapes &', () => {
    expect(NP.escapeHtml('A & B')).toBe('A &amp; B');
  });

  test('escapes ampersand in text with quotes', () => {
    // textContent→innerHTML escapes <, >, & but NOT quotes.
    // Quotes are safe inside element content (our use-case);
    // they are only dangerous inside HTML attribute values.
    const result = NP.escapeHtml('"hello" & \'world\'');
    expect(result).toContain('&amp;');
    expect(result).toContain('"hello"'); // quotes pass through — safe in element text
  });

  test('handles empty string', () => {
    expect(NP.escapeHtml('')).toBe('');
  });

  test('handles numbers', () => {
    expect(NP.escapeHtml(42)).toBe('42');
  });

  test('handles null/undefined coercion', () => {
    expect(NP.escapeHtml(null)).toBe('null');
    expect(NP.escapeHtml(undefined)).toBe('undefined');
  });

  test('preserves Cyrillic text', () => {
    expect(NP.escapeHtml('Привет мир')).toBe('Привет мир');
  });

  test('preserves emoji', () => {
    expect(NP.escapeHtml('Hello 🎉')).toBe('Hello 🎉');
  });
});

// ───────────────────────────────────────────────────────────────────
// 3. INPUT VALIDATION
// ───────────────────────────────────────────────────────────────────

describe('validateMessage', () => {
  test('accepts valid message', () => {
    const result = NP.validateMessage({
      action: 'startPresentation',
      splitMode: 'divider',
      theme: 'light',
      showToc: true
    });
    expect(result).not.toBeNull();
    expect(result.splitMode).toBe('divider');
    expect(result.theme).toBe('light');
    expect(result.showToc).toBe(true);
  });

  test('accepts all valid split modes', () => {
    for (const mode of ['divider', 'h1', 'h2', 'h1h2']) {
      const r = NP.validateMessage({
        action: 'startPresentation', splitMode: mode, theme: 'dark', showToc: false
      });
      expect(r).not.toBeNull();
      expect(r.splitMode).toBe(mode);
    }
  });

  test('accepts all valid themes', () => {
    for (const theme of ['light', 'dark', 'notion', 'gradient']) {
      const r = NP.validateMessage({
        action: 'startPresentation', splitMode: 'divider', theme, showToc: false
      });
      expect(r).not.toBeNull();
      expect(r.theme).toBe(theme);
    }
  });

  test('rejects invalid action', () => {
    expect(NP.validateMessage({
      action: 'deleteEverything', splitMode: 'divider', theme: 'light'
    })).toBeNull();
  });

  test('rejects invalid splitMode', () => {
    expect(NP.validateMessage({
      action: 'startPresentation', splitMode: 'h4', theme: 'light'
    })).toBeNull();
  });

  test('rejects invalid theme', () => {
    expect(NP.validateMessage({
      action: 'startPresentation', splitMode: 'divider', theme: 'hacker'
    })).toBeNull();
  });

  test('rejects XSS in splitMode', () => {
    expect(NP.validateMessage({
      action: 'startPresentation',
      splitMode: '<script>alert(1)</script>',
      theme: 'light'
    })).toBeNull();
  });

  test('rejects XSS in theme', () => {
    expect(NP.validateMessage({
      action: 'startPresentation',
      splitMode: 'divider',
      theme: '"><script>alert(1)</script>'
    })).toBeNull();
  });

  test('coerces showToc to boolean', () => {
    const r = NP.validateMessage({
      action: 'startPresentation', splitMode: 'divider', theme: 'light',
      showToc: 'true'  // string, not boolean
    });
    expect(r.showToc).toBe(false); // strict: only true === true
  });

  test('rejects null', () => {
    expect(NP.validateMessage(null)).toBeNull();
  });

  test('rejects undefined', () => {
    expect(NP.validateMessage(undefined)).toBeNull();
  });

  test('rejects string', () => {
    expect(NP.validateMessage('startPresentation')).toBeNull();
  });

  test('rejects array', () => {
    expect(NP.validateMessage([1, 2, 3])).toBeNull();
  });

  test('returns frozen object', () => {
    const result = NP.validateMessage({
      action: 'startPresentation', splitMode: 'h1', theme: 'dark', showToc: false
    });
    expect(Object.isFrozen(result)).toBe(true);
  });
});

// ───────────────────────────────────────────────────────────────────
// 4. DOMAIN VERIFICATION
// ───────────────────────────────────────────────────────────────────

describe('isNotionPage', () => {
  const origLocation = window.location;

  afterEach(() => {
    // Restore
    Object.defineProperty(window, 'location', {
      value: origLocation,
      writable: true,
      configurable: true
    });
  });

  function mockHostname(hostname) {
    delete window.location;
    window.location = { hostname };
  }

  test('accepts *.notion.site', () => {
    mockHostname('mypage.notion.site');
    expect(NP.isNotionPage()).toBe(true);
  });

  test('accepts *.notion.so', () => {
    mockHostname('www.notion.so');
    expect(NP.isNotionPage()).toBe(true);
  });

  test('accepts notion.site', () => {
    mockHostname('notion.site');
    expect(NP.isNotionPage()).toBe(true);
  });

  test('accepts notion.so', () => {
    mockHostname('notion.so');
    expect(NP.isNotionPage()).toBe(true);
  });

  test('rejects evil-notion.site', () => {
    mockHostname('evil-notion.site');
    expect(NP.isNotionPage()).toBe(false);
  });

  test('rejects notion.site.evil.com', () => {
    mockHostname('notion.site.evil.com');
    expect(NP.isNotionPage()).toBe(false);
  });

  test('rejects google.com', () => {
    mockHostname('google.com');
    expect(NP.isNotionPage()).toBe(false);
  });

  test('rejects localhost', () => {
    mockHostname('localhost');
    expect(NP.isNotionPage()).toBe(false);
  });

  test('rejects empty string', () => {
    mockHostname('');
    expect(NP.isNotionPage()).toBe(false);
  });
});

// ───────────────────────────────────────────────────────────────────
// 5. BLOCK TYPE DETECTION
// ───────────────────────────────────────────────────────────────────

describe('getBlockType', () => {
  test('detects notion-header-block as h1', () => {
    const e = el('div', { className: 'notion-header-block' });
    expect(NP.getBlockType(e)).toBe('h1');
  });

  test('detects notion-sub_header-block as h2', () => {
    const e = el('div', { className: 'notion-sub_header-block' });
    expect(NP.getBlockType(e)).toBe('h2');
  });

  test('detects notion-sub_sub_header-block as h3', () => {
    const e = el('div', { className: 'notion-sub_sub_header-block' });
    expect(NP.getBlockType(e)).toBe('h3');
  });

  test('detects notion-divider-block as divider', () => {
    const e = el('div', { className: 'notion-divider-block' });
    expect(NP.getBlockType(e)).toBe('divider');
  });

  test('detects raw <h1> tag', () => {
    const e = document.createElement('h1');
    expect(NP.getBlockType(e)).toBe('h1');
  });

  test('detects raw <h2> tag', () => {
    const e = document.createElement('h2');
    expect(NP.getBlockType(e)).toBe('h2');
  });

  test('detects raw <hr> tag', () => {
    const e = document.createElement('hr');
    expect(NP.getBlockType(e)).toBe('divider');
  });

  test('returns null for regular div', () => {
    const e = el('div', { className: 'notion-text-block' });
    expect(NP.getBlockType(e)).toBeNull();
  });

  test('does not confuse sub_header with header', () => {
    const e = el('div', { className: 'notion-sub_header-block' });
    expect(NP.getBlockType(e)).toBe('h2'); // not h1
  });
});

// ───────────────────────────────────────────────────────────────────
// 6. HEADING HELPERS
// ───────────────────────────────────────────────────────────────────

describe('isH1Block / isH2Block', () => {
  test('isH1Block returns true for h1', () => {
    expect(NP.isH1Block(el('div', { className: 'notion-header-block' }))).toBe(true);
  });

  test('isH1Block returns false for h2', () => {
    expect(NP.isH1Block(el('div', { className: 'notion-sub_header-block' }))).toBe(false);
  });

  test('isH2Block returns true for h2', () => {
    expect(NP.isH2Block(el('div', { className: 'notion-sub_header-block' }))).toBe(true);
  });

  test('isH2Block returns true for h3', () => {
    expect(NP.isH2Block(el('div', { className: 'notion-sub_sub_header-block' }))).toBe(true);
  });

  test('isH2Block returns false for h1', () => {
    expect(NP.isH2Block(el('div', { className: 'notion-header-block' }))).toBe(false);
  });
});

describe('getHeadingText', () => {
  test('extracts text from nested h2', () => {
    const e = el('div', { className: 'notion-sub_header-block' }, '<h2>My Heading</h2>');
    expect(NP.getHeadingText(e)).toBe('My Heading');
  });

  test('extracts text from nested h1', () => {
    const e = el('div', { className: 'notion-header-block' }, '<h1>Title</h1>');
    expect(NP.getHeadingText(e)).toBe('Title');
  });

  test('falls back to textContent if no heading tag', () => {
    const e = el('div', {}, 'Plain text heading');
    expect(NP.getHeadingText(e)).toBe('Plain text heading');
  });

  test('truncates long text to 100 chars', () => {
    const long = 'A'.repeat(200);
    const e = el('div', {}, long);
    expect(NP.getHeadingText(e).length).toBe(100);
  });

  test('trims whitespace', () => {
    const e = el('div', {}, '<h1>  Spaced Title  </h1>');
    expect(NP.getHeadingText(e)).toBe('Spaced Title');
  });
});

// ───────────────────────────────────────────────────────────────────
// 7. DIVIDER DETECTION
// ───────────────────────────────────────────────────────────────────

describe('isDivider', () => {
  test('detects notion-divider-block', () => {
    expect(NP.isDivider(el('div', { className: 'notion-divider-block' }))).toBe(true);
  });

  test('detects <hr> child', () => {
    const e = el('div', {}, '<hr>');
    expect(NP.isDivider(e)).toBe(true);
  });

  test('returns false for regular block', () => {
    expect(NP.isDivider(el('div', { className: 'notion-text-block' }, '<p>text</p>'))).toBe(false);
  });
});

// ───────────────────────────────────────────────────────────────────
// 8. SLIDE BUILDING (buildSlideFromBlocks)
// ───────────────────────────────────────────────────────────────────

describe('buildSlideFromBlocks', () => {
  test('extracts H1 as title when no H2 present', () => {
    const blocks = [
      el('div', { className: 'notion-header-block' }, '<h1>Step 1</h1>'),
      el('div', { className: 'notion-text-block' }, '<p>Content here</p>')
    ];
    const slide = NP.buildSlideFromBlocks(blocks, '');
    expect(slide.title).toBe('Step 1');
    expect(slide.parentH1).toBe('');
    expect(slide.content).toContain('Content here');
  });

  test('H1 + H2 → H1 as parentH1, H2 as title', () => {
    const blocks = [
      el('div', { className: 'notion-header-block' }, '<h1>Chapter 1</h1>'),
      el('div', { className: 'notion-sub_header-block' }, '<h2>Section A</h2>'),
      el('div', { className: 'notion-text-block' }, '<p>Details</p>')
    ];
    const slide = NP.buildSlideFromBlocks(blocks, '');
    expect(slide.title).toBe('Section A');
    expect(slide.parentH1).toBe('Chapter 1');
    expect(slide.content).toContain('Details');
  });

  test('only H2 with contextH1 → contextH1 as parentH1', () => {
    const blocks = [
      el('div', { className: 'notion-sub_header-block' }, '<h2>Sub-topic</h2>'),
      el('div', { className: 'notion-text-block' }, '<p>More info</p>')
    ];
    const slide = NP.buildSlideFromBlocks(blocks, 'Parent Chapter');
    expect(slide.title).toBe('Sub-topic');
    expect(slide.parentH1).toBe('Parent Chapter');
  });

  test('does not duplicate parentH1 if same as title', () => {
    const blocks = [
      el('div', { className: 'notion-sub_header-block' }, '<h2>Same Text</h2>'),
      el('div', { className: 'notion-text-block' }, '<p>Content</p>')
    ];
    const slide = NP.buildSlideFromBlocks(blocks, 'Same Text');
    expect(slide.parentH1).toBe('');
  });

  test('handles blocks with no headings', () => {
    const blocks = [
      el('div', { className: 'notion-text-block' }, '<p>Just text</p>'),
      el('div', { className: 'notion-text-block' }, '<p>More text</p>')
    ];
    const slide = NP.buildSlideFromBlocks(blocks, '');
    expect(slide.title).toBe('');
    expect(slide.content).toContain('Just text');
    expect(slide.content).toContain('More text');
  });
});

// ───────────────────────────────────────────────────────────────────
// 9. SPLIT BY DIVIDER
// ───────────────────────────────────────────────────────────────────

describe('splitByDivider', () => {
  test('splits blocks at dividers', () => {
    const blocks = [
      el('div', { className: 'notion-text-block' }, '<p>Slide 1</p>'),
      el('div', { className: 'notion-divider-block' }),
      el('div', { className: 'notion-text-block' }, '<p>Slide 2</p>')
    ];
    const slides = NP.splitByDivider(blocks, 'Page Title');
    expect(slides.length).toBe(2);
  });

  test('creates title slide from page title', () => {
    const blocks = [
      el('div', { className: 'notion-text-block' }, '<p>Intro</p>'),
      el('div', { className: 'notion-divider-block' }),
      el('div', { className: 'notion-text-block' }, '<p>Main</p>')
    ];
    const slides = NP.splitByDivider(blocks, 'My Presentation');
    expect(slides[0].isTitle).toBe(true);
    expect(slides[0].title).toBe('My Presentation');
  });

  test('tracks H1 context across dividers', () => {
    const blocks = [
      el('div', { className: 'notion-header-block' }, '<h1>Chapter</h1>'),
      el('div', { className: 'notion-divider-block' }),
      el('div', { className: 'notion-sub_header-block' }, '<h2>Section</h2>'),
      el('div', { className: 'notion-text-block' }, '<p>Content</p>')
    ];
    const slides = NP.splitByDivider(blocks, '');
    // Find the slide with "Section" title
    const sectionSlide = slides.find(s => s.title === 'Section');
    expect(sectionSlide).toBeDefined();
    expect(sectionSlide.parentH1).toBe('Chapter');
  });

  test('handles empty blocks array', () => {
    const slides = NP.splitByDivider([], 'Title');
    expect(slides.length).toBe(0);
  });

  test('handles no dividers', () => {
    const blocks = [
      el('div', { className: 'notion-text-block' }, '<p>All content</p>')
    ];
    const slides = NP.splitByDivider(blocks, 'Title');
    expect(slides.length).toBe(1);
  });
});

// ───────────────────────────────────────────────────────────────────
// 10. SPLIT BY HEADINGS
// ───────────────────────────────────────────────────────────────────

describe('splitByHeadings', () => {
  test('splits by H1 headings', () => {
    const blocks = [
      el('div', { className: 'notion-header-block' }, '<h1>First</h1>'),
      el('div', { className: 'notion-text-block' }, '<p>Content 1</p>'),
      el('div', { className: 'notion-header-block' }, '<h1>Second</h1>'),
      el('div', { className: 'notion-text-block' }, '<p>Content 2</p>')
    ];
    const slides = NP.splitByHeadings(blocks, 'h1', 'Page');
    // Should have title slide + 2 content slides
    expect(slides.length).toBe(3);
    expect(slides[0].isTitle).toBe(true);
    expect(slides[1].title).toBe('First');
    expect(slides[2].title).toBe('Second');
  });

  test('splits by H2 headings', () => {
    const blocks = [
      el('div', { className: 'notion-sub_header-block' }, '<h2>Part A</h2>'),
      el('div', { className: 'notion-text-block' }, '<p>Text A</p>'),
      el('div', { className: 'notion-sub_header-block' }, '<h2>Part B</h2>'),
      el('div', { className: 'notion-text-block' }, '<p>Text B</p>')
    ];
    const slides = NP.splitByHeadings(blocks, 'h2', '');
    expect(slides.length).toBeGreaterThanOrEqual(2);
  });

  test('H1+H2 mode: H2 shows parentH1', () => {
    const blocks = [
      el('div', { className: 'notion-header-block' }, '<h1>Main Topic</h1>'),
      el('div', { className: 'notion-text-block' }, '<p>Intro</p>'),
      el('div', { className: 'notion-sub_header-block' }, '<h2>Sub-topic</h2>'),
      el('div', { className: 'notion-text-block' }, '<p>Details</p>')
    ];
    const slides = NP.splitByHeadings(blocks, 'h1h2', '');
    const subSlide = slides.find(s => s.title === 'Sub-topic');
    expect(subSlide).toBeDefined();
    expect(subSlide.parentH1).toBe('Main Topic');
  });

  test('handles empty blocks', () => {
    const slides = NP.splitByHeadings([], 'h1', '');
    expect(slides.length).toBe(0);
  });
});

// ───────────────────────────────────────────────────────────────────
// 11. TOC GENERATION
// ───────────────────────────────────────────────────────────────────

describe('buildTocHtml', () => {
  test('generates TOC with correct slide indices', () => {
    const slides = [
      { title: 'Intro', parentH1: '', content: '', isTitle: true },
      { title: 'Chapter 1', parentH1: '', content: '<p>text</p>', isTitle: false },
      { title: 'Section A', parentH1: 'Chapter 1', content: '<p>text</p>', isTitle: false }
    ];
    const toc = NP.buildTocHtml(slides);
    expect(toc).toContain('data-slide-index="0"');
    expect(toc).toContain('data-slide-index="1"');
    expect(toc).toContain('data-slide-index="2"');
  });

  test('adds indent class for slides with parentH1', () => {
    const slides = [
      { title: 'Main', parentH1: '', content: '' },
      { title: 'Sub', parentH1: 'Main', content: '' }
    ];
    const toc = NP.buildTocHtml(slides);
    expect(toc).toContain('np-toc-indent');
  });

  test('escapes HTML in slide titles (XSS prevention)', () => {
    const slides = [
      { title: '<img src=x onerror=alert(1)>', parentH1: '', content: '' }
    ];
    const toc = NP.buildTocHtml(slides);
    expect(toc).not.toContain('<img');
    expect(toc).toContain('&lt;img');
  });

  test('falls back to "Slide N" for empty titles', () => {
    const slides = [
      { title: '', parentH1: '', content: '<p>text</p>' }
    ];
    const toc = NP.buildTocHtml(slides);
    expect(toc).toContain('Slide 1');
  });
});

// ───────────────────────────────────────────────────────────────────
// 12. SLIDE CONTENT SANITISATION
// ───────────────────────────────────────────────────────────────────

describe('sanitizeSlideContent', () => {
  test('removes loading placeholders', () => {
    const result = NP.sanitizeSlideContent(
      '<div data-placeholder="Loading...">Loading</div><p>Real content</p>'
    );
    expect(result).not.toContain('Loading');
    expect(result).toContain('Real content');
  });

  test('strips max-width inline styles', () => {
    const result = NP.sanitizeSlideContent(
      '<div style="max-width: 720px;">Content</div>'
    );
    expect(result).not.toContain('720px');
  });

  test('strips position: fixed', () => {
    const result = NP.sanitizeSlideContent(
      '<div style="position: fixed; top: 0;">Sticky nav</div>'
    );
    expect(result).not.toContain('fixed');
  });

  test('strips position: sticky', () => {
    const result = NP.sanitizeSlideContent(
      '<div style="position: sticky;">Header</div>'
    );
    expect(result).not.toContain('sticky');
  });

  test('runs sanitizeDOM as defence-in-depth', () => {
    const result = NP.sanitizeSlideContent(
      '<p>Safe</p><script>alert(1)</script>'
    );
    expect(result).not.toContain('<script>');
    expect(result).toContain('Safe');
  });

  test('removes javascript: URLs in content', () => {
    const result = NP.sanitizeSlideContent(
      '<a href="javascript:alert(document.cookie)">Click</a>'
    );
    expect(result).not.toContain('javascript:');
  });

  test('removes event handlers in content', () => {
    const result = NP.sanitizeSlideContent(
      '<img src="photo.jpg" onerror="alert(1)">'
    );
    expect(result).not.toContain('onerror');
  });
});

// ───────────────────────────────────────────────────────────────────
// 13. DUPLICATE HEADING REMOVAL
// ───────────────────────────────────────────────────────────────────

describe('removeDuplicateHeading', () => {
  test('removes matching h2 from content', () => {
    const result = NP.removeDuplicateHeading(
      '<h2>My Title</h2><p>Content below</p>',
      'My Title'
    );
    expect(result).not.toContain('<h2>');
    expect(result).toContain('Content below');
  });

  test('removes matching h1', () => {
    const result = NP.removeDuplicateHeading(
      '<h1>Big Title</h1><p>Text</p>',
      'Big Title'
    );
    expect(result).not.toContain('<h1>');
  });

  test('preserves non-matching headings', () => {
    const result = NP.removeDuplicateHeading(
      '<h2>Different Title</h2><p>Text</p>',
      'My Title'
    );
    expect(result).toContain('<h2>');
    expect(result).toContain('Different Title');
  });

  test('only removes first matching heading', () => {
    const result = NP.removeDuplicateHeading(
      '<h2>Dup</h2><p>Between</p><h2>Dup</h2>',
      'Dup'
    );
    // Should still contain one h2
    const count = (result.match(/<h2>/g) || []).length;
    expect(count).toBe(1);
  });

  test('handles empty content', () => {
    const result = NP.removeDuplicateHeading('', 'Title');
    expect(result).toBe('');
  });

  test('removes empty parent wrapper after heading removal', () => {
    const result = NP.removeDuplicateHeading(
      '<div><h2>Title</h2></div><p>Content</p>',
      'Title'
    );
    expect(result).toContain('Content');
  });
});

// ───────────────────────────────────────────────────────────────────
// 14. CONSTANTS INTEGRITY
// ───────────────────────────────────────────────────────────────────

describe('Security constants', () => {
  test('ALLOWED_SPLIT_MODES is frozen', () => {
    expect(Object.isFrozen(NP.ALLOWED_SPLIT_MODES)).toBe(true);
  });

  test('ALLOWED_THEMES is frozen', () => {
    expect(Object.isFrozen(NP.ALLOWED_THEMES)).toBe(true);
  });

  test('DANGEROUS_TAGS is frozen', () => {
    expect(Object.isFrozen(NP.DANGEROUS_TAGS)).toBe(true);
  });

  test('MAX_SLIDES is a positive number', () => {
    expect(NP.MAX_SLIDES).toBeGreaterThan(0);
    expect(NP.MAX_SLIDES).toBeLessThanOrEqual(1000);
  });

  test('DANGEROUS_TAGS includes critical entries', () => {
    const tags = NP.DANGEROUS_TAGS;
    expect(tags).toContain('script');
    expect(tags).toContain('iframe');
    expect(tags).toContain('object');
    expect(tags).toContain('embed');
    expect(tags).toContain('form');
    expect(tags).toContain('style');
    expect(tags).toContain('base');
    expect(tags).toContain('template');
    expect(tags).toContain('foreignobject');
  });
});

// ───────────────────────────────────────────────────────────────────
// 15. EDGE CASES
// ───────────────────────────────────────────────────────────────────

describe('Edge cases', () => {
  test('sanitizeDOM handles deeply nested scripts', () => {
    const root = html('<div><div><div><div><script>deep()</script></div></div></div></div>');
    NP.sanitizeDOM(root);
    expect(root.querySelector('script')).toBeNull();
  });

  test('sanitizeDOM handles multiple dangerous tags together', () => {
    const root = html(`
      <script>a()</script>
      <iframe src="x"></iframe>
      <object data="x"></object>
      <embed src="x">
      <form><input></form>
      <p onclick="z()" onmouseover="y()">Safe text</p>
    `);
    NP.sanitizeDOM(root);
    expect(root.querySelector('script')).toBeNull();
    expect(root.querySelector('iframe')).toBeNull();
    expect(root.querySelector('object')).toBeNull();
    expect(root.querySelector('embed')).toBeNull();
    expect(root.querySelector('form')).toBeNull();
    expect(root.querySelector('input')).toBeNull();
    expect(root.querySelector('[onclick]')).toBeNull();
    expect(root.querySelector('[onmouseover]')).toBeNull();
    expect(root.textContent).toContain('Safe text');
  });

  test('buildSlideFromBlocks handles empty array', () => {
    const slide = NP.buildSlideFromBlocks([], '');
    expect(slide.title).toBe('');
    expect(slide.parentH1).toBe('');
    expect(slide.content).toBe('');
  });

  test('getHeadingText handles element with no text', () => {
    const e = document.createElement('div');
    expect(NP.getHeadingText(e)).toBe('');
  });

  test('escapeHtml handles special HTML entities', () => {
    const result = NP.escapeHtml('1 < 2 && 3 > 2');
    expect(result).toContain('&lt;');
    expect(result).toContain('&amp;');
    expect(result).toContain('&gt;');
  });

  test('sanitizeSlideContent handles empty string', () => {
    expect(NP.sanitizeSlideContent('')).toBe('');
  });

  test('validateMessage handles prototype pollution attempt', () => {
    const malicious = JSON.parse('{"action":"startPresentation","splitMode":"divider","theme":"light","__proto__":{"admin":true}}');
    const result = NP.validateMessage(malicious);
    // Should still validate normally, not leak __proto__
    expect(result).not.toBeNull();
    expect(result.splitMode).toBe('divider');
    expect(result.admin).toBeUndefined();
  });
});
