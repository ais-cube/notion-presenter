(() => {
  'use strict';

  // ─── SECURITY CONFIGURATION ─────────────────────────────────────

  const ALLOWED_SPLIT_MODES = Object.freeze(['divider', 'h1', 'h2', 'h1h2']);
  const ALLOWED_THEMES = Object.freeze(['light', 'dark', 'notion', 'gradient']);

  /** Tags that are never safe inside slide content. */
  const DANGEROUS_TAGS = Object.freeze([
    'script', 'iframe', 'object', 'embed', 'applet', 'form',
    'input', 'textarea', 'select', 'button', 'base', 'meta',
    'link', 'style', 'frame', 'frameset', 'noscript', 'template',
    'foreignobject'
  ]);

  /** Attributes that carry URLs and must be scheme-checked. */
  const URL_BEARING_ATTRS = Object.freeze([
    'href', 'src', 'action', 'formaction', 'poster',
    'background', 'dynsrc', 'lowsrc', 'srcdoc', 'xlink:href'
  ]);

  const DANGEROUS_URL_RE   = /^\s*(javascript|vbscript|data\s*:\s*text\/html)/i;
  const DANGEROUS_STYLE_RE = /expression\s*\(|url\s*\(\s*["']?\s*(javascript|data\s*:\s*text\/html)|@import/i;

  /** Max slides to prevent memory exhaustion from malformed pages. */
  const MAX_SLIDES = 500;

  // ─── STATE ──────────────────────────────────────────────────────

  let presenterActive = false;
  let presenterOverlay = null;

  // ─── SECURITY HELPERS ───────────────────────────────────────────

  /**
   * Sanitise a DOM subtree in-place.
   * Removes dangerous elements, event-handler attributes,
   * javascript: / data:text/html URLs, and CSS expressions.
   */
  function sanitizeDOM(root) {
    // Pass 1 — strip dangerous elements entirely
    for (const tag of DANGEROUS_TAGS) {
      root.querySelectorAll(tag).forEach(el => el.remove());
    }

    // Pass 2 — sanitise every remaining element's attributes
    root.querySelectorAll('*').forEach(el => {
      const toRemove = [];

      for (const attr of el.attributes) {
        const name = attr.name.toLowerCase();

        // on* event handlers (onclick, onerror, onload …)
        if (name.startsWith('on')) {
          toRemove.push(attr.name);
          continue;
        }

        // Dangerous URL schemes in URL-bearing attributes
        if (URL_BEARING_ATTRS.includes(name) && DANGEROUS_URL_RE.test(attr.value)) {
          toRemove.push(attr.name);
          continue;
        }

        // CSS expression() / @import injection via style attribute
        if (name === 'style' && DANGEROUS_STYLE_RE.test(attr.value)) {
          toRemove.push(attr.name);
          continue;
        }
      }

      for (const n of toRemove) el.removeAttribute(n);
    });

    return root;
  }

  /** Escape plain text for safe insertion into HTML contexts. */
  function escapeHtml(text) {
    const d = document.createElement('div');
    d.textContent = String(text);
    return d.innerHTML;
  }

  /**
   * Validate an incoming message from the popup.
   * Returns a frozen params object or null if invalid.
   */
  function validateMessage(msg) {
    if (!msg || typeof msg !== 'object') return null;
    if (msg.action !== 'startPresentation') return null;

    const splitMode = ALLOWED_SPLIT_MODES.includes(msg.splitMode) ? msg.splitMode : null;
    const theme = ALLOWED_THEMES.includes(msg.theme) ? msg.theme : null;
    const showToc = msg.showToc === true;

    if (!splitMode || !theme) return null;
    return Object.freeze({ splitMode, theme, showToc });
  }

  /** Verify the current page is a legitimate Notion domain. */
  function isNotionPage() {
    const h = location.hostname;
    return h.endsWith('.notion.site') || h.endsWith('.notion.so') ||
           h === 'notion.site' || h === 'notion.so';
  }

  // ─── MESSAGE LISTENER ──────────────────────────────────────────

  chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
    if (msg.action !== 'startPresentation') return;

    try {
      // Security: verify we are on a Notion domain
      if (!isNotionPage()) {
        sendResponse({ success: false, error: 'Not a Notion page.' });
        return true;
      }

      // Security: whitelist every input parameter
      const params = validateMessage(msg);
      if (!params) {
        sendResponse({ success: false, error: 'Invalid parameters.' });
        return true;
      }

      const slides = parseNotionPage(params.splitMode);
      if (slides.length === 0) {
        sendResponse({ success: false, error: 'No slides found. Try a different split mode.' });
        return true;
      }

      launchPresenter(slides, params.theme, params.showToc);
      sendResponse({ success: true, slideCount: slides.length });
    } catch (e) {
      sendResponse({ success: false, error: String(e.message || 'Unknown error') });
    }

    return true;
  });

  // ─── NOTION PAGE PARSER ─────────────────────────────────────────

  function findPageContent() {
    const selectors = [
      '.notion-page-content',
      '[class*="notion-page-content"]',
      '.layout-content',
      'main .page-body',
      'main',
      'article',
      '.notion-app-inner'
    ];
    for (const sel of selectors) {
      const el = document.querySelector(sel);
      if (el && el.children.length > 0) return el;
    }
    return null;
  }

  function getPageTitle() {
    const selectors = [
      '.notion-page__title',
      '[class*="notion-page__title"]',
      'h1.notion-header__title',
      '.notion-title',
      'header h1',
      '.page-title h1',
      '.notion-page-block > h1',
      '.notion-page-block > div > h1'
    ];
    for (const sel of selectors) {
      const el = document.querySelector(sel);
      if (el && el.textContent.trim()) return el.textContent.trim();
    }
    const docTitle = document.title.replace(/\s*[|–—]\s*Notion.*$/i, '').trim();
    return docTitle || '';
  }

  function getBlockType(el) {
    const cls = el.className || '';
    if (cls.includes('notion-header-block') && !cls.includes('sub')) return 'h1';
    if (cls.includes('notion-sub_header-block') && !cls.includes('sub_sub')) return 'h2';
    if (cls.includes('notion-sub_sub_header-block')) return 'h3';
    if (cls.includes('notion-divider-block') || cls.includes('divider-block')) return 'divider';
    const tag = el.tagName?.toLowerCase();
    if (tag === 'h1') return 'h1';
    if (tag === 'h2') return 'h2';
    if (tag === 'h3') return 'h3';
    if (tag === 'hr') return 'divider';
    return null;
  }

  function parseNotionPage(splitMode) {
    const pageContent = findPageContent();
    if (!pageContent) {
      throw new Error('Cannot find Notion page content');
    }

    const pageTitle = getPageTitle();
    const clone = pageContent.cloneNode(true);

    // Security: sanitise all cloned DOM before any processing
    sanitizeDOM(clone);

    let blocks = Array.from(clone.children);
    let slides = [];

    if (splitMode === 'divider') {
      slides = splitByDivider(blocks, pageTitle);
    } else {
      slides = splitByHeadings(blocks, splitMode, pageTitle);
    }

    // If only one slide, try deeper nesting
    if (slides.length <= 1) {
      const deepBlocks = clone.querySelectorAll(':scope > div > div');
      if (deepBlocks.length > 2) {
        const blockArr = Array.from(deepBlocks);
        if (splitMode === 'divider') {
          slides = splitByDivider(blockArr, pageTitle);
        } else {
          slides = splitByHeadings(blockArr, splitMode, pageTitle);
        }
      }
    }

    if (slides.length === 0) {
      slides = [{ title: pageTitle || 'Slide 1', parentH1: '', content: clone.innerHTML }];
    }

    // Security: cap total slides to prevent resource exhaustion
    if (slides.length > MAX_SLIDES) slides.length = MAX_SLIDES;

    return slides;
  }

  function isHeadingMatch(el, splitMode) {
    const type = getBlockType(el);
    if (splitMode === 'h1' && type === 'h1') return true;
    if (splitMode === 'h2' && (type === 'h2' || type === 'h3')) return true;
    if (splitMode === 'h1h2' && (type === 'h1' || type === 'h2' || type === 'h3')) return true;
    // Deep check
    if (splitMode === 'h1' && el.querySelector(':scope > h1, :scope > div > h1')) return true;
    if (splitMode === 'h2' && el.querySelector(':scope > h2, :scope > h3, :scope > div > h2, :scope > div > h3')) return true;
    if (splitMode === 'h1h2' && el.querySelector(':scope > h1, :scope > h2, :scope > h3, :scope > div > h1, :scope > div > h2, :scope > div > h3')) return true;
    return false;
  }

  function isDivider(el) {
    return getBlockType(el) === 'divider' ||
      (el.querySelector?.(':scope > hr') != null) ||
      (el.children.length === 1 && el.children[0].tagName?.toLowerCase() === 'hr');
  }

  function isH1Block(el) {
    return getBlockType(el) === 'h1';
  }

  function isH2Block(el) {
    const t = getBlockType(el);
    return t === 'h2' || t === 'h3';
  }

  function getHeadingText(el) {
    const h = el.querySelector('h1, h2, h3');
    if (h) return h.textContent.trim();
    return el.textContent?.trim().substring(0, 100) || '';
  }

  function splitByHeadings(blocks, splitMode, pageTitle) {
    const slides = [];
    let currentSlide = null;
    let preHeadingContent = '';
    let lastH1 = '';

    for (const block of blocks) {
      if (isH1Block(block)) lastH1 = getHeadingText(block);

      if (isHeadingMatch(block, splitMode)) {
        if (currentSlide && (currentSlide.content.trim() || currentSlide.isTitle)) {
          slides.push(currentSlide);
        }
        const heading = getHeadingText(block);
        const isThisH1 = isH1Block(block);
        currentSlide = {
          title: heading,
          parentH1: isThisH1 ? '' : lastH1,
          content: '',
          isTitle: false
        };
      } else {
        if (!currentSlide) {
          preHeadingContent += block.outerHTML;
        } else {
          currentSlide.content += block.outerHTML;
        }
      }
    }

    if (currentSlide && (currentSlide.content.trim() || currentSlide.title)) {
      slides.push(currentSlide);
    }

    if (pageTitle || preHeadingContent) {
      slides.unshift({
        title: pageTitle,
        parentH1: '',
        content: preHeadingContent,
        isTitle: true
      });
    }

    return slides;
  }

  function splitByDivider(blocks, pageTitle) {
    const groups = [];
    let currentBlocks = [];
    let lastH1 = '';

    for (const block of blocks) {
      if (isDivider(block)) {
        if (currentBlocks.length > 0) {
          groups.push({ blocks: currentBlocks, contextH1: lastH1 });
        }
        currentBlocks = [];
      } else {
        if (isH1Block(block)) lastH1 = getHeadingText(block);
        currentBlocks.push(block);
      }
    }
    if (currentBlocks.length > 0) {
      groups.push({ blocks: currentBlocks, contextH1: lastH1 });
    }

    const slides = [];
    for (const group of groups) {
      slides.push(buildSlideFromBlocks(group.blocks, group.contextH1));
    }

    if (pageTitle && slides.length > 0) {
      const firstSlideText = slides[0].content.replace(/<[^>]*>/g, '').trim();
      if (firstSlideText.length < 200) {
        slides[0].isTitle = true;
        slides[0].title = pageTitle;
      } else {
        slides.unshift({ title: pageTitle, parentH1: '', content: '', isTitle: true });
      }
    }

    return slides;
  }

  function buildSlideFromBlocks(blocks, contextH1) {
    let localH1 = '';
    let title = '';
    let contentParts = [];

    for (const block of blocks) {
      if (isH1Block(block)) {
        localH1 = getHeadingText(block);
        continue;
      }
      if (!title && isH2Block(block)) {
        title = getHeadingText(block);
        continue;
      }
      if (!title) {
        const h = block.querySelector?.('h1, h2, h3');
        if (h) {
          title = h.textContent.trim();
          const cleaned = block.cloneNode(true);
          const hInClone = cleaned.querySelector('h1, h2, h3');
          if (hInClone) hInClone.remove();
          const remaining = cleaned.innerHTML.trim();
          if (remaining) contentParts.push(cleaned.outerHTML);
          continue;
        }
      }
      contentParts.push(block.outerHTML);
    }

    if (localH1 && !title) {
      title = localH1;
      return { title, parentH1: '', content: contentParts.join(''), isTitle: false };
    }

    let parentH1 = localH1 || contextH1 || '';
    if (parentH1 === title) parentH1 = '';

    return { title, parentH1, content: contentParts.join(''), isTitle: false };
  }

  // ─── PRESENTER ENGINE ───────────────────────────────────────────

  /**
   * Second-pass sanitiser for slide body HTML.
   * Runs AFTER the initial sanitizeDOM pass on the whole clone,
   * but catches anything that might have been assembled later.
   */
  function sanitizeSlideContent(html) {
    const temp = document.createElement('div');
    temp.innerHTML = html;

    // Security: full sanitisation pass (defence-in-depth)
    sanitizeDOM(temp);

    // Remove Notion loading placeholders
    temp.querySelectorAll('[data-placeholder]').forEach(el => {
      if (el.textContent.includes('Loading')) el.remove();
    });

    // Strip problematic layout styles
    temp.querySelectorAll('*').forEach(el => {
      const s = el.style;
      if (s.maxWidth) s.maxWidth = '';
      if (s.position === 'fixed' || s.position === 'sticky') s.position = '';
    });

    return temp.innerHTML;
  }

  /** Build TOC sidebar HTML. All labels are escaped. */
  function buildTocHtml(slides) {
    let html = '<nav class="np-toc"><div class="np-toc-title">Contents</div><ul class="np-toc-list">';
    slides.forEach((slide, i) => {
      // Security: escape user-controlled text
      const label = escapeHtml(slide.title || `Slide ${i + 1}`);
      const indent = slide.parentH1 ? ' np-toc-indent' : '';
      html += `<li class="np-toc-item${indent}" data-slide-index="${i}">${label}</li>`;
    });
    html += '</ul></nav>';
    return html;
  }

  function removeDuplicateHeading(html, titleText) {
    const temp = document.createElement('div');
    temp.innerHTML = html;
    const headings = temp.querySelectorAll('h1, h2, h3');
    for (const h of headings) {
      if (h.textContent.trim() === titleText.trim()) {
        const parent = h.parentElement;
        h.remove();
        if (parent && parent !== temp && parent.textContent.trim() === '' && parent.children.length === 0) {
          parent.remove();
        }
        break;
      }
    }
    return temp.innerHTML;
  }

  // ─── LAUNCH ─────────────────────────────────────────────────────

  function launchPresenter(slides, theme, showToc) {
    if (presenterActive) destroyPresenter();

    presenterActive = true;
    let currentIndex = 0;

    // Build overlay element
    presenterOverlay = document.createElement('div');
    presenterOverlay.id = 'notion-presenter-overlay';
    // Security: theme is already validated via whitelist
    presenterOverlay.className = `np-theme-${theme}${showToc ? ' np-with-toc' : ''}`;

    const tocHtml = showToc ? buildTocHtml(slides) : '';

    // Security: slides.length is a number we control — safe to interpolate
    presenterOverlay.innerHTML = `
      <div class="np-container">
        <div class="np-main-area">
          ${tocHtml}
          <div class="np-slide-wrapper">
            <div class="np-slide" id="np-slide-content"></div>
          </div>
        </div>
        <div class="np-controls">
          <button class="np-btn np-btn-prev" id="np-prev" title="Previous">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <polyline points="15 18 9 12 15 6"></polyline>
            </svg>
          </button>
          <div class="np-slide-counter">
            <span id="np-current">1</span> / <span id="np-total">${slides.length}</span>
          </div>
          <button class="np-btn np-btn-next" id="np-next" title="Next">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <polyline points="9 18 15 12 9 6"></polyline>
            </svg>
          </button>
          <div class="np-spacer"></div>
          <button class="np-btn np-btn-fullscreen" id="np-fullscreen" title="Fullscreen (F)">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M8 3H5a2 2 0 0 0-2 2v3m18 0V5a2 2 0 0 0-2-2h-3m0 18h3a2 2 0 0 0 2-2v-3M3 16v3a2 2 0 0 0 2 2h3"></path>
            </svg>
          </button>
          <button class="np-btn np-btn-close" id="np-close" title="Exit (Esc)">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <line x1="18" y1="6" x2="6" y2="18"></line>
              <line x1="6" y1="6" x2="18" y2="18"></line>
            </svg>
          </button>
        </div>
        <div class="np-progress">
          <div class="np-progress-bar" id="np-progress-bar"></div>
        </div>
      </div>
    `;

    document.body.appendChild(presenterOverlay);

    // Security: scope all element lookups to our overlay — prevents DOM-clobbering
    // attacks where a malicious page defines elements with matching IDs
    const slideEl       = presenterOverlay.querySelector('#np-slide-content');
    const currentEl     = presenterOverlay.querySelector('#np-current');
    const progressBar   = presenterOverlay.querySelector('#np-progress-bar');
    const prevBtn       = presenterOverlay.querySelector('#np-prev');
    const nextBtn       = presenterOverlay.querySelector('#np-next');
    const closeBtn      = presenterOverlay.querySelector('#np-close');
    const fullscreenBtn = presenterOverlay.querySelector('#np-fullscreen');

    function showSlide(index) {
      currentIndex = Math.max(0, Math.min(index, slides.length - 1));
      const slide = slides[currentIndex];
      const content = sanitizeSlideContent(slide.content);
      const cleanedContent = slide.title
        ? removeDuplicateHeading(content, slide.title)
        : content;

      const parentH1Html = slide.parentH1
        ? `<div class="np-slide-parent-h1">${escapeHtml(slide.parentH1)}</div>`
        : '';

      if (slide.isTitle) {
        slideEl.innerHTML = `
          <div class="np-title-slide">
            <div class="np-title-content">${escapeHtml(slide.title)}</div>
            ${cleanedContent ? `<div class="np-title-subtitle">${cleanedContent}</div>` : ''}
          </div>
        `;
      } else {
        slideEl.innerHTML = `
          <div class="np-content-slide">
            ${parentH1Html}
            ${slide.title ? `<div class="np-slide-heading">${escapeHtml(slide.title)}</div>` : ''}
            <div class="np-slide-body">${cleanedContent}</div>
          </div>
        `;
      }

      currentEl.textContent = currentIndex + 1;
      progressBar.style.width = `${((currentIndex + 1) / slides.length) * 100}%`;

      slideEl.classList.remove('np-slide-enter');
      void slideEl.offsetWidth;
      slideEl.classList.add('np-slide-enter');

      prevBtn.disabled = currentIndex === 0;
      nextBtn.disabled = currentIndex === slides.length - 1;

      // Update TOC active state
      if (showToc) {
        presenterOverlay.querySelectorAll('.np-toc-item').forEach((item, i) => {
          item.classList.toggle('np-toc-active', i === currentIndex);
        });
        const activeItem = presenterOverlay.querySelector('.np-toc-active');
        if (activeItem) activeItem.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
      }
    }

    // TOC click navigation
    if (showToc) {
      presenterOverlay.querySelector('.np-toc-list')?.addEventListener('click', (e) => {
        const item = e.target.closest('.np-toc-item');
        if (item) {
          const idx = parseInt(item.dataset.slideIndex, 10);
          // Security: validate index is within bounds
          if (!isNaN(idx) && idx >= 0 && idx < slides.length) showSlide(idx);
        }
      });
    }

    function nextSlide() {
      if (currentIndex < slides.length - 1) showSlide(currentIndex + 1);
    }

    function prevSlide() {
      if (currentIndex > 0) showSlide(currentIndex - 1);
    }

    prevBtn.addEventListener('click', prevSlide);
    nextBtn.addEventListener('click', nextSlide);
    closeBtn.addEventListener('click', destroyPresenter);
    fullscreenBtn.addEventListener('click', toggleFullscreen);

    function onKeyDown(e) {
      if (!presenterActive) return;
      switch (e.key) {
        case 'ArrowRight': case ' ': case 'PageDown':
          e.preventDefault(); nextSlide(); break;
        case 'ArrowLeft': case 'PageUp':
          e.preventDefault(); prevSlide(); break;
        case 'Home':
          e.preventDefault(); showSlide(0); break;
        case 'End':
          e.preventDefault(); showSlide(slides.length - 1); break;
        case 'Escape':
          e.preventDefault(); destroyPresenter(); break;
        case 'f': case 'F':
          e.preventDefault(); toggleFullscreen(); break;
      }
    }

    let touchStartX = 0, touchStartY = 0;
    function onTouchStart(e) {
      touchStartX = e.touches[0].clientX;
      touchStartY = e.touches[0].clientY;
    }
    function onTouchEnd(e) {
      const dx = e.changedTouches[0].clientX - touchStartX;
      const dy = e.changedTouches[0].clientY - touchStartY;
      if (Math.abs(dx) > Math.abs(dy) && Math.abs(dx) > 50) {
        dx < 0 ? nextSlide() : prevSlide();
      }
    }

    document.addEventListener('keydown', onKeyDown);
    presenterOverlay.addEventListener('touchstart', onTouchStart, { passive: true });
    presenterOverlay.addEventListener('touchend', onTouchEnd, { passive: true });
    presenterOverlay._cleanup = () => {
      document.removeEventListener('keydown', onKeyDown);
      presenterOverlay.removeEventListener('touchstart', onTouchStart);
      presenterOverlay.removeEventListener('touchend', onTouchEnd);
    };

    showSlide(0);
  }

  function toggleFullscreen() {
    if (!document.fullscreenElement) presenterOverlay?.requestFullscreen?.();
    else document.exitFullscreen?.();
  }

  function destroyPresenter() {
    if (presenterOverlay) {
      presenterOverlay._cleanup?.();
      presenterOverlay.remove();
      presenterOverlay = null;
    }
    presenterActive = false;
    if (document.fullscreenElement) document.exitFullscreen?.();
  }
})();
