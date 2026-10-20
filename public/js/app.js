/* Warden Main Application Orchestrator */

import { initHero } from './views/hero.js';
import { initPlayground } from './views/playground.js';
import { initArchitecture } from './views/architecture.js';
import { initPolicy } from './views/policy.js';
import { initClipboard } from './views/clipboard.js';
import { renderAttackMatrix } from './attack-matrix.js';
import { AuditFeed } from './audit-feed.js';

document.addEventListener("DOMContentLoaded", () => {
  // 1. Initialize Navbar Scroll Behavior
  const navbar = document.getElementById("navbar");
  if (navbar) {
    window.addEventListener("scroll", () => {
      if (window.scrollY > 20) {
        navbar.classList.add("scrolled");
      } else {
        navbar.classList.remove("scrolled");
      }
    });
  }

  // 2. Initialize Audit Feed Stream Component
  const auditBodyEl = document.getElementById("audit-feed-body");
  const auditFeed = auditBodyEl ? new AuditFeed(auditBodyEl) : null;
  if (auditFeed) {
    auditFeed.init();
  }

  // 3. Initialize Hero Live Demo Terminal
  initHero();

  // 4. Initialize Interactive Sandbox Playground
  initPlayground(auditFeed);

  // 5. Initialize Architecture Inspector (5 Layers)
  initArchitecture();

  // 6. Initialize Policy Builder
  initPolicy();

  // 7. Initialize Attack Matrix
  const attackMatrixEl = document.getElementById("attack-matrix-container");
  if (attackMatrixEl) {
    renderAttackMatrix(attackMatrixEl);
  }

  // 8. Clipboard Copy Actions
  initClipboard();
});
