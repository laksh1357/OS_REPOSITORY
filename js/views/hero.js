/* Warden View Module - Hero Live Demo Terminal */

import { SandboxEngine, PRESET_SNIPPETS } from '../sandbox-engine.js';

export function initHero() {
  const heroConsole = document.getElementById("hero-terminal");
  const heroStatus = document.getElementById("hero-status");

  if (heroConsole && heroStatus) {
    const heroEngine = new SandboxEngine(heroConsole, heroStatus, null);
    // Auto-run initial demo
    heroEngine.execute(PRESET_SNIPPETS.exfiltration.code, true);

    const replayBtn = document.getElementById("replay-hero-btn");
    if (replayBtn) {
      replayBtn.addEventListener("click", () => {
        heroEngine.execute(PRESET_SNIPPETS.exfiltration.code, true);
      });
    }
  }
}
