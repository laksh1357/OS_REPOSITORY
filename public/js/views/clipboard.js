/* Warden View Module - Clipboard Actions */

export function initClipboard() {
  document.querySelectorAll(".copy-trigger").forEach(btn => {
    btn.addEventListener("click", () => {
      const targetId = btn.dataset.copyTarget;
      let textToCopy = "";
      if (targetId) {
        const el = document.getElementById(targetId);
        textToCopy = el ? el.textContent || el.value : "";
      } else if (btn.dataset.copyText) {
        textToCopy = btn.dataset.copyText;
      }

      if (textToCopy) {
        navigator.clipboard.writeText(textToCopy);
        const originalText = btn.textContent;
        btn.textContent = "✓ Copied";
        setTimeout(() => {
          btn.textContent = originalText;
        }, 1500);
      }
    });
  });
}
