/* Warden View Module - Policy Builder UI */

import { PolicyBuilder } from '../policy-builder.js';

export function initPolicy() {
  const policy = new PolicyBuilder();
  const yamlOutput = document.getElementById("code-output-area");
  const cpuSlider = document.getElementById("slider-cpu");
  const cpuVal = document.getElementById("val-cpu");
  const memSlider = document.getElementById("slider-mem");
  const memVal = document.getElementById("val-mem");
  const pidSlider = document.getElementById("slider-pid");
  const pidVal = document.getElementById("val-pid");
  const domainInput = document.getElementById("input-domain");
  const addDomainBtn = document.getElementById("btn-add-domain");
  const chipsContainer = document.getElementById("domain-chips-container");

  let activeCodeTab = "yaml";

  const renderPolicyOutput = () => {
    if (!yamlOutput) return;
    if (activeCodeTab === "yaml") {
      yamlOutput.textContent = policy.generateYAML();
    } else if (activeCodeTab === "sql") {
      yamlOutput.textContent = policy.generateSQL();
    } else if (activeCodeTab === "python") {
      yamlOutput.textContent = policy.generatePythonSDK();
    } else if (activeCodeTab === "go") {
      yamlOutput.textContent = policy.generateGoSDK();
    } else if (activeCodeTab === "curl") {
      yamlOutput.textContent = policy.generateCurl();
    }
  };

  const renderDomainChips = () => {
    if (!chipsContainer) return;
    chipsContainer.innerHTML = "";

    policy.state.egressDomains.forEach(domain => {
      const chip = document.createElement("span");
      chip.className = "chip";
      
      const domainLabel = document.createTextNode(domain + " ");
      chip.appendChild(domainLabel);

      const removeBtn = document.createElement("button");
      removeBtn.setAttribute("aria-label", `Remove domain ${domain}`);
      removeBtn.textContent = "×";
      removeBtn.addEventListener("click", () => {
        policy.removeDomain(domain);
        renderDomainChips();
        renderPolicyOutput();
      });

      chip.appendChild(removeBtn);
      chipsContainer.appendChild(chip);
    });
  };

  if (cpuSlider) {
    cpuSlider.addEventListener("input", (e) => {
      const val = e.target.value;
      if (cpuVal) cpuVal.textContent = `${val} Cores`;
      policy.update("cpu", val);
      renderPolicyOutput();
    });
  }

  if (memSlider) {
    memSlider.addEventListener("input", (e) => {
      const val = e.target.value;
      if (memVal) memVal.textContent = `${val} MiB`;
      policy.update("memory", parseInt(val, 10));
      renderPolicyOutput();
    });
  }

  if (pidSlider) {
    pidSlider.addEventListener("input", (e) => {
      const val = e.target.value;
      if (pidVal) pidVal.textContent = val;
      policy.update("pids", parseInt(val, 10));
      renderPolicyOutput();
    });
  }

  if (addDomainBtn && domainInput) {
    const handleAdd = () => {
      const val = domainInput.value.trim();
      if (val) {
        policy.addDomain(val);
        domainInput.value = "";
        renderDomainChips();
        renderPolicyOutput();
      }
    };
    addDomainBtn.addEventListener("click", handleAdd);
    domainInput.addEventListener("keypress", (e) => {
      if (e.key === "Enter") {
        e.preventDefault();
        handleAdd();
      }
    });
  }

  // Code Tab switching
  document.querySelectorAll(".code-tab").forEach(tab => {
    tab.addEventListener("click", () => {
      document.querySelectorAll(".code-tab").forEach(t => t.classList.remove("active"));
      tab.classList.add("active");
      activeCodeTab = tab.dataset.lang;
      renderPolicyOutput();
    });
  });

  renderDomainChips();
  renderPolicyOutput();

  return policy;
}
