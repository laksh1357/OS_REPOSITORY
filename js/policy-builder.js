/* Warden Interactive Policy Builder & Code Exporter */

export class PolicyBuilder {
  constructor(config = {}) {
    this.state = {
      runtime: config.runtime || "microvm",
      cpu: config.cpu || "0.5",
      memory: config.memory || 256,
      pids: config.pids || 8,
      timeout: config.timeout || 30,
      rootFs: config.rootFs || "read-only",
      writableDirs: config.writableDirs || ["/tmp"],
      egressDomains: config.egressDomains || ["pypi.org", "files.pythonhosted.org", "api.openai.com"],
      syscallProfile: config.syscallProfile || "python-minimal"
    };
  }

  update(key, value) {
    this.state[key] = value;
  }

  addDomain(domain) {
    const trimmed = domain.trim().toLowerCase();
    if (trimmed && !this.state.egressDomains.includes(trimmed)) {
      this.state.egressDomains.push(trimmed);
    }
  }

  removeDomain(domain) {
    this.state.egressDomains = this.state.egressDomains.filter(d => d !== domain);
  }

  generateYAML() {
    const domainsStr = this.state.egressDomains.length > 0 
      ? this.state.egressDomains.map(d => `    - "${d}"`).join("\n")
      : "    # No outbound network access allowed";

    const writableStr = this.state.writableDirs.map(w => `"${w}"`).join(", ");

    return `# Warden Isolation Policy Definition
# Auto-generated via Interactive Warden Policy Builder

version: "v1alpha1"
name: "agent-task-sandbox"

runtime: ${this.state.runtime}
timeout: "${this.state.timeout}s"

resources:
  cpu: "${this.state.cpu}"
  memory: "${this.state.memory}Mi"
  processes: ${this.state.pids}

filesystem:
  root: ${this.state.rootFs}
  writable: [${writableStr}]

network:
  default: deny
  allow:
${domainsStr}

syscalls:
  profile: "${this.state.syscallProfile}"
  default_action: ERRNO
  audit_logging: true`;
  }

  generatePythonSDK() {
    const domains = JSON.stringify(this.state.egressDomains);
    return `from warden import Sandbox, Policy, PolicyViolationError

# Configure Warden Isolation Policy
policy = Policy(
    runtime="${this.state.runtime}",
    cpu_limit=${this.state.cpu},
    memory_limit_mb=${this.state.memory},
    max_processes=${this.state.pids},
    root_readonly=True,
    writable_paths=${JSON.stringify(this.state.writableDirs)},
    network_allowlist=${domains},
    syscall_profile="${this.state.syscallProfile}"
)

# Safely execute un-trusted AI generated code
code_snippet = agent.generate_code()

try:
    with Sandbox(policy=policy) as box:
        result = box.exec(["python3", "-c", code_snippet], timeout=${this.state.timeout})
        print("Sandbox STDOUT:", result.stdout)
except PolicyViolationError as err:
    print(f"[WARDEN CONTAINMENT] Execution blocked: {err}")
    print("Violation logs:", err.violations)`;
  }

  generateGoSDK() {
    return `package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/warden-dev/warden-go/warden"
)

func main() {
	pol := warden.NewPolicyBuilder().
		SetRuntime("${this.state.runtime}").
		SetCPU("${this.state.cpu}").
		SetMemoryMB(${this.state.memory}).
		SetMaxPIDs(${this.state.pids}).
		SetRootReadOnly(true).
		AllowEgress(${this.state.egressDomains.map(d => `"${d}"`).join(", ")}).
		SetSyscallProfile("${this.state.syscallProfile}").
		Build()

	ctx, cancel := context.WithTimeout(context.Background(), ${this.state.timeout}*time.Second)
	defer cancel()

	res, err := warden.RunSnippet(ctx, pol, "python3", "-c", codeSnippet)
	if err != nil {
		log.Fatalf("Sandbox security block: %v", err)
	}

	fmt.Printf("Sandbox Output: %s\\n", res.Stdout)
}`;
  }

  generateCurl() {
    const payload = {
      image: "python:3.12-slim",
      policy: {
        runtime: this.state.runtime,
        limits: {
          cpu: parseFloat(this.state.cpu),
          memory_mb: this.state.memory,
          pids: this.state.pids
        },
        network: {
          allowlist: this.state.egressDomains
        }
      },
      cmd: "python3 -c \"print('Hello from contained microvm')\""
    };

    return `curl -X POST https://api.warden.dev/v1/sandbox/run \\
  -H "Authorization: Bearer $WARDEN_API_KEY" \\
  -H "Content-Type: application/json" \\
  -d '${JSON.stringify(payload, null, 2)}'`;
  }
}
