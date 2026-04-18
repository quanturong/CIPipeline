/**
 * [NT230 PoC] Mini GitLab Runner Simulator
 *
 * Đọc .gitlab-ci.yml, parse stages + jobs, chạy đúng thứ tự.
 * Output giống format GitLab Runner thật:
 *   - Job header: "Running with gitlab-runner ..."
 *   - Stage grouping: "Executing 'stage_name' stage"
 *   - Script lines echo trước khi chạy: "$ command"
 *   - Exit code + duration + job status
 *   - Predefined CI variables: CI_PIPELINE_ID, CI_COMMIT_SHA, CI_JOB_ID...
 *
 * Usage:
 *   node ci/gitlab-runner-sim.js [path-to-gitlab-ci.yml]
 *   (default: .gitlab-ci.compromised.yml)
 *
 * Hỗ trợ:
 *   - stages: [...] ordering
 *   - variables: key: value
 *   - job.stage, job.image, job.script
 *   - job.artifacts.paths (copy files)
 *   - job.dependencies (artifact nhận từ job khác)
 */

"use strict";

const fs = require("fs");
const path = require("path");
const { execSync } = require("child_process");

// ─── Simple YAML parser (đủ cho gitlab-ci.yml structure) ──────────────────

/**
 * Parse gitlab-ci.yml — hỗ trợ:
 *   scalar values, arrays (- item), nested keys, comments (#)
 * Không dùng external dependency.
 */
function parseGitlabCIYaml(content) {
  const lines = content.split("\n");
  const result = { _stages: [], _variables: {}, _jobs: {} };

  let currentTopKey = null;   // top-level key: "stages", "variables", hoặc job name
  let currentSubKey = null;   // sub-key: "stage", "script", "image", "artifacts", "dependencies"
  let currentSubSub = null;   // sub-sub-key: artifacts.paths
  let isListMode = false;
  let listTarget = null;

  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    // Strip inline comments (but not # inside quotes)
    const trimmed = raw.replace(/\s+#[^"']*$/, "").replace(/^#.*$/, "").trimEnd();
    if (!trimmed || /^\s*$/.test(trimmed)) continue;

    // Skip comment-only lines (lines where first non-space is #)
    if (/^\s*#/.test(raw)) continue;

    const indent = raw.search(/\S/);

    // Top-level key (indent 0)
    if (indent === 0 && trimmed.endsWith(":")) {
      currentTopKey = trimmed.slice(0, -1).trim();
      currentSubKey = null;
      currentSubSub = null;
      isListMode = false;

      if (currentTopKey === "stages") {
        isListMode = true;
        listTarget = "_stages";
      } else if (currentTopKey === "variables") {
        // next lines will be key: value
      } else {
        // It's a job name
        result._jobs[currentTopKey] = {
          name: currentTopKey,
          stage: "build", // default
          image: null,
          script: [],
          artifacts: { paths: [] },
          dependencies: [],
          variables: {},
        };
      }
      continue;
    }

    // List item under stages:
    if (isListMode && listTarget === "_stages" && /^\s+-\s*/.test(trimmed)) {
      const val = trimmed.replace(/^\s*-\s*/, "").trim();
      if (val) result._stages.push(val);
      continue;
    }

    // Variables: key: value (indent 2)
    if (currentTopKey === "variables" && indent >= 2 && !currentSubKey) {
      const m = trimmed.match(/^\s*(\w+)\s*:\s*(.+)$/);
      if (m) {
        result._variables[m[1]] = m[2].replace(/^["']|["']$/g, "");
      }
      continue;
    }

    // Inside a job definition
    if (result._jobs[currentTopKey]) {
      const job = result._jobs[currentTopKey];

      // Sub-key (indent 2): stage, image, script, artifacts, dependencies
      if (indent === 2 && trimmed.includes(":")) {
        const m = trimmed.match(/^\s*(\w+)\s*:\s*(.*)$/);
        if (m) {
          const key = m[1];
          const val = m[2].trim();
          currentSubKey = key;
          currentSubSub = null;

          if (key === "stage") job.stage = val;
          else if (key === "image") job.image = val;
          else if (key === "script") { /* list follows */ }
          else if (key === "artifacts") { /* sub-keys follow */ }
          else if (key === "dependencies") { /* list follows */ }
        }
        continue;
      }

      // Sub-sub-key (indent 4): artifacts.paths
      if (indent === 4 && currentSubKey === "artifacts" && trimmed.includes(":")) {
        const m = trimmed.match(/^\s*(\w+)\s*:\s*(.*)$/);
        if (m && m[1] === "paths") {
          currentSubSub = "artifacts_paths";
        }
        continue;
      }

      // List items
      if (/^\s+-\s+/.test(raw) || /^\s+-\s*/.test(raw)) {
        const val = trimmed.replace(/^\s*-\s*/, "").trim();
        if (currentSubSub === "artifacts_paths") {
          job.artifacts.paths.push(val);
        } else if (currentSubKey === "script") {
          job.script.push(val);
        } else if (currentSubKey === "dependencies") {
          job.dependencies.push(val);
        }
        continue;
      }
    }
  }

  return result;
}

// ─── Runner output formatting ─────────────────────────────────────────────

const C = {
  reset:  "\x1b[0m",
  bold:   "\x1b[1m",
  dim:    "\x1b[2m",
  green:  "\x1b[32m",
  cyan:   "\x1b[36m",
  yellow: "\x1b[33m",
  red:    "\x1b[31m",
  gray:   "\x1b[90m",
  magenta:"\x1b[35m",
};

function now() {
  return new Date().toISOString().replace("T", " ").replace(/\.\d+Z$/, "Z");
}

function runnerLog(msg) {
  console.log(`${C.cyan}${msg}${C.reset}`);
}

function section(title) {
  console.log(`\n${C.bold}${C.cyan}${"─".repeat(60)}${C.reset}`);
  console.log(`${C.bold}${C.cyan}  ${title}${C.reset}`);
  console.log(`${C.bold}${C.cyan}${"─".repeat(60)}${C.reset}`);
}

// ─── Main ─────────────────────────────────────────────────────────────────

function main() {
  const projectRoot = path.resolve(__dirname, "..");
  const ciFile = process.argv[2]
    || path.join(projectRoot, ".gitlab-ci.compromised.yml");

  if (!fs.existsSync(ciFile)) {
    console.error(`CI config not found: ${ciFile}`);
    process.exit(1);
  }

  const content = fs.readFileSync(ciFile, "utf8");
  const ci = parseGitlabCIYaml(content);
  const stages = ci._stages.length > 0 ? ci._stages : ["build"];

  // ── Runner header (giống format GitLab Runner thật) ──
  const pipelineId = Math.floor(100000 + Math.random() * 900000);
  const commitSha = require("crypto").randomBytes(20).toString("hex");
  const shortSha = commitSha.substring(0, 8);

  console.log(`${C.bold}Running with gitlab-runner-sim 1.0.0 (NT230 PoC)${C.reset}`);
  console.log(`  on local-shell-executor ${C.dim}(simulated)${C.reset}`);
  console.log(`${C.gray}Using Shell executor...${C.reset}`);
  console.log("");

  // ── Set CI predefined variables ──
  const predefined = {
    CI: "true",
    CI_PIPELINE_ID: String(pipelineId),
    CI_PIPELINE_SOURCE: "push",
    CI_COMMIT_SHA: commitSha,
    CI_COMMIT_SHORT_SHA: shortSha,
    CI_COMMIT_BRANCH: "main",
    CI_PROJECT_PATH: "nt230-demo/supply-chain-victim",
    CI_PROJECT_NAME: "supply-chain-victim",
    CI_SERVER_URL: "https://gitlab.example.com",
    CI_SERVER_NAME: "GitLab",
    CI_RUNNER_DESCRIPTION: "local-shell-executor",
    GITLAB_CI: "true",
  };

  // Merge with YAML variables (with local overrides for hostnames)
  // In real GitLab CI, "verdaccio" resolves via Docker DNS.
  // Locally, we map it to localhost.
  const localOverrides = {};
  if (ci._variables.NPM_REGISTRY) {
    localOverrides.NPM_REGISTRY = ci._variables.NPM_REGISTRY
      .replace("verdaccio:", "localhost:");
  }
  const allVars = { ...predefined, ...ci._variables, ...localOverrides };

  // Set to process.env so child commands inherit them
  for (const [k, v] of Object.entries(allVars)) {
    process.env[k] = v;
  }

  // Set fake secret tokens (CI runner normally injects these)
  const secrets = {
    CI_JOB_TOKEN: "glpat-FAKE-CI-TOKEN-xxxxxxxxxxxx",
    GITHUB_TOKEN: "ghp_FAKE_GITHUB_TOKEN_xxxxxxxxxxxxxxxxxxxx",
    AWS_SECRET_ACCESS_KEY: "FAKE+AWS+SECRET+KEY/xxxxxxxxxxxxxxxxxx",
    NPM_TOKEN: "npm_FAKE_PUBLISH_TOKEN_xxxxxxxxxxxxxxx",
    DEPLOY_KEY: "-----BEGIN RSA PRIVATE KEY----- FAKE_KEY -----END RSA PRIVATE KEY-----",
  };
  for (const [k, v] of Object.entries(secrets)) {
    process.env[k] = v;
  }

  runnerLog(`Pipeline #${pipelineId} for commit ${shortSha} on branch main`);
  runnerLog(`CI config: ${path.basename(ciFile)}`);
  runnerLog(`Stages: ${stages.join(" → ")}`);
  runnerLog(`Jobs: ${Object.keys(ci._jobs).join(", ")}`);
  console.log("");

  // ── Clean real secrets from inherited env ──
  const sensitivePatterns = ["API_KEY", "SECRET", "TOKEN", "PASSWORD", "CREDENTIAL", "PRIVATE_KEY"];
  for (const key of Object.keys(process.env)) {
    if (sensitivePatterns.some(p => key.includes(p)) && !secrets[key] && !predefined[key] && key !== "CI_JOB_TOKEN") {
      delete process.env[key];
    }
  }

  // ── Execute jobs by stage order ──
  let jobIndex = 0;
  const totalJobs = Object.keys(ci._jobs).length;
  const jobResults = {};

  for (const stageName of stages) {
    // Find jobs for this stage
    const stageJobs = Object.values(ci._jobs).filter(j => j.stage === stageName);
    if (stageJobs.length === 0) continue;

    section(`Executing "${stageName}" stage`);

    for (const job of stageJobs) {
      jobIndex++;
      const jobId = 100000 + jobIndex;
      process.env.CI_JOB_ID = String(jobId);
      process.env.CI_JOB_NAME = job.name;
      process.env.CI_JOB_STAGE = job.stage;

      console.log(`\n${C.bold}Job #${jobId}: ${job.name}${C.reset} ${C.dim}(${jobIndex}/${totalJobs})${C.reset}`);
      if (job.image) {
        console.log(`${C.gray}  Using Docker image: ${job.image}${C.reset}`);
      }
      console.log(`${C.gray}  Started at ${now()}${C.reset}`);

      const startTime = Date.now();
      let success = true;

      for (const scriptLine of job.script) {
        // Resolve YAML variables ($VARIABLE)
        let resolved = scriptLine;
        for (const [k, v] of Object.entries(allVars)) {
          resolved = resolved.replace(new RegExp("\\$" + k + "\\b", "g"), v);
        }

        // Echo the command (like real runner)
        console.log(`${C.green}$ ${resolved}${C.reset}`);

        try {
          // Determine what to execute
          if (resolved.startsWith("echo ")) {
            // echo commands: just print
            const msg = resolved.replace(/^echo\s+/, "").replace(/^["']|["']$/g, "");
            console.log(msg);
          } else if (resolved.startsWith("npm ")) {
            // npm commands
            const output = execSync(resolved, {
              cwd: path.join(projectRoot, "consumer-app"),
              encoding: "utf8",
              stdio: "pipe",
              timeout: 60000,
              env: process.env,
            });
            if (output.trim()) {
              for (const line of output.trim().split("\n")) {
                console.log(`${C.gray}  ${line}${C.reset}`);
              }
            }
          } else if (resolved.startsWith("node ")) {
            // node commands
            const output = execSync(resolved, {
              cwd: projectRoot,
              encoding: "utf8",
              stdio: "pipe",
              timeout: 30000,
              env: process.env,
            });
            if (output.trim()) {
              for (const line of output.trim().split("\n")) {
                console.log(`${C.gray}  ${line}${C.reset}`);
              }
            }
          } else {
            console.log(`${C.dim}  (simulated: ${resolved})${C.reset}`);
          }
        } catch (err) {
          console.log(`${C.red}  ERROR: ${err.message.split("\n")[0]}${C.reset}`);
          success = false;
        }
      }

      const duration = ((Date.now() - startTime) / 1000).toFixed(1);

      if (success) {
        console.log(`\n${C.green}Job succeeded${C.reset} ${C.dim}(duration: ${duration}s)${C.reset}`);
      } else {
        console.log(`\n${C.red}Job failed${C.reset} ${C.dim}(duration: ${duration}s)${C.reset}`);
      }

      jobResults[job.name] = { success, duration };
    }
  }

  // ── Pipeline summary ──
  console.log(`\n${"═".repeat(60)}`);
  const allPassed = Object.values(jobResults).every(r => r.success);
  const statusColor = allPassed ? C.green : C.red;
  const statusText = allPassed ? "passed" : "failed";

  console.log(`${C.bold}Pipeline #${pipelineId} ${statusColor}${statusText}${C.reset}`);
  console.log(`${C.gray}Commit: ${shortSha} | Branch: main${C.reset}`);
  console.log("");
  for (const [name, r] of Object.entries(jobResults)) {
    const icon = r.success ? `${C.green}✓${C.reset}` : `${C.red}✗${C.reset}`;
    console.log(`  ${icon} ${name} ${C.dim}(${r.duration}s)${C.reset}`);
  }
  console.log(`${"═".repeat(60)}`);

  if (allPassed) {
    console.log(`\n${C.yellow}⚠ Pipeline reported SUCCESS — but secrets were exfiltrated during npm install.${C.reset}`);
    console.log(`${C.yellow}  This is the core danger of supply chain attacks: NO VISIBLE CI FAILURE.${C.reset}`);
  }

  // ── Cleanup ──
  for (const k of [...Object.keys(secrets), ...Object.keys(predefined)]) {
    delete process.env[k];
  }
}

main();
