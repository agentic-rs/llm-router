import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";

import { parseTaggedArgs, requireValue } from "./args";
import { ensureImage, namesForTag, resourceExists } from "./containers";
import { agentImage, container, defaultTag, engine, repoRoot, runAttached } from "./runtime";

const agents = new Set(["codex", "opencode", "pi"]);
const transports = new Set(["api", "proxy"]);

type ParsedAgentArgs = {
  agent: string;
  forwarded: string[];
  no_tty: boolean;
  proxy_listener?: string;
  tag: string;
  transport: string;
};

type ProxyContext = {
  cleanup_dir?: string;
  container_args: string[];
  environment_args: string[];
};

export async function agent(args: string[]): Promise<void> {
  const parsed = parseAgentArgs(args);
  const names = namesForTag(parsed.tag);
  ensureImage(agentImage, "run `bun --cwd scripts docker build-agent` first");
  if (!resourceExists("container", names.gatewayContainer)) {
    throw new Error(`gateway is not running; run \`bun --cwd scripts docker up --tag ${parsed.tag}\` first`);
  }
  const interactive = !parsed.no_tty && process.stdin.isTTY === true && process.stdout.isTTY === true;
  const proxy =
    parsed.transport === "proxy"
      ? prepareProxyContext(names.gatewayContainer, parsed.proxy_listener)
      : emptyProxyContext();
  try {
    await runAttached(
      engine,
      [
        "run",
        "--rm",
        "--sig-proxy=true",
        ...(interactive ? ["--interactive", "--tty"] : []),
        "--network",
        `container:${names.gatewayContainer}`,
        "-e",
        `TOKN_AGENT=${parsed.agent}`,
        "-e",
        `TOKN_TRANSPORT=${parsed.transport}`,
        "-e",
        `TOKN_GATEWAY_API_URL=${process.env.TOKN_GATEWAY_API_URL ?? "http://127.0.0.1:4141"}`,
        ...proxy.environment_args,
        ...proxy.container_args,
        "-v",
        `${repoRoot}:/workspace`,
        "-w",
        "/workspace",
        agentImage,
        ...parsed.forwarded,
      ],
      { stdin: interactive ? "inherit" : "ignore" },
    );
  } finally {
    if (proxy.cleanup_dir !== undefined) {
      rmSync(proxy.cleanup_dir, { force: true, recursive: true });
    }
  }
}

function emptyProxyContext(): ProxyContext {
  return { container_args: [], environment_args: [] };
}

function prepareProxyContext(gateway_container: string, listener: string | undefined): ProxyContext {
  const helperArgs = ["exec", gateway_container, "tokn-gateway", "proxy"];
  if (listener !== undefined) {
    helperArgs.push("--listener", listener);
  }
  helperArgs.push("env", "--format", "json");
  const output = container(helperArgs, { capture: true });
  const proxyEnvironment = parseProxyEnvironment(output);
  const proxy_url = proxyEnvironment.HTTPS_PROXY;
  if (proxy_url === undefined || proxy_url.length === 0) {
    throw new Error("gateway proxy helper did not emit HTTPS_PROXY");
  }

  const environment_args = ["-e", `TOKN_GATEWAY_PROXY_URL=${proxy_url}`];
  if (proxyEnvironment.NO_PROXY !== undefined) {
    environment_args.push("-e", `NO_PROXY=${proxyEnvironment.NO_PROXY}`);
  }
  const ca_cert_path = proxyEnvironment.NODE_EXTRA_CA_CERTS;
  if (ca_cert_path === undefined) {
    return { container_args: [], environment_args };
  }
  if (!ca_cert_path.startsWith("/") || ca_cert_path.includes("\0")) {
    throw new Error(`gateway proxy helper emitted an invalid CA path: ${JSON.stringify(ca_cert_path)}`);
  }

  const scratchRoot = join(repoRoot, "tmp");
  mkdirSync(scratchRoot, { recursive: true });
  const cleanup_dir = mkdtempSync(join(scratchRoot, "docker-agent-ca-"));
  const localCa = join(cleanup_dir, "ca.crt");
  try {
    container(["cp", `${gateway_container}:${ca_cert_path}`, localCa]);
  } catch (error) {
    rmSync(cleanup_dir, { force: true, recursive: true });
    throw error;
  }

  environment_args.push("-e", "TOKN_GATEWAY_CA_CERT=/run/tokn-ca/ca.crt");
  return {
    cleanup_dir,
    container_args: ["-v", `${localCa}:/run/tokn-ca/ca.crt:ro`],
    environment_args,
  };
}

function parseProxyEnvironment(output: string): Record<string, string> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(output);
  } catch (error) {
    throw new Error("gateway proxy helper emitted invalid JSON", { cause: error });
  }
  if (parsed === null || Array.isArray(parsed) || typeof parsed !== "object") {
    throw new Error("gateway proxy helper JSON must be an object");
  }
  const environment: Record<string, string> = {};
  for (const [name, value] of Object.entries(parsed)) {
    if (typeof value !== "string") {
      throw new Error(`gateway proxy helper JSON value ${JSON.stringify(name)} must be a string`);
    }
    environment[name] = value;
  }
  return environment;
}

function parseAgentArgs(args: string[]): ParsedAgentArgs {
  const rawForwardedAt = args.indexOf("--");
  const rawOptionArgs = rawForwardedAt >= 0 ? args.slice(0, rawForwardedAt) : args;
  const tagged = parseTaggedArgs(rawOptionArgs, defaultTag);
  let agent = process.env.TOKN_AGENT ?? "codex";
  let transport = process.env.TOKN_TRANSPORT ?? "api";
  let no_tty = false;
  let proxy_listener = process.env.TOKN_PROXY_LISTENER;
  const optionArgs = tagged.rest;
  const forwarded = rawForwardedAt >= 0 ? args.slice(rawForwardedAt + 1) : [];

  for (let i = 0; i < optionArgs.length; i += 1) {
    const arg = optionArgs[i];
    if (arg === "--agent") {
      agent = requireValue(optionArgs, i, "--agent");
      i += 1;
    } else if (arg.startsWith("--agent=")) {
      agent = arg.slice("--agent=".length);
    } else if (arg === "--transport") {
      transport = requireValue(optionArgs, i, "--transport");
      i += 1;
    } else if (arg.startsWith("--transport=")) {
      transport = arg.slice("--transport=".length);
    } else if (arg === "--listener") {
      proxy_listener = requireValue(optionArgs, i, "--listener");
      i += 1;
    } else if (arg.startsWith("--listener=")) {
      proxy_listener = arg.slice("--listener=".length);
    } else if (arg === "--no-tty") {
      no_tty = true;
    } else {
      throw new Error(`unknown agent option: ${arg}`);
    }
  }

  if (!agents.has(agent)) {
    throw new Error(`unsupported agent '${agent}' (expected codex, opencode, or pi)`);
  }
  if (!transports.has(transport)) {
    throw new Error(`unsupported transport '${transport}' (expected api or proxy)`);
  }
  if (transport !== "proxy" && proxy_listener !== undefined) {
    throw new Error("--listener is valid only with --transport proxy");
  }
  return { agent, forwarded, no_tty, proxy_listener, tag: tagged.tag, transport };
}
