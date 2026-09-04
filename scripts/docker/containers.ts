import { join, resolve } from "node:path";

import { parseTaggedArgs, requirePort, requireValue, UsageError } from "./args";
import {
  agentImage,
  container,
  containerOk,
  defaultTag,
  gatewayImageRepo,
  scriptDir,
} from "./runtime";

export type ContainerNames = {
  gatewayImage: string;
  gatewayContainer: string;
  networkName: string;
  projectName: string;
  routerStateVolume: string;
};

type UpArgs = {
  copyLocal: "none" | "config" | "accounts";
  forceCopyLocal: boolean;
  tag: string;
  port?: number;
  proxyPort?: number;
};

export function resourceExists(kind: "container" | "image" | "network" | "volume", name: string): boolean {
  return containerOk([kind, "inspect", name]);
}

export function namesForTag(tag: string): ContainerNames {
  const projectName = `tokn-router-${tag}`;
  return {
    gatewayImage: `${gatewayImageRepo}:${tag}`,
    gatewayContainer: `${projectName}-gateway`,
    networkName: `${projectName}-net`,
    projectName,
    routerStateVolume: `${projectName}-router-state`,
  };
}

export function ensureNetwork(names: ContainerNames): void {
  if (!resourceExists("network", names.networkName)) {
    container(["network", "create", names.networkName]);
  }
}

export function ensureImage(image: string, hint: string): void {
  if (!resourceExists("image", image)) {
    throw new Error(`${image} is not available; ${hint}`);
  }
}

function localRouterHome(): string {
  const home = process.env.HOME;
  if (!home) {
    throw new Error("HOME is not set; cannot resolve local ~/.tokn/router");
  }
  return join(home, ".tokn", "router");
}

function parseUpArgs(args: string[]): UpArgs {
  const tagged = parseTaggedArgs(args, defaultTag);
  let copyLocal: UpArgs["copyLocal"] = "none";
  let forceCopyLocal = false;
  let port: number | undefined;
  let proxyPort: number | undefined;
  for (let i = 0; i < tagged.rest.length; i += 1) {
    const arg = tagged.rest[i];
    if (arg === "--port") {
      port = requirePort(requireValue(tagged.rest, i, "--port"), "--port");
      i += 1;
    } else if (arg.startsWith("--port=")) {
      port = requirePort(arg.slice("--port=".length), "--port");
    } else if (arg === "--proxy-port") {
      proxyPort = requirePort(requireValue(tagged.rest, i, "--proxy-port"), "--proxy-port");
      i += 1;
    } else if (arg.startsWith("--proxy-port=")) {
      proxyPort = requirePort(arg.slice("--proxy-port=".length), "--proxy-port");
    } else if (arg === "--copy-local-config") {
      if (copyLocal !== "none") {
        throw new Error("--copy-local-config and --copy-local-accounts are mutually exclusive");
      }
      copyLocal = "config";
    } else if (arg === "--copy-local-accounts") {
      if (copyLocal !== "none") {
        throw new Error("--copy-local-config and --copy-local-accounts are mutually exclusive");
      }
      copyLocal = "accounts";
    } else if (arg === "--force-copy-local") {
      forceCopyLocal = true;
    } else {
      throw new Error(`unknown up option: ${arg}`);
    }
  }
  if (forceCopyLocal && copyLocal === "none") {
    throw new Error("--force-copy-local requires --copy-local-config or --copy-local-accounts");
  }
  return { copyLocal, forceCopyLocal, tag: tagged.tag, port, proxyPort };
}

function copyLocalRouterFiles(names: ContainerNames, parsed: UpArgs): void {
  if (parsed.copyLocal === "none") {
    return;
  }
  const localHome = localRouterHome();
  const files = parsed.copyLocal === "config" ? ["config.toml", "auth.yaml"] : ["auth.yaml"];
  const script = [
    "set -eu",
    "copied=0",
    ...files.flatMap((file) => [
      `if [ -f /src/${file} ]; then`,
      `  if [ -e /dst/${file} ] && [ "${parsed.forceCopyLocal ? "1" : "0"}" != "1" ]; then`,
      `    echo 'tokn-copy: target already exists: /dst/${file}' >&2`,
      "    echo 'tokn-copy: rerun with --force-copy-local to overwrite selected files' >&2",
      "    exit 1",
      "  fi",
      `  cp "/src/${file}" "/dst/${file}"`,
      "  copied=$((copied + 1))",
      `  echo 'tokn-copy: copied ${file}'`,
      "else",
      `  echo 'tokn-copy: skipped missing ${file}'`,
      "fi",
    ]),
    "if [ \"$copied\" -eq 0 ]; then",
    "  echo 'tokn-copy: no selected local files were found' >&2",
    "  exit 1",
    "fi",
  ].join("\n");

  container([
    "run",
    "--rm",
    "-v",
    `${localHome}:/src:ro`,
    "-v",
    `${names.routerStateVolume}:/dst`,
    "--entrypoint",
    "sh",
    names.gatewayImage,
    "-c",
    script,
  ]);
}

function loadHintForTag(tag: string): string {
  if (/^pr-[1-9][0-9]*$/.test(tag)) {
    return `run \`bun --cwd scripts docker load --pr ${tag.slice("pr-".length)}\` first`;
  }
  if (tag === "main") {
    return "run `bun --cwd scripts docker load --branch main` first";
  }
  return `run \`bun --cwd scripts docker load --tag ${tag} <image.tar>\` first`;
}

export function up(args: string[] = []): void {
  const parsed = parseUpArgs(args);
  const names = namesForTag(parsed.tag);
  ensureImage(names.gatewayImage, loadHintForTag(parsed.tag));
  ensureNetwork(names);
  if (resourceExists("container", names.gatewayContainer)) {
    container(["rm", "-f", names.gatewayContainer]);
  }
  copyLocalRouterFiles(names, parsed);
  const portArgs: string[] = [];
  if (parsed.port !== undefined) {
    portArgs.push("-p", `127.0.0.1:${parsed.port}:4141`);
  }
  if (parsed.proxyPort !== undefined) {
    portArgs.push("-p", `127.0.0.1:${parsed.proxyPort}:4142`);
  }
  container([
    "run",
    "-d",
    "--name",
    names.gatewayContainer,
    "--stop-timeout",
    "40",
    "--network",
    names.networkName,
    ...portArgs,
    "-v",
    `${names.routerStateVolume}:/root/.tokn/router`,
    names.gatewayImage,
    "serve",
    "--host",
    "0.0.0.0",
    "--with-proxy",
    "--insecure-allow-remote",
  ]);
  if (parsed.port !== undefined) {
    console.log(`API: http://127.0.0.1:${parsed.port}/v1`);
  }
  if (parsed.proxyPort !== undefined) {
    console.log(`Proxy: http://127.0.0.1:${parsed.proxyPort}`);
  }
}

export function buildAgent(): void {
  container(["build", "-t", agentImage, "-f", resolve(scriptDir, "Dockerfile.agent"), scriptDir]);
}

export function down(args: string[] = []): void {
  const tagged = parseTaggedArgs(args, defaultTag);
  if (tagged.rest.length !== 0) throw new UsageError("down does not accept positional arguments");
  const names = namesForTag(tagged.tag);
  if (resourceExists("container", names.gatewayContainer)) {
    container(["stop", "--time", "40", names.gatewayContainer]);
    container(["rm", names.gatewayContainer]);
  }
  if (resourceExists("network", names.networkName)) {
    container(["network", "rm", names.networkName]);
  }
}

export function reset(args: string[]): void {
  const tagged = parseTaggedArgs(args, defaultTag);
  if (tagged.rest.length !== 1 || tagged.rest[0] !== "--yes") {
    throw new Error("reset removes containers and volumes; pass --yes to confirm");
  }
  const names = namesForTag(tagged.tag);
  down(["--tag", tagged.tag]);
  if (resourceExists("volume", names.routerStateVolume)) {
    container(["volume", "rm", names.routerStateVolume]);
  }
}

export function status(args: string[] = []): void {
  const tagged = parseTaggedArgs(args, defaultTag);
  if (tagged.rest.length !== 0) throw new UsageError("status does not accept positional arguments");
  const names = namesForTag(tagged.tag);
  container(["ps", "-a", "--filter", `name=${names.projectName}`]);
  container(["image", "ls", names.gatewayImage]);
  container(["image", "ls", agentImage]);
  container(["volume", "ls", "--filter", `name=${names.routerStateVolume}`]);
  container(["network", "ls", "--filter", `name=${names.networkName}`]);
}

export function logs(args: string[] = []): void {
  const tagged = parseTaggedArgs(args, defaultTag);
  if (tagged.rest.length !== 0) throw new UsageError("logs does not accept positional arguments");
  const names = namesForTag(tagged.tag);
  container(["logs", "-f", names.gatewayContainer]);
}
