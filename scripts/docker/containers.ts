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
  projectName: string;
  routerStateVolume: string;
};

type UpArgs = {
  copyLocal: "none" | "config" | "accounts";
  forceCopyLocal: boolean;
  published_ports: PublishedPort[];
  tag: string;
};

type PublishedPort = {
  host_port: number;
  listener_port: number;
};

export function resourceExists(kind: "container" | "image" | "volume", name: string): boolean {
  return containerOk([kind, "inspect", name]);
}

export function namesForTag(tag: string): ContainerNames {
  const projectName = `tokn-router-${tag}`;
  return {
    gatewayImage: `${gatewayImageRepo}:${tag}`,
    gatewayContainer: `${projectName}-gateway`,
    projectName,
    routerStateVolume: `${projectName}-router-state`,
  };
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
  const published_ports: PublishedPort[] = [];
  for (let i = 0; i < tagged.rest.length; i += 1) {
    const arg = tagged.rest[i];
    if (arg === "--publish") {
      published_ports.push(parsePublishedPort(requireValue(tagged.rest, i, "--publish")));
      i += 1;
    } else if (arg.startsWith("--publish=")) {
      published_ports.push(parsePublishedPort(arg.slice("--publish=".length)));
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
  const duplicateHostPort = published_ports.find(
    (candidate, index) => published_ports.findIndex((entry) => entry.host_port === candidate.host_port) !== index,
  );
  if (duplicateHostPort !== undefined) {
    throw new Error(`host port ${duplicateHostPort.host_port} is published more than once`);
  }
  return { copyLocal, forceCopyLocal, published_ports, tag: tagged.tag };
}

function parsePublishedPort(value: string): PublishedPort {
  const parts = value.split(":");
  if (parts.length !== 2) {
    throw new Error(`invalid --publish value '${value}' (expected HOST_PORT:LISTENER_PORT)`);
  }
  return {
    host_port: requirePort(parts[0], "--publish host port"),
    listener_port: requirePort(parts[1], "--publish listener port"),
  };
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

function requireV2GatewayConfig(names: ContainerNames): void {
  const volumeArgs = ["-v", `${names.routerStateVolume}:/state:ro`];
  const hasConfig = containerOk([
    "run",
    "--rm",
    ...volumeArgs,
    "--entrypoint",
    "sh",
    names.gatewayImage,
    "-c",
    "test -f /state/config.toml",
  ]);
  if (!hasConfig) {
    throw new Error(
      `gateway state has no config.toml; seed a schema-v2 config with --copy-local-config for tag ${names.projectName}`,
    );
  }

  const isV2 = containerOk([
    "run",
    "--rm",
    ...volumeArgs,
    "--entrypoint",
    "sh",
    names.gatewayImage,
    "-c",
    "grep -Eq '^[[:space:]]*schema_version[[:space:]]*=[[:space:]]*2[[:space:]]*(#.*)?$' /state/config.toml",
  ]);
  if (!isV2) {
    throw new Error(
      `gateway config is not schema version 2; migrate it or replace it with --copy-local-config --force-copy-local`,
    );
  }
}

export function up(args: string[] = []): void {
  const parsed = parseUpArgs(args);
  const names = namesForTag(parsed.tag);
  ensureImage(names.gatewayImage, loadHintForTag(parsed.tag));
  if (resourceExists("container", names.gatewayContainer)) {
    container(["rm", "-f", names.gatewayContainer]);
  }
  copyLocalRouterFiles(names, parsed);
  requireV2GatewayConfig(names);
  const portArgs: string[] = [];
  for (const published of parsed.published_ports) {
    portArgs.push("-p", `127.0.0.1:${published.host_port}:${published.listener_port}`);
  }
  container([
    "run",
    "-d",
    "--name",
    names.gatewayContainer,
    ...portArgs,
    "-v",
    `${names.routerStateVolume}:/root/.tokn/router`,
    names.gatewayImage,
    "serve",
  ]);
  for (const published of parsed.published_ports) {
    console.log(`Published: 127.0.0.1:${published.host_port} -> listener port ${published.listener_port}`);
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
    container(["rm", "-f", names.gatewayContainer]);
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
}

export function logs(args: string[] = []): void {
  const tagged = parseTaggedArgs(args, defaultTag);
  if (tagged.rest.length !== 0) throw new UsageError("logs does not accept positional arguments");
  const names = namesForTag(tagged.tag);
  container(["logs", "-f", names.gatewayContainer]);
}
