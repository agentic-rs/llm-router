import { agent } from "./agent";
import { UsageError } from "./args";
import { loadImage } from "./artifacts";
import { buildAgent, down, logs, reset, status, up } from "./containers";

function usage(): never {
  console.error(`Usage:
  bun --cwd scripts docker load [--tag <tag>] <image.tar>
  bun --cwd scripts docker load --pr <number>
  bun --cwd scripts docker load --branch <name>
  bun --cwd scripts docker up [--tag <tag>] [--copy-local-config|--copy-local-accounts] [--force-copy-local] [--publish <host-port:listener-port>]...
  bun --cwd scripts docker agent [--tag <tag>] [--no-tty] --agent codex|opencode|pi --transport api|proxy [--listener <id>] [-- <args>]
  bun --cwd scripts docker down [--tag <tag>]
  bun --cwd scripts docker reset [--tag <tag>] --yes
  bun --cwd scripts docker status [--tag <tag>]
  bun --cwd scripts docker logs [--tag <tag>]
  bun --cwd scripts docker build-agent

Environment:
  TOKN_CONTAINER_ENGINE=podman|docker  (default: podman)`);
  process.exit(64);
}

async function main(): Promise<void> {
  const [cmd, ...args] = process.argv.slice(2);
  try {
    switch (cmd) {
      case "load":
        await loadImage(args);
        break;
      case "up":
        up(args);
        break;
      case "agent":
        await agent(args);
        break;
      case "down":
        down(args);
        break;
      case "reset":
        reset(args);
        break;
      case "status":
        status(args);
        break;
      case "logs":
        logs(args);
        break;
      case "build-agent":
        if (args.length !== 0) usage();
        buildAgent();
        break;
      default:
        usage();
    }
  } catch (err) {
    if (err instanceof UsageError) {
      usage();
    }
    console.error(err instanceof Error ? err.message : String(err));
    process.exit(1);
  }
}

await main();
