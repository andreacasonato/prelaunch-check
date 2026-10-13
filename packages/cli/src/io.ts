// Everything the CLI touches in the outside world, injectable for tests.
export interface Io {
  stdout(text: string): void;
  stderr(text: string): void;
  env: Record<string, string | undefined>;
  cwd: string;
  isTTY: boolean;
  columns: number;
  fetch: typeof fetch;
  /** Asks a yes/no question on a TTY. Resolves false when not interactive. */
  confirm(question: string): Promise<boolean>;
  now(): Date;
}
