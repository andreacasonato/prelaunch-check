/** Runs async tasks with at most `n` in flight. */
export function limiter(n: number) {
  let active = 0;
  const queue: Array<() => void> = [];
  const next = () => {
    if (active >= n) return;
    const run = queue.shift();
    if (run) run();
  };
  return <T>(task: () => Promise<T>): Promise<T> =>
    new Promise<T>((resolvePromise, reject) => {
      queue.push(() => {
        active++;
        task()
          .then(resolvePromise, reject)
          .finally(() => {
            active--;
            next();
          });
      });
      next();
    });
}
