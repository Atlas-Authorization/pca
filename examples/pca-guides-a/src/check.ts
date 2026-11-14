// A tiny assertion helper: print every outcome, and exit non-zero if any differs from what the guide says.
let failures = 0;

export function expectEq(label: string, actual: unknown, wanted: unknown): void {
  const a = JSON.stringify(actual);
  const w = JSON.stringify(wanted);
  if (a === w) {
    console.log(`ok    ${label}`);
  } else {
    failures += 1;
    console.log(`FAIL  ${label}\n      got    ${a}\n      wanted ${w}`);
  }
}

export function run(main: () => void | Promise<void>): void {
  Promise.resolve()
    .then(main)
    .then(() => {
      if (failures === 0) {
        console.log('All outcomes as expected.');
      } else {
        console.error(`${failures} outcome(s) differed from the guide.`);
        process.exitCode = 1;
      }
    })
    .catch((err: unknown) => {
      console.error(err);
      process.exitCode = 1;
    });
}
