console.log(process.env);

export function connect(apiKey: string, dbPassword: string) {
  console.log("Connecting with", apiKey);
  console.debug({ dbPassword });
}
