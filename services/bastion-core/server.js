import { createBastion, configFromEnv } from './service.js';

try {
  const app = createBastion(configFromEnv());
  await app.listen();
  console.log(`BASTION listening on http://127.0.0.1:${app.port}`);
  let stopping = false;
  const stop = async () => {
    if (stopping) return;
    stopping = true;
    await app.close();
  };
  process.on('SIGINT', stop);
  process.on('SIGTERM', stop);
} catch {
  console.error('BASTION startup failed: check configuration, database, and listen port.');
  process.exitCode = 1;
}
