const path = require('path');
const fs = require('fs');
const os = require('os');
const { runTests } = require('@vscode/test-electron');

async function main() {
  const isolated = fs.mkdtempSync(path.join(os.tmpdir(), 'fig-vscode-host-'));
  const home = path.join(isolated, 'home');
  fs.mkdirSync(home);
  try {
    const extensionDevelopmentPath = path.resolve(__dirname, '..');
    const extensionTestsPath = path.resolve(__dirname, 'suite', 'index');
    // Never open inspection samples as an executable workspace. Tests read them as text.
    const testWorkspace = path.join(isolated, 'workspace');
    fs.mkdirSync(path.join(testWorkspace, '.vscode'), { recursive: true });
    fs.writeFileSync(path.join(testWorkspace, '.vscode', 'settings.json'), JSON.stringify({ 'task.allowAutomaticTasks': 'off' }));
    await runTests({
      extensionDevelopmentPath,
      extensionTestsPath,
      extensionTestsEnv: { HOME: home, USERPROFILE: home },
      launchArgs: [
        testWorkspace,
        '--disable-extensions',
        `--user-data-dir=${path.join(isolated, 'profile')}`,
        `--extensions-dir=${path.join(isolated, 'extensions')}`,
        '--enable-proposed-api=fakeinterviewguard.fake-interview-guard',
      ],
    });
  } catch (error) {
    console.error('Failed to run tests:', error);
    process.exitCode = 1;
  } finally {
    fs.rmSync(isolated, { recursive: true, force: true });
  }
}
main();
