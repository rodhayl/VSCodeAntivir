import { parse, ParseError } from 'jsonc-parser';

export const TASK_PLATFORMS = ['windows', 'linux', 'osx'] as const;
export type TaskConfiguration = Record<string, unknown>;
export interface TaskVariant {
  taskPath: (string | number)[];
  taskIndex: number;
  taskLabel: string;
  variant: string;
  command: string;
  fullCommand: string;
  autoExecute: boolean;
}

function record(value: unknown): value is TaskConfiguration {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

function commandText(value: unknown): string {
  if (value === undefined) return '';
  if (typeof value === 'string') return value;
  if (record(value) && typeof value.value === 'string' &&
      typeof value.quoting === 'string' && ['strong', 'weak', 'escape'].includes(value.quoting) &&
      Object.keys(value).every(key => key === 'value' || key === 'quoting')) return value.value;
  throw new Error('Unsupported task command/argument; expected a string or { value, quoting }');
}

export function parseTaskConfiguration(content: string): TaskConfiguration {
  const errors: ParseError[] = [];
  const root: unknown = parse(content, errors, { allowTrailingComma: true });
  if (errors.length || !record(root)) throw new Error('Invalid task configuration');
  const validate = (scope: TaskConfiguration, global: boolean, allowPlatforms: boolean): void => {
    commandText(scope.command);
    if (scope.args !== undefined) {
      if (!Array.isArray(scope.args)) throw new Error('Invalid task arguments');
      scope.args.forEach(commandText);
    }
    if (scope.runOptions !== undefined && !record(scope.runOptions)) throw new Error('Invalid task runOptions');
    if (scope.options !== undefined && !record(scope.options)) throw new Error('Invalid task options');
    if (scope.tasks !== undefined) {
      if (!global || !Array.isArray(scope.tasks)) throw new Error('Invalid task list');
      for (const task of scope.tasks) {
        if (!record(task)) throw new Error('Invalid task description');
        validate(task, false, true);
      }
    }
    for (const platform of TASK_PLATFORMS) {
      if (scope[platform] === undefined) continue;
      if (!allowPlatforms || !record(scope[platform])) throw new Error('Invalid task platform override');
      validate(scope[platform], global, false);
    }
  };
  validate(root, true, true);
  return root;
}

function scope(value: unknown): TaskConfiguration { return record(value) ? value : {}; }
function merge(...layers: TaskConfiguration[]): TaskConfiguration {
  const result: TaskConfiguration = {};
  for (const layer of layers) {
    const runOptions = { ...scope(result.runOptions), ...scope(layer.runOptions) };
    Object.assign(result, layer);
    result.runOptions = runOptions;
  }
  return result;
}

// Inspect declarations on every platform, independent of the host OS. Global
// declarations are inspected too: an overridden default is still reviewable text.
// This is not a task resolver, variable evaluator, provider or shell interpreter.
export function taskVariants(root: TaskConfiguration): TaskVariant[] {
  const variants: TaskVariant[] = [];
  const add = (task: TaskConfiguration, taskPath: (string | number)[], platforms: string[]) => {
    const seen = new Set<string>();
    for (const platform of platforms) {
      const globalPlatform = scope(root[platform]);
      const globals = merge(root, globalPlatform);
      const local = merge(task, scope(task[platform]));
      const effective = taskPath.length ? merge(globals, local) : globals;
      // VS Code appends a task's args to the global args when it inherits the
      // global command. An OS-specific args array replaces that scope's base args.
      if (taskPath.length && local.command === undefined && globals.command !== undefined) {
        effective.args = [...(Array.isArray(globals.args) ? globals.args : []), ...(Array.isArray(local.args) ? local.args : [])];
      }
      const command = commandText(effective.command);
      const args = (Array.isArray(effective.args) ? effective.args : []).map(commandText).join(' ');
      const fullCommand = `${command} ${args}`.trim();
      const autoExecute = scope(effective.runOptions).runOn === 'folderOpen';
      const identity = JSON.stringify([fullCommand, autoExecute]);
      if (seen.has(identity)) continue;
      seen.add(identity);
      variants.push({ taskPath, taskIndex: typeof taskPath.at(-1) === 'number' ? taskPath.at(-1) as number : -1,
        taskLabel: typeof task.label === 'string' ? task.label : taskPath.length ? 'unnamed' : 'global defaults',
        variant: platform, command, fullCommand, autoExecute });
    }
  };
  const platforms = ['default', ...TASK_PLATFORMS];
  add(root, [], platforms);
  if (Array.isArray(root.tasks)) root.tasks.forEach((task, index) => add(scope(task), ['tasks', index], platforms));
  for (const platform of TASK_PLATFORMS) {
    const platformScope = scope(root[platform]);
    if (Array.isArray(platformScope.tasks)) platformScope.tasks.forEach((task, index) => add(scope(task), [platform, 'tasks', index], [platform]));
  }
  return variants;
}

export function taskAt(root: TaskConfiguration, taskPath: (string | number)[]): TaskConfiguration {
  let value: unknown = root;
  for (const key of taskPath) value = (value as Record<string | number, unknown>)?.[key];
  if (!record(value)) throw new Error('Reviewed task no longer exists');
  return value;
}

export function taskRemediationError(root: TaskConfiguration, taskPaths: (string | number)[][]): string | undefined {
  if (root.version !== undefined && root.version !== '2.0.0') return 'Only task version 2.0.0 is supported for remediation; edit this configuration manually.';
  if (TASK_PLATFORMS.some(platform => scope(root[platform]).tasks !== undefined)) {
    return 'Platform-level task lists can replace tasks by label and require manual editing; no task changes will be applied.';
  }
  const globals = [root, ...TASK_PLATFORMS.map(platform => scope(root[platform]))];
  const supported = new Set(['label', 'type', 'command', 'args', 'dependsOn', 'dependsOrder', 'runOptions', 'options',
    'group', 'presentation', 'problemMatcher', 'isBackground', 'detail', 'icon', 'hide', ...TASK_PLATFORMS]);
  const globalSupported = new Set([...supported, 'version', 'tasks', 'inputs', '$schema']);
  if (globals.some(value => Object.keys(value).some(key => !globalSupported.has(key)))) {
    return 'Unsupported global task properties require manual editing; no task changes will be applied.';
  }
  for (const taskPath of taskPaths) {
    if (taskPath.length !== 2 || taskPath[0] !== 'tasks') return 'Global commands and platform-level task lists require manual editing; no task changes will be applied.';
    if (globals.some(value => ['command', 'args', 'dependsOn', 'runOptions'].some(key => value[key] !== undefined))) {
      return 'Inherited global execution settings require manual editing; no task changes will be applied.';
    }
    const task = taskAt(root, taskPath);
    const layers = [...globals, task, ...TASK_PLATFORMS.map(platform => scope(task[platform]))];
    if (layers.some(value => value.type !== undefined && value.type !== 'shell')) {
      return 'Process tasks and custom task providers require manual editing; no task changes will be applied.';
    }
    if (layers.some(value => Object.keys(scope(value.options)).length > 0)) {
      return 'Task execution options (including custom shells and inherited options) require manual editing; no task changes will be applied.';
    }
    if ([task, ...TASK_PLATFORMS.map(platform => scope(task[platform]))].some(value => Object.keys(value).some(key => !supported.has(key)))) {
      return 'Unsupported task properties require manual editing; no task changes will be applied.';
    }
  }
  return undefined;
}
