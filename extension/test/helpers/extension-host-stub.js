// In-process UI and model transport stubs. All files live under the supplied fixture root.
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const extensionRoot = path.resolve(__dirname, '../..');
const defaults = Object.fromEntries(Object.entries(require('../../package.json').contributes.configuration.properties).map(([key, value]) => [key, value.default]));
const disposable = () => ({ dispose() {} });
function createHost(root, { user = {}, workspace = {}, trusted = true, ignoreAbort = false } = {}) {
  const messages = [], logs = [], commands = new Map(), diagnostics = new Map(), watchers = [], modelCalls = [], clients = [], replies = [];
  const handlers = {};
  let lastToken;
  const uri = file => ({ scheme: 'file', fsPath: file, toString: () => `file://${file}` });
  const listener = key => fn => { (handlers[key] ||= []).push(fn); return disposable(); };
  class Generic { constructor(...args) { this.args = args; } }
  class Position { constructor(line, character) { this.line = line; this.character = character; } }
  class Range { constructor(...args) { if (args.length === 2) [this.start, this.end] = args; else { this.start = new Position(args[0],args[1]); this.end = new Position(args[2],args[3]); } } }
  class EventEmitter { constructor() { this.event = () => disposable(); } fire() {} dispose() {} }
  const windowMessage = type => async (...args) => { messages.push({ type, text: args[0], options: args[1], choices: args.slice(typeof args[1] === 'object' ? 2 : 1) }); const reply = replies.shift(); return typeof reply === 'function' ? reply() : reply; };
  const vscode = {
    Position, Range, EventEmitter, TreeItem: Generic, ThemeIcon: Generic, ThemeColor: Generic,
    Diagnostic: class { constructor(range,message,severity) { Object.assign(this,{range,message,severity}); } },
    DiagnosticRelatedInformation: Generic, Location: Generic, Uri: { file: uri },
    CodeActionKind: { QuickFix:'quickfix' }, StatusBarAlignment: {Left:1}, TreeItemCollapsibleState:{None:0,Collapsed:1},
    DiagnosticSeverity:{Error:0,Warning:1,Information:2,Hint:3}, ProgressLocation:{Notification:15}, ViewColumn:{One:1,Two:2},
    window: {
      activeTextEditor: undefined,
      createOutputChannel: () => ({appendLine:line=>logs.push(line), show(){}, dispose(){}}),
      createStatusBarItem: () => ({show(){},dispose(){}}), createTreeView: () => disposable(),
      showInformationMessage: windowMessage('info'), showWarningMessage: windowMessage('warning'), showErrorMessage: windowMessage('error'),
      showTextDocument: async document => { vscode.window.activeTextEditor={document,selection:{isEmpty:true}}; return vscode.window.activeTextEditor; },
      withProgress: async (_options, fn) => {
        const callbacks = new Set();
        lastToken = { isCancellationRequested:false, onCancellationRequested(callback) { callbacks.add(callback); return {dispose:()=>callbacks.delete(callback)}; }, cancel() {this.isCancellationRequested=true;for(const fn of [...callbacks])fn();},get subscriptions(){return callbacks.size;} };
        return fn({report(){}},lastToken);
      },
    },
    workspace: {
      isTrusted: trusted, workspaceFolders:[], textDocuments:[],
      getConfiguration: section => ({get:(key,fallback)=>workspace[(section?section+'.':'')+key] ?? user[(section?section+'.':'')+key] ?? defaults[(section?section+'.':'')+key] ?? fallback,
        inspect:key=>({globalValue:user[(section?section+'.':'')+key],workspaceValue:workspace[(section?section+'.':'')+key],defaultValue:defaults[(section?section+'.':'')+key]})}),
      getWorkspaceFolder: resource => vscode.workspace.workspaceFolders.find(folder=>{const relative=path.relative(folder.uri.fsPath,resource.fsPath);return !relative.startsWith('..'+path.sep)&&relative!=='..'&&!path.isAbsolute(relative);}),
      onDidSaveTextDocument:listener('save'),onDidOpenTextDocument:listener('open'),onDidChangeTextDocument:listener('change'),onDidChangeConfiguration:listener('config'),
      createFileSystemWatcher:()=>{const value={onDidCreate(fn){this.create=fn;},onDidChange(fn){this.change=fn;},onDidDelete(fn){this.delete=fn;},dispose(){}};watchers.push(value);return value;},
      openTextDocument:async value=>{
        const filename=typeof value==='string'?value:value.fsPath;
        const document=filename?makeDocument(filename,fs.readFileSync(filename,'utf8')):makeDocument(path.join(root,'untitled.json'),value.content);
        if(!filename)document.uri.scheme='untitled';
        return document;
      },
    },
    languages:{registerCodeActionsProvider:()=>disposable(),getDiagnostics:resource=>diagnostics.get(resource.fsPath)||[],
      createDiagnosticCollection:()=>({clear:()=>diagnostics.clear(),set:(resource,values)=>diagnostics.set(resource.fsPath,values),delete:resource=>diagnostics.delete(resource.fsPath),dispose(){}})},
    commands:{registerCommand:(key,fn)=>{commands.set(key,fn);return disposable();}},
  };
  function makeDocument(filename, content) {
    const existing=vscode.workspace.textDocuments.find(document=>document.uri.fsPath===filename);
    if(existing)return existing;
    const document={uri:uri(filename),version:1,isDirty:false,text:content,getText(){return this.text;}};
    vscode.workspace.textDocuments.push(document);return document;
  }
  class OpenAI {
    constructor(options) {
      clients.push(options);
      this.chat={completions:{create:(body,options)=>new Promise((resolve,reject)=>{
        const call={body,options,resolve,reject};modelCalls.push(call);
        if(!ignoreAbort){const abort=()=>reject(Object.assign(new Error('aborted'),{name:'AbortError'}));if(options?.signal?.aborted)abort();else options?.signal?.addEventListener('abort',abort,{once:true});}
      })}};
      this.models={list:async()=>{modelCalls.push({health:true});return{data:[]};}};
    }
  }
  const modules = new Map();
  function load(relative) {
    let filename=path.resolve(extensionRoot,'out',relative);
    if(!path.extname(filename))filename=fs.existsSync(filename+'.js')?filename+'.js':path.join(filename,'index.js');
    if(modules.has(filename))return modules.get(filename).exports;
    const module={exports:{}};modules.set(filename,module);
    const request=name=>name==='vscode'?vscode:name==='openai'?OpenAI:name.startsWith('.')?load(path.relative(path.join(extensionRoot,'out'),path.resolve(path.dirname(filename),name))):require(name);
    vm.runInNewContext(fs.readFileSync(filename,'utf8'),{module,exports:module.exports,require:request,console,Buffer,URL,AbortController,setTimeout,clearTimeout,setImmediate,
      process:{env:{HOME:path.join(root,'home'),USERPROFILE:path.join(root,'home')},platform:process.platform},__dirname:path.dirname(filename),__filename:filename},{filename});
    return module.exports;
  }
  const context={extensionPath:extensionRoot,extensionUri:uri(extensionRoot),subscriptions:[]};
  return {vscode,load,context,messages,logs,commands,diagnostics,watchers,modelCalls,clients,replies,user,workspace,makeDocument,uri,
    fire:(key,value)=>(handlers[key]||[]).map(fn=>fn(value)),cancel:()=>lastToken.cancel(),subscriptions:()=>lastToken?.subscriptions,
    activate(){const extension=load('extension');extension.activate(context);return extension;}};
}
function modelResponse(findings = []) {
  return {choices:[{message:{content:JSON.stringify({malicious:findings.length>0,confidence:90,threats:findings,summary:'Synthetic fixture result'})}}],model:'stub-model',usage:{}};
}
module.exports = {createHost,modelResponse,tick:()=>new Promise(resolve=>setImmediate(resolve))};
