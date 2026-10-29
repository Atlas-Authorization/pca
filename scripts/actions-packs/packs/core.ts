// core - local and generic capabilities: files, shell, containers, git, ssh, generic HTTP, browser, computer use, environment,
// secrets, clipboard, OS, scheduling and agent control. Hand written; every def is `authored` (a person chose its class).
import { BUILTIN_DEFS, type ActionDef } from '@atlasauth/pca-actions';
import { P, def, handPack, type H } from '../lib/hand';

const fileSet = (extra: Partial<H> & Pick<H, 'verb' | 'title' | 'description' | 'effects' | 'params'>): H => ({ res: ['files.file', 'set'], ...extra });
const proc = (extra: Partial<H> & Pick<H, 'verb' | 'title' | 'description' | 'effects' | 'params'>): H => ({ res: ['shell.process', 'set'], ...extra });

const H1: H[] = [
  // ---- files (files.read / files.write / files.delete / http.get / http.post come from the built-in seed unchanged)
  fileSet({ verb: 'files.list', title: 'List a directory', description: 'Lists the entries of a directory.', effects: ['read'], params: { path: P.path(), recursive: P.opt(P.bool()), limit: P.limit(10_000) } }),
  fileSet({ verb: 'files.stat', title: 'Read file metadata', description: 'Size, times and mode of a path.', effects: ['read'], params: { path: P.path() } }),
  fileSet({ verb: 'files.search', title: 'Search file contents', description: 'Searches files under a path for a text pattern.', effects: ['read'], params: { path: P.path(), pattern: P.str(1024, { role: 'query.search' }), limit: P.limit(10_000) } }),
  fileSet({ verb: 'files.glob', title: 'Find files by pattern', description: 'Lists paths matching a glob.', effects: ['read'], params: { path: P.path(), glob: P.str(512), limit: P.limit(10_000) } }),
  fileSet({ verb: 'files.read_binary', title: 'Read a binary file', description: 'Reads a file as bytes (base64).', effects: ['read'], params: { path: P.path(), max_bytes: P.opt(P.int(1, 104_857_600, { role: 'bytes.size' })) } }),
  fileSet({ verb: 'files.append', title: 'Append to a file', description: 'Appends text to the end of a file.', effects: ['update'], rev: 'rate_limited', params: { path: P.path(), content: P.str(1_000_000) } }),
  fileSet({ verb: 'files.truncate', title: 'Truncate a file', description: 'Cuts a file to a given length, discarding the rest.', effects: ['update', 'delete'], params: { path: P.path(), length: P.int(0, 1_073_741_824, { role: 'bytes.size' }) } }),
  fileSet({ verb: 'files.mkdir', title: 'Create a directory', description: 'Creates a directory, including missing parents.', effects: ['create'], rev: 'reversible', params: { path: P.path() } }),
  fileSet({ verb: 'files.copy', title: 'Copy a file', description: 'Copies a file or directory to a new path.', effects: ['create'], rev: 'reversible', params: { from: P.path(), to: P.path(), overwrite: P.opt(P.bool()) } }),
  fileSet({ verb: 'files.move', title: 'Move or rename a file', description: 'Moves a path; the source no longer exists afterwards and an existing target is replaced.', effects: ['update', 'delete'], params: { from: P.path(), to: P.path() } }),
  fileSet({ verb: 'files.delete_dir', title: 'Delete a directory tree', description: 'Recursively deletes a directory and everything in it.', effects: ['delete'], params: { path: P.path() } }),
  fileSet({ verb: 'files.shred', title: 'Securely erase a file', description: 'Overwrites and deletes a file so it cannot be recovered.', effects: ['delete'], params: { path: P.path() } }),
  fileSet({ verb: 'files.chmod', title: 'Change file permissions', description: 'Changes the mode bits of a path.', effects: ['privilege'], rev: 'rate_limited', params: { path: P.path(), mode: P.str(8) } }),
  fileSet({ verb: 'files.chown', title: 'Change file owner', description: 'Changes the owner and group of a path.', effects: ['privilege'], rev: 'rate_limited', params: { path: P.path(), owner: P.str(64), group: P.opt(P.str(64)) } }),
  fileSet({ verb: 'files.symlink', title: 'Create a symbolic link', description: 'Creates a symlink at a path pointing at a target.', effects: ['create'], rev: 'reversible', params: { target: P.path(), link: P.path() } }),
  fileSet({ verb: 'files.archive', title: 'Create an archive', description: 'Packs paths into a zip or tar archive.', effects: ['create'], rev: 'reversible', params: { paths: P.arr('string', 1000), output: P.path(), format: P.enum(['zip', 'tar', 'tar.gz']) } }),
  fileSet({ verb: 'files.extract', title: 'Extract an archive', description: 'Unpacks an archive into a directory, creating or replacing files.', effects: ['create', 'update'], params: { archive: P.path(), into: P.path() } }),
  fileSet({ verb: 'files.temp', title: 'Create a temporary file', description: 'Creates an empty temporary file and returns its path.', effects: ['create'], rev: 'reversible', params: { suffix: P.opt(P.str(16)) } }),

  // ---- shell and processes
  proc({ verb: 'shell.run', title: 'Run a shell command', description: 'Runs a command line in a shell and returns its output.', effects: ['exec'], params: { command: P.cmd(), cwd: P.opt(P.path()), timeout_s: P.opt(P.int(1, 3600, { role: 'count.limit' })) } }),
  proc({ verb: 'shell.run_script', title: 'Run a script', description: 'Runs source code with an interpreter.', effects: ['exec'], params: { interpreter: P.enum(['sh', 'bash', 'zsh', 'python', 'node', 'ruby', 'perl', 'powershell']), source: P.code(), cwd: P.opt(P.path()) } }),
  proc({ verb: 'shell.run_background', title: 'Start a background process', description: 'Starts a long-running process and returns its pid.', effects: ['exec', 'provision'], params: { command: P.cmd(), cwd: P.opt(P.path()) } }),
  proc({ verb: 'shell.sudo', title: 'Run a command with elevated rights', description: 'Runs a command as root or another user.', effects: ['exec', 'privilege'], params: { command: P.cmd(), user: P.opt(P.str(64)) } }),
  { verb: 'shell.kill', title: 'Kill a process', description: 'Terminates a process.', effects: ['delete'], res: ['shell.process', 'one'], params: { pid: P.id('shell.process', { max_len: 10 }), signal: P.opt(P.enum(['TERM', 'KILL', 'INT', 'HUP'])) } },
  proc({ verb: 'shell.ps', title: 'List processes', description: 'Lists running processes.', effects: ['read'], params: { limit: P.limit(10_000) } }),
  { verb: 'shell.process_status', title: 'Read a process status', description: 'State, cpu and memory of one process.', effects: ['read'], res: ['shell.process', 'one'], params: { pid: P.id('shell.process', { max_len: 10 }) } },
  proc({ verb: 'shell.install_package', title: 'Install a software package', description: 'Installs a package with a package manager; install scripts run with the caller rights.', effects: ['exec', 'create'], traits: ['pca.persistence'], params: { manager: P.enum(['npm', 'pnpm', 'yarn', 'pip', 'uv', 'cargo', 'gem', 'go', 'brew', 'apt', 'dnf', 'apk', 'winget', 'choco']), package: P.str(256), version: P.opt(P.str(64)), global: P.opt(P.bool()) } }),
  proc({ verb: 'shell.uninstall_package', title: 'Remove a software package', description: 'Removes an installed package.', effects: ['exec', 'delete'], params: { manager: P.enum(['npm', 'pnpm', 'yarn', 'pip', 'uv', 'cargo', 'gem', 'go', 'brew', 'apt', 'dnf', 'apk', 'winget', 'choco']), package: P.str(256) } }),
  proc({ verb: 'shell.cron_add', title: 'Add a scheduled job', description: 'Adds a recurring command to the system scheduler.', effects: ['create', 'provision'], rev: 'rate_limited', params: { schedule: P.str(128), command: P.cmd() } }),
  proc({ verb: 'shell.cron_remove', title: 'Remove a scheduled job', description: 'Removes a recurring job from the system scheduler.', effects: ['delete'], params: { job: P.str(128) } }),
  proc({ verb: 'shell.service_control', title: 'Start, stop or restart a service', description: 'Controls a system service.', effects: ['update', 'exec'], params: { service: P.str(128), action: P.enum(['start', 'stop', 'restart', 'reload', 'enable', 'disable']) } }),

  // ---- containers
  { verb: 'docker.run', title: 'Run a container', description: 'Creates and starts a container from an image.', effects: ['exec', 'provision'], res: ['docker.container', 'set'], params: { image: P.str(512), command: P.opt(P.cmd()), env: P.opt(P.obj()), ports: P.opt(P.arr('string', 64)), privileged: P.opt(P.bool()), mounts: P.opt(P.arr('string', 64)) } },
  { verb: 'docker.exec', title: 'Run a command in a container', description: 'Executes a command inside a running container.', effects: ['exec'], res: ['docker.container', 'one'], params: { container: P.id('docker.container'), command: P.cmd() } },
  { verb: 'docker.build', title: 'Build an image', description: 'Builds an image from a build context; build steps run code.', effects: ['exec', 'create'], res: ['docker.image', 'set'], params: { context: P.path(), tag: P.opt(P.str(256)), dockerfile: P.opt(P.path()) } },
  { verb: 'docker.pull', title: 'Pull an image', description: 'Downloads an image from a registry.', effects: ['create'], rev: 'reversible', res: ['docker.image', 'set'], params: { image: P.str(512) } },
  { verb: 'docker.push', title: 'Push an image to a registry', description: 'Uploads an image to a registry where others may pull it.', effects: ['publish'], res: ['docker.image', 'set'], params: { image: P.str(512) } },
  { verb: 'docker.stop', title: 'Stop a container', description: 'Stops a running container.', effects: ['update'], rev: 'rate_limited', res: ['docker.container', 'one'], params: { container: P.id('docker.container') } },
  { verb: 'docker.rm', title: 'Remove a container', description: 'Deletes a container and optionally its volumes.', effects: ['delete'], res: ['docker.container', 'one'], params: { container: P.id('docker.container'), volumes: P.opt(P.bool()) } },
  { verb: 'docker.logs', title: 'Read container logs', description: 'Reads the output of a container.', effects: ['read'], res: ['docker.container', 'one'], params: { container: P.id('docker.container'), limit: P.limit(100_000) } },
  { verb: 'docker.ps', title: 'List containers', description: 'Lists containers.', effects: ['read'], res: ['docker.container', 'set'], params: { all: P.opt(P.bool()) } },
  { verb: 'docker.compose_up', title: 'Start a compose project', description: 'Starts every service of a compose file.', effects: ['exec', 'provision'], res: ['docker.project', 'set'], params: { file: P.path(), project: P.opt(P.str(64)) } },
  { verb: 'docker.compose_down', title: 'Stop and remove a compose project', description: 'Stops and removes the services of a compose project.', effects: ['delete'], res: ['docker.project', 'set'], params: { file: P.path(), volumes: P.opt(P.bool()) } },
  { verb: 'docker.prune', title: 'Prune unused containers and images', description: 'Deletes every unused container, image and network.', effects: ['delete'], res: ['docker.container', 'set'], params: { volumes: P.opt(P.bool()) } },

  // ---- git (local and remote)
  { verb: 'git.status', title: 'Read repository status', description: 'Working tree status.', effects: ['read'], res: ['git.repo', 'set'], params: { repo: P.path() } },
  { verb: 'git.diff', title: 'Read a diff', description: 'Differences between revisions or the working tree.', effects: ['read'], res: ['git.repo', 'set'], params: { repo: P.path(), rev: P.opt(P.str(256)) } },
  { verb: 'git.log', title: 'Read history', description: 'Commit history.', effects: ['read'], res: ['git.repo', 'set'], params: { repo: P.path(), limit: P.limit(10_000) } },
  { verb: 'git.clone', title: 'Clone a repository', description: 'Downloads a repository and its history.', effects: ['create'], rev: 'reversible', res: ['git.repo', 'set'], params: { url: P.url(), into: P.path() } },
  { verb: 'git.add', title: 'Stage changes', description: 'Stages paths for the next commit.', effects: ['update'], rev: 'rate_limited', res: ['git.repo', 'set'], params: { repo: P.path(), paths: P.arr('string', 1000) } },
  { verb: 'git.commit', title: 'Create a commit', description: 'Records staged changes as a commit.', effects: ['create'], rev: 'reversible', res: ['git.repo', 'set'], params: { repo: P.path(), message: P.str(10_000) } },
  { verb: 'git.checkout', title: 'Switch branches or restore files', description: 'Switches the working tree to a revision; uncommitted changes to restored files are lost.', effects: ['update'], rev: 'rate_limited', res: ['git.repo', 'set'], params: { repo: P.path(), rev: P.str(256) } },
  { verb: 'git.branch_create', title: 'Create a branch', description: 'Creates a branch.', effects: ['create'], rev: 'reversible', res: ['git.repo', 'set'], params: { repo: P.path(), name: P.str(256), from: P.opt(P.str(256)) } },
  { verb: 'git.branch_delete', title: 'Delete a branch', description: 'Deletes a local branch.', effects: ['delete'], res: ['git.repo', 'set'], params: { repo: P.path(), name: P.str(256), force: P.opt(P.bool()) } },
  { verb: 'git.merge', title: 'Merge a branch', description: 'Merges a revision into the current branch.', effects: ['update'], rev: 'rate_limited', res: ['git.repo', 'set'], params: { repo: P.path(), rev: P.str(256) } },
  { verb: 'git.rebase', title: 'Rebase the current branch', description: 'Rewrites the current branch onto another base.', effects: ['update'], res: ['git.repo', 'set'], params: { repo: P.path(), onto: P.str(256) } },
  { verb: 'git.reset_hard', title: 'Discard all local changes', description: 'Resets the branch and working tree to a revision, losing uncommitted work.', effects: ['update', 'delete'], res: ['git.repo', 'set'], params: { repo: P.path(), rev: P.str(256) } },
  { verb: 'git.clean', title: 'Delete untracked files', description: 'Removes every file not tracked by git.', effects: ['delete'], res: ['git.repo', 'set'], params: { repo: P.path() } },
  { verb: 'git.pull', title: 'Pull from a remote', description: 'Fetches and merges remote changes.', effects: ['update'], rev: 'rate_limited', res: ['git.repo', 'set'], params: { repo: P.path(), remote: P.opt(P.str(128)) } },
  { verb: 'git.push', title: 'Push to a remote', description: 'Publishes commits to a remote repository.', effects: ['publish'], res: ['git.repo', 'set'], params: { repo: P.path(), remote: P.str(128), branch: P.str(256) } },
  { verb: 'git.push_force', title: 'Force-push to a remote', description: 'Overwrites remote history with local history.', effects: ['publish', 'delete'], res: ['git.repo', 'set'], params: { repo: P.path(), remote: P.str(128), branch: P.str(256) } },
  { verb: 'git.tag_push', title: 'Push a tag', description: 'Publishes a tag, which often triggers a release.', effects: ['publish'], res: ['git.repo', 'set'], params: { repo: P.path(), remote: P.str(128), tag: P.str(256) } },

  // ---- remote shells
  { verb: 'ssh.exec', title: 'Run a command on a remote host', description: 'Runs a command over SSH.', effects: ['exec'], res: ['ssh.host', 'one'], params: { host: P.id('ssh.host', { max_len: 255 }), user: P.str(64), command: P.cmd() } },
  { verb: 'ssh.upload', title: 'Copy a file to a remote host', description: 'Uploads a local file with scp or sftp, replacing the target.', effects: ['update'], rev: 'rate_limited', res: ['ssh.host', 'one'], params: { host: P.id('ssh.host', { max_len: 255 }), local: P.path(), remote: P.path() } },
  { verb: 'ssh.download', title: 'Copy a file from a remote host', description: 'Downloads a remote file with scp or sftp.', effects: ['read', 'create'], rev: 'reversible', res: ['ssh.host', 'one'], params: { host: P.id('ssh.host', { max_len: 255 }), remote: P.path(), local: P.path() } },
  { verb: 'ssh.tunnel', title: 'Open a network tunnel', description: 'Forwards a local port to a remote service through a host.', effects: ['provision'], rev: 'rate_limited', res: ['ssh.host', 'one'], params: { host: P.id('ssh.host', { max_len: 255 }), local_port: P.int(1, 65_535), remote: P.str(255, { role: 'url.target' }) } },

  // ---- generic HTTP (http.get and http.post are in the built-in seed)
  { verb: 'http.head', title: 'HTTP HEAD', description: 'Reads response headers of a URL.', effects: ['read'], res: ['http.endpoint', 'set'], params: { url: P.url() } },
  { verb: 'http.put', title: 'HTTP PUT', description: 'Replaces a remote resource.', effects: ['update'], rev: 'rate_limited', res: ['http.endpoint', 'set'], params: { url: P.url(), body: P.opt(P.str(1_000_000)) } },
  { verb: 'http.patch', title: 'HTTP PATCH', description: 'Partially modifies a remote resource.', effects: ['update'], rev: 'rate_limited', res: ['http.endpoint', 'set'], params: { url: P.url(), body: P.opt(P.str(1_000_000)) } },
  { verb: 'http.delete', title: 'HTTP DELETE', description: 'Deletes a remote resource.', effects: ['delete'], res: ['http.endpoint', 'set'], params: { url: P.url() } },
  { verb: 'http.graphql_query', title: 'GraphQL query', description: 'Runs a read-only GraphQL query.', effects: ['read'], res: ['http.endpoint', 'set'], params: { url: P.url(), query: P.str(100_000, { role: 'query.search' }), variables: P.opt(P.obj()) } },
  { verb: 'http.graphql_mutation', title: 'GraphQL mutation', description: 'Runs a GraphQL mutation.', effects: ['update'], rev: 'rate_limited', res: ['http.endpoint', 'set'], params: { url: P.url(), mutation: P.str(100_000), variables: P.opt(P.obj()) } },
  { verb: 'http.download', title: 'Download a URL to a file', description: 'Fetches a URL and writes the response to disk.', effects: ['read', 'create'], rev: 'reversible', res: ['http.endpoint', 'set'], params: { url: P.url(), to: P.path() } },
  { verb: 'http.webhook', title: 'Send a webhook', description: 'Posts an event payload to a webhook URL outside the organisation.', effects: ['publish'], res: ['http.endpoint', 'set'], params: { url: P.url(), payload: P.obj() } },
  { verb: 'http.websocket_send', title: 'Send over a WebSocket', description: 'Sends a message on a WebSocket connection.', effects: ['update'], rev: 'rate_limited', res: ['http.endpoint', 'set'], params: { url: P.url(), message: P.str(1_000_000) } },
  { verb: 'http.oauth_token', title: 'Request an OAuth token', description: 'Exchanges client credentials or a code for an access token.', effects: ['create'], rev: 'reversible', traits: ['pca.credential_access'], res: ['http.endpoint', 'set'], params: { url: P.url(), client_id: P.str(256), client_secret: P.secret({ required: false }), code: P.opt(P.secret()) } },

  // ---- browser
  { verb: 'browser.navigate', title: 'Open a page', description: 'Loads a URL in the browser.', effects: ['read'], res: ['browser.tab', 'set'], params: { url: P.url() } },
  { verb: 'browser.read_page', title: 'Read the page', description: 'Reads the text and structure of the current page.', effects: ['read'], res: ['browser.tab', 'set'], params: {} },
  { verb: 'browser.screenshot', title: 'Take a screenshot', description: 'Captures the current page as an image.', effects: ['read'], res: ['browser.tab', 'set'], params: { full_page: P.opt(P.bool()) } },
  { verb: 'browser.click', title: 'Click an element', description: 'Clicks an element; a click may submit or purchase.', effects: ['update'], rev: 'irreversible', res: ['browser.tab', 'set'], params: { selector: P.str(1024) } },
  { verb: 'browser.type', title: 'Type text', description: 'Types text into the focused element.', effects: ['update'], rev: 'rate_limited', res: ['browser.tab', 'set'], params: { selector: P.str(1024), text: P.str(100_000) } },
  { verb: 'browser.fill_form', title: 'Fill in a form', description: 'Sets the fields of a form.', effects: ['update'], rev: 'rate_limited', res: ['browser.tab', 'set'], params: { fields: P.obj() } },
  { verb: 'browser.submit_form', title: 'Submit a form', description: 'Submits a form to the site, which may send data or trigger an action.', effects: ['update', 'publish'], res: ['browser.tab', 'set'], params: { selector: P.str(1024) } },
  { verb: 'browser.login', title: 'Sign in to a site', description: 'Enters credentials and signs in.', effects: ['update'], rev: 'rate_limited', traits: ['pca.credential_access'], res: ['browser.tab', 'set'], params: { url: P.url(), username: P.str(256), password: P.secret() } },
  { verb: 'browser.evaluate_js', title: 'Run JavaScript in the page', description: 'Executes script in the page context.', effects: ['exec'], res: ['browser.tab', 'set'], params: { source: P.code() } },
  { verb: 'browser.download', title: 'Download a file', description: 'Saves a file the page links to.', effects: ['read', 'create'], rev: 'reversible', res: ['browser.tab', 'set'], params: { url: P.url(), to: P.path() } },
  { verb: 'browser.upload_file', title: 'Upload a file to a page', description: 'Sends a local file to a website.', effects: ['publish'], res: ['browser.tab', 'set'], params: { selector: P.str(1024), path: P.path() } },
  { verb: 'browser.get_cookies', title: 'Read cookies', description: 'Reads cookies, which may hold session credentials.', effects: ['read'], traits: ['pca.credential_access'], res: ['browser.tab', 'set'], params: { domain: P.opt(P.str(255)) } },
  { verb: 'browser.set_cookie', title: 'Set a cookie', description: 'Writes a cookie.', effects: ['update'], rev: 'rate_limited', res: ['browser.tab', 'set'], params: { name: P.str(256), value: P.secret(), domain: P.str(255) } },
  { verb: 'browser.clear_storage', title: 'Clear cookies and storage', description: 'Deletes cookies, local storage and caches, signing out of sites.', effects: ['delete'], res: ['browser.tab', 'set'], params: {} },
  { verb: 'browser.tab_open', title: 'Open a tab', description: 'Opens a new tab.', effects: ['create'], rev: 'reversible', res: ['browser.tab', 'set'], params: { url: P.opt(P.url()) } },
  { verb: 'browser.tab_close', title: 'Close a tab', description: 'Closes a tab.', effects: ['delete'], rev: 'rate_limited', res: ['browser.tab', 'set'], params: { tab: P.opt(P.id('browser.tab')) } },
  { verb: 'browser.back', title: 'Go back', description: 'Navigates back in history.', effects: ['read'], res: ['browser.tab', 'set'], params: {} },
  { verb: 'browser.scroll', title: 'Scroll the page', description: 'Scrolls the page.', effects: ['read'], res: ['browser.tab', 'set'], params: { dy: P.int(-100_000, 100_000) } },
  { verb: 'browser.wait_for', title: 'Wait for an element', description: 'Waits until an element appears.', effects: ['read'], res: ['browser.tab', 'set'], params: { selector: P.str(1024), timeout_ms: P.opt(P.int(1, 120_000)) } },
  { verb: 'browser.select_option', title: 'Choose an option', description: 'Selects an option of a drop-down.', effects: ['update'], rev: 'rate_limited', res: ['browser.tab', 'set'], params: { selector: P.str(1024), value: P.str(1024) } },
  { verb: 'browser.press_key', title: 'Press a key', description: 'Sends a key press to the page.', effects: ['update'], rev: 'rate_limited', res: ['browser.tab', 'set'], params: { key: P.str(32) } },
  { verb: 'browser.handle_dialog', title: 'Answer a dialog', description: 'Accepts or dismisses a browser dialog.', effects: ['update'], rev: 'rate_limited', res: ['browser.tab', 'set'], params: { accept: P.bool() } },
  { verb: 'browser.print_pdf', title: 'Save the page as PDF', description: 'Renders the page to a PDF file.', effects: ['read', 'create'], rev: 'reversible', res: ['browser.tab', 'set'], params: { to: P.path() } },

  // ---- computer use (screen, mouse, keyboard)
  { verb: 'computer.screenshot', title: 'Capture the screen', description: 'Captures the screen, which may show private content.', effects: ['read'], traits: ['pca.pii_access'], res: ['computer.screen', 'set'], params: {} },
  { verb: 'computer.click', title: 'Click at a position', description: 'Moves the pointer and clicks.', effects: ['update'], rev: 'irreversible', res: ['computer.screen', 'set'], params: { x: P.int(0, 100_000), y: P.int(0, 100_000), button: P.opt(P.enum(['left', 'right', 'middle'])) } },
  { verb: 'computer.double_click', title: 'Double-click at a position', description: 'Double-clicks, which opens or runs items.', effects: ['update'], rev: 'irreversible', res: ['computer.screen', 'set'], params: { x: P.int(0, 100_000), y: P.int(0, 100_000) } },
  { verb: 'computer.move', title: 'Move the pointer', description: 'Moves the pointer.', effects: ['read'], res: ['computer.screen', 'set'], params: { x: P.int(0, 100_000), y: P.int(0, 100_000) } },
  { verb: 'computer.drag', title: 'Drag the pointer', description: 'Presses, moves and releases the pointer.', effects: ['update'], rev: 'rate_limited', res: ['computer.screen', 'set'], params: { from_x: P.int(0, 100_000), from_y: P.int(0, 100_000), to_x: P.int(0, 100_000), to_y: P.int(0, 100_000) } },
  { verb: 'computer.type', title: 'Type on the keyboard', description: 'Types text into whatever has focus.', effects: ['update'], rev: 'irreversible', res: ['computer.screen', 'set'], params: { text: P.str(100_000) } },
  { verb: 'computer.key', title: 'Press a key combination', description: 'Sends a key or shortcut to whatever has focus.', effects: ['update'], rev: 'irreversible', res: ['computer.screen', 'set'], params: { keys: P.str(64) } },
  { verb: 'computer.scroll', title: 'Scroll', description: 'Scrolls at the pointer.', effects: ['read'], res: ['computer.screen', 'set'], params: { dy: P.int(-100_000, 100_000) } },

  // ---- environment, secrets, clipboard
  { verb: 'env.get', title: 'Read an environment variable', description: 'Reads one variable.', effects: ['read'], res: ['env.variable', 'one'], params: { name: P.id('env.variable', { max_len: 128 }) } },
  { verb: 'env.list', title: 'List environment variables', description: 'Lists variable names.', effects: ['read'], res: ['env.variable', 'set'], params: {} },
  { verb: 'env.set', title: 'Set an environment variable', description: 'Sets a variable for later commands.', effects: ['update'], rev: 'rate_limited', res: ['env.variable', 'one'], params: { name: P.id('env.variable', { max_len: 128 }), value: P.str(32_768) } },
  { verb: 'secrets.read', title: 'Read a stored secret', description: 'Reads a secret from the local secret store.', effects: ['read'], traits: ['pca.credential_access'], res: ['secrets.secret', 'one'], params: { name: P.id('secrets.secret', { max_len: 128 }) } },
  { verb: 'secrets.write', title: 'Store a secret', description: 'Writes a secret to the local secret store.', effects: ['update'], rev: 'rate_limited', traits: ['pca.credential_access'], res: ['secrets.secret', 'one'], params: { name: P.id('secrets.secret', { max_len: 128 }), value: P.secret() } },
  { verb: 'secrets.delete', title: 'Delete a stored secret', description: 'Removes a secret from the local secret store.', effects: ['delete'], res: ['secrets.secret', 'one'], params: { name: P.id('secrets.secret', { max_len: 128 }) } },
  { verb: 'clipboard.read', title: 'Read the clipboard', description: 'Reads clipboard text, which may hold anything the user copied.', effects: ['read'], traits: ['pca.pii_access'], res: ['clipboard.clip', 'set'], params: {} },
  { verb: 'clipboard.write', title: 'Write to the clipboard', description: 'Replaces the clipboard content.', effects: ['update'], rev: 'rate_limited', res: ['clipboard.clip', 'set'], params: { text: P.str(1_000_000) } },

  // ---- operating system
  { verb: 'os.info', title: 'Read system information', description: 'OS, hardware and uptime.', effects: ['read'], res: ['os.system', 'set'], params: {} },
  { verb: 'os.notify', title: 'Show a notification', description: 'Shows a desktop notification.', effects: ['create'], rev: 'reversible', res: ['os.system', 'set'], params: { title: P.str(256), body: P.str(1024) } },
  { verb: 'os.open_url', title: 'Open a URL in the default browser', description: 'Opens a link outside the agent browser.', effects: ['read'], res: ['os.system', 'set'], params: { url: P.url() } },
  { verb: 'os.open_app', title: 'Launch an application', description: 'Starts an installed application.', effects: ['exec'], res: ['os.system', 'set'], params: { app: P.str(512) } },
  { verb: 'os.lock', title: 'Lock the screen', description: 'Locks the session.', effects: ['update'], rev: 'reversible', res: ['os.system', 'set'], params: {} },
  { verb: 'os.reboot', title: 'Restart the machine', description: 'Restarts the computer, ending every session.', effects: ['exec', 'privilege'], res: ['os.system', 'set'], params: { delay_s: P.opt(P.int(0, 86_400)) } },
  { verb: 'os.shutdown', title: 'Shut the machine down', description: 'Powers the computer off.', effects: ['exec', 'privilege'], res: ['os.system', 'set'], params: { delay_s: P.opt(P.int(0, 86_400)) } },
  { verb: 'os.set_clock', title: 'Set the system clock', description: 'Changes system time, which breaks certificates and logs.', effects: ['privilege'], rev: 'rate_limited', res: ['os.system', 'set'], params: { time: P.dt() } },

  // ---- scheduling and agents
  { verb: 'jobs.schedule', title: 'Schedule a recurring job', description: 'Creates a job that runs later or repeatedly.', effects: ['create'], rev: 'reversible', traits: ['pca.scheduled'], res: ['jobs.job', 'set'], params: { schedule: P.str(128), action: P.str(256), params: P.opt(P.obj()) } },
  { verb: 'jobs.cancel', title: 'Cancel a scheduled job', description: 'Removes a scheduled job.', effects: ['delete'], res: ['jobs.job', 'one'], params: { job: P.id('jobs.job') } },
  { verb: 'jobs.list', title: 'List scheduled jobs', description: 'Lists scheduled jobs.', effects: ['read'], res: ['jobs.job', 'set'], params: { limit: P.limit(1000) } },
  { verb: 'jobs.sleep', title: 'Wait', description: 'Pauses for a number of seconds.', effects: ['read'], res: ['jobs.job', 'set'], params: { seconds: P.int(0, 86_400) } },
  { verb: 'agent.spawn', title: 'Start another agent', description: 'Starts a sub-agent with its own task and tools.', effects: ['create', 'exec'], traits: ['pca.agent_spawning'], res: ['agent.agent', 'set'], params: { task: P.str(100_000), tools: P.opt(P.arr('string', 100)) } },
  { verb: 'agent.message', title: 'Message another agent', description: 'Sends a message to another running agent.', effects: ['update'], rev: 'rate_limited', res: ['agent.agent', 'one'], params: { agent: P.id('agent.agent'), message: P.str(100_000) } },
  { verb: 'agent.stop', title: 'Stop an agent', description: 'Stops a running agent.', effects: ['delete'], rev: 'rate_limited', res: ['agent.agent', 'one'], params: { agent: P.id('agent.agent') } },
  { verb: 'mcp.call_tool', title: 'Call an MCP tool', description: 'Calls a tool on an MCP server whose effects are not described here; treated as running code.', effects: ['exec'], res: ['mcp.tool', 'set'], params: { server: P.str(256), tool: P.str(256), arguments: P.opt(P.obj()) } },
];

const SEED_TEXT: Record<string, string> = {
  'files.read': 'Reads the contents of a file.',
  'files.write': 'Creates a file or replaces its contents.',
  'files.delete': 'Deletes a file permanently.',
  'http.get': 'Fetches a URL.',
  'http.post': 'Posts a body to a URL; the remote side may act on it.',
};
const seeds: ActionDef[] = BUILTIN_DEFS.filter((d) => d.verb in SEED_TEXT).map((d) => ({ ...(structuredClone(d) as ActionDef), description: SEED_TEXT[d.verb]! }));

export default handPack({
  name: 'core',
  licence_notes: 'Written in-house from public documentation of standard tools (POSIX utilities, git, docker, ssh, HTTP, WebDriver-style browser control); no third-party text or schema is carried.',
  config_file: __filename,
  sourceUri: 'in-repo:scripts/actions-packs/packs/core.ts',
  defs: [...seeds, ...H1.map(def)],
});
