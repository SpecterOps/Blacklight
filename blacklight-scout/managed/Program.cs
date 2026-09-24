using System;
using System.Collections.Generic;
using System.IO;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace Blacklight.Scout.Managed
{
    internal sealed class Target
    {
        internal Target(string tool, string family, string pattern)
        {
            Tool = tool;
            Family = family;
            Pattern = pattern;
        }

        internal string Tool { get; private set; }
        internal string Family { get; private set; }
        internal string Pattern { get; private set; }
    }

    internal sealed class Options
    {
        internal readonly List<string> IncludeTools = new List<string>();
        internal readonly List<string> ExcludeTools = new List<string>();
        internal int MaxDepth = 1;
        internal int DiscoveryCap = 5000;
        internal string OutPath;
    }

    internal sealed class Result
    {
        internal string Tool;
        internal string Family;
        internal string Type;
        internal string Path;
        internal int PriorityTier;
        internal string ParserHint;
        internal long SizeBytes;
        internal long ChildCount;
        internal bool ChildCountPartial;
        internal bool ChildCountUnavailable;
        internal bool ChildCountDisabled;
        internal bool AutoSelect;
        internal bool IsReparsePoint;
        internal DateTime LastWriteUtc;
        internal bool AnalysisTruncated;
        internal int CredentialKeyTypeCount;
        internal int ConfigSettingCount;
        internal int ConnectorDefinitionCount;
        internal int RuleCount;
        internal int AllowRuleCount;
        internal int DenyRuleCount;
        internal int PermissionSettingCount;
        internal int TokenLikeFieldCount;
        internal int RefreshFieldCount;
        internal int AccountMetadataFieldCount;
        internal int ExpirationFieldCount;
        internal int AuthStateFieldCount;
        internal readonly List<string> SafeSignals = new List<string>();
    }

    internal sealed class SessionCandidate
    {
        internal string Tool;
        internal string Path;
        internal long SizeBytes;
        internal DateTime LastWriteUtc;
    }

    internal sealed class CodexDatabaseFamily
    {
        internal CodexDatabaseFamily(string name)
        {
            Name = name;
        }

        internal string Name;
        internal int Count;
        internal string NewestPath;
        internal string NewestSuffix;
        internal long NewestSize;
        internal DateTime NewestWriteUtc;
    }

    internal static class Program
    {
        private const string Version = "0.2.1";
        private static TextWriter _output = Console.Out;
        private static int _hitCount;
        private static int _directoryCount;
        private static int _fileCount;
        private static int _filteredCount;
        private static int _autoSelectCount;
        private static readonly List<Result> TriageResults = new List<Result>();
        private const int SessionScanLimit = 10000;
        private const int SessionScanMaxDepth = 32;
        private const int MaximumChildCountDepth = 4;
        private const int DirectoryEntryScanLimit = 10000;
        private const int DynamicDiscoveryLimit = 5000;
        private const int DynamicRootLimit = DynamicDiscoveryLimit / 4;
        private const int DynamicDiscoveryMaxDepth = 6;
        private const int MaximumTriageResults = 256;
        private const long TotalInspectionByteLimit = 32L * 1024 * 1024;
        private const int InspectedFileLimit = 64;
        private static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(250);
        private static readonly List<SessionCandidate> TopSessions = new List<SessionCandidate>();
        private static readonly List<SessionCandidate> LargestSessions = new List<SessionCandidate>();
        private static readonly int[] SessionArtifactCounts = new int[5];
        private static readonly HashSet<string> SeenSessionArtifacts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private static readonly List<CodexDatabaseFamily> CodexDatabaseFamilies = new List<CodexDatabaseFamily>();
        private static int _sessionEntriesScanned;
        private static bool _sessionScanPartial;
        private static bool _sessionScanBudgetExhausted;
        private static int _directoryEntriesScanned;
        private static long _inspectionBytesRead;
        private static int _inspectedFileCount;
        private static int _dynamicEntriesScanned;
        private static int _dynamicRootEntriesScanned;
        private static int _dynamicRootLimit = DynamicRootLimit;
        private static int _dynamicDiscoveryLimit = DynamicDiscoveryLimit;
        private static bool _dynamicScanPartial;
        private static bool _triageResultOverflow;
        private static bool _codexDatabaseRootAvailable;
        private static bool _codexDatabaseRootMissing;
        private static bool _codexDatabasePartial;
        private static bool _codexDatabaseCheckRequested;

        private static int Main(string[] args)
        {
            ResetState();
            args = NormalizeApolloArgs(args);
            if (args.Any(arg => arg == "--help" || arg == "-h"))
            {
                Usage(Console.Out);
                return 0;
            }
            if (args.Any(arg => arg == "--version"))
            {
                Console.Out.WriteLine("ai_path_scout-managed {0}", Version);
                return 0;
            }

            Options options;
            if (!TryParseArgs(args, out options))
            {
                Usage(Console.Error);
                return 2;
            }

            StreamWriter outFile = null;
            try
            {
                if (!string.IsNullOrEmpty(options.OutPath))
                {
                    outFile = new StreamWriter(
                        new FileStream(options.OutPath, FileMode.CreateNew, FileAccess.Write, FileShare.None),
                        new UTF8Encoding(false));
                    _output = outFile;
                }

                if (options.IncludeTools.Count > 0)
                {
                    WriteLine("[i] Include filters enabled");
                }

                if (options.ExcludeTools.Count > 0)
                {
                    WriteLine("[i] Exclude filters enabled");
                }

                foreach (var target in GeneratedTargets.Windows)
                {
                    ScanTarget(target, options);
                }

                ScanDynamicTargets(options);
                ScanSessionCandidates();
                PrintHumanTriage();

                return 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("ai_path_scout-managed: {0}", ex.Message);
                return 2;
            }
            finally
            {
                if (outFile != null)
                {
                    outFile.Dispose();
                    _output = Console.Out;
                }
            }
        }

        // Apollo execute_assembly always runs CommandLineToArgvW on AssemblyArguments.
        // When -Arguments is omitted, that string is "", and CommandLineToArgvW("") returns
        // the sacrificial host process path as a single argv entry. Treat that as no args
        // so documented zero-arg triage works under register_assembly / execute_assembly.
        private static string[] NormalizeApolloArgs(string[] args)
        {
            if (args == null || args.Length == 0) return Array.Empty<string>();
            if (args.Length == 1 && IsApolloEmptyArgsGhost(args[0])) return Array.Empty<string>();
            return args;
        }

        private static bool IsApolloEmptyArgsGhost(string arg)
        {
            if (string.IsNullOrWhiteSpace(arg)) return true;
            if (arg[0] == '-') return false;
            return arg.IndexOf('\\') >= 0 || arg.IndexOf('/') >= 0;
        }

        private static bool TryParseArgs(string[] args, out Options options)
        {
            options = new Options();
            for (var i = 0; i < args.Length; i++)
            {
                var arg = args[i];
                if ((arg == "--out") && i + 1 < args.Length) options.OutPath = args[++i];
                else if ((arg == "--include-tool" || arg == "--tool") && i + 1 < args.Length) AddCsv(options.IncludeTools, args[++i]);
                else if (arg == "--exclude-tool" && i + 1 < args.Length) AddCsv(options.ExcludeTools, args[++i]);
                else if (arg == "--max-depth" && i + 1 < args.Length)
                {
                    int parsed;
                    if (!int.TryParse(args[++i], out parsed)) return false;
                    if (parsed < 0 || parsed > MaximumChildCountDepth) return false;
                    options.MaxDepth = parsed;
                }
                else if (arg == "--discovery-cap" && i + 1 < args.Length)
                {
                    int parsed;
                    if (!int.TryParse(args[++i], out parsed) || parsed < 1 || parsed > 1000000) return false;
                    options.DiscoveryCap = parsed;
                }
                else return false;
            }
            return true;
        }

        private static void AddCsv(List<string> values, string csv)
        {
            foreach (var token in csv.Split(','))
            {
                var trimmed = token.Trim();
                if (trimmed.Length > 0) values.Add(trimmed);
            }
        }

        private static void Usage(TextWriter writer)
        {
            writer.WriteLine("Blacklight Scout managed executable {0}", Version);
            writer.WriteLine("usage: ai_path_scout-managed.exe [--out PATH] [filters]");
            writer.WriteLine("  no arguments       run bounded human triage immediately");
            writer.WriteLine("  --out PATH         write output to a file");
            writer.WriteLine("  --max-depth N      directory child-count depth (default: 1, maximum: {0})", MaximumChildCountDepth);
            writer.WriteLine("  --discovery-cap N  dynamic-discovery entry cap (default: {0})", DynamicDiscoveryLimit);
            writer.WriteLine("  --include-tool TOOL | --exclude-tool TOOL");
            writer.WriteLine("  --version          print the executable version");
        }

        private static void ScanTarget(Target target, Options options)
        {
            if (!ToolAllowed(target.Tool, options.IncludeTools, true) ||
                !ToolAllowed(target.Tool, options.ExcludeTools, false))
            {
                _filteredCount++;
                return;
            }

            var path = ExpandPath(target.Pattern);
            if (string.IsNullOrEmpty(path))
            {
                _filteredCount++;
                return;
            }

            FileAttributes attributes;
            try { attributes = File.GetAttributes(path); }
            catch { return; }
            var isDirectory = (attributes & FileAttributes.Directory) != 0;
            var isFile = !isDirectory;
            var isReparsePoint = (attributes & FileAttributes.ReparsePoint) != 0;

            var type = isDirectory ? "directory" : "file";
            _hitCount++;
            if (isDirectory) _directoryCount++;
            if (isFile) _fileCount++;

            EmitTriage(target.Tool, target.Family, type, path, isDirectory, isReparsePoint, options);
        }

        private static string ExpandPath(string pattern)
        {
            var userProfile = Environment.GetEnvironmentVariable("USERPROFILE");
            if (string.IsNullOrEmpty(userProfile))
            {
                userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            }
            return pattern.Replace("%USERPROFILE%", userProfile ?? string.Empty).Replace('/', Path.DirectorySeparatorChar);
        }

        private static bool ToolAllowed(string tool, List<string> filters, bool include)
        {
            if (filters.Count == 0) return true;
            var matched = filters.Any(f => ToolMatches(tool, f));
            return include ? matched : !matched;
        }

        private static bool ToolMatches(string tool, string filter)
        {
            if (EqualsCi(tool, filter)) return true;
            if (EqualsCi(tool, "claude_code")) return EqualsCi(filter, "claude") || EqualsCi(filter, "claude-code");
            if (EqualsCi(tool, "antigravity_cli")) return EqualsCi(filter, "antigravity") || EqualsCi(filter, "antigravity-cli") || EqualsCi(filter, "gemini-antigravity-cli");
            if (EqualsCi(tool, "grok")) return EqualsCi(filter, "grok-cli");
            return false;
        }

        private static void EmitTriage(string tool, string family, string type, string path, bool isDirectory, bool isReparsePoint, Options options)
        {
            var sizeBytes = 0L;
            var childCount = 0L;
            var childCountPartial = false;
            var childCountUnavailable = false;
            if (isDirectory)
            {
                if (isReparsePoint) childCountUnavailable = true;
                else if (options.MaxDepth > 0) childCount = CountDirectoryChildren(path, options.MaxDepth, out childCountPartial, out childCountUnavailable);
            }
            else
            {
                try { sizeBytes = new FileInfo(path).Length; }
                catch { sizeBytes = 0; }
            }

            var sandboxSecret = ContainsCi(path, ".sandbox-secrets");
            var authAdjacentConfig = ContainsCi(path, ".claude.json") &&
                !ContainsCi(path, ".claude/.claude.json") &&
                !ContainsCi(path, ".claude\\.claude.json");
            var mcpNeedsAuthCache = ContainsCi(path, "mcp-needs-auth-cache");
            var secretLike = (!sandboxSecret && !mcpNeedsAuthCache && (ContainsPathToken(path, "auth") || ContainsPathToken(path, "credential") ||
                ContainsPathToken(path, "token") || ContainsPathToken(path, "secret"))) || authAdjacentConfig;
            var tier = TriagePriorityTier(family, secretLike);
            if (sandboxSecret && tier == 1) tier = 2;
            var parserHint = TriageParserHint(family, IsSqlitePath(path));
            var result = new Result
            {
                Tool = tool,
                Family = family,
                Type = type,
                Path = path,
                PriorityTier = tier,
                ParserHint = parserHint,
                SizeBytes = sizeBytes,
                ChildCount = childCount,
                ChildCountPartial = childCountPartial,
                ChildCountUnavailable = childCountUnavailable,
                ChildCountDisabled = isDirectory && options.MaxDepth == 0,
                AutoSelect = tier == 1 && !isDirectory,
                IsReparsePoint = isReparsePoint,
                LastWriteUtc = GetLastWriteUtc(path, isDirectory)
            };
            if (TriageResults.Count >= MaximumTriageResults)
            {
                _triageResultOverflow = true;
                if (result.AutoSelect) _autoSelectCount++;
                return;
            }
            InspectKnownArtifact(result);
            TriageResults.Add(result);

            if (result.AutoSelect)
            {
                _autoSelectCount++;
            }
        }

        private static long CountDirectoryChildren(string path, int depth, out bool partial, out bool unavailable)
        {
            partial = false;
            unavailable = false;
            if (_directoryEntriesScanned >= DirectoryEntryScanLimit)
            {
                partial = true;
                unavailable = true;
                return 0;
            }

            var count = 0L;
            try
            {
                foreach (var entry in Directory.EnumerateFileSystemEntries(path))
                {
                    if (_directoryEntriesScanned >= DirectoryEntryScanLimit)
                    {
                        partial = true;
                        break;
                    }
                    _directoryEntriesScanned++;
                    count++;
                    if (depth > 1)
                    {
                        FileAttributes attributes;
                        try { attributes = File.GetAttributes(entry); }
                        catch (Exception) { partial = true; continue; }
                        if ((attributes & FileAttributes.ReparsePoint) != 0 ||
                            (attributes & FileAttributes.Directory) == 0) continue;

                        bool childPartial;
                        bool childUnavailable;
                        count += CountDirectoryChildren(entry, depth - 1, out childPartial, out childUnavailable);
                        partial = partial || childPartial || childUnavailable;
                        if (_directoryEntriesScanned >= DirectoryEntryScanLimit) break;
                    }
                }
            }
            catch
            {
                if (count == 0) unavailable = true;
                else partial = true;
            }
            return count;
        }

        private static DateTime GetLastWriteUtc(string path, bool directory)
        {
            try { return directory ? Directory.GetLastWriteTimeUtc(path) : File.GetLastWriteTimeUtc(path); }
            catch { return DateTime.MinValue; }
        }

        private static void InspectKnownArtifact(Result result)
        {
            if (!EqualsCi(result.Type, "file")) return;
            if (EqualsCi(result.Tool, "grok"))
            {
                AddSafeSignal(result, "inspection=deferred");
                return;
            }
            if (IsSessionInspectionFamily(result.Family)) return;
            var extension = Path.GetExtension(result.Path);
            if (!(EqualsCi(extension, ".json") || EqualsCi(extension, ".jsonl") || EqualsCi(extension, ".toml") ||
                  EqualsCi(extension, ".rules") || EqualsCi(extension, ".txt"))) return;

            try
            {
                if ((File.GetAttributes(result.Path) & FileAttributes.ReparsePoint) != 0)
                {
                    AddSafeSignal(result, "inspection=skipped_reparse");
                    return;
                }
            }
            catch
            {
                AddSafeSignal(result, "inspection=unavailable");
                return;
            }

            const int maxBytes = 8 * 1024 * 1024;
            if (_inspectedFileCount >= InspectedFileLimit)
            {
                result.AnalysisTruncated = true;
                AddSafeSignal(result, "inspection=budget_exhausted");
                return;
            }
            var remainingBudget = TotalInspectionByteLimit - _inspectionBytesRead;
            if (remainingBudget <= 0)
            {
                result.AnalysisTruncated = true;
                AddSafeSignal(result, "inspection=budget_exhausted");
                return;
            }
            try
            {
                string text;
                _inspectedFileCount++;
                using (var stream = new FileStream(result.Path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                {
                    var length = Math.Min(Math.Min(stream.Length, maxBytes), remainingBudget);
                    var bytes = new byte[(int)length];
                    var offset = 0;
                    while (offset < bytes.Length)
                    {
                        var read = stream.Read(bytes, offset, bytes.Length - offset);
                        if (read <= 0) break;
                        offset += read;
                        _inspectionBytesRead += read;
                    }
                    text = Encoding.UTF8.GetString(bytes, 0, offset);
                    result.AnalysisTruncated = stream.Length > length;
                    if (remainingBudget <= maxBytes && stream.Length > length)
                        AddSafeSignal(result, "inspection=budget_exhausted");
                }

                if (IsAuthInspectionFamily(result.Family))
                {
                    result.CredentialKeyTypeCount = CountKnownKeys(text, new[] {
                        "access_token", "accessToken", "refresh_token", "refreshToken",
                        "api_key", "apiKey", "apikey", "token", "credential", "oauth", "claudeAiOauth"
                    });
                    result.TokenLikeFieldCount = CountKnownKeys(text, new[] {
                        "access_token", "accessToken", "refresh_token", "refreshToken",
                        "api_key", "apiKey", "apikey", "token", "oauth"
                    });
                    result.RefreshFieldCount = CountKnownKeys(text, new[] {
                        "refresh_token", "refreshToken", "refresh", "refresh_expires", "refreshExpires"
                    });
                    result.AccountMetadataFieldCount = CountKnownKeys(text, new[] {
                        "email", "account_id", "accountId", "account", "tenant_id", "tenantId",
                        "workspace_id", "workspaceId", "user_id", "userId"
                    });
                    result.ExpirationFieldCount = CountKnownKeys(text, new[] {
                        "expires", "expires_at", "expiresAt", "expiration", "expiry", "valid_until", "validUntil"
                    });
                    result.AuthStateFieldCount = CountKnownKeys(text, new[] {
                        "auth_state", "authState", "authenticated", "logged_in", "loggedIn", "login_state", "loginState", "status"
                    });
                }

                if (IsConfigInspectionFamily(result.Family))
                {
                    CountAssignmentSignal(result, text, "model_provider");
                    CountAssignmentSignal(result, text, "sandbox_mode");
                    CountAssignmentSignal(result, text, "sandbox");
                    CountAssignmentSignal(result, text, "approval_policy");
                    CountAssignmentSignal(result, text, "model_reasoning_effort");
                    CountAssignmentSignal(result, text, "model");

                    var mcpCount = Regex.Matches(text, @"(?im)^\s*\[\s*mcp_servers\.([A-Za-z0-9_.-]{1,64})\s*\]", RegexOptions.None, RegexTimeout).Count;
                    if (mcpCount > 0) { result.ConnectorDefinitionCount += mcpCount; AddSafeSignal(result, "mcp_definitions=" + mcpCount); }
                    AddProjectTrustSignals(result, text);
                    result.ConfigSettingCount += CountKnownKeys(text, new[] {
                        "permissions", "hooks", "env", "statusLine", "enabledPlugins", "extraKnownMarketplaces",
                        "mcpServers", "theme", "autoUpdates", "installMethod", "hasCompletedOnboarding",
                        "alwaysThinkingEnabled", "includeCoAuthoredBy", "cleanupPeriodDays", "outputStyle",
                        "apiKeyHelper", "language", "teammateMode", "attribution", "feedbackSurveyRate",
                        "projects", "githubRepoPaths", "trust_level"
                    });
                    if (result.ConfigSettingCount > 0) AddSafeSignal(result, "recognized_settings=" + result.ConfigSettingCount);
                    if (result.Family == "rules") CountRuleMetadata(result, text);
                    if (result.Family == "sandbox" || result.Family == "permissions")
                    {
                        result.PermissionSettingCount = CountKnownKeys(text, new[] {
                            "read_roots", "write_roots", "proxy_ports", "allow_local_binding",
                            "sandbox_mode", "approval_policy", "permissions"
                        });
                        if (result.PermissionSettingCount > 0)
                            AddSafeSignal(result, "permission_settings=" + result.PermissionSettingCount);
                    }
                }
            }
            catch (RegexMatchTimeoutException)
            {
                result.AnalysisTruncated = true;
                AddSafeSignal(result, "inspection=regex_timeout");
            }
            catch
            {
                AddSafeSignal(result, "inspection=unavailable");
            }
        }

        private static bool IsAuthInspectionFamily(string family)
        {
            return EqualsCi(family, "auth") || EqualsCi(family, "credential_metadata");
        }

        private static bool IsSessionInspectionFamily(string family)
        {
            return EqualsCi(family, "sessions") || EqualsCi(family, "history") || EqualsCi(family, "transcripts");
        }

        private static bool IsConfigInspectionFamily(string family)
        {
            return EqualsCi(family, "config") || EqualsCi(family, "mcp") || EqualsCi(family, "mcp_config") ||
                EqualsCi(family, "project_config") || EqualsCi(family, "project_mcp_config") || EqualsCi(family, "rules") ||
                EqualsCi(family, "sandbox") || EqualsCi(family, "permissions") || EqualsCi(family, "plugins") ||
                EqualsCi(family, "extensions") || EqualsCi(family, "skills");
        }

        private static void ResetState()
        {
            _output = Console.Out;
            _hitCount = 0;
            _directoryCount = 0;
            _fileCount = 0;
            _filteredCount = 0;
            _autoSelectCount = 0;
            TriageResults.Clear();
            TopSessions.Clear();
            LargestSessions.Clear();
            Array.Clear(SessionArtifactCounts, 0, SessionArtifactCounts.Length);
            SeenSessionArtifacts.Clear();
            _sessionEntriesScanned = 0;
            _sessionScanPartial = false;
            _sessionScanBudgetExhausted = false;
            _directoryEntriesScanned = 0;
            _inspectionBytesRead = 0;
            _inspectedFileCount = 0;
            _dynamicEntriesScanned = 0;
            _dynamicRootEntriesScanned = 0;
            _dynamicRootLimit = DynamicRootLimit;
            _dynamicDiscoveryLimit = DynamicDiscoveryLimit;
            _dynamicScanPartial = false;
            _triageResultOverflow = false;
            _codexDatabaseRootAvailable = false;
            _codexDatabaseRootMissing = false;
            _codexDatabasePartial = false;
            _codexDatabaseCheckRequested = false;
            CodexDatabaseFamilies.Clear();
            foreach (var family in new[] { "logs", "thread_history", "state", "memories", "goals" })
                CodexDatabaseFamilies.Add(new CodexDatabaseFamily(family));
        }

        private static int CountKnownKeys(string text, IEnumerable<string> keys)
        {
            var count = 0;
            foreach (var key in keys)
            {
                if (ContainsKnownKey(text, key)) count++;
            }
            return count;
        }

        private static void ScanDynamicTargets(Options options)
        {
            var profile = Environment.GetEnvironmentVariable("USERPROFILE");
            if (string.IsNullOrEmpty(profile)) profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            var codexAllowed = ToolAllowed("codex", options.IncludeTools, true) && ToolAllowed("codex", options.ExcludeTools, false);
            if (string.IsNullOrEmpty(profile))
            {
                if (codexAllowed)
                {
                    _codexDatabaseCheckRequested = true;
                    _dynamicScanPartial = true;
                }
                return;
            }
            var dynamicTools = new[] { "codex", "claude_code", "cursor", "cursor" };
            var allowedRoots = dynamicTools.Count(tool => ToolAllowed(tool, options.IncludeTools, true) && ToolAllowed(tool, options.ExcludeTools, false));
            if (allowedRoots == 0) return;
            _dynamicDiscoveryLimit = options.DiscoveryCap;
            _dynamicRootLimit = _dynamicDiscoveryLimit / allowedRoots;
            if (codexAllowed) ScanCodexDatabaseFiles(profile);
            ScanNamedFiles("codex", "rules", Path.Combine(profile, ".codex", "rules"), new[] { ".rules" }, false, options);
            ScanNamedFiles("claude_code", "mcp", Path.Combine(profile, ".claude", "projects"), new[] { ".mcp.json", "sessions-index.json" }, true, options);
            ScanNamedFiles("cursor", "mcp", Path.Combine(profile, ".cursor", "projects"), new[] { ".mcp.json" }, true, options);
            ScanNamedFiles("cursor", "plans", Path.Combine(profile, ".cursor", "plans"), new[] { ".plan.md" }, false, options);
        }

        private static void ScanNamedFiles(string tool, string family, string root, string[] namesOrExtensions, bool recursive, Options options)
        {
            if (!Directory.Exists(root) || !ToolAllowed(tool, options.IncludeTools, true) || !ToolAllowed(tool, options.ExcludeTools, false)) return;
            _dynamicRootEntriesScanned = 0;
            WalkDynamicFiles(tool, family, root, namesOrExtensions, recursive ? DynamicDiscoveryMaxDepth : 0, options);
        }

        private static void WalkDynamicFiles(string tool, string family, string directory, string[] namesOrExtensions, int depth, Options options)
        {
            if (depth < 0 || _dynamicEntriesScanned >= _dynamicDiscoveryLimit || _dynamicRootEntriesScanned >= _dynamicRootLimit)
            {
                if (_dynamicEntriesScanned >= _dynamicDiscoveryLimit || _dynamicRootEntriesScanned >= _dynamicRootLimit) _dynamicScanPartial = true;
                return;
            }
            try
            {
                foreach (var entry in Directory.EnumerateFileSystemEntries(directory))
                {
                    if (_dynamicEntriesScanned >= _dynamicDiscoveryLimit || _dynamicRootEntriesScanned >= _dynamicRootLimit) { _dynamicScanPartial = true; return; }
                    _dynamicEntriesScanned++;
                    _dynamicRootEntriesScanned++;
                    FileAttributes attributes;
                    try { attributes = File.GetAttributes(entry); }
                    catch { continue; }
                    if ((attributes & FileAttributes.ReparsePoint) != 0) continue;
                    if ((attributes & FileAttributes.Directory) != 0)
                    {
                        if (depth > 0) WalkDynamicFiles(tool, family, entry, namesOrExtensions, depth - 1, options);
                        continue;
                    }
                    var name = Path.GetFileName(entry);
                    var matched = namesOrExtensions.Any(value => value.StartsWith(".", StringComparison.Ordinal) && !value.Contains("json")
                        ? name.EndsWith(value, StringComparison.OrdinalIgnoreCase)
                        : string.Equals(name, value, StringComparison.OrdinalIgnoreCase));
                    if (!matched || TriageResults.Any(result => string.Equals(result.Path, entry, StringComparison.OrdinalIgnoreCase))) continue;
                    var matchedFamily = EqualsCi(tool, "claude_code") && EqualsCi(name, "sessions-index.json") ? "sessions" : family;
                    ScanTarget(new Target(tool, matchedFamily, entry), options);
                }
            }
            catch { }
        }

        private static bool ContainsKnownKey(string text, string key)
        {
            var start = 0;
            while (start <= text.Length - key.Length)
            {
                var index = text.IndexOf(key, start, StringComparison.OrdinalIgnoreCase);
                if (index < 0) return false;
                var beforeIsBoundary = index == 0 || !IsAsciiKeyCharacter(text[index - 1]);
                var after = index + key.Length;
                var afterIsBoundary = after == text.Length || !IsAsciiKeyCharacter(text[after]);
                if (beforeIsBoundary && afterIsBoundary) return true;
                start = index + 1;
            }
            return false;
        }

        private static bool IsAsciiKeyCharacter(char value)
        {
            return (value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z') ||
                (value >= '0' && value <= '9') || value == '_';
        }

        private static void CountAssignmentSignal(Result result, string text, string key)
        {
            var pattern = "(?im)(?:^\\s*\\uFEFF?" + Regex.Escape(key) + "\\s*=\\s*[\"']|\"" + Regex.Escape(key) + "\"\\s*:\\s*\")([A-Za-z0-9_.-]{1,80})";
            var match = Regex.Match(text, pattern, RegexOptions.None, RegexTimeout);
            if (match.Success)
            {
                result.ConfigSettingCount++;
            }
        }

        private static void AddProjectTrustSignals(Result result, string text)
        {
            var projectCount = Regex.Matches(text, @"(?im)^\s*\[\s*projects\.", RegexOptions.None, RegexTimeout).Count;
            if (projectCount > 0) AddSafeSignal(result, "projects=" + projectCount);
            var trustedCount = Regex.Matches(text, @"(?im)^\s*trust_level\s*=\s*[""']trusted[""']", RegexOptions.None, RegexTimeout).Count;
            if (trustedCount > 0) AddSafeSignal(result, "trusted=" + trustedCount);
        }

        private static string ConfigAnnotationSuffix(Result result)
        {
            var annotations = result.SafeSignals
                .Where(signal => !signal.StartsWith("inspection=", StringComparison.Ordinal) &&
                                 !signal.StartsWith("recognized_settings=", StringComparison.Ordinal))
                .ToList();
            if (annotations.Count == 0) return string.Empty;
            return " | " + string.Join(" | ", annotations);
        }

        private static void CountRuleMetadata(Result result, string text)
        {
            using (var reader = new StringReader(text))
            {
                string line;
                while ((line = reader.ReadLine()) != null)
                {
                    var trimmed = line.Trim().TrimStart('\uFEFF');
                    if (trimmed.Length == 0 || trimmed.StartsWith("#") || trimmed.StartsWith("//")) continue;
                    result.RuleCount++;
                    if (Regex.IsMatch(trimmed, "(?:^allow\\b|\\bdecision\\s*=\\s*['\"]allow['\"])", RegexOptions.IgnoreCase, RegexTimeout)) result.AllowRuleCount++;
                    else if (Regex.IsMatch(trimmed, "(?:^deny\\b|\\bdecision\\s*=\\s*['\"]deny['\"])", RegexOptions.IgnoreCase, RegexTimeout)) result.DenyRuleCount++;
                }
            }
        }

        private static void AddSafeSignal(Result result, string signal)
        {
            if (!result.SafeSignals.Contains(signal) && result.SafeSignals.Count < 12) result.SafeSignals.Add(signal);
        }

        private static void PrintHumanTriage()
        {
            var sorted = TriageResults.OrderBy(r => r.PriorityTier).ThenBy(r => r.Tool).ThenBy(r => r.Family).ThenBy(r => r.Path, StringComparer.OrdinalIgnoreCase).ToList();
            WriteLine("[i] Blacklight endpoint assessment");
            WriteLine("[i]");
            if (sorted.Count == 0)
            {
                PrintAssessmentSummary(sorted);
                PrintCodexDatabaseSummary();
                WriteLine("[i]   0 artifacts found");
                return;
            }

            PrintAssessmentSummary(sorted);
            var tools = ToolPresentationOrder(sorted).ToList();
            if (!tools.Contains("codex", StringComparer.Ordinal)) PrintCodexDatabaseSummary();
            foreach (var tool in tools)
            {
                if (tool == "codex") PrintCodexDatabaseSummary();
                PrintToolAssessment(sorted, tool);
            }
            PrintSessionFiles("PRIORITIZED SESSION ARTIFACTS (newest first)", TopSessions);
            PrintSessionFiles("LARGEST SESSION ARTIFACTS", LargestSessions);
            PrintOtherRecognizedPaths(sorted);
            if (_triageResultOverflow) WriteLine("[!] Result storage cap reached at {0} artifacts. Results are incomplete.", MaximumTriageResults);
            if (_dynamicScanPartial)
            {
                WriteLine("[!] Discovery cap reached after {0} candidate entries (per-root cap {1}; run cap {2}).", _dynamicEntriesScanned, _dynamicRootLimit, _dynamicDiscoveryLimit);
                WriteLine("[!] Results are incomplete. Increase --discovery-cap to continue.");
            }

        }

        private static void ScanCodexDatabaseFiles(string profile)
        {
            _codexDatabaseCheckRequested = true;
            var root = Path.Combine(profile, ".codex");
            FileAttributes rootAttributes;
            try { rootAttributes = File.GetAttributes(root); }
            catch (FileNotFoundException)
            {
                _codexDatabaseRootMissing = true;
                return;
            }
            catch (DirectoryNotFoundException)
            {
                _codexDatabaseRootMissing = true;
                return;
            }
            catch
            {
                _dynamicScanPartial = true;
                return;
            }
            if ((rootAttributes & FileAttributes.Directory) == 0 || (rootAttributes & FileAttributes.ReparsePoint) != 0)
            {
                _dynamicScanPartial = true;
                return;
            }

            _codexDatabaseRootAvailable = true;
            try
            {
                foreach (var entry in Directory.EnumerateFileSystemEntries(root))
                {
                    if (_dynamicEntriesScanned >= _dynamicDiscoveryLimit || _dynamicRootEntriesScanned >= _dynamicRootLimit)
                    {
                        _codexDatabasePartial = true;
                        _dynamicScanPartial = true;
                        break;
                    }
                    _dynamicEntriesScanned++;
                    _dynamicRootEntriesScanned++;
                    var name = Path.GetFileName(entry);
                    CodexDatabaseFamily matchedFamily = null;
                    string matchedSuffix = null;
                    foreach (var family in CodexDatabaseFamilies)
                    {
                        string suffix;
                        if (!TryCodexDatabaseSuffix(name, family.Name, out suffix)) continue;
                        matchedFamily = family;
                        matchedSuffix = suffix;
                        break;
                    }
                    if (matchedFamily == null) continue;
                    FileAttributes attributes;
                    try { attributes = File.GetAttributes(entry); }
                    catch
                    {
                        _codexDatabasePartial = true;
                        _dynamicScanPartial = true;
                        continue;
                    }
                    if ((attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0) continue;

                    try
                    {
                        var info = new FileInfo(entry);
                        var size = info.Length;
                        var modified = info.LastWriteTimeUtc;
                        matchedFamily.Count++;
                        if (matchedFamily.NewestPath == null || IsNewerCodexDatabase(entry, matchedSuffix, modified, matchedFamily))
                        {
                            matchedFamily.NewestPath = entry;
                            matchedFamily.NewestSuffix = matchedSuffix;
                            matchedFamily.NewestSize = size;
                            matchedFamily.NewestWriteUtc = modified;
                        }
                    }
                    catch
                    {
                        _codexDatabasePartial = true;
                        _dynamicScanPartial = true;
                    }
                }
            }
            catch
            {
                _codexDatabasePartial = true;
                _dynamicScanPartial = true;
            }
        }

        private static bool TryCodexDatabaseSuffix(string name, string family, out string suffix)
        {
            suffix = null;
            var prefix = family + "_";
            if (name.Length <= prefix.Length + ".sqlite".Length ||
                !name.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) ||
                !name.EndsWith(".sqlite", StringComparison.OrdinalIgnoreCase)) return false;
            suffix = name.Substring(prefix.Length, name.Length - prefix.Length - ".sqlite".Length);
            if (suffix.Length == 0) return false;
            foreach (var digit in suffix)
                if (digit < '0' || digit > '9') return false;
            return true;
        }

        private static string NormalizeNumericSuffix(string suffix)
        {
            var index = 0;
            while (index < suffix.Length - 1 && suffix[index] == '0') index++;
            return suffix.Substring(index);
        }

        private static bool IsNewerCodexDatabase(string path, string suffix, DateTime modified, CodexDatabaseFamily current)
        {
            var timeComparison = DateTime.Compare(modified, current.NewestWriteUtc);
            if (timeComparison != 0) return timeComparison > 0;
            var candidateNumber = NormalizeNumericSuffix(suffix);
            var currentNumber = NormalizeNumericSuffix(current.NewestSuffix);
            if (candidateNumber.Length != currentNumber.Length) return candidateNumber.Length > currentNumber.Length;
            var numericComparison = string.Compare(candidateNumber, currentNumber, StringComparison.Ordinal);
            if (numericComparison != 0) return numericComparison > 0;
            return string.Compare(Path.GetFileName(path), Path.GetFileName(current.NewestPath), StringComparison.Ordinal) > 0;
        }

        private static void PrintCodexDatabaseSummary()
        {
            if (!_codexDatabaseCheckRequested || CodexDatabaseFamilies.Count == 0) return;
            WriteLine("[i] CODEX SQLITE DATABASES");
            foreach (var family in CodexDatabaseFamilies)
            {
                if (_codexDatabaseRootMissing)
                {
                    WriteLine("    {0}: absent (0 versions)", family.Name);
                    continue;
                }
                if (!_codexDatabaseRootAvailable)
                {
                    WriteLine("    {0}: unknown (Codex root unavailable)", family.Name);
                    continue;
                }
                if (_codexDatabasePartial)
                {
                    WriteLine("    {0}: partial ({1}){2}", family.Name,
                        CountLabel(family.Count, "version observed", "versions observed"), CodexDatabaseNewestSummary(family));
                    if (family.NewestPath != null) WriteLine("        {0}", family.NewestPath);
                    continue;
                }
                if (family.Count == 0)
                {
                    WriteLine("    {0}: absent (0 versions)", family.Name);
                    continue;
                }
                WriteLine("    {0}: present ({1}){2}", family.Name,
                    CountLabel(family.Count, "version", "versions"), CodexDatabaseNewestSummary(family));
                if (family.NewestPath != null) WriteLine("        {0}", family.NewestPath);
            }
            WriteLine("[i]");
        }

        private static string CodexDatabaseNewestSummary(CodexDatabaseFamily family)
        {
            if (family.NewestPath == null) return string.Empty;
            return string.Format(CultureInfo.InvariantCulture,
                " | newest observed {0} | modified {1:yyyy-MM-dd'T'HH:mm:ss'Z'}",
                FormatSize(family.NewestSize), family.NewestWriteUtc);
        }

        private static IEnumerable<string> ToolPresentationOrder(List<Result> rows)
        {
            var preferred = new[] { "codex", "claude_code", "cursor", "antigravity_cli", "grok" };
            var present = new HashSet<string>(rows.Select(result => result.Tool), StringComparer.Ordinal);
            foreach (var tool in preferred) if (present.Remove(tool)) yield return tool;
            foreach (var tool in present.OrderBy(value => value, StringComparer.Ordinal)) yield return tool;
        }

        private static string ToolDisplayName(string tool)
        {
            if (tool == "codex") return "CODEX";
            if (tool == "claude_code") return "CLAUDE CODE";
            if (tool == "cursor") return "CURSOR";
            if (tool == "antigravity_cli") return "ANTIGRAVITY CLI";
            if (tool == "grok") return "GROK";
            return tool.Replace('_', ' ').ToUpperInvariant();
        }

        private static void PrintAssessmentSummary(List<Result> rows)
        {
            var toolRows = ToolPresentationOrder(rows).ToList();
            var auth = rows.Where(result => CompactCategory(result) == 3).ToList();
            var refreshTools = ToolPresentationOrder(auth.Where(result => result.RefreshFieldCount > 0).ToList())
                .Select(ToolDisplayName).ToList();
            var trusted = rows.Sum(result => SignalCount(result, "trusted="));
            var sessions = rows.Count(result => CompactCategory(result) == 4);
            var recentTools = ToolPresentationOrder(rows.Where(result => CompactCategory(result) == 4 && result.LastWriteUtc != DateTime.MinValue).ToList())
                .Select(ToolDisplayName).ToList();
            WriteLine("[i] ASSESSMENT SUMMARY");
            WriteLine("[i]   Tools detected:       {0}", toolRows.Count);
            if (auth.Count > 0) WriteLine("[+]   Credential stores:    {0}", CountLabel(auth.Count, "file", "files"));
            if (refreshTools.Count > 0) WriteLine("[+]   Refresh material:     {0}", string.Join(", ", refreshTools));
            if (trusted > 0) WriteLine("[+]   Trusted projects:     {0}", trusted);
            if (sessions > 0) WriteLine("[i]   Session locations:    {0}", sessions);
            if (sessions > 0 || _sessionScanPartial) WriteLine("[i]   Session artifacts:    {0}{1}", SessionArtifactCounts.Sum(), _sessionScanPartial ? " (partial scan)" : string.Empty);
            if (recentTools.Count > 0) WriteLine("[i]   Recent activity:      {0}", string.Join(", ", recentTools));
            WriteLine(_triageResultOverflow || _dynamicScanPartial || _sessionScanPartial ? "[!]   Discovery status:     PARTIAL" : "[i]   Discovery status:     COMPLETE");
            WriteLine("[i]");
        }

        private static int SignalCount(Result result, string prefix)
        {
            var signal = result.SafeSignals.FirstOrDefault(value => value.StartsWith(prefix, StringComparison.Ordinal));
            int parsedValue;
            return signal != null && int.TryParse(signal.Substring(prefix.Length), out parsedValue) ? parsedValue : 0;
        }

        private static int CompactCategory(Result result)
        {
            if (result.Type == "file" && (result.Family == "config" || result.Family == "mcp")) return 1;
            if (result.Type == "file" && (result.Family == "rules" || result.Family == "permissions" || result.Family == "sandbox")) return 2;
            if (result.Type == "file" && result.Family == "auth") return 3;
            if (result.Family == "sessions" || result.Family == "history" ||
                (result.Family == "workspace" && (result.Tool == "claude_code" || result.Tool == "cursor"))) return 4;
            return 0;
        }

        private static string CountLabel(int count, string singular, string plural)
        {
            return count + " " + (count == 1 ? singular : plural);
        }

        private static string HealthSuffix(List<Result> rows)
        {
            var partial = rows.Count(result => result.AnalysisTruncated);
            var unreadable = rows.Count(IsInspectionUnavailable);
            var labels = new List<string>();
            if (partial > 0) labels.Add(CountLabel(partial, "partial", "partial"));
            if (unreadable > 0) labels.Add(CountLabel(unreadable, "unreadable", "unreadable"));
            return labels.Count == 0 ? string.Empty : ", " + string.Join(", ", labels);
        }

        private static void PrintToolAssessment(List<Result> rows, string tool)
        {
            var toolRows = rows.Where(result => result.Tool == tool).ToList();
            var config = toolRows.Where(result => CompactCategory(result) == 1).ToList();
            var rules = toolRows.Where(result => CompactCategory(result) == 2).ToList();
            var auth = toolRows.Where(result => CompactCategory(result) == 3).ToList();
            var sessions = toolRows.Where(result => CompactCategory(result) == 4).ToList();
            var toolSlot = SessionToolSlot(tool);
            var sessionArtifacts = toolSlot >= 0 ? SessionArtifactCounts[toolSlot] : 0;

            WriteLine("[i] {0}", ToolDisplayName(tool));
            if (auth.Count > 0) WriteLine("[+]   {0} | {1}{2}{3}", CountLabel(auth.Count, "credential file", "credential files"),
                CountLabel(auth.Sum(result => result.TokenLikeFieldCount), "suspected credential field", "suspected credential fields"),
                auth.Sum(result => result.RefreshFieldCount) > 0 ? " | refresh token indicator present" : string.Empty, HealthSuffix(auth));
            if (rules.Count > 0) WriteLine("[i]   {0} | {1}", CountLabel(rules.Count, "rules file", "rules files"), CountLabel(rules.Sum(result => result.AllowRuleCount), "allow rule", "allow rules"));
            if (config.Count > 0) WriteLine("[i]   {0} | {1}{2}", CountLabel(config.Count, "config file", "config files"), CountLabel(config.Sum(result => result.ConfigSettingCount), "recognized setting", "recognized settings"), HealthSuffix(config));
            if (sessions.Count > 0 || sessionArtifacts > 0) {
                var latest = TopSessions.Where(result => result.Tool == tool).Select(result => result.LastWriteUtc).DefaultIfEmpty(DateTime.MinValue).Max();
                WriteLine("[i]   {0} | {1}{2}{3}", CountLabel(sessions.Count, "session location", "session locations"), CountLabel(sessionArtifacts, "session artifact", "session artifacts"), _sessionScanPartial ? " (partial scan)" : string.Empty, latest == DateTime.MinValue ? HealthSuffix(sessions) : " | latest activity " + latest.ToString("yyyy-MM-dd") + HealthSuffix(sessions));
            }
            WriteLine("[i]");

            if (auth.Count > 0)
            {
                WriteLine("[+] AUTHENTICATION ARTIFACTS");
                var refresh = auth.Sum(result => result.RefreshFieldCount) > 0 ? " | refresh token indicator present" : string.Empty;
                WriteLine("    {0}{1}", CountLabel(auth.Sum(result => result.TokenLikeFieldCount), "suspected credential field", "suspected credential fields"), refresh);
                foreach (var result in auth) WriteLine("    {0}", result.Path);
                WriteLine("");
            }
            if (rules.Count > 0)
            {
                WriteLine("[i] RULES");
                WriteLine("    {0} allow rules | {1} deny rules", rules.Sum(result => result.AllowRuleCount), rules.Sum(result => result.DenyRuleCount));
                foreach (var result in rules) WriteLine("    {0}", result.Path);
                WriteLine("");
            }
            if (config.Count > 0)
            {
                WriteLine("[i] CONFIGURATION");
                for (var index = 0; index < config.Count; index++)
                {
                    var result = config[index];
                    WriteLine("    {0}{1}", CountLabel(result.ConfigSettingCount, "recognized setting", "recognized settings"), ConfigAnnotationSuffix(result));
                    WriteLine("    {0}", result.Path);
                    if (index + 1 < config.Count) WriteLine("");
                }
                WriteLine("");
            }
            if (sessions.Count > 0)
            {
                WriteLine("[i] SESSION LOCATIONS");
                foreach (var result in sessions) WriteLine("    {0}", result.Path);
                WriteLine("");
            }
        }

        private static void PrintOtherRecognizedPaths(List<Result> rows)
        {
            var count = rows.Where(result => CompactCategory(result) == 0)
                .Select(result => result.Path).Distinct(StringComparer.OrdinalIgnoreCase).Count();
            if (count > 0) WriteLine("[i] Additional candidate artifacts: {0}", count);
        }

        private static int AssessmentCategory(Result result)
        {
            if (IsAuthInspectionFamily(result.Family)) return 3;
            if (result.Family == "rules" || result.Family == "permissions" || result.Family == "sandbox") return 2;
            if (IsConfigInspectionFamily(result.Family)) return 1;
            return 0;
        }

        private static int MetadataFieldCount(Result result)
        {
            var count = result.CredentialKeyTypeCount + result.ConfigSettingCount + result.ConnectorDefinitionCount + result.RuleCount +
                result.PermissionSettingCount +
                result.TokenLikeFieldCount + result.RefreshFieldCount + result.AccountMetadataFieldCount +
                result.ExpirationFieldCount + result.AuthStateFieldCount;
            return count > 0 ? count : result.SafeSignals.Count(signal => !signal.StartsWith("inspection=", StringComparison.Ordinal));
        }

        private static bool MetadataParsed(Result result)
        {
            var extension = Path.GetExtension(result.Path);
            var inspectable = EqualsCi(extension, ".json") || EqualsCi(extension, ".jsonl") || EqualsCi(extension, ".toml") ||
                EqualsCi(extension, ".rules") || EqualsCi(extension, ".txt");
            return result.Type == "file" && inspectable && !IsInspectionUnavailable(result) &&
                !result.SafeSignals.Contains("inspection=deferred");
        }

        private static void PrintAssessmentCategory(List<Result> rows, int category, string title)
        {
            WriteLine("[i] {0}. {1}", category, title);
            var selected = rows.Where(result => AssessmentCategory(result) == category).ToList();
            if (selected.Count == 0) WriteLine("[i]   none");
            foreach (var result in selected)
            {
                WriteLine("[i]   {0} {1}", result.Tool, result.Family);
                WriteLine("[i]     Parsed: {0}{1}", MetadataParsed(result) ? "yes" : "no", result.AnalysisTruncated ? " (partial)" : "");
                WriteLine("[i]     Metadata fields: {0}", MetadataFieldCount(result));
                if (category == 1)
                {
                    WriteLine("[i]     Recognized settings: {0}", result.ConfigSettingCount);
                    WriteLine("[i]     Connector definitions: {0}", result.ConnectorDefinitionCount);
                }
                else if (category == 2)
                {
                    WriteLine("[i]     Rules: {0}", result.RuleCount);
                    WriteLine("[i]     Allow entries: {0}", result.AllowRuleCount);
                    WriteLine("[i]     Deny entries: {0}", result.DenyRuleCount);
                    WriteLine("[i]     Permission settings: {0}", result.PermissionSettingCount);
                }
                else if (category == 3)
                {
                    WriteLine("[i]     Secret-like fields: {0}", result.CredentialKeyTypeCount);
                    WriteLine("[i]     Token-like fields: {0}", result.TokenLikeFieldCount);
                    WriteLine("[i]     Refresh-related fields: {0}", result.RefreshFieldCount);
                    WriteLine("[i]     Account-metadata fields: {0}", result.AccountMetadataFieldCount);
                    WriteLine("[i]     Expiration fields: {0}", result.ExpirationFieldCount);
                    WriteLine("[i]     Authentication-state fields: {0}", result.AuthStateFieldCount);
                }
                WriteLine("[i]     Path: {0}", result.Path);
            }
            WriteLine("[i]");
        }

        private static void PrintCollectNow(List<Result> rows)
        {
            var selected = rows.Where(r => r.AutoSelect).ToList();
            var containers = rows.Where(r => !r.AutoSelect).ToList();
            WriteLine("[i] Collect now ({0} artifact(s), {1})", selected.Count, FormatSize(selected.Sum(r => r.SizeBytes)));
            if (selected.Count == 0) WriteLine("[i]   none");
            foreach (var r in selected)
            {
                var credential = r.CredentialKeyTypeCount > 0 ? ", credential key types=" + r.CredentialKeyTypeCount : "";
                var health = IsInspectionUnavailable(r) ? ", inspection unavailable" : (r.AnalysisTruncated ? ", partial" : "");
                WriteLine("[i]   [1] {0} {1} - {2}{3}{4}", r.Tool, r.Family, FormatSize(r.SizeBytes), credential, health);
                WriteLine("[i]       {0}", r.Path);
            }
            if (containers.Count > 0)
            {
                WriteLine("[i] Auth containers requiring review");
                foreach (var r in containers)
                {
                    WriteLine("[i]   [1] {0} {1} - auth_container_review", r.Tool, r.Family);
                    WriteLine("[i]       {0}", r.Path);
                }
            }
            WriteLine("[i]");
        }

        private static void PrintCapabilities(List<Result> rows)
        {
            WriteLine("[i] Capabilities and security configuration");
            if (rows.Count == 0) { WriteLine("[i]   none"); WriteLine("[i]"); return; }
            foreach (var group in rows.GroupBy(r => r.Tool).OrderBy(g => g.Key))
            {
                var list = group.ToList();
                var hasConfig = list.Any(r => IsConfigCapabilityFamily(r.Family));
                var hasRules = list.Any(r => r.Family == "rules");
                var hasPlugins = list.Any(r => r.Family == "plugins" || r.Family == "extensions" || r.Family == "skills");
                var hasSandbox = list.Any(r => r.Family == "sandbox" || ContainsCi(r.Path, ".sandbox-secrets"));
                var hasOther = list.Any(r => !(IsConfigCapabilityFamily(r.Family) || r.Family == "rules" || r.Family == "sandbox" ||
                    r.Family == "plugins" || r.Family == "extensions" || r.Family == "skills" || ContainsCi(r.Path, ".sandbox-secrets")));
                var labels = new List<string>();
                if (hasConfig) labels.Add("config");
                if (hasRules) labels.Add("rules");
                if (hasPlugins) labels.Add("plugins");
                if (hasSandbox) labels.Add("sandbox");
                if (hasOther || labels.Count == 0) labels.Add("review");
                var type = list.All(r => r.Type == "file") ? "files" : (list.All(r => r.Type == "directory") ? "dirs" : "artifacts");
                WriteLine("[i]   [2] {0} {1} {2} x{3}", group.Key, string.Join("/", labels), type, list.Count);
                foreach (var r in list)
                {
                    var annotations = r.SafeSignals.Where(s => s != "inspection=unavailable").ToList();
                    if (r.AnalysisTruncated) annotations.Add("partial");
                    if (IsInspectionUnavailable(r)) annotations.Add("inspection unavailable");
                    WriteLine("[i]       {0}{1}", r.Path, annotations.Count > 0 ? " (" + string.Join(", ", annotations) + ")" : "");
                }
            }
            WriteLine("[i]");
        }

        private static bool IsConfigCapabilityFamily(string family)
        {
            return family == "config" || family == "mcp" || family == "mcp_config" ||
                family == "project_config" || family == "project_mcp_config" || family == "permissions";
        }

        private static void PrintSessions(List<Result> rows)
        {
            WriteLine("[i] 4. Session candidates");
            if (rows.Count == 0) { WriteLine("[i]   none"); WriteLine("[i]"); return; }
            foreach (var group in rows.GroupBy(r => r.Tool)
                .OrderByDescending(g => g.Count()).ThenByDescending(g => g.Max(r => r.SizeBytes)).ThenBy(g => g.Key))
            {
                var list = group.ToList();
                var latest = list.Max(r => r.LastWriteUtc);
                var partial = list.Count(r => r.AnalysisTruncated);
                var unavailable = list.Count(IsInspectionUnavailable);
                WriteLine("[i]   [3] {0} history/session artifacts x{1}{2}{3}{4}", group.Key, list.Count,
                    latest == DateTime.MinValue ? "" : ", latest=" + latest.ToString("yyyy-MM-dd"),
                    partial > 0 ? ", partial=" + partial : "",
                    unavailable > 0 ? ", unreadable=" + unavailable : "");
                foreach (var r in list) WriteLine("[i]       {0}", r.Path);
            }
            WriteLine("[i]");
        }

        private static void PrintInventory(List<Result> rows)
        {
            WriteLine("[i] Other inventory");
            if (rows.Count == 0) { WriteLine("[i]   none"); WriteLine("[i]"); return; }
            foreach (var group in rows.GroupBy(r => new { r.PriorityTier, r.Family }).OrderBy(g => g.Key.PriorityTier).ThenBy(g => g.Key.Family))
            {
                var list = group.OrderBy(r => r.Path, StringComparer.OrdinalIgnoreCase).ToList();
                var type = list.All(r => r.Type == "directory") ? "dirs" : (list.All(r => r.Type == "file") ? "files" : "artifacts");
                WriteLine("[i]   [{0}] {1} {2} x{3}", group.Key.PriorityTier, group.Key.Family, type, list.Count);
                foreach (var r in list) WriteLine("[i]       {0}", r.Path);
            }
            WriteLine("[i]");
        }

        private static bool IsRecognizedSessionFile(string tool, string path)
        {
            if (EqualsCi(tool, "codex"))
                return ContainsCi(path, "sessions") && path.EndsWith(".jsonl", StringComparison.OrdinalIgnoreCase);
            if (EqualsCi(tool, "claude_code"))
                return (ContainsCi(path, "sessions") || ContainsCi(path, "projects")) &&
                    path.EndsWith(".jsonl", StringComparison.OrdinalIgnoreCase);
            if (EqualsCi(tool, "cursor"))
                return path.EndsWith("store.db", StringComparison.OrdinalIgnoreCase) ||
                    (ContainsCi(path, "agent-transcripts") && path.EndsWith(".jsonl", StringComparison.OrdinalIgnoreCase));
            if (EqualsCi(tool, "antigravity_cli"))
                return path.EndsWith("transcript_full.jsonl", StringComparison.OrdinalIgnoreCase) ||
                    path.EndsWith("transcript.jsonl", StringComparison.OrdinalIgnoreCase) ||
                    path.EndsWith("conversation_summaries.db", StringComparison.OrdinalIgnoreCase) ||
                    (ContainsCi(path, "conversations") && path.EndsWith(".db", StringComparison.OrdinalIgnoreCase));
            if (EqualsCi(tool, "grok"))
                return path.EndsWith("updates.jsonl", StringComparison.OrdinalIgnoreCase);
            return false;
        }

        private static int SessionToolSlot(string tool)
        {
            if (EqualsCi(tool, "codex")) return 0;
            if (EqualsCi(tool, "claude_code")) return 1;
            if (EqualsCi(tool, "cursor")) return 2;
            if (EqualsCi(tool, "antigravity_cli")) return 3;
            if (EqualsCi(tool, "grok")) return 4;
            return -1;
        }

        private static bool CanContainSessionFiles(Result result)
        {
            if (result.Type != "directory" || result.IsReparsePoint) return false;
            if (result.Family == "sessions" || result.Family == "history") return true;
            return result.Family == "workspace" && (result.Tool == "claude_code" || result.Tool == "cursor");
        }

        private static void ConsiderSessionCandidate(string tool, string path)
        {
            if (!IsRecognizedSessionFile(tool, path)) return;
            try
            {
                if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0) return;
                var info = new FileInfo(path);
                var toolSlot = SessionToolSlot(tool);
                if (toolSlot < 0 || !SeenSessionArtifacts.Add(path)) return;
                SessionArtifactCounts[toolSlot]++;
                var candidate = new SessionCandidate { Tool = tool, Path = path, SizeBytes = info.Length, LastWriteUtc = info.LastWriteTimeUtc };
                RetainSessionCandidate(TopSessions, candidate, false);
                RetainSessionCandidate(LargestSessions, candidate, true);
            }
            catch (Exception) { _sessionScanPartial = true; }
        }

        private static void WalkSessionFiles(string tool, string directory, int depth)
        {
            if (depth > SessionScanMaxDepth) { _sessionScanPartial = true; return; }
            try
            {
                foreach (var entry in Directory.EnumerateFileSystemEntries(directory))
                {
                    if (_sessionEntriesScanned >= SessionScanLimit)
                    {
                        _sessionScanPartial = true;
                        _sessionScanBudgetExhausted = true;
                        return;
                    }
                    _sessionEntriesScanned++;
                    FileAttributes attributes;
                    try { attributes = File.GetAttributes(entry); }
                    catch (Exception) { _sessionScanPartial = true; continue; }
                    if ((attributes & FileAttributes.ReparsePoint) != 0) continue;
                    if ((attributes & FileAttributes.Directory) != 0) WalkSessionFiles(tool, entry, depth + 1);
                    else ConsiderSessionCandidate(tool, entry);
                    if (_sessionScanBudgetExhausted) return;
                }
            }
            catch (Exception) { _sessionScanPartial = true; }
        }

        private static void ScanSessionCandidates()
        {
            TopSessions.Clear();
            _sessionEntriesScanned = 0;
            _sessionScanPartial = false;
            _sessionScanBudgetExhausted = false;
            var visitedRoots = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var roots = new List<KeyValuePair<string, string>>();
            foreach (var result in TriageResults)
            {
                if (CanContainSessionFiles(result))
                {
                    string root;
                    try { root = Path.GetFullPath(result.Path).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar); }
                    catch (Exception) { root = result.Path; }
                    if (visitedRoots.Add(root)) roots.Add(new KeyValuePair<string, string>(result.Tool, root));
                }
                else if (result.Type == "file") ConsiderSessionCandidate(result.Tool, result.Path);
            }
            foreach (var root in roots)
            {
                WalkSessionFiles(root.Key, root.Value, 0);
                if (_sessionScanBudgetExhausted) break;
            }
        }

        private static void RetainSessionCandidate(List<SessionCandidate> candidates, SessionCandidate candidate, bool largestFirst)
        {
            candidates.Add(candidate);
            var order = new[] { "codex", "claude_code", "cursor", "antigravity_cli", "grok" };
            candidates.Sort((left, right) =>
            {
                var toolComparison = Array.IndexOf(order, left.Tool).CompareTo(Array.IndexOf(order, right.Tool));
                if (toolComparison != 0) return toolComparison;
                var primary = largestFirst ? right.SizeBytes.CompareTo(left.SizeBytes) : right.LastWriteUtc.CompareTo(left.LastWriteUtc);
                if (primary != 0) return primary;
                var secondary = largestFirst ? right.LastWriteUtc.CompareTo(left.LastWriteUtc) : right.SizeBytes.CompareTo(left.SizeBytes);
                if (secondary != 0) return secondary;
                return string.Compare(left.Path, right.Path, StringComparison.OrdinalIgnoreCase);
            });
            foreach (var extra in candidates.Where(value => value.Tool == candidate.Tool).Skip(3).ToList()) candidates.Remove(extra);
        }

        private static void PrintSessionFiles(string heading, List<SessionCandidate> candidates)
        {
            WriteLine("[i] {0}{1}", heading, _sessionScanPartial ? " (partial scan)" : string.Empty);
            if (candidates.Count == 0) WriteLine("[i]   none");
            string previousTool = null;
            var rank = 0;
            for (var index = 0; index < candidates.Count; index++)
            {
                var result = candidates[index];
                if (result.Tool != previousTool) { previousTool = result.Tool; rank = 0; }
                rank++;
                var project = ExtractProjectName(result.Tool, result.Path);
                WriteLine("[+] [{0}] {1} | {2} | modified {3}{4}", rank, ToolDisplayName(result.Tool),
                    FormatSize(result.SizeBytes), result.LastWriteUtc.ToString("yyyy-MM-dd"),
                    string.IsNullOrEmpty(project) ? string.Empty : " | project=" + project);
                WriteLine("        {0}", result.Path);
            }
            WriteLine("[i]");
        }

        private static string ExtractProjectName(string tool, string path)
        {
            var parts = path.Replace(Path.AltDirectorySeparatorChar, Path.DirectorySeparatorChar)
                .Split(new[] { Path.DirectorySeparatorChar }, StringSplitOptions.RemoveEmptyEntries);
            for (var index = 0; index + 1 < parts.Length; index++)
            {
                if ((EqualsCi(tool, "claude_code") || EqualsCi(tool, "cursor")) && EqualsCi(parts[index], "projects"))
                {
                    var encoded = parts[index + 1];
                    var separator = encoded.LastIndexOf('-');
                    return separator >= 0 && separator + 1 < encoded.Length ? encoded.Substring(separator + 1) : encoded;
                }
            }
            return null;
        }

        private static bool IsInspectionUnavailable(Result result)
        {
            return result.SafeSignals.Contains("inspection=unavailable");
        }

        private static string FormatSize(long value)
        {
            if (value < 1024) return value + " B";
            if (value < 1024 * 1024) return (value / 1024.0).ToString("0.0") + " KB";
            return (value / (1024.0 * 1024.0)).ToString("0.0") + " MB";
        }

        private static int TriagePriorityTier(string family, bool secretLikePath)
        {
            if (EqualsCi(family, "auth") || EqualsCi(family, "credential_metadata") || secretLikePath) return 1;
            if (EqualsCi(family, "config") || EqualsCi(family, "mcp") || EqualsCi(family, "mcp_config") ||
                EqualsCi(family, "project_config") || EqualsCi(family, "project_mcp_config") || EqualsCi(family, "rules") ||
                EqualsCi(family, "sandbox") || EqualsCi(family, "permissions") || EqualsCi(family, "plugins") ||
                EqualsCi(family, "extensions") || EqualsCi(family, "skills")) return 2;
            if (EqualsCi(family, "sessions") || EqualsCi(family, "history") || EqualsCi(family, "transcripts")) return 3;
            if (EqualsCi(family, "workspace") || EqualsCi(family, "state") || EqualsCi(family, "telemetry") ||
                EqualsCi(family, "plans") || EqualsCi(family, "worktrees") || EqualsCi(family, "snapshots")) return 4;
            return 5;
        }

        private static string TriageParserHint(string family, bool sqlitePath)
        {
            if (sqlitePath || EqualsCi(family, "state") || EqualsCi(family, "telemetry")) return "sqlite-metadata";
            return ParserHintForFamily(family);
        }

        private static string ParserHintForFamily(string family)
        {
            if (EqualsCi(family, "auth") || EqualsCi(family, "credential_metadata")) return "credential-session-metadata";
            if (EqualsCi(family, "sessions") || EqualsCi(family, "history") || EqualsCi(family, "transcripts")) return "session-detail";
            if (EqualsCi(family, "config") || EqualsCi(family, "mcp") || EqualsCi(family, "mcp_config") ||
                EqualsCi(family, "project_config") || EqualsCi(family, "project_mcp_config") || EqualsCi(family, "rules") ||
                EqualsCi(family, "sandbox") || EqualsCi(family, "permissions") || EqualsCi(family, "plugins") ||
                EqualsCi(family, "extensions") || EqualsCi(family, "skills")) return "config-rules";
            if (EqualsCi(family, "state") || EqualsCi(family, "telemetry")) return "sqlite-metadata";
            if (EqualsCi(family, "workspace")) return "inventory-only";
            return "unknown";
        }

        private static bool IsSqlitePath(string path)
        {
            return ContainsCi(path, ".db") || ContainsCi(path, ".sqlite");
        }

        private static bool ContainsPathToken(string path, string token)
        {
            return Regex.IsMatch(path, "(^|[^A-Za-z0-9])" + Regex.Escape(token) + "([^A-Za-z0-9]|$)", RegexOptions.IgnoreCase, RegexTimeout);
        }

        private static bool ContainsCi(string value, string needle)
        {
            return value != null && value.IndexOf(needle, StringComparison.OrdinalIgnoreCase) >= 0;
        }

        private static bool EqualsCi(string left, string right)
        {
            return string.Equals(left, right, StringComparison.OrdinalIgnoreCase);
        }

        private static void WriteLine(string format, params object[] args)
        {
            _output.WriteLine(format, args);
        }
    }
}
