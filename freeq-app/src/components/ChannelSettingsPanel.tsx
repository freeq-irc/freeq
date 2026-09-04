import { useState, useEffect, useCallback } from 'react';
import { useStore } from '../store';
import { rawCommand } from '../irc/client';
import { AuditTimeline } from './AuditTimeline';

interface PolicyInfo {
  policy?: {
    channel_id: string;
    version: number;
    policy_id?: string;
    requirements: any;
    role_requirements: Record<string, any>;
    credential_endpoints: Record<string, {
      issuer: string;
      url: string;
      label: string;
      description?: string;
    }>;
    effective_at: string;
  };
  authority_set?: any;
}

// Presets for common credential types
const VERIFIER_PRESETS: {
  id: string;
  label: string;
  icon: string;
  description: string;
  credentialType: string;
  buildUrl: (param: string) => string;
  placeholder: string;
  paramLabel: string;
}[] = [
  {
    id: 'github_repo',
    label: 'GitHub Repo Collaborator',
    icon: '🐙',
    description: 'Require push access to a GitHub repository',
    credentialType: 'github_repo',
    buildUrl: (repo) => `/verify/github/start?repo=${encodeURIComponent(repo)}`,
    placeholder: 'owner/repo',
    paramLabel: 'Repository',
  },
  {
    id: 'github_org',
    label: 'GitHub Org Member',
    icon: '🏢',
    description: 'Require membership in a GitHub organization',
    credentialType: 'github_membership',
    buildUrl: (org) => `/verify/github/start?org=${encodeURIComponent(org)}`,
    placeholder: 'org-name',
    paramLabel: 'Organization',
  },
  {
    id: 'bluesky_follower',
    label: 'Bluesky Follower',
    icon: '🦋',
    description: 'Require the user to follow a Bluesky account',
    credentialType: 'bluesky_follower',
    buildUrl: (handle) => `/verify/bluesky/start?target=${encodeURIComponent(handle)}`,
    placeholder: 'handle.bsky.social',
    paramLabel: 'Bluesky Handle',
  },
  {
    id: 'moderator',
    label: 'Moderator',
    icon: '🛡️',
    description: 'Appoint moderators who can kick/ban users and set voice (+h)',
    credentialType: 'channel_moderator',
    buildUrl: (_) => '/verify/mod/start',
    placeholder: '',
    paramLabel: '',
  },
];

export function ChannelSettingsPanel() {
  const settingsChannel = useStore((s) => s.channelSettingsOpen);
  const setOpen = useStore((s) => s.setChannelSettingsOpen);

  if (!settingsChannel) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm" onClick={() => setOpen(null)}>
      <div className="bg-bg-secondary border border-border rounded-xl shadow-2xl w-full max-w-3xl h-[80vh] flex flex-col overflow-hidden" onClick={(e) => e.stopPropagation()}>
        <SettingsContent channel={settingsChannel} onClose={() => setOpen(null)} />
      </div>
    </div>
  );
}

const POLICY_EXAMPLES = [
  {
    label: 'Code of Conduct',
    icon: '📜',
    description: 'Require users to accept community guidelines before joining',
    rulesText: 'Be respectful. No harassment, spam, or hate speech. Violations result in removal.',
  },
  {
    label: 'GitHub Contributors',
    icon: '🐙',
    description: 'Only repo collaborators can join — great for project channels',
    rulesText: 'This channel is for project contributors. Verify your GitHub access to join.',
  },
  {
    label: 'Bluesky Community',
    icon: '🦋',
    description: 'Require following a Bluesky account to join',
    rulesText: 'Follow our community account on Bluesky to access this channel.',
  },
];

function NoPolicySetup({ rulesText, setRulesText, saving, handleSetRules }: {
  rulesText: string;
  setRulesText: (v: string) => void;
  saving: boolean;
  handleSetRules: () => void;
}) {
  const [showCustom, setShowCustom] = useState(false);

  return (
    <div className="space-y-4">
      <div className="text-center py-2">
        <div className="text-3xl mb-2">🛡️</div>
        <p className="text-base text-fg font-semibold">Set up channel access</p>
        <p className="text-xs text-fg-dim mt-1 max-w-xs mx-auto leading-relaxed">
          Channel policies let you control who can join. Start with a template or write your own rules.
        </p>
      </div>

      {/* Quick templates */}
      <div className="space-y-2">
        <label className="block text-xs text-fg-dim uppercase tracking-wide">Quick start</label>
        {POLICY_EXAMPLES.map((ex) => (
          <button
            key={ex.label}
            onClick={() => { setRulesText(ex.rulesText); setShowCustom(true); }}
            className="w-full text-left p-3 bg-bg border border-border rounded-lg hover:border-accent/50 transition-colors group"
          >
            <div className="flex items-center gap-2.5">
              <span className="text-lg">{ex.icon}</span>
              <div className="flex-1 min-w-0">
                <p className="text-sm font-medium text-fg group-hover:text-accent transition-colors">{ex.label}</p>
                <p className="text-xs text-fg-dim">{ex.description}</p>
              </div>
              <svg className="w-4 h-4 text-fg-dim group-hover:text-accent" viewBox="0 0 20 20" fill="currentColor">
                <path fillRule="evenodd" d="M7.21 14.77a.75.75 0 01.02-1.06L11.168 10 7.23 6.29a.75.75 0 111.04-1.08l4.5 4.25a.75.75 0 010 1.08l-4.5 4.25a.75.75 0 01-1.06-.02z" clipRule="evenodd" />
              </svg>
            </div>
          </button>
        ))}
      </div>

      {/* Custom or selected rules */}
      {!showCustom ? (
        <button
          onClick={() => setShowCustom(true)}
          className="w-full p-2.5 border border-dashed border-border rounded-lg text-sm text-fg-dim hover:border-accent hover:text-accent transition-colors"
        >
          ✏️ Write custom rules
        </button>
      ) : (
        <div className="animate-fadeIn">
          <label className="block text-xs text-fg-dim uppercase tracking-wide mb-2">
            Channel rules
          </label>
          <textarea
            value={rulesText}
            onChange={(e) => setRulesText(e.target.value)}
            placeholder="Describe the rules users must accept to join this channel..."
            rows={3}
            autoFocus
            className="w-full bg-bg border border-border rounded-lg p-3 text-sm text-fg placeholder-fg-dim resize-none focus:outline-none focus:border-accent"
          />
          <div className="flex items-center justify-between mt-2">
            <p className="text-[10px] text-fg-dim">
              Users will see these rules and must accept to join.
            </p>
            <button
              onClick={handleSetRules}
              disabled={!rulesText.trim() || saving}
              className="px-4 py-1.5 text-sm font-medium bg-accent text-bg rounded-lg hover:bg-accent/90 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {saving ? 'Saving…' : 'Set Policy'}
            </button>
          </div>
        </div>
      )}

      {/* Docs link */}
      <div className="border-t border-border pt-3 mt-3">
        <a
          href="https://github.com/freeq-irc/freeq/blob/main/docs/POLICY.md"
          target="_blank"
          rel="noopener noreferrer"
          className="flex items-center gap-2 text-xs text-fg-dim hover:text-accent transition-colors group"
        >
          <svg className="w-3.5 h-3.5 text-fg-dim group-hover:text-accent" viewBox="0 0 20 20" fill="currentColor">
            <path d="M9 4.804A7.968 7.968 0 005.5 4c-1.255 0-2.443.29-3.5.804v10A7.969 7.969 0 015.5 14c1.669 0 3.218.51 4.5 1.385A7.962 7.962 0 0114.5 14c1.255 0 2.443.29 3.5.804v-10A7.968 7.968 0 0014.5 4c-1.255 0-2.443.29-3.5.804V14a.5.5 0 01-1 0V4.804z" />
          </svg>
          <span>Read the policy documentation</span>
          <svg className="w-3 h-3 opacity-50" viewBox="0 0 20 20" fill="currentColor">
            <path fillRule="evenodd" d="M5.22 14.78a.75.75 0 001.06 0l7.22-7.22v5.69a.75.75 0 001.5 0v-7.5a.75.75 0 00-.75-.75h-7.5a.75.75 0 000 1.5h5.69l-7.22 7.22a.75.75 0 000 1.06z" clipRule="evenodd" />
          </svg>
        </a>
      </div>
    </div>
  );
}

function SettingsContent({ channel, onClose }: { channel: string; onClose: () => void }) {
  const nick = useStore((s) => s.nick);
  const channels = useStore((s) => s.channels);
  const ch = channels.get(channel.toLowerCase());
  const myMember = ch?.members.get(nick.toLowerCase());
  const isOp = myMember?.isOp ?? false;

  const [tab, setTab] = useState<'rules' | 'requirements' | 'roles' | 'audit'>('rules');
  const [policy, setPolicy] = useState<PolicyInfo | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Rules tab state
  const [rulesText, setRulesText] = useState('');
  const [saving, setSaving] = useState(false);

  // Requirements tab state
  const [showAddVerifier, setShowAddVerifier] = useState(false);
  const [selectedPreset, setSelectedPreset] = useState<string | null>(null);
  const [presetParam, setPresetParam] = useState('');
  const [addingVerifier, setAddingVerifier] = useState(false);

  // Roles tab state
  const [roleCredType, setRoleCredType] = useState('');
  const [roleName, setRoleName] = useState('op');
  const [addingRole, setAddingRole] = useState(false);

  const fetchPolicy = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const encoded = encodeURIComponent(channel);
      const res = await fetch(`/api/v1/policy/${encoded}`);
      if (res.status === 404) {
        setPolicy(null);
        setLoading(false);
        return;
      }
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setPolicy(data);
    } catch (e: any) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }, [channel]);

  useEffect(() => { fetchPolicy(); }, [fetchPolicy]);

  const handleSetRules = () => {
    if (!rulesText.trim()) return;
    setSaving(true);
    rawCommand(`POLICY ${channel} SET ${rulesText.trim()}`);
    setTimeout(() => {
      fetchPolicy();
      setSaving(false);
    }, 1000);
  };

  const handleAddVerifier = () => {
    const preset = VERIFIER_PRESETS.find((p) => p.id === selectedPreset);
    if (!preset || !presetParam.trim()) return;

    setAddingVerifier(true);
    const issuerDid = `did:web:${window.location.hostname}:verify`;
    const url = preset.buildUrl(presetParam.trim());
    const label = preset.label.replace(/ /g, '_');

    rawCommand(`POLICY ${channel} REQUIRE ${preset.credentialType} issuer=${issuerDid} url=${url} label=${label}`);

    setTimeout(() => {
      fetchPolicy();
      setAddingVerifier(false);
      setShowAddVerifier(false);
      setSelectedPreset(null);
      setPresetParam('');
    }, 1000);
  };

  const handleAddRole = () => {
    if (!roleCredType.trim()) return;
    setAddingRole(true);

    const issuerDid = `did:web:${window.location.hostname}:verify`;
    const requirement = JSON.stringify({
      type: 'PRESENT',
      credential_type: roleCredType.trim(),
      issuer: issuerDid,
    });

    rawCommand(`POLICY ${channel} SET-ROLE ${roleName} ${requirement}`);

    setTimeout(() => {
      fetchPolicy();
      setAddingRole(false);
      setRoleCredType('');
    }, 1000);
  };

  const handleClearPolicy = () => {
    if (!confirm(`Remove all policy from ${channel}? This cannot be undone.`)) return;
    rawCommand(`POLICY ${channel} CLEAR`);
    setTimeout(() => {
      fetchPolicy();
    }, 1000);
  };

  const tabs = [
    { id: 'rules' as const, label: 'Rules' },
    { id: 'requirements' as const, label: 'Verifiers' },
    { id: 'roles' as const, label: 'Roles' },
    { id: 'audit' as const, label: 'Audit' },
  ];

  return (
    <>
      {/* Header */}
      <div className="px-6 pt-5 pb-0 border-b border-border">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h2 className="text-lg font-bold text-fg flex items-center gap-2">
              <svg className="w-4 h-4 text-fg-dim" viewBox="0 0 20 20" fill="currentColor">
                <path fillRule="evenodd" d="M11.49 3.17c-.38-1.56-2.6-1.56-2.98 0a1.532 1.532 0 01-2.286.948c-1.372-.836-2.942.734-2.106 2.106.54.886.061 2.042-.947 2.287-1.561.379-1.561 2.6 0 2.978a1.532 1.532 0 01.947 2.287c-.836 1.372.734 2.942 2.106 2.106a1.532 1.532 0 012.287.947c.379 1.561 2.6 1.561 2.978 0a1.533 1.533 0 012.287-.947c1.372.836 2.942-.734 2.106-2.106a1.533 1.533 0 01.947-2.287c1.561-.379 1.561-2.6 0-2.978a1.532 1.532 0 01-.947-2.287c.836-1.372-.734-2.942-2.106-2.106a1.532 1.532 0 01-2.287-.947zM10 13a3 3 0 100-6 3 3 0 000 6z" clipRule="evenodd" />
              </svg>
              Channel Settings
            </h2>
            <p className="text-sm text-fg-dim">{channel}</p>
          </div>
          <button onClick={onClose} className="text-fg-dim hover:text-fg p-1 -mr-1">
            <svg className="w-5 h-5" viewBox="0 0 20 20" fill="currentColor">
              <path fillRule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" />
            </svg>
          </button>
        </div>
        {/* Tabs */}
        <div className="flex gap-1">
          {tabs.map((t) => (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              className={`px-4 py-2 text-sm font-medium rounded-t-lg transition-colors ${
                tab === t.id
                  ? 'bg-bg text-fg border-b-2 border-accent'
                  : 'text-fg-dim hover:text-fg-muted'
              }`}
            >
              {t.label}
            </button>
          ))}
        </div>
      </div>

      {/* Body */}
      <div className="flex-1 overflow-y-auto px-6 py-4">
        {loading && (
          <div className="flex items-center justify-center py-8">
            <div className="w-6 h-6 border-2 border-accent border-t-transparent rounded-full animate-spin" />
          </div>
        )}

        {error && (
          <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-3 text-sm text-red-400 mb-4">
            {error}
          </div>
        )}

        {!loading && tab === 'rules' && (
          <div className="space-y-4">
            {policy?.policy ? (
              <div className="bg-bg rounded-lg border border-border p-3">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs text-fg-dim uppercase tracking-wide">Current Policy (v{policy.policy.version})</span>
                  {isOp && (
                    <button
                      onClick={handleClearPolicy}
                      className="text-xs text-red-400 hover:text-red-300"
                    >
                      Remove policy
                    </button>
                  )}
                </div>
                <p className="text-sm text-fg-muted">{describeRequirements(policy.policy.requirements)}</p>
                <details className="mt-2">
                  <summary className="text-[10px] text-fg-dim cursor-pointer hover:text-fg-muted">
                    Policy DSL · {policy.policy.policy_id?.slice(0, 12)}…
                  </summary>
                  <pre className="mt-1 text-[10px] text-fg-dim font-mono bg-bg-tertiary rounded p-2 overflow-x-auto whitespace-pre-wrap break-all">
{describeRequirementsTechnical(policy.policy.requirements)}
{'\n'}policy_id={policy.policy.policy_id}
{'\n'}version={policy.policy.version}
                  </pre>
                </details>
              </div>
            ) : isOp ? (
              /* Guided setup for ops when no policy exists */
              <NoPolicySetup rulesText={rulesText} setRulesText={setRulesText} saving={saving} handleSetRules={handleSetRules} />
            ) : (
              /* Read-only view for non-ops */
              <div className="text-center py-6">
                <div className="text-3xl mb-2">🔓</div>
                <p className="text-sm text-fg-muted font-medium">Open Channel</p>
                <p className="text-xs text-fg-dim mt-1">
                  This channel has no access policy — anyone can join and participate.
                </p>
              </div>
            )}

            {isOp && policy?.policy && (
              <div>
                <label className="block text-xs text-fg-dim uppercase tracking-wide mb-2">
                  Update rules
                </label>
                <textarea
                  value={rulesText}
                  onChange={(e) => setRulesText(e.target.value)}
                  placeholder="e.g., By participating you agree to our Code of Conduct."
                  rows={3}
                  className="w-full bg-bg border border-border rounded-lg p-3 text-sm text-fg placeholder-fg-dim resize-none focus:outline-none focus:border-accent"
                />
                <button
                  onClick={handleSetRules}
                  disabled={!rulesText.trim() || saving}
                  className="mt-2 px-4 py-1.5 text-sm font-medium bg-accent text-bg rounded-lg hover:bg-accent/90 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {saving ? 'Saving…' : 'Update Policy'}
                </button>
              </div>
            )}
          </div>
        )}

        {!loading && tab === 'requirements' && (
          <div className="space-y-4">
            {!policy?.policy && (
              <div className="text-center py-4">
                <div className="text-2xl mb-2">🔑</div>
                <p className="text-sm text-fg-muted font-medium">No verifiers configured</p>
                <p className="text-xs text-fg-dim mt-1 max-w-xs mx-auto">
                  Set channel rules on the Rules tab first, then add verifiers here to require credentials for access.
                </p>
              </div>
            )}

            {/* Existing credential endpoints */}
            {policy?.policy?.credential_endpoints && Object.keys(policy.policy.credential_endpoints).length > 0 && (
              <div>
                <label className="block text-xs text-fg-dim uppercase tracking-wide mb-2">Active verifiers</label>
                <div className="space-y-2">
                  {Object.entries(policy.policy.credential_endpoints).map(([type, ep]) => (
                    <div key={type} className="bg-bg border border-border rounded-lg p-3 flex items-center gap-3">
                      <div className="w-8 h-8 rounded-lg bg-bg-tertiary flex items-center justify-center text-lg">
                        {type.includes('github') ? '🐙' : type.includes('bluesky') ? '🦋' : '🔑'}
                      </div>
                      <div className="flex-1 min-w-0">
                        <p className="text-sm font-medium text-fg">{ep.label}</p>
                        <p className="text-xs text-fg-dim truncate">{type} · {ep.issuer}</p>
                      </div>
                      <span className="text-xs text-green-400 bg-green-500/10 px-2 py-0.5 rounded-full">Active</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Add verifier (ops only) */}
            {isOp && policy?.policy && !showAddVerifier && (
              <button
                onClick={() => setShowAddVerifier(true)}
                className="w-full p-3 border border-dashed border-border rounded-lg text-sm text-fg-dim hover:border-accent hover:text-accent transition-colors"
              >
                + Add credential verifier
              </button>
            )}

            {showAddVerifier && (
              <div className="bg-bg border border-border rounded-lg p-4 space-y-3">
                <label className="block text-xs text-fg-dim uppercase tracking-wide">Choose verifier type</label>
                <div className="grid grid-cols-1 gap-2">
                  {VERIFIER_PRESETS.map((preset) => (
                    <button
                      key={preset.id}
                      onClick={() => { setSelectedPreset(preset.id); setPresetParam(''); }}
                      className={`text-left p-3 rounded-lg border transition-colors ${
                        selectedPreset === preset.id
                          ? 'border-accent bg-accent/5'
                          : 'border-border hover:border-fg-dim'
                      }`}
                    >
                      <div className="flex items-center gap-2">
                        <span className="text-lg">{preset.icon}</span>
                        <span className="text-sm font-medium text-fg">{preset.label}</span>
                      </div>
                      <p className="text-xs text-fg-dim mt-1 ml-7">{preset.description}</p>
                    </button>
                  ))}
                </div>

                {selectedPreset && (
                  <div className="pt-2">
                    {(() => {
                      const preset = VERIFIER_PRESETS.find((p) => p.id === selectedPreset)!;
                      return (
                        <>
                          <label className="block text-xs text-fg-dim mb-1">{preset.paramLabel}</label>
                          <input
                            value={presetParam}
                            onChange={(e) => setPresetParam(e.target.value)}
                            placeholder={preset.placeholder}
                            className="w-full bg-bg-secondary border border-border rounded-lg px-3 py-2 text-sm text-fg placeholder-fg-dim focus:outline-none focus:border-accent"
                            onKeyDown={(e) => e.key === 'Enter' && handleAddVerifier()}
                          />
                        </>
                      );
                    })()}
                  </div>
                )}

                <div className="flex justify-end gap-2 pt-1">
                  <button
                    onClick={() => { setShowAddVerifier(false); setSelectedPreset(null); }}
                    className="px-3 py-1.5 text-xs text-fg-dim hover:text-fg"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={handleAddVerifier}
                    disabled={!selectedPreset || !presetParam.trim() || addingVerifier}
                    className="px-4 py-1.5 text-xs font-medium bg-accent text-bg rounded-lg hover:bg-accent/90 disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    {addingVerifier ? 'Adding…' : 'Add Verifier'}
                  </button>
                </div>
              </div>
            )}
          </div>
        )}

        {!loading && tab === 'roles' && (
          <div className="space-y-4">
            {!policy?.policy && (
              <div className="text-center py-4">
                <div className="text-2xl mb-2">👑</div>
                <p className="text-sm text-fg-muted font-medium">No role rules configured</p>
                <p className="text-xs text-fg-dim mt-1 max-w-xs mx-auto">
                  Set channel rules and add verifiers first. Then configure which credentials auto-grant op, moderator, or voice status.
                </p>
              </div>
            )}

            {/* Existing role requirements */}
            {policy?.policy?.role_requirements && Object.keys(policy.policy.role_requirements).length > 0 && (
              <div>
                <label className="block text-xs text-fg-dim uppercase tracking-wide mb-2">Role escalation rules</label>
                <div className="space-y-2">
                  {Object.entries(policy.policy.role_requirements).map(([role, req]) => (
                    <div key={role} className="bg-bg border border-border rounded-lg p-3">
                      <div className="flex items-center gap-2 mb-1">
                        {(role === 'op' || role === 'admin' || role === 'owner') && (
                          <span className="text-yellow-400 text-xs">⚡</span>
                        )}
                        <span className="text-sm font-medium text-fg">{role}</span>
                        <span className="text-xs text-fg-dim">→ {role === 'op' || role === 'admin' || role === 'owner' ? '+o' : role === 'moderator' || role === 'halfop' ? '+h' : role === 'voice' ? '+v' : 'no mode'}</span>
                      </div>
                      <p className="text-xs text-fg-dim ml-5">{describeRequirements(req)}</p>
                      <p className="text-[10px] text-fg-dim ml-5 font-mono opacity-60 mt-0.5">{describeRequirementsTechnical(req)}</p>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Add role (ops only) */}
            {isOp && policy?.policy && (
              <div className="bg-bg border border-border rounded-lg p-4 space-y-3">
                <label className="block text-xs text-fg-dim uppercase tracking-wide">Auto-assign role by credential</label>

                <div className="grid grid-cols-2 gap-2">
                  <div>
                    <label className="block text-xs text-fg-dim mb-1">Role</label>
                    <select
                      value={roleName}
                      onChange={(e) => setRoleName(e.target.value)}
                      className="w-full bg-bg-secondary border border-border rounded-lg px-3 py-2 text-sm text-fg focus:outline-none focus:border-accent"
                    >
                      <option value="op">Op (+o)</option>
                      <option value="moderator">Moderator (+h)</option>
                      <option value="voice">Voice (+v)</option>
                      <option value="admin">Admin (+o)</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-xs text-fg-dim mb-1">Requires credential</label>
                    <select
                      value={roleCredType}
                      onChange={(e) => setRoleCredType(e.target.value)}
                      className="w-full bg-bg-secondary border border-border rounded-lg px-3 py-2 text-sm text-fg focus:outline-none focus:border-accent"
                    >
                      <option value="">Select…</option>
                      {/* Active verifiers on this channel */}
                      {policy?.policy?.credential_endpoints && Object.keys(policy.policy.credential_endpoints).map((type) => (
                        <option key={type} value={type}>{CRED_LABELS[type] || type}</option>
                      ))}
                      {/* Built-in types not yet added as verifiers */}
                      {VERIFIER_PRESETS
                        .filter((p) => !policy?.policy?.credential_endpoints?.[p.credentialType])
                        .map((p) => (
                          <option key={p.credentialType} value={p.credentialType}>
                            {p.label} (not yet verified)
                          </option>
                        ))
                      }
                    </select>
                  </div>
                </div>

                <div className="flex justify-end">
                  <button
                    onClick={handleAddRole}
                    disabled={!roleCredType || addingRole}
                    className="px-4 py-1.5 text-xs font-medium bg-accent text-bg rounded-lg hover:bg-accent/90 disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    {addingRole ? 'Adding…' : 'Add Role Rule'}
                  </button>
                </div>
              </div>
            )}
          </div>
        )}

        {tab === 'audit' && (
          <div className="h-full">
            <AuditTimeline channel={channel} onClose={onClose} />
          </div>
        )}
      </div>
    </>
  );
}

/** Friendly credential type labels. */
const CRED_LABELS: Record<string, string> = {
  github_repo: 'GitHub repo collaborator',
  github_membership: 'GitHub org member',
  bluesky_follower: 'Bluesky follower',
  channel_moderator: 'Moderator appointment',
};

/** Describe a requirement tree as human-readable text. */
function describeRequirements(req: any): string {
  if (!req) return 'None';
  switch (req.type) {
    case 'ACCEPT':
      return `Accept channel rules`;
    case 'PRESENT': {
      const label = CRED_LABELS[req.credential_type] || req.credential_type?.replace(/_/g, ' ');
      return `Require ${label} credential`;
    }
    case 'PROVE':
      return `Prove: ${req.proof_type}`;
    case 'ALL':
      return (req.requirements || []).map(describeRequirements).join(' + ');
    case 'ANY':
      return 'Any of: ' + (req.requirements || []).map(describeRequirements).join(' or ');
    case 'NOT':
      return `Not: ${describeRequirements(req.requirement)}`;
    default:
      return JSON.stringify(req).slice(0, 60);
  }
}

/** Describe a requirement with technical details for the tooltip/detail view. */
function describeRequirementsTechnical(req: any): string {
  if (!req) return '';
  switch (req.type) {
    case 'ACCEPT':
      return `ACCEPT hash=${req.hash?.slice(0, 16)}…`;
    case 'PRESENT':
      return `PRESENT type=${req.credential_type} issuer=${req.issuer || 'any'}`;
    case 'ALL':
      return `ALL(${(req.requirements || []).map(describeRequirementsTechnical).join(', ')})`;
    case 'ANY':
      return `ANY(${(req.requirements || []).map(describeRequirementsTechnical).join(', ')})`;
    default:
      return JSON.stringify(req).slice(0, 80);
  }
}
