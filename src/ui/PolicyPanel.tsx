import { useEffect, useRef, useState } from 'react';
import type { RedactionPolicy } from '../core/contracts.ts';
import { BASELINE_SENSITIVE_KEYS, DEFAULT_REDACTION_POLICY, exportRedactionPolicy, parseRedactionPolicy, validateRedactionPolicy } from '../core/policy.ts';

interface Props {
  active?: RedactionPolicy;
  busy: boolean;
  hasText: boolean;
  onApply: (policy: RedactionPolicy) => Promise<void>;
}

export default function PolicyPanel({ active, busy, hasText, onApply }: Props) {
  const [draft, setDraft] = useState<RedactionPolicy>(DEFAULT_REDACTION_POLICY);
  const [extraKeys, setExtraKeys] = useState('');
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [confirmed, setConfirmed] = useState(false);
  const input = useRef<HTMLInputElement>(null);
  const savedUrl = useRef<string | null>(null);
  useEffect(() => () => { if (savedUrl.current) URL.revokeObjectURL(savedUrl.current); }, []);

  const change = (value: RedactionPolicy) => { setDraft(value); setConfirmed(false); setNotice(''); setError(''); };
  const current = () => validateRedactionPolicy({
    ...draft,
    sensitiveKeys: [...BASELINE_SENSITIVE_KEYS, ...extraKeys.split(',').map(key => key.trim()).filter(Boolean)],
  });
  const load = async (file?: File) => {
    if (!file || busy) return;
    setError(''); setNotice('');
    try {
      if (file.size < 1 || file.size > 64 * 1024) throw new Error('Policy files must be between 1 byte and 64 KiB.');
      const policy = parseRedactionPolicy(new TextDecoder('utf-8', { fatal: true }).decode(await file.arrayBuffer()));
      setExtraKeys(policy.sensitiveKeys.filter(key => !BASELINE_SENSITIVE_KEYS.includes(key)).join(', '));
      change(policy);
      setNotice('Policy loaded for inspection. Apply it to use it.');
    } catch (cause) { setError(cause instanceof Error ? cause.message : 'The policy could not be read.'); }
  };
  const save = () => {
    setError('');
    try {
      const policy = current();
      const url = URL.createObjectURL(new Blob([exportRedactionPolicy(policy)], { type: 'application/json' }));
      if (savedUrl.current) URL.revokeObjectURL(savedUrl.current);
      savedUrl.current = url;
      const anchor = document.createElement('a'); anchor.href = url; anchor.download = 'bugpack-policy.json'; anchor.click();
      setNotice('Policy downloaded. It contains your literal match values; keep it private.');
    } catch (cause) { setError(cause instanceof Error ? cause.message : 'The policy could not be saved.'); }
  };
  const apply = async () => {
    setError(''); setNotice('');
    try { await onApply(current()); setNotice('Policy applied. Review the cleaned evidence again.'); setConfirmed(false); }
    catch (cause) { setError(cause instanceof Error ? cause.message : 'The policy could not be applied.'); }
  };

  return <details className="policy-panel">
    <summary>Cleaning policy <span>{active?.name ?? 'BugPack default'} · {active?.bodyMode === 'supported' ? 'supported bodies' : 'bodies omitted'}</span></summary>
    <div className="policy-content">
      <p>Authorization and cookies are always removed. Save a policy to reuse your extra rules; evidence and policies are not saved automatically.</p>
      <fieldset disabled={busy} className="policy-fields">
        <label>Policy name<input value={draft.name} maxLength={80} onChange={event => change({ ...draft, name: event.currentTarget.value })} /></label>
        <label>HAR body handling<select value={draft.bodyMode} onChange={event => change({ ...draft, bodyMode: event.currentTarget.value as RedactionPolicy['bodyMode'] })}>
          <option value="omit">Omit all bodies (default)</option><option value="supported">Clean supported JSON and form bodies</option>
        </select></label>
        <p>Supported-body mode retains cleaned content for manual review. Binary, encoded, unsupported and invalid bodies are omitted and reported.</p>
        <label>Extra sensitive field names<input value={extraKeys} onChange={event => { setExtraKeys(event.currentTarget.value); setConfirmed(false); setNotice(''); }} placeholder="customer_id, internal_key" /></label>
        <p>Comma-separated field names supplement the mandatory credential rules.</p>
        <div className="policy-rules">
          <strong>Literal replacements</strong>
          {draft.literalRules.map((rule, index) => <div className="policy-rule" key={index}>
            <label>Match {index + 1}<input value={rule.value} maxLength={256} autoComplete="off" spellCheck={false} onChange={event => change({ ...draft, literalRules: draft.literalRules.map((item, row) => row === index ? { ...item, value: event.currentTarget.value } : item) })} /></label>
            <label>Replacement {index + 1}<input value={rule.replacement} maxLength={256} autoComplete="off" onChange={event => change({ ...draft, literalRules: draft.literalRules.map((item, row) => row === index ? { ...item, replacement: event.currentTarget.value } : item) })} /></label>
            <button type="button" className="button button-quiet" aria-label={`Remove literal rule ${index + 1}`} onClick={() => change({ ...draft, literalRules: draft.literalRules.filter((_, row) => row !== index) })}>Remove</button>
          </div>)}
          <button type="button" className="button button-secondary button-small" disabled={draft.literalRules.length >= 128} onClick={() => change({ ...draft, literalRules: [...draft.literalRules, { value: '', replacement: '[REDACTED]' }] })}>Add literal rule</button>
        </div>
        {hasText && <label className="policy-confirm"><input type="checkbox" checked={confirmed} onChange={event => setConfirmed(event.currentTarget.checked)} /> Rebuild text from the originals and discard my manual text edits.</label>}
        <div className="policy-actions">
          <button type="button" className="button button-primary" disabled={hasText && !confirmed} onClick={() => void apply()}>Apply policy</button>
          <button type="button" className="button button-secondary" onClick={save}>Save policy file</button>
          <button type="button" className="button button-secondary" onClick={() => input.current?.click()}>Load policy file</button>
          <button type="button" className="button button-quiet" onClick={() => { change(DEFAULT_REDACTION_POLICY); setExtraKeys(''); }}>Reset draft</button>
          <input ref={input} type="file" className="visually-hidden" accept=".json,application/json" aria-label="Load cleaning policy" onChange={event => { const file = event.currentTarget.files?.[0]; event.currentTarget.value = ''; void load(file); }} />
        </div>
      </fieldset>
      {error && <p className="inline-error" role="alert">{error}</p>}
      {notice && <p role="status">{notice}</p>}
    </div>
  </details>;
}
