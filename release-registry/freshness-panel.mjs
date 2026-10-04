// Draft adapter. Do not connect until a trusted service issues versioned receipts.
// This component displays observations; it does not verify their authenticity.
export function renderFreshness(container, observations) {
  const doc=container.ownerDocument, section=doc.createElement('section');
  section.setAttribute('aria-label','RIO bronstatus');
  const title=doc.createElement('h2');title.textContent='RIO bronstatus';section.append(title);
  const allowed=new Set(['CURRENT','STALE','UNKNOWN','REVOKED']);
  const list=Array.isArray(observations)?observations:[];
  const current=list.at(-1), record=current?.record||{};
  const status=allowed.has(current?.status)?current.status:'UNKNOWN';
  const badge=doc.createElement('p');badge.setAttribute('role','status');badge.textContent=status;section.append(badge);
  const fields=doc.createElement('dl');
  for(const [name,value] of Object.entries({source_version:record.source_version,generated_at:record.generated_at,verified_at:record.verified_at,valid_for_seconds:record.valid_for_seconds,observed_at:current?.observed_at})){
    const row=doc.createElement('div'),key=doc.createElement('dt'),val=doc.createElement('dd');key.textContent=name;val.textContent=value===null||value===undefined?'UNKNOWN':String(value);row.append(key,val);fields.append(row);
  }
  section.append(fields);
  const note=doc.createElement('p');note.textContent='Conceptweergave. Bronstatus verleent geen bevoegdheid.';section.append(note);
  const details=doc.createElement('details'),summary=doc.createElement('summary'),history=doc.createElement('ol');summary.textContent='Eerdere toestanden';details.append(summary,history);
  for(const event of list){const row=doc.createElement('li');row.textContent=`${event.observed_at??'UNKNOWN'} · ${allowed.has(event.status)?event.status:'UNKNOWN'} · ${event.record?.source_version??'UNKNOWN'} · ${event.digest??'UNKNOWN'}`;history.append(row);}
  section.append(details);container.replaceChildren(section);
}
