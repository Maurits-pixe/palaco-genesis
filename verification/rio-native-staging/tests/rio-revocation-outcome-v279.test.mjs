import test from 'node:test';
import assert from 'node:assert/strict';
import {createRioRevocationOutcomeCoordinatorV279} from '../rio-revocation-outcome-coordinator-v279.mjs';
const request={requestId:'synthetic-request',actorAuditRef:'synthetic-actor',subjectId:'synthetic-subject',
  sessionRef:'synthetic-session',reason:'REVOKED'};
const mutation=async()=>({state:'AUTHORITY_MUTATED',changed:true});
test('outcome coordinator requires explicit trusted dependencies',()=>{
  assert.throws(()=>createRioRevocationOutcomeCoordinatorV279(),TypeError);
});
test('invalid request never acquires a connection or permits a retry',async()=>{
  let calls=0;
  const port=createRioRevocationOutcomeCoordinatorV279({acquireConnection:async()=>{calls++;},
    applySessionAuthorityMutation:mutation,applyPolicyAuthorityMutation:mutation});
  const r=await port.revokeSession({});
  assert.equal(calls,0);assert.equal(r.transactionOutcome,'NOT_STARTED');
  assert.equal(r.automaticRetryAllowed,false);assert.equal(r.authorization,'NONE');
});
test('connection acquisition failure is contained without leaking its diagnostic',async()=>{
  const port=createRioRevocationOutcomeCoordinatorV279({acquireConnection:async()=>{throw Error('private-diagnostic');},
    applySessionAuthorityMutation:mutation,applyPolicyAuthorityMutation:mutation});
  const r=await port.revokeSession(request);
  assert.equal(r.transactionOutcome,'NOT_STARTED');assert.equal(r.ok,false);
  assert.equal(JSON.stringify(r).includes('private-diagnostic'),false);
});
test('BEGIN failure discards its connection and does not claim a confirmed rollback',async()=>{
  let discarded=false;
  const port=createRioRevocationOutcomeCoordinatorV279({acquireConnection:async()=>({
    query:async()=>{throw Error('begin-failure');},release:async error=>{discarded=error instanceof Error;}}),
    applySessionAuthorityMutation:mutation,applyPolicyAuthorityMutation:mutation});
  const r=await port.revokeSession(request);
  assert.equal(r.transactionOutcome,'NOT_STARTED');assert.equal(r.connectionCleanup,'RELEASED');
  assert.equal(discarded,true);assert.equal(r.automaticRetryAllowed,false);
});
