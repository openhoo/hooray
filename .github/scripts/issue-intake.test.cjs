'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const intake = require('./issue-intake.cjs');

const BOT = Object.freeze({ type: 'Bot', login: 'github-actions[bot]' });
const FOREIGN_BOT = Object.freeze({ type: 'Bot', login: 'dependabot[bot]' });
const MAINTAINER = Object.freeze({ type: 'User', login: 'maintainer' });
const OWNER = 'openhoo';
const REPO = 'hooray';
const ISSUE_NUMBER = 314;
const TIMELINE_BASE = Date.parse('2026-09-11T12:00:00.000Z');
const NEEDS_INFO_MARKER = '<!-- hooray-issue-intake:v1 needs-info-owned=true -->';
const RESOLVED_MARKER = '<!-- hooray-issue-intake:v1 needs-info-owned=false -->';

const CANONICAL_VALUES = Object.freeze({
  Summary: 'The analyzer reports an observable result that needs investigation.',
  Classification: 'Bug',
  'Version and provenance': 'N/A — this structural fixture is not executable.',
  Reproduction: 'N/A — this structural fixture is not executable.',
  'Expected and actual behavior': 'N/A — this structural fixture is not executable.',
  'Evidence and scope': 'N/A — this structural fixture is not executable.',
  'Acceptance criteria': 'N/A — this structural fixture is not executable.',
});

function bodyFrom(order = intake.REQUIRED_HEADINGS, overrides = {}) {
  return order
    .map((heading) => `### ${heading}\n${overrides[heading] ?? CANONICAL_VALUES[heading]}`)
    .join('\n\n');
}

function incompleteBody() {
  return bodyFrom(intake.REQUIRED_HEADINGS.filter((heading) => heading !== 'Evidence and scope'));
}


function comment(id, body, user = BOT, createdAt = '2026-09-11T12:01:00.000Z') {
  return { id, body, user: { ...user }, created_at: createdAt, updated_at: createdAt };
}

function timelineEvent(id, offsetSeconds, event, label, actor = BOT) {
  return {
    id,
    event,
    label: { name: label },
    actor: { ...actor },
    created_at: new Date(TIMELINE_BASE + offsetSeconds * 1000).toISOString(),
  };
}

function createGithubModel({
  body,
  labels = [],
  comments = [],
  events = [],
  failures = {},
} = {}) {
  const state = {
    issue: {
      number: ISSUE_NUMBER,
      body,
      labels: labels.map((name) => ({ name })),
    },
    comments: comments.map((item) => ({
      ...item,
      user: item.user ? { ...item.user } : undefined,
    })),
    events: events.map((item) => ({
      ...item,
      label: item.label ? { ...item.label } : item.label,
      actor: item.actor ? { ...item.actor } : item.actor,
    })),
    nextCommentId: Math.max(0, ...comments.map((item) => Number(item.id) || 0)) + 1,
    nextEventId: Math.max(0, ...events.map((item) => Number(item.id) || 0)) + 1,
  };
  const pendingFailures = new Map(Object.entries(failures));
  const attempts = [];
  const mutations = [];

  function maybeFail(operation) {
    const remaining = Number(pendingFailures.get(operation) || 0);
    if (remaining > 0) {
      if (remaining === 1) {
        pendingFailures.delete(operation);
      } else {
        pendingFailures.set(operation, remaining - 1);
      }
      throw new Error(`${operation} failed once for the regression fixture`);
    }
  }

  function recordEvent(event, label, actor = BOT) {
    state.events.push(
      timelineEvent(state.nextEventId, state.nextEventId, event, label, actor),
    );
    state.nextEventId += 1;
  }

  const listComments = async () => undefined;
  const listEventsForTimeline = async () => undefined;

  const github = {
    rest: {
      issues: {
        get: async () => {
          attempts.push('get');
          return {
            data: {
              ...state.issue,
              labels: state.issue.labels.map((label) => ({ ...label })),
            },
          };
        },
        listComments,
        listEventsForTimeline,
        addLabels: async ({ labels: names }) => {
          attempts.push('addLabels');
          maybeFail('addLabels');
          for (const name of names) {
            if (!state.issue.labels.some((label) => label.name === name)) {
              state.issue.labels.push({ name });
              recordEvent('labeled', name);
            }
          }
          mutations.push({ operation: 'addLabels', labels: [...names] });
        },
        removeLabel: async ({ name }) => {
          attempts.push(`removeLabel:${name}`);
          maybeFail('removeLabel');
          const before = state.issue.labels.length;
          state.issue.labels = state.issue.labels.filter((label) => label.name !== name);
          if (state.issue.labels.length !== before) {
            recordEvent('unlabeled', name);
          }
          mutations.push({ operation: 'removeLabel', label: name });
        },
        createComment: async ({ body: commentBody }) => {
          attempts.push('createComment');
          maybeFail('createComment');
          const createdAt = new Date(
            TIMELINE_BASE + state.nextCommentId * 1000,
          ).toISOString();
          state.comments.push(
            comment(state.nextCommentId, commentBody, BOT, createdAt),
          );
          state.nextCommentId += 1;
          mutations.push({ operation: 'createComment' });
        },
        updateComment: async ({ comment_id: commentId, body: commentBody }) => {
          attempts.push(`updateComment:${commentId}`);
          maybeFail('updateComment');
          const existing = state.comments.find((item) => item.id === commentId);
          assert.ok(existing, `comment ${commentId} must exist before updating`);
          existing.body = commentBody;
          existing.updated_at = new Date(
            TIMELINE_BASE + state.nextCommentId * 1000,
          ).toISOString();
          mutations.push({ operation: 'updateComment', commentId });
        },
      },
    },
    paginate: async (endpoint, request) => {
      if (endpoint === listComments) {
        attempts.push('listComments');
        maybeFail('listComments');
        return state.comments.map((item) => ({
          ...item,
          user: item.user ? { ...item.user } : undefined,
        }));
      }
      if (endpoint === listEventsForTimeline) {
        attempts.push('listEventsForTimeline');
        maybeFail('listEventsForTimeline');
        return state.events.map((item) => ({
          ...item,
          label: item.label ? { ...item.label } : item.label,
          actor: item.actor ? { ...item.actor } : item.actor,
        }));
      }
      throw new Error(`unexpected paginate endpoint for ${JSON.stringify(request)}`);
    },
  };

  return {
    github,
    state,
    attempts,
    mutations,
    context: {
      repo: { owner: OWNER, repo: REPO },
      payload: { issue: { number: ISSUE_NUMBER } },
    },
    setBody(nextBody) {
      state.issue.body = nextBody;
    },
    labels() {
      return state.issue.labels.map((label) => label.name);
    },
    failOnce(operation) {
      pendingFailures.set(operation, 1);
    },
  };
}

async function runModel(model) {
  return intake.run({
    github: model.github,
    context: model.context,
    core: { info() {} },
  });
}

async function runMayFail(model) {
  try {
    return await runModel(model);
  } catch (error) {
    return { error };
  }
}



test('accepts nested headings, literal fenced HTML comments, and inline triple-backtick code', () => {
  const validation = intake.validateIssueBody(
    bodyFrom(intake.REQUIRED_HEADINGS, {
      Summary: '```x```',
      Reproduction: ['```html', '<!-- actual input -->', '```'].join('\n'),
      'Evidence and scope': [
        '#### Additional context',
        'Visible evidence for the structural fixture.',
      ].join('\n'),
    }),
  );

  assert.equal(validation.valid, true);
});

test('rejects hidden forms, duplicate canonical fields, and reordered canonical fields', () => {
  const hidden = intake.validateIssueBody(`<!--\n${bodyFrom()}\n-->`);
  assert.equal(hidden.valid, false);
  for (const heading of intake.REQUIRED_HEADINGS) {
    assert.equal(hidden.missing.includes(heading), true);
  }

  const duplicate = intake.validateIssueBody(
    `${bodyFrom()}\n\n### Reproduction\nA second reproduction answer.`,
  );
  assert.equal(duplicate.valid, false);
  assert.equal(
    duplicate.invalid.some(
      (entry) => entry.heading === 'Reproduction' && entry.reason === 'duplicate',
    ),
    true,
  );

  const reordered = intake.validateIssueBody(
    bodyFrom(['Classification', 'Summary', ...intake.REQUIRED_HEADINGS.slice(2)]),
  );
  assert.equal(reordered.valid, false);
});

test('does not let a quoted inline HTML opener hide later canonical fields', () => {
  const validation = intake.validateIssueBody(
    bodyFrom(intake.REQUIRED_HEADINGS, {
      Summary: '> `<!-- quoted inline example without a closing marker`',
    }),
  );

  assert.equal(validation.valid, true);
  assert.deepEqual(validation.missing, []);
});

test('keeps an interrupted incomplete transition recoverable and resolves its sole notice', async () => {
  const model = createGithubModel({
    body: incompleteBody(),
    labels: ['needs-triage'],
    failures: { createComment: 1 },
  });

  await runMayFail(model);
  assert.deepEqual(model.labels(), ['needs-triage']);
  assert.deepEqual(model.state.comments, []);

  await runModel(model);
  assert.deepEqual(model.labels(), ['needs-info']);
  assert.equal(model.state.comments.length, 1);
  const notice = model.state.comments[0];
  assert.deepEqual(notice.user, BOT);
  assert.equal(notice.body.includes(NEEDS_INFO_MARKER), true);

  model.setBody(bodyFrom());
  const completed = await runModel(model);
  assert.equal(completed.valid, true);
  assert.deepEqual(new Set(model.labels()), new Set(['needs-triage', 'bug']));
  assert.equal(model.labels().includes('needs-info'), false);
  assert.equal(model.state.comments.length, 1);
  assert.equal(model.state.comments[0].body.includes(RESOLVED_MARKER), true);
});

test('reconciles needs-triage after a remove failure that follows needs-info addition', async () => {
  const model = createGithubModel({
    body: incompleteBody(),
    labels: ['needs-triage'],
    failures: { removeLabel: 1 },
  });

  await runMayFail(model);
  assert.deepEqual(new Set(model.labels()), new Set(['needs-triage', 'needs-info']));
  assert.equal(model.state.comments.length, 1);
  assert.equal(model.state.comments[0].body.includes(NEEDS_INFO_MARKER), true);

  await runModel(model);
  assert.deepEqual(model.labels(), ['needs-info']);
  assert.equal(model.state.comments.length, 1);
});

test('does not mutate on a timeline read failure and removes proven bot state after recovery', async () => {
  const model = createGithubModel({
    body: bodyFrom(),
    labels: ['needs-info'],
    comments: [comment(41, `${NEEDS_INFO_MARKER}\nPrevious intake notice.`)],
    events: [timelineEvent(501, 1, 'labeled', 'needs-info')],
    failures: { listEventsForTimeline: 1 },
  });

  await runMayFail(model);
  assert.deepEqual(model.mutations, []);
  assert.deepEqual(model.labels(), ['needs-info']);
  assert.equal(model.state.comments[0].body.includes(NEEDS_INFO_MARKER), true);

  await runModel(model);
  assert.deepEqual(new Set(model.labels()), new Set(['needs-triage', 'bug']));
  assert.equal(model.labels().includes('needs-info'), false);
  assert.equal(model.state.comments.length, 1);
  assert.equal(model.state.comments[0].body.includes(RESOLVED_MARKER), true);

  const ambiguousActor = createGithubModel({
    body: bodyFrom(),
    labels: ['needs-info'],
    comments: [comment(42, `${NEEDS_INFO_MARKER}\nStale notice.`)],
    events: [
      timelineEvent(502, 1, 'labeled', 'needs-info', {
        login: 'github-actions[bot]',
      }),
    ],
  });
  await runMayFail(ambiguousActor);
  assert.deepEqual(ambiguousActor.labels(), ['needs-info']);
  assert.deepEqual(ambiguousActor.mutations, []);
  assert.equal(ambiguousActor.state.comments[0].body.includes(NEEDS_INFO_MARKER), true);

  ambiguousActor.state.events[0].actor = { ...BOT };
  await runModel(ambiguousActor);
  assert.deepEqual(new Set(ambiguousActor.labels()), new Set(['needs-triage', 'bug']));
});

test('retains manually re-added needs-info and never displaces ready-for-agent', async () => {
  const retained = createGithubModel({
    body: bodyFrom(),
    labels: ['needs-info', 'ready-for-agent'],
    comments: [comment(51, `${NEEDS_INFO_MARKER}\nStale bot notice.`)],
    events: [
      timelineEvent(601, 1, 'labeled', 'needs-info', BOT),
      timelineEvent(602, 2, 'unlabeled', 'needs-info', MAINTAINER),
      timelineEvent(603, 3, 'labeled', 'needs-info', MAINTAINER),
    ],
  });
  await runModel(retained);
  assert.deepEqual(new Set(retained.labels()), new Set(['needs-info', 'ready-for-agent', 'bug']));
  assert.equal(
    retained.mutations.some(
      (mutation) => mutation.operation === 'removeLabel' && mutation.label === 'needs-info',
    ),
    false,
  );
  assert.equal(retained.state.comments[0].body.includes(RESOLVED_MARKER), true);

  const protectedState = createGithubModel({
    body: incompleteBody(),
    labels: ['ready-for-agent'],
  });
  await runModel(protectedState);
  assert.deepEqual(protectedState.labels(), ['ready-for-agent']);
  assert.equal(
    protectedState.mutations.some(
      (mutation) => mutation.operation === 'addLabels' && mutation.labels.includes('needs-info'),
    ),
    false,
  );
  assert.equal(
    protectedState.mutations.some(
      (mutation) => mutation.operation === 'removeLabel' && mutation.label === 'ready-for-agent',
    ),
    false,
  );
});

test('ignores copied markers from unrelated bots and ambiguous notice identity', async () => {
  const foreign = comment(
    71,
    `${NEEDS_INFO_MARKER}\nThis belongs to another automation bot.`,
    FOREIGN_BOT,
  );
  const model = createGithubModel({
    body: incompleteBody(),
    labels: ['needs-triage'],
    comments: [foreign],
  });

  await runModel(model);
  assert.equal(model.state.comments[0].id, foreign.id);
  assert.equal(model.state.comments[0].body, foreign.body);
  assert.deepEqual(model.state.comments[0].user, FOREIGN_BOT);
  assert.equal(
    model.mutations.some(
      (mutation) => mutation.operation === 'updateComment' && mutation.commentId === foreign.id,
    ),
    false,
  );
  assert.equal(model.state.comments.length, 2);
  assert.equal(model.state.comments[1].user.type, BOT.type);
  assert.equal(model.state.comments[1].user.login, BOT.login);

  const ambiguousUser = createGithubModel({
    body: bodyFrom(),
    labels: ['needs-info'],
    comments: [
      comment(72, `${NEEDS_INFO_MARKER}\nCopied by a bot with ambiguous identity.`, {
        type: 'Bot',
      }),
    ],
    events: [timelineEvent(701, 1, 'labeled', 'needs-info', BOT)],
  });
  await runModel(ambiguousUser);
  assert.deepEqual(new Set(ambiguousUser.labels()), new Set(['needs-info', 'bug']));
  assert.equal(
    ambiguousUser.mutations.some(
      (mutation) => mutation.operation === 'removeLabel' && mutation.label === 'needs-info',
    ),
    false,
  );
  assert.equal(ambiguousUser.state.comments[0].body.includes(NEEDS_INFO_MARKER), true);
});

test('verifyNeedsInfoOwnership tiebreaks same-timestamp events by id and rejects ambiguous ordering', async () => {
  // Two needs-info events at the same instant: the higher id wins, so a
  // later maintainer re-add at the same second is honored.
  const sameInstant = createGithubModel({
    body: bodyFrom(),
    labels: ['needs-info'],
    comments: [comment(81, `${NEEDS_INFO_MARKER}\nNotice.`)],
    events: [
      timelineEvent(801, 1, 'labeled', 'needs-info', BOT),
      timelineEvent(802, 1, 'unlabeled', 'needs-info', MAINTAINER),
      timelineEvent(803, 1, 'labeled', 'needs-info', MAINTAINER),
    ],
  });
  await runModel(sameInstant);
  // Latest event is the maintainer's re-add (highest id) → not bot-owned →
  // the label is retained.
  assert.equal(sameInstant.labels().includes('needs-info'), true);
  assert.equal(
    sameInstant.mutations.some(
      (mutation) => mutation.operation === 'removeLabel' && mutation.label === 'needs-info',
    ),
    false,
  );

  // An event with an unparseable timestamp makes ordering ambiguous: the
  // run must fail rather than guess ownership.
  const ambiguous = createGithubModel({
    body: bodyFrom(),
    labels: ['needs-info'],
    comments: [comment(82, `${NEEDS_INFO_MARKER}\nNotice.`)],
    events: [
      {
        id: 804,
        event: 'labeled',
        label: { name: 'needs-info' },
        actor: { ...BOT },
        created_at: 'not-a-date',
      },
    ],
  });
  const outcome = await runMayFail(ambiguous);
  assert.equal(Boolean(outcome && outcome.error), true);
  assert.deepEqual(ambiguous.mutations, []);
  assert.deepEqual(ambiguous.labels(), ['needs-info']);
});

test('retains unowned needs-info on a valid body and resolves the notice', async () => {
  // needs-info present but the notice marker says the bot does not own it
  // (needs-info-owned=false): the label stays and the notice resolves.
  const retained = createGithubModel({
    body: bodyFrom(),
    labels: ['needs-info'],
    comments: [comment(91, `${RESOLVED_MARKER}\nOlder resolved notice.`)],
    events: [timelineEvent(901, 1, 'labeled', 'needs-info', MAINTAINER)],
  });
  await runModel(retained);
  assert.equal(retained.labels().includes('needs-info'), true);
  assert.equal(
    retained.mutations.some(
      (mutation) => mutation.operation === 'removeLabel' && mutation.label === 'needs-info',
    ),
    false,
  );
  // needs-triage is not added while a manual needs-info is retained.
  assert.equal(retained.labels().includes('needs-triage'), false);
});

test('protected states block both needs-info and needs-triage transitions', async () => {
  // Invalid body + wontfix: needs-info must not be added over a protected
  // maintainer state.
  const wontfix = createGithubModel({
    body: incompleteBody(),
    labels: ['wontfix'],
  });
  await runModel(wontfix);
  assert.deepEqual(wontfix.labels(), ['wontfix']);

  // Valid body + wontfix: needs-triage must not be added either.
  const validWontfix = createGithubModel({
    body: bodyFrom(),
    labels: ['wontfix'],
  });
  await runModel(validWontfix);
  assert.deepEqual(validWontfix.labels(), ['wontfix', 'bug']);
});

test('bot-owned needs-info displaces needs-triage on an invalid body', async () => {
  // Invalid body with needs-info already present and bot-owned: the stale
  // needs-triage is removed while needs-info is kept.
  const model = createGithubModel({
    body: incompleteBody(),
    labels: ['needs-info', 'needs-triage'],
    comments: [comment(95, `${NEEDS_INFO_MARKER}\nNotice.`)],
    events: [timelineEvent(951, 1, 'labeled', 'needs-info', BOT)],
  });
  await runModel(model);
  assert.deepEqual(model.labels(), ['needs-info']);
});
