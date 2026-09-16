'use strict';

const REQUIRED_HEADINGS = Object.freeze([
  'Summary',
  'Classification',
  'Version and provenance',
  'Reproduction',
  'Expected and actual behavior',
  'Evidence and scope',
  'Acceptance criteria',
]);

const CLASSIFICATION_CHOICES = Object.freeze([
  'Bug',
  'Coverage request',
  'Enhancement',
  'Documentation',
]);

const CATEGORY_LABELS = Object.freeze([
  'bug',
  'enhancement',
]);

const CLASSIFICATION_LABELS = Object.freeze({
  Bug: Object.freeze({ category: 'bug', qualifier: null }),
  'Coverage request': Object.freeze({ category: 'enhancement', qualifier: 'coverage' }),
  Enhancement: Object.freeze({ category: 'enhancement', qualifier: null }),
  Documentation: Object.freeze({ category: 'enhancement', qualifier: 'documentation' }),
});

// These labels represent a maintainer decision. The intake bot never removes them
// and never adds another human-handoff state.
const PROTECTED_STATE_LABELS = Object.freeze([
  'ready-for-agent',
  'wontfix',
]);

const NOTICE_MARKER_RE = /<!--\s*hooray-issue-intake:v1\s+needs-info-owned=(true|false)\s*-->/i;

function normalizeBody(body) {
  return typeof body === 'string' ? body.replace(/\r\n?/g, '\n').replace(/^\uFEFF/, '') : '';
}

function parseHeadingLine(line) {
  const match = /^( {0,3})(#{1,6})[ \t]+(.+?)[ \t]*$/.exec(line);
  if (!match) {
    return null;
  }

  const title = match[3].replace(/[ \t]+#+[ \t]*$/, '').trim();
  if (!title) {
    return null;
  }

  return {
    title,
    level: match[2].length,
  };
}

function fenceStart(line) {
  const match = /^( {0,3})(`{3,}|~{3,})(.*)$/.exec(line);
  if (!match) {
    return null;
  }

  const marker = match[2];
  if (marker[0] === '`' && match[3].includes('`')) {
    return null;
  }

  return {
    character: marker[0],
    length: marker.length,
  };
}

function fenceCloses(line, fence) {
  const match = /^( {0,3})(`{3,}|~{3,})[ \t]*$/.exec(line);
  return Boolean(
    match &&
      match[2][0] === fence.character &&
      match[2].length >= fence.length,
  );
}

function stripHtmlCommentsOutsideCode(line, htmlCommentOpen, inlineTicks) {
  let output = '';
  let index = 0;
  let inComment = htmlCommentOpen;
  let ticks = inlineTicks;

  while (index < line.length) {
    if (inComment) {
      const close = line.indexOf('-->', index);
      if (close < 0) {
        return { text: output, htmlCommentOpen: true, inlineTicks: 0 };
      }
      index = close + 3;
      inComment = false;
      continue;
    }

    if (ticks > 0) {
      const marker = '`'.repeat(ticks);
      const close = line.indexOf(marker, index);
      if (close < 0) {
        return {
          text: output + line.slice(index),
          htmlCommentOpen: false,
          inlineTicks: ticks,
        };
      }
      output += line.slice(index, close + ticks);
      index = close + ticks;
      ticks = 0;
      continue;
    }

    if (line.startsWith('<!--', index)) {
      inComment = true;
      index += 4;
      continue;
    }

    if (line[index] === '`') {
      let length = 1;
      while (line[index + length] === '`') {
        length += 1;
      }
      const marker = '`'.repeat(length);
      const close = line.indexOf(marker, index + length);
      if (close < 0) {
        return {
          text: output + line.slice(index),
          htmlCommentOpen: false,
          inlineTicks: length,
        };
      }
      output += line.slice(index, close + length);
      index = close + length;
      continue;
    }

    output += line[index];
    index += 1;
  }

  return { text: output, htmlCommentOpen: inComment, inlineTicks: ticks };
}

function walkMarkdown(value) {
  const normalized = normalizeBody(value);
  const lines = normalized.split('\n');
  const entries = [];
  let fence = null;
  let htmlCommentOpen = false;
  let inlineTicks = 0;

  for (const line of lines) {
    if (fence) {
      const closes = fenceCloses(line, fence);
      entries.push({
        raw: line,
        text: line,
        inFence: true,
        isFenceDelimiter: closes,
      });
      if (closes) {
        fence = null;
      }
      continue;
    }

    if (!htmlCommentOpen && inlineTicks === 0) {
      const start = fenceStart(line);
      if (start) {
        entries.push({
          raw: line,
          text: line,
          inFence: false,
          isFenceDelimiter: true,
        });
        fence = start;
        continue;
      }
    }

    const stripped = stripHtmlCommentsOutsideCode(
      line,
      htmlCommentOpen,
      inlineTicks,
    );
    entries.push({
      raw: line,
      text: stripped.text,
      inFence: false,
      isFenceDelimiter: false,
    });
    htmlCommentOpen = stripped.htmlCommentOpen;
    inlineTicks = stripped.inlineTicks;
  }

  return entries;
}

function extractSections(body) {
  const normalized = normalizeBody(body);
  const entries = walkMarkdown(normalized);
  const headings = [];

  for (let index = 0; index < entries.length; index += 1) {
    const entry = entries[index];
    if (entry.inFence) {
      continue;
    }
    const heading = parseHeadingLine(entry.text);
    if (heading) {
      headings.push({ ...heading, line: index });
    }
  }

  // The issue form emits level-three headings. Deeper headings are content
  // inside the current field; only a same-level or higher-level heading ends
  // that field.
  const sectionHeadings = headings.filter((heading) => heading.level <= 3);
  const sections = Object.create(null);
  const duplicateHeadings = [];
  const unknownHeadings = [];
  const canonicalOrder = [];
  const required = new Set(REQUIRED_HEADINGS);

  for (let index = 0; index < sectionHeadings.length; index += 1) {
    const heading = sectionHeadings[index];
    const nextLine =
      index + 1 < sectionHeadings.length
        ? sectionHeadings[index + 1].line
        : entries.length;
    const value = entries
      .slice(heading.line + 1, nextLine)
      .map((entry) => entry.text)
      .join('\n')
      .trim();

    if (heading.level !== 3 || !required.has(heading.title)) {
      unknownHeadings.push(heading.title);
      continue;
    }

    canonicalOrder.push(heading.title);
    if (Object.prototype.hasOwnProperty.call(sections, heading.title)) {
      duplicateHeadings.push(heading.title);
      continue;
    }

    sections[heading.title] = value;
  }

  return {
    body: normalized,
    headings,
    sections,
    canonicalOrder,
    duplicateHeadings: [...new Set(duplicateHeadings)],
    unknownHeadings,
  };
}

function removeHtmlComments(value) {
  return walkMarkdown(value)
    .map((entry) => entry.text)
    .join('\n');
}

function removeFenceDelimiters(value) {
  return walkMarkdown(value)
    .filter((entry) => !entry.isFenceDelimiter)
    .map((entry) => entry.text)
    .join('\n')
    .trim();
}

function isReasonedNa(value) {
  const text = removeFenceDelimiters(removeHtmlComments(value)).trim();
  if (!/^n\/a\b/i.test(text)) {
    return false;
  }

  const reason = text.slice(3).trim();
  if (!reason) {
    return false;
  }
  const unwrapped = reason
    .replace(/^[-–—:]\s*/, '')
    .replace(/^\(\s*/, '')
    .replace(/\s*\)$/, '')
    .trim();

  return (
    Boolean(unwrapped) &&
    !/^_?no response_?$/i.test(unwrapped) &&
    !/^<[^<>]+>$/.test(unwrapped)
  );
}

function sectionValueProblem(value) {
  const withoutComments = removeHtmlComments(value).trim();
  const text = removeFenceDelimiters(withoutComments);
  if (!text) {
    return 'empty';
  }

  if (
    /^(?:>\s*)?(?:[-*+]\s*)?(?:[*_`]+)?no response(?:[*_`]+)?$/i.test(
      text,
    )
  ) {
    return 'placeholder';
  }

  if (/^n\/?a\.?\b/i.test(text)) {
    return isReasonedNa(text) ? null : 'placeholder';
  }

  // A reasoned N/A is explicitly allowed for genuinely non-executable requests.
  if (isReasonedNa(text)) {
    return null;
  }

  return null;
}

function validateIssueBody(body) {
  const extracted = extractSections(body);
  const missing = REQUIRED_HEADINGS.filter(
    (heading) => !Object.prototype.hasOwnProperty.call(extracted.sections, heading),
  );
  const invalid = [];
  if (
    missing.length === 0 &&
    extracted.duplicateHeadings.length === 0 &&
    (extracted.canonicalOrder.length !== REQUIRED_HEADINGS.length ||
      extracted.canonicalOrder.some(
        (heading, index) => heading !== REQUIRED_HEADINGS[index],
      ))
  ) {
    invalid.push({ heading: 'Canonical headings', reason: 'order' });
  }

  for (const heading of extracted.duplicateHeadings) {
    invalid.push({ heading, reason: 'duplicate' });
  }

  for (const heading of REQUIRED_HEADINGS) {
    if (missing.includes(heading) || extracted.duplicateHeadings.includes(heading)) {
      continue;
    }

    const problem = sectionValueProblem(extracted.sections[heading]);
    if (problem) {
      invalid.push({ heading, reason: problem });
    }
  }

  const classification = extracted.sections.Classification;
  if (
    classification !== undefined &&
    !missing.includes('Classification') &&
    !extracted.duplicateHeadings.includes('Classification') &&
    !sectionValueProblem(classification)
  ) {
    const values = removeHtmlComments(classification)
      .split('\n')
      .map((line) => line.trim())
      .filter(Boolean);
    if (values.length !== 1 || !CLASSIFICATION_CHOICES.includes(values[0])) {
      invalid.push({ heading: 'Classification', reason: 'choice' });
    }
  }

  const uniqueInvalid = [];
  const seenInvalid = new Set();
  for (const entry of invalid) {
    const key = `${entry.heading}\u0000${entry.reason}`;
    if (!seenInvalid.has(key)) {
      seenInvalid.add(key);
      uniqueInvalid.push(entry);
    }
  }

  const errors = [
    ...missing.map((heading) => ({ heading, reason: 'missing' })),
    ...uniqueInvalid,
  ];

  const valid = missing.length === 0 && uniqueInvalid.length === 0;
  return {
    ...extracted,
    valid,
    isComplete: valid,
    missing,
    invalid: uniqueInvalid,
    errors,
    classification:
      classification === undefined
        ? null
        : removeHtmlComments(classification).trim(),
  };
}

function normalizeLabels(labels) {
  if (!Array.isArray(labels)) {
    return [];
  }

  return labels
    .map((label) => {
      if (typeof label === 'string') {
        return label;
      }
      return label && typeof label.name === 'string' ? label.name : null;
    })
    .filter(Boolean);
}

function planCategoryChanges(labels, classification) {
  const names = new Set(normalizeLabels(labels));
  const desired = CLASSIFICATION_LABELS[classification];
  if (!desired) {
    return { add: [], discrepancies: [] };
  }

  const presentCategories = CATEGORY_LABELS.filter((label) => names.has(label));
  const discrepancies = [];
  const add = [];

  if (presentCategories.length > 1) {
    discrepancies.push('More than one category label is already present; preserve the labels and resolve the category explicitly.');
    return { add, discrepancies };
  }

  if (presentCategories.length === 1 && presentCategories[0] !== desired.category) {
    discrepancies.push(`The existing category label conflicts with the form classification "${classification}"; preserve the label and resolve the category explicitly.`);
    return { add, discrepancies };
  }

  if (presentCategories.length === 0) {
    add.push(desired.category);
  }

  if (desired.qualifier && !names.has(desired.qualifier)) {
    add.push(desired.qualifier);
  }

  return { add, discrepancies };
}

function parseNoticeMarker(body) {
  if (typeof body !== 'string') {
    return null;
  }

  const match = NOTICE_MARKER_RE.exec(body);
  return match ? { needsInfoOwned: match[1].toLowerCase() === 'true' } : null;
}

function findNoticeComment(comments) {
  if (!Array.isArray(comments)) {
    return null;
  }

  for (const comment of comments) {
    const marker = parseNoticeMarker(comment && comment.body);
    if (!marker) {
      continue;
    }

    const user = comment && comment.user;
    if (!user || user.type !== 'Bot' || user.login !== 'github-actions[bot]') {
      continue;
    }

    return { ...marker, id: comment.id, body: comment.body };
  }

  return null;
}

function planLabelChanges(labels, validation, { noticeOwned = false } = {}) {
  const names = new Set(normalizeLabels(labels));
  const hasNeedsInfo = names.has('needs-info');
  const hasNeedsTriage = names.has('needs-triage');
  const hasProtectedState = PROTECTED_STATE_LABELS.some((label) => names.has(label));
  const add = [];
  const remove = [];
  let automationNeedsInfoOwned = false;
  let category = { add: [], discrepancies: [] };

  if (!validation.valid) {
    if (hasNeedsInfo) {
      automationNeedsInfoOwned = noticeOwned;
      if (noticeOwned && hasNeedsTriage) {
        remove.push('needs-triage');
      }
    } else if (!hasProtectedState) {
      // needs-triage is the ordinary queue state. Replace it with the more
      // specific needs-info state when the body becomes incomplete. A
      // maintainer-owned ready-for-agent/wontfix state is never displaced.
      add.push('needs-info');
      if (hasNeedsTriage) {
        remove.push('needs-triage');
      }
      automationNeedsInfoOwned = true;
    }

    return {
      add,
      remove,
      category,
      automationNeedsInfoOwned,
      preserveManualNeedsInfo: hasNeedsInfo && !noticeOwned,
    };
  }

  if (hasNeedsInfo && noticeOwned) {
    remove.push('needs-info');
  }

  const needsInfoAfter = hasNeedsInfo && !noticeOwned;
  if (!needsInfoAfter && !hasNeedsTriage && !hasProtectedState) {
    add.push('needs-triage');
  }

  category = planCategoryChanges(labels, validation.classification);
  add.push(...category.add);

  return {
    add: [...new Set(add)],
    remove: [...new Set(remove)],
    category,
    automationNeedsInfoOwned: false,
    preserveManualNeedsInfo: hasNeedsInfo && !noticeOwned,
  };
}

function buildNotice(validation, options = {}) {
  if (!validation) {
    return null;
  }

  const discrepancies = Array.isArray(options.categoryDiscrepancies)
    ? options.categoryDiscrepancies
    : [];
  if (validation.valid && discrepancies.length === 0) {
    return null;
  }

  const needsInfoOwned = Boolean(options.needsInfoOwned);
  const marker = `<!-- hooray-issue-intake:v1 needs-info-owned=${needsInfoOwned ? 'true' : 'false'} -->`;
  const problems = [];
  const seen = new Set();
  for (const heading of validation.missing || []) {
    const message = `- **${heading}**: add this section with the requested evidence.`;
    if (!seen.has(message)) {
      seen.add(message);
      problems.push(message);
    }
  }

  for (const entry of validation.invalid || []) {
    const reason =
      entry.reason === 'empty'
        ? 'provide a non-empty answer'
        : entry.reason === 'placeholder'
          ? 'replace the placeholder with evidence or a reasoned N/A explanation'
          : entry.reason === 'choice'
            ? `choose exactly one of: ${CLASSIFICATION_CHOICES.join(', ')}`
            : entry.reason === 'duplicate'
              ? 'keep one canonical section'
              : entry.reason === 'order'
                ? `use the canonical order: ${REQUIRED_HEADINGS.join(', ')}`
                : 'complete this section';
    const message = `- **${entry.heading}**: ${reason}.`;
    if (!seen.has(message)) {
      seen.add(message);
      problems.push(message);
    }
  }

  for (const discrepancy of discrepancies) {
    const message = `- **Labels**: ${discrepancy}`;
    if (!seen.has(message)) {
      seen.add(message);
      problems.push(message);
    }
  }

  const incomplete = !validation.valid;
  const needsInfoRetained = Boolean(options.needsInfoRetained);
  return [
    marker,
    '',
    incomplete
      ? 'This report needs more information before conservative triage can begin.'
      : needsInfoRetained
        ? 'The report structure is complete, but the existing `needs-info` label was retained because the intake bot could not prove that it added it.'
        : 'The report structure is complete, but existing category labels need explicit maintainer review.',
    '',
    incomplete
      ? 'Please edit the original issue and address the following:'
      : needsInfoRetained
        ? 'A maintainer may resolve the retained state explicitly; the intake bot will not erase it:'
        : 'Please resolve the following label discrepancy explicitly; the intake bot will not erase or replace existing labels:',
    ...problems,
    '',
    'Keep the seven canonical headings exactly as shown in the issue form. Give immutable project/source/native/reference provenance, exact commands and scope, outcomes, clean controls where relevant, durable evidence, and bounded acceptance criteria. A reference finding is a lead rather than proof, and an incomplete run is not a clean run.',
    '',
    'Do not post suspected vulnerability details here; use [private vulnerability reporting](https://github.com/openhoo/hooray/security/advisories/new). This automated check does not verify or close the report.',
  ].join('\n');
}
function buildResolvedNotice({
  needsInfoRetained = false,
  needsInfoOwned = false,
} = {}) {
  const marker = `<!-- hooray-issue-intake:v1 needs-info-owned=${needsInfoOwned ? 'true' : 'false'} -->`;
  return [
    marker,
    '',
    needsInfoOwned
      ? 'The canonical issue sections are complete, but ownership of the existing `needs-info` label could not be verified; the intake bot retained the state and ownership marker.'
      : needsInfoRetained
        ? 'The canonical issue sections are complete. The intake bot retained the existing `needs-info` label because it could not prove that this run added it; a maintainer may resolve that state explicitly.'
        : 'The canonical issue sections are complete and this intake notice is resolved.',
    '',
    'The intake check is structural only: it does not verify, close, or infer additional acceptance criteria. Reference findings remain leads rather than proof, and an incomplete run is not a clean run.',
  ].join('\n');
}


async function listComments(github, params) {
  return github.paginate(github.rest.issues.listComments, params);
}

function eventOrder(event) {
  const time = Date.parse(event && event.created_at);
  const id = Number(event && event.id);
  if (!Number.isFinite(time) || !Number.isSafeInteger(id)) {
    return null;
  }
  return { time, id };
}

function isLaterEvent(candidate, current) {
  const candidateOrder = eventOrder(candidate);
  const currentOrder = eventOrder(current);
  if (!candidateOrder || !currentOrder) {
    throw new Error('issue label event ordering is ambiguous');
  }

  if (candidateOrder.time !== currentOrder.time) {
    return candidateOrder.time > currentOrder.time;
  }

  return candidateOrder.id > currentOrder.id;
}

async function verifyNeedsInfoOwnership(github, request, issue, notice) {
  if (!notice || !notice.needsInfoOwned) {
    return false;
  }

  const labels = normalizeLabels(issue && issue.labels);
  if (!labels.includes('needs-info')) {
    return false;
  }

  const events = await github.paginate(
    github.rest.issues.listEventsForTimeline,
    request,
  );
  if (!Array.isArray(events)) {
    throw new Error('issue label timeline was unavailable');
  }

  const relevant = events.filter(
    (event) =>
      event &&
      (event.event === 'labeled' || event.event === 'unlabeled') &&
      event.label &&
      event.label.name === 'needs-info',
  );
  if (relevant.length === 0) {
    throw new Error('issue label ownership could not be established');
  }
  if (relevant.some((event) => !eventOrder(event))) {
    throw new Error('issue label event ordering is ambiguous');
  }

  let latest = relevant[0];
  for (const event of relevant.slice(1)) {
    if (isLaterEvent(event, latest)) {
      latest = event;
    }
  }

  if (
    !latest.actor ||
    !latest.actor.type ||
    !latest.actor.login
  ) {
    throw new Error('issue label event actor metadata is unavailable');
  }

  return (
    latest.event === 'labeled' &&
    latest.actor.type === 'Bot' &&
    latest.actor.login === 'github-actions[bot]'
  );
}
async function upsertNotice(github, request, notice, body) {
  if (notice) {
    if (notice.body === body) {
      return 'unchanged';
    }
    await github.rest.issues.updateComment({
      owner: request.owner,
      repo: request.repo,
      comment_id: notice.id,
      body,
    });
    return 'updated';
  }

  await github.rest.issues.createComment({
    ...request,
    body,
  });
  return 'created';
}


async function run({ github, context, core } = {}) {
  if (!github || !context) {
    throw new TypeError('run requires github and context');
  }

  const issueNumber = context.payload && context.payload.issue && context.payload.issue.number;
  if (!Number.isInteger(issueNumber)) {
    return { skipped: true, reason: 'not-an-issue-event' };
  }

  const { owner, repo } = context.repo || {};
  if (!owner || !repo) {
    throw new TypeError('run requires context.repo owner and repo');
  }

  const request = { owner, repo, issue_number: issueNumber };
  const issueResponse = await github.rest.issues.get(request);
  const issue = issueResponse.data;
  if (issue && issue.pull_request) {
    return { skipped: true, reason: 'pull-request' };
  }

  const comments = await listComments(github, request);
  const notice = findNoticeComment(comments);
  const validation = validateIssueBody(issue && issue.body);
  const labels = normalizeLabels(issue && issue.labels);
  let noticeOwned = Boolean(notice && notice.needsInfoOwned);
  if (validation.valid && noticeOwned && labels.includes('needs-info')) {
    noticeOwned = await verifyNeedsInfoOwnership(github, request, issue, notice);
  }
  const plan = planLabelChanges(labels, validation, { noticeOwned });
  const categoryDiscrepancies = plan.category.discrepancies;
  const noticeNeeded =
    !validation.valid || categoryDiscrepancies.length > 0;
  let noticeAction = 'none';

  if (noticeNeeded) {
    const noticeBody = buildNotice(validation, {
      needsInfoOwned: plan.automationNeedsInfoOwned,
      needsInfoRetained: plan.preserveManualNeedsInfo,
      categoryDiscrepancies,
    });
    noticeAction = await upsertNotice(github, request, notice, noticeBody);
  }

  // Add before remove so a complete transition never leaves an issue without
  // an intake state if the second request is interrupted. Incomplete
  // ownership intent is persisted by the notice above before this mutation.
  if (plan.add.length > 0) {
    await github.rest.issues.addLabels({ ...request, labels: plan.add });
  }
  for (const label of plan.remove) {
    await github.rest.issues.removeLabel({ ...request, name: label });
  }

  if (!noticeNeeded && notice) {
    const resolvedBody = buildResolvedNotice({
      needsInfoRetained: plan.preserveManualNeedsInfo,
      needsInfoOwned: false,
    });
    noticeAction = await upsertNotice(github, request, notice, resolvedBody);
  }

  if (core && typeof core.info === 'function') {
    core.info(
      !validation.valid
        ? `Issue #${issueNumber} requires additional intake information.`
        : categoryDiscrepancies.length > 0
          ? `Issue #${issueNumber} has a category-label discrepancy requiring explicit review.`
          : `Issue #${issueNumber} passed canonical intake validation.`,
    );
  }

  return {
    skipped: false,
    issueNumber,
    valid: validation.valid,
    validation,
    labelPlan: plan,
    noticeAction,
  };
}

module.exports = {
  REQUIRED_HEADINGS,
  CLASSIFICATION_CHOICES,
  normalizeBody,
  extractSections,
  validateIssueBody,
  planCategoryChanges,
  planLabelChanges,
  findNoticeComment,
  buildNotice,
  buildResolvedNotice,
  run,
};
