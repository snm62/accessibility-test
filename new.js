// Security Headers
const securityHeaders = {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'SAMEORIGIN',
    'X-XSS-Protection': '1; mode=block',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains'
};



// Check if installation exists
async function handleCheckInstallation(request, env) {
  const origin = request.headers.get('origin');
  
  try {
    const url = new URL(request.url);
    const siteId = url.searchParams.get('siteId');
    
    if (!siteId) {
      const errorResponse = secureJsonResponse({ 
        error: 'Missing siteId parameter' 
      }, 400);
      return addSecurityAndCorsHeaders(errorResponse, origin);
    }
    
    console.log('🔍 Checking if installation exists for siteId:', siteId);
    
    // Check if installation record exists in KV
    const installationKey = `installation_${siteId}`;
    const installationRecord = await env.ACCESSIBILITY_AUTH.get(installationKey);
    
    if (!installationRecord) {
      console.log('❌ Installation record not found for siteId:', siteId);
      const response = secureJsonResponse({ exists: false }, 404);
      return addSecurityAndCorsHeaders(response, origin);
    }
    
    console.log('✅ Installation record found for siteId:', siteId);
    const response = secureJsonResponse({ exists: true });
    return addSecurityAndCorsHeaders(response, origin);
    
  } catch (error) {
    console.error('❌ Error checking installation:', error);
    const errorResponse = secureJsonResponse({ 
      error: 'Failed to check installation',
      details: error.message 
    }, 500);
    return addSecurityAndCorsHeaders(errorResponse, origin);
  }
}

// Handle Webflow App Installation
async function handleWebflowAppInstallation(request, env) {
  const origin = request.headers.get('origin');
  const ip = getClientIp(request);
  const ipOk = await checkRateLimit(env, 'app-installed-ip', ip, 10, 60);
  if (!ipOk) {
    return addSecurityAndCorsHeaders(new Response(JSON.stringify({ error: 'Too many requests', retryAfter: 60 }), {
      status: 429,
      headers: { 'Content-Type': 'application/json', 'Retry-After': '60' }
    }), origin);
  }
  try {
    console.log('🔍 Starting installation webhook handler');
    const requestBody = await request.text();
    console.log('📦 Raw request body:', requestBody);
    
    let parsedData;
    try {
      parsedData = JSON.parse(requestBody);
    } catch (parseError) {
      console.error('❌ Failed to parse JSON:', parseError);
      const errorResponse = secureJsonResponse({ 
        error: 'Invalid JSON in request body',
        details: parseError.message 
      }, 400);
      return addSecurityAndCorsHeaders(errorResponse, origin);
    }
    
    console.log('✅ Parsed data:', JSON.stringify(parsedData, null, 2));
    
    const { siteId, userId, userEmail, siteName, installationData } = parsedData;
    
    if (!siteId || !userEmail) {
      console.error('❌ Missing required fields: siteId or userEmail');
      const errorResponse = secureJsonResponse({ 
        error: 'Missing required fields: siteId and userEmail are required' 
      }, 400);
      return addSecurityAndCorsHeaders(errorResponse, origin);
    }
    
    const siteOk = await checkRateLimit(env, 'app-installed-site', siteId, 5, 60);
    if (!siteOk) {
      return addSecurityAndCorsHeaders(new Response(JSON.stringify({ error: 'Too many requests', retryAfter: 60 }), {
        status: 429,
        headers: { 'Content-Type': 'application/json', 'Retry-After': '60' }
      }), origin);
    }
    
    const maskedEmail = userEmail ? userEmail.replace(/([^@]).*(@.*)/, '$1****$2') : '';
    console.log('📤 Preparing to send installation notifications for:', maskedEmail);
    
    // Determine domain and check if it's staging or live
    // Never treat staging URL as customDomain: if frontend sent .webflow.io as customDomain, use only stagingUrl
    let customDomain = installationData?.customDomain || null;
    const shortName = installationData?.shortName || null;
    const stagingUrl = shortName ? `https://${shortName}.webflow.io` : null;
    const isStagingDomain = (d) => {
      if (!d) return false;
      const h = (d.startsWith('http') ? d : `https://${d}`).toLowerCase();
      return h.includes('.webflow.io') || h.includes('.webflow.com') || h.includes('localhost') || h.includes('127.0.0.1') || h.includes('staging');
    };
    if (customDomain && isStagingDomain(customDomain)) {
      customDomain = null;
      console.log('🔍 Ignored staging URL as customDomain; using only stagingUrl from shortName');
    }
    const domain = customDomain || stagingUrl;
    const domainHost = domain ? normalizeHost(domain) : null;
    
    // Check if staging domain (.webflow.io)
    const isStaging = domainHost && (
      domainHost.includes('.webflow.io') || 
      domainHost.includes('.webflow.com') ||
      domainHost.includes('localhost') ||
      domainHost.includes('127.0.0.1') ||
      domainHost.includes('staging')
    );
    
    console.log('🔍 Domain check:', { domain, domainHost, isStaging });
    
    // Check payment status for live domains
    let hasActivePayment = false;
    let clickupFolder = null;
    let paymentStatusData = null; // Store payment details for router condition
    
    if (isStaging) {
      // Staging: always create task in staging folder
      clickupFolder = 'staging';
      console.log('📁 Staging domain detected, will create task in staging folder');
    } else if (domainHost) {
      // Live domain: check payment status
      console.log('💰 Checking payment status for live domain:', domainHost);
      
      try {
        // Try to get customer data by domain
        const domainKey = `domain:${domainHost}`;
        const customerId = await env.ACCESSIBILITY_AUTH.get(domainKey);
        
        if (customerId) {
          const customerKey = `customer:${customerId}`;
          const customerDataStr = await env.ACCESSIBILITY_AUTH.get(customerKey);
          
          if (customerDataStr) {
            const customerData = JSON.parse(customerDataStr);
            hasActivePayment = !!(
              customerData.paymentStatus === 'paid' ||
              customerData.subscriptionStatus === 'complete' ||
              customerData.isSubscribed === true ||
              (customerData.subscriptionStatus === 'active' && customerData.paymentStatus === 'paid')
            );
            
            // Store payment status details for router condition
            paymentStatusData = {
              paymentStatus: customerData.paymentStatus || 'unknown',
              subscriptionStatus: customerData.subscriptionStatus || 'unknown',
              isSubscribed: customerData.isSubscribed || false,
              subscriptionId: customerData.stripeSubscriptionId || null,
              customerId: customerId || null,
              planType: customerData.planType || null
            };
            
            console.log('💰 Payment status from customer data:', {
              paymentStatus: customerData.paymentStatus,
              subscriptionStatus: customerData.subscriptionStatus,
              isSubscribed: customerData.isSubscribed,
              hasActivePayment
            });
          }
        }
        
        // Also check by siteId as fallback
        if (!paymentStatusData && siteId) {
          const paymentRecord = await env.ACCESSIBILITY_AUTH.get(`payment:${siteId}`);
          if (paymentRecord) {
            const paymentData = JSON.parse(paymentRecord);
            hasActivePayment = paymentData.status === 'active' || paymentData.paymentStatus === 'paid';
            
            paymentStatusData = {
              paymentStatus: paymentData.paymentStatus || paymentData.status || 'unknown',
              subscriptionStatus: paymentData.subscriptionStatus || paymentData.status || 'unknown',
              isSubscribed: hasActivePayment,
              subscriptionId: paymentData.subscriptionId || null,
              customerId: paymentData.customerId || null,
              planType: paymentData.planType || null
            };
            
            console.log('💰 Payment status from siteId payment record:', {
              status: paymentData.status,
              paymentStatus: paymentData.paymentStatus,
              hasActivePayment
            });
          }
        }
        
        if (hasActivePayment) {
          clickupFolder = 'live';
          console.log('✅ Active payment found, will create task in live folder');
        } else {
          console.log('❌ No active payment found, will NOT create ClickUp task for live domain');
        }
      } catch (paymentCheckError) {
        console.error('❌ Error checking payment status:', paymentCheckError);
        // Don't create task if payment check fails for live domain
      }
    }
    
    // Send welcome email via Brevo and webhooks to Make.com for ClickUp task creation
    try {
      // Derive first name once, prefer explicit installationData firstName, then email local-part
      const firstName = (installationData?.firstName && installationData.firstName.trim()) || (userEmail?.split('@')[0]) || 'User';

      // ClickUp webhook URL
      const clickupWebhookUrl = env.MAKE_CLICKUP_WEBHOOK_URL || 'https://hook.us1.make.com/2nq5grcxerkoum85ibdhoayngay6j1hg';
      
      // Prepare webhook payload with all data in a flat, accessible structure
      const webhookPayload = {
        event: 'webflow_app_installed',
        // Customer information at top level for easy access
        email: userEmail,
        firstName,
        siteId: siteId,
        siteName: siteName,
        userId: userId,
        // Additional data from installationData
        customDomain: customDomain,
        stagingUrl: stagingUrl, // Include staging URL if available
        shortName: shortName,
        exp: installationData?.exp || null,
        timestamp: installationData?.timestamp || new Date().toISOString(),
        source: installationData?.source || 'webflow_app',
        // ClickUp folder information
        clickupFolder: clickupFolder,
        isStaging: isStaging,
        hasActivePayment: hasActivePayment,
        // Payment status details for router condition in Make.com
        paymentStatus: paymentStatusData?.paymentStatus || 'unknown',
        subscriptionStatus: paymentStatusData?.subscriptionStatus || 'unknown',
        isSubscribed: paymentStatusData?.isSubscribed || false,
        subscriptionId: paymentStatusData?.subscriptionId || null,
        customerId: paymentStatusData?.customerId || null,
        planType: paymentStatusData?.planType || null,
        // Keep nested structure for backward compatibility
        customer: {
          email: userEmail,
          firstName,
          siteId: siteId,
          siteName: siteName,
          userId: userId
        },
        installation: {
          timestamp: installationData?.timestamp || new Date().toISOString(),
          data: installationData || {}
        },
        // Include full siteInfo if available
        siteInfo: installationData?.siteInfo || null
      };
      
      // Mask email in logs before printing payload
      const payloadToLog = Object.assign({}, webhookPayload, { email: webhookPayload.email ? webhookPayload.email.replace(/([^@]).*(@.*)/, '$1****$2') : webhookPayload.email });
      console.log('🚀 Sending welcome email via Brevo (email masked payload):', JSON.stringify(payloadToLog, null, 2));

      // Send welcome email through Brevo
      const emailSent = await sendWelcomeEmail(env, userEmail, firstName);
      if (!emailSent) {
        console.warn('⚠️ Brevo welcome email failed or returned false for:', maskedEmail);
      }
      
      // Always send to ClickUp webhook - Make.com router will decide based on clickupFolder
      // clickupFolder will be: 'staging', 'live', or null
      // Make.com router can check payment status and folder to route accordingly
      console.log(`📁 Sending to ClickUp webhook with folder: ${clickupFolder || 'null (no folder - live domain without payment)'}`);
      const clickupWebhookResponse = await fetch(clickupWebhookUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(webhookPayload)
      });
      
      const clickupWebhookResponseText = await clickupWebhookResponse.text();
      console.log('📨 ClickUp webhook response status:', clickupWebhookResponse.status);
      console.log('📨 ClickUp webhook response body:', clickupWebhookResponseText);
      
      if (!clickupWebhookResponse.ok) {
        console.error('❌ ClickUp webhook failed:', clickupWebhookResponse.status, clickupWebhookResponseText);
      } else {
        console.log(`✅ ClickUp webhook sent successfully (folder: ${clickupFolder || 'null'})`);
      }
      
    } catch (webhookError) {
      console.error('❌ Error sending webhook to Make.com:', webhookError);
      console.error('❌ Webhook error stack:', webhookError.stack);
    }
    
    // Store full installation data from frontend for reuse in payment webhooks
    const installationRecord = {
      siteId,
      userId,
      userEmail,
      siteName,
      firstName: (installationData?.firstName && installationData.firstName.trim()) || (userEmail?.split('@')[0]) || 'User',
      customDomain: customDomain,
      stagingUrl: stagingUrl,
      shortName: shortName,
      installedAt: new Date().toISOString(),
      status: 'installed',
      installationData: installationData // Store full installation data
    };
    
    await env.ACCESSIBILITY_AUTH.put(`installation_${siteId}`, JSON.stringify(installationRecord));
    
    // Also store by email for easy lookup during payment webhooks
    if (userEmail) {
      try {
        const emailLower = userEmail.toLowerCase().trim();
        if (env.EMAIL_ENCRYPTION_KEY && env.EMAIL_INDEX_KEY) {
          // encrypt and index by HMAC(email)
          const encrypted = await encryptEmailServerSide(emailLower, env);
          const emailHash = await computeHmacHex(emailLower, env.EMAIL_INDEX_KEY);
          installationRecord.encryptedEmail = encrypted;
          installationRecord.emailHash = emailHash;
          // Remove plaintext email from stored record
          delete installationRecord.userEmail;
          await env.ACCESSIBILITY_AUTH.put(`installation-email-hash:${emailHash}`, JSON.stringify(installationRecord));
          console.log('✅ Stored encrypted installation data under hashed email key:', `installation-email-hash:${emailHash}`);
        } else {
          // Fallback: legacy behavior (plaintext index) if env not configured
          await env.ACCESSIBILITY_AUTH.put(`installation-email:${emailLower}`, JSON.stringify(installationRecord));
          console.log('✅ Stored installation data by email (legacy):', userEmail);
        }
      } catch (encryptionErr) {
        console.error('❌ Failed to encrypt/store email:', encryptionErr);
        // Fall back to plaintext storage to avoid blocking installation flow
        try { await env.ACCESSIBILITY_AUTH.put(`installation-email:${userEmail.toLowerCase()}`, JSON.stringify(installationRecord)); } catch (e) {}
      }
    }
    
    // Also store by domain for lookup when email doesn't match
    // Store with raw customDomain value (no normalization) to match exactly
    if (customDomain) {
      await env.ACCESSIBILITY_AUTH.put(`installation-domain:${customDomain}`, JSON.stringify(installationRecord));
      console.log('✅ Stored installation data by domain (raw):', customDomain);
      
      // Also store normalized version as fallback for variations
      const normalizedDomain = normalizeHost(customDomain);
      if (normalizedDomain && normalizedDomain !== customDomain) {
        await env.ACCESSIBILITY_AUTH.put(`installation-domain:${normalizedDomain}`, JSON.stringify(installationRecord));
        console.log('✅ Stored installation data by domain (normalized):', normalizedDomain);
      }
    }
    // Start 7-day trial immediately for new installs
    const now = new Date();
    const trialEnd = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000);
    
    // Ledger record
    const userData = {
      siteId,
      email: userEmail || '',
      domain: '',
      paymentStatus: 'trial',
      trialStartDate: now.toISOString(),
      trialEndDate: trialEnd.toISOString(),
      createdAt: now.toISOString()
    };
    // user_data_${siteId} removed - using customer:${customerId} instead
    
    // Unified settings
    await mergeSiteSettings(env, siteId, {
      siteId,
      email: userEmail || '',
      siteName: siteName || '',
      paymentStatus: 'trial',
      trialStartDate: now.toISOString(),
      trialEndDate: trialEnd.toISOString()
    });
    
    const successResponse = secureJsonResponse({ 
      success: true,
      message: 'App installation recorded successfully'
    });
    return addSecurityAndCorsHeaders(successResponse, origin);
    
  } catch (error) {
    console.error('❌ Fatal error in handleWebflowAppInstallation:', error);
    console.error('❌ Error stack:', error.stack);
    const errorResponse = secureJsonResponse({ 
      error: 'Failed to process app installation',
      details: error.message 
    }, 500);
    return addSecurityAndCorsHeaders(errorResponse, origin);
  }
}

// Security Functions
function secureJsonResponse(data, status = 200) {
    return new Response(JSON.stringify(data), {
        status,
        headers: {
            'Content-Type': 'application/json',
        },
    });
}

function sanitizeInput(input) {
    return input.replace(/[<>\"'&]/g, (match) => {
        const escapeMap = {
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#x27;',
            '&': '&amp;'
        };
        return escapeMap[match];
    });
}

// Strictly sanitize the Accessibility Statement URL:
// - Only allow absolute http/https URLs
// - Everything else (javascript:, data:, invalid URLs, empty) becomes an empty string
function sanitizeAccessibilityStatementLink(link) {
    if (!link || typeof link !== 'string') return '';
    const trimmed = link.trim();
    if (!trimmed) return '';
    try {
        const url = new URL(trimmed);
        const protocol = url.protocol.toLowerCase();
        if (protocol === 'http:' || protocol === 'https:') {
            return trimmed;
        }
        return '';
    } catch (e) {
        // Invalid/relative URL – treat as unsafe
        return '';
    }
}

// Allowed origins for auth-data and save-settings only (CORS whitelist; publish uses any origin)
const AUTH_DATA_ALLOWED_ORIGINS = new Set([
    'https://app.accessbit.io',
    'https://accessbit.io',
    'https://accessbit-test.web-8fb.workers.dev',
    'https://accessibility-widget.web-8fb.workers.dev'
]);

function getAllowedAuthDataOrigin(origin) {
    if (!origin || typeof origin !== 'string') return null;
    const normalized = origin.replace(/\/+$/, '');
    return AUTH_DATA_ALLOWED_ORIGINS.has(normalized) ? normalized : null;
}

// Publish only: allow any origin (echo request origin or '*')
function getPublishCorsOrigin(origin) {
    if (!origin || typeof origin !== 'string') return '*';
    const normalized = origin.replace(/\/+$/, '');
    try {
        const u = new URL(normalized);
        if (u.protocol !== 'https:' && u.protocol !== 'http:') return '*';
        if (u.protocol === 'http:' && u.hostname !== 'localhost' && !u.hostname.startsWith('127.')) return '*';
        return normalized;
    } catch (_) { return '*'; }
}

// Rate limiting via KV (per identifier + time window)
function getClientIp(request) {
    return request.headers.get('CF-Connecting-IP') ||
        (request.headers.get('X-Forwarded-For') || '').split(',')[0].trim() ||
        'unknown';
}

async function checkRateLimit(env, prefix, identifier, limit, windowSec) {
    if (!identifier || limit <= 0 || windowSec <= 0) return true;
    const bucket = windowSec <= 1
        ? Math.floor(Date.now() / 1000)
        : Math.floor(Date.now() / 60000);
    const key = `ratelimit:${prefix}:${String(identifier).replace(/:/g, '_')}:${bucket}`;
    const raw = await env.ACCESSIBILITY_AUTH.get(key);
    const count = parseInt(raw || '0', 10);
    if (count >= limit) return false;
    // Cloudflare KV requires expiration_ttl >= 60 seconds.
    // For 1-second buckets we still use per-second keys, but keep them for 60s.
    const ttl = windowSec <= 1 ? 60 : Math.max(windowSec + 60, 60);
    await env.ACCESSIBILITY_AUTH.put(key, String(count + 1), { expirationTtl: ttl });
    return true;
}

function rateLimitResponse(origin) {
    const body = JSON.stringify({ error: 'Too many requests', retryAfter: 60 });
    const headers = new Headers({
        'Content-Type': 'application/json',
        'Retry-After': '60'
    });
    if (origin) headers.set('Access-Control-Allow-Origin', origin);
    return new Response(body, { status: 429, headers });
}

// --- Server-side email encryption & HMAC helpers (AES-GCM + HMAC-SHA256) ---
async function base64ToArrayBuffer(s) {
    const b = atob(s);
    const len = b.length;
    const arr = new Uint8Array(len);
    for (let i = 0; i < len; i++) arr[i] = b.charCodeAt(i);
    return arr.buffer;
}

function arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary);
}

async function importAesKeyFromBase64(b64) {
    const raw = await base64ToArrayBuffer(b64);
    return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

async function importHmacKeyFromBase64(b64) {
    const raw = await base64ToArrayBuffer(b64);
    return crypto.subtle.importKey('raw', raw, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
}

async function encryptEmailServerSide(plaintext, env) {
    if (!env.EMAIL_ENCRYPTION_KEY) throw new Error('EMAIL_ENCRYPTION_KEY not configured');
    const aesKey = await importAesKeyFromBase64(env.EMAIL_ENCRYPTION_KEY);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const enc = new TextEncoder().encode(plaintext);
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, enc);
    const ciphertextB64 = arrayBufferToBase64(ct);
    const ivB64 = arrayBufferToBase64(iv.buffer);
    return { ciphertext: ciphertextB64, iv: ivB64 };
}

async function decryptEmailServerSide(encryptedObj, env) {
    if (!env.EMAIL_ENCRYPTION_KEY) throw new Error('EMAIL_ENCRYPTION_KEY not configured');
    const aesKey = await importAesKeyFromBase64(env.EMAIL_ENCRYPTION_KEY);
    const ivBuf = await base64ToArrayBuffer(encryptedObj.iv);
    const ctBuf = await base64ToArrayBuffer(encryptedObj.ciphertext);
    const plainBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: new Uint8Array(ivBuf) }, aesKey, ctBuf);
    return new TextDecoder().decode(plainBuf);
}

async function computeHmacHex(message, b64Key) {
    if (!b64Key) throw new Error('HMAC key not configured');
    const hmacKey = await importHmacKeyFromBase64(b64Key);
    const data = new TextEncoder().encode(message);
    const sig = await crypto.subtle.sign('HMAC', hmacKey, data);
    const bytes = new Uint8Array(sig);
    // return hex string
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

// --- End encryption helpers ---

// function rateLimitCheck(ip, requests) { ... } // removed

// Unified site settings storage helpers (canonical key: accessibility-settings:<siteId>)
async function getSiteSettings(env, siteId) {
  const existing = await env.ACCESSIBILITY_AUTH.get(`accessibility-settings:${siteId}`);
  if (!existing) {
    return {
      siteId,
      customization: {},
      accessibilityProfiles: {},
      email: '',
      domain: '',
      paymentStatus: 'unknown',
      trialStartDate: null,
      trialEndDate: null,
      customerId: '',
      subscriptionId: '',
      lastPaymentDate: null,
      lastUpdated: new Date().toISOString(),
      lastUsed: new Date().toISOString()
    };
  }
  try { return JSON.parse(existing); } catch { return { siteId, customization: {} }; }
}

async function mergeSiteSettings(env, siteId, patch) {
  const current = await getSiteSettings(env, siteId);
  const updated = { ...current, ...patch, lastUpdated: new Date().toISOString(), lastUsed: new Date().toISOString() };
  await env.ACCESSIBILITY_AUTH.put(`accessibility-settings:${siteId}`, JSON.stringify(updated));
  return updated;
}

// Persist payment record per site in KV
async function savePaymentRecord(env, siteId, record) {
  if (!siteId) return;
  const key = `payments:${siteId}`;
  let existing = [];
  try {
    const raw = await env.ACCESSIBILITY_AUTH.get(key);
    if (raw) existing = JSON.parse(raw);
  } catch (_) {}
  const enriched = {
    id: record.id || crypto.randomUUID?.() || `${Date.now()}`,
    siteId,
    type: record.type || 'unknown',
    timestamp: record.timestamp || new Date().toISOString(),
    currency: record.currency || null,
    amount: record.amount || null,
    status: record.status || null,
    customerId: record.customerId || null,
    subscriptionId: record.subscriptionId || null,
    invoiceId: record.invoiceId || null,
    paymentIntentId: record.paymentIntentId || null,
    paymentMethodId: record.paymentMethodId || null,
    currentPeriodStart: record.currentPeriodStart || null,
    currentPeriodEnd: record.currentPeriodEnd || null,
    metadata: record.metadata || {},
  };
  existing.push(enriched);
  await env.ACCESSIBILITY_AUTH.put(key, JSON.stringify(existing));
  // Also keep last-payment shortcut
  await env.ACCESSIBILITY_AUTH.put(`payments:last:${siteId}`, JSON.stringify(enriched));
  return enriched;
}

function addSecurityAndCorsHeaders(response, origin) {
    const headers = new Headers(response.headers);
    
    // Add all security headers
    Object.entries(securityHeaders).forEach(([key, value]) => {
        headers.set(key, value);
    });
    // CORS Headers
    headers.set('Access-Control-Allow-Origin', origin || '*');
    headers.set('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    headers.set('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With, Accept, Origin, X-CSRF-Token');
    headers.set('Access-Control-Allow-Credentials', 'true');
    headers.set('Access-Control-Max-Age', '86400');
    headers.set('Vary', 'Origin');
    
    return new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers,
    });
}


// Complete Accessibility Widget Cloudflare Worker
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const origin = request.headers.get('origin');
    // const clientIP = request.headers.get('x-forwarded-for') || 'unknown';
    
    // Handle CORS preflight (publish = any origin; others = whitelist)
    if (request.method === 'OPTIONS') {
      const pathNorm = url.pathname.replace(/\/+/g, '/').replace(/\/$/, '') || '/';
      const allowOrigin = pathNorm === '/api/accessibility/publish'
        ? getPublishCorsOrigin(origin)
        : (getAllowedAuthDataOrigin(origin) || '*');
      return handleCORS(allowOrigin);
    }
    
    // OAuth Authorization - redirect to Webflow
    if (url.pathname === '/api/auth/authorize') {
      return handleOAuthAuthorize(request, env);
    }
    
    // OAuth Callback - handle Webflow redirect
    if (url.pathname === '/api/auth/callback') {
      return handleOAuthCallback(request, env);
    }
    
    // OAuth Success Page - closes popup and sends message to parent
    if (url.pathname === '/auth-success') {
      return handleAuthSuccess(request, env);
    }
    
    
    // Token Authentication
    if (url.pathname === '/api/auth/token' && request.method === 'POST') {
      return handleTokenAuth(request, env);
    }
    
     if (url.pathname === '/api/auth/verify') {
      return handleVerifyAuth(request, env);
    }
    
    // Publish accessibility settings (normalize path so trailing slash still matches)
    const pathNorm = url.pathname.replace(/\/+/g, '/').replace(/\/$/, '') || '/';
    if (pathNorm === '/api/accessibility/publish' && request.method === 'POST') {
      try {
        return await handlePublishSettings(request, env);
      } catch (err) {
        const errMsg = (err && (err.message || String(err))) || 'Unhandled error';
        const body = JSON.stringify({ error: 'Internal server error', message: errMsg });
        return new Response(body, {
          status: 500,
          headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': getPublishCorsOrigin(origin || '') }
        });
      }
    }
    
    // Register accessibility script
    if (url.pathname.replace(/\/+/g,'/') === '/api/accessibility/register-script') {
      return handleRegisterScript(request, env);
    }
    
    // Apply accessibility script
    if (url.pathname.replace(/\/+/g,'/') === '/api/accessibility/apply-script') {
      return handleApplyScript(request, env);
    }
    
    // Get access token by site ID from URL params
if (url.pathname === '/api/accessibility/get-token' && request.method === 'GET') {
  return handleGetTokenBySiteId(request, env);
}

    // Get widget script URL by site ID
if (url.pathname === '/api/accessibility/get-widget-url' && request.method === 'GET') {
  return handleGetWidgetUrl(request, env);
}

  // RATE LIMITING DISABLED per request (was returning 429 Too Many Requests)
    

    // Get accessibility settings
    if (url.pathname === '/api/accessibility/settings' && request.method === 'GET') {
      return handleGetSettings(request, env);
    }
    
    // Update accessibility settings
    if (url.pathname === '/api/accessibility/settings' && (request.method === 'POST' || request.method === 'PUT')) {
      return handleUpdateSettings(request, env);
    }
    
   
   
    
// Get accessibility configuration for hosted script
if (url.pathname.replace(/\/+/g,'/') === '/api/accessibility/config' && request.method === 'GET') {
  return handleGetConfig(request, env);
}


// Domain lookup endpoint
if (url.pathname.replace(/\/+/g,'/') === '/api/accessibility/domain-lookup' && request.method === 'GET') {
  return handleDomainLookup(request, env);
}

// Save accessibility settings
if (url.pathname.replace(/\/+/g,'/') === '/api/accessibility/save-settings' && request.method === 'POST') {
  return handleSaveSettings(request, env);
}

// NEW PAYMENT ENDPOINTS
if (url.pathname.replace(/\/+/g,'/') === '/api/accessibility/payment-status' && request.method === 'GET') {
  return handlePaymentStatus(request, env);
}
if (url.pathname.replace(/\/+/g,'/') === '/api/accessibility/validate-domain' && request.method === 'POST') {
  return handleValidateDomain(request, env);
}
if (url.pathname.replace(/\/+/g,'/') === '/api/accessibility/user-data' && request.method === 'GET') {
  return handleUserData(request, env);
}

// Get decrypted email (authorized webhooks) - requires header 'x-webhook-auth' === env.WEBHOOK_AUTH_TOKEN
if (url.pathname.replace(/\/+/g,'/') === '/api/accessibility/get-decrypted-email' && request.method === 'GET') {
  const auth = request.headers.get('x-webhook-auth') || request.headers.get('authorization');
  if (!auth || !env.WEBHOOK_AUTH_TOKEN || auth !== env.WEBHOOK_AUTH_TOKEN) {
    return addSecurityAndCorsHeaders(secureJsonResponse({ error: 'Unauthorized' }, 401), origin);
  }

  const siteId = url.searchParams.get('siteId');
  const email = url.searchParams.get('email');

  try {
    let installationDataStr = null;
    if (siteId) {
      installationDataStr = await env.ACCESSIBILITY_AUTH.get(`installation_${siteId}`);
    } else if (email && env.EMAIL_INDEX_KEY) {
      const emailLower = email.toLowerCase().trim();
      const emailHash = await computeHmacHex(emailLower, env.EMAIL_INDEX_KEY);
      installationDataStr = await env.ACCESSIBILITY_AUTH.get(`installation-email-hash:${emailHash}`);
    }

    if (!installationDataStr) return addSecurityAndCorsHeaders(secureJsonResponse({ error: 'Not found' }, 404), origin);

    const installationData = JSON.parse(installationDataStr);
    if (!installationData.encryptedEmail) return addSecurityAndCorsHeaders(secureJsonResponse({ error: 'No encrypted email stored' }, 404), origin);

    const decrypted = await decryptEmailServerSide(installationData.encryptedEmail, env);
    return addSecurityAndCorsHeaders(secureJsonResponse({ email: decrypted }), origin);
  } catch (err) {
    console.error('❌ Error decrypting email:', err);
    return addSecurityAndCorsHeaders(secureJsonResponse({ error: 'Failed to decrypt' }, 500), origin);
  }
}
if (url.pathname.replace(/\/+/g,'/') === '/api/accessibility/update-payment' && request.method === 'POST') {
  return handleUpdatePayment(request, env);
}
if (url.pathname.replace(/\/+/g,'/') === '/api/accessibility/create-setup-intent' && request.method === 'POST') {
  return handleCreateSetupIntent(request, env);
}
if (url.pathname.replace(/\/+/g,'/') === '/api/accessibility/create-subscription' && request.method === 'POST') {
  return handleCreateSubscription(request, env);
}
if (url.pathname.replace(/\/+/g,'/') === '/api/accessibility/cancel-subscription' && request.method === 'POST') {
  return handleCancelSubscription(request, env);
}
if (url.pathname.replace(/\/+/g,'/') === '/api/accessibility/subscription-status' && request.method === 'POST') {
  return handleGetSubscriptionStatus(request, env);
}
if (url.pathname.replace(/\/+/g,'/') === '/api/accessibility/update-subscription-metadata' && request.method === 'POST') {
  return handleUpdateSubscriptionMetadata(request, env);
}
if (url.pathname.replace(/\/+/g,'/') === '/api/accessibility/remove-widget' && request.method === 'POST') {
  return handleRemoveWidget(request, env);
}
if (url.pathname.replace(/\/+/g,'/') === '/api/accessibility/install-widget' && request.method === 'POST') {
  return handleInstallWidget(request, env);
}
if (url.pathname.replace(/\/+/g,'/') === '/api/accessibility/create-payment-intent' && request.method === 'POST') {
  return handleCreatePaymentIntent(request, env);
}

    // Stripe Webhook endpoint
    if (url.pathname.replace(/\/+/g,'/') === '/api/stripe/webhook' && request.method === 'POST') {
      return handleStripeWebhook(request, env);
    }

    // Create Stripe Checkout Session
    if (url.pathname === '/api/stripe/create-checkout-session' && request.method === 'POST') {
      return handleCreateCheckoutSession(request, env);
    }

    // Debug endpoint to check KV data
    if (url.pathname === '/api/debug/kv-keys' && request.method === 'GET') {
      return handleDebugKVKeys(request, env);
    }

    // Fix domain index for existing data
    if (url.pathname === '/api/debug/fix-domain-index' && request.method === 'POST') {
      return handleFixDomainIndex(request, env);
    }

    // Domain-based customer data lookup
    if (url.pathname === '/api/stripe/customer-data-by-domain' && request.method === 'GET') {
      return handleCustomerDataByDomain(request, env);
    }

    
    // Webflow App Installation Webhook
    if (url.pathname.replace(/\/+/g,'/') === '/api/webflow/app-installed' && request.method === 'POST') {
      console.log('📥 Installation webhook request received');
      return handleWebflowAppInstallation(request, env);
    }
    
    // Check if installation exists
    if (url.pathname.replace(/\/+/g,'/') === '/api/accessibility/check-installation' && request.method === 'GET') {
      return handleCheckInstallation(request, env);
    }
    
    // Manual subscription activation
    if (url.pathname === '/api/accessibility/activate-subscription' && request.method === 'POST') {
     
      return handleActivateSubscription(request, env);
    }
    
    // Check subscription status
    if (url.pathname === '/api/accessibility/check-subscription-status' && request.method === 'GET') {
      return handleCheckSubscriptionStatus(request, env);
    }
    
    // Get subscription plan details
    if (url.pathname === '/api/accessibility/get-subscription-plan' && request.method === 'GET') {
      return handleGetSubscriptionPlan(request, env);
    }
    

    
    // Test endpoint to verify worker is working
    if (url.pathname === '/api/test' && request.method === 'GET') {
      return new Response(JSON.stringify({ message: 'Worker is working', timestamp: new Date().toISOString() }), {
        headers: { 'Content-Type': 'application/json' }
      });
    }
    
// Check payment status for custom domain
if (url.pathname === '/api/accessibility/check-payment-status' && request.method === 'GET') {
  return handleCheckPaymentStatus(request, env);
}

// Manual domain mapping fix endpoint
if (url.pathname === '/api/accessibility/fix-domain-mapping' && request.method === 'POST') {
  return handleFixDomainMapping(request, env);
}

// Debug payment data endpoint
if (url.pathname === '/api/accessibility/debug-payment' && request.method === 'GET') {
  return handleDebugPayment(request, env);
}


// Reactivate subscription endpoint
if (url.pathname === '/api/accessibility/reactivate-subscription' && request.method === 'POST') {
  return handleReactivateSubscription(request, env);
}
    
    // Widget script with payment check
    if (url.pathname === '/widget.js' && request.method === 'GET') {
      return handleWidgetScript(request, env);
    }
    
    // Setup payment method
    if (url.pathname === '/api/accessibility/setup-payment' && request.method === 'POST') {
      return handleSetupPayment(request, env);
    }
    
    // Verify payment method
    if (url.pathname === '/api/accessibility/verify-payment-method' && request.method === 'POST') {
      return handleVerifyPaymentMethod(request, env);
    }
    

// Save custom domain data (can be updated)
if (url.pathname === '/api/accessibility/save-custom-domain' && request.method === 'POST') {
    try {
        const { siteId, customDomain, customization } = await request.json();
        
        if (!siteId || !customDomain) {
            return new Response(JSON.stringify({ error: 'Missing siteId or customDomain' }), {
                status: 400,
                headers: { 
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*',
                    'Access-Control-Allow-Methods': 'POST, OPTIONS',
                    'Access-Control-Allow-Headers': 'Content-Type'
                }
            });
        }
        
        // Get existing custom domain data
        const existingData = await env.ACCESSIBILITY_AUTH.get(`custom-domain-data:${siteId}`);
        let existingDomainData = {};
        
        if (existingData) {
            try {
                existingDomainData = JSON.parse(existingData);
            } catch (error) {
                console.warn('Failed to parse existing custom domain data:', error);
            }
        }
        
        // Update custom domain data
        const updatedDomainData = {
            ...existingDomainData,
            siteId: siteId,
            customDomain: customDomain,
            customization: customization || existingDomainData.customization || {},
            lastUpdated: new Date().toISOString(),
            lastUsed: new Date().toISOString()
        };
        
        // Save custom domain data
            await env.ACCESSIBILITY_AUTH.put(`custom-domain-data:${siteId}`, JSON.stringify(updatedDomainData));
            // Also save a domain-scoped record as requested
            const customDomainMirrorKey = `custom-domain:${customDomain}`;
            await env.ACCESSIBILITY_AUTH.put(customDomainMirrorKey, JSON.stringify({
              siteId,
              customDomain,
              customization: updatedDomainData.customization,
              lastUpdated: new Date().toISOString(),
              lastUsed: new Date().toISOString()
            }));
        
        // Also create domain mapping for lookup
        const domainKey = `domain:${customDomain}`;
        await env.ACCESSIBILITY_AUTH.put(domainKey, JSON.stringify({
            siteId: siteId,
            customDomain: customDomain,
            connectedAt: new Date().toISOString()
        }), { expirationTtl: 86400 * 30 }); // 30 days

        // Link domain -> installation so payment webhook can find installation when user pays with different email
        await backfillInstallationDomainIndex(env, siteId, customDomain);
        
        return new Response(JSON.stringify({ success: true }), {
            status: 200,
            headers: { 
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Methods': 'POST, OPTIONS',
                'Access-Control-Allow-Headers': 'Content-Type'
            }
        });
        
    } catch (error) {
        return new Response(JSON.stringify({ error: 'Failed to save custom domain data' }), {
            status: 500,
            headers: { 
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Methods': 'POST, OPTIONS',
                'Access-Control-Allow-Headers': 'Content-Type'
            }
        });
    }
}

// Get authorization data (read-only, never updated) — requires Bearer JWT; CORS restricted to whitelist
if (url.pathname === '/api/accessibility/auth-data' && request.method === 'GET') {
    try {
        const url = new URL(request.url);
        const siteId = url.searchParams.get('siteId');
        const requestOrigin = request.headers.get('origin') || '';
        const allowedOrigin = getAllowedAuthDataOrigin(requestOrigin);
        
        const makeHeaders = (statusCode) => {
            const base = {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Methods': 'GET, OPTIONS',
                'Access-Control-Allow-Headers': 'Content-Type, Authorization'
            };
            if (allowedOrigin) base['Access-Control-Allow-Origin'] = allowedOrigin;
            // For 401 we also advertise WWW-Authenticate
            if (statusCode === 401) {
                base['WWW-Authenticate'] = 'Bearer';
            }
            return base;
        };
        
        if (!siteId) {
            return new Response(JSON.stringify({ error: 'Missing siteId parameter' }), {
                status: 400,
                headers: makeHeaders(400)
            });
        }
        
        const ip = getClientIp(request);
        const ipOk = await checkRateLimit(env, 'auth-data-ip', ip, 10, 1);
        const siteOk = await checkRateLimit(env, 'auth-data-site', siteId, 30, 60);
        if (!ipOk || !siteOk) {
            const h = { ...makeHeaders(429), 'Retry-After': '60' };
            if (allowedOrigin) h['Access-Control-Allow-Origin'] = allowedOrigin;
            return new Response(JSON.stringify({ error: 'Too many requests', retryAfter: 60 }), { status: 429, headers: h });
        }
        
        // Require authentication: Bearer JWT must be present and valid
        const authResult = await verifyAuth(request, env);
        if (!authResult) {
            return new Response(JSON.stringify({ error: 'Unauthorized', message: 'Valid Authorization header required' }), {
                status: 401,
                headers: makeHeaders(401)
            });
        }
        // Restrict: caller may only access auth-data for the site they are authenticated for
        if (authResult.siteId !== siteId) {
            return new Response(JSON.stringify({ error: 'Forbidden', message: 'Not authorized to access this site' }), {
                status: 403,
                headers: makeHeaders(403)
            });
        }
        
        // Get authorization data from separate key (never overwritten)
        const authData = await env.ACCESSIBILITY_AUTH.get(`auth-data:${siteId}`);
        
        if (!authData) {
            return new Response(JSON.stringify({ error: 'Authorization data not found' }), {
                status: 404,
                headers: makeHeaders(404)
            });
        }
        
        const parsedData = JSON.parse(authData);
        
        // Return only authorization data (access token, site info, user info)
        const authResponse = {
            accessToken: parsedData.accessToken,
            siteId: parsedData.siteId,
            siteName: parsedData.siteName,
            user: parsedData.user,
            installedAt: parsedData.installedAt,
            widgetVersion: parsedData.widgetVersion
        };
        
        return new Response(JSON.stringify(authResponse), {
            status: 200,
            headers: makeHeaders(200)
        });
        
    } catch (error) {
        return new Response(JSON.stringify({ error: 'Failed to get authorization data' }), {
            status: 500,
            headers: {
                'Content-Type': 'application/json'
            }
        });
    }
}
    // Default response
    return new Response('Accessibility Widget API', { 
      status: 200,
      headers: { 
        'Content-Type': 'text/plain',
        'Access-Control-Allow-Origin': '*'
      }
    });
  },

  async scheduled(event, env, ctx) {
    try {
      await handle7DayReminderCron(env);
    } catch (e) {
      console.error('[CRON] scheduled handler error:', e);
    }
  }
};

// Handle CORS preflight (allowOrigin already computed by caller)
function handleCORS(allowOrigin) {
  const corsResponse = new Response(null, {
    status: 204,
    headers: {
      'Access-Control-Allow-Origin': allowOrigin,
      'Access-Control-Allow-Methods': 'GET, POST, PUT, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Access-Control-Max-Age': '86400'
    }
  });
  return addSecurityAndCorsHeaders(corsResponse, allowOrigin);
}
// Handle OAuth Authorization
async function handleOAuthAuthorize(request, env) {
  const url = new URL(request.url);
  const incomingState = url.searchParams.get("state");
  const siteId = url.searchParams.get("siteId");
  // Determine flow type and extract site ID
  const isDesigner = incomingState && incomingState.startsWith("webflow_designer");
  const scopes = [
    "sites:read",
    "sites:write",
    "custom_code:read",
    "custom_code:write",
    "authorized_user:read"
  ];
  // Use your worker's redirect URI for both flows
  const redirectUri = "https://accessbit-test-worker.web-8fb.workers.dev/api/auth/callback";
  const authUrl = new URL('https://webflow.com/oauth/authorize');
  authUrl.searchParams.set('client_id', env.WEBFLOW_CLIENT_ID);
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('redirect_uri', redirectUri);
  authUrl.searchParams.set('scope', scopes.join(' '));
  // Set state parameter with site ID for App Interface
  if (isDesigner) {
    const currentSiteId = siteId || (incomingState.includes('_') ? incomingState.split('_')[1] : null);
    if (currentSiteId) {
      authUrl.searchParams.set('state', `webflow_designer_${currentSiteId}`);
    } else {
      authUrl.searchParams.set('state', 'webflow_designer');
    }
  } else {
    // For Apps & Integrations flow, try to get site info from referrer
    const referrer = request.headers.get('referer') || '';
    let siteInfo = '';
    if (referrer.includes('.design.webflow.com')) {
      const match = referrer.match(/([^.]+)\.design\.webflow\.com/);
      if (match) {
        siteInfo = `_${match[1]}`;
      
      }
    }
    authUrl.searchParams.set('state', `accessibility_widget${siteInfo}`);
  }
  return new Response(null, {
    status: 302,
    headers: {
      'Location': authUrl.toString()
    }
  });
}


async function handleOAuthCallback(request, env) {
  const url = new URL(request.url);
  const code = url.searchParams.get('code');
  const state = url.searchParams.get('state');
  
  if (!code) {
    return new Response(JSON.stringify({ error: 'No authorization code provided' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  // Handle missing state parameter - assume Apps & Integrations flow
  if (!state) {
    // Continue with Apps & Integrations flow instead of throwing error
  }
  
  try {
    const isDesigner = state && state.startsWith('webflow_designer');
    const isAppsIntegrations = state && state.startsWith('accessibility_widget');
    const redirectUri = "https://accessbit-test-worker.web-8fb.workers.dev/api/auth/callback";
    
    // Extract site info from Apps & Integrations state
    let appsIntegrationsSiteInfo = null;
    if (isAppsIntegrations && state.includes('_')) {
      const parts = state.split('_');
      if (parts.length >= 3) {
        appsIntegrationsSiteInfo = parts.slice(2).join('_'); // Get everything after accessibility_widget_
       
      }
    }
    
    
    
    // Extract siteId from URL parameters
    const urlSiteId = url.searchParams.get('siteId');
 
    
    // Build token exchange request body conditionally
    const tokenRequestBody = {
      client_id: env.WEBFLOW_CLIENT_ID,
      client_secret: env.WEBFLOW_CLIENT_SECRET,
      code: code,
      grant_type: 'authorization_code'
    };
    
    // Only include redirect_uri for App Interface flow (Designer)
    // Apps & Integrations flow doesn't require redirect_uri in token exchange
    if (isDesigner) {
      tokenRequestBody.redirect_uri = redirectUri;
    }
    

    
    const tokenResponse = await fetch('https://api.webflow.com/oauth/access_token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(tokenRequestBody)
    });
    
    if (!tokenResponse.ok) {
      const errorText = await tokenResponse.text();
      
      throw new Error(`Token exchange failed: ${tokenResponse.status} - ${errorText}`);
    }
    
    const tokenData = await tokenResponse.json();
    
    
    // Get user info
    const userResponse = await fetch('https://api.webflow.com/v2/token/authorized_by', {
      headers: {
        'Authorization': `Bearer ${tokenData.access_token}`,
        'accept-version': '2.0.0'
      }
    });
    
    if (!userResponse.ok) {
      throw new Error(`User fetch failed: ${userResponse.status}`);
    }
    
    const userData = await userResponse.json();
    
    // Get sites
    const sitesResponse = await fetch('https://api.webflow.com/v2/sites', {
      headers: {
        'Authorization': `Bearer ${tokenData.access_token}`,
        'accept-version': '2.0.0'
      }
    });
    
    if (!sitesResponse.ok) {
      throw new Error(`Sites fetch failed: ${sitesResponse.status}`);
    }
    
    const sitesData = await sitesResponse.json();
    let sites = [];
    if (sitesData.sites) {
      sites = sitesData.sites;
    } else if (sitesData.items) {
      sites = sitesData.items;
    } else if (Array.isArray(sitesData)) {
      sites = sitesData;
    }
    
    if (sites.length === 0) {
      throw new Error('No Webflow sites found');
    }
    
    // Determine the current site FIRST
    let currentSite;
    if (isDesigner) {
      // App Interface flow - get site from state parameter
      const siteIdFromState = state.includes('_') ? state.split('_')[1] : null;
      if (siteIdFromState) {
        currentSite = sites.find(site => site.id === siteIdFromState) || sites[0];
      } else {
        currentSite = sites[0];
      }
    } else {
      // Apps & Integrations flow - determine site from URL parameter, state, or referrer
      if (urlSiteId) {
        // Use siteId from URL parameter if available
        const foundSite = sites.find(site => site.id === urlSiteId);
        if (foundSite) {
          currentSite = foundSite;
          
        } else {
        
          currentSite = sites[0];
        }
      } else if (appsIntegrationsSiteInfo) {
        const foundSite = sites.find(site => site.shortName === appsIntegrationsSiteInfo);
        currentSite = foundSite || sites[0];
      } else {
        // Fallback: try to get site info from referrer
        const referrer = request.headers.get('referer') || '';
        if (referrer.includes('.design.webflow.com')) {
          const match = referrer.match(/([^.]+)\.design\.webflow\.com/);
          if (match) {
            const shortName = match[1];
            const foundSite = sites.find(site => site.shortName === shortName);
            currentSite = foundSite || sites[0];
          } else {
            currentSite = sites[0];
          }
        } else {
          currentSite = sites[0];
        }
      }
    }
    
    // Generate JWT session token with the determined site
    const userId = userData.id || userData.email;
    const sessionToken = await createSessionToken({...userData, id: userId}, env, currentSite.id);
    
    // Handle different redirect scenarios
    if (isDesigner) {
      // App Interface flow - only store data for the current site
      
      // Store authorization data (canonical key)
      await env.ACCESSIBILITY_AUTH.put(`auth-data:${currentSite.id}`, JSON.stringify({
        accessToken: tokenData.access_token,
        siteName: currentSite.name || currentSite.shortName,
        siteId: currentSite.id,
        user: userData,
        email: userData.email || '',
        domainUrl: '',
        workspaceId: userData.workspaceId || '',
        installedAt: new Date().toISOString(),
        widgetVersion: '1.0.0',
        lastUsed: new Date().toISOString()
      }));
      
      // Create email->siteId index for easy lookup during payment webhooks
      if (userData.email) {
        await env.ACCESSIBILITY_AUTH.put(`email-siteid:${userData.email.toLowerCase()}`, currentSite.id);
      }
      
      // Store accessibility settings separately (can be updated)
      await env.ACCESSIBILITY_AUTH.put(`accessibility-settings:${currentSite.id}`, JSON.stringify({
        siteId: currentSite.id,
        customization: {},
        accessibilityProfiles: {},
        customDomain: null,
        lastUpdated: new Date().toISOString(),
        lastUsed: new Date().toISOString()
      }));


      // App Interface flow - redirect to success page that closes popup and sends message to parent
      const successUrl = new URL('https://accessbit-test-worker.web-8fb.workers.dev/auth-success');
      successUrl.searchParams.set('token', sessionToken.token);
      successUrl.searchParams.set('siteId', currentSite.id);
      successUrl.searchParams.set('siteName', encodeURIComponent(currentSite.name || currentSite.shortName || ''));
      successUrl.searchParams.set('shortName', currentSite.shortName || '');
      successUrl.searchParams.set('redirectUrl', encodeURIComponent(`https://${currentSite.shortName}.design.webflow.com?app=${env.WEBFLOW_CLIENT_ID}`));
      
      return new Response(null, {
        status: 302,
        headers: {
          'Location': successUrl.toString()
        }
      });
    }
    
    // Apps & Integrations flow - use the currentSite that was already determined

    
    // Store authorization data (canonical key)
    await env.ACCESSIBILITY_AUTH.put(`auth-data:${currentSite.id}`, JSON.stringify({
      accessToken: tokenData.access_token,
      siteName: currentSite.name || currentSite.shortName,
      siteId: currentSite.id,
      user: userData,
      email: userData.email || '',
      domainUrl: '',
      workspaceId: userData.workspaceId || '',
      installedAt: new Date().toISOString(),
      widgetVersion: '1.0.0',
      lastUsed: new Date().toISOString()
    }));
    
    // Create email->siteId index for easy lookup during payment webhooks
    if (userData.email) {
      await env.ACCESSIBILITY_AUTH.put(`email-siteid:${userData.email.toLowerCase()}`, currentSite.id);
    }
    
    // Initialize unified site settings (idempotent)
    await mergeSiteSettings(env, currentSite.id, { siteId: currentSite.id });
    // Initialize unified site settings (idempotent)
    await mergeSiteSettings(env, currentSite.id, { siteId: currentSite.id });
    
    // Also store the Webflow subdomain mapping for this site
    try {
      if (currentSite.shortName) {
        const webflowSubdomain = `${currentSite.shortName}.webflow.io`;
        const domainKey = `domain:${webflowSubdomain}`;
        
        await env.ACCESSIBILITY_AUTH.put(domainKey, JSON.stringify({
          siteId: currentSite.id,
          domain: webflowSubdomain,
          isPrimary: true,
          isWebflowSubdomain: true,
          connectedAt: new Date().toISOString()
        }), { expirationTtl: 86400 * 30 }); // 30 days
        
   
      }
    } catch (domainError) {
      
    }
    
    // Apps & Integrations flow - direct redirect to the selected Webflow site
    return new Response(null, {
      status: 302,
      headers: {
        'Location': `https://${currentSite.shortName}.design.webflow.com`
      }
    });
    
    
  } catch (error) {
   
    return new Response(JSON.stringify({ 
      error: 'Authorization failed', 
      details: error.message
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

// Handle OAuth Success Page - closes popup and sends message to parent
async function handleAuthSuccess(request, env) {
  const url = new URL(request.url);
  const token = url.searchParams.get('token');
  const siteId = url.searchParams.get('siteId');
  const siteName = url.searchParams.get('siteName') || '';
  const shortName = url.searchParams.get('shortName') || '';
  const redirectUrl = url.searchParams.get('redirectUrl') || '';
  
  // Get user data from stored auth data
  let userData = null;
  if (siteId) {
    try {
      const authData = await env.ACCESSIBILITY_AUTH.get(`auth-data:${siteId}`);
      if (authData) {
        const parsed = JSON.parse(authData);
        userData = parsed.user || {};
      }
    } catch (e) {
      // Ignore errors
    }
  }
  
  const decodedSiteName = siteName ? decodeURIComponent(siteName) : '';
  const decodedRedirectUrl = redirectUrl ? decodeURIComponent(redirectUrl) : '';
  
  // Escape all values for safe injection into JavaScript
  const escapeJs = (str) => {
    if (!str) return '';
    return String(str)
      .replace(/\\/g, '\\\\')
      .replace(/'/g, "\\'")
      .replace(/"/g, '&quot;')
      .replace(/\n/g, '\\n')
      .replace(/\r/g, '\\r');
  };
  
  const safeToken = escapeJs(token || '');
  const safeSiteId = escapeJs(siteId || '');
  const safeFirstName = escapeJs(userData?.firstName || 'User');
  const safeEmail = escapeJs(userData?.email || '');
  const safeSiteName = escapeJs(decodedSiteName);
  const safeShortName = escapeJs(shortName);
  const safeRedirectUrl = escapeJs(decodedRedirectUrl);
  
  return new Response(`<!DOCTYPE html>
<html>
<head>
  <title>Authorization Successful</title>
  <meta charset="utf-8">
</head>
<body>
  <script>
    (function() {
      try {
        const sessionData = {
          type: 'AUTH_SUCCESS',
          sessionToken: '${safeToken}',
          user: {
            firstName: '${safeFirstName}',
            email: '${safeEmail}'
          },
          siteInfo: {
            siteId: '${safeSiteId}',
            siteName: '${safeSiteName}',
            shortName: '${safeShortName}'
          }
        };
        
        // SECURITY NOTE: We use '*' as targetOrigin here because we cannot access window.opener.location
        // due to cross-origin restrictions. However, the RECEIVING end (Designer window) performs
      
        // This is secure because: 1) Browser sets event.origin to actual sender origin, 2) Receiver validates it
        
        function sendMessage() {
          if (!window.opener || window.opener.closed) {
            console.warn('window.opener is null or closed');
            return;
          }
          
          try {
            // Try to get actual origin for better security
            let targetOrigin = '*'; // Fallback to wildcard if we can't determine origin
            try {
              if (window.opener.location && window.opener.location.origin) {
                targetOrigin = window.opener.location.origin;
              }
            } catch (e) {
              // Cross-origin error - expected when opener is on different domain (webflow.com)
              // We must use '*' in this case, but receiver will validate event.origin
            }
            
            // Send message
         
            window.opener.postMessage(sessionData, targetOrigin);
          } catch (e) {
            console.error('Error sending postMessage:', e);
          }
        }
        
        // Send message immediately
        sendMessage();
        
        // Also send after a short delay to ensure opener is ready
        setTimeout(sendMessage, 100);
        setTimeout(sendMessage, 500);
        
        // Close popup after sending message (give time for message to be received)
        setTimeout(function() {
          try {
            window.close();
          } catch (e) {
            // Ignore close errors
          }
        }, 1000);
      } catch (e) {
        if (window.opener && !window.opener.closed) {
          try {
            // Try to send error message with wildcard origin for maximum compatibility
            try {
              let targetOrigin = '*';
              try {
                if (window.opener.location && window.opener.location.origin) {
                  targetOrigin = window.opener.location.origin;
                }
              } catch (e) {
                // Cross-origin - use wildcard
              }
              window.opener.postMessage({ type: 'AUTH_ERROR', error: 'Failed to process authorization' }, targetOrigin);
            } catch (err) {
              console.error('Error sending error message:', err);
            }
          } catch (err) {
            console.error('Error sending error message:', err);
          }
        }
        setTimeout(function() {
          window.close();
        }, 100);
      }
    })();
  </script>
</body>
</html>`, {
    headers: { 
      'Content-Type': 'text/html; charset=utf-8'
    }
  });
}

// Handle publish accessibility settings
async function handlePublishSettings(request, env) {
  const requestId = `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  const ip = getClientIp(request);
  const ipOk = await checkRateLimit(env, 'publish-ip', ip, 10, 1);
  if (!ipOk) {
    const origin = request.headers.get('origin') || '';
    const h = { 'Content-Type': 'application/json', 'Retry-After': '60', 'Access-Control-Allow-Origin': getPublishCorsOrigin(origin) };
    return new Response(JSON.stringify({ error: 'Too many requests', retryAfter: 60 }), { status: 429, headers: h });
  }
  try {
    const origin = request.headers.get('origin') || '';
    const corsOrigin = getPublishCorsOrigin(origin);
    const makeHeaders = (statusCode) => {
      const base = {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': corsOrigin,
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization'
      };
      return base;
    };
    
    // Verify authentication
    const authResult = await verifyAuth(request, env);
    if (!authResult) {
   
      return new Response(JSON.stringify({ 
        error: "Unauthorized", 
        requestId 
      }), {
        status: 401,
        headers: makeHeaders(401)
      });
    }
    
    // Get siteId from URL parameter (preferred) or from auth result
    const url = new URL(request.url);
    const urlSiteId = url.searchParams.get('siteId');
    const siteId = urlSiteId || authResult.siteId;
    
    console.log(`[PUBLISH] ${requestId} Using siteId: ${siteId} (from ${urlSiteId ? 'URL parameter' : 'auth result'})`);
    
    if (!siteId) {
      console.log(`[PUBLISH] ${requestId} No siteId available`);
      return new Response(JSON.stringify({ 
        error: "No siteId provided", 
        requestId 
      }), {
        status: 400,
        headers: makeHeaders(400)
      });
    }
    
    const siteOk = await checkRateLimit(env, 'publish-site', siteId, 15, 60);
    if (!siteOk) {
      const h = new Headers(makeHeaders(429));
      h.set('Retry-After', '60');
      return new Response(JSON.stringify({ error: 'Too many requests', retryAfter: 60 }), { status: 429, headers: h });
    }
    
    // Parse the request body
    let body;
    try {
      body = await request.json();
    } catch (parseErr) {
      console.warn(`[PUBLISH] ${requestId} Invalid JSON body:`, parseErr);
      return new Response(JSON.stringify({ error: 'Invalid JSON body', requestId }), {
        status: 400,
        headers: makeHeaders(400)
      });
    }
    if (!body || typeof body !== 'object') {
      return new Response(JSON.stringify({ error: 'Request body must be a JSON object', requestId }), {
        status: 400,
        headers: makeHeaders(400)
      });
    }
    const { 
      customization, 
      accessibilityProfiles, 
      customDomain, 
      publishedAt,
      interfaceLanguage
    } = body;
    
    // Get existing accessibility settings (separate from auth data)
    const existingSettingsData = await env.ACCESSIBILITY_AUTH.get(`accessibility-settings:${siteId}`);
    let existingSettings = {};
    if (existingSettingsData) {
      try {
        const parsed = JSON.parse(existingSettingsData);
        if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
          existingSettings = parsed;
        }
        console.log(`[PUBLISH] ${requestId} Found existing accessibility settings`);
      } catch (error) {
        console.warn(`[PUBLISH] ${requestId} Failed to parse existing accessibility settings:`, error);
      }
    }
    
    // Get authorization data separately (never overwritten)
    const authData = await env.ACCESSIBILITY_AUTH.get(`auth-data:${siteId}`);
    let authInfo = {};
    if (authData) {
      try {
        authInfo = JSON.parse(authData);
        console.log(`[PUBLISH] ${requestId} Found authorization data`);
      } catch (error) {
        console.warn(`[PUBLISH] ${requestId} Failed to parse authorization data:`, error);
      }
    }
    // Get accessToken from auth data
    let accessToken = authInfo.accessToken;
    console.log(`[PUBLISH] ${requestId} Access token status:`, !!accessToken);
    
    // Sanitize accessibilityStatementLink in customization (server-side protection against javascript: URLs)
    let safeCustomization = customization || {};
    if (safeCustomization && typeof safeCustomization.accessibilityStatementLink === 'string') {
      safeCustomization = {
        ...safeCustomization,
        accessibilityStatementLink: sanitizeAccessibilityStatementLink(safeCustomization.accessibilityStatementLink)
      };
    }
    
    const existingCustom = existingSettings && typeof existingSettings.customization === 'object' ? existingSettings.customization : {};
    const accessibilityData = {
      siteId: siteId,
      customization: {
        ...existingCustom,
        ...safeCustomization,
        interfaceLanguage: interfaceLanguage ?? customization?.interfaceLanguage ?? existingCustom?.interfaceLanguage
      },
      accessibilityProfiles: accessibilityProfiles ?? existingSettings?.accessibilityProfiles,
      customDomain: customDomain ?? existingSettings?.customDomain,
      publishedAt: publishedAt,
      lastUpdated: new Date().toISOString(),
      lastUsed: new Date().toISOString()
    };
    
    // Store accessibility settings separately
    const accessibilityKey = `accessibility-settings:${siteId}`;
    console.log(`[PUBLISH] ${requestId} Storing accessibility settings with key: ${accessibilityKey}`);
    console.log(`[PUBLISH] ${requestId} Accessibility data to store:`, JSON.stringify(accessibilityData, null, 2));
    
    await env.ACCESSIBILITY_AUTH.put(accessibilityKey, JSON.stringify(accessibilityData));
    
    // Also store domain mappings for easy lookup
    // Get the site's domains from Webflow API
    try {
      const domainsResponse = await fetch(`https://api.webflow.com/v2/sites/${siteId}/domains`, {
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'accept-version': '1.0.0'
        }
      });
      
      if (domainsResponse.ok) {
        const domainsData = await domainsResponse.json();
        console.log(`[PUBLISH] ${requestId} Found domains:`, domainsData);
        
        // Store mapping for each domain
        for (const domain of domainsData.domains || []) {
          const domainKey = `domain:${domain.name}`;
          await env.ACCESSIBILITY_AUTH.put(domainKey, JSON.stringify({
            siteId: siteId,
            domain: domain.name,
            isPrimary: domain.isPrimary,
            connectedAt: new Date().toISOString()
          }), { expirationTtl: 86400 * 30 }); // 30 days
          
          console.log(`[PUBLISH] ${requestId} Stored domain mapping: ${domain.name} -> ${siteId}`);
        }
      }
    } catch (domainError) {
      console.warn(`[PUBLISH] ${requestId} Failed to get domains:`, domainError);
    }
    
    // IMPORTANT: Also store the Webflow subdomain mapping
    // This is crucial for sites that only have Webflow subdomains (like test-dbae38.webflow.io)
    try {
      // Get site info to get the shortName for Webflow subdomain
      const siteResponse = await fetch(`https://api.webflow.com/v2/sites/${siteId}`, {
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'accept-version': '2.0.0'
        }
      });
      
      if (siteResponse.ok) {
        const siteData = await siteResponse.json();
        console.log(`[PUBLISH] ${requestId} Site data:`, siteData);
        
        if (siteData.shortName) {
          const webflowSubdomain = `${siteData.shortName}.webflow.io`;
          const domainKey = `domain:${webflowSubdomain}`;
          
          await env.ACCESSIBILITY_AUTH.put(domainKey, JSON.stringify({
            siteId: siteId,
            domain: webflowSubdomain,
            isPrimary: true, // Webflow subdomain is always primary
            isWebflowSubdomain: true,
            connectedAt: new Date().toISOString()
          }), { expirationTtl: 86400 * 30 }); // 30 days
          
          console.log(`[PUBLISH] ${requestId} Stored Webflow subdomain mapping: ${webflowSubdomain} -> ${siteId}`);
        }
      }
    } catch (siteError) {
      console.warn(`[PUBLISH] ${requestId} Failed to get site info for subdomain mapping:`, siteError);
    }
    
    // If custom domain is provided, create a domain mapping
    if (customDomain) {
      const domainKey = `domain:${customDomain}`;
      await env.ACCESSIBILITY_AUTH.put(domainKey, JSON.stringify({
        siteId: siteId,
        customDomain: customDomain,
        connectedAt: new Date().toISOString()
      }), { expirationTtl: 86400 });
    }
    
    console.log(`[PUBLISH] ${requestId} Settings published successfully`);
    
    return new Response(JSON.stringify({
      success: true,
      message: "Accessibility settings published successfully",
      data: {
        customization: accessibilityData.customization,
        accessibilityProfiles: accessibilityData.accessibilityProfiles,
        customDomain: accessibilityData.customDomain,
        publishedAt: accessibilityData.publishedAt
      },
      requestId
    }), {
      status: 200,
      headers: makeHeaders(200)
    });
    
  } catch (error) {
    const errMsg = (error && (error.message || String(error))) || 'Unknown error';
    console.error(`[PUBLISH] ${requestId} Error:`, errMsg, error);
    const origin = request.headers.get('origin') || '';
    const body = JSON.stringify({
      error: "Failed to publish accessibility settings",
      message: errMsg,
      requestId
    });
    return new Response(body, {
      status: 500,
      headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': getPublishCorsOrigin(origin) }
    });
  }
}

// Get accessibility settings - UPDATED TO USE ONLY PUBLISHED SETTINGS
async function handleGetSettings(request, env) {
  const origin = request.headers.get('origin');
  
  const authResult = await verifyAuth(request, env);
  if (!authResult) {
    const errorResponse = secureJsonResponse({ error: 'Unauthorized' }, 401);
    return addSecurityAndCorsHeaders(errorResponse, origin);
  }
  
  // Get siteId from URL parameter (preferred) or from auth result
  const url = new URL(request.url);
  const urlSiteId = url.searchParams.get('siteId');
  const siteId = urlSiteId || authResult.siteId;
  
  if (!siteId) {
    const errorResponse = secureJsonResponse({ error: 'No siteId provided' }, 400);
    return addSecurityAndCorsHeaders(errorResponse, origin);
  }
  
  // Get accessibility settings from separate key
  const accessibilityData = await env.ACCESSIBILITY_AUTH.get(`accessibility-settings:${siteId}`);
  if (!accessibilityData) {
    const errorResponse = secureJsonResponse({ error: 'Accessibility settings not found' }, 404);
    return addSecurityAndCorsHeaders(errorResponse, origin);
  }
  
  // Get authorization data for site info
  const authData = await env.ACCESSIBILITY_AUTH.get(`auth-data:${siteId}`);
  let authInfo = {};
  if (authData) {
    try {
      authInfo = JSON.parse(authData);
    } catch (error) {
      console.warn('Failed to parse authorization data:', error);
    }
  }
  
  const settings = JSON.parse(accessibilityData);
  const successResponse = secureJsonResponse({
    customization: settings.customization,
    accessibilityProfiles: settings.accessibilityProfiles,
    customDomain: settings.customDomain,
    siteId: siteId,
    siteName: authInfo.siteName,
    installedAt: authInfo.installedAt,
    lastUsed: settings.lastUsed,
    widgetVersion: authInfo.widgetVersion,
    publishedAt: settings.publishedAt
  });
  return addSecurityAndCorsHeaders(successResponse, origin);
}

// Handle Token Authentication - SECURITY FIX: No longer accepts idToken
// Per Webflow Marketplace security requirements, idToken is for backend-to-backend verification only
// All authentication must use access_token stored during OAuth handshake
async function handleTokenAuth(request, env) {
  const ip = getClientIp(request);
  const ok = await checkRateLimit(env, 'auth-token-ip', ip, 20, 60);
  if (!ok) {
    return new Response(JSON.stringify({ error: 'Too many requests', retryAfter: 60 }), {
      status: 429,
      headers: {
        'Content-Type': 'application/json',
        'Retry-After': '60',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization'
      }
    });
  }
  try {
    console.log('=== TOKEN AUTH DEBUG START ===');
    console.log('Request method:', request.method);
    console.log('Request URL:', request.url);
    
    const requestBody = await request.json();
    const { siteId, idToken } = requestBody;
    
    // SECURITY: Reject requests with idToken - idToken should NOT be sent to worker
    // idToken is for client-side identity verification only
    // Worker uses stored access_token from OAuth to verify identity and make API calls
    if (idToken) {
      console.error('SECURITY: Request contains idToken - rejecting per Webflow Marketplace requirements');
      return new Response(JSON.stringify({ 
        error: 'idToken should not be sent to worker. Use stored access_token from OAuth instead.' 
      }), {
        status: 400,
        headers: { 
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'POST, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type, Authorization'
        }
      });
    }
    
    if (!siteId) {
      console.error('Missing required parameter: siteId');
      return new Response(JSON.stringify({ error: 'Missing siteId parameter' }), {
        status: 400,
        headers: { 
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'POST, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type, Authorization'
        }
      });
    }
    
    // Get user data from stored OAuth access_token (use stored token for API calls)
    console.log('Getting user data from stored OAuth access_token...');
    let userData;
    
    try {
      // Get stored auth data from OAuth handshake
      const storedAuthData = await env.ACCESSIBILITY_AUTH.get(`auth-data:${siteId}`);
      
      if (!storedAuthData) {
        console.error('No stored auth data found for siteId:', siteId);
        return new Response(JSON.stringify({ 
          error: 'No authentication data found. Please complete OAuth flow first.' 
        }), {
          status: 401,
          headers: { 
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'POST, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type, Authorization'
          }
        });
      }
      
      const parsed = JSON.parse(storedAuthData);
      const user = parsed.user || {};
      
      userData = {
        id: user.id || siteId, // Use siteId as fallback if no user ID
        email: user.email || parsed.email || '',
        firstName: user.firstName || user.name || 'User'
      };
      
      console.log('Retrieved user data from stored OAuth data:', { 
        hasId: !!userData.id, 
        hasEmail: !!userData.email 
      });
      
      // Validate required fields
      if (!userData.id) {
        console.error('Missing required user ID in stored auth data');
        return new Response(JSON.stringify({ error: 'Invalid user data in stored auth' }), {
          status: 401,
          headers: { 
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'POST, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type, Authorization'
          }
        });
      }
      
    } catch (error) {
      console.error('Failed to retrieve stored auth data:', error);
      return new Response(JSON.stringify({ error: 'Failed to retrieve authentication data' }), {
        status: 401,
        headers: { 
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'POST, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type, Authorization'
        }
      });
    }
    
    // Create session token
    console.log('Creating session token...');
    const sessionToken = await createSessionToken(userData, env, siteId);
    console.log('Session token created successfully');
    
    // Try to get accessToken from existing published settings using siteId
    let accessToken = null;
    const existingPublishedData = await env.ACCESSIBILITY_AUTH.get(`accessibility-settings:${siteId}`);
    if (existingPublishedData) {
      const parsedData = JSON.parse(existingPublishedData);
      accessToken = parsedData.accessToken;
      console.log('Found accessToken from existing published settings:', !!accessToken);
    }
    
    // Store user authentication
    await env.ACCESSIBILITY_AUTH.put(`user-auth:${userData.id}`, JSON.stringify({
      accessToken: accessToken, // Use found accessToken or null
      userData: {
        id: userData.id,
        email: userData.email,
        firstName: userData.firstName
      },
      siteId,
      widgetType: 'accessibility',
      authType: 'silent_auth'
    }), { expirationTtl: 86400 });
    
    // Check if authorization data exists, if not create initial auth data
    const authData = await env.ACCESSIBILITY_AUTH.get(`auth-data:${siteId}`);
    if (!authData) {
      console.log('No authorization data found, creating initial auth data...');
      await env.ACCESSIBILITY_AUTH.put(`auth-data:${siteId}`, JSON.stringify({
        accessToken: null, // No access token for silent auth
        siteName: 'Unknown Site', // Will be updated when user publishes
        siteId: siteId,
        user: userData,
        installedAt: new Date().toISOString(),
        widgetVersion: '1.0.0',
        lastUsed: new Date().toISOString()
      }));
      console.log('Initial authorization data created');
    } else {
      console.log('Authorization data already exists, skipping creation');
    }
    
    // Check if accessibility settings exist, if not create initial settings
    const accessibilityData = await env.ACCESSIBILITY_AUTH.get(`accessibility-settings:${siteId}`);
    if (!accessibilityData) {
      console.log('No accessibility settings found, creating initial settings...');
      await env.ACCESSIBILITY_AUTH.put(`accessibility-settings:${siteId}`, JSON.stringify({
        siteId: siteId,
        customization: {},
        accessibilityProfiles: {},
        customDomain: null,
        lastUpdated: new Date().toISOString(),
        lastUsed: new Date().toISOString()
      }));
      console.log('Initial accessibility settings created');
    } else {
      console.log('Accessibility settings already exist, skipping creation');
    }
    
    console.log('User authentication stored');
    console.log('=== TOKEN AUTH DEBUG END ===');
    
    // Get real email from stored auth data (not proxy email from userData)
    const storedAuthData = await env.ACCESSIBILITY_AUTH.get(`auth-data:${siteId}`);
    let realEmail = userData.email || '';
    let realFirstName = userData.firstName || 'User';
    
    if (storedAuthData) {
      try {
        const parsed = JSON.parse(storedAuthData);
        realEmail = parsed.email || userData.email || '';
        realFirstName = parsed.user?.firstName || userData.firstName || 'User';
      } catch (e) {
        console.warn('Failed to parse stored auth data:', e);
      }
    }
    
    return new Response(JSON.stringify({
      sessionToken: sessionToken.token,
      email: realEmail,
      firstName: realFirstName,
      exp: sessionToken.exp,
      widgetType: 'accessibility'
    }), {
      headers: { 
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization'
      }
    });
    
  } catch (error) {
    console.error('Token auth error:', error);
    return new Response(JSON.stringify({ 
      error: 'Authentication failed',
      details: error.message 
    }), {
      status: 500,
      headers: { 
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization'
      }
    });
  }
}

// Update accessibility settings - UPDATED TO USE PUBLISHED SETTINGS
async function handleUpdateSettings(request, env) {
  const origin = request.headers.get('origin');
  
  const authResult = await verifyAuth(request, env);
  if (!authResult) {
    const errorResponse = secureJsonResponse({ error: 'Unauthorized' }, 401);
    return addSecurityAndCorsHeaders(errorResponse, origin);
  }
  
  const { siteId } = authResult;
  const newSettings = await request.json();
  
  // Sanitize input data
  const sanitizedSettings = {};
  for (const [key, value] of Object.entries(newSettings)) {
    if (typeof value === 'string') {
      sanitizedSettings[key] = sanitizeInput(value);
    } else if (typeof value === 'object' && value !== null) {
      // Recursively sanitize object values
      sanitizedSettings[key] = {};
      for (const [subKey, subValue] of Object.entries(value)) {
        if (typeof subValue === 'string') {
          sanitizedSettings[key][subKey] = sanitizeInput(subValue);
        } else {
          sanitizedSettings[key][subKey] = subValue;
        }
      }
    } else {
      sanitizedSettings[key] = value;
    }
  }
  
  // Additional hardening for accessibilityStatementLink if present in customization
  if (sanitizedSettings.customization && typeof sanitizedSettings.customization.accessibilityStatementLink === 'string') {
    sanitizedSettings.customization.accessibilityStatementLink =
      sanitizeAccessibilityStatementLink(sanitizedSettings.customization.accessibilityStatementLink);
  }
  
  // Get existing accessibility settings
  const accessibilityData = await env.ACCESSIBILITY_AUTH.get(`accessibility-settings:${siteId}`);
  if (!accessibilityData) {
    const errorResponse = secureJsonResponse({ error: 'Accessibility settings not found' }, 404);
    return addSecurityAndCorsHeaders(errorResponse, origin);
  }
  
  const settings = JSON.parse(accessibilityData);
  settings.accessibilitySettings = { ...settings.accessibilitySettings, ...sanitizedSettings };
  settings.lastUpdated = new Date().toISOString();
  settings.lastUsed = new Date().toISOString();
  
  await env.ACCESSIBILITY_AUTH.put(`accessibility-settings:${siteId}`, JSON.stringify(settings));
  // Also refresh site domain mapping if customization carries a domain, and always map staging if available
  try {
    const domainFromSettings = settings?.customization?.customDomain || settings?.customDomain;
    if (domainFromSettings) {
      const host = normalizeHost(domainFromSettings);
      const baseHost = host.replace(/^www\./, '');
      const mapping = JSON.stringify({ siteId, domain: domainFromSettings, isPrimary: true, lastUpdated: new Date().toISOString() });
      await env.ACCESSIBILITY_AUTH.put(`site:domain:${baseHost}`, mapping);
      await env.ACCESSIBILITY_AUTH.put(`site:domain:www.${baseHost}`, mapping);
    }
    // Map staging domain using auth-data if present
    try {
      const authDataRaw = await env.ACCESSIBILITY_AUTH.get(`auth-data:${siteId}`);
      if (authDataRaw) {
        const authData = JSON.parse(authDataRaw);
        const shortName = authData?.currentSite?.shortName || authData?.site?.shortName;
        if (shortName) {
          const stagingDomain = `${shortName}.webflow.io`;
          const sHost = normalizeHost(stagingDomain);
          const sBase = sHost.replace(/^www\./, '');
          const sMapping = JSON.stringify({ siteId, domain: stagingDomain, isPrimary: true, lastUpdated: new Date().toISOString() });
          await env.ACCESSIBILITY_AUTH.put(`site:domain:${sBase}`, sMapping);
          await env.ACCESSIBILITY_AUTH.put(`site:domain:www.${sBase}`, sMapping);
        }
      }
    } catch {}
  } catch {}
  
  const successResponse = secureJsonResponse({
    success: true,
    settings: settings.accessibilitySettings,
    lastUpdated: settings.lastUpdated
  });
  return addSecurityAndCorsHeaders(successResponse, origin);
}

// Verify authentication
async function handleVerifyAuth(request, env) {
  const authResult = await verifyAuth(request, env);
  
  return new Response(JSON.stringify({
    authenticated: !!authResult,
    user: authResult?.userData || null
  }), {
    headers: { 
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization'
    }
  });
}


// Register Script - Using actual Webflow API
async function handleRegisterScript(request, env) {
  const origin = request.headers.get('origin') || '';
  const corsOrigin = getPublishCorsOrigin(origin);
  try {
    console.log('=== REGISTER SCRIPT DEBUG START ===');
    
    // Get siteId from URL parameters
    const url = new URL(request.url);
    const siteIdFromUrl = url.searchParams.get('siteId');
    console.log('SiteId from URL:', siteIdFromUrl);

    const authResult = await verifyAuth(request, env);
    if (!authResult) {
      console.log('Authentication failed in register script');
      return new Response(JSON.stringify({ error: 'Authentication failed' }), {
        status: 401,
        headers: { 
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': corsOrigin
        }
      });
    }
    console.log('Authentication successful, siteId from auth:', authResult.siteId);
    
    // Get access token from authorization data using the new key structure
    let accessToken = null;
    const authData = await env.ACCESSIBILITY_AUTH.get(`auth-data:${siteIdFromUrl}`);
    if (authData) {
      const parsedAuthData = JSON.parse(authData);
      accessToken = parsedAuthData.accessToken;
      console.log('Found access token from auth-data:', !!accessToken);
    } else {
      console.log('No auth-data found for siteId:', siteIdFromUrl);
    }
    
    console.log('Access token status:', !!accessToken);
    
    // If still no access token, skip script registration
    if (!accessToken) {
      console.log('No access token available - skipping script registration');
      return new Response(JSON.stringify({
        success: true,
        message: "Script registration skipped - no access token available",
        skipApplyScript: true
      }), {
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': corsOrigin
        }
      });
    }
    // Derive staging host from auth-data (ensure shortName exists in this scope)
    let shortName = '';
    try {
      const authDataRawForSite = await env.ACCESSIBILITY_AUTH.get(`auth-data:${siteIdFromUrl}`);
      if (authDataRawForSite) {
        const parsedAuth = JSON.parse(authDataRawForSite);
        shortName = parsedAuth?.currentSite?.shortName || parsedAuth?.site?.shortName || '';
      }
    } catch {}
    // Ensure shortName exists in this scope as well
    shortName = shortName || '';
    if (!shortName) {
      // Fallback: fetch from Webflow Sites API
      try {
        const siteResp = await fetch(`https://api.webflow.com/v2/sites/${siteIdFromUrl}`, {
          headers: {
            'Authorization': `Bearer ${accessToken}`,
            'accept-version': '2.0.0'
          }
        });
        if (siteResp.ok) {
          const siteJson = await siteResp.json();
          shortName = siteJson?.shortName || siteJson?.subdomain || '';
        }
      } catch {}
    }
    // Install-time site token (persistent)
    let siteToken = await env.ACCESSIBILITY_AUTH.get(`siteToken:${siteIdFromUrl}`);
    if (!siteToken) {
      const raw = crypto.getRandomValues(new Uint8Array(32));
      siteToken = btoa(String.fromCharCode(...raw)).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
      await env.ACCESSIBILITY_AUTH.put(`siteToken:${siteIdFromUrl}`, siteToken);
      console.log('🔐 siteToken PUT', { key: `siteToken:${siteIdFromUrl}` });
    }
    const scriptUrl = `https://cdn.jsdelivr.net/gh/snm62/accessibility-test@3d74dbd/new.js?siteId=${encodeURIComponent(siteIdFromUrl || authResult.siteId || '')}&siteToken=${encodeURIComponent(siteToken)}`;
    const normalizeCdnBase = (urlStr) => {
      try {
        const u = new URL(urlStr);
        // remove commit segment after repo name ("@...") and strip query
        const noQuery = `${u.origin}${u.pathname}`;
        return noQuery.replace(/@[^/]+/, '');
      } catch { return urlStr; }
    };
    const expectedBase = normalizeCdnBase(scriptUrl);
    console.log(accessToken);
    // Check if script is already registered - CORRECTED: Use exact match
    const existingScriptsResponse = await fetch(`https://api.webflow.com/v2/sites/${siteIdFromUrl}/registered_scripts`, {
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'accept-version': '2.0.0'
      }
    });
    if (existingScriptsResponse.ok) {
      const existingScripts = await existingScriptsResponse.json();
      const registeredList = existingScripts.registeredScripts || [];
      // Find any script with same logical base (ignoring commit and query)
      const matchByBase = registeredList.find(s => normalizeCdnBase(s.hostedLocation) === expectedBase);
      if (matchByBase) {
        if (matchByBase.hostedLocation === scriptUrl) {
          console.log('Script already registered (exact):', matchByBase.id);
        return new Response(JSON.stringify({
          success: true,
          message: "Script already registered",
            result: matchByBase,
            alreadyRegistered: true
        }), {
          headers: {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': corsOrigin
          }
        });
        }
        // Version or query changed → update in-place: delete then post new
        try {
          await fetch(`https://api.webflow.com/v2/sites/${siteIdFromUrl}/registered_scripts/${matchByBase.id}`, {
            method: 'DELETE',
            headers: {
              'Authorization': `Bearer ${accessToken}`,
              'accept-version': '2.0.0'
            }
          });
        } catch {}
        // Continue to registration below
      }
    }
    
   
    const scriptResponse = await fetch(scriptUrl);
    const scriptContent = await scriptResponse.text();
    const scriptBuffer = new TextEncoder().encode(scriptContent);
    const hashBuffer = await crypto.subtle.digest('SHA-384', scriptBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashBase64 = btoa(String.fromCharCode.apply(null, hashArray));
    const integrityHash = `sha384-${hashBase64}`;
    
    console.log('Generated SRI hash:', integrityHash);
    
    // Register the script with Webflow
    const registerResponse = await fetch(`https://api.webflow.com/v2/sites/${siteIdFromUrl}/registered_scripts/hosted`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Content-Type': 'application/json',
        'accept-version': '2.0.0'
      },
      body: JSON.stringify({
        displayName: `ContrastKit${Date.now()}`,
        scriptUrl: scriptUrl,
        version: '1.0.0',
        hostedLocation: scriptUrl,
        integrityHash: integrityHash,
        canCopy: false,
        isRequired: false
      })
    });
    
    console.log('Webflow API response status:', registerResponse.status);
    
    if (!registerResponse.ok) {
      const errorText = await registerResponse.text();
      console.error('Script registration failed:', registerResponse.status, errorText);
      throw new Error(`Script registration failed: ${registerResponse.status} - ${errorText}`);
    }
    
    const scriptResult = await registerResponse.json();
    console.log('Script registered successfully:', JSON.stringify(scriptResult, null, 2));
    console.log('=== REGISTER SCRIPT DEBUG END ===');
    
    return new Response(JSON.stringify({
      success: true,
      result: scriptResult
    }), {
      headers: { 
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': corsOrigin
      }
    });
    
  } catch (error) {
    console.error('Register script error:', error);
    console.error('Error details:', error.message, error.stack);
    return new Response(JSON.stringify({ 
      error: 'Failed to register script',
      details: error.message 
    }), {
      status: 500,
      headers: { 
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': corsOrigin
      }
    });
  }
}

// Apply Script
async function handleApplyScript(request, env) {
  const origin = request.headers.get('origin') || '';
  const corsOrigin = getPublishCorsOrigin(origin);
  try {
    const authResult = await verifyAuth(request, env);
    if (!authResult) {
      return new Response(JSON.stringify({ error: 'Authentication failed' }), {
        status: 401,
        headers: { 
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': corsOrigin
        }
      });
    }
    
    // Get siteId from URL parameter (preferred) or from auth result
    const url = new URL(request.url);
    const urlSiteId = url.searchParams.get('siteId');
    const siteId = urlSiteId || authResult.siteId;
    
    if (!siteId) {
      return new Response(JSON.stringify({ error: 'No siteId provided' }), {
        status: 400,
        headers: { 
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': corsOrigin
        }
      });
    }
    
    let requestBody;
    try {
      requestBody = await request.json();
    } catch (parseError) {
      console.error('Failed to parse request body:', parseError);
      return new Response(JSON.stringify({ 
        error: 'Invalid request body',
        details: parseError.message 
      }), {
        status: 400,
        headers: { 
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': corsOrigin
        }
      });
    }
    const { targetType, scriptId, location, version } = requestBody;
    console.log("script request body:", requestBody);
    
    // Get access token from authorization data
    let accessToken = null;
    const authData = await env.ACCESSIBILITY_AUTH.get(`auth-data:${siteId}`);
    if (authData) {
      const parsedAuthData = JSON.parse(authData);
      accessToken = parsedAuthData.accessToken;
    }
    
    if (!accessToken) {
      return new Response(JSON.stringify({ error: 'No access token available' }), {
        status: 401,
        headers: { 
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': corsOrigin
        }
      });
    }
    
    // Build scriptUrl aligned with register-script
    // Resolve shortName for host param
    let shortName = '';
    try {
      const authRaw = await env.ACCESSIBILITY_AUTH.get(`auth-data:${siteId}`);
      if (authRaw) {
        const parsed = JSON.parse(authRaw);
        shortName = parsed?.currentSite?.shortName || parsed?.site?.shortName || '';
      }
    } catch {}
    if (!shortName) {
      try {
        const siteResp = await fetch(`https://api.webflow.com/v2/sites/${siteId}`, {
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'accept-version': '2.0.0'
      }
    });
        if (siteResp.ok) {
          const siteJson = await siteResp.json();
          shortName = siteJson?.shortName || siteJson?.subdomain || '';
        }
      } catch {}
    }
    let siteToken = await env.ACCESSIBILITY_AUTH.get(`siteToken:${siteId}`);
    if (!siteToken) {
      const raw = crypto.getRandomValues(new Uint8Array(32));
      siteToken = btoa(String.fromCharCode(...raw)).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
      await env.ACCESSIBILITY_AUTH.put(`siteToken:${siteId}`, siteToken);
      console.log(' siteToken PUT', { key: `siteToken:${siteId}` });
    }
    
    // Validate siteId and siteToken before constructing URL
    if (!siteId || !siteToken) {
      console.error('Missing siteId or siteToken:', { siteId, siteToken });
      return new Response(JSON.stringify({ 
        error: 'Missing required parameters',
        details: `siteId: ${siteId ? 'present' : 'missing'}, siteToken: ${siteToken ? 'present' : 'missing'}`
      }), {
        status: 400,
        headers: { 
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': corsOrigin
        }
      });
    }

    const scriptUrl = `https://cdn.jsdelivr.net/gh/snm62/accessibility-test@3d74dbd/new.js?siteId=${encodeURIComponent(siteId)}&siteToken=${encodeURIComponent(siteToken)}`;
   
    const normalizeCdnBase = (urlStr) => {
      try {
        const u = new URL(urlStr);
        const noQuery = `${u.origin}${u.pathname}`;
        return noQuery.replace(/@[^/]+/, '');
      } catch { return urlStr; }
    };
    const expectedBase = normalizeCdnBase(scriptUrl);

    // Read currently registered scripts
    const regResp = await fetch(`https://api.webflow.com/v2/sites/${siteId}/registered_scripts`, {
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'accept-version': '2.0.0'
      }
    });
    if (!regResp.ok) {
      const err = await regResp.text();
      throw new Error(`Failed to read registered scripts: ${regResp.status} - ${err}`);
    }
    const regJson = await regResp.json();
    const registered = regJson.registeredScripts || [];
    const matchByBase = registered.find(s => normalizeCdnBase(s.hostedLocation) === expectedBase);
    if (matchByBase && matchByBase.hostedLocation === scriptUrl) {
      // Ensure it's applied to head via custom_code without duplicates
      const existingResponse = await fetch(`https://api.webflow.com/v2/sites/${siteId}/custom_code`, {
      headers: {
        'Authorization': `Bearer ${accessToken}`,
          'accept-version': '2.0.0'
      }
    });
      let scriptsArr = [];
    if (existingResponse.ok) {
      const existingData = await existingResponse.json();
        scriptsArr = existingData.scripts || [];
      }
      // Clean up any stale entries that reference older registered scripts with the same base
      let regListForClean = [];
      try {
        const reg = await fetch(`https://api.webflow.com/v2/sites/${siteId}/registered_scripts`, {
          headers: { 'Authorization': `Bearer ${accessToken}`, 'accept-version': '2.0.0' }
        });
        if (reg.ok) {
          const rj = await reg.json();
          regListForClean = rj.registeredScripts || [];
        }
      } catch {}
      const idsToRemove = regListForClean
        .filter(r => normalizeCdnBase(r.hostedLocation) === expectedBase && r.id !== matchByBase.id)
        .map(r => r.id);
      // Check if script is already applied. We always apply this widget script in the footer
      // so it loads at the end of <body> instead of blocking <head>.
      const targetLocation = 'footer';
      const existingApplied = scriptsArr.find(
        s => s.id === matchByBase.id && s.location === targetLocation && s.version === (version || '1.0.0')
      );

      if (existingApplied) {
        // Already applied, return success with alreadyApplied flag
        return new Response(JSON.stringify({
          success: true,
          message: 'Script already registered and applied',
          result: matchByBase,
          alreadyApplied: true
        }), {
          headers: { 
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
          }
        });
      }

      // Not applied yet, apply it now
      // Filter out invalid locations from existing scripts (only allow 'header' or 'footer')
      const pruned = scriptsArr
        .filter(s => s.id !== matchByBase.id && !idsToRemove.includes(s.id))
        .map(s => {
          // Ensure existing scripts have valid location values
          if (s.location && s.location !== 'header' && s.location !== 'footer') {
            console.warn(`Invalid location '${s.location}' found in existing script, defaulting to 'header'`);
            return { ...s, location: 'header' };
          }
          return s;
        });
      
      // Ensure targetLocation is valid
      const validLocation = (targetLocation === 'header' || targetLocation === 'footer') ? targetLocation : 'footer';
      console.log(`Adding script with location: ${validLocation} (targetLocation was: ${targetLocation})`);
      
      pruned.push({ id: matchByBase.id, version: version || matchByBase.version || '1.0.0', location: validLocation });
      
      console.log('Sending scripts array to Webflow:', JSON.stringify(pruned, null, 2));
      
      const updateResponse = await fetch(`https://api.webflow.com/v2/sites/${siteId}/custom_code`, {
        method: 'PUT',
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Content-Type': 'application/json',
          'accept-version': '2.0.0'
        },
        body: JSON.stringify({ scripts: pruned })
      });
      if (!updateResponse.ok) {
        const err = await updateResponse.text();
        throw new Error(`Failed to apply custom code: ${updateResponse.status} - ${err}`);
      }
      return new Response(JSON.stringify({
        success: true,
        message: 'Script already registered, now applied',
        result: matchByBase,
        alreadyApplied: false
      }), {
        headers: { 
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*'
        }
      });
    }

    // If exists but differs, delete then post new
    if (matchByBase) {
      try {
        await fetch(`https://api.webflow.com/v2/sites/${siteId}/registered_scripts/${matchByBase.id}`, {
          method: 'DELETE',
          headers: {
            'Authorization': `Bearer ${accessToken}`,
            'accept-version': '2.0.0'
          }
        });
      } catch {}
    }

    // Fetch script to compute integrity
    let scriptResponse;
    try {
      scriptResponse = await fetch(scriptUrl);
      if (!scriptResponse.ok) {
        throw new Error(`Failed to fetch script from ${scriptUrl}: ${scriptResponse.status} ${scriptResponse.statusText}`);
      }
    } catch (fetchError) {
      console.error('Failed to fetch script URL:', fetchError);
      throw new Error(`Failed to fetch script: ${fetchError.message}`);
    }
    
    let scriptContent;
    try {
      scriptContent = await scriptResponse.text();
    } catch (textError) {
      console.error('Failed to read script content:', textError);
      throw new Error(`Failed to read script content: ${textError.message}`);
    }
    
    let integrityHash;
    try {
      const scriptBuffer = new TextEncoder().encode(scriptContent);
      const hashBuffer = await crypto.subtle.digest('SHA-384', scriptBuffer);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      const hashBase64 = btoa(String.fromCharCode.apply(null, hashArray));
      integrityHash = `sha384-${hashBase64}`;
    } catch (hashError) {
      console.error('Failed to compute integrity hash:', hashError);
      throw new Error(`Failed to compute integrity hash: ${hashError.message}`);
    }

    const postResp = await fetch(`https://api.webflow.com/v2/sites/${siteId}/registered_scripts/hosted`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Content-Type': 'application/json',
        'accept-version': '2.0.0'
      },
      body: JSON.stringify({
        displayName: `ContrastKit${Date.now()}`,
        scriptUrl,
        version: '1.0.0',
        hostedLocation: scriptUrl,
        integrityHash,
        canCopy: false,
        isRequired: false
      })
    });
    if (!postResp.ok) {
      const errorText = await postResp.text();
      throw new Error(`Script application failed: ${postResp.status} - ${errorText}`);
    }
    const postJson = await postResp.json();
    // After registering, apply to head via custom_code without duplicates
    const existingResponse = await fetch(`https://api.webflow.com/v2/sites/${siteId}/custom_code`, {
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'accept-version': '2.0.0'
      }
    });
    let scriptsArr = [];
    if (existingResponse.ok) {
      const existingData = await existingResponse.json();
      scriptsArr = existingData.scripts || [];
    }
    // Clean up any stale entries that reference older registered scripts with the same base
    let regListForClean = [];
    try {
      const reg = await fetch(`https://api.webflow.com/v2/sites/${siteId}/registered_scripts`, {
        headers: { 'Authorization': `Bearer ${accessToken}`, 'accept-version': '2.0.0' }
      });
      if (reg.ok) {
        const rj = await reg.json();
        regListForClean = rj.registeredScripts || [];
      }
    } catch {}
    const idsToRemove = regListForClean
      .filter(r => normalizeCdnBase(r.hostedLocation) === expectedBase && r.id !== postJson.id)
      .map(r => r.id);
    // Filter out invalid locations from existing scripts (only allow 'header' or 'footer')
    const pruned = scriptsArr
      .filter(s => s.id !== postJson.id && !idsToRemove.includes(s.id))
      .map(s => {
        // Ensure existing scripts have valid location values
        if (s.location && s.location !== 'header' && s.location !== 'footer') {
          console.warn(`Invalid location '${s.location}' found in existing script, defaulting to 'header'`);
          return { ...s, location: 'header' };
        }
        return s;
      });
    
    // Ensure location is valid ('header' or 'footer'). Always use 'footer' for this widget script
    // so it loads at the end of <body> instead of blocking <head>.
    const validLocation = 'footer';
    console.log(`Adding new script with location: ${validLocation} (requested location was: ${location})`);
    
    pruned.push({ id: postJson.id, version: postJson.version || '1.0.0', location: validLocation });
    
    console.log('Sending scripts array to Webflow:', JSON.stringify(pruned, null, 2));
    
    const updateResponse = await fetch(`https://api.webflow.com/v2/sites/${siteId}/custom_code`, {
      method: 'PUT',
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Content-Type': 'application/json',
        'accept-version': '2.0.0'
      },
      body: JSON.stringify({ scripts: pruned })
    });
    if (!updateResponse.ok) {
      const err = await updateResponse.text();
      throw new Error(`Failed to apply custom code: ${updateResponse.status} - ${err}`);
    }
    return new Response(JSON.stringify({ 
      success: true, 
      result: postJson,
      alreadyApplied: false
    }), {
      headers: { 
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*'
      }
    });
    
  } catch (error) {
    console.error('Apply script error:', error);
    const errorMessage = error?.message || String(error);
    const errorStack = error?.stack || '';
    console.error('Apply script error details:', {
      message: errorMessage,
      stack: errorStack,
      name: error?.name
    });
    return new Response(JSON.stringify({ 
      error: 'Failed to apply script',
      details: errorMessage,
      stack: errorStack
    }), {
      status: 500,
      headers: { 
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*'
      }
    });
  }
}

// Helper function to verify authentication
async function verifyAuth(request, env) {
  const authHeader = request.headers.get('authorization');
  if (!authHeader) return null;
  
  const token = authHeader.split(' ')[1];
  if (!token) return null;
  
  try {
    // Verify JWT token
    const payload = await verifyJWT(token, env.WEBFLOW_CLIENT_SECRET);
    const userId = payload.user.id;
    
    // Get user data from KV
    const userData = await env.ACCESSIBILITY_AUTH.get(`user-auth:${userId}`);
    if (!userData) return null;
    
    const { accessToken, userData: user, siteId } = JSON.parse(userData);
    
    // Get site name from the site-specific data
    let siteName;
    try {
      const siteData = await env.ACCESSIBILITY_AUTH.get(`accessibility-settings:${siteId}`);
      if (siteData) {
        const parsedSiteData = JSON.parse(siteData);
        siteName = parsedSiteData.siteName;
      }
    } catch (error) {
      console.warn('Failed to get site name:', error);
    }
    
    return {
      accessToken,
      userData: user,
      siteId,
      siteName
    };
  } catch (error) {
    console.error('Auth verification error:', error);
    return null;
  }
}

// === Token helpers ===
function toBase64Url(bytes) {
  const b64 = btoa(String.fromCharCode(...new Uint8Array(bytes)));
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/,'');
}

async function signSiteToken(env, siteId, ts) {
  const secret = env.SITE_TOKEN_SECRET || env.WEBFLOW_CLIENT_SECRET;
  const data = `${siteId}.${ts}.${secret}`;
  const enc = new TextEncoder().encode(data);
  const digest = await crypto.subtle.digest('SHA-256', enc);
  return toBase64Url(digest);
}

async function verifySiteToken(env, siteId, ts, token) {
  // Optional expiration: 30 days
  const now = Date.now();
  const tsNum = parseInt(ts, 10);
  if (!tsNum || Math.abs(now - tsNum) > 30 * 24 * 3600 * 1000) {
    return false;
  }
  const expected = await signSiteToken(env, siteId, ts);
  return expected === token;
}

// Create JWT session token
async function createSessionToken(user, env,siteId=null) {
  const header = {
    alg: 'HS256',
    typ: 'JWT'
  };
  
  const payload = {
    user: user,
    siteId:siteId,
    exp: Math.floor(Date.now() / 1000) + (24 * 60 * 60)
     // 24 hours
  };
  
  const encodedHeader = base64UrlEncode(JSON.stringify(header));
  const encodedPayload = base64UrlEncode(JSON.stringify(payload));
  
  const signature = await signJWT(
    `${encodedHeader}.${encodedPayload}`,
    env.WEBFLOW_CLIENT_SECRET
  );
  
  return {
    token: `${encodedHeader}.${encodedPayload}.${signature}`,
    exp: payload.exp
  };
}

// Verify JWT token
async function verifyJWT(token, secret) {
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('Invalid JWT format');
  
  const [header, payload, signature] = parts;
  
  // Verify signature
  const expectedSignature = await signJWT(`${header}.${payload}`, secret);
  if (signature !== expectedSignature) {
    throw new Error('Invalid signature');
  }
  
  // Check expiration
  const decodedPayload = JSON.parse(base64UrlDecode(payload));
  if (decodedPayload.exp < Math.floor(Date.now() / 1000)) {
    throw new Error('Token expired');
  }
  
  return decodedPayload;
}

// Sign JWT
async function signJWT(data, secret) {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  
  const signature = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data));
  return base64UrlEncode(new Uint8Array(signature));
}

// Base64 URL encoding helpers
function base64UrlEncode(str) {
  return btoa(str)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

function base64UrlDecode(str) {
  str += '='.repeat((4 - str.length % 4) % 4);
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  return atob(str);
}

// Get accessibility configuration for hosted script
async function handleGetConfig(request, env) {
  const origin = request.headers.get('origin');
  
  try {
    const url = new URL(request.url);
    const siteId = url.searchParams.get('siteId');
    
    if (!siteId) {
      const errorResponse = secureJsonResponse({ 
        error: 'Missing siteId parameter' 
      }, 400);
      return addSecurityAndCorsHeaders(errorResponse, origin);
    }
    
    // Get accessibility settings from separate key
    const accessibilityKey = `accessibility-settings:${siteId}`;
    const accessibilityData = await env.ACCESSIBILITY_AUTH.get(accessibilityKey);
    
    if (!accessibilityData) {
      const errorResponse = secureJsonResponse({ 
        error: 'Accessibility settings not found' 
      }, 404);
      return addSecurityAndCorsHeaders(errorResponse, origin);
    }
    
    // Get authorization data for widget version
    const authData = await env.ACCESSIBILITY_AUTH.get(`auth-data:${siteId}`);
    let authInfo = {};
    if (authData) {
      try {
        authInfo = JSON.parse(authData);
      } catch (error) {
        console.warn('Failed to parse authorization data:', error);
      }
    }
    
    const settings = JSON.parse(accessibilityData);
    const customization = settings.customization || {};
    // Enforce safe accessibilityStatementLink at read-time as well (covers legacy data)
    if (typeof customization.accessibilityStatementLink === 'string') {
      customization.accessibilityStatementLink =
        sanitizeAccessibilityStatementLink(customization.accessibilityStatementLink);
    }
    
    // Return only the customization data needed by the widget
    const config = {
      customization,
      accessibilityProfiles: settings.accessibilityProfiles,
      siteId: siteId,
      publishedAt: settings.publishedAt,
      widgetVersion: authInfo.widgetVersion || '1.0.0'
    };
    
    const successResponse = secureJsonResponse(config);
    const responseWithHeaders = addSecurityAndCorsHeaders(successResponse, origin);
    
    // Add cache headers (reduced for faster QA feedback)
    const headers = new Headers(responseWithHeaders.headers);
    headers.set('Cache-Control', 'public, max-age=60'); // Cache for 1 minute
    
    return new Response(responseWithHeaders.body, {
      status: responseWithHeaders.status,
      statusText: responseWithHeaders.statusText,
      headers
    });
    
  } catch (error) {
    console.error('Get config error:', error);
    const errorResponse = secureJsonResponse({ 
      error: 'Failed to get configuration',
      details: error.message 
    }, 500);
    return addSecurityAndCorsHeaders(errorResponse, origin);
  }
}

async function handleDomainLookup(request, env) {
  const origin = request.headers.get('origin');
  const url = new URL(request.url);
  let domain = url.searchParams.get('domain');

  if (!domain) {
    return addSecurityAndCorsHeaders(secureJsonResponse({ error: 'Domain parameter is missing' }, 400), origin);
  }

  // 1. Normalize the domain to match how it's stored
  // Removes https://, trailing slashes, and converts to lowercase
  const normalizedDomain = domain.toLowerCase()
    .replace(/^https?:\/\//, '')
    .replace(/\/$/, '')
    .split(':')[0]; // removes port if present

  console.log('🔍 Looking up siteId for domain:', normalizedDomain);

  try {
    // 2. Try looking up by the domain key you created in handleWebflowAppInstallation
    const installationRecord = await env.ACCESSIBILITY_AUTH.get(`installation-domain:${normalizedDomain}`);

    if (!installationRecord) {
      console.log('❌ No installation record found for domain:', normalizedDomain);
      return addSecurityAndCorsHeaders(secureJsonResponse({ error: 'Domain not registered' }, 404), origin);
    }

    const data = JSON.parse(installationRecord);

    // 3. Return the siteId so the widget can initialize
    console.log('✅ Found siteId:', data.siteId, 'for domain:', normalizedDomain);
    return addSecurityAndCorsHeaders(secureJsonResponse({
      success: true,
      siteId: data.siteId
    }), origin);

  } catch (error) {
    console.error('❌ Database error during domain lookup:', error);
    return addSecurityAndCorsHeaders(secureJsonResponse({ error: 'Internal server error' }, 500), origin);
  }
}

// Save accessibility settings
async function handleSaveSettings(request, env) {
  const ip = getClientIp(request);
  const ipOk = await checkRateLimit(env, 'save-settings-ip', ip, 10, 1);
  if (!ipOk) {
    const origin = request.headers.get('origin') || '';
    const allowedOrigin = getAllowedAuthDataOrigin(origin);
    const h = new Headers();
    h.set('Content-Type', 'application/json');
    h.set('Retry-After', '60');
    if (allowedOrigin) h.set('Access-Control-Allow-Origin', allowedOrigin);
    return new Response(JSON.stringify({ error: 'Too many requests', retryAfter: 60 }), { status: 429, headers: h });
  }
  const origin = request.headers.get('origin') || '';
  const allowedOrigin = getAllowedAuthDataOrigin(origin);
  const makeHeaders = (statusCode) => {
    const headers = new Headers();
    Object.entries(securityHeaders).forEach(([key, value]) => {
      headers.set(key, value);
    });
    headers.set('Content-Type', 'application/json');
    headers.set('Access-Control-Allow-Methods', 'POST, OPTIONS');
    headers.set('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With, Accept, Origin, X-CSRF-Token');
    headers.set('Access-Control-Allow-Credentials', 'true');
    headers.set('Access-Control-Max-Age', '86400');
    headers.set('Vary', 'Origin');
    if (allowedOrigin) headers.set('Access-Control-Allow-Origin', allowedOrigin);
    return headers;
  };
  
  try {
    const body = await request.json();
    const { siteId, settings } = body;
    
    if (!siteId || !settings) {
      const errorResponse = secureJsonResponse({ error: 'Missing siteId or settings' }, 400);
      return new Response(errorResponse.body, {
        status: errorResponse.status,
        statusText: errorResponse.statusText,
        headers: makeHeaders(400)
      });
    }
    
    const siteOk = await checkRateLimit(env, 'save-settings-site', siteId, 30, 60);
    if (!siteOk) {
      const h = new Headers(makeHeaders(429));
      h.set('Retry-After', '60');
      return new Response(JSON.stringify({ error: 'Too many requests', retryAfter: 60 }), { status: 429, headers: h });
    }
    
    // Sanitize input data
    const sanitizedSettings = {};
    for (const [key, value] of Object.entries(settings)) {
      if (typeof value === 'string') {
        sanitizedSettings[key] = sanitizeInput(value);
      } else if (typeof value === 'object' && value !== null) {
        // Recursively sanitize object values
        sanitizedSettings[key] = {};
        for (const [subKey, subValue] of Object.entries(value)) {
          if (typeof subValue === 'string') {
            sanitizedSettings[key][subKey] = sanitizeInput(subValue);
          } else {
            sanitizedSettings[key][subKey] = subValue;
          }
        }
      } else {
        sanitizedSettings[key] = value;
      }
    }
    
    // Additional hardening for accessibilityStatementLink if present in customization
    if (sanitizedSettings.customization && typeof sanitizedSettings.customization.accessibilityStatementLink === 'string') {
      sanitizedSettings.customization.accessibilityStatementLink =
        sanitizeAccessibilityStatementLink(sanitizedSettings.customization.accessibilityStatementLink);
    }
    
    // Get existing accessibility settings
    const existingData = await env.ACCESSIBILITY_AUTH.get(`accessibility-settings:${siteId}`);
    let existingSettings = {};
    
    if (existingData) {
      try {
        existingSettings = JSON.parse(existingData);
      } catch (error) {
        console.warn('Failed to parse existing accessibility settings:', error);
      }
    }
    
    // Update settings
    const updatedSettings = {
      ...existingSettings,
      ...sanitizedSettings,
      siteId: siteId,
      lastUpdated: new Date().toISOString(),
      lastUsed: new Date().toISOString()
    };
    
    // Save to KV storage
    await env.ACCESSIBILITY_AUTH.put(`accessibility-settings:${siteId}`, JSON.stringify(updatedSettings));
  // Write canonical site domain mapping if we have a domain
  try {
    const domainFromBody = customDomain || updatedSettings?.customization?.customDomain || updatedSettings?.customDomain;
    if (domainFromBody) {
      const host = normalizeHost(domainFromBody);
      const baseHost = host.replace(/^www\./, '');
      const mapping = JSON.stringify({ siteId, domain: domainFromBody, isPrimary: true, lastUpdated: new Date().toISOString() });
      await env.ACCESSIBILITY_AUTH.put(`site:domain:${baseHost}`, mapping);
      await env.ACCESSIBILITY_AUTH.put(`site:domain:www.${baseHost}`, mapping);
    }
    // Also map staging domain if we can read shortName from auth data
    try {
      const authDataRaw = await env.ACCESSIBILITY_AUTH.get(`auth-data:${siteId}`);
      if (authDataRaw) {
        const authData = JSON.parse(authDataRaw);
        const shortName = authData?.currentSite?.shortName || authData?.site?.shortName;
        if (shortName) {
          const stagingDomain = `${shortName}.webflow.io`;
          const sHost = normalizeHost(stagingDomain);
          const sBase = sHost.replace(/^www\./, '');
          const sMapping = JSON.stringify({ siteId, domain: stagingDomain, isPrimary: true, lastUpdated: new Date().toISOString() });
          await env.ACCESSIBILITY_AUTH.put(`site:domain:${sBase}`, sMapping);
          await env.ACCESSIBILITY_AUTH.put(`site:domain:www.${sBase}`, sMapping);
        }
      }
    } catch {}
  } catch {}
    
    const successResponse = secureJsonResponse({ 
      success: true,
      message: 'Settings saved successfully',
      settings: updatedSettings
    });
    return new Response(successResponse.body, {
      status: successResponse.status,
      statusText: successResponse.statusText,
      headers: makeHeaders(200)
    });
    
  } catch (error) {
    console.error('Save settings error:', error);
    const errorResponse = secureJsonResponse({ 
      error: 'Failed to save settings',
      details: error.message 
    }, 500);
    return new Response(errorResponse.body, {
      status: errorResponse.status,
      statusText: errorResponse.statusText,
      headers: makeHeaders(500)
    });
  }
}

// Get access token by site ID from URL params
async function handleGetTokenBySiteId(request, env) {
  try {
    const url = new URL(request.url);
    const siteId = url.searchParams.get('siteId');
    
    if (!siteId) {
      return new Response(JSON.stringify({ error: 'Missing siteId parameter' }), {
        status: 400,
        headers: { 
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type'
        }
      });
    }
    
    // Get authorization data for the site
    const authData = await env.ACCESSIBILITY_AUTH.get(`auth-data:${siteId}`);
    
    if (!authData) {
      return new Response(JSON.stringify({ error: 'Site not found' }), {
        status: 404,
        headers: { 
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type'
        }
      });
    }
    
    const parsedData = JSON.parse(authData);
    
    // Return access token and site info
    return new Response(JSON.stringify({
      accessToken: parsedData.accessToken,
      siteId: parsedData.siteId,
      siteName: parsedData.siteName,
      user: parsedData.user,
      hasAccessToken: !!parsedData.accessToken
    }), {
      headers: { 
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type'
      }
    });
    
  } catch (error) {
    console.error('Get token by site ID error:', error);
    return new Response(JSON.stringify({ error: 'Failed to get token' }), {
      status: 500,
      headers: { 
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type'
      }
    });
  }
}

// Get widget script URL by site ID
async function handleGetWidgetUrl(request, env) {
  try {
    const authResult = await verifyAuth(request, env);
    if (!authResult) {
      return new Response(JSON.stringify({ error: 'Authentication failed' }), {
        status: 401,
        headers: { 
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*'
        }
      });
    }

    const url = new URL(request.url);
    const siteId = url.searchParams.get('siteId') || authResult.siteId;
    
    if (!siteId) {
      return new Response(JSON.stringify({ error: 'Missing siteId parameter' }), {
        status: 400,
        headers: { 
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*'
        }
      });
    }

    // Get site token (or create if doesn't exist)
    let siteToken = await env.ACCESSIBILITY_AUTH.get(`siteToken:${siteId}`);
    if (!siteToken) {
      const raw = crypto.getRandomValues(new Uint8Array(32));
      siteToken = btoa(String.fromCharCode(...raw)).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
      await env.ACCESSIBILITY_AUTH.put(`siteToken:${siteId}`, siteToken);
    }

    // Generate script URL (same logic as handleRegisterScript)
    const scriptUrl = `https://cdn.jsdelivr.net/gh/snm62/accessibility-test@3d74dbd/new.js?siteId=${encodeURIComponent(siteId)}&siteToken=${encodeURIComponent(siteToken)}`;

    return new Response(JSON.stringify({
      scriptUrl: scriptUrl,
      siteId: siteId
    }), {
      headers: { 
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*'
      }
    });
    
  } catch (error) {
    console.error('Get widget URL error:', error);
    return new Response(JSON.stringify({ error: 'Failed to get widget URL' }), {
      status: 500,
      headers: { 
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*'
      }
    });
  }
}

// Helper function to get site ID from URL params and retrieve access token
async function getSiteIdAndToken(request, env) {
  try {
    const url = new URL(request.url);
    const siteId = url.searchParams.get('siteId');
    
    if (!siteId) {
      return { error: 'No siteId provided in URL parameters' };
    }
    
    // Get authorization data for the site
    const authData = await env.ACCESSIBILITY_AUTH.get(`auth-data:${siteId}`);
    
    if (!authData) {
      return { error: 'Site not found' };
    }
    
    const parsedData = JSON.parse(authData);
    
    return {
      siteId: parsedData.siteId,
      accessToken: parsedData.accessToken,
      siteName: parsedData.siteName,
      user: parsedData.user,
      hasAccessToken: !!parsedData.accessToken
    };
    
  } catch (error) {
    console.error('Get site ID and token error:', error);
    return { error: 'Failed to get site data' };
  }
}

// ===== PAYMENT HANDLER FUNCTIONS =====

// (Removed) handleCreateTrial - endpoint no longer used

// Check payment status - DEPRECATED
async function handlePaymentStatus(request, env) {
  const origin = request.headers.get('origin');
  return addSecurityAndCorsHeaders(secureJsonResponse({ 
    error: 'This endpoint is deprecated. Use /api/stripe/customer-data-by-domain instead.' 
  }, 410), origin);
}

// Validate domain access
async function handleValidateDomain(request, env) {
  const origin = request.headers.get('origin');
  
  try {
    const { domain, siteId, siteToken, visitorId } = await request.json();
    console.log('🔐 validate-domain: incoming', {
      siteId,
      domain,
      hasToken: !!siteToken,
      visitorIdPresent: !!visitorId
    });
    
    if (!siteId) {
      const errorResponse = secureJsonResponse({ error: 'siteId required' }, 400);
      return addSecurityAndCorsHeaders(errorResponse, origin);
    }
    
    // Check if this is a staging domain - allow without token validation
    const isStagingDomain = domain && (
      domain.includes('.webflow.io') || 
      domain.includes('.webflow.com') || 
      domain.includes('localhost') ||
      domain.includes('127.0.0.1') ||
      domain.includes('staging')
    );
    
    if (isStagingDomain) {
      console.log('🔐 validate-domain: staging domain detected, allowing without token:', domain);
      const successResponse = secureJsonResponse({ isValid: true, visitorId: visitorId || undefined, isStaging: true });
      return addSecurityAndCorsHeaders(successResponse, origin);
    }
    
    // Persistent install-time token check (only for custom domains)
    if (!siteToken) {
      console.log('🔐 validate-domain: missing siteToken');
      const errorResponse = secureJsonResponse({ isValid: false, error: 'token missing' }, 400);
      return addSecurityAndCorsHeaders(errorResponse, origin);
    }
    const stored = await env.ACCESSIBILITY_AUTH.get(`siteToken:${siteId}`);
    if (!stored || stored !== siteToken) {
      console.log('🔐 validate-domain: siteToken mismatch');
      const errorResponse = secureJsonResponse({ isValid: false, error: 'token invalid' }, 401);
      return addSecurityAndCorsHeaders(errorResponse, origin);
    }
    // No referer host enforcement; token validation is the single gate
    // Domain mapping check disabled (siteToken is the single gate)
    console.log('🔐 validate-domain: success', { siteId, domain });
    const successResponse = secureJsonResponse({ isValid: true, visitorId: visitorId || undefined });
    return addSecurityAndCorsHeaders(successResponse, origin);
    
  } catch (error) {
    console.error('Validate domain error:', error);
    const errorResponse = secureJsonResponse({ 
      isValid: false,
      error: error.message 
    }, 500);
    return addSecurityAndCorsHeaders(errorResponse, origin);
  }
}

// Send welcome email via Brevo when Webflow app is installed
async function sendWelcomeEmail(env, email, firstName) {
  try {
    const response = await fetch('https://api.brevo.com/v3/smtp/email', {
      method: 'POST',
      headers: {
        'accept': 'application/json',
        'api-key': env.BREVO_API_KEY,
        'content-type': 'application/json'
      },
      body: JSON.stringify({
        sender: {
          name: 'AccessBit Team',
          email: 'web@accessbit.io'
        },
        to: [{
          email,
          name: firstName
        }],
        subject: 'Thanks for installing AccessBit on Webflow',
        htmlContent: `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <p>Hi ${firstName},</p>
            <p>Thank you for installing the Accessbit app on your Webflow website! We’re excited to have you onboard.</p>
            <p><strong>Important note:</strong> If you plan to publish your site to a custom domain, you’ll need to upgrade to the paid plan.</p>
            <p>Need assistance? We’ve got you covered:</p>
            <ul>
              <li>Email us anytime at <a href="mailto:web@accessbit.io" style="color:#007BFF;">web@accessbit.io</a></li>
              <li>Book a quick support call directly.</li>
              <li>Fill out our contact form and we’ll get back to you shortly.</li>
            </ul>
            <p>We’re excited to support you in creating an inclusive, accessible experience for all users and meeting global accessibility standards. If you have questions, feature suggestions, or need any assistance, we’re always just a message away.</p>
            <p>Thanks again,<br><strong>The AccessBit Team</strong></p>
          </div>
        `,
        textContent: `Hi ${firstName},

Thank you for installing the Accessbit app on your Webflow website! We’re excited to have you onboard.

Important note: If you plan to publish your site to a custom domain, you’ll need to upgrade to the paid plan.

Need assistance? We’ve got you covered:
- Email us anytime at web@accessbit.io
- Book a quick support call directly.
- Fill out our contact form and we’ll get back to you shortly.

We’re excited to support you in creating an inclusive, accessible experience for all users and meeting global accessibility standards. If you have questions, feature suggestions, or need any assistance, we’re always just a message away.

Thanks again,
The AccessBit Team`,
        tags: ['welcome', 'signup']
      })
    });

    if (response.ok) {
      const result = await response.json();
      console.log(`[SIGNUP] Brevo welcome email sent: ${email} → MessageId: ${result.messageId || 'n/a'}`);
      return true;
    } else {
      const errorData = await response.json().catch(() => ({}));
      console.warn(`[SIGNUP] Brevo error (${response.status}):`, errorData);
      return false;
    }
  } catch (err) {
    console.error(`[SIGNUP] Brevo send failed for ${email}:`, err);
    return false;
  }
}

// Reminder copy per milestone (7, 30, 60, 90 days)
const REMINDER_MESSAGES = {
  7: {
    subject: 'Ready to take AccessBit to your live site?',
    intro: "You've been using AccessBit on staging for a week — nice!",
    tag: '7day'
  },
  30: {
    subject: 'AccessBit: Still on staging? Go live in 30 seconds',
    intro: "You've been using AccessBit on staging for a month. Ready to go live on your custom domain?",
    tag: '30day'
  },
  60: {
    subject: 'AccessBit: Unlock your live site — 60 days and counting',
    intro: "You've been with AccessBit on staging for 60 days. Upgrade to publish to your custom domain and get the full experience.",
    tag: '60day'
  },
  90: {
    subject: 'AccessBit: Don’t miss out — go live on your domain',
    intro: "You've been using AccessBit on staging for 90 days. When you're ready, upgrade to publish to your custom domain and reach all your visitors.",
    tag: '90day'
  }
};

// Send reminder email via Brevo (day = 7, 30, 60, or 90)
async function sendReminderEmail(env, email, firstName, day) {
  if (!env.BREVO_API_KEY || !email || !email.includes('@')) return false;
  const msg = REMINDER_MESSAGES[day] || REMINDER_MESSAGES[7];
  try {
    const response = await fetch('https://api.brevo.com/v3/smtp/email', {
      method: 'POST',
      headers: {
        'accept': 'application/json',
        'api-key': env.BREVO_API_KEY,
        'content-type': 'application/json'
      },
      body: JSON.stringify({
        sender: { name: 'AccessBit Team', email: 'web@accessbit.io' },
        to: [{ email, name: firstName || 'User' }],
        subject: msg.subject,
        htmlContent: `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <p>Hi ${firstName || 'there'},</p>
            <p>${msg.intro}</p>
            <p>When you're ready to go live on your custom domain, upgrade to the paid plan and publish from the AccessBit app.</p>
            <p>Questions? Reply to this email or contact us at <a href="mailto:web@accessbit.io" style="color:#007BFF;">web@accessbit.io</a>.</p>
            <p>Thanks,<br><strong>The AccessBit Team</strong></p>
          </div>
        `,
        textContent: `Hi ${firstName || 'there'},\n\n${msg.intro}\n\nWhen you're ready to go live on your custom domain, upgrade to the paid plan and publish from the AccessBit app.\n\nQuestions? Email web@accessbit.io.\n\nThanks,\nThe AccessBit Team`,
        tags: ['reminder', msg.tag]
      })
    });
    if (response.ok) {
      console.log(`[CRON] ${day}-day reminder sent: ${email}`);
      return true;
    }
    console.warn(`[CRON] Brevo reminder failed (${response.status}):`, await response.text());
    return false;
  } catch (err) {
    console.error(`[CRON] Brevo reminder send failed for ${email}:`, err);
    return false;
  }
}

// Milestones (days): check highest first so we send at most one reminder per site per run
const REMINDER_DAYS = [90, 60, 30, 7];
const MS_PER_DAY = 24 * 60 * 60 * 1000;

// Daily cron: find installations 7/30/60/90+ days old with no payment, send highest-due reminder once per site
async function handle7DayReminderCron(env) {
  const now = Date.now();
  let cursor;
  let sent = 0;
  let skipped = 0;
  let errors = 0;
  const sentByDay = { 7: 0, 30: 0, 60: 0, 90: 0 };
  const prefix = 'installation_';

  try {
    do {
      const list = await env.ACCESSIBILITY_AUTH.list({ prefix, limit: 100, cursor });
      cursor = list.cursor;

      for (const key of list.keys || []) {
        const siteId = key.name.startsWith(prefix) ? key.name.slice(prefix.length) : key.name;
        if (!siteId) continue;

        try {
          const installationStr = await env.ACCESSIBILITY_AUTH.get(key.name);
          if (!installationStr) continue;
          const installation = JSON.parse(installationStr);
          const installedAt = installation.installedAt ? new Date(installation.installedAt).getTime() : 0;
          if (!installedAt) {
            skipped++;
            continue;
          }
          const daysSinceInstall = Math.floor((now - installedAt) / MS_PER_DAY);
          if (daysSinceInstall < 7) {
            skipped++;
            continue;
          }

          const paymentStr = await env.ACCESSIBILITY_AUTH.get(`payment:${siteId}`);
          if (paymentStr) {
            try {
              const payment = JSON.parse(paymentStr);
              const paid = payment.paymentStatus === 'paid' || payment.status === 'active';
              if (paid) {
                skipped++;
                continue;
              }
            } catch (_) {}
          }

          const email = installation.userEmail || installation.installationData?.email;
          if (!email || !email.includes('@')) {
            skipped++;
            continue;
          }

          let reminderDay = null;
          for (const day of REMINDER_DAYS) {
            if (daysSinceInstall >= day) {
              const alreadySent = await env.ACCESSIBILITY_AUTH.get(`reminder_${day}day_sent:${siteId}`);
              if (!alreadySent) {
                reminderDay = day;
                break;
              }
            }
          }
          if (reminderDay === null) {
            skipped++;
            continue;
          }

          const firstName = installation.firstName || installation.installationData?.firstName || (email && email.split('@')[0]) || 'User';
          const ok = await sendReminderEmail(env, email, firstName, reminderDay);
          if (ok) {
            await env.ACCESSIBILITY_AUTH.put(`reminder_${reminderDay}day_sent:${siteId}`, Date.now().toString(), { expirationTtl: 86400 * 365 });
            sent++;
            sentByDay[reminderDay] = (sentByDay[reminderDay] || 0) + 1;
          } else {
            errors++;
          }
        } catch (e) {
          console.error(`[CRON] Error processing ${key.name}:`, e);
          errors++;
        }
      }
    } while (cursor);

    console.log(`[CRON] Reminder cron finished: sent=${sent} (7d=${sentByDay[7] || 0} 30d=${sentByDay[30] || 0} 60d=${sentByDay[60] || 0} 90d=${sentByDay[90] || 0}) skipped=${skipped} errors=${errors}`);
  } catch (e) {
    console.error('[CRON] Reminder cron failed:', e);
    throw e;
  }
}

// Send payment confirmation email via Brevo when customer completes paid plan
async function sendPaymentEmail(env, email, firstName) {
  if (!email || !email.includes('@')) return false;
  try {
    const response = await fetch('https://api.brevo.com/v3/smtp/email', {
      method: 'POST',
      headers: {
        'accept': 'application/json',
        'api-key': env.BREVO_API_KEY,
        'content-type': 'application/json'
      },
      body: JSON.stringify({
        sender: {
          name: 'AccessBit Team',
          email: 'web@accessbit.io'
        },
        to: [{ email, name: firstName || email.split('@')[0] || 'Customer' }],
        subject: 'Thank you for signing up with AccessBit and choosing our paid plan!',
        htmlContent: `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <p>We're excited to have you onboard and to help you build a more accessible, inclusive, and compliant website experience for all users.</p>
            <p>The next step is to install the AccessBit app on your Webflow website. Once installed, you'll be able to publish seamlessly to your custom domain and unlock all the premium accessibility features included in your plan.</p>
            <p>Need assistance? We've got you covered:</p>
            <ul>
              <li>Email us anytime at <a href="mailto:web@accessbit.io" style="color:#007BFF;">web@accessbit.io</a></li>
              <li>Book a quick support call</li>
              <li>Fill out our contact form and we'll get back to you shortly</li>
            </ul>
            <p>If you have any questions, feature suggestions, or need help with installation, we're just a message away.</p>
            <p>Thanks again for choosing AccessBit.</p>
            <p>Best regards,<br><strong>The AccessBit Team</strong></p>
          </div>
        `,
        textContent: `We're excited to have you onboard and to help you build a more accessible, inclusive, and compliant website experience for all users.

The next step is to install the AccessBit app on your Webflow website. Once installed, you'll be able to publish seamlessly to your custom domain and unlock all the premium accessibility features included in your plan.

Need assistance? We've got you covered:
- Email us anytime at web@accessbit.io
- Book a quick support call
- Fill out our contact form and we'll get back to you shortly

If you have any questions, feature suggestions, or need help with installation, we're just a message away.

Thanks again for choosing AccessBit.

Best regards,
The AccessBit Team`,
        tags: ['payment', 'paid-plan']
      })
    });

    if (response.ok) {
      const result = await response.json();
      console.log(`[PAYMENT] Brevo payment email sent: ${email} → MessageId: ${result.messageId || 'n/a'}`);
      return true;
    } else {
      const errorData = await response.json().catch(() => ({}));
      console.warn(`[PAYMENT] Brevo error (${response.status}):`, errorData);
      return false;
    }
  } catch (err) {
    console.error(`[PAYMENT] Brevo send failed for ${email}:`, err);
    return false;
  }
}

// Get user data - DEPRECATED
async function handleUserData(request, env) {
  const origin = request.headers.get('origin');
  return addSecurityAndCorsHeaders(secureJsonResponse({ 
    error: 'This endpoint is deprecated. Use /api/stripe/customer-data-by-domain instead.' 
  }, 410), origin);
}

// Create Stripe subscription with products
async function handleUpdatePayment(request, env) {
  try {
    const { siteId, paymentStatus, subscriptionId, customerId } = await request.json();
    
    console.log('Updating payment status:', { siteId, paymentStatus, subscriptionId, customerId });
    
    // Update subscription status in Stripe
    if (subscriptionId) {
      const updateResponse = await fetch(`https://api.stripe.com/v1/subscriptions/${subscriptionId}`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${env.STRIPE_SECRET_KEY}`,
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: new URLSearchParams({
          'metadata[status]': paymentStatus
        })
      });
      
      if (!updateResponse.ok) {
        console.error('Failed to update subscription in Stripe');
      }
    }
    
    // Update local storage
    const userData = {
      siteId,
      paymentStatus,
      subscriptionId,
      customerId,
      timestamp: new Date().toISOString()
    };
    
    await env.ACCESSIBILITY_AUTH.put(`user-data:${siteId}`, JSON.stringify(userData));
    
    return new Response(JSON.stringify({ success: true }), {
      headers: { 'Content-Type': 'application/json' }
    });
    
  } catch (error) {
    console.error('Update payment error:', error);
    return new Response(JSON.stringify({ error: error.message }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

async function handleCreateSetupIntent(request, env) {
  const origin = request.headers.get('origin');
  
  try {
    const { siteId, email, domainUrl } = await request.json();
    
    console.log('Creating setup intent for:', { siteId, email, domainUrl });
    
    // Sanitize domain
    const sanitizedDomain = domainUrl ? domainUrl.replace(/^https?:\/\//, '').replace(/\/$/, '') : '';
    
    // Find or create customer
    let customerId;
    if (email) {
      const customersResponse = await fetch(`https://api.stripe.com/v1/customers?email=${encodeURIComponent(email)}&limit=1`, {
        headers: {
          Authorization: `Bearer ${env.STRIPE_SECRET_KEY}`
        }
      });
      
      if (customersResponse.ok) {
        const customers = await customersResponse.json();
        if (customers.data.length > 0) {
          customerId = customers.data[0].id;
          console.log('Found existing customer:', customerId);
        }
      }
    }
    
    if (!customerId) {
      const customerData = new URLSearchParams();
      customerData.append('email', email || '');
      if (domainUrl || sanitizedDomain) {
        customerData.append('metadata[domain]', domainUrl || sanitizedDomain);
      }
      customerData.append('metadata[siteId]', siteId);
      
      const customerResponse = await fetch('https://api.stripe.com/v1/customers', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${env.STRIPE_SECRET_KEY}`,
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: customerData
      });
      
      if (!customerResponse.ok) {
        const errorText = await customerResponse.text();
        throw new Error(`Failed to create customer: ${errorText}`);
      }
      
      const customer = await customerResponse.json();
      customerId = customer.id;
      console.log('Created new customer:', customerId);
    }
    
    // Create a Setup Intent to collect payment details
    const setupIntentData = new URLSearchParams();
    setupIntentData.append('customer', customerId);
    setupIntentData.append('payment_method_types[0]', 'card');
    setupIntentData.append('usage', 'off_session');
    setupIntentData.append('metadata[siteId]', siteId);
    setupIntentData.append('metadata[domain]', domainUrl || sanitizedDomain);
    
    console.log('Creating setup intent with data:', setupIntentData.toString());
    
    const setupIntentResponse = await fetch('https://api.stripe.com/v1/setup_intents', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${env.STRIPE_SECRET_KEY}`,
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: setupIntentData
    });
    
    if (!setupIntentResponse.ok) {
      const errorText = await setupIntentResponse.text();
      throw new Error(`Failed to create setup intent: ${errorText}`);
    }
    
    const setupIntent = await setupIntentResponse.json();
    console.log('Setup intent created successfully:', setupIntent);
    console.log('Setup intent client_secret:', setupIntent.client_secret);
    
    if (!setupIntent.client_secret) {
      console.error('No client_secret in setup intent response:', setupIntent);
      throw new Error('Setup intent did not return a client secret');
    }
    
    // Store setup intent data temporarily
    await env.ACCESSIBILITY_AUTH.put(`setup_intent_${siteId}`, JSON.stringify({
      siteId,
      customerId,
      setupIntentId: setupIntent.id,
      createdAt: new Date().toISOString()
    }));
    
    const successResponse = secureJsonResponse({ 
      success: true,
      clientSecret: setupIntent.client_secret,
      customerId: customerId,
      setupIntentId: setupIntent.id
    });
    return addSecurityAndCorsHeaders(successResponse, origin);
    
  } catch (error) {
    console.error('Setup intent creation error:', error);
    const errorResponse = secureJsonResponse({ 
      error: 'Failed to create setup intent', 
      details: error.message 
    });
    return addSecurityAndCorsHeaders(errorResponse, origin);
  }
}

async function handleCreateSubscription(request, env) {
  const origin = request.headers.get('origin');
  
  try {
    const { siteId, productId, domain, email, domainUrl, firstName, paymentMethodId, customerId: providedCustomerId } = await request.json();
    
    console.log('Create subscription request data:', { siteId, productId, domain, email, domainUrl, paymentMethodId });
    console.log('Email received:', email);
    console.log('Domain received:', domain);
    console.log('DomainUrl received:', domainUrl);
    console.log('PaymentMethodId received:', paymentMethodId);
    console.log('PaymentMethodId type:', typeof paymentMethodId);
    console.log('PaymentMethodId value:', paymentMethodId);
    
    if (!siteId || !productId || !domain) {
      const errorResponse = secureJsonResponse({ error: 'Missing required fields' }, 400);
      return addSecurityAndCorsHeaders(errorResponse, origin);
    }
    
    // Sanitize input data
    const sanitizedDomain = sanitizeInput(domain);
    
    // Use provided customerId if available (preferred)
    let customerId = providedCustomerId || '';
    if (!customerId && email) {
      console.log('Checking for existing customer with email:', email);
      const existingCustomersResponse = await fetch(`https://api.stripe.com/v1/customers?email=${encodeURIComponent(email)}&limit=1`, {
        headers: {
          Authorization: `Bearer ${env.STRIPE_SECRET_KEY}`
        }
      });
      
      if (existingCustomersResponse.ok) {
        const existingCustomers = await existingCustomersResponse.json();
        if (existingCustomers.data && existingCustomers.data.length > 0) {
          customerId = existingCustomers.data[0].id;
          console.log('Found existing customer:', customerId);
        }
      }
    }
    
    // Create new customer only if no existing customer found
    if (!customerId) {
      console.log('Creating new customer...');
      const customerData = new URLSearchParams();
      customerData.append('metadata[siteId]', siteId);
      customerData.append('metadata[domain]', domainUrl || sanitizedDomain);
      customerData.append('metadata[firstName]', firstName || '');
      
      if (email) {
        customerData.append('email', email);
      }
      
      
      const customerResponse = await fetch('https://api.stripe.com/v1/customers', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${env.STRIPE_SECRET_KEY}`,
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: customerData
      });
      
      if (!customerResponse.ok) {
        const errorText = await customerResponse.text();
        throw new Error(`Failed to create customer: ${errorText}`);
      }
      
      const customer = await customerResponse.json();
      customerId = customer.id;
      console.log('Created new customer:', customerId);
      console.log('Customer default payment method:', customer.invoice_settings?.default_payment_method);
    }
    
    // Get product details to find the price
    const productResponse = await fetch(`https://api.stripe.com/v1/products/${productId}`, {
      headers: {
        Authorization: `Bearer ${env.STRIPE_SECRET_KEY}`
      }
    });
    
    if (!productResponse.ok) {
      throw new Error('Failed to get product details');
    }
    
    const product = await productResponse.json();
    const priceId = product.default_price;
    
    // Create the subscription with verified payment method
    const subscriptionData = new URLSearchParams();
    subscriptionData.append('customer', customerId);
    subscriptionData.append('items[0][price]', priceId);
    
    // Set the payment method if provided
    if (paymentMethodId) {
      subscriptionData.append('default_payment_method', paymentMethodId);
      console.log('Creating subscription with payment method:', paymentMethodId);
      // Try to charge immediately if we have a payment method
      subscriptionData.append('payment_behavior', 'error_if_incomplete');
    } else {
      console.log('Creating subscription without payment method - will be set via SetupIntent webhook');
    subscriptionData.append('payment_behavior', 'default_incomplete');
    }
    
    subscriptionData.append('collection_method', 'charge_automatically');
    subscriptionData.append('payment_settings[save_default_payment_method]', 'on_subscription');
    subscriptionData.append('payment_settings[payment_method_types][0]', 'card');
    subscriptionData.append('payment_settings[payment_method_options][card][request_three_d_secure]', 'automatic');
    subscriptionData.append('expand[]', 'latest_invoice.payment_intent');
    subscriptionData.append('metadata[siteId]', siteId);
    subscriptionData.append('metadata[domain]', domainUrl || sanitizedDomain);
    subscriptionData.append('metadata[email]', email || '');
    subscriptionData.append('metadata[firstName]', firstName || '');
    subscriptionData.append('metadata[productId]', productId);
    subscriptionData.append('metadata[createdAt]', new Date().toISOString());
    
    console.log('Creating subscription with data:', subscriptionData.toString());
    console.log('Payment method ID being used:', paymentMethodId);
    console.log('Customer ID being used:', customerId);
    console.log('Subscription metadata:', {
      siteId: siteId,
      domain: domainUrl || sanitizedDomain,
      email: email || '',
      domainUrl: domainUrl || '',
      productId: productId
    });
    
    const subscriptionResponse = await fetch('https://api.stripe.com/v1/subscriptions', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${env.STRIPE_SECRET_KEY}`,
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: subscriptionData
    });
    
    if (!subscriptionResponse.ok) {
      const errorText = await subscriptionResponse.text();
      console.error('Stripe subscription creation failed:', errorText);
      throw new Error(`Failed to create subscription: ${errorText}`);
    }
    
    const subscription = await subscriptionResponse.json();
    console.log('Subscription created successfully:', subscription);
    console.log('Subscription status:', subscription.status);
    console.log('Subscription payment method:', subscription.default_payment_method);
    console.log('Subscription latest invoice:', subscription.latest_invoice);
    console.log('Subscription items:', subscription.items?.data?.[0]);
    
    // Store user data for subscription
    const userData = {
      siteId,
      domain: sanitizedDomain,
      customerId: customerId,
      subscriptionId: subscription.id,
      paymentStatus: subscription.status,
      firstName: firstName || '',
      currentPeriodStart: subscription.current_period_start,
      currentPeriodEnd: subscription.current_period_end,
      cancelAtPeriodEnd: subscription.cancel_at_period_end || false,
      createdAt: new Date().toISOString()
    };
    
    // user_data_${siteId} removed - using customer:${customerId} instead
    // Save single payment snapshot per site
    try {
      const paymentSnapshot = {
        id: subscription.id,
        siteId,
        type: 'subscription_created',
        timestamp: new Date().toISOString(),
        status: subscription.status,
        currency: subscription.currency || null,
        amount: subscription.items?.data?.[0]?.price?.unit_amount || null,
        customerId,
        subscriptionId: subscription.id,
        invoiceId: subscription.latest_invoice || null,
        paymentIntentId: subscription.latest_invoice?.payment_intent || null,
        paymentMethodId: paymentMethodId || null,
        firstName: firstName || '',
        currentPeriodStart: subscription.current_period_start || null,
        currentPeriodEnd: subscription.current_period_end || null,
        metadata: subscription.metadata || {}
      };
      await env.ACCESSIBILITY_AUTH.put(`payment:${siteId}`, JSON.stringify(paymentSnapshot));
    } catch (snapErr) {
      console.warn('Failed to save payment snapshot:', snapErr);
    }
    
    // Check subscription status and return appropriate response
    if (subscription.status === 'incomplete') {
      // Payment needs more actions - this is expected for our flow
      console.log('Subscription created in incomplete status - will be completed by SetupIntent webhook');
      
      // If we have a payment method, try to activate the subscription immediately
      if (paymentMethodId) {
        console.log('Attempting to activate incomplete subscription with payment method:', paymentMethodId);
        try {
          const activateParams = new URLSearchParams();
          activateParams.append('default_payment_method', paymentMethodId);
          
          const activateResponse = await fetch(`https://api.stripe.com/v1/subscriptions/${subscription.id}`, {
            method: 'POST',
            headers: {
              Authorization: `Bearer ${env.STRIPE_SECRET_KEY}`,
              'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: activateParams
          });
          
          if (activateResponse.ok) {
            const activatedSubscription = await activateResponse.json();
            console.log('Subscription activated successfully:', activatedSubscription.status);
            
            // Update user data
            userData.paymentStatus = activatedSubscription.status;
            // user_data_${siteId} removed - using customer:${customerId} instead
            
            return addSecurityAndCorsHeaders(secureJsonResponse({ 
              subscriptionId: subscription.id,
              status: activatedSubscription.status,
              requiresAction: false
            }), origin);
          } else {
            const errorText = await activateResponse.text();
            console.error('Failed to activate subscription:', errorText);
          }
        } catch (error) {
          console.error('Error activating subscription:', error);
        }
      }
      
      return addSecurityAndCorsHeaders(secureJsonResponse({ 
        subscriptionId: subscription.id,
        status: subscription.status,
        requiresAction: false, // No action needed - webhook will complete it
        message: 'Subscription created successfully. Payment will be processed automatically.'
      }), origin);
    } else if (subscription.status === 'active') {
      // Subscription is active immediately
    await env.ACCESSIBILITY_AUTH.put(`domain_${sanitizedDomain}`, JSON.stringify({ 
      siteId, 
      verified: true 
    }));

      return addSecurityAndCorsHeaders(secureJsonResponse({ 
      subscriptionId: subscription.id,
        status: subscription.status,
        requiresAction: false
      }), origin);
    } else {
      // Some other status
      return addSecurityAndCorsHeaders(secureJsonResponse({ 
        subscriptionId: subscription.id,
        status: subscription.status,
        requiresAction: false
      }), origin);
    }
    
  } catch (error) {
    console.error('Create subscription error:', error);
    const errorResponse = secureJsonResponse({ 
      error: 'Failed to create subscription',
      details: error.message 
    }, 500);
    return addSecurityAndCorsHeaders(errorResponse, origin);
  }
}


// Create payment intent for Stripe Elements (REAL Stripe call)
async function handleCreatePaymentIntent(request, env) {
  const origin = request.headers.get('origin');
  try {
    const { siteId, amount, currency = 'usd', email } = await request.json();
    if (!siteId || !amount) {
      return addSecurityAndCorsHeaders(secureJsonResponse({ error: 'Missing required fields' }, 400), origin);
    }

    // Optional: create/reuse a customer for saved methods / Link
    let customerId = '';
    if (email) {
      const custRes = await fetch('https://api.stripe.com/v1/customers', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${env.STRIPE_SECRET_KEY}`,
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: new URLSearchParams({ email })
      });
      const cust = await custRes.json();
      customerId = cust.id || '';
    }

    // Create PaymentIntent with Card payments only - completely disable automatic methods
    const piRes = await fetch('https://api.stripe.com/v1/payment_intents', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${env.STRIPE_SECRET_KEY}`,
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: new URLSearchParams({
        amount: String(amount),
        currency,
        'payment_method_types[]': 'card',
        'automatic_payment_methods[enabled]': 'false',
        'payment_method_options[card][request_three_d_secure]': 'automatic',
        ...(customerId ? { customer: customerId } : {}),
        ...(siteId ? { 'metadata[siteId]': siteId } : {})
      })
    });

    if (!piRes.ok) {
      const text = await piRes.text();
      return addSecurityAndCorsHeaders(secureJsonResponse({ error: `Stripe error: ${text}` }, 400), origin);
    }
    const pi = await piRes.json();
    return addSecurityAndCorsHeaders(secureJsonResponse({ clientSecret: pi.client_secret }), origin);
  } catch (error) {
    return addSecurityAndCorsHeaders(secureJsonResponse({ error: error.message || 'failed' }, 500), origin);
  }
}

// Verify and handle Stripe webhooks
async function handleStripeWebhook(request, env) {
  const origin = request.headers.get('origin');
  try {
    const sig = request.headers.get('stripe-signature');
    if (!sig || !env.STRIPE_WEBHOOK_SECRET) {
      return addSecurityAndCorsHeaders(secureJsonResponse({ error: 'Missing signature or webhook secret' }, 400), origin);
    }

    const payload = await request.text();

    // Minimal Stripe signature verification using raw HMAC
    // Stripe header format: t=timestamp,v1=signature
    const parts = Object.fromEntries(sig.split(',').map(kv => kv.split('=')));
    const timestamp = parts['t'];
    const v1 = parts['v1'];
    if (!timestamp || !v1) {
      return addSecurityAndCorsHeaders(secureJsonResponse({ error: 'Invalid signature header' }, 400), origin);
    }

    const signedPayload = `${timestamp}.${payload}`;
    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey(
      'raw',
      encoder.encode(env.STRIPE_WEBHOOK_SECRET),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );
    const signatureBuffer = await crypto.subtle.sign('HMAC', key, encoder.encode(signedPayload));
    const signatureHex = Array.from(new Uint8Array(signatureBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');

    // Constant-time compare
    if (signatureHex !== v1) {
      return addSecurityAndCorsHeaders(secureJsonResponse({ error: 'Signature verification failed' }, 400), origin);
    }

    const event = JSON.parse(payload);
    
    // Process all Stripe events with customer-centric approach
    await processStripeEvent(env, event);

    return addSecurityAndCorsHeaders(secureJsonResponse({ success: true, event: event.type }, 200), origin);
        } catch (error) {
    console.error('Webhook error:', error);
    const errorResponse = secureJsonResponse({ error: 'Webhook processing failed' }, 500);
    return addSecurityAndCorsHeaders(errorResponse, origin);
  }
}

// Manual subscription activation
async function handleActivateSubscription(request, env) {
  const origin = request.headers.get('origin');
  
  try {
    const { siteId, setupIntentId, paymentMethodId } = await request.json();
    
    if (!siteId || !setupIntentId || !paymentMethodId) {
      const errorResponse = secureJsonResponse({ error: 'Missing required fields' }, 400);
      return addSecurityAndCorsHeaders(errorResponse, origin);
    }
    
    console.log('Manual activation request:', { siteId, setupIntentId, paymentMethodId });
    
    // Implementation would go here
    return addSecurityAndCorsHeaders(secureJsonResponse({ success: true }, 200), origin);
    
    } catch (error) {
    console.error('Error in handleActivateSubscription:', error);
    const errorResponse = secureJsonResponse({ error: 'Activation failed' }, 500);
    return addSecurityAndCorsHeaders(errorResponse, origin);
  }
}

// Second duplicate function removed - all broken code cleaned up

// Check subscription status
async function handleCheckSubscriptionStatus(request, env) {
  const origin = request.headers.get('origin');
  const url = new URL(request.url);
  const subscriptionId = url.searchParams.get('id');
    
    if (!subscriptionId) {
      const errorResponse = secureJsonResponse({ error: 'Missing subscription ID' }, 400);
      return addSecurityAndCorsHeaders(errorResponse, origin);
    }
    
  try {
    const subscriptionResponse = await fetch(`https://api.stripe.com/v1/subscriptions/${subscriptionId}`, {
      headers: {
        Authorization: `Bearer ${env.STRIPE_SECRET_KEY}`
      }
    });
    
    if (!subscriptionResponse.ok) {
      const errorText = await subscriptionResponse.text();
      throw new Error(`Failed to retrieve subscription: ${errorText}`);
    }
    
    const subscription = await subscriptionResponse.json();
    
    return addSecurityAndCorsHeaders(secureJsonResponse({
      status: subscription.status,
      subscriptionId: subscription.id,
      current_period_end: subscription.current_period_end,
      current_period_start: subscription.current_period_start,
      cancel_at_period_end: subscription.cancel_at_period_end,
      canceled_at: subscription.canceled_at,
      access_details: {
        has_access: subscription.status === 'active',
        access_until: subscription.current_period_end,
        access_start: subscription.current_period_start,
        will_cancel: subscription.cancel_at_period_end,
        canceled_at: subscription.canceled_at
      }
    }), origin);
    
  } catch (error) {
    console.error('Check subscription status error:', error);
    const errorResponse = secureJsonResponse({ 
      error: 'Failed to check subscription status',
      details: error.message 
    }, 500);
    return addSecurityAndCorsHeaders(errorResponse, origin);
  }
}



// Get subscription plan details
async function handleGetSubscriptionPlan(request, env) {
  const origin = request.headers.get('origin');
  const url = new URL(request.url);
  const subscriptionId = url.searchParams.get('id');
    
  if (!subscriptionId) {
    const errorResponse = secureJsonResponse({ error: 'Missing subscription ID' }, 400);
    return addSecurityAndCorsHeaders(errorResponse, origin);
  }
    
  try {
    const subscriptionResponse = await fetch(`https://api.stripe.com/v1/subscriptions/${subscriptionId}`, {
      headers: {
        Authorization: `Bearer ${env.STRIPE_SECRET_KEY}`
      }
    });
    
    if (!subscriptionResponse.ok) {
      const errorText = await subscriptionResponse.text();
      throw new Error(`Failed to retrieve subscription: ${errorText}`);
    }
    
    const subscription = await subscriptionResponse.json();
    
    // Extract plan type from subscription
    let planType = 'monthly'; // default
    if (subscription.items && subscription.items.data && subscription.items.data.length > 0) {
      const priceId = subscription.items.data[0].price.id;
      // Check if it's annual plan based on price ID
      if (priceId === 'price_1SL2ZQRh1lS9W4XK8QJqJzKx' || priceId.includes('annual')) {
        planType = 'annual';
      } else if (priceId === 'price_1SL2ZQRh1lS9W4XK8QJqJzKy' || priceId.includes('monthly')) {
        planType = 'monthly';
      }
    }
    
    // Calculate valid until date
    const validUntil = new Date(subscription.current_period_end * 1000).toISOString();
    
    return addSecurityAndCorsHeaders(secureJsonResponse({
      planType: planType,
      validUntil: validUntil,
      subscriptionId: subscription.id,
      status: subscription.status,
      current_period_end: subscription.current_period_end,
      current_period_start: subscription.current_period_start
    }), origin);
    
  } catch (error) {
    console.error('Get subscription plan error:', error);
    const errorResponse = secureJsonResponse({ 
      error: 'Failed to get subscription plan',
      details: error.message 
    }, 500);
    return addSecurityAndCorsHeaders(errorResponse, origin);
  }
}

// Setup payment method
async function handleSetupPayment(request, env) {
  const origin = request.headers.get('origin');
  
  try {
    // Log the raw request body
    const requestBody = await request.text();
    console.log('🔍 Raw request body:', requestBody);
    console.log('🔍 Request body length:', requestBody.length);
    
    let requestData;
    try {
      requestData = JSON.parse(requestBody);
      console.log('🔍 Parsed request data:', requestData);
    } catch (parseError) {
      console.error('🔍 JSON parse error:', parseError);
      const errorResponse = secureJsonResponse({ error: 'Invalid JSON in request body' }, 400);
      return addSecurityAndCorsHeaders(errorResponse, origin);
    }
    
    const { email, domainUrl, siteId } = requestData;
    
   
    
    if (!email || !siteId) {
      console.error('🔍 Missing required fields - email:', !!email, 'siteId:', !!siteId);
      const errorResponse = secureJsonResponse({ error: 'Missing required fields', details: { email: !!email, siteId: !!siteId } }, 400);
      return addSecurityAndCorsHeaders(errorResponse, origin);
    }
    
    console.log('Setting up payment for:', { email, domainUrl, siteId });
    
    // Create or retrieve customer
    let customer;
    const existingCustomersResponse = await fetch(`https://api.stripe.com/v1/customers?email=${encodeURIComponent(email)}&limit=1`, {
      headers: {
        Authorization: `Bearer ${env.STRIPE_SECRET_KEY}`
      }
    });
    
    if (existingCustomersResponse.ok) {
      const existingCustomers = await existingCustomersResponse.json();
      if (existingCustomers.data.length > 0) {
        customer = existingCustomers.data[0];
        console.log('Found existing customer:', customer.id);
      }
    }
    
    if (!customer) {
      // Create new customer
      const customerData = new URLSearchParams();
      customerData.append('email', email);
      customerData.append('metadata[siteId]', siteId);
      customerData.append('metadata[domain]', domainUrl || '');
      
      const customerResponse = await fetch('https://api.stripe.com/v1/customers', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${env.STRIPE_SECRET_KEY}`,
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: customerData
      });
      
      if (!customerResponse.ok) {
        const errorText = await customerResponse.text();
        throw new Error(`Failed to create customer: ${errorText}`);
      }
      
      customer = await customerResponse.json();
      console.log('Created new customer:', customer.id);
    }
    
    // Create Setup Intent
    const setupIntentData = new URLSearchParams();
    setupIntentData.append('customer', customer.id);
    setupIntentData.append('payment_method_types[]', 'card');
    setupIntentData.append('usage', 'off_session');
    setupIntentData.append('metadata[siteId]', siteId);
    setupIntentData.append('metadata[email]', email);
    setupIntentData.append('metadata[domain]', domainUrl || '');
    
    const setupIntentResponse = await fetch('https://api.stripe.com/v1/setup_intents', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${env.STRIPE_SECRET_KEY}`,
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: setupIntentData
    });
    
    if (!setupIntentResponse.ok) {
      const errorText = await setupIntentResponse.text();
      throw new Error(`Failed to create setup intent: ${errorText}`);
    }
    
    const setupIntent = await setupIntentResponse.json();
    console.log('Created setup intent:', setupIntent.id);
    
    return addSecurityAndCorsHeaders(secureJsonResponse({
      setupIntentId: setupIntent.id,
      clientSecret: setupIntent.client_secret,
      customerId: customer.id
    }), origin);
    
  } catch (error) {
    console.error('Setup payment error:', error);
    const errorResponse = secureJsonResponse({ 
      error: 'Failed to set up payment',
      details: error.message 
    }, 500);
    return addSecurityAndCorsHeaders(errorResponse, origin);
  }
}

// Verify payment method
async function handleVerifyPaymentMethod(request, env) {
  const origin = request.headers.get('origin');
  
  try {
    const { setupIntentId } = await request.json();
    
    if (!setupIntentId) {
      const errorResponse = secureJsonResponse({ error: 'Missing setupIntentId' }, 400);
      return addSecurityAndCorsHeaders(errorResponse, origin);
    }
    
    console.log('Verifying payment method for setup intent:', setupIntentId);
    
    // Retrieve the setup intent
    const setupIntentResponse = await fetch(`https://api.stripe.com/v1/setup_intents/${setupIntentId}`, {
      headers: {
        Authorization: `Bearer ${env.STRIPE_SECRET_KEY}`
      }
    });
    
    if (!setupIntentResponse.ok) {
      const errorText = await setupIntentResponse.text();
      throw new Error(`Failed to retrieve setup intent: ${errorText}`);
    }
    
    const setupIntent = await setupIntentResponse.json();
    console.log('Setup intent status:', setupIntent.status);
    
    if (setupIntent.status !== 'succeeded') {
      const errorResponse = secureJsonResponse({ 
        error: 'Setup intent not successful',
        details: `Current status: ${setupIntent.status}` 
      }, 400);
      return addSecurityAndCorsHeaders(errorResponse, origin);
    }
    
    if (!setupIntent.payment_method) {
      const errorResponse = secureJsonResponse({ 
        error: 'No payment method attached',
        details: 'The setup intent did not result in an attached payment method' 
      }, 400);
      return addSecurityAndCorsHeaders(errorResponse, origin);
    }
    
    // Payment method is available from the setup intent
    const paymentMethodId = setupIntent.payment_method;
    const customerId = setupIntent.customer;
    
    console.log('Payment method attached:', paymentMethodId);
    console.log('Customer ID:', customerId);
    
    // Set as default payment method
    const customerUpdateData = new URLSearchParams();
    customerUpdateData.append('invoice_settings[default_payment_method]', paymentMethodId);
    
    const customerUpdateResponse = await fetch(`https://api.stripe.com/v1/customers/${customerId}`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${env.STRIPE_SECRET_KEY}`,
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: customerUpdateData
    });
    
    if (!customerUpdateResponse.ok) {
      const errorText = await customerUpdateResponse.text();
      console.warn('Failed to set default payment method:', errorText);
    } else {
      console.log('Default payment method set successfully');
    }
    
    // Verify it was set
    const customerResponse = await fetch(`https://api.stripe.com/v1/customers/${customerId}`, {
      headers: {
        Authorization: `Bearer ${env.STRIPE_SECRET_KEY}`
      }
    });
    
    let isDefaultSet = false;
    if (customerResponse.ok) {
      const customer = await customerResponse.json();
      isDefaultSet = customer.invoice_settings?.default_payment_method === paymentMethodId;
      console.log('Default payment method verification:', isDefaultSet);
    }
    
    return addSecurityAndCorsHeaders(secureJsonResponse({
      success: true,
      paymentMethodId: paymentMethodId,
      customerId: customerId,
      isDefaultPaymentMethodSet: isDefaultSet
    }), origin);
    
  } catch (error) {
    console.error('Payment method verification error:', error);
    const errorResponse = secureJsonResponse({ 
      error: 'Failed to verify payment method',
      details: error.message 
    }, 500);
    return addSecurityAndCorsHeaders(errorResponse, origin);
  }
}

// Check payment status for custom domain
async function handleCheckPaymentStatus(request, env) {
  const origin = request.headers.get('origin');
  const url = new URL(request.url);
  const siteId = url.searchParams.get('siteId');
  const domain = url.searchParams.get('domain');
  
  try {
    console.log('Checking payment status for siteId:', siteId, 'domain:', domain);
    
    // Check if this is a staging domain (always allow)
    if (domain) {
      const isStagingDomain = domain.includes('.webflow.io') || 
                             domain.includes('.webflow.com') || 
                             domain.includes('localhost') ||
                             domain.includes('127.0.0.1') ||
                             domain.includes('staging');
      
      if (isStagingDomain) {
        console.log('Staging domain detected, allowing access:', domain);
        return addSecurityAndCorsHeaders(secureJsonResponse({
          hasAccess: true,
          isStaging: true
        }), origin);
      }
    }
    
    // Priority 1: Check by siteId if provided (most reliable for multi-site workspaces)
    let customerId = null;
    let customerData = null;
    
    if (siteId) {
      console.log('Checking payment status by siteId:', siteId);
      
      // Get installation record by siteId to find the customDomain
      const installationKey = `installation_${siteId}`;
      const installationDataStr = await env.ACCESSIBILITY_AUTH.get(installationKey);
      
      // When we have both siteId and domain, link domain -> installation for future payment webhook lookup
      if (installationDataStr && domain) {
        await backfillInstallationDomainIndex(env, siteId, domain);
      }
      
      if (installationDataStr) {
        try {
          const installationData = JSON.parse(installationDataStr);
          const installationDomain = installationData.customDomain;
          
          if (installationDomain) {
            // Use the domain from installation to find customerId
            const domainKey = `domain:${installationDomain}`;
            let domainData = await env.ACCESSIBILITY_AUTH.get(domainKey);
            
            // Try with https:// prefix if domain doesn't have it
            if (!domainData && !installationDomain.startsWith('http')) {
              const domainKeyWithHttps = `domain:https://${installationDomain}`;
              domainData = await env.ACCESSIBILITY_AUTH.get(domainKeyWithHttps);
            }
            
            // Try normalized domain
            if (!domainData) {
              const normalizedDomain = normalizeHost(installationDomain);
              if (normalizedDomain && normalizedDomain !== installationDomain) {
                const normalizedDomainKey = `domain:${normalizedDomain}`;
                domainData = await env.ACCESSIBILITY_AUTH.get(normalizedDomainKey);
              }
            }
            
            if (domainData) {
              if (!domainData.startsWith('{')) {
                customerId = domainData;
                console.log('Found customerId from siteId->installation->domain mapping:', customerId);
              } else {
                try {
                  const domainInfo = JSON.parse(domainData);
                  customerId = domainInfo.customerId || domainInfo.stripeCustomerId;
                  console.log('Found customerId from siteId->installation->domain mapping (JSON):', customerId);
                } catch (e) {
                  console.warn('Failed to parse domain data from installation:', e);
                }
              }
            }
          }
        } catch (e) {
          console.warn('Failed to parse installation data:', e);
        }
      }
    }
    
    // Priority 2: If no customerId found yet, try domain lookup (fallback)
    if (!customerId && domain) {
      console.log('Falling back to domain lookup:', domain);
    
    // Try raw domain first
    const domainKey = `domain:${domain}`;
    let domainData = await env.ACCESSIBILITY_AUTH.get(domainKey);
    
    // Try with https:// prefix if domain doesn't have it
    if (!domainData && !domain.startsWith('http')) {
      const domainKeyWithHttps = `domain:https://${domain}`;
      domainData = await env.ACCESSIBILITY_AUTH.get(domainKeyWithHttps);
    }
    
    // Try normalized domain
    if (!domainData) {
      const normalizedDomain = normalizeHost(domain);
      if (normalizedDomain && normalizedDomain !== domain) {
        const normalizedDomainKey = `domain:${normalizedDomain}`;
        domainData = await env.ACCESSIBILITY_AUTH.get(normalizedDomainKey);
      }
    }
    
    if (domainData) {
      // domain:${domain} stores customerId as a string (e.g., "cus_TRnDeFH0zKWYXz")
      if (!domainData.startsWith('{')) {
        // It's a customerId string
        customerId = domainData;
        console.log('Found customerId from domain mapping:', customerId);
      } else {
        // Try to parse as JSON (legacy format)
        try {
          const domainInfo = JSON.parse(domainData);
          customerId = domainInfo.customerId || domainInfo.stripeCustomerId;
          console.log('Found customerId from domain mapping (JSON):', customerId);
        } catch (e) {
          console.warn('Failed to parse domain data:', e);
        }
      }
    }
    
    }
    
    // If still no customerId found, return error
    if (!customerId) {
      console.log('No customerId found for siteId:', siteId, 'domain:', domain);
      // Return only hasAccess (no billing details to frontend)
      return addSecurityAndCorsHeaders(secureJsonResponse({
        hasAccess: false,
        isStaging: false
      }), origin);
    }
    
    // Step 2: Get customer data using customerId (customer:${customerId} -> customer data)
    const customerKey = `customer:${customerId}`;
    const customerDataStr = await env.ACCESSIBILITY_AUTH.get(customerKey);
    
    if (!customerDataStr) {
      console.log('No customer data found for customerId:', customerId);
      // Return only hasAccess (no billing details to frontend)
      return addSecurityAndCorsHeaders(secureJsonResponse({
        hasAccess: false,
        isStaging: false
      }), origin);
    }
    
    try {
      customerData = JSON.parse(customerDataStr);
      console.log('Found customer data:', {
        email: customerData.email,
        customDomain: customerData.customDomain,
        paymentStatus: customerData.paymentStatus,
        subscriptionStatus: customerData.subscriptionStatus,
        isSubscribed: customerData.isSubscribed
      });
    } catch (e) {
      console.error('Failed to parse customer data:', e);
      // Return only hasAccess (no billing details to frontend)
      return addSecurityAndCorsHeaders(secureJsonResponse({
        hasAccess: false,
        isStaging: false
      }), origin);
    }
    
    // Extract payment status from customer data
    const paymentData = {
      email: customerData.email,
      customDomain: customerData.customDomain,
      paymentStatus: customerData.paymentStatus,
      subscriptionStatus: customerData.subscriptionStatus,
      isSubscribed: customerData.isSubscribed,
      stripeSubscriptionId: customerData.stripeSubscriptionId,
      stripeCustomerId: customerData.stripeCustomerId,
      planType: customerData.planType,
      validUntil: customerData.validUntil
    };
    
    // Check if payment is active based on customer data
    // Payment is active if: isSubscribed === true AND paymentStatus === 'paid'
    const isActive = paymentData.isSubscribed === true && paymentData.paymentStatus === 'paid';
    
    console.log('Payment validation:', {
      isSubscribed: paymentData.isSubscribed,
      paymentStatus: paymentData.paymentStatus,
      subscriptionStatus: paymentData.subscriptionStatus,
      isActive: isActive
    });
    
    if (isActive) {
      console.log('Payment is active for siteId:', siteId, 'domain:', domain);
      let validUntil = paymentData.validUntil || null;
      
      // Format validUntil if it's a date string
      if (validUntil) {
        try {
          const validUntilDate = new Date(validUntil);
          if (!isNaN(validUntilDate.getTime())) {
            validUntil = validUntilDate.toISOString();
          }
        } catch (e) {
          console.warn('Failed to format validUntil:', e);
        }
      }
      
      // Return only hasAccess (no billing details to frontend)
      return addSecurityAndCorsHeaders(secureJsonResponse({
        hasAccess: true,
        isStaging: false
      }), origin);
    } else {
      console.log('Payment is not active for siteId:', siteId, 'domain:', domain, 'paymentStatus:', paymentData.paymentStatus, 'isSubscribed:', paymentData.isSubscribed);
      let validUntil = paymentData.validUntil || null;
      
      // Format validUntil if it's a date string
      if (validUntil) {
        try {
          const validUntilDate = new Date(validUntil);
          if (!isNaN(validUntilDate.getTime())) {
            validUntil = validUntilDate.toISOString();
          }
        } catch (e) {
          console.warn('Failed to format validUntil:', e);
        }
      }
      
      // Return only hasAccess (no billing details to frontend)
      return addSecurityAndCorsHeaders(secureJsonResponse({
        hasAccess: false,
        isStaging: false
      }), origin);
    }
    
  } catch (error) {
    console.error('Check payment status error:', error);
    const errorResponse = secureJsonResponse({ 
      error: 'Failed to check payment status',
      details: error.message 
    }, 500);
    return addSecurityAndCorsHeaders(errorResponse, origin);
  }
}

// Widget script with payment check
async function handleWidgetScript(request, env) {
  const origin = request.headers.get('origin');
  const url = new URL(request.url);
  const domain = url.searchParams.get('domain');
  const siteId = url.searchParams.get('siteId');
  
  try {
    console.log('🔥 Widget script requested for domain:', domain, 'siteId:', siteId);
    console.log('🔥 Request headers referer:', request.headers.get('referer'));
    console.log('🔥 Request URL:', request.url);
    
    // Get current domain from referer if not provided
    const currentDomain = domain || request.headers.get('referer') || 'unknown';
    console.log('🔥 Current domain determined as:', currentDomain);
    
    // Check if this is a staging domain (always allow)
    const isStagingDomain = currentDomain.includes('.webflow.io') || 
                           currentDomain.includes('.webflow.com') || 
                           currentDomain.includes('localhost') ||
                           currentDomain.includes('127.0.0.1') ||
                           currentDomain.includes('staging');
    
    if (isStagingDomain) {
      console.log('Staging domain detected, serving widget script:', currentDomain);
      return new Response(getWidgetScript(true), {
        headers: { 
          'Content-Type': 'application/javascript',
          'Access-Control-Allow-Origin': '*',
          'Cache-Control': 'public, max-age=3600'
        }
      });
    }
    
    // For custom domains, check payment status
    let paymentData = null;
    
    // First try to get payment data by siteId if provided
    if (siteId) {
      const paymentRecord = await env.ACCESSIBILITY_AUTH.get(`payment:${siteId}`);
      if (paymentRecord) {
        paymentData = JSON.parse(paymentRecord);
        console.log('Found payment data by siteId:', paymentData);
      }
    }
    
    // If no payment data found by siteId, try to find by domain
    if (!paymentData) {
      const domainKey = `domain:${currentDomain}`;
      console.log('🔥 Looking for domain mapping with key:', domainKey);
      const domainData = await env.ACCESSIBILITY_AUTH.get(domainKey);
      if (domainData) {
        const domainInfo = JSON.parse(domainData);
        console.log('🔥 Found domain mapping:', domainInfo);
        const siteIdFromDomain = domainInfo.siteId;
        if (siteIdFromDomain) {
          const paymentRecord = await env.ACCESSIBILITY_AUTH.get(`payment:${siteIdFromDomain}`);
          if (paymentRecord) {
            paymentData = JSON.parse(paymentRecord);
            console.log('🔥 Found payment data by domain lookup:', paymentData);
          }
        }
      } else {
        console.log('🔥 No domain mapping found for:', domainKey);
      }
    }
    
    if (!paymentData) {
      console.log('No payment data found for domain:', currentDomain);
      return new Response(getWidgetScript(false, 'No payment found for this domain'), {
        headers: { 
          'Content-Type': 'application/javascript',
          'Access-Control-Allow-Origin': '*',
          'Cache-Control': 'public, max-age=300'
        }
      });
    }
    
    // Check if payment is active
    const now = new Date().getTime();
    const currentPeriodEnd = paymentData.currentPeriodEnd;
    
    // Handle different currentPeriodEnd formats and null values
    let isActive = false;
    if (paymentData.status === 'active') {
      if (currentPeriodEnd) {
        // Convert to milliseconds if it's in seconds (Unix timestamp)
        const periodEndMs = currentPeriodEnd > 1000000000000 ? currentPeriodEnd : currentPeriodEnd * 1000;
        isActive = now < periodEndMs;
        console.log('Payment validation:', {
          status: paymentData.status,
          currentPeriodEnd: currentPeriodEnd,
          periodEndMs: periodEndMs,
          now: now,
          isActive: isActive
        });
      } else {
        // If no currentPeriodEnd, consider active if status is active
        isActive = true;
        console.log('Payment validation: No currentPeriodEnd, using status only:', paymentData.status);
      }
    }
    
    // Special case: If payment data exists and status is active but periods are null,
    // check if this is a recent subscription (within last 30 days)
    if (!isActive && paymentData.status === 'active' && !currentPeriodEnd) {
      const subscriptionDate = new Date(paymentData.timestamp);
      const thirtyDaysAgo = new Date(now - 30 * 24 * 60 * 60 * 1000);
      if (subscriptionDate > thirtyDaysAgo) {
        isActive = true;
        console.log('Payment validation: Recent subscription without period data, allowing access');
      }
    }
    
    if (isActive) {
      console.log('Payment is active for domain:', currentDomain);
      return new Response(getWidgetScript(true), {
        headers: { 
          'Content-Type': 'application/javascript',
          'Access-Control-Allow-Origin': '*',
          'Cache-Control': 'public, max-age=3600'
        }
      });
    } else {
      console.log('Payment is not active for domain:', currentDomain, 'status:', paymentData.status);
      const reason = paymentData.status === 'active' ? 'Payment expired' : 'Payment not active';
      return new Response(getWidgetScript(false, reason), {
        headers: { 
          'Content-Type': 'application/javascript',
          'Access-Control-Allow-Origin': '*',
          'Cache-Control': 'public, max-age=300'
        }
      });
    }
    
  } catch (error) {
  
    return new Response(getWidgetScript(false, 'Error checking payment status'), {
      headers: { 
        'Content-Type': 'application/javascript',
        'Access-Control-Allow-Origin': '*',
        'Cache-Control': 'no-cache'
      }
    });
  }
}

// Generate widget script based on payment status
function getWidgetScript(hasAccess, reason = '') {
  if (hasAccess) {
    // Full widget script for paid users
    return `
(function() {
  'use strict';
  
  
  
  // Accessibility Widget Implementation
  const ContrastKitWidget = {
    isInitialized: false,
    
    init: function() {
      if (this.isInitialized) return;
      this.isInitialized = true;
      
     
      
      // Create accessibility toolbar
      this.createToolbar();
      
      // Add keyboard navigation support
      this.addKeyboardSupport();
      
      // Add screen reader support
      this.addScreenReaderSupport();
      
     
    },
    
    createToolbar: function() {
    
      const toolbar = document.createElement('div');
      toolbar.id = 'accessbit-toolbar';
      
      const toolbarContent = document.createElement('div');
      toolbarContent.style.cssText = 'position: fixed; top: 20px; left: 20px; background: #1a1a1a; color: white; padding: 12px; border-radius: 8px; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; font-size: 14px; z-index: 9999; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1); max-width: 200px;';
      
      const title = document.createElement('div');
      title.style.cssText = 'font-weight: 600; margin-bottom: 8px;';
      title.textContent = 'Accessibility Tools';
      toolbarContent.appendChild(title);
      
      const btnIncrease = document.createElement('button');
      btnIncrease.textContent = 'A+';
      btnIncrease.style.cssText = 'background: #3b82f6; color: white; border: none; padding: 6px 12px; border-radius: 4px; margin: 2px; cursor: pointer; font-size: 12px;';
      btnIncrease.addEventListener('click', ContrastKitWidget.increaseFontSize);
      toolbarContent.appendChild(btnIncrease);
      
      const btnDecrease = document.createElement('button');
      btnDecrease.textContent = 'A-';
      btnDecrease.style.cssText = 'background: #3b82f6; color: white; border: none; padding: 6px 12px; border-radius: 4px; margin: 2px; cursor: pointer; font-size: 12px;';
      btnDecrease.addEventListener('click', ContrastKitWidget.decreaseFontSize);
      toolbarContent.appendChild(btnDecrease);
      
      const btnContrast = document.createElement('button');
      btnContrast.textContent = 'High Contrast';
      btnContrast.style.cssText = 'background: #3b82f6; color: white; border: none; padding: 6px 12px; border-radius: 4px; margin: 2px; cursor: pointer; font-size: 12px;';
      btnContrast.addEventListener('click', ContrastKitWidget.toggleHighContrast);
      toolbarContent.appendChild(btnContrast);
      
      toolbar.appendChild(toolbarContent);
      document.body.appendChild(toolbar);
    },
    
    increaseFontSize: function() {
      const currentSize = parseFloat(getComputedStyle(document.body).fontSize);
      document.body.style.fontSize = (currentSize + 2) + 'px';
    },
    
    decreaseFontSize: function() {
      const currentSize = parseFloat(getComputedStyle(document.body).fontSize);
      document.body.style.fontSize = Math.max(currentSize - 2, 12) + 'px';
    },
    
    toggleHighContrast: function() {
      document.body.classList.toggle('contrastkit-high-contrast');
      if (!document.querySelector('#contrastkit-contrast-styles')) {
        const style = document.createElement('style');
        style.id = 'contrastkit-contrast-styles';
        style.textContent = \`
          .contrastkit-high-contrast {
            filter: contrast(150%) brightness(120%);
          }
          .contrastkit-high-contrast * {
            background-color: white !important;
            color: black !important;
          }
        \`;
        document.head.appendChild(style);
      }
    },
    
    addKeyboardSupport: function() {
      document.addEventListener('keydown', function(e) {
        // Alt + A to toggle accessibility toolbar
        if (e.altKey && e.key === 'a') {
          const toolbar = document.getElementById('contrastkit-toolbar');
          if (toolbar) {
            toolbar.style.display = toolbar.style.display === 'none' ? 'block' : 'none';
          }
        }
      });
    },
    
    addScreenReaderSupport: function() {
      // Add ARIA labels to interactive elements
      const buttons = document.querySelectorAll('button:not([aria-label])');
      buttons.forEach(button => {
        if (!button.getAttribute('aria-label')) {
          button.setAttribute('aria-label', button.textContent || 'Button');
        }
      });
    }
  };
  
  // Make widget globally accessible
  window.ContrastKitWidget = ContrastKitWidget;
  
  // Initialize when DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function() {
      ContrastKitWidget.init();
    });
  } else {
    ContrastKitWidget.init();
  }
})();
`;
  } else {
    // Limited script for unpaid users
    return `
(function() {
  'use strict';
  
  console.log('ContrastKit Accessibility Widget - Payment Required');
  console.log('Reason: ${reason}');
  
  
  const showPaymentMessage = function() {
    const message = document.createElement('div');
    message.style.cssText = 'position: fixed; top: 20px; right: 20px; background: #f59e0b; color: white; padding: 12px 16px; border-radius: 8px; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; font-size: 14px; z-index: 9999; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1); max-width: 300px;';
    
    const strong = document.createElement('strong');
    strong.textContent = 'Accessibility Widget';
    message.appendChild(strong);
    
    message.appendChild(document.createElement('br'));
    
    const text = document.createTextNode('Payment required to activate features. ');
    message.appendChild(text);
    
    const link = document.createElement('a');
    link.href = 'https://accessbit-test-worker.web-8fb.workers.dev';
    link.textContent = 'Subscribe Now';
    link.style.cssText = 'color: white; text-decoration: underline; margin-left: 4px;';
    message.appendChild(link);
    
    document.body.appendChild(message);
    
    // Remove message after 10 seconds
    setTimeout(() => {
      if (message.parentNode) {
        message.parentNode.removeChild(message);
      }
    }, 10000);
  };
  
  // Show message when DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', showPaymentMessage);
  } else {
    showPaymentMessage();
  }
})();
`;
  }
}

// Cancel subscription
async function handleCancelSubscription(request, env) {
  const origin = request.headers.get('origin');
  
  try {
    const { subscriptionId, siteId, cancelAtPeriodEnd = true } = await request.json();
    
    let finalSubscriptionId = subscriptionId;
    
    // If no subscriptionId provided, try to get it from siteId
    if (!finalSubscriptionId && siteId) {
      console.log('No subscriptionId provided, looking up from siteId:', siteId);
      
      // Try to get subscription ID from user data
      // user_data_${siteId} removed - using customer:${customerId} instead
      if (userDataStr) {
        const userData = JSON.parse(userDataStr);
        finalSubscriptionId = userData.subscriptionId;
        console.log('Found subscriptionId in user_data:', finalSubscriptionId);
        console.log('Full user_data:', userData);
      }
      
      // If still not found, try payment snapshot
      if (!finalSubscriptionId) {
        const paymentSnapshotStr = await env.ACCESSIBILITY_AUTH.get(`payment:${siteId}`);
        if (paymentSnapshotStr) {
          const paymentSnapshot = JSON.parse(paymentSnapshotStr);
          finalSubscriptionId = paymentSnapshot.subscriptionId;
          console.log('Found subscriptionId in payment snapshot:', finalSubscriptionId);
        }
      }
    }
    
    if (!finalSubscriptionId) {
      const errorResponse = secureJsonResponse({ error: 'Missing subscription ID' }, 400);
      return addSecurityAndCorsHeaders(errorResponse, origin);
    }
    
    console.log('Cancel subscription request:', { subscriptionId: finalSubscriptionId, siteId, cancelAtPeriodEnd });
    console.log('About to call Stripe API with subscription ID:', finalSubscriptionId);
    
    let subscription;
    
    if (cancelAtPeriodEnd) {
      // Cancel at period end (recommended approach)
      // This lets the customer continue using service until end of billing period
      console.log('Canceling subscription at period end');
      const subscriptionResponse = await fetch(`https://api.stripe.com/v1/subscriptions/${finalSubscriptionId}`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${env.STRIPE_SECRET_KEY}`,
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: new URLSearchParams({
        cancel_at_period_end: 'true'
      })
    });
    
    if (!subscriptionResponse.ok) {
      const errorText = await subscriptionResponse.text();
        console.error('Stripe API error (period end):', errorText);
      throw new Error(`Failed to cancel subscription: ${errorText}`);
    }
    
      subscription = await subscriptionResponse.json();
      console.log('Stripe cancellation response (period end):', subscription);
    } else {
      // Cancel immediately (optional)
      // This ends access immediately and may generate prorations
      console.log('Canceling subscription immediately');
      const subscriptionResponse = await fetch(`https://api.stripe.com/v1/subscriptions/${finalSubscriptionId}`, {
        method: 'DELETE',
        headers: {
          Authorization: `Bearer ${env.STRIPE_SECRET_KEY}`
        }
      });
      
      if (!subscriptionResponse.ok) {
        const errorText = await subscriptionResponse.text();
        console.error('Stripe API error (immediate):', errorText);
        throw new Error(`Failed to cancel subscription: ${errorText}`);
      }
      
      subscription = await subscriptionResponse.json();
      console.log('Stripe cancellation response (immediate):', subscription);
    }
    
    // Update local data if siteId provided
    if (siteId) {
      console.log('Updating KV store for cancellation:', { siteId, cancelAtPeriodEnd });
      
      // user_data_${siteId} removed - using customer:${customerId} instead
      // user_data_${siteId} removed - using customer:${customerId} instead
      if (userDataStr) {
        const userData = JSON.parse(userDataStr);
        userData.paymentStatus = cancelAtPeriodEnd ? 'canceling' : 'canceled';
        userData.cancelAtPeriodEnd = subscription.cancel_at_period_end;
        userData.currentPeriodEnd = subscription.current_period_end;
        userData.lastUpdated = new Date().toISOString();
        userData.cancellationDate = new Date().toISOString();
        userData.canceled_at = new Date().toISOString();
        
        // user_data_${siteId} removed - using customer:${customerId} instead
        console.log('Updated customer data with cancellation status');
      }
      
      // Update payment:${siteId} snapshot
      const paymentSnapshotStr = await env.ACCESSIBILITY_AUTH.get(`payment:${siteId}`);
      if (paymentSnapshotStr) {
        const paymentSnapshot = JSON.parse(paymentSnapshotStr);
        paymentSnapshot.status = cancelAtPeriodEnd ? 'canceling' : 'canceled';
        paymentSnapshot.cancelAtPeriodEnd = subscription.cancel_at_period_end;
        paymentSnapshot.currentPeriodEnd = subscription.current_period_end;
        paymentSnapshot.cancellationDate = new Date().toISOString();
        paymentSnapshot.canceled_at = new Date().toISOString();
        paymentSnapshot.lastUpdated = new Date().toISOString();
        
        await env.ACCESSIBILITY_AUTH.put(`payment:${siteId}`, JSON.stringify(paymentSnapshot));
        console.log('Updated payment:${siteId} with cancellation status');
      }
      
      // Update site settings
        await mergeSiteSettings(env, siteId, {
          siteId,
        paymentStatus: cancelAtPeriodEnd ? 'canceling' : 'canceled',
          cancelAtPeriodEnd: subscription.cancel_at_period_end,
          currentPeriodEnd: subscription.current_period_end,
        cancellationDate: new Date().toISOString(),
        lastUpdated: new Date().toISOString()
        });
      console.log('Updated site settings with cancellation status');
    }
    
    const successResponse = secureJsonResponse({ 
      success: true,
      subscription: {
        id: subscription.id,
        status: subscription.status,
        cancel_at_period_end: subscription.cancel_at_period_end,
        current_period_end: subscription.current_period_end,
        canceled_at: subscription.canceled_at,
        access_details: {
          has_access: subscription.status === 'active',
          access_until: subscription.current_period_end,
          access_start: subscription.current_period_start,
          will_cancel: subscription.cancel_at_period_end,
          canceled_at: subscription.canceled_at
        }
      },
      message: cancelAtPeriodEnd 
        ? 'Subscription will be canceled at the end of the current billing period'
        : 'Subscription has been canceled immediately'
    });
    return addSecurityAndCorsHeaders(successResponse, origin);
    
  } catch (error) {
    console.error('Cancel subscription error:', error);
    const errorResponse = secureJsonResponse({ 
      success: false,
      error: 'Failed to cancel subscription',
      details: error.message 
    }, 500);
    return addSecurityAndCorsHeaders(errorResponse, origin);
  }
}

// Get subscription status
async function handleGetSubscriptionStatus(request, env) {
  const origin = request.headers.get('origin');
  
  try {
    const { siteId } = await request.json();
    
    if (!siteId) {
      const errorResponse = secureJsonResponse({ error: 'Missing site ID' }, 400);
      return addSecurityAndCorsHeaders(errorResponse, origin);
    }
    
    // Get user data from KV
    // user_data_${siteId} removed - using customer:${customerId} instead
    if (!userDataStr) {
      const errorResponse = secureJsonResponse({ error: 'No subscription found for this site' }, 404);
      return addSecurityAndCorsHeaders(errorResponse, origin);
    }
    
    const userData = JSON.parse(userDataStr);
    console.log('🔥 Backend: User data from KV:', {
      subscriptionId: userData.subscriptionId,
      paymentStatus: userData.paymentStatus,
      currentPeriodEnd: userData.currentPeriodEnd
    });
    
    // If we have a subscription ID, get current status from Stripe
    let subscriptionDetails = null;
    if (userData.subscriptionId) {
      console.log('🔥 Backend: Fetching Stripe subscription:', userData.subscriptionId);
      try {
        const subscriptionResponse = await fetch(`https://api.stripe.com/v1/subscriptions/${userData.subscriptionId}`, {
          headers: {
            Authorization: `Bearer ${env.STRIPE_SECRET_KEY}`
          }
        });
        
        console.log('🔥 Backend: Stripe API response status:', subscriptionResponse.status);
        
        if (subscriptionResponse.ok) {
          subscriptionDetails = await subscriptionResponse.json();
          // console.log('🔥 Backend: Full Stripe response:', JSON.stringify(subscriptionDetails, null, 2));
          // Extract current_period_end from items.data[0] (subscription items)
          const currentPeriodEnd = subscriptionDetails.items && 
                                  subscriptionDetails.items.data && 
                                  subscriptionDetails.items.data.length > 0 ? 
                                  subscriptionDetails.items.data[0].current_period_end : null;
          
          console.log('🔥 Backend: Stripe subscription details:', {
            id: subscriptionDetails.id,
            current_period_end: currentPeriodEnd,
            current_period_start: subscriptionDetails.items?.data?.[0]?.current_period_start,
            status: subscriptionDetails.status,
            created: subscriptionDetails.created,
            billing_cycle_anchor: subscriptionDetails.billing_cycle_anchor
          });
          
          // Add the extracted current_period_end to the subscriptionDetails object
          if (currentPeriodEnd) {
            subscriptionDetails.current_period_end = currentPeriodEnd;
            console.log('🔥 Backend: Added current_period_end to subscriptionDetails:', currentPeriodEnd);
          } else {
            console.error('🔥 Backend: Could not extract current_period_end from items!');
          }
        } else {
          const errorText = await subscriptionResponse.text();
          console.error('🔥 Backend: Stripe API error:', subscriptionResponse.status, errorText);
        }
      } catch (error) {
        console.error('🔥 Backend: Failed to fetch subscription details from Stripe:', error);
      }
    } else {
      console.log('🔥 Backend: No subscription ID found in user data');
    }
    
    const successResponse = secureJsonResponse({ 
      success: true,
      subscription: {
        id: userData.subscriptionId,
        status: userData.paymentStatus,
        cancelAtPeriodEnd: userData.cancelAtPeriodEnd || false,
        currentPeriodEnd: userData.currentPeriodEnd,
        lastPaymentDate: userData.lastPaymentDate,
        current_period_end: subscriptionDetails ? subscriptionDetails.current_period_end : userData.currentPeriodEnd,
        details: subscriptionDetails
      }
    });
    
    console.log('🔥 Backend: Returning subscription data:', {
      id: userData.subscriptionId,
      status: userData.paymentStatus,
      currentPeriodEnd: userData.currentPeriodEnd,
      current_period_end: subscriptionDetails ? subscriptionDetails.current_period_end : userData.currentPeriodEnd,
      details: subscriptionDetails ? {
        current_period_end: subscriptionDetails.current_period_end,
        status: subscriptionDetails.status
      } : null
    });
    return addSecurityAndCorsHeaders(successResponse, origin);
    
  } catch (error) {
    console.error('Get subscription status error:', error);
    const errorResponse = secureJsonResponse({ 
      error: 'Failed to get subscription status',
      details: error.message 
    }, 500);
    return addSecurityAndCorsHeaders(errorResponse, origin);
  }
}

async function handleUpdateSubscriptionMetadata(request, env) {
  const origin = request.headers.get('origin');
  
  try {
    const { siteId, subscriptionId, metadata } = await request.json();
    
    if (!siteId || !subscriptionId || !metadata) {
      const errorResponse = secureJsonResponse({ error: 'Missing required fields' }, 400);
      return addSecurityAndCorsHeaders(errorResponse, origin);
    }
    
    console.log('Updating subscription metadata:', { siteId, subscriptionId, metadata });
    
    // Retrieve existing subscription to preserve any existing metadata
    const existingSubscriptionResponse = await fetch(`https://api.stripe.com/v1/subscriptions/${subscriptionId}`, {
      headers: {
        Authorization: `Bearer ${env.STRIPE_SECRET_KEY}`
      }
    });
    
    if (!existingSubscriptionResponse.ok) {
      const errorText = await existingSubscriptionResponse.text();
      console.error('Failed to retrieve existing subscription:', errorText);
      const errorResponse = secureJsonResponse({ 
        error: 'Failed to retrieve subscription',
        details: errorText 
      }, 400);
      return addSecurityAndCorsHeaders(errorResponse, origin);
    }
    
    const existingSubscription = await existingSubscriptionResponse.json();
    const existingMetadata = existingSubscription.metadata || {};
    
    // Merge existing metadata with new metadata
    const mergedMetadata = {
      ...existingMetadata,
      ...metadata,
      updated_at: new Date().toISOString()
    };
    
    console.log('Merged metadata:', mergedMetadata);
    
    // Update the subscription with merged metadata
    // Stripe expects metadata as individual key-value pairs, not a JSON string
    const formData = new URLSearchParams();
    Object.entries(mergedMetadata).forEach(([key, value]) => {
      formData.append(`metadata[${key}]`, value);
    });
    
    const updateResponse = await fetch(`https://api.stripe.com/v1/subscriptions/${subscriptionId}`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${env.STRIPE_SECRET_KEY}`,
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: formData
    });
    
    if (!updateResponse.ok) {
      const errorText = await updateResponse.text();
      console.error('Failed to update subscription metadata:', errorText);
      const errorResponse = secureJsonResponse({ 
        error: 'Failed to update subscription metadata',
        details: errorText 
      }, 400);
      return addSecurityAndCorsHeaders(errorResponse, origin);
    }
    
    const updatedSubscription = await updateResponse.json();
    console.log('Subscription metadata updated successfully:', updatedSubscription.metadata);
    
    // Update KV store with new domain information
    try {
      // user_data_${siteId} removed - using customer:${customerId} instead
      if (userDataStr) {
        const userData = JSON.parse(userDataStr);
        userData.domain = metadata.domain || userData.domain;
        userData.lastUpdated = new Date().toISOString();
        // user_data_${siteId} removed - using customer:${customerId} instead
        console.log('Updated user_data with new domain:', userData.domain);
      }
      
      // Update payment snapshot
      const paymentSnapshotStr = await env.ACCESSIBILITY_AUTH.get(`payment:${siteId}`);
      if (paymentSnapshotStr) {
        const paymentSnapshot = JSON.parse(paymentSnapshotStr);
        paymentSnapshot.metadata = mergedMetadata;
        paymentSnapshot.lastUpdated = new Date().toISOString();
        await env.ACCESSIBILITY_AUTH.put(`payment:${siteId}`, JSON.stringify(paymentSnapshot));
        console.log('Updated payment snapshot with new metadata');
      }
      
      // Update domain mapping if domain is provided
      if (metadata.domain) {
        const domainKey = `domain:${metadata.domain}`;
        await env.ACCESSIBILITY_AUTH.put(domainKey, JSON.stringify({
          siteId: siteId,
          domain: metadata.domain,
          connectedAt: new Date().toISOString(),
          lastUpdated: new Date().toISOString()
        }), { expirationTtl: 86400 * 30 }); // 30 days
        console.log('Updated domain mapping for:', metadata.domain);
      }
      
    } catch (kvError) {
      console.warn('Failed to update KV store:', kvError);
      // Don't fail the request if KV update fails
    }
    
    const successResponse = secureJsonResponse({ 
      success: true,
      subscription: {
        id: updatedSubscription.id,
        metadata: updatedSubscription.metadata
      }
    });
    return addSecurityAndCorsHeaders(successResponse, origin);
    
  } catch (error) {
    console.error('Update subscription metadata error:', error);
    const errorResponse = secureJsonResponse({ 
      error: 'Failed to update subscription metadata',
      details: error.message 
    }, 500);
    return addSecurityAndCorsHeaders(errorResponse, origin);
  }
}

async function handleRemoveWidget(request, env) {
  const origin = request.headers.get('origin');
  
  try {
    const { siteId, domain, subscriptionId } = await request.json();
    
    if (!siteId || !domain || !subscriptionId) {
      const errorResponse = secureJsonResponse({ error: 'Missing required fields' }, 400);
      return addSecurityAndCorsHeaders(errorResponse, origin);
    }
    
    console.log('🔥 Backend: Removing widget from domain:', domain, 'siteId:', siteId);
    
    // Remove domain mapping from KV
    const domainKey = `domain:${domain}`;
    await env.ACCESSIBILITY_AUTH.delete(domainKey);
    console.log('🔥 Backend: Removed domain mapping for:', domain);
    
    // Also clean up any other domain mappings for this siteId to prevent conflicts
    try {
      // Get all domain mappings and remove any that belong to this siteId
      const allKeys = await env.ACCESSIBILITY_AUTH.list({ prefix: 'domain:' });
      for (const key of allKeys.keys) {
        const domainData = await env.ACCESSIBILITY_AUTH.get(key.name);
        if (domainData) {
          const domainInfo = JSON.parse(domainData);
          if (domainInfo.siteId === siteId && domainInfo.domain !== domain) {
            console.log('🔥 Backend: Removing conflicting domain mapping:', key.name, 'for siteId:', siteId);
            await env.ACCESSIBILITY_AUTH.delete(key.name);
          }
        }
      }
    } catch (error) {
      console.log('🔥 Backend: Could not clean up conflicting domain mappings:', error);
    }
    
    // Update user data to remove domain
    // user_data_${siteId} removed - using customer:${customerId} instead
    if (userDataStr) {
      const userData = JSON.parse(userDataStr);
      userData.previousDomain = userData.domain;
      userData.domain = null;
      userData.widgetRemovedAt = new Date().toISOString();
      // user_data_${siteId} removed - using customer:${customerId} instead
      console.log('🔥 Backend: Updated user data - widget removed from domain');
    }
    
    // Update payment snapshot
    const paymentSnapshotStr = await env.ACCESSIBILITY_AUTH.get(`payment:${siteId}`);
    if (paymentSnapshotStr) {
      const paymentSnapshot = JSON.parse(paymentSnapshotStr);
      paymentSnapshot.previousDomain = paymentSnapshot.domain;
      paymentSnapshot.domain = null;
      paymentSnapshot.widgetRemovedAt = new Date().toISOString();
      await env.ACCESSIBILITY_AUTH.put(`payment:${siteId}`, JSON.stringify(paymentSnapshot));
      console.log('🔥 Backend: Updated payment snapshot - widget removed');
    }
    
    const successResponse = secureJsonResponse({ 
      success: true,
      message: 'Widget removed from domain successfully',
      domain: domain,
      removedAt: new Date().toISOString()
    });
    return addSecurityAndCorsHeaders(successResponse, origin);
    
  } catch (error) {
    console.error('🔥 Backend: Remove widget error:', error);
    const errorResponse = secureJsonResponse({ 
      error: 'Failed to remove widget from domain',
      details: error.message 
    }, 500);
    return addSecurityAndCorsHeaders(errorResponse, origin);
  }
}

async function handleInstallWidget(request, env) {
  const origin = request.headers.get('origin');
  
  try {
    const { siteId, domain, subscriptionId } = await request.json();
    
    if (!siteId || !domain || !subscriptionId) {
      const errorResponse = secureJsonResponse({ error: 'Missing required fields' }, 400);
      return addSecurityAndCorsHeaders(errorResponse, origin);
    }
    
    console.log('🔥 Backend: Installing widget on domain:', domain, 'siteId:', siteId);
    
    // Create domain mapping in KV
    const domainKey = `domain:${domain}`;
    await env.ACCESSIBILITY_AUTH.put(domainKey, JSON.stringify({
      siteId: siteId,
      domain: domain,
      subscriptionId: subscriptionId,
      connectedAt: new Date().toISOString(),
      lastUpdated: new Date().toISOString()
    }), { expirationTtl: 86400 * 30 }); // 30 days
    console.log('🔥 Backend: Created domain mapping for:', domain);

    // Link domain -> installation so payment webhook can find installation when user pays with different email
    await backfillInstallationDomainIndex(env, siteId, domain);
    
    // Update user data with new domain
    // user_data_${siteId} removed - using customer:${customerId} instead
    if (userDataStr) {
      const userData = JSON.parse(userDataStr);
      userData.previousDomain = userData.domain;
      userData.domain = domain;
      userData.widgetInstalledAt = new Date().toISOString();
      userData.lastUpdated = new Date().toISOString();
      // user_data_${siteId} removed - using customer:${customerId} instead
      console.log('🔥 Backend: Updated user data with new domain:', domain);
    }
    
    // Update payment snapshot
    const paymentSnapshotStr = await env.ACCESSIBILITY_AUTH.get(`payment:${siteId}`);
    if (paymentSnapshotStr) {
      const paymentSnapshot = JSON.parse(paymentSnapshotStr);
      paymentSnapshot.previousDomain = paymentSnapshot.domain;
      paymentSnapshot.domain = domain;
      paymentSnapshot.widgetInstalledAt = new Date().toISOString();
      paymentSnapshot.lastUpdated = new Date().toISOString();
      await env.ACCESSIBILITY_AUTH.put(`payment:${siteId}`, JSON.stringify(paymentSnapshot));
      console.log('🔥 Backend: Updated payment snapshot with new domain');
    }
    
    // Update subscription metadata with new domain
    try {
      const formData = new URLSearchParams();
      formData.append('metadata[domain]', domain);
      formData.append('metadata[domainInstalledAt]', new Date().toISOString());
      
      const updateResponse = await fetch(`https://api.stripe.com/v1/subscriptions/${subscriptionId}`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${env.STRIPE_SECRET_KEY}`,
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: formData
      });
      
      if (updateResponse.ok) {
        console.log('🔥 Backend: Updated Stripe subscription metadata with new domain');
      } else {
        console.warn('🔥 Backend: Failed to update Stripe subscription metadata');
      }
    } catch (stripeError) {
      console.warn('🔥 Backend: Stripe metadata update failed:', stripeError);
      // Don't fail the request if Stripe update fails
    }
    
    const successResponse = secureJsonResponse({ 
      success: true,
      message: 'Widget installed on domain successfully',
      domain: domain,
      installedAt: new Date().toISOString()
    });
    return addSecurityAndCorsHeaders(successResponse, origin);
    
  } catch (error) {
    console.error('🔥 Backend: Install widget error:', error);
    const errorResponse = secureJsonResponse({ 
      error: 'Failed to install widget on domain',
      details: error.message 
    }, 500);
    return addSecurityAndCorsHeaders(errorResponse, origin);
  }
}

async function handleFixDomainMapping(request, env) {
  const origin = request.headers.get('origin');
  
  try {
    const { domain, siteId } = await request.json();
    
    if (!domain || !siteId) {
      const errorResponse = secureJsonResponse({ error: 'Missing domain or siteId' }, 400);
      return addSecurityAndCorsHeaders(errorResponse, origin);
    }
    
    console.log('Fixing domain mapping for:', domain, 'siteId:', siteId);
    
    // Create domain mapping
    const domainKey = `domain:${domain}`;
    await env.ACCESSIBILITY_AUTH.put(domainKey, JSON.stringify({
      siteId: siteId,
      domain: domain,
      connectedAt: new Date().toISOString(),
      lastUpdated: new Date().toISOString()
    }), { expirationTtl: 86400 * 30 }); // 30 days
    
    console.log('Domain mapping created successfully for:', domain);
    
    const successResponse = secureJsonResponse({ 
      success: true, 
      message: 'Domain mapping created successfully',
      domain: domain,
      siteId: siteId
    });
    return addSecurityAndCorsHeaders(successResponse, origin);
    
  } catch (error) {
    console.error('Error in handleFixDomainMapping:', error);
    const errorResponse = secureJsonResponse({ error: 'Failed to fix domain mapping' }, 500);
    return addSecurityAndCorsHeaders(errorResponse, origin);
  }
}

async function handleDebugPayment(request, env) {
  const origin = request.headers.get('origin');
  
  try {
    const url = new URL(request.url);
    const siteId = url.searchParams.get('siteId');
    
    if (!siteId) {
      const errorResponse = secureJsonResponse({ error: 'Missing siteId parameter' }, 400);
      return addSecurityAndCorsHeaders(errorResponse, origin);
    }
    
    console.log('Debug payment data for siteId:', siteId);
    
    // Get all possible payment-related keys
    const paymentKey = `payment:${siteId}`;
    // user_data_${siteId} removed - using customer:${customerId} instead
    const authDataKey = `auth-data:${siteId}`;
    
    const paymentData = await env.ACCESSIBILITY_AUTH.get(paymentKey);
    const userData = await env.ACCESSIBILITY_AUTH.get(userDataKey);
    const authData = await env.ACCESSIBILITY_AUTH.get(authDataKey);
    
    const debugInfo = {
      siteId: siteId,
      paymentData: paymentData ? JSON.parse(paymentData) : null,
      userData: userData ? JSON.parse(userData) : null,
      authData: authData ? JSON.parse(authData) : null,
      timestamp: new Date().toISOString()
    };
    
    console.log('Debug payment info:', debugInfo);
    
    const successResponse = secureJsonResponse(debugInfo);
    return addSecurityAndCorsHeaders(successResponse, origin);
    
  } catch (error) {
    console.error('Error in handleDebugPayment:', error);
    const errorResponse = secureJsonResponse({ error: 'Failed to debug payment data' }, 500);
    return addSecurityAndCorsHeaders(errorResponse, origin);
  }
}


// Reactivate subscription (for testing purposes)
async function handleReactivateSubscription(request, env) {
  const origin = request.headers.get('origin');
  
  try {
    const { siteId } = await request.json();
    
    if (!siteId) {
      const errorResponse = secureJsonResponse({ error: 'Missing siteId' }, 400);
      return addSecurityAndCorsHeaders(errorResponse, origin);
    }
    
    console.log('Reactivating subscription for siteId:', siteId);
    
    // user_data_${siteId} removed - using customer:${customerId} instead
    // user_data_${siteId} removed - using customer:${customerId} instead
    if (userDataStr) {
      const userData = JSON.parse(userDataStr);
      userData.paymentStatus = 'active';
      userData.lastPaymentDate = new Date().toISOString();
      userData.currentPeriodStart = Math.floor(Date.now() / 1000);
      userData.currentPeriodEnd = Math.floor(Date.now() / 1000) + (365 * 24 * 60 * 60); // 1 year from now
      userData.cancelAtPeriodEnd = false;
      userData.lastUpdated = new Date().toISOString();
      
      // user_data_${siteId} removed - using customer:${customerId} instead
     
    }
    
    // Update payment:${siteId} snapshot
    const paymentSnapshotStr = await env.ACCESSIBILITY_AUTH.get(`payment:${siteId}`);
    if (paymentSnapshotStr) {
      const paymentSnapshot = JSON.parse(paymentSnapshotStr);
      paymentSnapshot.status = 'active';
      paymentSnapshot.lastPaymentDate = new Date().toISOString();
      paymentSnapshot.currentPeriodStart = Math.floor(Date.now() / 1000);
      paymentSnapshot.currentPeriodEnd = Math.floor(Date.now() / 1000) + (365 * 24 * 60 * 60); // 1 year from now
      paymentSnapshot.cancelAtPeriodEnd = false;
      paymentSnapshot.lastUpdated = new Date().toISOString();
      
      await env.ACCESSIBILITY_AUTH.put(`payment:${siteId}`, JSON.stringify(paymentSnapshot));
    
    }
    
    const successResponse = secureJsonResponse({
      success: true,
      message: 'Subscription reactivated successfully',
      siteId: siteId,
      status: 'active',
      validUntil: new Date(Date.now() + (365 * 24 * 60 * 60 * 1000)).toISOString()
    });
    return addSecurityAndCorsHeaders(successResponse, origin);
    
  } catch (error) {

    const errorResponse = secureJsonResponse({ error: 'Failed to reactivate subscription' }, 500);
    return addSecurityAndCorsHeaders(errorResponse, origin);
  }
}

// Fetch customer details from Stripe API
async function fetchCustomerDetails(env, customerId, customerData) {
  try {
    const response = await fetch(`https://api.stripe.com/v1/customers/${customerId}`, {
      headers: {
        'Authorization': `Bearer ${env.STRIPE_SECRET_KEY}`,
        'Content-Type': 'application/x-www-form-urlencoded'
      }
    });
    
    if (response.ok) {
      const customer = await response.json();
      console.log('🔍 Fetched customer details:', { 
        customerId, 
        email: customer.email, 
        domain: customer.metadata?.domain,
        metadata: customer.metadata 
      });
      
      // Update email if not already set
      if (customer.email && !customerData.email) {
        customerData.email = customer.email;
      }
      
      // Update domain from various sources
      if (!customerData.customDomain) {
        // Try different metadata keys for domain
        const domain = customer.metadata?.domain || 
                      customer.metadata?.customDomain || 
                      customer.metadata?.website ||
                      customer.metadata?.site_url ||
                      customer.metadata?.yourwebsiteurllivedomain;
        
        if (domain) {
          customerData.customDomain = domain;
        }
      }

      // Note: Subscription data is now handled by webhook handlers directly
    }
  } catch (error) {
    console.error('Error fetching customer details:', error);
  }
}

// Fetch subscription details from Stripe API
async function fetchSubscriptionDetails(env, customerId, customerData) {
  try {
    const response = await fetch(`https://api.stripe.com/v1/subscriptions?customer=${customerId}&limit=1`, {
      headers: {
        'Authorization': `Bearer ${env.STRIPE_SECRET_KEY}`,
        'Content-Type': 'application/x-www-form-urlencoded'
      }
    });
    
    if (response.ok) {
      const subscriptions = await response.json();
      if (subscriptions.data && subscriptions.data.length > 0) {
        const subscription = subscriptions.data[0];
        console.log('🔍 Fetched subscription details:', { 
          subscriptionId: subscription.id, 
          status: subscription.status,
          current_period_end: subscription.current_period_end,
          items: subscription.items?.data?.[0]?.price
        });
        
        customerData.stripeSubscriptionId = subscription.id;
        customerData.subscriptionStatus = subscription.status === 'active' ? 'complete' : 'incomplete';
        customerData.paymentStatus = subscription.status === 'active' ? 'paid' : 'unpaid';
        customerData.isSubscribed = subscription.status === 'active';
        
        // Extract plan info
        if (subscription.items?.data?.[0]?.price) {
          const price = subscription.items.data[0].price;
          customerData.planType = price.unit_amount > 1000 ? 'annual' : 'monthly';
          customerData.validUntil = new Date(subscription.current_period_end * 1000).toISOString();
        }
      }
    }
  } catch (error) {
    console.error('Error fetching subscription details:', error);
  }
}

// Get latest subscription for a customer
async function getLatestSubscription(env, customerId) {
  if (!customerId) return null;
  const res = await fetch(`https://api.stripe.com/v1/subscriptions?customer=${customerId}&limit=1`, {
    headers: {
      'Authorization': `Bearer ${env.STRIPE_SECRET_KEY}`,
      'Content-Type': 'application/x-www-form-urlencoded'
    }
  });
  if (!res.ok) return null;
  const data = await res.json();
  return data?.data?.[0] || null;
}

// Get a subscription by ID
async function getSubscriptionById(env, subscriptionId) {
  if (!subscriptionId) return null;
  const res = await fetch(`https://api.stripe.com/v1/subscriptions/${subscriptionId}`, {
    headers: {
      'Authorization': `Bearer ${env.STRIPE_SECRET_KEY}`,
      'Content-Type': 'application/x-www-form-urlencoded'
    }
  });
  if (!res.ok) return null;
  return await res.json();
}

// Process Stripe events with customer-centric approach
async function processStripeEvent(env, event) {
  try {
    const obj = event?.data?.object || {};
    const type = event?.type || '';

    console.log('🔍 Processing Stripe event:', { type, eventId: event.id });

    // Extract customer ID
    const customerId = obj.customer || obj.subscription?.customer || null;
    if (!customerId) {
      console.log('No customer ID found in event:', type);
      return;
    }

    console.log('🔍 Found customer ID:', customerId);

    // Get existing customer data
    const customerKey = `customer:${customerId}`;
    const existingStr = await env.ACCESSIBILITY_AUTH.get(customerKey);
    let customerData = existingStr ? JSON.parse(existingStr) : {
      email: '',
      customDomain: '',
      isSubscribed: false,
      stripeCustomerId: customerId,
      stripeSubscriptionId: '',
      subscriptionStatus: 'incomplete',
      paymentStatus: 'unpaid',
      planType: '',
      validUntil: '',
      created: new Date().toISOString(),
      lastUpdated: new Date().toISOString()
    };

    // Process based on event type
    console.log('🔍 Event type:', type, 'Processing...');
    switch (type) {
      case 'checkout.session.completed':
        await handleCheckoutSessionCompleted(env, obj, customerData, customerKey);
        break;
      case 'customer.subscription.created':
        await handleSubscriptionCreated(env, obj, customerData, customerKey);
        break;
      case 'customer.subscription.updated':
        await handleSubscriptionUpdated(env, obj, customerData, customerKey);
        break;
      case 'customer.subscription.deleted':
        await handleSubscriptionDeleted(env, obj, customerData, customerKey);
        break;
      case 'invoice.payment_succeeded':
        await handleInvoicePaymentSucceeded(env, obj, customerData, customerKey);
        break;
      case 'payment_intent.succeeded':
        await handlePaymentIntentSucceeded(env, obj, customerData, customerKey);
        break;
      default:
        console.log('⚠️ Unhandled event type:', type);
        break;
    }
  } catch (error) {
    console.error('Error processing Stripe event:', error);
  }
}

// Handle checkout.session.completed - extract domain from custom_fields, siteId from metadata (set when session created via API)
async function handleCheckoutSessionCompleted(env, session, customerData, customerKey) {
  console.log('🔍 Processing checkout.session.completed:', session.id);
  
  // Extract siteId from session metadata (no custom field: set when app calls create-checkout-session with siteId in body)
  if (session.metadata?.siteId) {
    customerData.siteId = session.metadata.siteId;
    console.log('🔍 Extracted siteId from session metadata:', customerData.siteId);
  }
  if (!customerData.siteId && session.subscription) {
    try {
      const sub = await getSubscriptionById(env, session.subscription);
      if (sub?.metadata?.siteId) {
        customerData.siteId = sub.metadata.siteId;
        console.log('🔍 Extracted siteId from subscription metadata:', customerData.siteId);
      }
    } catch (_) {}
  }
  
  // Extract email from customer_details
  const email = session.customer_details?.email || session.customer_email || customerData.email;
  console.log('🔍 Extracted email from checkout session:', email);
  
  // Extract custom domain from custom_fields
  let customDomain = customerData.customDomain;
  if (session.custom_fields && Array.isArray(session.custom_fields)) {
    const domainField = session.custom_fields.find(field => 
      field.key === 'yourwebsiteurllivedomain' || 
      field.text?.label === 'Your Website URL (Live Domain)'
    );
    if (domainField?.text?.value) {
      customDomain = domainField.text.value;
      console.log('🔍 Extracted domain from checkout session:', customDomain);
    }
  }

  // Update customer data
  customerData.email = email;
  customerData.customDomain = customDomain;
  customerData.paymentStatus = session.payment_status === 'paid' ? 'paid' : 'unpaid';
  customerData.subscriptionStatus = 'complete';
  customerData.isSubscribed = true;
  customerData.stripeSubscriptionId = session.subscription || customerData.stripeSubscriptionId;
  customerData.lastUpdated = new Date().toISOString();

  // Backfill subscription fields if missing
  if (!customerData.stripeSubscriptionId || !customerData.planType || !customerData.validUntil) {
    try {
      const sub = await getLatestSubscription(env, customerData.stripeCustomerId);
      if (sub) {
        customerData.stripeSubscriptionId = customerData.stripeSubscriptionId || sub.id;
        const price = sub.items?.data?.[0]?.price;
        if (!customerData.planType && price?.recurring?.interval) {
          customerData.planType = price.recurring.interval === 'year' ? 'annual' : 'monthly';
        }
        if (!customerData.validUntil && sub.current_period_end) {
          customerData.validUntil = new Date(sub.current_period_end * 1000).toISOString();
        }
      }
    } catch (e) {
      console.log('⚠️ Backfill in checkout.session.completed failed:', String(e));
    }
  }

  // Canonical upsert once (include siteId so payment webhook can resolve installation by siteId)
  const updatedCustomerData = await upsertCustomerRecord(env, customerData.stripeCustomerId, {
    email,
    customDomain,
    siteId: customerData.siteId || undefined,
    isSubscribed: true,
    paymentStatus: customerData.paymentStatus,
    subscriptionStatus: customerData.subscriptionStatus,
    stripeSubscriptionId: customerData.stripeSubscriptionId,
    planType: customerData.planType,
    validUntil: customerData.validUntil,
    created: customerData.created
  });
  if (customerData.siteId && updatedCustomerData) {
    updatedCustomerData.siteId = customerData.siteId;
  }

  // Send ClickUp webhook when payment is completed for live domains
  if (customerData.paymentStatus === 'paid' && customerData.isSubscribed) {
    await sendPaymentCompletedClickUpWebhook(env, updatedCustomerData || customerData, 'checkout.session.completed');
  }
}

// Handle subscription events
async function handleSubscriptionCreated(env, subscription, customerData, customerKey) {
  console.log('🔍 Processing subscription.created:', subscription.id);
  
  // Extract subscription data directly from webhook
  customerData.stripeSubscriptionId = subscription.id;
  customerData.subscriptionStatus = subscription.status === 'active' ? 'complete' : 'incomplete';
  customerData.paymentStatus = subscription.status === 'active' ? 'paid' : 'unpaid';
  customerData.isSubscribed = subscription.status === 'active';
  customerData.lastUpdated = new Date().toISOString();

  // Extract plan info from subscription data
  if (subscription.items?.data?.[0]?.price) {
    const price = subscription.items.data[0].price;
    console.log('🔍 Price details:', { 
      unit_amount: price.unit_amount, 
      interval: price.recurring?.interval,
      currency: price.currency 
    });
    
    // Determine plan type based on interval (monthly vs annual)
    customerData.planType = price.recurring?.interval === 'year' ? 'annual' : 'monthly';
    
    // Extract valid until date from current_period_end
    if (subscription.current_period_end) {
      customerData.validUntil = new Date(subscription.current_period_end * 1000).toISOString();
      console.log('🔍 Valid until:', customerData.validUntil);
    }
  }

  // Fetch customer details from Stripe API for email and domain
  await fetchCustomerDetails(env, customerData.stripeCustomerId, customerData);

  // Canonical upsert once
  const updatedCustomerData = await upsertCustomerRecord(env, customerData.stripeCustomerId, {
    email: customerData.email,
    customDomain: customerData.customDomain,
    isSubscribed: customerData.isSubscribed,
    paymentStatus: customerData.paymentStatus,
    subscriptionStatus: customerData.subscriptionStatus,
    stripeSubscriptionId: customerData.stripeSubscriptionId,
    planType: customerData.planType,
    validUntil: customerData.validUntil,
    created: customerData.created
  });

  // Send ClickUp webhook when subscription is created and active (payment completed)
  // NOTE: Only checkout.session.completed sends webhook to avoid duplicates
  // Other events (subscription.created, invoice.payment_succeeded, payment_intent.succeeded) 
  // are handled by checkout.session.completed
  // if (subscription.status === 'active' && customerData.isSubscribed) {
  //   await sendPaymentCompletedClickUpWebhook(env, updatedCustomerData || customerData, 'customer.subscription.created');
  // }
}

async function handleSubscriptionUpdated(env, subscription, customerData, customerKey) {
  customerData.stripeSubscriptionId = subscription.id;
  // Handle cancellations and scheduled cancellations/renewals
  if (subscription.status === 'canceled' || subscription.canceled_at) {
    customerData.subscriptionStatus = 'cancelled';
    customerData.paymentStatus = 'cancelled';
    customerData.isSubscribed = false;
  } else if (subscription.cancel_at || subscription.cancel_at_period_end) {
    customerData.subscriptionStatus = 'scheduled_cancellation';
    customerData.paymentStatus = 'paid';
    customerData.isSubscribed = true;
    // Prefer explicit cancel_at timestamp if provided, else period end
    const endTs = subscription.cancel_at || subscription.current_period_end;
    if (endTs) {
      customerData.validUntil = new Date(endTs * 1000).toISOString();
    }
  } else {
    customerData.subscriptionStatus = subscription.status === 'active' ? 'complete' : 'incomplete';
    customerData.paymentStatus = subscription.status === 'active' ? 'paid' : 'unpaid';
    customerData.isSubscribed = subscription.status === 'active';
  }
  customerData.lastUpdated = new Date().toISOString();

  // Update plan info
  if (subscription.items?.data?.[0]?.price) {
    const price = subscription.items.data[0].price;
    customerData.planType = price.unit_amount > 1000 ? 'annual' : 'monthly';
    if (subscription.current_period_end) {
      customerData.validUntil = new Date(subscription.current_period_end * 1000).toISOString();
    }
  }

  // Canonical upsert once
  await upsertCustomerRecord(env, customerData.stripeCustomerId, {
    email: customerData.email,
    customDomain: customerData.customDomain,
    isSubscribed: customerData.isSubscribed,
    paymentStatus: customerData.paymentStatus,
    subscriptionStatus: customerData.subscriptionStatus,
    stripeSubscriptionId: customerData.stripeSubscriptionId,
    planType: customerData.planType,
    validUntil: customerData.validUntil,
    created: customerData.created
  });
}

async function handleSubscriptionDeleted(env, subscription, customerData, customerKey) {
  customerData.stripeSubscriptionId = subscription.id;
  customerData.subscriptionStatus = 'cancelled';
  customerData.paymentStatus = 'cancelled';
  customerData.isSubscribed = false;
  customerData.lastUpdated = new Date().toISOString();

  // Canonical upsert once
  await upsertCustomerRecord(env, customerData.stripeCustomerId, {
    email: customerData.email,
    customDomain: customerData.customDomain,
    isSubscribed: false,
    paymentStatus: 'cancelled',
    subscriptionStatus: 'cancelled',
    stripeSubscriptionId: customerData.stripeSubscriptionId,
    planType: customerData.planType,
    validUntil: customerData.validUntil,
    created: customerData.created
  });
}

async function handleInvoicePaymentSucceeded(env, invoice, customerData, customerKey) {
  // Fetch customer details from Stripe API
  await fetchCustomerDetails(env, customerData.stripeCustomerId, customerData);

  customerData.paymentStatus = 'paid';
  customerData.subscriptionStatus = 'complete';
  customerData.isSubscribed = true;
  customerData.lastUpdated = new Date().toISOString();

  // Backfill subscription fields if missing
  try {
    let subscriptionId = invoice.subscription || invoice.parent?.subscription_details?.subscription || customerData.stripeSubscriptionId;
    if (!subscriptionId) {
      const sub = await getLatestSubscription(env, customerData.stripeCustomerId);
      if (sub) subscriptionId = sub.id;
    }
    if (subscriptionId) {
      if (!customerData.stripeSubscriptionId) customerData.stripeSubscriptionId = subscriptionId;
      if (!customerData.planType || !customerData.validUntil) {
        const sub = await getSubscriptionById(env, subscriptionId);
        if (sub) {
          const price = sub.items?.data?.[0]?.price;
          if (!customerData.planType && price?.recurring?.interval) {
            customerData.planType = price.recurring.interval === 'year' ? 'annual' : 'monthly';
          }
          if (!customerData.validUntil && sub.current_period_end) {
            customerData.validUntil = new Date(sub.current_period_end * 1000).toISOString();
          }
        }
      }
    }
  } catch (e) {
    console.log('⚠️ Backfill in invoice.payment_succeeded failed:', String(e));
  }

  // Canonical upsert once
  const updatedCustomerData = await upsertCustomerRecord(env, customerData.stripeCustomerId, {
    email: customerData.email,
    customDomain: customerData.customDomain,
    isSubscribed: customerData.isSubscribed,
    paymentStatus: customerData.paymentStatus,
    subscriptionStatus: customerData.subscriptionStatus,
    stripeSubscriptionId: customerData.stripeSubscriptionId,
    planType: customerData.planType,
    validUntil: customerData.validUntil,
    created: customerData.created
  });

  // Create domain index if we have a domain
  if (customerData.customDomain) {
    const keys = buildDomainIndexKeys(customerData.customDomain);
    for (const k of keys) {
      await env.ACCESSIBILITY_AUTH.put(k, customerData.stripeCustomerId);
    }
  }

  // Create email index
  if (customerData.email) {
    await env.ACCESSIBILITY_AUTH.put(`email:${customerData.email.toLowerCase()}`, customerData.stripeCustomerId);
  }

  // Send ClickUp webhook when payment is completed for live domains
  // NOTE: Only checkout.session.completed sends webhook to avoid duplicates
  // Other events (subscription.created, invoice.payment_succeeded, payment_intent.succeeded) 
  // are handled by checkout.session.completed
  // await sendPaymentCompletedClickUpWebhook(env, updatedCustomerData || customerData, 'invoice.payment_succeeded');
}

async function handlePaymentIntentSucceeded(env, paymentIntent, customerData, customerKey) {
  // Fetch customer details from Stripe API
  await fetchCustomerDetails(env, customerData.stripeCustomerId, customerData);

  customerData.paymentStatus = 'paid';
  customerData.subscriptionStatus = 'complete';
  customerData.isSubscribed = true;
  customerData.lastUpdated = new Date().toISOString();

  // Backfill subscription fields if missing
  try {
    let subscriptionId = paymentIntent.subscription || customerData.stripeSubscriptionId;
    if (!subscriptionId) {
      const sub = await getLatestSubscription(env, customerData.stripeCustomerId);
      if (sub) subscriptionId = sub.id;
    }
    if (subscriptionId) {
      if (!customerData.stripeSubscriptionId) customerData.stripeSubscriptionId = subscriptionId;
      if (!customerData.planType || !customerData.validUntil) {
        const sub = await getSubscriptionById(env, subscriptionId);
        if (sub) {
          const price = sub.items?.data?.[0]?.price;
          if (!customerData.planType && price?.recurring?.interval) {
            customerData.planType = price.recurring.interval === 'year' ? 'annual' : 'monthly';
          }
          if (!customerData.validUntil && sub.current_period_end) {
            customerData.validUntil = new Date(sub.current_period_end * 1000).toISOString();
          }
        }
      }
    }
  } catch (e) {
    console.log('⚠️ Backfill in payment_intent.succeeded failed:', String(e));
  }

  // Canonical upsert once
  const updatedCustomerData = await upsertCustomerRecord(env, customerData.stripeCustomerId, {
    email: customerData.email,
    customDomain: customerData.customDomain,
    isSubscribed: customerData.isSubscribed,
    paymentStatus: customerData.paymentStatus,
    subscriptionStatus: customerData.subscriptionStatus,
    stripeSubscriptionId: customerData.stripeSubscriptionId,
    planType: customerData.planType,
    validUntil: customerData.validUntil,
    created: customerData.created
  });

  // Create domain index if we have a domain
  if (customerData.customDomain) {
    const domainKey1 = `domain:${customerData.customDomain}`;
    const domainKey2 = `domain:${customerData.customDomain.replace(/\/$/, '')}`;
    await env.ACCESSIBILITY_AUTH.put(domainKey1, customerData.stripeCustomerId);
    await env.ACCESSIBILITY_AUTH.put(domainKey2, customerData.stripeCustomerId);
  }

  // Create email index
  if (customerData.email) {
    await env.ACCESSIBILITY_AUTH.put(`email:${customerData.email.toLowerCase()}`, customerData.stripeCustomerId);
  }

  // Send ClickUp webhook when payment is completed for live domains (only if it's a subscription)
  // NOTE: Only checkout.session.completed sends webhook to avoid duplicates
  // Other events (subscription.created, invoice.payment_succeeded, payment_intent.succeeded) 
  // are handled by checkout.session.completed
  // if (paymentIntent.subscription || customerData.stripeSubscriptionId) {
  //   await sendPaymentCompletedClickUpWebhook(env, updatedCustomerData || customerData, 'payment_intent.succeeded');
  // }
}

// Extract host from domain URL
function extractHostFromDomain(domain) {
  if (!domain) return null;
  try {
    const url = new URL(domain.startsWith('http') ? domain : `https://${domain}`);
    return url.hostname.toLowerCase();
  } catch {
    return domain.replace(/^https?:\/\//, '').split('/')[0].toLowerCase();
  }
}

// Normalize a domain/URL to host-only, lowercased, no trailing slash, no path
function normalizeHost(domain) {
  if (!domain) return '';
  try {
    const url = new URL(domain.startsWith('http') ? domain : `https://${domain}`);
    return url.hostname.toLowerCase();
  } catch {
    return String(domain)
      .replace(/^https?:\/\//, '')
      .replace(/\/$/, '')
      .split('/')[0]
      .toLowerCase();
  }
}

// Build canonical domain index keys: host and www.host only
function buildDomainIndexKeys(domain) {
  const host = normalizeHost(domain);
  if (!host) return [];
  const noWww = host.replace(/^www\./, '');
  const withWww = noWww === host ? `www.${noWww}` : host;
  const keys = new Set();
  keys.add(`domain:${noWww}`);
  keys.add(`domain:${withWww}`);
  return Array.from(keys);
}

// Build installation-domain key variants for lookup (payment webhook can try each)
function buildInstallationDomainKeyVariants(domain) {
  if (!domain) return [];
  const host = normalizeHost(domain);
  if (!host) return []; // raw as fallback
  const noWww = host.replace(/^www\./, '');
  const withWww = noWww === host ? `www.${noWww}` : host;
  const keys = [`installation-domain:${noWww}`, `installation-domain:${withWww}`];
  if (domain !== host && domain !== noWww && domain !== withWww) {
    keys.push(`installation-domain:${domain}`);
  }
  return keys;
}

// Backfill installation-domain index so payment webhook can find installation by domain (no Stripe metadata needed).
// Call whenever we learn (siteId, domain) from save-custom-domain, check-payment-status, or install-widget.
async function backfillInstallationDomainIndex(env, siteId, domain) {
  if (!siteId || !domain) return;
  const host = normalizeHost(domain);
  if (!host) return;
  try {
    const installationStr = await env.ACCESSIBILITY_AUTH.get(`installation_${siteId}`);
    if (!installationStr) return;
    const noWww = host.replace(/^www\./, '');
    const withWww = noWww === host ? `www.${noWww}` : host;
    for (const key of [`installation-domain:${noWww}`, `installation-domain:${withWww}`]) {
      await env.ACCESSIBILITY_AUTH.put(key, installationStr);
    }
    console.log('✅ Backfilled installation-domain index for siteId:', siteId, 'domain:', host);
  } catch (e) {
    console.warn('⚠️ backfillInstallationDomainIndex failed:', String(e));
  }
}

// Delete legacy protocol/slash variants once canonical keys exist
async function cleanupLegacyDomainKeys(env, domain) {
  const host = normalizeHost(domain);
  if (!host) return;
  const candidates = [
    `domain:https://${host}`,
    `domain:https://${host}/`,
    `domain:https://www.${host.replace(/^www\./,'')}`,
    `domain:${host}/`,
  ];
  for (const k of candidates) {
    try { await env.ACCESSIBILITY_AUTH.delete(k); } catch {}
  }
}

// Merge helper: only apply provided values; avoid overwriting with empty strings
function mergeCustomerFields(existing, updates) {
  const result = { ...(existing || {}) };
  for (const [key, value] of Object.entries(updates || {})) {
    if (value === undefined) continue;
    if (typeof value === 'string') {
      // Allow explicit status strings, but avoid blank overwrites
      if (value.trim() === '' && typeof result[key] === 'string' && result[key].trim() !== '') {
        continue;
      }
    }
    result[key] = value;
  }
  return result;
}

// Helper function to send ClickUp webhook when payment is completed
async function sendPaymentCompletedClickUpWebhook(env, customerData, eventType = 'payment_completed') {
  try {
    // Check payment status - payment webhooks should ONLY fire for active, paid subscriptions
    const hasActivePayment = customerData.isSubscribed && customerData.paymentStatus === 'paid';
    
    // CRITICAL: If payment is not active, don't send webhook at all
    // Payment webhooks should only be sent for successful payments
    if (!hasActivePayment) {
      console.log('⏭️ Skipping ClickUp webhook - payment not active (payment webhooks only for active payments)');
      return;
    }

    // Deduplication: Prevent duplicate tasks for the same payment
    // Use customerId only to ensure we only send once per customer payment
    // This works even if subscription ID changes or isn't set yet
    let dedupeKey = null;
    if (hasActivePayment && customerData.stripeCustomerId) {
      dedupeKey = `clickup-webhook-sent:${customerData.stripeCustomerId}`;
      const existingWebhook = await env.ACCESSIBILITY_AUTH.get(dedupeKey);
      if (existingWebhook) {
        console.log('⏭️ Skipping ClickUp webhook - already sent for this customer payment (deduplication)');
        console.log('⏭️ Dedupe key:', dedupeKey);
        return;
      }
    }

    // Get installation data: try siteId from metadata first (when session created via create-checkout-session with siteId), then email, then domain
    let installationData = null;
    
    // Prefer siteId from payment (session/subscription metadata) - no custom field, set when app calls create-checkout-session with siteId
    if (customerData.siteId) {
      try {
        const installationDataStr = await env.ACCESSIBILITY_AUTH.get(`installation_${customerData.siteId}`);
        if (installationDataStr) {
          installationData = JSON.parse(installationDataStr);
          console.log('✅ DEBUG: Found installation data by siteId (from metadata):', customerData.siteId);
        }
      } catch (e) {
        console.log('⚠️ Could not fetch installation data by siteId:', e);
      }
    }
    
    // Try email lookup
    if (customerData.email) {
      try {
        const emailLower = customerData.email.toLowerCase().trim();
        let installationDataStr = null;
        if (env.EMAIL_INDEX_KEY) {
          const emailHash = await computeHmacHex(emailLower, env.EMAIL_INDEX_KEY);
          const installationKey = `installation-email-hash:${emailHash}`;
          console.log('🔍 DEBUG: Fetching installation data by email hash:', installationKey);
          installationDataStr = await env.ACCESSIBILITY_AUTH.get(installationKey);
        }

        // Fallback to legacy plaintext index if not configured or not found
        if (!installationDataStr) {
          const installationKeyLegacy = `installation-email:${emailLower}`;
          console.log('🔍 DEBUG: Fetching installation data by legacy email key:', installationKeyLegacy);
          installationDataStr = await env.ACCESSIBILITY_AUTH.get(installationKeyLegacy);
        }

        if (installationDataStr) {
          installationData = JSON.parse(installationDataStr);
          console.log('✅ DEBUG: Found installation data by email (or hash):', {
            firstName: installationData.firstName,
            siteName: installationData.siteName,
            customDomain: installationData.customDomain,
            stagingUrl: installationData.stagingUrl,
            siteId: installationData.siteId
          });
        } else {
          console.log('⚠️ DEBUG: No installation data found for email:', customerData.email);
        }
      } catch (e) {
        console.log('⚠️ Could not fetch installation data by email:', e);
      }
    }
    
    // If email lookup failed, try domain lookup (from checkout custom field - only thing we have without Stripe metadata)
    // Try all key variants (normalized, www, no-www) so we find installation even if format differs
    if (!installationData && customerData.customDomain) {
      try {
        const keyVariants = buildInstallationDomainKeyVariants(customerData.customDomain);
        console.log('🔍 DEBUG: Email lookup failed, trying domain lookup. Keys to try:', keyVariants);
        let installationDataStr = null;
        for (const key of keyVariants) {
          installationDataStr = await env.ACCESSIBILITY_AUTH.get(key);
          if (installationDataStr) break;
        }
        if (installationDataStr) {
          installationData = JSON.parse(installationDataStr);
          console.log('✅ DEBUG: Found installation data by domain:', {
            firstName: installationData.firstName,
            siteName: installationData.siteName,
            customDomain: installationData.customDomain,
            stagingUrl: installationData.stagingUrl,
            siteId: installationData.siteId
          });
        } else {
          console.log('⚠️ DEBUG: No installation data found for domain (tried variants):', customerData.customDomain);
        }
      } catch (e) {
        console.log('⚠️ Could not fetch installation data by domain:', e);
      }
    }
    
    if (!installationData) {
      console.log('⚠️ DEBUG: Installation data not found by email or domain');
      console.log('⚠️ DEBUG: Searched for email:', customerData.email);
      console.log('⚠️ DEBUG: Searched for domain:', customerData.customDomain);
      console.log('⚠️ DEBUG: customerData keys:', Object.keys(customerData || {}));
      console.log('⚠️ DEBUG: customerData:', JSON.stringify({
        email: customerData.email,
        customDomain: customerData.customDomain,
        stripeCustomerId: customerData.stripeCustomerId,
        stripeSubscriptionId: customerData.stripeSubscriptionId
      }, null, 2));
      
      // Try to list what installation keys exist (for debugging)
      // Note: KV doesn't support listing, but we can try to see if we can find related keys
      console.log('⚠️ DEBUG: Attempted lookup keys:');
      if (customerData.email) {
        console.log('  - installation-email:' + customerData.email.toLowerCase());
      }
      if (customerData.customDomain) {
        const normalizedDomain = normalizeHost(customerData.customDomain);
        if (normalizedDomain) {
          console.log('  - installation-domain:' + normalizedDomain);
        }
      }
      if (customerData.siteId) {
        console.log('  - installation_:' + customerData.siteId);
      }
    }

    // Use installation data from frontend, fallback to defaults
    const firstName = installationData?.firstName || 'User';
    const siteName = installationData?.siteName || null;
    const customDomain = installationData?.customDomain || null;
    const stagingUrl = installationData?.stagingUrl || null;
    const shortName = installationData?.shortName || null;
    
    // Determine if this is staging: ONLY if payment is NOT active
    // CRITICAL: If payment is active (hasActivePayment = true), it should NEVER be staging
    // Payment webhooks should only fire for active payments, so they should ALWAYS go to live folder
    const isStaging = !hasActivePayment;
    
    console.log('🔍 DEBUG: Final values before webhook:', {
      firstName: firstName,
      siteName: siteName,
      customDomain: customDomain,
      stagingUrl: stagingUrl,
      hasActivePayment: hasActivePayment,
      isStaging: isStaging,
      subscriptionId: customerData.stripeSubscriptionId,
      paymentStatus: customerData.paymentStatus
    });
    
    console.log('✅ CONFIRMED: Using installation data from frontend + adding payment info:', {
      fromInstallation: {
        firstName: firstName,
        siteName: siteName,
        customDomain: customDomain,
        stagingUrl: stagingUrl,
        siteId: installationData?.siteId
      },
      addedPaymentInfo: {
        paymentStatus: customerData.paymentStatus,
        subscriptionId: customerData.stripeSubscriptionId,
        customerId: customerData.stripeCustomerId,
        planType: customerData.planType
      },
      clickupFolder: 'live' // Always live for payment webhooks
    });
    
    const clickupWebhookUrl = env.MAKE_CLICKUP_WEBHOOK_URL || 'https://hook.us1.make.com/2nq5grcxerkoum85ibdhoayngay6j1hg';
    
    // Use same structure as installation webhook, just add payment status and subscription ID
    // This takes installation data from frontend and adds payment info
    // Ensure we include a usable email: prefer customerData.email, else decrypt stored installation encryptedEmail if present
    let payloadEmail = '';
    if (customerData.email) {
      payloadEmail = customerData.email;
    } else if (installationData?.encryptedEmail) {
      try { payloadEmail = await decryptEmailServerSide(installationData.encryptedEmail, env); } catch (e) { payloadEmail = installationData?.userEmail || ''; }
    } else {
      payloadEmail = installationData?.userEmail || '';
    }

    const webhookPayload = {
      event: eventType,
      // Customer information at top level (same as installation - from frontend)
      email: payloadEmail,
      firstName: firstName, // From installation data
      siteId: installationData?.siteId || null, // From installation data
      siteName: siteName, // From installation data
      userId: installationData?.userId || null, // From installation data
      // Additional data from installation (same structure - from frontend)
      customDomain: customDomain, // From installation data
      stagingUrl: stagingUrl, // From installation data
      shortName: shortName, // From installation data
      timestamp: new Date().toISOString(),
      source: 'payment_webhook',
      // ClickUp folder information
      // CRITICAL: Payment webhooks should ONLY fire for active payments
      // If hasActivePayment is true, ALWAYS use 'live' folder, NEVER 'staging'
      clickupFolder: 'live', // Always 'live' for payment webhooks (payment is active)
      isStaging: false, // Always false for payment webhooks (payment is active)
      hasActivePayment: true, // Always true (we only send when payment is active)
      // Payment status details (ADDED to installation data - this is the new data)
      paymentStatus: customerData.paymentStatus || 'paid',
      subscriptionStatus: customerData.subscriptionStatus || 'complete',
      isSubscribed: customerData.isSubscribed || true,
      subscriptionId: customerData.stripeSubscriptionId || null, // Payment subscription ID
      customerId: customerData.stripeCustomerId, // Payment customer ID
      planType: customerData.planType || null, // Payment plan type
      // Keep nested structure for backward compatibility (same as installation)
      customer: {
        email: customerData.email || installationData?.userEmail || '',
        firstName: firstName,
        siteId: installationData?.siteId || null,
        siteName: siteName,
        userId: installationData?.userId || null
      },
      payment: {
        status: customerData.paymentStatus || 'paid',
        subscriptionId: customerData.stripeSubscriptionId || null,
        planType: customerData.planType || null,
        validUntil: customerData.validUntil || null
      }
    };

    // Send payment confirmation email via Brevo (no Make email webhook)
    if (payloadEmail) {
      const emailSent = await sendPaymentEmail(env, payloadEmail, firstName);
      if (!emailSent) console.warn('⚠️ Brevo payment email failed or returned false for:', payloadEmail.replace(/([^@]).*(@.*)/, '$1****$2'));
    }

    console.log(`📁 Sending ClickUp webhook with folder: ${hasActivePayment ? 'live' : 'staging'}, isStaging: ${isStaging}`);
    const payloadToLog2 = Object.assign({}, webhookPayload, { email: webhookPayload.email ? webhookPayload.email.replace(/([^@]).*(@.*)/, '$1****$2') : webhookPayload.email });
    console.log('📤 DEBUG: Full webhook payload being sent (email masked):', JSON.stringify(payloadToLog2, null, 2));
    const clickupWebhookResponse = await fetch(clickupWebhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(webhookPayload)
    });

    const clickupWebhookResponseText = await clickupWebhookResponse.text();
    console.log('📨 Payment-completed ClickUp webhook response status:', clickupWebhookResponse.status);
    console.log('📨 Payment-completed ClickUp webhook response body:', clickupWebhookResponseText);

    if (!clickupWebhookResponse.ok) {
      console.error('❌ Payment-completed ClickUp webhook failed:', clickupWebhookResponse.status, clickupWebhookResponseText);
    } else {
      console.log(`✅ ClickUp webhook sent successfully (folder: ${hasActivePayment ? 'live' : 'staging'})`);
      
      // Mark webhook as sent to prevent duplicates (for all active payments)
      // Use customerId only for deduplication key
      if (dedupeKey && hasActivePayment && customerData.stripeCustomerId) {
        await env.ACCESSIBILITY_AUTH.put(dedupeKey, JSON.stringify({
          sentAt: new Date().toISOString(),
          eventType: eventType,
          customerId: customerData.stripeCustomerId,
          subscriptionId: customerData.stripeSubscriptionId || null,
          email: customerData.email || '',
          clickupFolder: 'live',
          isStaging: false
        }), { expirationTtl: 90 * 24 * 60 * 60 }); // 90 days in seconds
        
        console.log('✅ Deduplication flag set for this customer payment (folder: live)');
        console.log('✅ Dedupe key:', dedupeKey);
      }
    }
  } catch (error) {
    console.error('❌ Error sending payment-completed ClickUp webhook:', error);
    // Don't throw - this is a non-critical operation
  }
}

// Single canonical upsert for customer:{customerId}
async function upsertCustomerRecord(env, customerId, updates) {
  if (!customerId) return null;
  const customerKey = `customer:${customerId}`;
  const existingStr = await env.ACCESSIBILITY_AUTH.get(customerKey);
  const existing = existingStr ? JSON.parse(existingStr) : {};
  const merged = mergeCustomerFields(existing, updates);

  // Ensure ids are set
  merged.stripeCustomerId = customerId;
  merged.lastUpdated = new Date().toISOString();
  if (!merged.created) merged.created = new Date().toISOString();

  await env.ACCESSIBILITY_AUTH.put(customerKey, JSON.stringify(merged));

  // Write canonical indexes if present
  if (merged.customDomain) {
    const keys = buildDomainIndexKeys(merged.customDomain);
    for (const k of keys) {
      const existing = await env.ACCESSIBILITY_AUTH.get(k);
      if (existing !== customerId) {
        await env.ACCESSIBILITY_AUTH.put(k, customerId);
      }
    }
    // Optional cleanup of legacy protocol/slash variants
    try { await cleanupLegacyDomainKeys(env, merged.customDomain); } catch {}
  }
  if (merged.email) {
    await env.ACCESSIBILITY_AUTH.put(`email:${merged.email.toLowerCase()}`, customerId);
  }

  return merged;
}

// Fix domain index for existing customer data
async function handleFixDomainIndex(request, env) {
  const origin = request.headers.get('origin');
  
  try {
    const url = new URL(request.url);
    const customerId = url.searchParams.get('customerId');
    
    if (!customerId) {
      return addSecurityAndCorsHeaders(secureJsonResponse({ 
        error: 'Missing customerId parameter' 
      }), origin);
    }
    
    const customerKey = `customer:${customerId}`;
    const customerDataStr = await env.ACCESSIBILITY_AUTH.get(customerKey);
    
    if (!customerDataStr) {
      return addSecurityAndCorsHeaders(secureJsonResponse({ 
        error: 'Customer data not found' 
      }), origin);
    }
    
    const customerData = JSON.parse(customerDataStr);
    console.log('🔍 Found customer data:', customerData);
    
    // Create domain index using full domain (both with and without trailing slash)
    if (customerData.customDomain) {
      const domainKey1 = `domain:${customerData.customDomain}`;
      const domainKey2 = `domain:${customerData.customDomain.replace(/\/$/, '')}`;
      
      console.log('🔍 Creating domain keys:', { domainKey1, domainKey2 });
      await env.ACCESSIBILITY_AUTH.put(domainKey1, customerId);
      await env.ACCESSIBILITY_AUTH.put(domainKey2, customerId);
      
      return addSecurityAndCorsHeaders(secureJsonResponse({ 
        success: true,
        domainKeys: [domainKey1, domainKey2],
        customerId,
        customDomain: customerData.customDomain
      }), origin);
    }
    
    return addSecurityAndCorsHeaders(secureJsonResponse({ 
      error: 'No customDomain found in customer data' 
    }), origin);
    
  } catch (error) {
    console.error('Error in handleFixDomainIndex:', error);
    return addSecurityAndCorsHeaders(secureJsonResponse({ 
      error: 'Internal server error',
      details: String(error)
    }, 500), origin);
  }
}

// Debug function to check KV keys
async function handleDebugKVKeys(request, env) {
  const origin = request.headers.get('origin');
  
  try {
    const url = new URL(request.url);
    const searchTerm = url.searchParams.get('search') || '';
    
    // This is a simple debug function - in production you'd want proper KV listing
    return addSecurityAndCorsHeaders(secureJsonResponse({ 
      message: 'Debug KV keys check - use specific search terms',
      searchTerm,
      note: 'This endpoint is for debugging only'
    }), origin);
    
  } catch (error) {
    console.error('Error in handleDebugKVKeys:', error);
    return addSecurityAndCorsHeaders(secureJsonResponse({ 
      error: 'Internal server error',
      details: String(error)
    }, 500), origin);
  }
}

// Domain-based customer data lookup
async function handleCustomerDataByDomain(request, env) {
  const origin = request.headers.get('origin');
  
  try {
    const url = new URL(request.url);
    const domainParamRaw = url.searchParams.get('domain') || '';
    const host = normalizeHost(domainParamRaw);
    
    console.log('🔍 Domain lookup request:', { domainParam: domainParamRaw, normalizedHost: host, url: request.url });
    
    if (!host) {
      console.log('❌ No domain parameter provided');
      return addSecurityAndCorsHeaders(secureJsonResponse({}), origin);
    }
    // Staging sites are always allowed for widget access; do not hit KV for .webflow.io
    // But return a flag to indicate this is staging (not a real payment)
    if (/\.webflow\.io$/i.test(host)) {
      return addSecurityAndCorsHeaders(secureJsonResponse({
        isSubscribed: true,
        subscriptionStatus: 'active',
        paymentStatus: 'paid',
        isStagingDomain: true, // Flag to indicate this is staging, not real payment
        stripeSubscriptionId: null, // Explicitly no subscription ID
        subscriptionId: null
      }), origin);
    }
    
    // Try canonical keys only: host and www.host
    const hostNoWww = host.replace(/^www\./, '');
    const keysToTry = [`domain:${hostNoWww}`, `domain:www.${hostNoWww}`];
    console.log('🔍 Looking up domain keys:', keysToTry);
    let customerId = null;
    for (const k of keysToTry) {
      customerId = await env.ACCESSIBILITY_AUTH.get(k);
      if (customerId) { break; }
    }
    console.log('🔍 Found customer ID:', customerId);
    
    if (!customerId) {
      console.log('❌ No customer ID found for domain');
      return addSecurityAndCorsHeaders(secureJsonResponse({}), origin);
    }
    
    // Get customer data
    const customerKey = `customer:${customerId}`;
    console.log('🔍 Looking up customer key:', customerKey);
    
    const customerDataStr = await env.ACCESSIBILITY_AUTH.get(customerKey);
    let customerData = customerDataStr ? JSON.parse(customerDataStr) : {};
    
    console.log('✅ Found customer data:', customerData);

    // Enrich missing fields at read-time (no duplication, one-shot fill)
    let enriched = false;

    // Backfill customDomain from the requested domain if missing
    if (!customerData.customDomain && domainParamRaw) {
      customerData.customDomain = domainParamRaw;
      enriched = true;
    }

    // Backfill subscription fields from Stripe if missing
    if ((!customerData.stripeSubscriptionId || !customerData.planType || !customerData.validUntil) && customerId) {
      try {
        const subsRes = await fetch(`https://api.stripe.com/v1/subscriptions?customer=${customerId}&limit=1`, {
          headers: {
            'Authorization': `Bearer ${env.STRIPE_SECRET_KEY}`,
            'Content-Type': 'application/x-www-form-urlencoded'
          }
        });
        if (subsRes.ok) {
          const subs = await subsRes.json();
          if (subs.data && subs.data.length > 0) {
            const sub = subs.data[0];
            if (!customerData.stripeSubscriptionId) customerData.stripeSubscriptionId = sub.id;
            const price = sub.items?.data?.[0]?.price;
            if (!customerData.planType && price?.recurring?.interval) {
              customerData.planType = price.recurring.interval === 'year' ? 'annual' : 'monthly';
            }
            if (!customerData.validUntil && sub.current_period_end) {
              customerData.validUntil = new Date(sub.current_period_end * 1000).toISOString();
            }
            customerData.subscriptionStatus = sub.status === 'active' ? 'complete' : customerData.subscriptionStatus || 'incomplete';
            customerData.paymentStatus = sub.status === 'active' ? 'paid' : customerData.paymentStatus || 'unpaid';
            customerData.isSubscribed = sub.status === 'active' ? true : !!customerData.isSubscribed;
            enriched = true;
          }
        }
      } catch (e) {
        console.log('⚠️ Enrichment fetch error:', e);
      }
    }

    // Persist enrichment if any
    if (enriched) {
      customerData.lastUpdated = new Date().toISOString();
      await env.ACCESSIBILITY_AUTH.put(customerKey, JSON.stringify(customerData));
      console.log('✅ Enriched and saved customer data:', customerData);
    }

    const resp = secureJsonResponse(customerData);
    try { resp.headers.set('Cache-Control', 'no-store, no-cache, must-revalidate'); } catch {}
    return addSecurityAndCorsHeaders(resp, origin);
    
  } catch (error) {
    console.error('Error in handleCustomerDataByDomain:', error);
    return addSecurityAndCorsHeaders(secureJsonResponse({ 
      error: 'Internal server error' 
    }, 500), origin);
  }
}

// Create Stripe Checkout Session with metadata

async function handleCreateCheckoutSession(request, env) {
  const origin = request.headers.get('origin');
  
  try {
    const { siteId, planType, successUrl, cancelUrl } = await request.json();
    
    if (!siteId || !planType) {
      return addSecurityAndCorsHeaders(secureJsonResponse({ 
        error: 'Missing required parameters: siteId and planType' 
      }, 400), origin);
    }

    // Map plan types to your Stripe price IDs
    // You need to get the actual price IDs from your Stripe dashboard
    // For now, using the product IDs from your checkout links
    const priceId = planType === 'annual' 
      ? 'price_1QXXXXXX'  // Replace with your actual annual price ID from Stripe dashboard
      : 'price_1QXXXXXX'; // Replace with your actual monthly price ID from Stripe dashboard

    // Create checkout session
    const session = await fetch('https://api.stripe.com/v1/checkout/sessions', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${env.STRIPE_SECRET_KEY}`,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        'mode': 'subscription',
        'line_items[0][price]': priceId,
        'line_items[0][quantity]': '1',
        'success_url': successUrl,
        'cancel_url': cancelUrl,
        'metadata[siteId]': siteId,
        'metadata[planType]': planType,
        'subscription_data[metadata][siteId]': siteId,
        'subscription_data[metadata][planType]': planType,
        'customer_email': '', // Will be collected during checkout
      })
    });

    if (!session.ok) {
      const error = await session.text();
      return addSecurityAndCorsHeaders(secureJsonResponse({ 
        error: 'Failed to create checkout session', 
        details: error 
      }, 500), origin);
    }

    const sessionData = await session.json();
    
    return addSecurityAndCorsHeaders(secureJsonResponse({ 
      success: true, 
      url: sessionData.url,
      sessionId: sessionData.id 
    }, 200), origin);

  } catch (error) {
    return addSecurityAndCorsHeaders(secureJsonResponse({ 
      error: 'Internal server error', 
      message: error.message 
    }, 500), origin);
  }
}
