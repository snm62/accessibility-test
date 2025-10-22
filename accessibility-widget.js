import React, { useState, useEffect } from 'react';
import '../styles/payment.css';

// TypeScript declarations for global Stripe functions
declare global {
  interface Window {
    initializeExistingPaymentIntegration: () => void;
    stripeIntegration: {
      handlePurchaseNow: () => void;
      reSetupEventListeners: () => void;
    };
  }
}
const whitearrow = "data:image/svg+xml;utf8," + encodeURIComponent(`<svg xmlns="http://www.w3.org/2000/svg" width="14" height="15" viewBox="0 0 14 15" fill="none">
  <path d="M0.756 8.59012V6.62812H10.314L5.598 2.30812L6.948 0.940125L13.356 6.97012V8.23012L6.948 14.2601L5.58 12.8741L10.278 8.59012H0.756Z" fill="white"/>
</svg>`);

interface PaymentScreenProps {
  onBack: () => void;
  onNext: () => void;
  customizationData: any;
}

const PaymentScreen: React.FC<PaymentScreenProps> = ({ onBack, onNext, customizationData }) => {
  console.log('🔥 PaymentScreen: Component rendered');
  console.log('🔥 PaymentScreen: Props received:', { onBack, onNext, customizationData });
  
  const [isAnnual, setIsAnnual] = useState(true);
  const [isProcessing, setIsProcessing] = useState(false);
  const [showStripeForm, setShowStripeForm] = useState(false);
  const [paymentSuccess, setPaymentSuccess] = useState(false);
  const [subscriptionValidUntil, setSubscriptionValidUntil] = useState<string | null>(null);
  const [actualPlanType, setActualPlanType] = useState<'annual' | 'monthly' | null>(null);
  
  // No fallbacks - only use fresh data from server
  const [showCancelModal, setShowCancelModal] = useState(false);

  // Debug: Monitor actualPlanType changes
  useEffect(() => {
    console.log('🔥 PaymentScreen: actualPlanType changed to:', actualPlanType);
  }, [actualPlanType]);
  const [isCanceling, setIsCanceling] = useState(false);
  const [showDomainModal, setShowDomainModal] = useState(false);
  const [newDomain, setNewDomain] = useState('');
  const [isUpdatingDomain, setIsUpdatingDomain] = useState(false);
  const [domainValidationError, setDomainValidationError] = useState<string | null>(null);
  const [notification, setNotification] = useState<{type: 'success' | 'error' | 'info', message: string} | null>(null);

  // Helper function to show notifications
  const showNotification = (type: 'success' | 'error' | 'info', message: string) => {
    setNotification({ type, message });
    // Auto-hide after 5 seconds
    setTimeout(() => {
      setNotification(null);
    }, 5000);
  };

  // Domain validation function
  const validateDomain = (domain: string) => {
    // Remove protocol if present
    const cleanDomain = domain.replace(/^https?:\/\//, '').toLowerCase();
    
    // Basic format validation
    const domainRegex = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
    if (!domainRegex.test(cleanDomain)) {
      return {
        isValid: false,
        error: 'Please enter a valid domain format (e.g., yoursite.com)'
      };
    }
    
    // Block major commercial domains
    const blockedDomains = [
      'amazon.com', 'amazon.in', 'amazon.co.uk', 'amazon.ca', 'amazon.de', 'amazon.fr', 'amazon.it', 'amazon.es', 'amazon.com.au', 'amazon.co.jp',
      'flipkart.com', 'flipkart.in',
      'google.com', 'google.co.in', 'google.co.uk', 'google.ca', 'google.com.au',
      'facebook.com', 'instagram.com', 'twitter.com', 'linkedin.com', 'youtube.com',
      'microsoft.com', 'apple.com', 'netflix.com', 'spotify.com', 'uber.com',
      'airbnb.com', 'booking.com', 'expedia.com', 'tripadvisor.com',
      'ebay.com', 'etsy.com', 'shopify.com', 'walmart.com', 'target.com',
      'github.com', 'stackoverflow.com', 'reddit.com', 'wikipedia.org',
      'paypal.com', 'stripe.com', 'square.com', 'venmo.com',
      'dropbox.com', 'onedrive.com', 'icloud.com', 'gmail.com', 'outlook.com',
      'yahoo.com', 'hotmail.com', 'aol.com', 'protonmail.com',
      'zoom.us', 'teams.microsoft.com', 'slack.com', 'discord.com',
      'twitch.tv', 'tiktok.com', 'snapchat.com', 'pinterest.com',
      'medium.com', 'substack.com', 'wordpress.com', 'blogger.com',
      'tumblr.com', 'flickr.com', 'imgur.com', 'deviantart.com'
    ];
    
    // Check if domain is blocked
    for (const blockedDomain of blockedDomains) {
      if (cleanDomain === blockedDomain || cleanDomain.endsWith('.' + blockedDomain)) {
        return {
          isValid: false,
          error: 'This domain is not allowed. Please enter your own website domain.'
        };
      }
    }
    
    // Block common TLDs that are likely not user domains
    const suspiciousTlds = ['.tk', '.ml', '.ga', '.cf', '.co.nf'];
    for (const tld of suspiciousTlds) {
      if (cleanDomain.endsWith(tld)) {
        return {
          isValid: false,
          error: 'Please enter a professional domain name (avoid free domains)'
        };
      }
    }
    
    // Block localhost and IP addresses
    if (cleanDomain.includes('localhost') || cleanDomain.includes('127.0.0.1') || 
        cleanDomain.match(/^\d+\.\d+\.\d+\.\d+$/)) {
      return {
        isValid: false,
        error: 'Please enter a public domain name, not localhost or IP address'
      };
    }
    
    // Block subdomains of major platforms (but allow Webflow staging URLs)
    const blockedSubdomains = [
      'github.io', 'netlify.app', 'vercel.app', 'herokuapp.com', 'firebaseapp.com',
      'wordpress.com', 'blogspot.com', 'tumblr.com', 'wix.com', 'squarespace.com',
      'weebly.com', 'shopify.com', 'bigcommerce.com'
    ];
    
    // Allow Webflow staging URLs (they have specific patterns)
    const isWebflowStaging = cleanDomain.includes('.webflow.io') && 
      (cleanDomain.includes('-') || cleanDomain.match(/^[a-z0-9-]+\.webflow\.io$/));
    
    if (!isWebflowStaging) {
      for (const blockedSubdomain of blockedSubdomains) {
        if (cleanDomain.endsWith('.' + blockedSubdomain)) {
          return {
            isValid: false,
            error: 'Please enter your own custom domain, not a subdomain of a platform'
          };
        }
      }
    }
    
    // Require at least one dot (TLD)
    if (!cleanDomain.includes('.')) {
      return {
        isValid: false,
        error: 'Please enter a complete domain name with extension (e.g., yoursite.com)'
      };
    }
    
    // Check minimum length
    if (cleanDomain.length < 4) {
      return {
        isValid: false,
        error: 'Domain name is too short'
      };
    }
    
    return {
      isValid: true,
      error: null
    };
  };

  // Domain ownership verification function
  const verifyDomainOwnership = async (domain: string) => {
    try {
      // Get the current site info from Webflow
      if (typeof window !== 'undefined' && window.webflow && window.webflow.getSiteInfo) {
        const siteInfo = await window.webflow.getSiteInfo();
        console.log('🔥 Domain verification: Current site info:', siteInfo);
        
        if (!siteInfo || !siteInfo.url) {
          return {
            isValid: false,
            error: 'Unable to verify domain ownership. Please ensure you are logged into your Webflow account.'
          };
        }
        
        // Clean the domain for comparison
        const cleanDomain = domain.replace(/^https?:\/\//, '').toLowerCase();
        const currentSiteUrl = siteInfo.url.replace(/^https?:\/\//, '').toLowerCase();
        
        console.log('🔥 Domain verification: Comparing', cleanDomain, 'with', currentSiteUrl);
        
        // Check if the domain matches the current site exactly
        if (cleanDomain === currentSiteUrl) {
          return {
            isValid: true,
            error: null
          };
        }
        
        // Check if it's a subdomain of the current site
        if (cleanDomain.endsWith('.' + currentSiteUrl)) {
          return {
            isValid: true,
            error: null
          };
        }
        
        // Check if it's the same base domain with different subdomain
        const currentDomainParts = currentSiteUrl.split('.');
        const inputDomainParts = cleanDomain.split('.');
        
        if (currentDomainParts.length >= 2 && inputDomainParts.length >= 2) {
          const currentBaseDomain = currentDomainParts.slice(-2).join('.');
          const inputBaseDomain = inputDomainParts.slice(-2).join('.');
          
          if (currentBaseDomain === inputBaseDomain) {
            return {
              isValid: true,
              error: null
            };
          }
        }
        
        // Try to get additional site information if available
        try {
          // Check if there are other sites in the user's account
          if (window.webflow.getSites) {
            const sites = await window.webflow.getSites();
            console.log('🔥 Domain verification: All user sites:', sites);
            
            if (sites && Array.isArray(sites)) {
              for (const site of sites) {
                if (site.url) {
                  const siteUrl = site.url.replace(/^https?:\/\//, '').toLowerCase();
                  
                  // Check exact match
                  if (cleanDomain === siteUrl) {
                    return {
                      isValid: true,
                      error: null
                    };
                  }
                  
                  // Check subdomain match
                  if (cleanDomain.endsWith('.' + siteUrl)) {
                    return {
                      isValid: true,
                      error: null
                    };
                  }
                  
                  // Check base domain match
                  const siteDomainParts = siteUrl.split('.');
                  if (siteDomainParts.length >= 2) {
                    const siteBaseDomain = siteDomainParts.slice(-2).join('.');
                    const inputBaseDomain = inputDomainParts.slice(-2).join('.');
                    
                    if (siteBaseDomain === inputBaseDomain) {
                      return {
                        isValid: true,
                        error: null
                      };
                    }
                  }
                }
              }
            }
          }
        } catch (sitesError) {
          console.log('🔥 Domain verification: Could not get additional sites:', sitesError);
        }
        
        return {
          isValid: false,
          error: `This domain (${domain}) is not associated with your Webflow account. Please enter a domain that belongs to one of your Webflow sites.`
        };
      } else {
        return {
          isValid: false,
          error: 'Unable to verify domain ownership. Please ensure you are using this extension within Webflow Designer.'
        };
      }
    } catch (error) {
      console.error('🔥 Domain verification error:', error);
      return {
        isValid: false,
        error: 'Unable to verify domain ownership. Please try again or contact support.'
      };
    }
  };

  // Helper function to get siteId from various sources
  const getSiteId = async () => {
    // Debug: Log all sessionStorage keys
    console.log('🔥 PaymentScreen: All sessionStorage keys:', Object.keys(sessionStorage));
    console.log('🔥 PaymentScreen: All sessionStorage values:', Object.keys(sessionStorage).map(key => ({ key, value: sessionStorage.getItem(key) })));
    
    // Try multiple possible session storage keys for siteId
    let siteId = null;
    
    // First try the main auth key
    const userData = sessionStorage.getItem('accessbit-userinfo');
    console.log('🔥 PaymentScreen: accessbit-userinfo data:', userData);
    if (userData) {
      try {
        const parsed = JSON.parse(userData);
        siteId = parsed.siteId;
        console.log('🔥 PaymentScreen: Found siteId in accessbit-userinfo:', siteId);
      } catch (error) {
        console.log('🔥 PaymentScreen: Error parsing accessbit-userinfo:', error);
      }
    }
    
    // Fallback to currentSiteId
    if (!siteId) {
      siteId = sessionStorage.getItem('currentSiteId');
      console.log('🔥 PaymentScreen: Found siteId in currentSiteId:', siteId);
    }
    
    // Legacy fallbacks
    if (!siteId) {
      siteId = sessionStorage.getItem('contrastkit') || 
               sessionStorage.getItem('webflow_site_id') || 
               sessionStorage.getItem('siteId');
      console.log('🔥 PaymentScreen: Found siteId in legacy keys:', siteId);
    }
    
    // Try to get from Webflow API as last resort
    if (!siteId) {
      try {
        if (window.webflow && window.webflow.getSiteInfo) {
          const siteInfo = await window.webflow.getSiteInfo();
          if (siteInfo && siteInfo.siteId) {
            siteId = siteInfo.siteId;
            console.log('🔥 PaymentScreen: Found siteId from Webflow API:', siteId);
          }
        }
      } catch (error) {
        console.log('🔥 PaymentScreen: Error getting siteId from Webflow API:', error);
      }
    }
    
    console.log('🔥 PaymentScreen: Final siteId result:', siteId);
    return siteId;
  };

  // Debug current state
  console.log('🔥 PaymentScreen: Current state:', { 
    paymentSuccess, 
    subscriptionValidUntil, 
    showStripeForm 
  });

  // Check for payment success from URL parameters (for redirect methods)
  useEffect(() => {
    const urlParams = new URLSearchParams(window.location.search);
    const paymentIntent = urlParams.get('payment_intent');
    const paymentIntentClientSecret = urlParams.get('payment_intent_client_secret');
    const planType = urlParams.get('plan');
    
    if (paymentIntent && paymentIntentClientSecret) {
      console.log('🔥 PaymentScreen: Detected payment redirect, checking status');
      // If we have payment intent parameters, it means user was redirected back
      // We should show success screen since the webhook will handle the final status
      setPaymentSuccess(true);
    }
    
    // Set plan type from URL parameter if available
    if (planType && (planType === 'annual' || planType === 'monthly')) {
      console.log('🔥 PaymentScreen: Setting plan type from URL parameter:', planType);
      setActualPlanType(planType);
      setIsAnnual(planType === 'annual');
    }
  }, []);

  // Initialize Stripe integration when component mounts
  useEffect(() => {
    console.log('🔥 PaymentScreen: useEffect running, checking for Stripe integration');
    console.log('🔥 PaymentScreen: window object:', typeof window);
    console.log('🔥 PaymentScreen: window.initializeExistingPaymentIntegration:', typeof window.initializeExistingPaymentIntegration);
    
    // Populate domain field with actual site URL
    const populateDomainField = async () => {
      try {
        if (typeof window !== 'undefined' && window.webflow && window.webflow.getSiteInfo) {
          const siteInfo = await window.webflow.getSiteInfo();
          console.log('🔥 PaymentScreen: Site info:', siteInfo);
          
          if (siteInfo.url) {
            const domainInput = document.getElementById('domain-url') as HTMLInputElement;
            if (domainInput) {
              domainInput.value = siteInfo.url;
              console.log('🔥 PaymentScreen: Domain field populated with:', siteInfo.url);
            }
          }
        }
      } catch (error) {
        console.log('🔥 PaymentScreen: Could not get site info:', error);
      }
    };
    
    // Populate domain field after a short delay to ensure DOM is ready
    setTimeout(populateDomainField, 500);
    
    // Add event listeners for domain field to handle paste and input events
    const setupDomainFieldListeners = () => {
      const domainInput = document.getElementById('domain-url') as HTMLInputElement;
      if (domainInput) {
        // Handle paste events
        domainInput.addEventListener('paste', (e) => {
          setTimeout(() => {
            const value = domainInput.value;
            console.log('🔥 Domain field paste detected:', value);
            if (value && !value.includes('example.com')) {
              console.log('🔥 Valid domain pasted:', value);
            }
          }, 100);
        });
        
        // Handle input events
        domainInput.addEventListener('input', (e) => {
          const value = (e.target as HTMLInputElement).value;
          console.log('🔥 Domain field input detected:', value);
          if (value && !value.includes('example.com')) {
            console.log('🔥 Valid domain typed:', value);
          }
        });
        
        // Handle change events
        domainInput.addEventListener('change', (e) => {
          const value = (e.target as HTMLInputElement).value;
          console.log('🔥 Domain field change detected:', value);
        });
      }
    };
    
    // Set up domain field listeners after a delay
    setTimeout(setupDomainFieldListeners, 1000);
    
    // Wait a bit for scripts to load
    const timer = setTimeout(() => {
      console.log('🔥 PaymentScreen: Timeout reached, checking Stripe integration');
      if (typeof window !== 'undefined' && window.initializeExistingPaymentIntegration) {
        console.log('🔥 PaymentScreen: Stripe integration function found, calling it');
        window.initializeExistingPaymentIntegration();
      } else {
        console.log('🔥 PaymentScreen: Stripe integration function not found after timeout');
        console.log('🔥 PaymentScreen: Available window properties:', Object.keys(window).filter(key => key.includes('stripe') || key.includes('payment')));
      }
    }, 1000);
    
    return () => {
      console.log('🔥 PaymentScreen: useEffect cleanup');
      clearTimeout(timer);
    };
  }, []);

  // Clear any existing subscription data from localStorage on component mount
  useEffect(() => {
    // Clear all subscription-related localStorage data for security
    const keysToRemove = [];
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i);
      if (key && key.startsWith('subscription_')) {
        keysToRemove.push(key);
      }
    }
    keysToRemove.forEach(key => {
      console.log('🔥 PaymentScreen: Clearing old subscription data from localStorage:', key);
      localStorage.removeItem(key);
    });
  }, []);

  // Check for existing subscription status on component mount
  useEffect(() => {
    const checkExistingSubscription = async () => {
      try {
        const siteId = await getSiteId();
        
        console.log('🔥 PaymentScreen: Checking existing subscription for siteId:', siteId);
        
        if (!siteId) {
          console.log('🔥 PaymentScreen: No siteId found, skipping subscription check');
          return;
        }

        // Always fetch fresh data from server - no localStorage usage for security
        console.log('🔥 PaymentScreen: Fetching fresh subscription data from server (no localStorage for security)');
        
        // Clear any existing subscription data from localStorage for security
        const keysToRemove = [];
        for (let i = 0; i < localStorage.length; i++) {
          const key = localStorage.key(i);
          if (key && key.startsWith('subscription_')) {
            keysToRemove.push(key);
          }
        }
        keysToRemove.forEach(key => {
          console.log('🔥 PaymentScreen: Removing old subscription data from localStorage:', key);
          localStorage.removeItem(key);
        });

        // Always check subscription status from server first (don't trust localStorage)
        console.log('🔥 PaymentScreen: Checking subscription status from server');
        const response = await fetch(`https://accessibility-widget.web-8fb.workers.dev/api/accessibility/subscription-status`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ siteId })
        });
        
        if (response.ok) {
          const data = await response.json();
          console.log('🔥 PaymentScreen: Server response:', data);
          
          if (data.success && data.subscription && data.subscription.status === 'active') {
            // Get current period end from subscription details - handle both formats
            let endDate = null;
            
            // Try different sources for current_period_end
            if (data.subscription.details && data.subscription.details.current_period_end) {
              // Stripe returns seconds, convert to milliseconds
              endDate = new Date(data.subscription.details.current_period_end * 1000);
              console.log('🔥 PaymentScreen: Using current_period_end from details (seconds):', data.subscription.details.current_period_end);
            } else if (data.subscription.currentPeriodEnd) {
              // Check if it's already in milliseconds or seconds
              const periodEnd = data.subscription.currentPeriodEnd;
              if (typeof periodEnd === 'number') {
                // If it's a large number (milliseconds), use as is
                if (periodEnd > 1000000000000) {
                  endDate = new Date(periodEnd);
                  console.log('🔥 PaymentScreen: Using currentPeriodEnd (milliseconds):', periodEnd);
                } else {
                  // If it's a smaller number (seconds), convert to milliseconds
                  endDate = new Date(periodEnd * 1000);
                  console.log('🔥 PaymentScreen: Using currentPeriodEnd (seconds):', periodEnd);
                }
              } else {
                endDate = new Date(periodEnd);
                console.log('🔥 PaymentScreen: Using currentPeriodEnd (date string):', periodEnd);
              }
            }
            
            console.log('🔥 PaymentScreen: Calculated endDate:', endDate);
            console.log('🔥 PaymentScreen: ProductId from data:', data.subscription.productId || data.subscription.details?.metadata?.productId);
            
            if (endDate && !isNaN(endDate.getTime())) {
              const now = new Date().getTime();
              console.log('🔥 PaymentScreen: Checking validity - now:', now, 'endDate:', endDate.getTime());
              
              if (now < endDate.getTime()) {
                // Subscription is active and valid
                console.log('🔥 PaymentScreen: Active subscription found, showing success screen');
                setPaymentSuccess(true);
                setSubscriptionValidUntil(endDate.toLocaleDateString());
                
                // Determine plan type from server data only
                let planType = 'monthly'; // default
                let isAnnual = false;
                
                // Get plan type from server response
                const productId = data.subscription.productId || data.subscription.details?.metadata?.productId;
                if (productId) {
                  isAnnual = productId === 'prod_TEHrwLZdPcOsgq';
                  planType = isAnnual ? 'annual' : 'monthly';
                  console.log('🔥 PaymentScreen: Determined plan type from server productId:', productId, 'isAnnual:', isAnnual, 'planType:', planType);
                } else {
                  console.log('🔥 PaymentScreen: No productId found in server response, using default monthly');
                }
                
                // No localStorage storage for security - data is fetched fresh from server each time
                console.log('🔥 PaymentScreen: Subscription data processed (no localStorage for security)');
                
                // Set the actual plan type for display
                setActualPlanType(planType as 'annual' | 'monthly');
              } else {
                console.log('🔥 PaymentScreen: Subscription expired, not showing success screen');
                // No localStorage usage for security - data managed server-side
              }
            } else {
              console.log('🔥 PaymentScreen: No valid end date found, using fallback');
              // Determine fallback period based on productId and plan type from payment form
              const productId = data.subscription.productId || data.subscription.details?.metadata?.productId;
              
              // First try to get plan type from payment form
              let isAnnual = false;
              try {
                const paymentForm = document.getElementById('payment-form');
                if (paymentForm) {
                  const planTypeAttr = paymentForm.getAttribute('data-plan-type');
                  isAnnual = planTypeAttr === 'annual';
                  console.log('🔥 PaymentScreen: Got plan type from payment form:', planTypeAttr, 'isAnnual:', isAnnual);
                }
              } catch (e) {
                console.log('🔥 PaymentScreen: Could not get plan type from payment form, using productId fallback');
              }
              
              // Fallback to productId if payment form plan type not available
              if (!isAnnual && productId) {
                isAnnual = productId === 'prod_TEHrwLZdPcOsgq';
                console.log('🔥 PaymentScreen: Using productId fallback - productId:', productId, 'isAnnual:', isAnnual);
              }
              const fallbackDays = isAnnual ? 365 : 30; // 1 year for annual, 1 month for monthly
              const fallbackDate = new Date(Date.now() + fallbackDays * 24 * 60 * 60 * 1000);
              
              setPaymentSuccess(true);
              setSubscriptionValidUntil(fallbackDate.toLocaleDateString());
              
              // Set the actual plan type for display
              setActualPlanType(isAnnual ? 'annual' : 'monthly');
              
              // No localStorage storage for security - data is fetched fresh from server each time
              console.log('🔥 PaymentScreen: Fallback subscription data processed (no localStorage for security)');
            }
          } else {
            console.log('🔥 PaymentScreen: No active subscription found');
          }
        } else {
          console.log('🔥 PaymentScreen: Failed to check subscription status:', response.status);
          // No localStorage fallback for security - always use server data
          console.log('🔥 PaymentScreen: Server request failed, no fallback to localStorage for security');
        }
      } catch (error) {
        console.error('Failed to check existing subscription:', error);
      }
    };

    checkExistingSubscription();
  }, []);

  // Listen for payment success events
  useEffect(() => {
    const handlePaymentSuccess = async (event: CustomEvent) => {
      console.log('🔥 PaymentScreen: Payment success event received:', event.detail);
      console.log('🔥 PaymentScreen: Setting paymentSuccess to true');
      setPaymentSuccess(true);
      setShowStripeForm(false);
      
      // Get siteId first
      const siteId = await getSiteId();
      if (!siteId) {
        console.log('🔥 PaymentScreen: No siteId found for storing subscription data');
        return;
      }
      
      // Try to get subscription details from multiple sources
      let subscriptionDetails = null;
      let subscriptionId = null;
      let eventPlanType = null;
      
      // Get plan type from event first
      if (event.detail.planType) {
        eventPlanType = event.detail.planType;
        console.log('🔥 PaymentScreen: Found plan type in event:', eventPlanType);
      } else {
        console.log('🔥 PaymentScreen: No plan type found in event detail:', event.detail);
      }
      
      // Check if we have subscriptionDetails in the event
      if (event.detail.subscriptionDetails) {
        subscriptionDetails = event.detail.subscriptionDetails;
        subscriptionId = event.detail.subscriptionId;
        console.log('🔥 PaymentScreen: Found subscriptionDetails in event:', subscriptionDetails);
        
        // Try to get plan type from subscription details metadata
        if (!eventPlanType && subscriptionDetails.metadata && subscriptionDetails.metadata.productId) {
          const productId = subscriptionDetails.metadata.productId;
          eventPlanType = productId === 'prod_TEHrwLZdPcOsgq' ? 'annual' : 'monthly';
          console.log('🔥 PaymentScreen: Determined plan type from subscription metadata:', eventPlanType, 'productId:', productId);
        }
        
        // Try to determine plan type from subscription details
        if (subscriptionDetails.details && subscriptionDetails.details.items && subscriptionDetails.details.items.data && subscriptionDetails.details.items.data.length > 0) {
          const item = subscriptionDetails.details.items.data[0];
          const productId = item.price?.product;
          console.log('🔥 PaymentScreen: Found product ID in subscription details:', productId);
          
          // Store the product ID for plan type determination
          if (productId) {
            // First try to get plan type from payment form
            let isAnnual = false;
            try {
              const paymentForm = document.getElementById('payment-form');
              if (paymentForm) {
                const planTypeAttr = paymentForm.getAttribute('data-plan-type');
                isAnnual = planTypeAttr === 'annual';
                console.log('🔥 PaymentScreen: Got plan type from payment form:', planTypeAttr, 'isAnnual:', isAnnual);
              }
            } catch (e) {
              console.log('🔥 PaymentScreen: Could not get plan type from payment form, using productId fallback');
            }
            
            // Fallback to productId if payment form plan type not available
            if (!isAnnual) {
              isAnnual = productId === 'prod_TEHrwLZdPcOsgq';
              console.log('🔥 PaymentScreen: Using productId fallback - productId:', productId, 'isAnnual:', isAnnual);
            }
            console.log('🔥 PaymentScreen: Determined plan type from subscription details - isAnnual:', isAnnual);
            
            // Update the subscription details with plan type info
            subscriptionDetails.planType = isAnnual ? 'annual' : 'monthly';
            subscriptionDetails.productId = productId;
          }
        }
      } else {
        // If no subscriptionDetails, try to fetch from server
        console.log('🔥 PaymentScreen: No subscriptionDetails in event, fetching from server');
        try {
          const response = await fetch(`https://accessibility-widget.web-8fb.workers.dev/api/accessibility/subscription-status`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ siteId })
          });
          
          if (response.ok) {
            const data = await response.json();
            console.log('🔥 PaymentScreen: Server response for subscription details:', data);
            
            if (data.success && data.subscription) {
              subscriptionDetails = data.subscription;
              subscriptionId = data.subscription.id;
            }
          }
        } catch (error) {
          console.error('🔥 PaymentScreen: Failed to fetch subscription details:', error);
        }
      }
      
      // Set subscription validity if we have details
      if (subscriptionDetails) {
        let endDate = null;
        
        // Try to get current_period_end from different sources
        if (subscriptionDetails.details && subscriptionDetails.details.current_period_end) {
          // Stripe returns seconds, convert to milliseconds
          endDate = new Date(subscriptionDetails.details.current_period_end * 1000);
          console.log('🔥 PaymentScreen: Using current_period_end from details (seconds):', subscriptionDetails.details.current_period_end);
        } else if (subscriptionDetails.currentPeriodEnd) {
          // Check if it's already in milliseconds or seconds
          const periodEnd = subscriptionDetails.currentPeriodEnd;
          if (typeof periodEnd === 'number') {
            if (periodEnd > 1000000000000) {
              endDate = new Date(periodEnd);
              console.log('🔥 PaymentScreen: Using currentPeriodEnd (milliseconds):', periodEnd);
            } else {
              endDate = new Date(periodEnd * 1000);
              console.log('🔥 PaymentScreen: Using currentPeriodEnd (seconds):', periodEnd);
            }
          } else {
            endDate = new Date(periodEnd);
            console.log('🔥 PaymentScreen: Using currentPeriodEnd (date string):', periodEnd);
          }
        } else if (subscriptionDetails.current_period_end) {
          // Stripe returns seconds, convert to milliseconds
          endDate = new Date(subscriptionDetails.current_period_end * 1000);
          console.log('🔥 PaymentScreen: Using current_period_end from subscription (seconds):', subscriptionDetails.current_period_end);
        }
        
        if (endDate) {
          setSubscriptionValidUntil(endDate.toLocaleDateString());
          console.log('🔥 PaymentScreen: Set subscription valid until:', endDate.toLocaleDateString());
          
          // Determine plan type from subscription details or payment form
          let planTypeForDisplay = 'monthly'; // default
          try {
            const paymentForm = document.getElementById('payment-form');
            if (paymentForm) {
              const planTypeAttr = paymentForm.getAttribute('data-plan-type');
              planTypeForDisplay = planTypeAttr || 'monthly';
              console.log('🔥 PaymentScreen: Got plan type from payment form for display:', planTypeForDisplay);
            }
          } catch (e) {
            console.log('🔥 PaymentScreen: Could not get plan type from payment form for display');
          }
          
          // Set the actual plan type for display
          setActualPlanType(planTypeForDisplay as 'annual' | 'monthly');
          
          // Store subscription data for persistence
          const subscriptionData = {
            status: subscriptionDetails.status || 'active',
            validUntil: endDate.getTime(),
            subscriptionId: subscriptionId
          };
          // No localStorage storage for security - data is fetched fresh from server each time
          console.log('🔥 PaymentScreen: Payment success data processed (no localStorage for security)');
        } else {
          console.log('🔥 PaymentScreen: No valid end date found, using fallback');
          // Determine fallback period based on productId or plan type
          const productId = subscriptionDetails?.metadata?.productId || subscriptionDetails?.productId || subscriptionDetails?.productId;
          const planType = subscriptionDetails?.planType;
          
          // First try to get plan type from payment form
          let isAnnual = false;
          try {
            const paymentForm = document.getElementById('payment-form');
            if (paymentForm) {
              const planTypeAttr = paymentForm.getAttribute('data-plan-type');
              isAnnual = planTypeAttr === 'annual';
              console.log('🔥 PaymentScreen: Got plan type from payment form:', planTypeAttr, 'isAnnual:', isAnnual);
            }
          } catch (e) {
            console.log('🔥 PaymentScreen: Could not get plan type from payment form, using fallback');
          }
          
          // Fallback to productId or planType if payment form plan type not available
          if (!isAnnual) {
            isAnnual = productId === 'prod_TEHrwLZdPcOsgq' || planType === 'annual';
            console.log('🔥 PaymentScreen: Using fallback - productId:', productId, 'planType:', planType, 'isAnnual:', isAnnual);
          }
          const fallbackDays = isAnnual ? 365 : 30; // 1 year for annual, 1 month for monthly
          const fallbackDate = new Date(Date.now() + fallbackDays * 24 * 60 * 60 * 1000);
          setSubscriptionValidUntil(fallbackDate.toLocaleDateString());
          
          const subscriptionData = {
            status: 'active',
            validUntil: fallbackDate.getTime(),
            subscriptionId: subscriptionId || 'unknown',
            fallback: true, // Mark as fallback
            isAnnual: isAnnual, // Store the plan type
            productId: productId, // Store the product ID for future reference
            planType: planType // Store the plan type
          };
          // No localStorage storage for security - data is fetched fresh from server each time
          console.log('🔥 PaymentScreen: Payment success fallback data processed (no localStorage for security)');
        }
      } else {
        console.log('🔥 PaymentScreen: No subscription details available, using fallback');
        
        // Try to get the plan type from the payment form that was just used
        let paymentFormPlanType = null;
        try {
          const paymentForm = document.getElementById('payment-form');
          if (paymentForm) {
            const planTypeAttr = paymentForm.getAttribute('data-plan-type');
            paymentFormPlanType = planTypeAttr;
            console.log('🔥 PaymentScreen: Found plan type from payment form:', paymentFormPlanType);
            console.log('🔥 PaymentScreen: Payment form element:', paymentForm);
            console.log('🔥 PaymentScreen: All data attributes on payment form:', Array.from(paymentForm.attributes).map(attr => `${attr.name}="${attr.value}"`));
          } else {
            console.log('🔥 PaymentScreen: Payment form element not found');
            }
          } catch (e) {
          console.log('🔥 PaymentScreen: Could not get plan type from payment form:', e);
        }
        
        // Use the actual plan type from the event, payment form, or fall back to current state
        // Priority: eventPlanType > paymentFormPlanType > component state
        const currentPlanIsAnnual = eventPlanType ? eventPlanType === 'annual' : 
                                   paymentFormPlanType ? paymentFormPlanType === 'annual' : 
                                   isAnnual;
        console.log('🔥 PaymentScreen: Plan type determination - eventPlanType:', eventPlanType, 'paymentFormPlanType:', paymentFormPlanType, 'component isAnnual:', isAnnual, 'final currentPlanIsAnnual:', currentPlanIsAnnual);
        
        // Additional validation: if we have a plan type from the event, use it as the source of truth
        if (eventPlanType) {
          console.log('🔥 PaymentScreen: Using event plan type as source of truth:', eventPlanType);
        } else if (paymentFormPlanType) {
          console.log('🔥 PaymentScreen: Using payment form plan type as source of truth:', paymentFormPlanType);
        } else {
          console.log('🔥 PaymentScreen: WARNING - No plan type found in event or payment form, using component state:', isAnnual);
        }
        
        // Set the actual plan type for display
        const finalPlanType = currentPlanIsAnnual ? 'annual' : 'monthly';
        setActualPlanType(finalPlanType);
        console.log('🔥 PaymentScreen: Setting actualPlanType to:', finalPlanType, 'based on currentPlanIsAnnual:', currentPlanIsAnnual);
        
        // Don't set fallback date - wait for server response
        console.log('🔥 PaymentScreen: Waiting for server response to get actual valid until date');
      }
      
      // Force a refresh of the subscription status to ensure UI is updated with correct data
      console.log('🔥 PaymentScreen: Forcing subscription status refresh after payment success');
      
      // Immediate refresh attempt
      const immediateRefresh = async () => {
        try {
          const response = await fetch(`https://accessibility-widget.web-8fb.workers.dev/api/accessibility/subscription-status`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ siteId })
          });
          
          if (response.ok) {
            const data = await response.json();
            console.log('🔥 PaymentScreen: Immediate refresh response:', data);
            
            if (data.success && data.subscription && data.subscription.status === 'active') {
              let endDate = null;
              
              if (data.subscription.details && data.subscription.details.current_period_end) {
                endDate = new Date(data.subscription.details.current_period_end * 1000);
                console.log('🔥 PaymentScreen: Immediate refresh - Using current_period_end from details:', data.subscription.details.current_period_end);
                console.log('🔥 PaymentScreen: Immediate refresh - Calculated endDate:', endDate);
                console.log('🔥 PaymentScreen: Immediate refresh - EndDate timestamp:', endDate.getTime());
                console.log('🔥 PaymentScreen: Immediate refresh - Current time:', new Date().getTime());
                console.log('🔥 PaymentScreen: Immediate refresh - Time difference (days):', (endDate.getTime() - new Date().getTime()) / (1000 * 60 * 60 * 24));
              } else if (data.subscription.currentPeriodEnd) {
                const periodEnd = data.subscription.currentPeriodEnd;
                if (periodEnd > 1000000000000) {
                  endDate = new Date(periodEnd);
                } else {
                  endDate = new Date(periodEnd * 1000);
                }
                console.log('🔥 PaymentScreen: Immediate refresh - Using currentPeriodEnd:', periodEnd);
              } else if (data.subscription.current_period_end) {
                endDate = new Date(data.subscription.current_period_end * 1000);
                console.log('🔥 PaymentScreen: Immediate refresh - Using current_period_end:', data.subscription.current_period_end);
                console.log('🔥 PaymentScreen: Immediate refresh - Calculated endDate:', endDate);
                console.log('🔥 PaymentScreen: Immediate refresh - EndDate timestamp:', endDate.getTime());
                console.log('🔥 PaymentScreen: Immediate refresh - Current time:', new Date().getTime());
                console.log('🔥 PaymentScreen: Immediate refresh - Time difference (days):', (endDate.getTime() - new Date().getTime()) / (1000 * 60 * 60 * 24));
              }
              
              if (endDate) {
                setSubscriptionValidUntil(endDate.toLocaleDateString());
                console.log('🔥 PaymentScreen: Immediate refresh - Updated subscription valid until:', endDate.toLocaleDateString());
                
                // Determine plan type from server response metadata
                let serverPlanType = 'monthly'; // default
                if (data.subscription.details && data.subscription.details.metadata && data.subscription.details.metadata.productId) {
                  const productId = data.subscription.details.metadata.productId;
                  serverPlanType = productId === 'prod_TEHrwLZdPcOsgq' ? 'annual' : 'monthly';
                  console.log('🔥 PaymentScreen: Immediate refresh - Determined plan type from server metadata:', serverPlanType, 'productId:', productId);
                }
                
                // Set the actual plan type for display
                setActualPlanType(serverPlanType as 'annual' | 'monthly');
                console.log('🔥 PaymentScreen: Immediate refresh - Set actualPlanType to:', serverPlanType);
                
                const subscriptionData = {
                  status: data.subscription.status,
                  validUntil: endDate.getTime(),
                  subscriptionId: data.subscription.id,
                  refreshed: true,
                  planType: serverPlanType,
                  isAnnual: serverPlanType === 'annual'
                };
                // No localStorage storage for security - data is fetched fresh from server each time
                console.log('🔥 PaymentScreen: Immediate refresh - Updated with server data (no localStorage for security)');
                return; // Exit early if we got valid data
              }
            }
          }
        } catch (error) {
          console.error('🔥 PaymentScreen: Immediate refresh failed:', error);
        }
      };
      
      // Try immediate refresh first
      await immediateRefresh();
      
      // If immediate refresh didn't work, try again after delay
      setTimeout(async () => {
        try {
          const response = await fetch(`https://accessibility-widget.web-8fb.workers.dev/api/accessibility/subscription-status`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ siteId })
          });
          
          if (response.ok) {
            const data = await response.json();
            console.log('🔥 PaymentScreen: Refresh response after payment success:', data);
            
            if (data.success && data.subscription && data.subscription.status === 'active') {
              // Update the subscription validity with fresh data from server
              let endDate = null;
              
              if (data.subscription.details && data.subscription.details.current_period_end) {
                endDate = new Date(data.subscription.details.current_period_end * 1000);
                console.log('🔥 PaymentScreen: Refresh - Using current_period_end from details:', data.subscription.details.current_period_end);
              } else if (data.subscription.currentPeriodEnd) {
                const periodEnd = data.subscription.currentPeriodEnd;
                if (periodEnd > 1000000000000) {
                  endDate = new Date(periodEnd);
                } else {
                  endDate = new Date(periodEnd * 1000);
                }
                console.log('🔥 PaymentScreen: Refresh - Using currentPeriodEnd:', periodEnd);
              } else if (data.subscription.current_period_end) {
                endDate = new Date(data.subscription.current_period_end * 1000);
                console.log('🔥 PaymentScreen: Refresh - Using current_period_end:', data.subscription.current_period_end);
              }
              
              if (endDate) {
                setSubscriptionValidUntil(endDate.toLocaleDateString());
                console.log('🔥 PaymentScreen: Refresh - Updated subscription valid until:', endDate.toLocaleDateString());
                
                // Update localStorage with fresh data from server
                const subscriptionData = {
                  status: data.subscription.status,
                  validUntil: endDate.getTime(),
                  subscriptionId: data.subscription.id,
                  refreshed: true // Mark as refreshed from server
                };
                // No localStorage storage for security - data is fetched fresh from server each time
                console.log('🔥 PaymentScreen: Refresh - Updated with server data (no localStorage for security)');
              }
            }
          }
        } catch (error) {
          console.error('🔥 PaymentScreen: Failed to refresh subscription status after payment success:', error);
        }
      }, 2000); // Wait 2 seconds for server to process the payment and webhook
    };

    console.log('🔥 PaymentScreen: Adding stripe-payment-success event listener');
    window.addEventListener('stripe-payment-success', handlePaymentSuccess as EventListener);
    
    return () => {
      console.log('🔥 PaymentScreen: Removing stripe-payment-success event listener');
      window.removeEventListener('stripe-payment-success', handlePaymentSuccess as EventListener);
    };
  }, []);

  // Periodic check for subscription validity
  useEffect(() => {
    if (paymentSuccess) {
      const checkValidity = async () => {
        const siteId = await getSiteId();
        
        if (!siteId) return;

        // No localStorage usage for security - always fetch fresh data from server
        console.log('🔥 PaymentScreen: Subscription expiration check - fetching fresh data from server');
      };

      // Check immediately
      checkValidity();
      
      // Check every minute
      const interval = setInterval(checkValidity, 60000);
      
      return () => clearInterval(interval);
    }
  }, [paymentSuccess]);

  const handlePurchaseNow = () => {
    console.log('🔥 Purchase Now clicked - showing Stripe form');
    console.log('🔥 PaymentScreen: showStripeForm state:', showStripeForm);
    
    // Ensure actualPlanType is set based on current isAnnual state
    if (!actualPlanType) {
      const planType = isAnnual ? 'annual' : 'monthly';
      setActualPlanType(planType);
      console.log('🔥 PaymentScreen: Setting actualPlanType to:', planType, 'based on isAnnual:', isAnnual);
    }
    
    setShowStripeForm(true);
  };

  // After the Stripe form is shown, wait for DOM to paint, then initialize
  useEffect(() => {
    if (!showStripeForm) return;
    if (typeof window === 'undefined') return;
    // Lock background scroll while full-screen Stripe is open
    const prevOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    // wait until the #payment-element exists in DOM
    requestAnimationFrame(() => {
      const target = document.querySelector('#payment-element');
      if (target && window.stripeIntegration) {
        console.log('PaymentScreen: Mounting Stripe on #payment-element');
        window.stripeIntegration.handlePurchaseNow();
        // Re-setup event listeners now that the form is rendered
        setTimeout(() => {
          if (window.stripeIntegration && window.stripeIntegration.reSetupEventListeners) {
            window.stripeIntegration.reSetupEventListeners();
          }
        }, 100);
      } else {
        console.log('PaymentScreen: payment-element not ready or integration missing');
        // try again shortly if needed
        setTimeout(() => {
          const t2 = document.querySelector('#payment-element');
          if (t2 && window.stripeIntegration) {
            console.log('PaymentScreen: Retrying Stripe mount');
            window.stripeIntegration.handlePurchaseNow();
            // Re-setup event listeners after retry
            setTimeout(() => {
              if (window.stripeIntegration && window.stripeIntegration.reSetupEventListeners) {
                window.stripeIntegration.reSetupEventListeners();
              }
            }, 100);
          }
        }, 100);
      }
    });
    return () => {
      // restore scroll when effect cleans up
      document.body.style.overflow = prevOverflow;
    };
  }, [showStripeForm]);

  // Cleanup when exiting Stripe mode: unmount Stripe element
  useEffect(() => {
    if (!showStripeForm && typeof window !== 'undefined' && window.stripeIntegration) {
      try {
        if (typeof (window as any).stripeIntegration.unmount === 'function') {
          (window as any).stripeIntegration.unmount();
        }
      } catch (e) {
        console.warn('Stripe cleanup warning:', e);
      }
    }
  }, [showStripeForm]);

  // Listen for custom success/error events from integration to show in-app UI
  useEffect(() => {
    function onSuccess(e: any) {
      // Replace with your in-app toast/notification; for now, minimal banner
      const msg = e?.detail?.message || 'Payment successful';
      console.log(':white_tick: Stripe success:', msg);
      // Close Stripe view and show success screen
      setShowStripeForm(false);
      setPaymentSuccess(true);
    }
    function onError(e: any) {
      const msg = e?.detail?.message || 'Payment failed';
      console.error(':x: Stripe error:', msg);
      // You can surface a toast here; keeping console for brevity
    }
    // Add event listeners for payment processing states
    function onPaymentStart() {
      console.log('🔥 PaymentScreen: Payment processing started');
      setIsProcessing(true);
    }
    
    function onPaymentEnd() {
      console.log('🔥 PaymentScreen: Payment processing ended');
      setIsProcessing(false);
    }
    
    window.addEventListener('stripe-payment-success', onSuccess as EventListener);
    window.addEventListener('stripe-payment-error', onError as EventListener);
    window.addEventListener('stripe-payment-start', onPaymentStart as EventListener);
    window.addEventListener('stripe-payment-end', onPaymentEnd as EventListener);
    
    return () => {
      window.removeEventListener('stripe-payment-success', onSuccess as EventListener);
      window.removeEventListener('stripe-payment-error', onError as EventListener);
      window.removeEventListener('stripe-payment-start', onPaymentStart as EventListener);
      window.removeEventListener('stripe-payment-end', onPaymentEnd as EventListener);
    };
  }, []);

  const handlePayment = async () => {
    // When Stripe form is visible, submit should be handled by Stripe
    if (showStripeForm) {
      const form = document.getElementById('payment-form');
      if (form) {
        form.dispatchEvent(new Event('submit'));
        return;
      }
    }
    // Fallback: original next action (kept if no Stripe shown)
    setIsProcessing(true);
    try {
      await new Promise(resolve => setTimeout(resolve, 800));
      onNext();
    } catch (error) {
      console.error('Payment failed:', error);
    } finally {
      setIsProcessing(false);
    }
  };

  const handleBack = () => {
    console.log('Payment: Going back to customization');
    onBack();
  };

  const handleSuccessNext = () => {
    console.log('Payment: Moving to next step after success');
    onNext();
  };


  const handleEditDomain = () => {
    console.log('Payment: Opening domain change modal');
    setShowDomainModal(true);
  };

  const handleCancelSubscription = () => {
    console.log('Payment: Opening cancel subscription modal');
    setShowCancelModal(true);
  };

  const handleConfirmCancel = async () => {
    setIsCanceling(true);
    try {
      // Get siteId from session storage
      const siteId = await getSiteId();
      console.log('🔥 PaymentScreen: Cancellation - siteId found:', siteId);
      
      if (!siteId) {
        showNotification('error', 'Unable to find site ID. Please refresh and try again.');
        return;
      }

      // Simple approach: use siteId to cancel subscription directly
      console.log('🔥 PaymentScreen: Canceling subscription for siteId:', siteId);
      
      // Calculate if cancellation date is close to billing period end
      const now = new Date();
      // For simplicity, assume 30 days from now as fallback
      const currentPeriodEnd = new Date(now.getTime() + (30 * 24 * 60 * 60 * 1000));
      const daysUntilPeriodEnd = Math.ceil((currentPeriodEnd.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));
      
      // If less than 7 days until period end, cancel at period end, otherwise cancel immediately
      const cancelAtPeriodEnd = daysUntilPeriodEnd <= 7;
      
      console.log(`🔥 PaymentScreen: Cancellation logic - Days until period end: ${daysUntilPeriodEnd}, Cancel at period end: ${cancelAtPeriodEnd}`);

      const cancelPayload = { 
        siteId,
        cancelAtPeriodEnd: cancelAtPeriodEnd
      };
      console.log('🔥 PaymentScreen: Cancel payload:', cancelPayload);

      const response = await fetch('https://accessibility-widget.web-8fb.workers.dev/api/accessibility/cancel-subscription', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(cancelPayload)
      });

      console.log('🔥 PaymentScreen: Cancel response status:', response.status, response.ok);

      if (response.ok) {
        const result = await response.json();
        console.log('🔥 PaymentScreen: Cancel success result:', result);
        
        if (cancelAtPeriodEnd) {
          showNotification('success', `Subscription canceled successfully. Your access will continue until ${new Date(result.subscription.current_period_end * 1000).toLocaleDateString()}.`);
        } else {
          showNotification('info', 'Subscription canceled immediately. Your access has ended.');
        }
        
        setPaymentSuccess(false);
        setShowStripeForm(false);
        setShowCancelModal(false);
        
        // No localStorage usage for security - data is managed server-side
        console.log('🔥 PaymentScreen: Subscription canceled - data managed server-side');
      } else {
        const error = await response.json();
        console.log('🔥 PaymentScreen: Cancel error response:', error);
        showNotification('error', `Failed to cancel subscription: ${error.error || 'Unknown error'}`);
      }
    } catch (error) {
      console.error('Cancel subscription error:', error);
      showNotification('error', 'Failed to cancel subscription. Please try again.');
    } finally {
      setIsCanceling(false);
    }
  };

  const handleCloseCancelModal = () => {
    setShowCancelModal(false);
  };

  const handleUpdateDomain = async () => {
    if (!newDomain.trim()) {
      showNotification('error', 'Please enter a domain URL');
      return;
    }

    setIsUpdatingDomain(true);
    try {
      const siteId = await getSiteId();
      if (!siteId) {
        showNotification('error', 'Unable to find site ID. Please refresh and try again.');
        return;
      }

      // Get subscription ID from server - no localStorage for security
      let subscriptionId = null;
      console.log('🔥 PaymentScreen: Fetching subscription ID from server for domain update');

      if (!subscriptionId) {
        // Try to get from server
        const response = await fetch(`https://accessibility-widget.web-8fb.workers.dev/api/accessibility/subscription-status`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ siteId })
        });
        
        if (response.ok) {
          const data = await response.json();
          subscriptionId = data.subscription?.id;
        }
      }

      if (!subscriptionId) {
        showNotification('error', 'Unable to find subscription ID. Please refresh and try again.');
        return;
      }

      // Update subscription metadata
      const updateResponse = await fetch('https://accessibility-widget.web-8fb.workers.dev/api/accessibility/update-subscription-metadata', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          siteId,
          subscriptionId,
          metadata: {
            domain: newDomain.trim()
          }
        })
      });

      if (updateResponse.ok) {
        const result = await updateResponse.json();
        console.log('Domain updated successfully:', result);
        
        // Update localStorage with new domain
        // No localStorage usage for security - domain is updated server-side
        console.log('🔥 PaymentScreen: Domain updated server-side (no localStorage for security)');
        
        showNotification('success', 'Domain updated successfully!');
        setShowDomainModal(false);
        setNewDomain('');
      } else {
        const error = await updateResponse.json();
        console.error('Failed to update domain:', error);
        showNotification('error', `Failed to update domain: ${error.error || 'Unknown error'}`);
      }
    } catch (error) {
      console.error('Domain update error:', error);
      showNotification('error', 'Failed to update domain. Please try again.');
    } finally {
      setIsUpdatingDomain(false);
    }
  };

  const handleCloseDomainModal = () => {
    setShowDomainModal(false);
    setNewDomain('');
    setDomainValidationError(null);
  };

  const handleDomainInputChange = (value: string) => {
    setNewDomain(value);
    setDomainValidationError(null);
  };

  // When Stripe form is showing, render a full-screen scrollable view
  if (showStripeForm) {
    return (
      <div
        className="payment-screen"
        style={{
          position: 'fixed',
          inset: 0,
          zIndex: 1000,
          display: 'flex',
          flexDirection: 'column',
          width: '100%',
          height: '100vh',
          overflow: 'hidden',
          background: 'var(--ck-bg, #0b0f1a)'
        }}
      >
        <div className="payment-header">
          <div className="app-name"></div>
          <div className="header-buttons">
            <button className="back-btn" onClick={() => setShowStripeForm(false)} disabled={isProcessing}>
              <img src={whitearrow} alt="" style={{ transform: 'rotate(180deg)' }} /> Back to Pricing
            </button>
          </div>
        </div>

        <div style={{ padding: '5px 20px', overflowY: 'auto', flex: 1, minHeight: 0 }}>
          <style>{`
            /* Stripe Elements styling */
            .StripeElement {
              height: 40px !important;
              /* padding: 10px 14px !important; */
              border: 1px solid #e6e6e6 !important;
              border-radius: 4px !important;
              background-color: white !important;
              color: #333333 !important;
              font-size: 16px !important;
              box-shadow: 0px 1px 3px rgba(50, 50, 93, 0.07) !important;
              transition: box-shadow 150ms ease, border-color 150ms ease !important;
              box-sizing: border-box !important;
            }
            
            .StripeElement--focus {
              border-color: #0570de !important;
              box-shadow: 0 0 0 1px #0570de !important;
            }
            
            .StripeElement--invalid {
              border-color: #df1b41 !important;
            }
            
            /* Link Authentication Element styling */
            #link-authentication-element .StripeElement {
              height: 40px !important;
            }
            
            /* Payment Element styling */
            #payment-element .StripeElement {
              height: 40px !important;
            }
            
            /* Ensure only input fields have white background, not labels */
            input[type="email"], 
            input[type="text"], 
            input[type="tel"] {
              height: 40px !important;
              background-color: #ffffff00 !important;
              color: #fff !important;
              border: 1px solid #ffffff !important;
              box-shadow: 0px 1px 3px rgba(50, 50, 93, 0.07) !important;
              box-sizing: border-box !important;
            }
            
            /* Domain URL field - force transparent background */
            input[type="url"] {
              height: 40px !important;
              background-color: transparent !important;
              background: transparent !important;
              color: #ffffff !important;
              border: 1px solid #e6e6e6 !important;
              box-shadow: 0px 1px 3px rgba(50, 50, 93, 0.07) !important;
              box-sizing: border-box !important;
            }
            
            /* Override browser autofill and focus states for domain URL */
            input[type="url"]:focus,
            input[type="url"]:active,
            input[type="url"]:hover,
            input[type="url"]:autofill,
            input[type="url"]:-webkit-autofill,
            input[type="url"]:-webkit-autofill:hover,
            input[type="url"]:-webkit-autofill:focus,
            input[type="url"]:-webkit-autofill:active {
              background-color: transparent !important;
              background: transparent !important;
              color: #ffffff !important;
              -webkit-box-shadow: 0 0 0 30px transparent inset !important;
              box-shadow: 0px 1px 3px rgba(50, 50, 93, 0.07) !important;
            }
            
            /* Ultra-aggressive override for domain URL field by ID */
            #domain-url,
            #domain-url:focus,
            #domain-url:active,
            #domain-url:hover,
            #domain-url:autofill,
            #domain-url:-webkit-autofill,
            #domain-url:-webkit-autofill:hover,
            #domain-url:-webkit-autofill:focus,
            #domain-url:-webkit-autofill:active,
            #domain-url:-moz-autofill,
            #domain-url:-moz-autofill:hover,
            #domain-url:-moz-autofill:focus,
            #domain-url:-moz-autofill:active {
              background-color: transparent !important;
              background: transparent !important;
              background-image: none !important;
              color: #ffffff !important;
              -webkit-box-shadow: 0 0 0 1000px transparent inset !important;
              -moz-box-shadow: 0 0 0 1000px transparent inset !important;
              box-shadow: 0px 1px 3px rgba(50, 50, 93, 0.07) !important;
            }
            
            /* Force override any inherited styles */
            input#domain-url {
              background: transparent !important;
              background-color: transparent !important;
              background-image: none !important;
              color: #ffffff !important;
            }
            
            /* Ensure labels stay white text on transparent background */
            label {
              background-color: transparent !important;
              color: #ffffff !important;
            }
            
            /* Remove white background from text labels only */
            label {
              background-color: transparent !important;
              background: transparent !important;
            }
            
            /* Remove white backgrounds and borders from all possible wrapper elements */
            .StripeElement,
            .StripeElement--complete,
            .StripeElement--empty,
            .StripeElement--focus,
            .StripeElement--invalid,
            .StripeElement--webkit-autofill,
            div[class*="Stripe"],
            div[class*="stripe"],
            span[class*="Stripe"],
            span[class*="stripe"] {
              background-color: transparent !important;
              background: transparent !important;
              border: none !important;
              border-color: transparent !important;
            }
            
            /* Target any divs that might be wrapping labels */
            form div:not([class*="input"]):not([class*="field"]) {
              background-color: transparent !important;
              background: transparent !important;
              border: none !important;
              border-color: transparent !important;
            }
            
            /* Placeholder text styling */
            input::placeholder {
              color: #a3a3a3 !important;
            }
            
            /* Ensure proper alignment of Email and Domain URL fields */
            #link-authentication-element {
              height: 40px !important;
              width: 100% !important;
              display: flex !important;
              align-items: center !important;
              margin-top: 0 !important;
              margin-bottom: 0 !important;
              padding-top: 0 !important;
              padding-bottom: 0 !important;
            }
            
            #link-authentication-element .StripeElement {
              height: 40px !important;
              width: 100% !important;
              margin-bottom: 0 !important;
              margin-top: 0 !important;
              flex: 1 !important;
              padding-top: 0 !important;
              padding-bottom: 0 !important;
            }
            
            /* Ensure both fields have same height, width and alignment */
            #link-authentication-element,
            #domain-url {
              height: 40px !important;
              width: 100% !important;
              vertical-align: top !important;
              display: flex !important;
              align-items: center !important;
              margin-top: 0 !important;
              margin-bottom: 0 !important;
              padding-top: 0 !important;
              padding-bottom: 0 !important;
            }
            
            /* Force both containers to have same baseline */
            .contact-info-container > div {
              align-items: flex-start !important;
              justify-content: flex-start !important;
            }
            
            .contact-info-container > div:first-child,
            .contact-info-container > div:last-child {
              align-items: flex-start !important;
              justify-content: flex-start !important;
              margin-top: 0 !important;
              padding-top: 0 !important;
            }
            
            /* Force both containers to have identical height and alignment */
            .contact-info-container {
              align-items: flex-start !important;
            }
            
            .contact-info-container > div {
              display: flex !important;
              flex-direction: column !important;
              justify-content: flex-start !important;
              min-height: 60px !important;
              align-items: stretch !important;
            }
            
            /* Ensure both input containers have same baseline */
            .contact-info-container > div:first-child,
            .contact-info-container > div:last-child {
              align-items: stretch !important;
              justify-content: flex-start !important;
              min-height: 60px !important;
            }
            
            /* Make sure Stripe Elements container matches regular input height */
            #link-authentication-element {
              min-height: 40px !important;
              max-height: 40px !important;
              height: 40px !important;
              display: flex !important;
              align-items: center !important;
              line-height: 1 !important;
              padding: 0 !important;
              margin: 0 !important;
            }
            
            /* Remove any extra spacing from Stripe Elements */
            #link-authentication-element * {
              line-height: 1 !important;
              margin: 0 !important;
              padding: 0 !important;
            }
            
            #link-authentication-element .StripeElement {
              height: 40px !important;
              max-height: 40px !important;
              line-height: 1 !important;
              padding: 0 !important;
              margin: 0 !important;
            }
            
            /* Force alignment of the container divs */
            .contact-info-container > div {
              display: flex !important;
              flex-direction: column !important;
              align-items: stretch !important;
              justify-content: flex-start !important;
            }
            
            .contact-info-container > div > * {
              margin-bottom: 0 !important;
              margin-top: 0 !important;
            }
            
            /* Ensure both input containers have same vertical positioning */
            .contact-info-container > div:first-child,
            .contact-info-container > div:last-child {
              align-items: flex-start !important;
              justify-content: flex-start !important;
            }
            
            /* Fix vertical alignment of Stripe Elements */
            #link-authentication-element {
              margin-top: 0 !important;
              margin-bottom: 0 !important;
              padding-top: 0 !important;
              padding-bottom: 0 !important;
            }
            
            /* Position Stripe's legal text properly - above the Subscribe button */
            .StripeElement + *,
            #payment-element + *,
            form > div:last-of-type:not(#payment-element),
            form > p:last-of-type,
            form > span:last-of-type {
              margin-bottom: '20px' !important;
              margin-top: '20px' !important;
              display: block !important;
              position: relative !important;
              z-index: 1 !important;
            }
            
            /* Ensure legal text appears above Subscribe button with proper spacing */
            form > div:last-of-type:not(#payment-element) {
              order: -1 !important;
              margin-bottom: '20px' !important;
            }
            
            /* Fix any overlapping text by ensuring proper stacking */
            #subscribe-btn {
              position: relative !important;
              z-index: 2 !important;
              margin-top: '20px' !important;
            }
            
            /* Target any Stripe-generated text elements */
            div[class*="stripe"],
            p[class*="stripe"],
            span[class*="stripe"] {
              position: relative !important;
              z-index: 1 !important;
              margin-bottom: '20px' !important;
            }
            
          `}</style>
          <h2 style={{ margin: '0 0 4px 0' }}>Complete Your Payment</h2>
          <div style={{ marginBottom: 12, color: '#a3a3a3' }}>
            {actualPlanType === 'annual' ? 'Annual Plan' : 'Monthly Plan'} - ${actualPlanType === 'annual' ? '19' : '24'}/month{actualPlanType === 'annual' ? ': Purchased Annually' : ''}
          </div>
          
          {actualPlanType ? (
            <form id="payment-form" data-plan-type={actualPlanType === 'annual' ? 'annual' : 'monthly'}>
            <h3 style={{ 
              fontSize: '16px', 
              fontWeight: '600', 
              margin: '0 0 16px 0',
              color: '#ffffff'
            }}>
              Contact Information
            </h3>
            
            <div className="contact-info-container" style={{ 
              display: 'flex', 
              gap: '16px', 
              marginBottom: '20px',
              flexWrap: 'wrap',
              alignItems: 'flex-start'
            }}>
              <div style={{ flex: '1 1 0', minWidth: 0, maxWidth: 'calc(50% - 8px)' }}>
                <div id="link-authentication-element" style={{ marginBottom: 0 }}>
                  {/* Link Authentication Element will mount here */}
                </div>
              </div>
              
              <div style={{ flex: '1 1 0', minWidth: 0,marginLeft:'-69px', maxWidth: 'calc(67% - 8px)' }}>
                <label htmlFor="domain-url" style={{ 
                  display: 'block', 
                  marginTop: '25px', 
                  fontSize: '14px',
                  fontWeight: '500', 
                  color: '#ffffff',
                  backgroundColor: 'transparent'
                }}>
                  Your Domain URL
                </label>
                <input 
                  id="domain-url" 
                  type="url" 
                  placeholder="https://your-domain.com" 
                  required 
                  style={{
                    width: '100%',
                    height: '40px',
                    padding: '10px 14px',
                    fontSize: '16px',
                    border: '1px solid #e6e6e6',
                    borderRadius: '4px',
                    backgroundColor: 'transparent',
                    color: '#ffffff',
                    boxShadow: '0px 1px 3px rgba(50, 50, 93, 0.07)',
                    transition: 'box-shadow 150ms ease, border-color 150ms ease',
                    boxSizing: 'border-box'
                  }}
                  onFocus={(e) => {
                    const target = e.target as HTMLInputElement;
                    target.style.borderColor = '#0570de';
                    target.style.backgroundColor = 'transparent';
                    target.style.background = 'transparent';
                  }}
                  onBlur={(e) => {
                    const target = e.target as HTMLInputElement;
                    target.style.borderColor = '#e6e6e6';
                    target.style.backgroundColor = 'transparent';
                    target.style.background = 'transparent';
                  }}
                  onInput={(e) => {
                    const target = e.target as HTMLInputElement;
                    target.style.backgroundColor = 'transparent';
                    target.style.background = 'transparent';
                  }}
                />
              </div>
            </div>
            
            <h3 style={{ 
              fontSize: '16px', 
              fontWeight: '600', 
              margin: '0 0 16px 0',
              color: '#ffffff'
            }}>
              Payment
            </h3>
            
            <div id="payment-element" style={{ marginBottom: '60px' }}>
              {/* Payment Element will mount here */}
            </div>
            
            <div id="error-message" style={{ 
              color: '#fa755a', 
              fontSize: '14px', 
              marginBottom: '16px',
              minHeight: '20px'
            }}></div>
            
            <div id="success-message" style={{ 
              color: '#4caf50', 
              fontSize: '14px', 
              marginBottom: '16px',
              minHeight: '20px'
            }}></div>
            
            <button 
              id="subscribe-btn" 
              className="subscribe-button" 
              type="submit" 
              disabled={isProcessing}
              style={{
                opacity: isProcessing ? 0.7 : 1,
                cursor: isProcessing ? 'not-allowed' : 'pointer',
                transition: 'opacity 0.2s ease',
                marginTop: '60px'
              }}
            >
              {isProcessing ? (
                <>
                  <span style={{ marginRight: '8px' }}>⏳</span>
                  Processing...
                </>
              ) : (
                'Subscribe'
              )}
            </button>
          </form>
          ) : (
            <div style={{ 
              display: 'flex', 
              justifyContent: 'center', 
              alignItems: 'center', 
              height: '200px',
              color: '#a3a3a3',
              fontSize: '16px'
            }}>
              Loading payment form...
            </div>
          )}
        </div>
      </div>
    );
  }

  // Debug logging
  console.log('🔥 PaymentScreen: Current state - paymentSuccess:', paymentSuccess, 'showStripeForm:', showStripeForm);

  // Success screen - shows after successful payment
  if (paymentSuccess) {
    return (
      <div className="payment-screen">
        {/* Header */}
        <div className="payment-header">
          <div className="app-name"></div>
          <div className="header-buttons">
            <button className="back-btn" onClick={onBack} disabled={isProcessing}>
              <img src={whitearrow} alt="" style={{ transform: 'rotate(180deg)' }} /> Back
            </button>
            <button className="next-btn" onClick={handleSuccessNext}>
              Continue <img src={whitearrow} alt="" />
            </button>
          </div>
        </div>

        {/* Step Navigation */}
        <div className="step-navigation">
          <div className="step completed">
            <span className="step-number">STEP 1</span>
            <span className="step-name">Customization</span>
          </div>
          <div className="step completed">
            <span className="step-number">STEP 2</span>
            <span className="step-name">Payment</span>
          </div>
          <div className="step">
            <span className="step-number">STEP 3</span>
            <span className="step-name">Publish</span>
          </div>
        </div>

        {/* Success Content */}
        <div className="main-content" style={{ 
          display: 'flex', 
          flexDirection: 'column', 
          height: '100%', 
          overflow: 'auto',
          padding: '20px 24px'
        }}>
          <div className="payment-card" style={{ 
            textAlign: 'center', 
            padding: '20px 20px',
            maxWidth: '700px',
            margin: '0 auto',
            flex: '1',
            display: 'flex',
            flexDirection: 'column',
            justifyContent: 'center'
          }}>
            
            <h2 style={{ 
              fontSize: '24px', 
              fontWeight: '600', 
              margin: '0 0 12px 0',
              color: 'rgba(43, 110, 47, 1)'
            }}>
              Payment Successful!
            </h2>
            
            <p style={{ 
              fontSize: '14px', 
              color: '#a3a3a3', 
              margin: '0 0 20px 0',
              lineHeight: '1.4'
            }}>
              Your subscription is now active. You can now proceed to publish your accessibility widget.
            </p>
            
            <div style={{ 
              padding: '12px 16px', 
              margin: '20px 0'
            }}>
              <div style={{ fontSize: '12px', color: '#a3a3a3', marginBottom: '6px' }}>
                Subscription Details
              </div>
              <div style={{ fontSize: '14px', fontWeight: '500', marginBottom: '8px' }}>
                {(actualPlanType || 'monthly') === 'annual' ? 'Annual Plan' : 'Monthly Plan'} - ${(actualPlanType || 'monthly') === 'annual' ? '19' : '24'}/month{(actualPlanType || 'monthly') === 'annual' ? ': Purchased Annually' : ''}
              </div>
              <div style={{ fontSize: '12px', color: '#a3a3a3' }}>
                Valid until: {subscriptionValidUntil || 'Loading...'}
              </div>
            </div>
            
            <div style={{ 
              display: 'flex', 
              gap: '8px', 
              justifyContent: 'center',
              marginTop: '24px',
              flexWrap: 'wrap'
            }}>
              <button 
                className="back-btn" 
                onClick={handleEditDomain}
                style={{ 
                  padding: '10px 16px',
                  backgroundColor: 'transparent',
                  border: '1px solid #333',
                  color: '#a3a3a3',
                  fontSize: '14px',
                  borderRadius: '6px'
                }}
              >
                Edit Domain URL
              </button>
              <button 
                className="next-btn" 
                onClick={handleCancelSubscription}
                style={{ 
                  padding: '10px 12px',
                  fontSize: '13px',
                  borderRadius: '6px',
                  whiteSpace: 'nowrap',
                  minWidth: '140px',
                  backgroundColor: 'rgba(38, 46, 132, 1)',
                  border: '1px solid rgba(38, 46, 132, 1)'
                }}
              >
                Cancel Subscription <img src={whitearrow} alt="" />
              </button>
            </div>
          </div>
        </div>
        
        {/* Cancellation Modal */}
        {showCancelModal && (
          <div style={{
            position: 'fixed',
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            backgroundColor: 'rgba(0, 0, 0, 0.8)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 1000
          }}>
            <div style={{
              backgroundColor: 'rgba(46, 43, 69, 1)',
              borderRadius: '12px',
              padding: '32px',
              maxWidth: '400px',
              width: '90%',
              border: '1px solid #333',
              boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04)',
              textAlign: 'center'
            }}>
              
              <h3 style={{
                fontSize: '24px',
                fontWeight: '600',
                margin: '0 0 16px 0',
                color: '#fff'
              }}>
                Cancel Subscription?
              </h3>
              
              <p style={{ 
                fontSize: '16px', 
                color: '#a3a3a3', 
                margin: '0 0 24px 0',
                lineHeight: '1.5'
              }}>
                Are you sure you want to cancel your subscription? This action cannot be undone.
              </p>
              
              <div style={{ 
                display: 'flex', 
                gap: '12px', 
                justifyContent: 'center' 
              }}>
                <button 
                  onClick={handleCloseCancelModal}
                  style={{
                    padding: '12px 24px',
                    backgroundColor: 'transparent',
                    border: '1px solid #333',
                    color: '#a3a3a3',
                    fontSize: '14px',
                    borderRadius: '6px',
                    cursor: 'pointer'
                  }}
                >
                  No, Keep Subscription
                </button>
                <button 
                  onClick={handleConfirmCancel}
                  disabled={isCanceling}
                  style={{
                    padding: '12px 24px',
                    backgroundColor: isCanceling ? '#6b7280' : '#dc2626',
                    border: 'none',
                    color: '#fff',
                    fontSize: '14px',
                    borderRadius: '6px',
                    cursor: isCanceling ? 'not-allowed' : 'pointer'
                  }}
                >
                  {isCanceling ? 'Cancelling...' : 'Yes, Cancel'}
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Domain Change Modal */}
        {showDomainModal && (
          <div style={{
            position: 'fixed',
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            backgroundColor: 'rgba(0, 0, 0, 0.8)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 1000
          }}>
            <div style={{
              backgroundColor: '#1a1a1a',
              borderRadius: '12px',
              padding: '32px',
              maxWidth: '500px',
              width: '90%',
              border: '1px solid #333',
              boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04)',
              textAlign: 'center'
            }}>
              
              <h3 style={{
                fontSize: '24px',
                fontWeight: '600',
                margin: '0 0 16px 0',
                color: '#fff'
              }}>
                Change Domain URL
              </h3>
              
              <p style={{ 
                fontSize: '16px', 
                color: '#a3a3a3', 
                margin: '0 0 16px 0',
                lineHeight: '1.5'
              }}>
                Enter the new domain URL where you want to use the accessibility widget.
              </p>
              
              
              <div style={{ marginBottom: '24px', display: 'flex', justifyContent: 'center' }}>
                <input
                  type="url"
                  value={newDomain}
                  onChange={(e) => handleDomainInputChange(e.target.value)}
                  placeholder="https://your-new-domain.com"
                  style={{
                    width: '100%',
                    maxWidth: '400px',
                    padding: '12px 16px',
                    fontSize: '16px',
                    border: '1px solid #333',
                    borderRadius: '8px',
                    backgroundColor: '#2a2a2a',
                    color: '#fff',
                    outline: 'none',
                    transition: 'border-color 0.2s'
                  }}
                  onFocus={(e) => e.target.style.borderColor = '#10b981'}
                  onBlur={(e) => e.target.style.borderColor = '#333'}
                />
                
              </div>
              
              <div style={{ 
                display: 'flex', 
                gap: '12px', 
                justifyContent: 'center' 
              }}>
                <button 
                  onClick={handleCloseDomainModal}
                  style={{
                    padding: '12px 24px',
                    backgroundColor: 'transparent',
                    border: '1px solid #333',
                    color: '#a3a3a3',
                    fontSize: '14px',
                    borderRadius: '6px',
                    cursor: 'pointer'
                  }}
                >
                  Cancel
                </button>
                <button 
                  onClick={handleUpdateDomain}
                  disabled={isUpdatingDomain || !newDomain.trim()}
                  style={{
                    padding: '12px 24px',
                    backgroundColor: isUpdatingDomain || !newDomain.trim() ? '#6b7280' : '#10b981',
                    border: 'none',
                    color: '#fff',
                    fontSize: '14px',
                    borderRadius: '6px',
                    cursor: isUpdatingDomain || !newDomain.trim() ? 'not-allowed' : 'pointer'
                  }}
                >
                  {isUpdatingDomain ? 'Updating...' : 'Update Domain'}
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    );
  }

  return (
    <div className="payment-screen">
      {/* Header */}
      <div className="payment-header">
        <div className="app-name"></div>
        <div className="header-buttons">
         <button className="back-btn" onClick={handleBack} disabled={isProcessing}>
            <img src={whitearrow} alt="" style={{ transform: 'rotate(180deg)' }} /> Back
          </button>
                <button className="next-btn" onClick={handlePayment} disabled={isProcessing}>
            {isProcessing ? 'Processing...' : 'Next'} <img src={whitearrow} alt="" />
          </button>
        </div>
      </div>

      {/* Step Navigation */}
      <div className="step-navigation">
        <div className="step completed">
          <span className="step-number">STEP 1</span>
          <span className="step-name">Customization</span>
        </div>
        <div className="step active">
          <span className="step-number">STEP 2</span>
          <span className="step-name">Payment</span>
        </div>
        <div className="step">
          <span className="step-number">STEP 3</span>
          <span className="step-name">Publish</span>
        </div>
      </div>

      {/* Main Content */}
      <div className="main-content">
        <div className="payment-card">
          <div className="pricing-flex">
            {/* Left side - Main pricing */}
            <div className="pricing-left">
              <div className="main-price">
                <div className="price-number">${isAnnual ? '19' : '24'}</div>
                <div className="price-period">/{isAnnual ? 'month: Purchased Annually' : 'month'}</div>
              </div>
              
              <div className={`payment-toggle ${isAnnual ? 'annually' : 'monthly'}`}>
                <button 
                  className={`toggle-option ${!isAnnual ? 'active' : ''}`}
                  onClick={() => {
                    setIsAnnual(false);
                    setActualPlanType('monthly');
                  }}
                >
                  Monthly
                </button>
                <button 
                  className={`toggle-option ${isAnnual ? 'active' : ''}`}
                  onClick={() => {
                    setIsAnnual(true);
                    setActualPlanType('annual');
                  }}
                >
                  Annually
                </button>
              </div>
              
              <div className="savings-info" style={{ opacity: isAnnual ? 1 : 0, visibility: isAnnual ? 'visible' : 'hidden' }}>
                You Save 20%
              </div>
            </div>

            {/* Right side - Secondary pricing and button */}
            <div className="pricing-right">
              <div className="secondary-price">
                ${isAnnual ? '19' : '24'}/month{isAnnual ? ': Purchased Annually' : ''}
              </div>
              
              <button 
                className="purchase-btn" 
                onClick={handlePurchaseNow}
                disabled={isProcessing}
              >
                Purchase Now <img style={{width: "11px"}} src={whitearrow} alt="" />
              </button>
            </div>
          </div>
        </div>

        {/* Stripe replaced full-screen above; nothing inline here */}
      </div>
      
      {/* Notification Popup */}
      {notification && (
        <div style={{
          position: 'fixed',
          top: '20px',
          right: '20px',
          zIndex: 10000,
          backgroundColor: notification.type === 'success' ? '#10b981' : 
                          notification.type === 'error' ? '#ef4444' : 'rgba(46, 43, 69, 1)',
          color: 'white',
          padding: '12px 16px',
          borderRadius: '8px',
          boxShadow: '0 4px 12px rgba(0, 0, 0, 0.15)',
          maxWidth: '400px',
          fontSize: '14px',
          fontWeight: '500',
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
          animation: 'slideInRight 0.3s ease-out',
          border: '1px solid rgba(255, 255, 255, 0.2)'
        }}>
          <div style={{
            width: '20px',
            height: '20px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            fontSize: '16px'
          }}>
            {notification.type === 'success' ? '' : 
             notification.type === 'error' ? '' : ''}
          </div>
          <div style={{ flex: 1 }}>
            {notification.message}
          </div>
          <button
            onClick={() => setNotification(null)}
            style={{
              background: 'none',
              border: 'none',
              color: 'white',
              cursor: 'pointer',
              padding: '4px',
              borderRadius: '4px',
              fontSize: '18px',
              lineHeight: 1,
              opacity: 0.8
            }}
            onMouseEnter={(e) => e.currentTarget.style.opacity = '1'}
            onMouseLeave={(e) => e.currentTarget.style.opacity = '0.8'}
          >
            ×
          </button>
        </div>
      )}
    </div>
  );
};

export default PaymentScreen;
