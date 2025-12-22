// CRITICAL: Immediate seizure-safe check - runs before any animations can start
(function() {
    try {
        // CRITICAL: Don't run widget in Webflow Designer environment
        const isDesigner = 
            (window.location.hostname.includes('webflow.com') && 
             (window.location.pathname.includes('/design/') || 
              window.location.pathname.includes('/designer'))) ||
            document.querySelector('[data-webflow-design-mode]') ||
            (typeof window.webflow !== 'undefined' && 
             typeof window.webflow.getSiteInfo === 'function' && 
             window.location.hostname.includes('webflow.com'));
        
        if (isDesigner) {
            // Exit early - widget should not run in Designer
            return;
        }
        
        // Skip accessibility widget if in reader mode or if page is being processed for reader mode
        if (isReaderModeStandalone()) {
            return;
        }
        
        // Check localStorage immediately for seizure-safe mode
        const seizureSafeFromStorage = localStorage.getItem('accessibility-widget-seizure-safe');
        if (seizureSafeFromStorage === 'true') {
            
            document.body.classList.add('seizure-safe');
            
            // Apply immediate CSS to stop all animations
            const immediateStyle = document.createElement('style');
            immediateStyle.id = 'accessibility-seizure-immediate-early';
            immediateStyle.textContent = `
                /* APPLY GREYISH COLOR FILTER IMMEDIATELY - Reduce color intensity to prevent seizures */
                body.seizure-safe,
                html.seizure-safe {
                    filter: grayscale(30%) contrast(0.9) brightness(0.95) !important;
                    -webkit-filter: grayscale(30%) contrast(0.9) brightness(0.95) !important;
                }
                
                /* CRITICAL: Exclude navigation elements from filter to preserve sticky/fixed positioning */
                body.seizure-safe nav,
                body.seizure-safe header,
                body.seizure-safe .navbar,
                body.seizure-safe [role="navigation"],
                body.seizure-safe [class*="nav"],
                body.seizure-safe [class*="header"],
                body.seizure-safe [class*="navbar"],
                body.seizure-safe [data-sticky],
                body.seizure-safe [data-fixed],
                body.seizure-safe [style*="position: sticky"],
                body.seizure-safe [style*="position:fixed"],
                body.seizure-safe [style*="position: fixed"] {
                    filter: none !important;
                    -webkit-filter: none !important;
                }
                
                /* Exclude widget container and all its contents from color filter */
                body.seizure-safe #accessibility-widget-container,
                body.seizure-safe [id*="accessibility-widget"],
                body.seizure-safe [class*="accessibility-widget"],
                body.seizure-safe [data-ck-widget] {
                    filter: none !important;
                    -webkit-filter: none !important;
                }
                
                /* Also exclude any shadow DOM content by targeting the host element */
                body.seizure-safe accessibility-widget {
                    filter: none !important;
                    -webkit-filter: none !important;
                }
                
                /* NOTE: Global animation-kill rules removed per configuration change to allow more motion */
                /* Ensure interactive elements still show pointer cursor in seizure-safe mode */
                body.seizure-safe a[href], body.seizure-safe button, body.seizure-safe [role="button"], body.seizure-safe [onclick], body.seizure-safe input[type="button"], body.seizure-safe input[type="submit"], body.seizure-safe input[type="reset"], body.seizure-safe .btn, body.seizure-safe .button, body.seizure-safe [class*="btn"], body.seizure-safe [class*="button"], body.seizure-safe [tabindex]:not([tabindex="-1"]) {
                    cursor: pointer !important;
                }
                /* Keep text cursor for text-editable fields */
                body.seizure-safe input[type="text"], body.seizure-safe input[type="email"], body.seizure-safe input[type="search"], body.seizure-safe input[type="tel"], body.seizure-safe input[type="url"], body.seizure-safe input[type="password"], body.seizure-safe textarea, body.seizure-safe [contenteditable="true"] {
                    cursor: text !important;
                }
                /* Stop animations for media elements without changing their layout */
                body.seizure-safe img, body.seizure-safe video, body.seizure-safe audio, body.seizure-safe iframe, body.seizure-safe embed, body.seizure-safe object {
                    animation: none !important;
                    transition: none !important;
                    animation-fill-mode: forwards !important;
                    opacity: 1 !important;
                    visibility: visible !important;
                }
                /* Stop animations for text elements without forcing hidden animation clones to become visible */
                body.seizure-safe h1, body.seizure-safe h2, body.seizure-safe h3, body.seizure-safe h4, body.seizure-safe h5, body.seizure-safe h6,
                body.seizure-safe p, body.seizure-safe span, body.seizure-safe div, body.seizure-safe a,
                body.seizure-safe li, body.seizure-safe td, body.seizure-safe th, body.seizure-safe label {
                    animation: none !important;
                    transition: none !important;
                    animation-fill-mode: forwards !important;
                    /* Do NOT override opacity/visibility here: many animation libraries keep
                       duplicate text elements hidden with opacity:0; forcing them visible
                       causes overlapping/ghost text behind the main heading. */
                }
                /* Force GSAP and other library fade/slide utilities to final, static state */
                body.seizure-safe .fade-up,
                body.seizure-safe .fade-left,
                body.seizure-safe .fade-right,
                body.seizure-safe .fade-in,
                body.seizure-safe .slide-in,
                body.seizure-safe .scale-in,
                body.seizure-safe .zoom-in {
                    opacity: 1 !important;
                    visibility: visible !important;
                    animation: none !important;
                    transition: none !important;
                    animation-fill-mode: forwards !important;
                }
                /* AUTOPLAY MEDIA: Stop all autoplay videos and media */
                body.seizure-safe video, body.seizure-safe audio, body.seizure-safe iframe, body.seizure-safe embed, body.seizure-safe object, body.seizure-safe [autoplay], body.seizure-safe [data-autoplay], body.seizure-safe [class*="autoplay"], body.seizure-safe [class*="video"], body.seizure-safe [class*="media"] {
                    animation: none !important;
                    transition: none !important;
                    animation-fill-mode: forwards !important;
                    opacity: 1 !important;
                    visibility: visible !important;
                }
                /* HOVER ANIMATIONS: Disable all hover-triggered animations */
                body.seizure-safe *:hover, body.seizure-safe *:focus, body.seizure-safe *:active, body.seizure-safe *[class*="hover"], body.seizure-safe *[class*="focus"], body.seizure-safe *[class*="active"], body.seizure-safe *[data-hover], body.seizure-safe *[data-focus], body.seizure-safe *[data-active] {
                    animation: none !important;
                    transition: none !important;
                    animation-fill-mode: forwards !important;
                    opacity: 1 !important;
                    visibility: visible !important;
                }
                
                /* CRITICAL: Exclude dropdown menus from visibility forcing - they should remain hidden until explicitly opened */
                /* This rule must come after the hover rule above to override it for dropdowns */
                /* Handle both normal and hover states to prevent auto-opening */
                body.seizure-safe [class*="dropdown"]:not([class*="open"]):not([class*="active"]):not([class*="show"]):not([aria-expanded="true"]),
                body.seizure-safe [class*="dropdown"]:not([class*="open"]):not([class*="active"]):not([class*="show"]):not([aria-expanded="true"]):hover,
                body.seizure-safe [id*="dropdown"]:not([class*="open"]):not([class*="active"]):not([class*="show"]):not([aria-expanded="true"]),
                body.seizure-safe [id*="dropdown"]:not([class*="open"]):not([class*="active"]):not([class*="show"]):not([aria-expanded="true"]):hover,
                body.seizure-safe [class*="menu"]:not([class*="open"]):not([class*="active"]):not([class*="show"]):not([aria-expanded="true"]):not(nav):not(header),
                body.seizure-safe [class*="menu"]:not([class*="open"]):not([class*="active"]):not([class*="show"]):not([aria-expanded="true"]):not(nav):not(header):hover,
                body.seizure-safe [id*="menu"]:not([class*="open"]):not([class*="active"]):not([class*="show"]):not([aria-expanded="true"]):not(nav):not(header),
                body.seizure-safe [id*="menu"]:not([class*="open"]):not([class*="active"]):not([class*="show"]):not([aria-expanded="true"]):not(nav):not(header):hover,
                body.seizure-safe [role="menu"]:not([class*="open"]):not([class*="active"]):not([class*="show"]):not([aria-expanded="true"]),
                body.seizure-safe [role="menu"]:not([class*="open"]):not([class*="active"]):not([class*="show"]):not([aria-expanded="true"]):hover,
                body.seizure-safe [role="menubar"]:not([class*="open"]):not([class*="active"]):not([class*="show"]):not([aria-expanded="true"]),
                body.seizure-safe [role="menubar"]:not([class*="open"]):not([class*="active"]):not([class*="show"]):not([aria-expanded="true"]):hover,
                /* Also handle common dropdown patterns like ul/ol inside nav items */
                body.seizure-safe nav ul:not([class*="open"]):not([class*="active"]):not([class*="show"]):not([aria-expanded="true"]),
                body.seizure-safe nav ul:not([class*="open"]):not([class*="active"]):not([class*="show"]):not([aria-expanded="true"]):hover,
                body.seizure-safe header ul:not([class*="open"]):not([class*="active"]):not([class*="show"]):not([aria-expanded="true"]),
                body.seizure-safe header ul:not([class*="open"]):not([class*="active"]):not([class*="show"]):not([aria-expanded="true"]):hover,
                body.seizure-safe [class*="nav"] ul:not([class*="open"]):not([class*="active"]):not([class*="show"]):not([aria-expanded="true"]),
                body.seizure-safe [class*="nav"] ul:not([class*="open"]):not([class*="active"]):not([class*="show"]):not([aria-expanded="true"]):hover,
                body.seizure-safe [class*="submenu"]:not([class*="open"]):not([class*="active"]):not([class*="show"]):not([aria-expanded="true"]),
                body.seizure-safe [class*="submenu"]:not([class*="open"]):not([class*="active"]):not([class*="show"]):not([aria-expanded="true"]):hover,
                body.seizure-safe [class*="sub-menu"]:not([class*="open"]):not([class*="active"]):not([class*="show"]):not([aria-expanded="true"]),
                body.seizure-safe [class*="sub-menu"]:not([class*="open"]):not([class*="active"]):not([class*="show"]):not([aria-expanded="true"]):hover {
                    /* Allow dropdowns to maintain their original visibility state - override the hover rule */
                    opacity: inherit !important;
                    visibility: inherit !important;
                    display: inherit !important;
                }
                /* LETTER-BY-LETTER ANIMATIONS: Force all text animations to final state */
                /* Hide per-character/word spans ONLY after JS has consolidated text on the container.
                   This prevents overlap on processed elements, without breaking sites where JS fails. */
                body.seizure-safe [data-splitting][data-seizure-text-processed] .char, 
                body.seizure-safe [data-splitting][data-seizure-text-processed] .word,
                body.seizure-safe .split[data-seizure-text-processed] .char, 
                body.seizure-safe .split[data-seizure-text-processed] .word,
                body.seizure-safe [class*="split"][data-seizure-text-processed] [class*="char"]:not([class*="character"]):not([class*="chart"]), 
                body.seizure-safe [class*="split"][data-seizure-text-processed] [class*="word"]:not([class*="wording"]),
                body.seizure-safe [class*="text-animation"][data-seizure-text-processed] .char,
                body.seizure-safe [class*="text-animation"][data-seizure-text-processed] .word,
                body.seizure-safe [class*="text-animation"][data-seizure-text-processed] [class*="char"]:not([class*="character"]):not([class*="chart"]),
                body.seizure-safe [class*="text-animation"][data-seizure-text-processed] [class*="word"]:not([class*="wording"]),
                body.seizure-safe [class*="typing"][data-seizure-text-processed] .char,
                body.seizure-safe [class*="typing"][data-seizure-text-processed] .word,
                body.seizure-safe [class*="typewriter"][data-seizure-text-processed] .char,
                body.seizure-safe [class*="typewriter"][data-seizure-text-processed] .word,
                body.seizure-safe [class*="reveal"][data-seizure-text-processed] .char,
                body.seizure-safe [class*="reveal"][data-seizure-text-processed] .word,
                body.seizure-safe [class*="unveil"][data-seizure-text-processed] .char,
                body.seizure-safe [class*="unveil"][data-seizure-text-processed] .word,
                body.seizure-safe [class*="show-text"][data-seizure-text-processed] .char,
                body.seizure-safe [class*="show-text"][data-seizure-text-processed] .word,
                body.seizure-safe [class*="text-effect"][data-seizure-text-processed] .char,
                body.seizure-safe [class*="text-effect"][data-seizure-text-processed] .word {
                    animation: none !important;
                    transition: none !important;
                    opacity: 0 !important;
                    visibility: hidden !important;
                    position: absolute !important;
                    transform: none !important;
                    clip-path: none !important;
                    -webkit-clip-path: none !important;
                    display: none !important;
                    pointer-events: none !important;
                }
                /* Show parent containers after JS processes them - these will have the consolidated text */
                body.seizure-safe [data-splitting][data-seizure-text-processed], 
                body.seizure-safe .split[data-seizure-text-processed], 
                body.seizure-safe [class*="split"][data-seizure-text-processed], 
                body.seizure-safe [class*="text-animation"][data-seizure-text-processed], 
                body.seizure-safe [class*="typing"][data-seizure-text-processed], 
                body.seizure-safe [class*="typewriter"][data-seizure-text-processed], 
                body.seizure-safe [class*="reveal"][data-seizure-text-processed], 
                body.seizure-safe [class*="unveil"][data-seizure-text-processed], 
                body.seizure-safe [class*="show-text"][data-seizure-text-processed], 
                body.seizure-safe [class*="text-effect"][data-seizure-text-processed] {
                    animation: none !important;
                    transition: none !important;
                    animation-fill-mode: forwards !important;
                    animation-play-state: paused !important;
                    opacity: 1 !important;
                    visibility: visible !important;
                    /* Force all text to be fully visible - remove any clipping or width restrictions */
                    clip-path: none !important;
                    -webkit-clip-path: none !important;
                    width: auto !important;
                    height: auto !important;
                    max-width: none !important;
                    max-height: none !important;
                }
                /* For text animation containers not yet processed, ensure they're visible but hide overlapping children */
                body.seizure-safe [data-splitting]:not([data-seizure-text-processed]), 
                body.seizure-safe .split:not([data-seizure-text-processed]), 
                body.seizure-safe [class*="split"]:not([data-seizure-text-processed]), 
                body.seizure-safe [class*="text-animation"]:not([data-seizure-text-processed]), 
                body.seizure-safe [class*="typing"]:not([data-seizure-text-processed]), 
                body.seizure-safe [class*="typewriter"]:not([data-seizure-text-processed]), 
                body.seizure-safe [class*="reveal"]:not([data-seizure-text-processed]), 
                body.seizure-safe [class*="unveil"]:not([data-seizure-text-processed]), 
                body.seizure-safe [class*="show-text"]:not([data-seizure-text-processed]), 
                body.seizure-safe [class*="text-effect"]:not([data-seizure-text-processed]) {
                    animation: none !important;
                    transition: none !important;
                    animation-fill-mode: forwards !important;
                    animation-play-state: paused !important;
                    /* Don't force opacity/visibility here - let JS handle consolidation first */
                }
                /* Hide duplicate text elements detected by JS (like Webflow's h1 + animated h2) */
                body.seizure-safe [data-seizure-duplicate-hidden] {
                    display: none !important;
                    visibility: hidden !important;
                    opacity: 0 !important;
                    position: absolute !important;
                    pointer-events: none !important;
                }
                /* Hide per-letter spans in Webflow-style elements that have been consolidated.
                   Only hide spans in elements that have many child spans (likely per-letter animation) */
                body.seizure-safe [data-seizure-text-processed][class*="fade-up"] > span,
                body.seizure-safe [data-seizure-text-processed][class*="fade-in"] > span,
                body.seizure-safe [data-seizure-text-processed][class*="multi-text"] > span,
                body.seizure-safe [data-seizure-text-processed].hero-heading > span {
                    display: none !important;
                    visibility: hidden !important;
                    opacity: 0 !important;
                    position: absolute !important;
                    pointer-events: none !important;
                }
                /* IMAGE HOVER EFFECTS: Disable all image hover animations */
                body.seizure-safe img:hover, body.seizure-safe [class*="image"]:hover, body.seizure-safe [class*="img"]:hover, body.seizure-safe [class*="photo"]:hover, body.seizure-safe [class*="picture"]:hover, body.seizure-safe [class*="gallery"]:hover, body.seizure-safe [class*="portfolio"]:hover, body.seizure-safe [class*="card"]:hover, body.seizure-safe [class*="item"]:hover {
                    animation: none !important;
                    transition: none !important;
                    animation-fill-mode: forwards !important;
                    opacity: 1 !important;
                    visibility: visible !important;
                }
                /* SCROLL-TRIGGERED ANIMATIONS: Stop all scroll-based animations IMMEDIATELY */
                body.seizure-safe *[class*="scroll"], 
                body.seizure-safe *[class*="progress"], 
                body.seizure-safe *[class*="bar"], 
                body.seizure-safe *[class*="line"], 
                body.seizure-safe *[class*="timeline"], 
                body.seizure-safe *[class*="track"], 
                body.seizure-safe *[class*="path"], 
                body.seizure-safe *[class*="stroke"], 
                body.seizure-safe *[class*="fill"], 
                body.seizure-safe *[class*="gradient"], 
                body.seizure-safe *[class*="wave"], 
                body.seizure-safe *[class*="flow"], 
                body.seizure-safe *[class*="stream"], 
                body.seizure-safe *[class*="runner"], 
                body.seizure-safe *[class*="mover"], 
                body.seizure-safe *[class*="indicator"], 
                body.seizure-safe *[class*="stopper"], 
                body.seizure-safe *[class*="marker"], 
                body.seizure-safe *[class*="pointer"], 
                body.seizure-safe *[class*="cursor"], 
                body.seizure-safe *[class*="dot"], 
                body.seizure-safe *[class*="circle"], 
                body.seizure-safe *[class*="ring"], 
                body.seizure-safe *[class*="orbit"],
                body.seizure-safe [data-scroll],
                body.seizure-safe [data-aos],
                body.seizure-safe [data-animate],
                body.seizure-safe [data-wf-page],
                body.seizure-safe [data-w-id] {
                    animation: none !important;
                    transition: none !important;
                    animation-fill-mode: forwards !important;
                    opacity: 1 !important;
                    visibility: visible !important;
                    /* Preserve transforms for slider manual navigation */
                    transform: none !important;
                    will-change: auto !important;
                }
                
                /* SLIDERS: Block auto-play animations but allow manual navigation - preserve transforms */
                body.seizure-safe .swiper-slide,
                body.seizure-safe .slick-slide,
                body.seizure-safe .carousel-item,
                body.seizure-safe [class*="swiper"] *,
                body.seizure-safe [class*="slick"] *,
                body.seizure-safe [class*="carousel"] *,
                body.seizure-safe [data-slider] *,
                body.seizure-safe [data-carousel] * {
                    /* Allow transforms for manual slide navigation */
                    transform: unset !important;
                }
                
                /* SLIDERS: Block auto-play animations but allow manual navigation */
                body.seizure-safe .swiper,
                body.seizure-safe .swiper-container,
                body.seizure-safe .slick-slider,
                body.seizure-safe .carousel,
                body.seizure-safe [class*="slider"]:not([class*="toggle"]):not(.toggle-switch .slider),
                body.seizure-safe [class*="carousel"],
                body.seizure-safe [data-slider],
                body.seizure-safe [data-carousel] {
                    /* Block auto-play animations */
                    animation: none !important;
                    /* Allow pointer events for manual navigation */
                    pointer-events: auto !important;
                    cursor: default !important;
                    /* Allow slide transitions for manual navigation */
                    transition: transform 0.3s ease !important;
                }
                
                /* Slider slides: block auto-animations but allow manual slide changes */
                body.seizure-safe .swiper-slide,
                body.seizure-safe .slick-slide,
                body.seizure-safe .carousel-item {
                    animation: none !important;
                    /* Allow transform for manual slide navigation */
                    transition: transform 0.3s ease !important;
                    pointer-events: auto !important;
                }
                /* REMOVED: Duplicate rule - already covered by scroll-triggered animations section */
                /* REMOVED: Duplicate data-splitting rules - already covered by letter-by-letter animations section */
            `;
            document.head.appendChild(immediateStyle);
            
            // Reinforce at root: cover both html.seizure-safe and body.seizure-safe
            try {
                if (!document.getElementById('accessibility-seizure-reinforce')) {
                    const reinforce = document.createElement('style');
                    reinforce.id = 'accessibility-seizure-reinforce';
                    reinforce.textContent = `
                        /* Exclude nav/header to preserve sticky positioning */
                        html.seizure-safe *:not(nav):not(header):not(.navbar):not([class*="nav"]):not([class*="header"]), html.seizure-safe *:not(nav):not(header):not(.navbar):not([class*="nav"]):not([class*="header"])::before, html.seizure-safe *:not(nav):not(header):not(.navbar):not([class*="nav"]):not([class*="header"])::after,
                        body.seizure-safe *:not(nav):not(header):not(.navbar):not([class*="nav"]):not([class*="header"]), body.seizure-safe *:not(nav):not(header):not(.navbar):not([class*="nav"]):not([class*="header"])::before, body.seizure-safe *:not(nav):not(header):not(.navbar):not([class*="nav"]):not([class*="header"])::after {
                            /* Complete animations to final state instead of stopping mid-way */
                            animation-play-state: paused !important;
                            animation-fill-mode: forwards !important;
                            animation: none !important;
                            animation-name: none !important;
                            transition: none !important;
                            transition-property: none !important;
                        }
                        /* Keep cursors intact */
                        html.seizure-safe a[href], html.seizure-safe button, html.seizure-safe [role="button"], html.seizure-safe [onclick],
                        html.seizure-safe input[type="button"], html.seizure-safe input[type="submit"], html.seizure-safe input[type="reset"],
                        html.seizure-safe .btn, html.seizure-safe .button, html.seizure-safe [class*="btn"], html.seizure-safe [class*="button"],
                        html.seizure-safe [tabindex]:not([tabindex="-1"]) { cursor: pointer !important; }
                        html.seizure-safe input[type="text"], html.seizure-safe input[type="email"], html.seizure-safe input[type="search"],
                        html.seizure-safe input[type="tel"], html.seizure-safe input[type="url"], html.seizure-safe input[type="password"],
                        html.seizure-safe textarea, html.seizure-safe [contenteditable="true"] { cursor: text !important; }
                    `;
                    document.head.appendChild(reinforce);
                }
            } catch (_) {}
            
            // Master layer: globally disable CSS animations/transitions without altering layout
            try {
                if (!document.getElementById('accessibility-seizure-master')) {
                    const master = document.createElement('style');
                    master.id = 'accessibility-seizure-master';
                    master.textContent = `
                        /* Hard stop for CSS animations and transitions */
                        /* Force animations to final state immediately - either prevent from starting or jump to final state */
                        /* Exclude nav/header to preserve sticky positioning and layout */
                        body.seizure-safe *:not(nav):not(header):not(.navbar):not([class*="nav"]):not([class*="header"]), 
                        body.seizure-safe *:not(nav):not(header):not(.navbar):not([class*="nav"]):not([class*="header"])::before, 
                        body.seizure-safe *:not(nav):not(header):not(.navbar):not([class*="nav"]):not([class*="header"])::after {
                            /* Set duration to 0s so animations complete instantly (jump to final state) */
                            animation-duration: 0s !important;
                            animation-delay: 0s !important;
                            animation-fill-mode: forwards !important;
                            animation-iteration-count: 1 !important;
                            /* Prevent new animations from starting */
                            animation-play-state: paused !important;
                            transition: none !important;
                            transition-property: none !important;
                            transition-duration: 0s !important;
                            transition-delay: 0s !important;
                            /* REMOVED: scroll-behavior: auto !important; - This was blocking Lenis smooth scrolling */
                        }
                        /* Do not affect cursor appearance */
                        body.seizure-safe * { cursor: inherit; }
                    `;
                    document.head.appendChild(master);
                }
                
                // Correction layer: preserve site layout styles while keeping animations disabled
                if (!document.getElementById('accessibility-seizure-correction')) {
                    const correction = document.createElement('style');
                    correction.id = 'accessibility-seizure-correction';
                    correction.textContent = `
                        /* Keep animations disabled - exclude nav/header to preserve sticky positioning */
                        body.seizure-safe *:not(nav):not(header):not(.navbar):not([class*="nav"]):not([class*="header"]) {
                            animation: none !important;
                            transition: none !important;
                        }
                        /* Restore layout-affecting properties to stylesheet values - exclude nav/header */
                        body.seizure-safe *:not(nav):not(header):not(.navbar):not([class*="nav"]):not([class*="header"]), 
                        body.seizure-safe *:not(nav):not(header):not(.navbar):not([class*="nav"]):not([class*="header"])::before, 
                        body.seizure-safe *:not(nav):not(header):not(.navbar):not([class*="nav"]):not([class*="header"])::after {
                            transform: unset !important;
                            translate: unset !important;
                            scale: unset !important;
                            rotate: unset !important;
                            opacity: unset !important;
                            visibility: unset !important;
                            /* CRITICAL: Do NOT unset position - this breaks sticky/fixed navigation */
                            /* REMOVED: position: unset !important; */
                            top: unset !important;
                            left: unset !important;
                            right: unset !important;
                            bottom: unset !important;
                            width: unset !important;
                            height: unset !important;
                        }
                        
                        /* CRITICAL: Preserve positioning for nav elements and ensure their positioning is not affected */
                        body.seizure-safe nav,
                        body.seizure-safe header,
                        body.seizure-safe .navbar,
                        body.seizure-safe [role="navigation"],
                        body.seizure-safe [class*="nav"],
                        body.seizure-safe [class*="header"],
                        body.seizure-safe [class*="navbar"],
                        body.seizure-safe [data-sticky],
                        body.seizure-safe [data-fixed],
                        body.seizure-safe [style*="position: sticky"],
                        body.seizure-safe [style*="position:fixed"],
                        body.seizure-safe [style*="position: fixed"] {
                            position: inherit !important;
                            transform: inherit !important;
                            /* Preserve opacity and visibility for nav elements to maintain their appearance */
                            opacity: inherit !important;
                            visibility: inherit !important;
                        }
                        /* Preserve only genuine navigation/header and explicit opt-outs */
                        body.seizure-safe nav, body.seizure-safe header, body.seizure-safe .navbar,
                        body.seizure-safe [role="navigation"], body.seizure-safe [data-allow-transform] {
                            /* Do not touch nav/header positioning to preserve sticky/fixed behavior */
                            /* REMOVED: transform: unset !important; - This was conflicting with transform: inherit above and breaking sticky navigation */
                            opacity: inherit !important;
                            visibility: inherit !important;
                        }
                    `;
                    document.head.appendChild(correction);
                }
            } catch (_) {}
            
            // Enforce no-scroll-animations for known libraries/selectors with high specificity
            try {
                if (!document.getElementById('accessibility-seizure-animation-enforcer')) {
                    const enforce = document.createElement('style');
                    enforce.id = 'accessibility-seizure-animation-enforcer';
                    enforce.textContent = `
                        /* Target common scroll animation libs without affecting layout of others */
                        body.seizure-safe [data-aos], body.seizure-safe .aos-init, body.seizure-safe .aos-animate,
                        body.seizure-safe [data-scroll], body.seizure-safe [data-animate], body.seizure-safe .wow,
                        body.seizure-safe .animate__animated, body.seizure-safe .fade-up, body.seizure-safe .fade-in,
                        body.seizure-safe .slide-in, body.seizure-safe .reveal, body.seizure-safe [class*="fade-"],
                        body.seizure-safe [class*="slide-"], body.seizure-safe [class*="reveal"], body.seizure-safe [class*="animate"] {
                            animation: none !important;
                            transition: none !important;
                            opacity: 1 !important;
                            /* transform: none !important; - REMOVED: This was breaking website layout */
                            will-change: auto !important;
                        }
                    `;
                    document.head.appendChild(enforce);
                }
            } catch (_) {}
            
            try { document.documentElement.classList.add('seizure-safe'); } catch (_) {}
            try { document.documentElement.setAttribute('data-seizure-safe', 'true'); } catch (_) {}
            
            // Runtime guards: stop JS-driven animations and reveal typewriter/progress instantly
            try {
                if (!window.__seizureGuardsApplied) {
                    window.__seizureGuardsApplied = true;
                    
                    // NOTE: Do not globally override timers/animation frames to avoid breaking sticky/nav behavior
                    if (!window.__origRequestAnimationFrame) window.__origRequestAnimationFrame = window.requestAnimationFrame;
                    if (!window.__origCancelAnimationFrame) window.__origCancelAnimationFrame = window.cancelAnimationFrame;
                    if (!window.__origSetInterval) window.__origSetInterval = window.setInterval;
                    if (!window.__origSetTimeout) window.__origSetTimeout = window.setTimeout;
                    if (!window.__origClearInterval) window.__origClearInterval = window.clearInterval;
                    if (!window.__origClearTimeout) window.__origClearTimeout = window.clearTimeout;
                    
                    // Ensure originals are active
                    window.requestAnimationFrame = window.__origRequestAnimationFrame;
                    window.cancelAnimationFrame = window.__origCancelAnimationFrame;
                    window.setInterval = window.__origSetInterval;
                    window.setTimeout = window.__origSetTimeout;
                    window.clearInterval = window.__origClearInterval;
                    window.clearTimeout = window.__origClearTimeout;
                    
                    // Disable Web Animations API - Only when seizure-safe is active
                    try {
                        if (!window.__origElementAnimate) {
                            window.__origElementAnimate = Element.prototype.animate;
                            Element.prototype.animate = function(...args) {
                                // Only block if seizure-safe or stop-animation mode is active
                                const isActive = document.body.classList.contains('seizure-safe') || document.body.classList.contains('stop-animation');
                                if (isActive) {
                                    // return a stub Animation
                                    return {
                                        cancel: function(){}, finish: function(){}, play: function(){}, pause: function(){},
                                        reverse: function(){}, updatePlaybackRate: function(){}, addEventListener: function(){},
                                        removeEventListener: function(){}, dispatchEvent: function(){ return false; },
                                        currentTime: 0, playState: 'finished',
                                    };
                                }
                                // Otherwise, use original (normal behavior)
                                return window.__origElementAnimate.apply(this, args);
                            };
                        }
                    } catch (_) { /* ignore */ }
                    
                    // Helper to reveal typewriter text and freeze progress visuals (Designer-safe)
                    window.__applySeizureSafeDOMFreeze = function() {
                        try {
                            // Check Designer mode first
                            // Use standalone Designer mode check
                            if (isDesignerModeStandalone()) return; // Exit early in Designer
                            
                            // Reveal typewriter/typing effects by consolidating text
                            const typeSelectors = [
                                '[class*="typewriter"]', '[class*="typing"]', '[data-typing]', '[data-typewriter]'
                            ];
                            // Use scoped query that excludes Designer elements
                            const widget = window.AccessibilityWidgetInstance;
                            const queryFn = widget && typeof widget.scopedQuerySelectorAll === 'function' 
                                ? (sel) => widget.scopedQuerySelectorAll(sel)
                                : (sel) => document.querySelectorAll(sel);
                            
                            queryFn(typeSelectors.join(',')).forEach(el => {
                                try {
                                    // Skip if already processed to prevent duplication
                                    if (el.hasAttribute('data-seizure-processed')) return;
                                    el.setAttribute('data-seizure-processed', 'true');
                                    
                                    const datasetText = el.getAttribute('data-full-text') || el.getAttribute('data-text') || '';
                                    if (datasetText) { 
                                        el.textContent = datasetText; 
                                        return; 
                                    }
                                    // If split into character spans, join them (but preserve original structure)
                                    const charSpans = el.querySelectorAll('.char, [class*="char"], .letter, [class*="letter"]');
                                    if (charSpans && charSpans.length > 0) {
                                        // Only consolidate if the element doesn't already have complete text
                                        const currentText = el.textContent.trim();
                                        if (!currentText || currentText.length < charSpans.length) {
                                            let joined = '';
                                            charSpans.forEach(n => { joined += n.textContent || ''; });
                                            if (joined && joined.trim()) {
                                                el.textContent = joined;
                                            }
                                        }
                                    }
                                } catch (_) { /* ignore per-element errors */ }
                            });
                            
                            // Freeze progress bars and indicators (keep current visual state)
                            const progressSelectors = [
                                'progress', '[role="progressbar"]', '[class*="progress"]', '[class*="indicator"]', '[class*="bar"]'
                            ];
                            queryFn(progressSelectors.join(',')).forEach(el => {
                                try {
                                    // Skip if already processed or in Designer
                                    if (el.hasAttribute('data-webflow-design') || 
                                        el.closest('[data-webflow-design-mode]')) {
                                        return;
                                    }
                                    
                                    // Mark as widget-managed
                                    el.setAttribute('data-accessibility-widget-managed', 'true');
                                    
                                    const cs = window.getComputedStyle(el);
                                    // Lock width/transform/transition to current (prefer CSS class, fallback to inline)
                                    el.style.transition = 'none';
                                    el.style.animation = 'none';
                                    if (cs.width && cs.width !== 'auto') el.style.width = cs.width;
                                    if (cs.transform && cs.transform !== 'none') el.style.transform = 'none';
                                    // For ARIA progressbar, keep the current value and stop changing
                                    if (el.getAttribute && el.getAttribute('role') === 'progressbar') {
                                        const now = el.getAttribute('aria-valuenow');
                                        if (now) el.setAttribute('aria-valuenow', now);
                                    }
                                } catch (_) { /* ignore per-element errors */ }
                            });
                            
                            // Preserve manual slider navigation controls: arrows and dots must remain functional
                            const sliderControlSelectors = [
                                '.swiper-button-next', '.swiper-button-prev', '.swiper-pagination-bullet', '.swiper-pagination-clickable',
                                '.slick-next', '.slick-prev', '.slick-dots li', '.slick-dots button',
                                '.glide__arrow', '.glide__bullet', '.splide__arrow', '.splide__pagination__page',
                                '.carousel-control-next', '.carousel-control-prev', '.carousel-indicators li', '.carousel-indicators button',
                                '[data-slide]', '[data-bs-slide]', '[data-glide-dir]'
                            ];
                            queryFn(sliderControlSelectors.join(',')).forEach(ctrl => {
                                try {
                                    ctrl.style.pointerEvents = 'auto';
                                    ctrl.style.cursor = 'pointer';
                                    // Ensure visibility and opacity aren't suppressed
                                    ctrl.style.visibility = '';
                                    ctrl.style.opacity = '';
                                } catch (_) {}
                            });
                            
                            // Pause autoplay for common slider libraries while keeping navigation enabled
                            try {
                                // Swiper
                                const swipers = queryFn('.swiper, .swiper-container');
                                swipers.forEach(el => {
                                    const inst = el.swiper || el.__swiper || (el._swiper || null);
                                    if (inst && inst.autoplay && typeof inst.autoplay.stop === 'function') {
                                        inst.autoplay.stop();
                                    }
                                });
                            } catch (_) {}
                            try {
                                // Slick (requires jQuery)
                                const jq = window.jQuery || window.$;
                                if (jq) {
                                    jq('.slick-slider').each(function() {
                                        try { jq(this).slick && jq(thi
