/**
 * GraphGuard - Professional Frontend JavaScript
 * Multi-Agent Security Investigation Platform
 * Powered by FalkorDB Graph Database
 */

const API_BASE = (window.location.protocol === 'file:') 
    ? 'http://localhost:8000/api' 
    : '/api';

// State Management
const state = {
    currentInvestigation: null,
    activeTab: 'cypher',
    isInvestigating: false
};

// DOM Elements (initialized after DOMContentLoaded)
let elements = {};

// Node color palette for graph visualization
const NODE_COLORS = {
    incident: '#ef4444',
    system: '#6366f1',
    user: '#10b981',
    threat: '#f59e0b',
    indicator: '#8b5cf6',
    historical: '#64748b'
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.innerHTML = `<span>${message}</span>`;
    container.appendChild(toast);
    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateX(100%)';
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}

function setStatusIndicator(status, message) {
    const el = elements.statusIndicator;
    if (!el) return;
    el.style.display = 'inline-flex';
    el.className = `status-indicator status-${status}`;

    // Clean any leading emojis from message to ensure clean typography and SVG icon alignment
    const cleanMessage = (message || '').replace(/^[\u2700-\u27BF\uE000-\uF8FF\uD83C-\uDBFF\uDC00-\uDFFF\u200D\uFE0F\s?🔍✅❌]+/u, '').trim();

    if (status === 'completed') {
        el.innerHTML = `
            <span class="status-icon status-icon-completed" aria-hidden="true">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                    <circle cx="12" cy="12" r="10" stroke="currentColor" stroke-width="2"/>
                    <path d="M7.5 12.5L10.5 15.5L16.5 9.5" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/>
                </svg>
            </span>
            <span class="status-text">${escapeHtml(cleanMessage || 'Investigation complete')}</span>
        `;
    } else if (status === 'running') {
        el.innerHTML = `
            <span class="status-icon status-icon-running" aria-hidden="true">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" class="status-spin">
                    <circle cx="12" cy="12" r="10" stroke="rgba(245, 158, 11, 0.25)" stroke-width="2.5"/>
                    <path d="M12 2a10 10 0 0 1 10 10" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"/>
                </svg>
            </span>
            <span class="status-text">${escapeHtml(cleanMessage || 'Investigation in progress...')}</span>
        `;
    } else if (status === 'error') {
        el.innerHTML = `
            <span class="status-icon status-icon-error" aria-hidden="true">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                    <circle cx="12" cy="12" r="10" fill="rgba(239, 68, 68, 0.2)" stroke="currentColor" stroke-width="2"/>
                    <line x1="15" y1="9" x2="9" y2="15" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"/>
                    <line x1="9" y1="9" x2="15" y2="15" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"/>
                </svg>
            </span>
            <span class="status-text">${escapeHtml(cleanMessage || 'Investigation failed')}</span>
        `;
    } else {
        el.innerHTML = `<span class="status-text">${escapeHtml(cleanMessage)}</span>`;
    }
}

function formatTime(seconds) {
    if (seconds < 1) return '< 1s';
    return `${seconds}s`;
}

function animateCounter(element, targetVal, isTime = false) {
    if (!element) return;
    if (isTime) {
        element.textContent = formatTime(targetVal);
        return;
    }
    const target = Number(targetVal) || 0;
    if (target === 0) {
        element.textContent = '0';
        return;
    }
    let current = 0;
    const step = Math.max(1, Math.ceil(target / 12));
    const timer = setInterval(() => {
        current += step;
        if (current >= target) {
            element.textContent = target;
            clearInterval(timer);
        } else {
            element.textContent = current;
        }
    }, 35);
}

function getSeverityColor(severity) {
    const colors = {
        CRITICAL: 'var(--color-severity-critical)',
        HIGH: 'var(--color-severity-high)',
        MEDIUM: 'var(--color-severity-medium)',
        LOW: 'var(--color-severity-low)'
    };
    return colors[severity] || 'var(--color-text-secondary)';
}

function escapeHtml(text) {
    const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' };
    return text.replace(/[&<>"']/g, m => map[m]);
}

function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        showToast('Query copied to clipboard', 'success');
    });
}

function showHowTo() {
    const modal = document.getElementById('howto-modal');
    if (modal) modal.style.display = 'block';
}

function closeHowTo() {
    const modal = document.getElementById('howto-modal');
    if (modal) modal.style.display = 'none';
}

function toggleAccordion(button) {
    const item = button.closest('.accordion-item');
    if (item) item.classList.toggle('open');
}

// ============================================================================
// HEALTH CHECK
// ============================================================================

async function checkHealth() {
    const dot = document.getElementById('falkor-status-dot');
    const text = document.getElementById('falkor-status-text');
    const badge = document.getElementById('falkor-status-badge');
    try {
        const res = await fetch(`${API_BASE}/health`);
        const data = await res.json();
        if (data.falkor_fallback) {
            dot.style.background = 'var(--color-warning)';
            text.textContent = 'FalkorDB Fallback Mode';
            if (badge) {
                badge.style.background = 'rgba(245, 158, 11, 0.1)';
                badge.style.borderColor = 'rgba(245, 158, 11, 0.25)';
                badge.style.color = 'var(--color-warning)';
            }
        } else {
            dot.style.background = 'var(--color-success)';
            text.textContent = 'FalkorDB Connected';
            if (badge) {
                badge.style.background = 'rgba(16, 185, 129, 0.1)';
                badge.style.borderColor = 'rgba(16, 185, 129, 0.25)';
                badge.style.color = 'var(--color-success)';
            }
        }
    } catch {
        dot.style.background = 'var(--color-danger)';
        text.textContent = 'Backend Offline';
        if (badge) {
            badge.style.background = 'rgba(239, 68, 68, 0.1)';
            badge.style.borderColor = 'rgba(239, 68, 68, 0.25)';
            badge.style.color = 'var(--color-danger)';
        }
    }
}

// ============================================================================
// INVESTIGATION PROGRESS ANIMATION
// ============================================================================

function showProgress() {
    elements.welcomeState.style.display = 'none';
    elements.resultsState.style.display = 'none';
    document.getElementById('progress-state').style.display = 'block';

    const steps = ['enricher', 'threatographer', 'memory', 'orchestrator'];
    steps.forEach(s => {
        const el = document.getElementById(`progress-${s}`);
        if (el) { el.className = 'progress-step'; }
    });

    // Animate steps sequentially
    let delay = 0;
    steps.forEach((step, idx) => {
        setTimeout(() => {
            const el = document.getElementById(`progress-${step}`);
            if (el) el.className = 'progress-step active';
            // Mark previous as completed
            if (idx > 0) {
                const prev = document.getElementById(`progress-${steps[idx - 1]}`);
                if (prev) prev.className = 'progress-step completed';
            }
        }, delay);
        delay += 400;
    });
}

function hideProgress() {
    document.getElementById('progress-state').style.display = 'none';
    // Mark all steps completed
    ['enricher', 'threatographer', 'memory', 'orchestrator'].forEach(s => {
        const el = document.getElementById(`progress-${s}`);
        if (el) el.className = 'progress-step completed';
    });
}

// ============================================================================
// INVESTIGATION FLOW
// ============================================================================

async function startInvestigation() {
    const incidentId = elements.incidentIdInput.value.trim();
    const tenantId = elements.tenantIdInput.value.trim() || 'tenant_east';

    if (!incidentId) {
        showToast('Please enter an incident ID', 'error');
        elements.incidentIdInput.focus();
        return;
    }

    if (state.isInvestigating) return;

    state.isInvestigating = true;
    const btn = document.getElementById('btn-investigate');
    if (btn) btn.disabled = true;
    setStatusIndicator('running', 'Starting multi-agent investigation...');
    showProgress();

    try {
        const response = await fetch(`${API_BASE}/investigation`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ incident_id: incidentId, tenant_id: tenantId })
        });

        if (!response.ok) {
            throw new Error(`Investigation failed: ${response.statusText}`);
        }

        const data = await response.json();
        state.currentInvestigation = data;

        // Brief pause for animation effect
        await new Promise(resolve => setTimeout(resolve, 600));
        hideProgress();
        displayResults(data);
        setStatusIndicator('completed', 'Investigation complete');
        showToast('Investigation completed successfully', 'success');

    } catch (error) {
        console.error('Investigation error:', error);
        hideProgress();
        setStatusIndicator('error', 'Investigation failed');
        showToast(error.message, 'error');
        // Show welcome state again on error
        elements.welcomeState.style.display = 'block';
    } finally {
        state.isInvestigating = false;
        if (btn) btn.disabled = false;
    }
}

function loadScenario(scenarioId) {
    elements.incidentIdInput.value = scenarioId;
    showToast(`Loading scenario ${scenarioId}...`, 'info');
    // Auto-start the investigation
    startInvestigation();
}

// ============================================================================
// RESULTS DISPLAY
// ============================================================================

function displayResults(data) {
    // Hide welcome and progress, show results
    elements.welcomeState.style.display = 'none';
    document.getElementById('progress-state').style.display = 'none';
    elements.resultsState.style.display = 'block';

    // Update header info
    elements.incidentIdDisplay.textContent = data.incident_id;
    elements.tenantIdDisplay.textContent = data.tenant_id;

    const severity = data.threat_attribution.severity;
    elements.severityBadge.textContent = severity;
    elements.severityBadge.className = `badge badge-${severity.toLowerCase()}`;

    // Update confidence meter with animation
    const confidence = Math.round(data.overall_confidence * 100);
    setTimeout(() => {
        elements.confidenceFill.style.width = `${confidence}%`;
        elements.confidenceValue.textContent = `${confidence}%`;
    }, 100);

    // Format and highlight narrative
    const formattedNarrative = escapeHtml(data.summary_narrative)
        .replace(/(APT29 \(Cozy Bear\)|LAPSUS\$|SQL Injection \(T1190\)|Mimikatz|Active Directory)/g, '<strong style="color: var(--color-brand-cyan); font-weight: 600;">$1</strong>')
        .replace(/(CRITICAL)/g, '<span class="badge badge-critical">$1</span>');

    elements.incidentSummary.innerHTML = `
        <p style="font-size: var(--font-size-base); color: var(--color-text-secondary); line-height: var(--line-height-relaxed);">
            ${formattedNarrative}
        </p>
    `;

    // Animate KPI metrics counters
    animateCounter(elements.metricTime, data.execution_time_seconds, true);
    animateCounter(elements.metricSystems, data.affected_systems_count || 0);
    animateCounter(elements.metricUsers, data.compromised_users_count || 0);
    animateCounter(elements.metricCards, (data.evidence_cards && data.evidence_cards.length) || 0);

    // Render graph visualization
    if (data.graph_visualization_data) {
        renderGraphVisualization(data.graph_visualization_data);
    }

    // Render dynamic agent timeline
    renderAgentTimeline(data.agent_timeline);

    // Render evidence cards
    renderEvidenceCards(data.evidence_cards);

    // Render all executed queries
    renderExecutedQueries(data.all_executed_queries);

    // Reset containment UI
    const containmentBadge = document.getElementById('containment-status-badge');
    if (containmentBadge) {
        containmentBadge.textContent = 'READY TO CONTAIN';
        containmentBadge.className = 'badge badge-brand';
    }
    const auditBox = document.getElementById('containment-audit-trail');
    if (auditBox) {
        auditBox.style.display = 'none';
    }
    // Reset containment buttons: default "Execute Full Graph Containment" highlighted
    const btnGroup = document.getElementById('containment-buttons-group');
    if (btnGroup) {
        btnGroup.querySelectorAll('.containment-btn').forEach(b => {
            b.classList.remove('btn-primary');
            b.classList.add('btn-secondary');
        });
        const defaultBtn = document.getElementById('btn-contain-all');
        if (defaultBtn) {
            defaultBtn.classList.remove('btn-secondary');
            defaultBtn.classList.add('btn-primary');
        }
    }

    // Scroll to top
    window.scrollTo({ top: 0, behavior: 'smooth' });
}

// ============================================================================
// AUTONOMOUS GRAPH-DRIVEN CONTAINMENT (Track 01 Rubric: Actions Based on Graph)
// ============================================================================

async function executeContainment(actionType = 'CONTAIN_ALL', clickedBtn = null) {
    if (!state.currentInvestigation || !state.currentInvestigation.incident_id) {
        showToast('No active incident to contain. Launch an investigation first.', 'warning');
        return;
    }
    const incidentId = state.currentInvestigation.incident_id;
    const tenantId = state.currentInvestigation.tenant_id || 'tenant_east';

    // Highlight the clicked button like "Execute Full Graph Containment" so it looks selected
    const btnGroup = document.getElementById('containment-buttons-group');
    if (btnGroup) {
        btnGroup.querySelectorAll('.containment-btn').forEach(b => {
            b.classList.remove('btn-primary');
            b.classList.add('btn-secondary');
        });
        const targetBtn = clickedBtn || (
            actionType === 'CONTAIN_ALL' ? document.getElementById('btn-contain-all') :
            actionType === 'ISOLATE_HOST' ? document.getElementById('btn-isolate-host') :
            document.getElementById('btn-revoke-cred')
        );
        if (targetBtn) {
            targetBtn.classList.remove('btn-secondary');
            targetBtn.classList.add('btn-primary');
        }
    }

    showToast(`Executing autonomous containment: ${actionType}...`, 'info');
    
    try {
        const response = await fetch(`${API_BASE}/action/containment`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                incident_id: incidentId,
                action_type: actionType,
                tenant_id: tenantId
            })
        });

        if (!response.ok) {
            throw new Error(`Containment failed: ${response.statusText}`);
        }

        const data = await response.json();
        
        // Update badge
        const badge = document.getElementById('containment-status-badge');
        if (badge) {
            badge.textContent = 'CONTAINMENT ACTIVE (ISOLATED)';
            badge.className = 'badge badge-success';
        }

        // Show audit trail
        const auditBoxEl = document.getElementById('containment-audit-trail');
        const auditListEl = document.getElementById('containment-audit-list');
        if (auditBoxEl && auditListEl) {
            auditBoxEl.style.display = 'block';
            const items = (data.audit_trail || []).map(item => `<div>• ${escapeHtml(item)}</div>`).join('');
            auditListEl.innerHTML = `
                ${items}
                <div style="margin-top: 6px; color: var(--color-brand-cyan); font-size: 11px;">
                    Cypher Mutation: <code>${escapeHtml(data.cypher_mutation)}</code>
                </div>
            `;
        }

        showToast(`Successfully contained ${data.mutated_nodes_count} connected nodes in FalkorDB`, 'success');
    } catch (err) {
        console.error('Containment error:', err);
        showToast(`Containment execution failed: ${err.message}`, 'error');
    }
}

// ============================================================================
// GRAPH VISUALIZATION (D3.js Force-Directed with Arrowheads & Interactive Controls)
// ============================================================================

function highlightCypher(cypher) {
    if (!cypher) return '';
    let escaped = escapeHtml(cypher);
    const keywords = ['MATCH', 'OPTIONAL MATCH', 'RETURN', 'WHERE', 'WITH', 'ORDER BY', 'LIMIT', 'DESC', 'ASC', 'AS', 'AND', 'OR', 'NOT', 'SET', 'MERGE', 'CREATE', 'DELETE', 'collect', 'count'];
    keywords.forEach(kw => {
        const regex = new RegExp(`\\b(${kw})\\b`, 'g');
        escaped = escaped.replace(regex, '<span style="color: #ec4899; font-weight: 600;">$1</span>');
    });
    escaped = escaped.replace(/(:\w+)/g, '<span style="color: #22d3ee; font-weight: 500;">$1</span>');
    return escaped;
}

function renderGraphVisualization(vizData) {
    const container = document.getElementById('graph-viz');
    if (!container || !vizData) return;

    // Check if d3 is loaded
    if (typeof d3 === 'undefined') {
        container.innerHTML = `
            <div style="display: flex; align-items: center; justify-content: center; height: 100%; color: var(--color-text-secondary); text-align: center; padding: var(--space-4);">
                <div>
                    <div style="font-size: 2.5rem; margin-bottom: var(--space-2);">🕸️</div>
                    <p style="font-weight: var(--font-weight-medium); margin-bottom: var(--space-1); color: var(--color-text-primary);">Threat Graph Topology</p>
                    <p style="font-size: var(--font-size-xs); color: var(--color-text-tertiary);">${vizData.nodes ? vizData.nodes.length : 0} nodes and ${vizData.edges ? vizData.edges.length : 0} connected relationships discovered</p>
                </div>
            </div>`;
        return;
    }

    try {
        // Clear previous SVG
        container.querySelectorAll('svg').forEach(s => s.remove());

        const width = container.clientWidth || 800;
        const height = container.clientHeight || 480;

        // Render legend
        const legendEl = document.getElementById('graph-legend');
        if (legendEl) {
            legendEl.innerHTML = Object.entries(NODE_COLORS).map(([key, color]) =>
                `<div class="graph-legend-item">
                    <div class="graph-legend-dot" style="background: ${color}"></div>
                    <span>${key.charAt(0).toUpperCase() + key.slice(1)}</span>
                </div>`
            ).join('');
        }

        const svg = d3.select(container)
            .append('svg')
            .attr('width', width)
            .attr('height', height);

        // SVG Defs: Arrowhead markers & Glow Filter
        const defs = svg.append('defs');
        
        defs.append('marker')
            .attr('id', 'graph-arrow')
            .attr('viewBox', '0 -5 10 10')
            .attr('refX', 22)
            .attr('refY', 0)
            .attr('markerWidth', 5)
            .attr('markerHeight', 5)
            .attr('orient', 'auto')
            .append('path')
            .attr('d', 'M0,-4L8,0L0,4')
            .attr('fill', '#64748b');

        // Add zoom container
        const g = svg.append('g');
        const zoom = d3.zoom().scaleExtent([0.2, 4]).on('zoom', (event) => {
            g.attr('transform', event.transform);
        });
        svg.call(zoom);

        // Bind floating zoom toolbar buttons
        const zoomInBtn = document.getElementById('graph-zoom-in');
        const zoomOutBtn = document.getElementById('graph-zoom-out');
        const zoomResetBtn = document.getElementById('graph-zoom-reset');
        if (zoomInBtn) zoomInBtn.onclick = () => svg.transition().duration(250).call(zoom.scaleBy, 1.3);
        if (zoomOutBtn) zoomOutBtn.onclick = () => svg.transition().duration(250).call(zoom.scaleBy, 0.7);
        if (zoomResetBtn) zoomResetBtn.onclick = () => svg.transition().duration(300).call(zoom.transform, d3.zoomIdentity);

        // Prepare data - filter out invalid nodes and deduplicate
        const nodeMap = new Map();
        (vizData.nodes || []).forEach(n => {
            if (n && n.id && String(n.id).trim() !== '' && !nodeMap.has(n.id)) {
                nodeMap.set(n.id, { ...n });
            }
        });
        const nodes = Array.from(nodeMap.values());
        const nodeIds = new Set(nodes.map(n => n.id));

        // Filter edges to only reference existing, valid nodes
        const edges = (vizData.edges || [])
            .filter(e => e && e.source && e.target && nodeIds.has(e.source) && nodeIds.has(e.target))
            .map(e => ({ ...e }));

        // Create force simulation
        const simulation = d3.forceSimulation(nodes)
            .force('link', d3.forceLink(edges).id(d => d.id).distance(130))
            .force('charge', d3.forceManyBody().strength(-450))
            .force('center', d3.forceCenter(width / 2, height / 2))
            .force('collision', d3.forceCollide().radius(45));

        // Draw edges
        const link = g.append('g')
            .attr('class', 'links')
            .selectAll('line')
            .data(edges)
            .enter().append('line')
            .attr('class', 'graph-link')
            .attr('stroke', '#475569')
            .attr('stroke-width', 1.5)
            .attr('stroke-dasharray', d => d.type === 'SIMILAR_TO' ? '4,4' : 'none')
            .attr('marker-end', 'url(#graph-arrow)');

        // Draw edge labels
        const linkLabel = g.append('g')
            .attr('class', 'link-labels')
            .selectAll('text')
            .data(edges)
            .enter().append('text')
            .attr('class', 'graph-link-label')
            .text(d => d.type)
            .attr('text-anchor', 'middle');

        // Tooltip container
        let tooltip = document.getElementById('graph-tooltip');
        if (!tooltip) {
            tooltip = document.createElement('div');
            tooltip.id = 'graph-tooltip';
            tooltip.className = 'graph-tooltip';
            tooltip.style.display = 'none';
            container.appendChild(tooltip);
        }

        // Draw nodes
        const node = g.append('g')
            .attr('class', 'nodes')
            .selectAll('g')
            .data(nodes)
            .enter().append('g')
            .call(d3.drag()
                .on('start', (event, d) => {
                    if (!event.active) simulation.alphaTarget(0.3).restart();
                    d.fx = d.x; d.fy = d.y;
                })
                .on('drag', (event, d) => {
                    d.fx = event.x; d.fy = event.y;
                })
                .on('end', (event, d) => {
                    if (!event.active) simulation.alphaTarget(0);
                    d.fx = null; d.fy = null;
                })
            );

        // Node circles
        node.append('circle')
            .attr('r', d => d.label === 'INCIDENT' ? 20 : d.label === 'THREAT' ? 18 : 14)
            .attr('fill', d => NODE_COLORS[d.group] || '#64748b')
            .attr('stroke', '#ffffff')
            .attr('stroke-width', 1.5)
            .attr('stroke-opacity', 0.8)
            .style('filter', d => d.label === 'INCIDENT' || d.label === 'THREAT' 
                ? 'drop-shadow(0 0 8px ' + (NODE_COLORS[d.group] || '#64748b') + ')' 
                : 'drop-shadow(0 0 4px rgba(0,0,0,0.5))');

        // Node label icons
        node.append('text')
            .attr('text-anchor', 'middle')
            .attr('dominant-baseline', 'central')
            .attr('font-size', '10px')
            .attr('fill', '#ffffff')
            .attr('font-weight', 'bold')
            .attr('pointer-events', 'none')
            .text(d => {
                const icons = { INCIDENT: '!', SYSTEM: 'S', USER: 'U', THREAT: 'T', INDICATOR: 'I' };
                return icons[d.label] || '?';
            });

        // Node name text labels below circles
        node.append('text')
            .attr('class', 'graph-node-label')
            .attr('dy', d => (d.label === 'INCIDENT' ? 30 : 24))
            .text(d => {
                const name = d.name || d.id;
                return name.length > 22 ? name.substring(0, 20) + '…' : name;
            });

        // Interactive node tooltips
        node.on('mouseenter', (event, d) => {
            tooltip.style.display = 'block';
            tooltip.innerHTML = `
                <div style="font-weight: 700; color: ${NODE_COLORS[d.group] || '#38bdf8'}; font-size: 10px; text-transform: uppercase; letter-spacing: 0.05em;">
                    ${escapeHtml(d.label || '')}
                </div>
                <div style="font-weight: 600; font-size: 13px; color: #f8fafc; margin: 3px 0;">
                    ${escapeHtml(d.name || d.id)}
                </div>
                ${d.is_critical ? '<span class="badge badge-critical" style="margin-top: 4px;">CRITICAL NODE</span>' : ''}
                ${d.role ? `<div style="font-size: 11px; color: #94a3b8; margin-top: 2px;">Role: ${escapeHtml(d.role)}</div>` : ''}
            `;
        })
        .on('mousemove', (event) => {
            const bounds = container.getBoundingClientRect();
            tooltip.style.left = (event.clientX - bounds.left + 15) + 'px';
            tooltip.style.top = (event.clientY - bounds.top + 15) + 'px';
        })
        .on('mouseleave', () => {
            tooltip.style.display = 'none';
        });

        // Tick simulation
        simulation.on('tick', () => {
            link
                .attr('x1', d => d.source.x)
                .attr('y1', d => d.source.y)
                .attr('x2', d => d.target.x)
                .attr('y2', d => d.target.y);

            linkLabel
                .attr('x', d => (d.source.x + d.target.x) / 2)
                .attr('y', d => (d.source.y + d.target.y) / 2 - 6);

            node.attr('transform', d => `translate(${d.x},${d.y})`);
        });

    } catch (err) {
        console.error('D3 visualization render error:', err);
    }
}

// ============================================================================
// AGENT TIMELINE (Dynamic)
// ============================================================================

function renderAgentTimeline(timeline) {
    const container = document.getElementById('agent-timeline');
    if (!container || !timeline) return;

    const agentIcons = {
        'Enricher Agent': '🔎',
        'Threatographer Agent': '🎯',
        'Memory Agent': '💾',
        'Orchestrator Agent': '🧠'
    };

    container.innerHTML = timeline.map(step => {
        const duration = (step.duration_seconds !== undefined && step.duration_seconds !== null) 
            ? `${step.duration_seconds}s` 
            : '';
        return `
        <div class="timeline-step completed">
            <div class="timeline-marker">${agentIcons[step.agent] || '✓'}</div>
            <div style="flex: 1;">
                <div class="timeline-title">
                    <span>${step.agent}</span>
                    ${duration ? `<span class="badge badge-brand" style="font-size: var(--font-size-xs); font-weight: normal;">${duration}</span>` : ''}
                </div>
                <div class="timeline-desc">${step.action} • ${step.queries_count} Cypher queries executed</div>
            </div>
        </div>
    `;
    }).join('');
}

// ============================================================================
// EVIDENCE CARDS
// ============================================================================

function renderEvidenceCards(cards) {
    elements.evidenceGrid.innerHTML = cards.map((card, idx) => {
        const confidence = Math.round(card.confidence * 100);
        const isHighConfidence = confidence >= 90;

        // Parse full graph path — backend uses ' -> ' as separator
        const pathParts = card.graph_path.split('->').map(p => p.trim()).filter(Boolean);
        const pathHtml = pathParts.map((part, i) => {
            let html = `<span class="path-node">${escapeHtml(part)}</span>`;
            if (i < pathParts.length - 1) html += '<span class="path-arrow">→</span>';
            return html;
        }).join('');

        return `
            <div class="evidence-card-v2">
                <div class="evidence-header">
                    <div>
                        <h4 class="evidence-title">${escapeHtml(card.title)}</h4>
                        <span class="badge ${isHighConfidence ? 'badge-success' : 'badge-info'}" 
                              style="margin-top: var(--space-1)">
                            ${confidence}% Confidence
                        </span>
                    </div>
                </div>
                
                <p class="evidence-statement">${escapeHtml(card.statement)}</p>
                
                <div class="path-container">${pathHtml}</div>

                <div class="accordion">
                    <div class="accordion-item">
                        <button class="accordion-header" onclick="toggleAccordion(this)">
                            <span>View FalkorDB Cypher Traversal</span>
                            <span class="accordion-icon">▼</span>
                        </button>
                        <div class="accordion-content">
                            <div class="code-block">
                                <code>${highlightCypher(card.cypher_query)}</code>
                            </div>
                            <button class="btn btn-secondary btn-sm" onclick="copyEvidenceQuery(${idx}, this)">
                                <span>Copy Cypher</span>
                            </button>
                        </div>
                    </div>
                </div>

                <div class="evidence-meta">
                    <span>Provenance: ${escapeHtml(card.source_agent)}</span>
                    <span>${escapeHtml(card.id)}</span>
                </div>
            </div>
        `;
    }).join('');
}

function copyEvidenceQuery(index, btn) {
    if (state.currentInvestigation && state.currentInvestigation.evidence_cards[index]) {
        const query = state.currentInvestigation.evidence_cards[index].cypher_query;
        navigator.clipboard.writeText(query).then(() => {
            showToast('Cypher query copied to clipboard', 'success');
            if (btn) {
                const originalHtml = btn.innerHTML;
                btn.innerHTML = '<span>✓ Copied!</span>';
                btn.style.borderColor = 'var(--color-success)';
                btn.style.color = 'var(--color-success)';
                setTimeout(() => {
                    btn.innerHTML = originalHtml;
                    btn.style.borderColor = '';
                    btn.style.color = '';
                }, 2000);
            }
        });
    }
}

// ============================================================================
// EXECUTED QUERIES PANEL
// ============================================================================

function renderExecutedQueries(queries) {
    const container = document.getElementById('executed-queries-panel');
    if (!container || !queries) return;

    container.innerHTML = queries.map((q, idx) => `
        <div class="query-item">
            <div class="query-item-title">
                <span class="badge badge-brand">Q${idx + 1}</span>
                <span>${escapeHtml(q.description)}</span>
            </div>
            <div class="query-item-code">${highlightCypher(q.cypher)}</div>
        </div>
    `).join('');
}

// ============================================================================
// ADVANCED TOOLS MODAL
// ============================================================================

function toggleAdvancedTools() {
    const modal = elements.advancedModal;
    const isVisible = modal.style.display === 'block';
    if (isVisible) {
        modal.style.display = 'none';
    } else {
        modal.style.display = 'block';
        renderAdvancedTabs();
    }
}

function renderAdvancedTabs() {
    elements.advancedTabs.innerHTML = `
        <div class="tabs-nav">
            <button class="tab-btn active" data-tab="cypher" onclick="switchAdvancedTab('cypher')">
                Cypher Query
            </button>
            <button class="tab-btn" data-tab="graph" onclick="switchAdvancedTab('graph')">
                Graph Data
            </button>
            <button class="tab-btn" data-tab="scenarios" onclick="switchAdvancedTab('scenarios')">
                Custom Scenarios
            </button>
        </div>
        <div class="tab-pane active" id="tab-cypher">
            ${renderCypherTab()}
        </div>
        <div class="tab-pane" id="tab-graph">
            ${renderGraphTab()}
        </div>
        <div class="tab-pane" id="tab-scenarios">
            ${renderScenariosTab()}
        </div>
    `;

    // Load custom scenarios list on render
    loadCustomScenariosList();
}

function switchAdvancedTab(tabName) {
    state.activeTab = tabName;
    document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
    const activeBtn = document.querySelector(`.tab-btn[data-tab="${tabName}"]`);
    if (activeBtn) activeBtn.classList.add('active');

    document.querySelectorAll('.tab-pane').forEach(pane => pane.classList.remove('active'));
    const activePane = document.getElementById(`tab-${tabName}`);
    if (activePane) activePane.classList.add('active');

    if (tabName === 'scenarios') loadCustomScenariosList();
}

function renderCypherTab() {
    return `
        <div class="card">
            <div class="card-body">
                <div style="display: flex; gap: var(--space-3); align-items: flex-end; margin-bottom: var(--space-3); flex-wrap: wrap;">
                    <div class="form-group" style="margin-bottom: 0; min-width: 260px; flex: 1;">
                        <label class="form-label">Graph Partition</label>
                        <input type="text" class="form-control" id="cypher-graph" value="graphguard_tenant_east">
                    </div>
                    <div style="display: flex; gap: var(--space-2); flex-wrap: wrap; align-items: center;">
                        <span style="font-size: var(--font-size-xs); color: var(--color-text-tertiary); font-weight: 600;">Presets:</span>
                        <button type="button" class="btn btn-ghost btn-sm" onclick="setCypherQuery('MATCH (n) RETURN n LIMIT 25')">All Nodes</button>
                        <button type="button" class="btn btn-ghost btn-sm" onclick="setCypherQuery('MATCH (n:INCIDENT) RETURN n.incr_id, n.title, n.severity, n.status')">Incidents</button>
                        <button type="button" class="btn btn-ghost btn-sm" onclick="setCypherQuery('MATCH (t:THREAT) RETURN t.actor, t.technique, t.confidence')">Threats</button>
                        <button type="button" class="btn btn-ghost btn-sm" onclick="setCypherQuery('MATCH (s:SYSTEM) RETURN s.name, s.domain, s.is_critical, s.has_internet_exposure')">Systems</button>
                        <button type="button" class="btn btn-ghost btn-sm" onclick="setCypherQuery('MATCH (u:USER) RETURN u.id, u.email, u.role, u.location')">Users</button>
                    </div>
                </div>
                <div class="form-group">
                    <label class="form-label">Cypher Query</label>
                    <textarea class="form-control" id="cypher-query" rows="5" 
                              placeholder="MATCH (n) RETURN n LIMIT 10" style="font-family: var(--font-family-mono); font-size: 0.85rem; line-height: 1.5;"></textarea>
                </div>
                <div style="display: flex; gap: var(--space-3); align-items: center;">
                    <button class="btn btn-primary" onclick="executeCypher()">
                        <span>⚡ Execute Query</span>
                    </button>
                    <button class="btn btn-secondary btn-sm" onclick="document.getElementById('cypher-query').value = '';">Clear</button>
                </div>
                <div id="cypher-results" style="margin-top: var(--space-4);"></div>
            </div>
        </div>
    `;
}

function setCypherQuery(query) {
    const textarea = document.getElementById('cypher-query');
    if (textarea) {
        textarea.value = query;
        textarea.focus();
    }
}

function renderGraphTab() {
    return `
        <div class="card">
            <div class="card-body">
                <div style="display: grid; grid-template-columns: 2fr 1fr auto; gap: var(--space-3); align-items: flex-end; margin-bottom: var(--space-4);">
                    <div class="form-group" style="margin-bottom: 0;">
                        <label class="form-label">Graph Partition</label>
                        <input type="text" class="form-control" id="graph-name" value="graphguard_tenant_east">
                    </div>
                    <div class="form-group" style="margin-bottom: 0;">
                        <label class="form-label">Node Label Filter</label>
                        <select class="form-control" id="graph-node-label">
                            <option value="">All Labels</option>
                            <option value="INCIDENT">INCIDENT</option>
                            <option value="SYSTEM">SYSTEM</option>
                            <option value="USER">USER</option>
                            <option value="THREAT">THREAT</option>
                            <option value="INDICATOR">INDICATOR</option>
                            <option value="COMPONENT">COMPONENT</option>
                            <option value="EVIDENCE">EVIDENCE</option>
                            <option value="AGENT_HANDOFF">AGENT_HANDOFF</option>
                        </select>
                    </div>
                    <button class="btn btn-primary" onclick="viewGraphData()">
                        <span>Inspect Graph</span>
                    </button>
                </div>
                <div id="graph-results" style="margin-top: var(--space-2);"></div>
            </div>
        </div>
    `;
}

function renderScenariosTab() {
    return `
        <div class="card">
            <div class="card-body">
                <div class="scenarios-grid-layout">
                    <div>
                        <h4 style="margin-bottom: var(--space-3); color: var(--color-text-primary); font-size: var(--font-size-md);">Save Custom Scenario</h4>
                        <div class="form-group">
                            <label class="form-label">Scenario ID</label>
                            <input type="text" class="form-control" id="custom-scenario-id" placeholder="INC-2026-0001">
                        </div>
                        <div class="form-group">
                            <label class="form-label">Title</label>
                            <input type="text" class="form-control" id="custom-scenario-title" placeholder="e.g. Cobalt Strike Lateral Movement">
                        </div>
                        <div class="form-group">
                            <label class="form-label">Severity</label>
                            <select class="form-control" id="custom-scenario-severity">
                                <option value="LOW">LOW</option>
                                <option value="MEDIUM">MEDIUM</option>
                                <option value="HIGH" selected>HIGH</option>
                                <option value="CRITICAL">CRITICAL</option>
                            </select>
                        </div>
                        <div class="form-group">
                            <label class="form-label">Description</label>
                            <textarea class="form-control" id="custom-scenario-description" rows="3" placeholder="Brief description of the attack scenario..."></textarea>
                        </div>
                        <button class="btn btn-primary" onclick="saveCustomScenario()">Save Scenario</button>
                        <div id="custom-scenario-status" style="margin-top: var(--space-3);"></div>
                    </div>
                    <div>
                        <h4 style="margin-bottom: var(--space-3); color: var(--color-text-primary); font-size: var(--font-size-md);">Saved Scenarios</h4>
                        <div id="custom-scenarios-list" style="max-height: 380px; overflow-y: auto;"></div>
                    </div>
                </div>
            </div>
        </div>
    `;
}

// ============================================================================
// ADVANCED TOOLS API FUNCTIONS
// ============================================================================

async function executeCypher() {
    const graphName = document.getElementById('cypher-graph').value;
    const cypher = document.getElementById('cypher-query').value;
    const resultsDiv = document.getElementById('cypher-results');

    if (!cypher) {
        showToast('Please enter a Cypher query', 'error');
        return;
    }

    resultsDiv.innerHTML = '<div class="status-indicator status-running">Executing query...</div>';

    try {
        const response = await fetch(`${API_BASE}/cypher`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ graph_name: graphName, cypher, params: {} })
        });

        const data = await response.json();

        if (data.rows && data.rows.length > 0) {
            const headers = Object.keys(data.rows[0]);
            let html = `
                <div style="margin-bottom: var(--space-2); display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: var(--space-2); color: var(--color-text-secondary); font-size: var(--font-size-xs);">
                    <span>Showing <strong style="color: var(--color-brand-cyan); font-weight: 700;">${data.row_count}</strong> row(s) returned from FalkorDB:</span>
                    <span style="color: var(--color-text-tertiary); font-family: var(--font-family-mono);">Partition: ${escapeHtml(graphName)}</span>
                </div>
                <div class="responsive-table-wrap">
                    <table class="responsive-table">
                        <thead>
                            <tr>
                                ${headers.map(h => `<th>${escapeHtml(h)}</th>`).join('')}
                            </tr>
                        </thead>
                        <tbody>
                            ${data.rows.map(row => `
                                <tr>
                                    ${headers.map(h => {
                                        const raw = row[h];
                                        let displayContent = '';
                                        if (raw !== null && typeof raw === 'object') {
                                            displayContent = escapeHtml(JSON.stringify(raw));
                                        } else {
                                            displayContent = escapeHtml(String(raw ?? ''));
                                        }
                                        return `<td class="props-cell">${displayContent}</td>`;
                                    }).join('')}
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                </div>
            `;
            resultsDiv.innerHTML = html;
            showToast(`Query returned ${data.row_count} rows`, 'success');
        } else {
            resultsDiv.innerHTML = '<div style="color: var(--color-text-tertiary); font-style: italic; margin-top: var(--space-3);">Query executed successfully. 0 rows returned.</div>';
        }
    } catch (error) {
        resultsDiv.innerHTML = `<div class="status-indicator status-error">Error: ${escapeHtml(error.message)}</div>`;
        showToast('Query execution failed', 'error');
    }
}

// Global cache for graph view filtering
let cachedGraphData = null;
let currentGraphView = 'nodes';

function renderFilteredGraphView() {
    const resultsDiv = document.getElementById('graph-results');
    if (!resultsDiv || !cachedGraphData) return;

    const searchTerm = (document.getElementById('graph-search-input')?.value || '').toLowerCase().trim();

    let filteredNodes = (cachedGraphData.nodes || []).filter(n => {
        if (!searchTerm) return true;
        const id = String(n.id || '').toLowerCase();
        const label = String(n.label || '').toLowerCase();
        const propsStr = JSON.stringify(n.props || {}).toLowerCase();
        return id.includes(searchTerm) || label.includes(searchTerm) || propsStr.includes(searchTerm);
    });

    let filteredEdges = (cachedGraphData.edges || []).filter(e => {
        if (!searchTerm) return true;
        const from = String(e.from || '').toLowerCase();
        const to = String(e.to || '').toLowerCase();
        const type = String(e.type || '').toLowerCase();
        return from.includes(searchTerm) || to.includes(searchTerm) || type.includes(searchTerm);
    });

    let contentHtml = '';

    if (currentGraphView === 'nodes') {
        contentHtml = `
            <div class="responsive-table-wrap">
                <table class="responsive-table">
                    <thead>
                        <tr>
                            <th style="width: 140px;">Entity Label</th>
                            <th style="width: 220px;">Node ID</th>
                            <th>Properties Summary</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${filteredNodes.length > 0 ? filteredNodes.slice(0, 100).map(node => {
                            const props = node.props || {};
                            const propBadges = Object.entries(props)
                                .filter(([k]) => k !== 'id')
                                .slice(0, 8)
                                .map(([k, v]) => {
                                    const valStr = typeof v === 'object' ? JSON.stringify(v) : String(v ?? '');
                                    const displayVal = valStr.length > 60 ? valStr.slice(0, 58) + '…' : valStr;
                                    return `<span class="prop-badge"><strong class="prop-key">${escapeHtml(k)}:</strong> <span class="prop-val">${escapeHtml(displayVal)}</span></span>`;
                                })
                                .join(' ');

                            return `
                                <tr>
                                    <td><span class="badge badge-brand">${escapeHtml(node.label || 'NODE')}</span></td>
                                    <td style="font-family: var(--font-family-mono); font-weight: 600; color: #f8fafc; font-size: 0.78rem;">${escapeHtml(node.id || '')}</td>
                                    <td class="props-cell">${propBadges || '<span style="color: var(--color-text-tertiary); font-style: italic;">No extra properties</span>'}</td>
                                </tr>
                            `;
                        }).join('') : `<tr><td colspan="3" style="text-align: center; color: var(--color-text-tertiary); padding: var(--space-4);">No nodes match current filter.</td></tr>`}
                    </tbody>
                </table>
            </div>
            ${filteredNodes.length > 100 ? `<div style="font-size: 0.72rem; color: var(--color-text-tertiary); margin-top: var(--space-2); text-align: right;">Showing first 100 of ${filteredNodes.length} nodes</div>` : ''}
        `;
    } else {
        contentHtml = `
            <div class="responsive-table-wrap">
                <table class="responsive-table">
                    <thead>
                        <tr>
                            <th style="width: 280px;">Source (From)</th>
                            <th style="width: 180px;">Relationship</th>
                            <th>Target (To)</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${filteredEdges.length > 0 ? filteredEdges.slice(0, 100).map(edge => `
                            <tr>
                                <td style="font-family: var(--font-family-mono); color: #cbd5e1; font-size: 0.78rem;">${escapeHtml(edge.from || '')}</td>
                                <td><span class="badge badge-info" style="font-weight: 700; letter-spacing: 0.03em;">${escapeHtml(edge.type || 'RELATES_TO')}</span></td>
                                <td style="font-family: var(--font-family-mono); color: var(--color-brand-cyan); font-size: 0.78rem;">${escapeHtml(edge.to || '')}</td>
                            </tr>
                        `).join('') : `<tr><td colspan="3" style="text-align: center; color: var(--color-text-tertiary); padding: var(--space-4);">No relationships match current filter.</td></tr>`}
                    </tbody>
                </table>
            </div>
            ${filteredEdges.length > 100 ? `<div style="font-size: 0.72rem; color: var(--color-text-tertiary); margin-top: var(--space-2); text-align: right;">Showing first 100 of ${filteredEdges.length} edges</div>` : ''}
        `;
    }

    const tableContainer = document.getElementById('graph-table-container');
    if (tableContainer) {
        tableContainer.innerHTML = contentHtml;
    }
}

function switchGraphSubView(view) {
    currentGraphView = view;
    document.querySelectorAll('.graph-sub-btn').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.view === view);
    });
    renderFilteredGraphView();
}

async function viewGraphData() {
    const graphName = document.getElementById('graph-name').value;
    const nodeLabel = document.getElementById('graph-node-label').value;
    const resultsDiv = document.getElementById('graph-results');

    if (!graphName) {
        showToast('Please enter a graph name', 'error');
        return;
    }

    resultsDiv.innerHTML = '<div class="status-indicator status-running"><span class="status-dot status-dot-pulse" style="background: var(--color-warning);"></span> Reading connected graph from FalkorDB...</div>';

    try {
        const url = `${API_BASE}/graph-data?graph_name=${encodeURIComponent(graphName)}${nodeLabel ? `&node_label=${encodeURIComponent(nodeLabel)}` : ''}`;
        const response = await fetch(url);
        const data = await response.json();

        if (data.success) {
            cachedGraphData = data;

            resultsDiv.innerHTML = `
                <div style="background: rgba(18, 26, 43, 0.8); border: 1px solid var(--color-border-primary); border-radius: var(--radius-md); padding: var(--space-3) var(--space-4); margin-bottom: var(--space-3); display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: var(--space-3);">
                    <div style="display: flex; gap: var(--space-2); align-items: center;">
                        <button class="btn btn-secondary btn-sm graph-sub-btn active" data-view="nodes" onclick="switchGraphSubView('nodes')">
                            <span>Nodes (${data.node_count})</span>
                        </button>
                        <button class="btn btn-secondary btn-sm graph-sub-btn" data-view="edges" onclick="switchGraphSubView('edges')">
                            <span>Relationships (${data.edge_count})</span>
                        </button>
                    </div>
                    <div style="flex: 1; max-width: 260px; min-width: 180px;">
                        <input type="text" class="form-control" id="graph-search-input" placeholder="Search ID or label..." style="padding: 4px 8px; font-size: 0.75rem;" oninput="renderFilteredGraphView()">
                    </div>
                </div>
                <div id="graph-table-container"></div>
            `;

            renderFilteredGraphView();
            showToast(`Loaded ${data.node_count} nodes and ${data.edge_count} relationships`, 'success');
        } else {
            resultsDiv.innerHTML = '<div class="status-indicator status-error">Failed to load graph data from FalkorDB</div>';
        }
    } catch (error) {
        console.error('Graph data load error:', error);
        resultsDiv.innerHTML = `<div class="status-indicator status-error">Error: ${escapeHtml(error.message)}</div>`;
        showToast('Failed to load graph data', 'error');
    }
}

async function saveCustomScenario() {
    const scenarioId = document.getElementById('custom-scenario-id').value;
    const title = document.getElementById('custom-scenario-title').value;
    const severity = document.getElementById('custom-scenario-severity').value;
    const description = document.getElementById('custom-scenario-description').value;
    const statusDiv = document.getElementById('custom-scenario-status');

    if (!scenarioId || !title || !description) {
        showToast('Please fill in all fields', 'error');
        return;
    }

    try {
        const scenarioData = { id: scenarioId, title, severity, description };
        let scenarios = JSON.parse(localStorage.getItem('graphguardCustomScenarios') || '[]');
        scenarios = scenarios.filter(s => s.id !== scenarioId);
        scenarios.push(scenarioData);
        localStorage.setItem('graphguardCustomScenarios', JSON.stringify(scenarios));

        statusDiv.innerHTML = `
            <div class="status-indicator status-completed">
                <span class="status-icon status-icon-completed" aria-hidden="true">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                        <circle cx="12" cy="12" r="10" stroke="currentColor" stroke-width="2"/>
                        <path d="M7.5 12.5L10.5 15.5L16.5 9.5" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/>
                    </svg>
                </span>
                <span class="status-text">Scenario saved!</span>
            </div>
        `;
        showToast('Scenario saved successfully', 'success');

        document.getElementById('custom-scenario-id').value = '';
        document.getElementById('custom-scenario-title').value = '';
        document.getElementById('custom-scenario-description').value = '';

        loadCustomScenariosList();
    } catch (error) {
        statusDiv.innerHTML = `
            <div class="status-indicator status-error">
                <span class="status-icon status-icon-error" aria-hidden="true">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                        <circle cx="12" cy="12" r="10" fill="rgba(239, 68, 68, 0.2)" stroke="currentColor" stroke-width="2"/>
                        <line x1="15" y1="9" x2="9" y2="15" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"/>
                        <line x1="9" y1="9" x2="15" y2="15" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"/>
                    </svg>
                </span>
                <span class="status-text">Error: ${escapeHtml(error.message)}</span>
            </div>
        `;
        showToast('Failed to save scenario', 'error');
    }
}

function loadCustomScenariosList() {
    const listDiv = document.getElementById('custom-scenarios-list');
    if (!listDiv) return;

    try {
        const scenarios = JSON.parse(localStorage.getItem('graphguardCustomScenarios') || '[]');

        if (scenarios.length === 0) {
            listDiv.innerHTML = '<p style="color: var(--color-text-tertiary); font-style: italic;">No custom scenarios saved yet.</p>';
            return;
        }

        let html = '<ul style="list-style: none; padding: 0;">';
        scenarios.forEach(scenario => {
            html += `
                <li style="padding: var(--space-3); border: 1px solid var(--color-border-primary); border-radius: var(--radius-md); margin-bottom: var(--space-2); display: flex; align-items: center; justify-content: space-between; gap: var(--space-3);">
                    <div style="flex: 1;">
                        <div style="font-weight: var(--font-weight-semibold);">${escapeHtml(scenario.id)}: ${escapeHtml(scenario.title)}</div>
                        <div style="font-size: var(--font-size-sm); color: var(--color-text-secondary);">${escapeHtml(scenario.description)}</div>
                    </div>
                    <span class="badge badge-${scenario.severity.toLowerCase()}">${escapeHtml(scenario.severity)}</span>
                    <button class="btn btn-ghost btn-sm" onclick="loadScenario('${escapeHtml(scenario.id)}'); toggleAdvancedTools();">Load</button>
                </li>
            `;
        });
        html += '</ul>';
        listDiv.innerHTML = html;
    } catch (error) {
        listDiv.innerHTML = `<p style="color: var(--color-danger);">Error loading scenarios: ${escapeHtml(error.message)}</p>`;
    }
}

function toggleModalMaximize() {
    const modalContent = document.querySelector('#advanced-modal .modal-content');
    if (!modalContent) return;
    const isMax = modalContent.classList.toggle('modal-maximized');
    const maxBtn = document.getElementById('btn-modal-maximize');
    if (maxBtn) {
        maxBtn.textContent = isMax ? '❐' : '⛶';
        maxBtn.title = isMax ? 'Restore Normal Size' : 'Maximize Window';
    }
}

// ============================================================================
// GLOBAL FUNCTION EXPORTS (for onclick handlers in HTML)
// ============================================================================

window.startInvestigation = startInvestigation;
window.loadScenario = loadScenario;
window.toggleAdvancedTools = toggleAdvancedTools;
window.toggleModalMaximize = toggleModalMaximize;
window.setCypherQuery = setCypherQuery;
window.executeCypher = executeCypher;
window.copyToClipboard = copyToClipboard;
window.showHowTo = showHowTo;
window.closeHowTo = closeHowTo;
window.toggleAccordion = toggleAccordion;
window.switchAdvancedTab = switchAdvancedTab;
window.viewGraphData = viewGraphData;
window.switchGraphSubView = switchGraphSubView;
window.renderFilteredGraphView = renderFilteredGraphView;
window.saveCustomScenario = saveCustomScenario;
window.loadCustomScenariosList = loadCustomScenariosList;
window.copyEvidenceQuery = copyEvidenceQuery;

// ============================================================================
// INITIALIZATION
// ============================================================================

document.addEventListener('DOMContentLoaded', () => {
    // Cache DOM elements
    elements = {
        welcomeState: document.getElementById('welcome-state'),
        resultsState: document.getElementById('results-state'),
        statusIndicator: document.getElementById('status-indicator'),
        incidentIdInput: document.getElementById('incidentId'),
        tenantIdInput: document.getElementById('tenantId'),
        incidentIdDisplay: document.getElementById('incident-id-display'),
        tenantIdDisplay: document.getElementById('tenant-id-display'),
        severityBadge: document.getElementById('severity-badge'),
        confidenceFill: document.getElementById('confidence-fill'),
        confidenceValue: document.getElementById('confidence-value'),
        incidentSummary: document.getElementById('incident-summary'),
        metricTime: document.getElementById('metric-time'),
        metricSystems: document.getElementById('metric-systems'),
        metricUsers: document.getElementById('metric-users'),
        metricCards: document.getElementById('metric-cards'),
        evidenceGrid: document.getElementById('evidence-grid'),
        advancedModal: document.getElementById('advanced-modal'),
        advancedTabs: document.getElementById('advanced-tabs')
    };

    // Set default incident ID
    elements.incidentIdInput.value = 'INC-2026-0447';

    // Add keyboard shortcut
    elements.incidentIdInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') startInvestigation();
    });

    // Check FalkorDB health
    checkHealth();

    // Close modals when clicking backdrop
    window.addEventListener('click', (e) => {
        if (e.target && e.target.classList && e.target.classList.contains('modal')) {
            e.target.style.display = 'none';
        }
    });

    // Close modals on Escape key
    window.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            const advModal = document.getElementById('advanced-modal');
            if (advModal && advModal.style.display === 'block') {
                advModal.style.display = 'none';
            }
            const howtoModal = document.getElementById('howto-modal');
            if (howtoModal && howtoModal.style.display === 'block') {
                howtoModal.style.display = 'none';
            }
        }
    });
});
