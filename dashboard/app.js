/**
 * Sussy PDF — Dashboard Application Logic
 * Drag & drop upload, API communication, dynamic rendering
 */

// === State ===
let analysisResult = null;
const API_URL = window.location.origin;

// === DOM Elements ===
const uploadSection = document.getElementById('upload-section');
const analyzingSection = document.getElementById('analyzing-section');
const resultsSection = document.getElementById('results-section');
const uploadZone = document.getElementById('upload-zone');
const fileInput = document.getElementById('file-input');

// === Initialization ===
document.addEventListener('DOMContentLoaded', () => {
    setupDragDrop();
    setupFileInput();
});

// === Drag & Drop ===
function setupDragDrop() {
    uploadZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        uploadZone.classList.add('drag-over');
    });

    uploadZone.addEventListener('dragleave', () => {
        uploadZone.classList.remove('drag-over');
    });

    uploadZone.addEventListener('drop', (e) => {
        e.preventDefault();
        uploadZone.classList.remove('drag-over');
        const files = e.dataTransfer.files;
        if (files.length > 0 && files[0].name.toLowerCase().endsWith('.pdf')) {
            startAnalysis(files[0]);
        } else {
            showError('Sadece PDF dosyaları kabul edilir.');
        }
    });

    uploadZone.addEventListener('click', () => fileInput.click());
}

function setupFileInput() {
    fileInput.addEventListener('change', (e) => {
        if (e.target.files.length > 0) {
            startAnalysis(e.target.files[0]);
        }
    });
}

// === Analysis ===
async function startAnalysis(file) {
    if (file.size > 50 * 1024 * 1024) {
        showError('Dosya boyutu 50MB sınırını aşıyor.');
        return;
    }

    showSection('analyzing');
    animateSteps();

    const formData = new FormData();
    formData.append('file', file);

    try {
        const response = await fetch(`${API_URL}/api/analyze`, {
            method: 'POST',
            body: formData,
        });

        if (!response.ok) {
            const err = await response.json().catch(() => ({}));
            throw new Error(err.detail || `HTTP ${response.status}`);
        }

        analysisResult = await response.json();
        renderResults(analysisResult);
        showSection('results');
    } catch (error) {
        console.error('Analysis error:', error);
        showError(`Analiz hatası: ${error.message}`);
        showSection('upload');
    }
}

function animateSteps() {
    const steps = document.querySelectorAll('.step');
    const names = ['ingestion', 'static', 'deobfuscation', 'dynamic', 'scoring'];

    names.forEach((name, i) => {
        setTimeout(() => {
            steps.forEach(s => s.classList.remove('active'));
            const step = document.querySelector(`.step[data-step="${name}"]`);
            if (step) {
                step.classList.add('active');
                // Mark previous as done
                for (let j = 0; j < i; j++) {
                    const prev = document.querySelector(`.step[data-step="${names[j]}"]`);
                    if (prev) prev.classList.add('done');
                }
            }
        }, i * 400);
    });
}

// === Render Results ===
function renderResults(data) {
    renderGauge(data.risk_score);
    renderFileInfo(data.file_info);
    renderScoreBreakdown(data.risk_score);
    renderTags(data.tags);
    renderStructure(data);
    renderMITRE(data.mitre);
    renderIOC(data.ioc);
    renderRecommendations(data.risk_score.recommendations);
}

function renderGauge(score) {
    const gaugeArc = document.getElementById('gauge-arc');
    const gaugeScore = document.getElementById('gauge-score');
    const verdict = document.getElementById('verdict');
    const gaugeCard = document.getElementById('risk-gauge-card');

    // Animate score number
    let current = 0;
    const target = score.total;
    const duration = 1500;
    const start = performance.now();

    function animateScore(now) {
        const elapsed = now - start;
        const progress = Math.min(elapsed / duration, 1);
        const eased = 1 - Math.pow(1 - progress, 3); // ease-out cubic
        current = Math.round(eased * target);
        gaugeScore.textContent = current;

        if (progress < 1) requestAnimationFrame(animateScore);
    }
    requestAnimationFrame(animateScore);

    // Set gauge arc
    const maxDash = 251.2;
    const offset = maxDash - (maxDash * (target / 100));
    gaugeArc.style.strokeDashoffset = offset;
    gaugeArc.style.stroke = score.color;

    // Score glow
    gaugeScore.style.color = score.color;
    gaugeScore.style.textShadow = `0 0 30px ${score.color}60`;

    // Verdict
    verdict.textContent = score.verdict;
    verdict.style.background = `${score.color}15`;
    verdict.style.borderLeft = `3px solid ${score.color}`;

    // Card border glow
    gaugeCard.style.borderColor = `${score.color}30`;
}

function renderFileInfo(info) {
    const el = document.getElementById('file-info-content');
    el.innerHTML = `
        <div class="info-row"><span class="info-label">Dosya Adı</span><span class="info-value">${info.name}</span></div>
        <div class="info-row"><span class="info-label">Boyut</span><span class="info-value">${info.size}</span></div>
        <div class="info-row"><span class="info-label">PDF Versiyonu</span><span class="info-value">${info.pdf_version || 'N/A'}</span></div>
        <div class="info-row"><span class="info-label">MD5</span><span class="info-value mono" style="font-size:0.7rem;">${info.md5}</span></div>
        <div class="info-row"><span class="info-label">SHA256</span><span class="info-value mono" style="font-size:0.65rem;">${info.sha256}</span></div>
    `;
}

function renderScoreBreakdown(score) {
    const el = document.getElementById('score-breakdown-content');
    if (!score.breakdown || score.breakdown.length === 0) {
        el.innerHTML = '<p style="color:var(--text-dim);">Skor detayı yok.</p>';
        return;
    }

    el.innerHTML = score.breakdown.map(b => {
        const pct = Math.round((b.points / b.max) * 100);
        return `
            <div class="score-bar">
                <div class="score-bar-header">
                    <span>${b.category}</span>
                    <span style="font-family:var(--font-mono);">${b.points}/${b.max}</span>
                </div>
                <div class="score-bar-track">
                    <div class="score-bar-fill" style="width:${pct}%;background:${score.color};"></div>
                </div>
                <div class="score-bar-detail">${b.details}</div>
            </div>
        `;
    }).join('');
}

function renderTags(tags) {
    const el = document.getElementById('tags-content');

    if (!tags.matches || tags.matches.length === 0) {
        el.innerHTML = '<p style="color:var(--neon-green);">✅ Şüpheli etiket bulunamadı.</p>';
        return;
    }

    el.innerHTML = `
        <table class="data-table">
            <thead>
                <tr><th>Etiket</th><th>Seviye</th><th>Sayı</th><th>Nesneler</th><th>Açıklama</th></tr>
            </thead>
            <tbody>
                ${tags.matches.map(m => `
                    <tr>
                        <td class="mono" style="color:var(--${getLevelColor(m.level)});">${m.tag}</td>
                        <td><span class="badge badge-${m.level}">${m.level}</span></td>
                        <td>${m.count}</td>
                        <td class="mono">${m.objects ? m.objects.join(', ') : '-'}</td>
                        <td style="font-size:0.8rem;color:var(--text-secondary);">${m.description}</td>
                    </tr>
                `).join('')}
            </tbody>
        </table>
        <p style="margin-top:1rem;font-size:0.85rem;">${tags.verdict}</p>
    `;
}

function renderStructure(data) {
    const el = document.getElementById('structure-content');
    const s = data.structure;
    const meta = data.metadata;

    el.innerHTML = `
        <div class="info-row"><span class="info-label">PDF Versiyonu</span><span class="info-value">${s.version}</span></div>
        <div class="info-row"><span class="info-label">Nesne Sayısı</span><span class="info-value">${s.object_count}</span></div>
        <div class="info-row"><span class="info-label">Stream Sayısı</span><span class="info-value">${s.stream_count}</span></div>
        <div class="info-row"><span class="info-label">%%EOF Sayısı</span><span class="info-value ${s.eof_count > 1 ? 'badge badge-medium' : ''}">${s.eof_count}</span></div>
        <div class="info-row"><span class="info-label">Şifreli</span><span class="info-value">${s.encrypted ? '🔒 Evet' : '🔓 Hayır'}</span></div>
        <div class="info-row"><span class="info-label">Artımlı Güncelleme</span><span class="info-value">${s.incremental ? '⚠️ Evet' : 'Hayır'}</span></div>
        ${meta.title ? `<div class="info-row"><span class="info-label">Başlık</span><span class="info-value">${meta.title}</span></div>` : ''}
        ${meta.author ? `<div class="info-row"><span class="info-label">Yazar</span><span class="info-value">${meta.author}</span></div>` : ''}
        ${meta.producer ? `<div class="info-row"><span class="info-label">Üretici</span><span class="info-value">${meta.producer}</span></div>` : ''}
    `;
}

function renderMITRE(mitre) {
    const el = document.getElementById('mitre-content');

    if (!mitre || mitre.length === 0) {
        el.innerHTML = '<p style="color:var(--text-dim);">MITRE eşleşmesi yok.</p>';
        return;
    }

    el.innerHTML = mitre.map(m => `
        <div class="mitre-tag" title="${m.tactic}: ${m.name}">
            <span class="tag-id">${m.id}</span>
            <span>${m.name}</span>
        </div>
    `).join('');
}

function renderIOC(ioc) {
    const el = document.getElementById('ioc-content');

    if (!ioc || ioc.total === 0) {
        el.innerHTML = '<p style="color:var(--text-dim);">IOC göstergesi yok.</p>';
        return;
    }

    el.innerHTML = `
        <p style="margin-bottom:1rem;font-size:0.85rem;color:var(--text-secondary);">
            Toplam <strong style="color:var(--text-primary);">${ioc.total}</strong> IOC göstergesi tespit edildi.
        </p>
        ${ioc.entries.map(e => `
            <div class="ioc-entry">
                <span class="ioc-type">${e.type}</span>
                <span class="ioc-value">${e.value}</span>
                <span class="badge badge-${e.confidence === 'high' ? 'critical' : 'medium'}">${e.confidence}</span>
            </div>
        `).join('')}
    `;
}

function renderRecommendations(recs) {
    const el = document.getElementById('recommendations-content');

    if (!recs || recs.length === 0) {
        el.innerHTML = '<p style="color:var(--neon-green);">Ek öneri yok.</p>';
        return;
    }

    el.innerHTML = recs.map(r => `
        <div class="recommendation-item">
            <span>→</span>
            <span>${r}</span>
        </div>
    `).join('');
}

// === Helpers ===
function getLevelColor(level) {
    const map = { critical: 'neon-red', high: 'neon-orange', medium: 'neon-yellow', low: 'neon-green' };
    return map[level] || 'text-secondary';
}

function showSection(name) {
    uploadSection.classList.add('hidden');
    analyzingSection.classList.add('hidden');
    resultsSection.classList.add('hidden');

    const sections = { upload: uploadSection, analyzing: analyzingSection, results: resultsSection };
    if (sections[name]) sections[name].classList.remove('hidden');

    // Update status
    const statusDot = document.querySelector('.status-dot');
    const statusText = document.querySelector('.status-indicator span:last-child');
    if (name === 'analyzing') {
        statusDot.className = 'status-dot';
        statusDot.style.background = 'var(--accent-cyan)';
        statusDot.style.boxShadow = '0 0 8px var(--accent-cyan)';
        statusText.textContent = 'Analiz ediliyor...';
    } else {
        statusDot.className = 'status-dot online';
        statusDot.style.background = '';
        statusDot.style.boxShadow = '';
        statusText.textContent = 'Hazır';
    }
}

function showError(message) {
    alert(message); // Basic — could be replaced with a toast notification
}

function resetAnalysis() {
    analysisResult = null;
    fileInput.value = '';
    showSection('upload');
}

function downloadReport(format) {
    if (!analysisResult) return;

    const blob = new Blob([JSON.stringify(analysisResult, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `sussy_pdf_report_${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
}
