let lastResult = null;

async function analyzeURL() {
    const url = document.getElementById('urlInput').value.trim();
    if (!url) {
        alert('Please enter a URL');
        return;
    }

    try {
        new URL(url);
    } catch {
        alert('Please enter a valid URL including http:// or https://');
        return;
    }

    document.getElementById('loadingSpinner').classList.remove('d-none');
    document.getElementById('resultBox').classList.add('d-none');

    try {
        const response = await fetch('/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: url })
        });

        const data = await response.json();
        lastResult = data;

        document.getElementById('loadingSpinner').classList.add('d-none');

        const resultBox        = document.getElementById('resultBox');
        const resultText       = document.getElementById('resultText');
        const resultConfidence = document.getElementById('resultConfidence');
        const resultURL        = document.getElementById('resultURL');
        const resultReasons    = document.getElementById('resultReasons');

        resultBox.classList.remove('d-none', 'safe', 'unsafe');

        if (data.prediction === 'legitimate') {
            resultBox.classList.add('safe');
            resultText.innerHTML = 'This URL appears to be <span class="text-success fw-bold">Safe</span>';
            resultReasons.innerHTML = '';
        } else {
            resultBox.classList.add('unsafe');
            resultText.innerHTML = 'This URL appears to be <span class="text-danger fw-bold">Phishing</span>';

            if (data.reasons && data.reasons.length > 0) {
                let reasonsHTML = '<div class="mt-3 text-start"><p class="fw-semibold mb-2" style="color: var(--cu-red)">Why we flagged this:</p><ul class="mt-1">';
                data.reasons.forEach(reason => {
                    reasonsHTML += `<li>${reason}</li>`;
                });
                reasonsHTML += '</ul></div>';
                resultReasons.innerHTML = reasonsHTML;
            }
        }

        resultConfidence.innerHTML = `Confidence: <strong>${data.confidence}%</strong>`;
        resultURL.innerHTML = `Analyzed: <span class="text-muted">${data.url}</span>`;

        document.getElementById('feedbackSection').classList.remove('d-none');
        document.getElementById('feedbackMessage').innerHTML = '';

    } catch (error) {
        document.getElementById('loadingSpinner').classList.add('d-none');
        alert('Error analyzing URL. Please try again.');
    }
}

async function sendFeedback(correct) {
    if (!lastResult) return;

    const response = await fetch('/feedback', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            url: lastResult.url,
            prediction: lastResult.prediction,
            correct: correct
        })
    });

    const data = await response.json();
    document.getElementById('feedbackSection').classList.add('d-none');
    document.getElementById('feedbackMessage').innerHTML = `<p class="mt-2 small" style="color: var(--success-green)">${data.message}</p>`;
}

document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('urlInput').addEventListener('keypress', (e) => {
        if (e.key === 'Enter') analyzeURL();
    });
});