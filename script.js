function toBase64(str) {
    const bytes = new TextEncoder().encode(str);
    const bin = Array.from(bytes, b => String.fromCharCode(b)).join('');
    return btoa(bin);
}

function showActionMessage(message, isError = false) {
    const messageElement = document.getElementById('actionMessage');
    if (!messageElement) return;
    messageElement.textContent = message;
    messageElement.style.opacity = '1';
    messageElement.classList.toggle('error', isError);

    setTimeout(() => {
        messageElement.style.opacity = '0';
    }, 2000);
}

function copyToClipboard(text, buttonElement, message = 'Copied!') {
    navigator.clipboard.writeText(text).then(() => {
        const originalText = buttonElement.textContent;
        buttonElement.textContent = 'Copied!';
        setTimeout(() => {
            buttonElement.textContent = originalText;
        }, 2000);

        if (buttonElement.id === 'copyAllBtn') {
            showActionMessage(message);
        }
    }).catch(err => {
        console.error('Could not copy text: ', err);
        if (buttonElement.id === 'copyAllBtn') {
            showActionMessage('Failed to copy. Try again.', true);
        }
    });
}

function downloadAllLinks(urls, filenames) {
    try {
        let content = '';
        for (let i = 0; i < urls.length; i++) {
            content += `${filenames[i]}:\n${urls[i]}\n\n`;
        }

        const blob = new Blob([content], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const downloadLink = document.createElement('a');
        downloadLink.href = url;
        downloadLink.download = `proxied_links_${new Date().toISOString().slice(0, 10)}.txt`;
        document.body.appendChild(downloadLink);
        downloadLink.click();
        document.body.removeChild(downloadLink);
        URL.revokeObjectURL(url);

        showActionMessage('Links downloaded as text file!');
    } catch (error) {
        console.error('Could not download links: ', error);
        showActionMessage('Failed to download. Try again.', true);
    }
}

let allProxiedUrls = [];
let allFilenames = [];

// Attach bulk action listeners once
document.getElementById('copyAllBtn')?.addEventListener('click', function() {
    if (allProxiedUrls.length > 0) {
        copyToClipboard(allProxiedUrls.join('\n'), this, 'All links copied to clipboard!');
    }
});

document.getElementById('downloadAllBtn')?.addEventListener('click', function() {
    if (allProxiedUrls.length > 0) {
        downloadAllLinks(allProxiedUrls, allFilenames);
    }
});

document.getElementById('proxyForm').addEventListener('submit', (e) => {
    e.preventDefault();

    const urlsText = document.getElementById('urlInput').value;
    const urls = urlsText.split('\n').map(u => u.trim()).filter(Boolean);

    const resultsContainer = document.getElementById('results');
    resultsContainer.innerHTML = '';

    const bulkContainer = document.getElementById('bulkActionsContainer');
    bulkContainer.style.display = 'none';

    allProxiedUrls = [];
    allFilenames = [];

    const domainMeta = document.querySelector('meta[name="proxy-domain"]');
    const baseUrl = (domainMeta?.content?.trim() || window.location.origin).replace(/\/+$/, '');

    for (const urlStr of urls) {
        const resultDiv = document.createElement('div');
        resultDiv.className = 'result-item';

        try {
            const parsed = new URL(urlStr);
            if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
                throw new Error('Invalid protocol (must be http:// or https://)');
            }

            const filename = parsed.pathname.split('/').filter(Boolean).pop() || 'download';
            const encodedData = toBase64(JSON.stringify({ url: urlStr, filename }));
            const proxiedUrl = `${baseUrl}/dl/${encodedData}`;

            allProxiedUrls.push(proxiedUrl);
            allFilenames.push(filename);

            const origDiv = document.createElement('div');
            origDiv.className = 'url-original';
            origDiv.textContent = urlStr;

            const proxiedDiv = document.createElement('div');
            proxiedDiv.className = 'url-proxied';
            proxiedDiv.textContent = proxiedUrl;

            const fnDiv = document.createElement('div');
            fnDiv.className = 'filename';
            fnDiv.textContent = `Filename: ${filename}`;

            const actionDiv = document.createElement('div');
            actionDiv.className = 'action-buttons';

            const downloadLink = document.createElement('a');
            downloadLink.className = 'download-btn';
            downloadLink.href = proxiedUrl;
            downloadLink.target = '_blank';
            downloadLink.rel = 'noopener noreferrer';
            downloadLink.textContent = 'Download';

            const copyBtn = document.createElement('button');
            copyBtn.type = 'button';
            copyBtn.className = 'copy-btn';
            copyBtn.textContent = 'Copy Link';
            copyBtn.addEventListener('click', () => copyToClipboard(proxiedUrl, copyBtn));

            actionDiv.appendChild(downloadLink);
            actionDiv.appendChild(copyBtn);

            resultDiv.appendChild(origDiv);
            resultDiv.appendChild(proxiedDiv);
            resultDiv.appendChild(fnDiv);
            resultDiv.appendChild(actionDiv);
        } catch (err) {
            resultDiv.classList.add('error');

            const origDiv = document.createElement('div');
            origDiv.className = 'url-original';
            origDiv.textContent = urlStr;

            const errDiv = document.createElement('div');
            errDiv.className = 'error-message';
            errDiv.textContent = `Error: ${err.message}`;

            resultDiv.appendChild(origDiv);
            resultDiv.appendChild(errDiv);
        }

        resultsContainer.appendChild(resultDiv);
    }

    resultsContainer.style.display = 'block';
    if (allProxiedUrls.length > 0) {
        bulkContainer.style.display = 'flex';
    }
});
