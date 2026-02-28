document.getElementById('scanBtn').addEventListener('click', async () => {
    const urlInput = document.getElementById('urlInput').value.trim();
    if (!urlInput) return;

    const loader = document.getElementById('loader');
    const resultPanel = document.getElementById('resultPanel');
    const statusBadge = document.getElementById('statusBadge');
    const issueList = document.getElementById('issueList');

    // Show loader, hide results
    loader.classList.remove('hidden');
    resultPanel.classList.add('hidden');
    issueList.innerHTML = '';

    try {
        // Send the URL to our Python Backend
        const response = await fetch('/api/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: urlInput })
        });

        const data = await response.json();
        
        // Hide loader, show results
        loader.classList.add('hidden');
        resultPanel.classList.remove('hidden');

        if (data.safe) {
            statusBadge.className = 'badge safe';
            statusBadge.innerText = '✅ URL is Safe';
            issueList.innerHTML = '<li>No malicious patterns or global threats detected.</li>';
        } else {
            statusBadge.className = 'badge danger';
            statusBadge.innerText = '⚠️ Suspicious Activity Detected';
            data.issues.forEach(issue => {
                const li = document.createElement('li');
                li.innerText = issue;
                issueList.appendChild(li);
            });
        }
    } catch (error) {
        loader.classList.add('hidden');
        alert("Error connecting to the backend server.");
    }
});