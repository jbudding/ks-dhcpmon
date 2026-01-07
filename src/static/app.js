// WebSocket connection
let ws = null;
let isPaused = false;
let requests = [];
const MAX_DISPLAY_REQUESTS = 500;

// DOM elements
const statusIndicator = document.getElementById('indicator');
const statusText = document.getElementById('status-text');
const requestsBody = document.getElementById('requests-body');
const requestCount = document.getElementById('request-count');

// Statistics elements
const totalRequests = document.getElementById('total-requests');
const uniqueMacs = document.getElementById('unique-macs');
const reqPerMin = document.getElementById('req-per-min');
const uptimeEl = document.getElementById('uptime');
const messageTypes = document.getElementById('message-types');

// Filter elements
const filterMac = document.getElementById('filter-mac');
const filterVendor = document.getElementById('filter-vendor');
const filterType = document.getElementById('filter-type');
const btnClearFilters = document.getElementById('btn-clear-filters');
const btnPause = document.getElementById('btn-pause');

// Initialize WebSocket connection
function connectWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws`;

    ws = new WebSocket(wsUrl);

    ws.onopen = () => {
        console.log('WebSocket connected');
        updateStatus('connected');
        loadStatistics();
    };

    ws.onmessage = (event) => {
        if (isPaused) return;

        try {
            const request = JSON.parse(event.data);
            addRequest(request);
        } catch (error) {
            console.error('Error parsing message:', error);
        }
    };

    ws.onerror = (error) => {
        console.error('WebSocket error:', error);
        updateStatus('error');
    };

    ws.onclose = () => {
        console.log('WebSocket disconnected');
        updateStatus('disconnected');

        // Attempt reconnection after 3 seconds
        setTimeout(connectWebSocket, 3000);
    };
}

// Update connection status
function updateStatus(status) {
    statusIndicator.className = `indicator ${status}`;

    switch(status) {
        case 'connected':
            statusText.textContent = 'Connected';
            break;
        case 'disconnected':
            statusText.textContent = 'Disconnected - Reconnecting...';
            break;
        case 'error':
            statusText.textContent = 'Connection Error';
            break;
    }
}

// Add request to table
function addRequest(request) {
    // Add to internal array
    requests.unshift(request);

    // Limit array size
    if (requests.length > MAX_DISPLAY_REQUESTS) {
        requests.pop();
    }

    // Re-render filtered results
    renderRequests();
}

// Render requests based on filters
function renderRequests() {
    const macFilter = filterMac.value.toLowerCase();
    const vendorFilter = filterVendor.value.toLowerCase();
    const typeFilter = filterType.value;

    const filtered = requests.filter(req => {
        const macMatch = !macFilter || req.mac_address.toLowerCase().includes(macFilter);
        const vendorMatch = !vendorFilter || (req.vendor_class && req.vendor_class.toLowerCase().includes(vendorFilter));
        const typeMatch = !typeFilter || req.message_type === typeFilter;

        return macMatch && vendorMatch && typeMatch;
    });

    requestsBody.innerHTML = '';

    filtered.slice(0, 100).forEach(req => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td class="timestamp">${formatTimestamp(req.timestamp)}</td>
            <td class="mac">${req.mac_address}</td>
            <td>${req.source_ip}:${req.source_port}</td>
            <td><span class="badge badge-${req.message_type.toLowerCase()}">${req.message_type}</span></td>
            <td class="vendor">${req.vendor_class || '-'}</td>
            <td class="xid">${req.xid}</td>
            <td class="fingerprint">${req.fingerprint}</td>
        `;
        requestsBody.appendChild(row);
    });

    requestCount.textContent = `(${filtered.length})`;
}

// Format timestamp
function formatTimestamp(timestamp) {
    const date = new Date(timestamp);
    return date.toLocaleTimeString() + '.' + date.getMilliseconds().toString().padStart(3, '0');
}

// Truncate string
function truncate(str, length) {
    return str.length > length ? str.substring(0, length) + '...' : str;
}

// Load statistics from API
async function loadStatistics() {
    try {
        const response = await fetch('/api/stats');
        const stats = await response.json();
        updateStatistics(stats);
    } catch (error) {
        console.error('Error loading statistics:', error);
    }
}

// Update statistics display
function updateStatistics(stats) {
    totalRequests.textContent = stats.total_requests.toLocaleString();
    uniqueMacs.textContent = stats.unique_macs.toLocaleString();
    reqPerMin.textContent = stats.requests_per_minute.toFixed(2);
    uptimeEl.textContent = formatUptime(stats.uptime_seconds);

    // Update message type distribution
    messageTypes.innerHTML = '';
    for (const [type, count] of Object.entries(stats.request_types)) {
        const bar = document.createElement('div');
        bar.className = 'type-bar';
        bar.innerHTML = `
            <div class="type-label">${type}</div>
            <div class="type-value">${count}</div>
            <div class="type-bar-fill" style="width: ${(count / stats.total_requests * 100)}%"></div>
        `;
        messageTypes.appendChild(bar);
    }
}

// Format uptime
function formatUptime(seconds) {
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const secs = seconds % 60;

    if (hours > 0) {
        return `${hours}h ${minutes}m`;
    } else if (minutes > 0) {
        return `${minutes}m ${secs}s`;
    } else {
        return `${secs}s`;
    }
}

// Event listeners
filterMac.addEventListener('input', renderRequests);
filterVendor.addEventListener('input', renderRequests);
filterType.addEventListener('change', renderRequests);

btnClearFilters.addEventListener('click', () => {
    filterMac.value = '';
    filterVendor.value = '';
    filterType.value = '';
    renderRequests();
});

btnPause.addEventListener('click', () => {
    isPaused = !isPaused;
    btnPause.textContent = isPaused ? 'Resume' : 'Pause';
    btnPause.classList.toggle('paused');
});

// Refresh statistics every 5 seconds
setInterval(loadStatistics, 5000);

// Initialize
connectWebSocket();
