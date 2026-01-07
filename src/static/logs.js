// State management
let currentFilters = {
    start_date: null,
    end_date: null,
    mac_address: null,
    vendor_class: null,
    message_type: null,
    xid: null,
};
let currentSort = {
    sort_by: 'timestamp',
    sort_order: 'DESC'
};
let currentPage = 1;
let pageSize = 100;
let totalRecords = 0;

// DOM elements
const logsBody = document.getElementById('logs-body');
const loading = document.getElementById('loading');
const noResults = document.getElementById('no-results');
const totalCount = document.getElementById('total-count');
const pagination = document.getElementById('pagination');

// Filter inputs
const startDate = document.getElementById('start-date');
const endDate = document.getElementById('end-date');
const filterMac = document.getElementById('filter-mac');
const filterVendor = document.getElementById('filter-vendor');
const filterType = document.getElementById('filter-type');
const filterXid = document.getElementById('filter-xid');
const pageSizeSelect = document.getElementById('page-size');

// Buttons
const btnApplyFilters = document.getElementById('btn-apply-filters');
const btnClearFilters = document.getElementById('btn-clear-filters');
const btnExportCsv = document.getElementById('btn-export-csv');
const btnExportJson = document.getElementById('btn-export-json');

// Load logs from API
async function loadLogs() {
    showLoading();

    const params = new URLSearchParams({
        page: currentPage,
        page_size: pageSize,
        sort_by: currentSort.sort_by,
        sort_order: currentSort.sort_order,
    });

    // Add filters
    if (currentFilters.start_date) params.append('start_date', currentFilters.start_date);
    if (currentFilters.end_date) params.append('end_date', currentFilters.end_date);
    if (currentFilters.mac_address) params.append('mac_address', currentFilters.mac_address);
    if (currentFilters.vendor_class) params.append('vendor_class', currentFilters.vendor_class);
    if (currentFilters.message_type) params.append('message_type', currentFilters.message_type);
    if (currentFilters.xid) params.append('xid', currentFilters.xid);

    try {
        const response = await fetch(`/api/logs?${params}`);
        const logs = await response.json();

        renderLogs(logs);
        await loadCount();
    } catch (error) {
        console.error('Error loading logs:', error);
        hideLoading();
        showNoResults();
    }
}

// Load total count
async function loadCount() {
    const params = new URLSearchParams();

    // Add filters
    if (currentFilters.start_date) params.append('start_date', currentFilters.start_date);
    if (currentFilters.end_date) params.append('end_date', currentFilters.end_date);
    if (currentFilters.mac_address) params.append('mac_address', currentFilters.mac_address);
    if (currentFilters.vendor_class) params.append('vendor_class', currentFilters.vendor_class);
    if (currentFilters.message_type) params.append('message_type', currentFilters.message_type);
    if (currentFilters.xid) params.append('xid', currentFilters.xid);

    try {
        const response = await fetch(`/api/logs/count?${params}`);
        const data = await response.json();
        totalRecords = data.count;
        totalCount.textContent = totalRecords.toLocaleString();
        renderPagination();
    } catch (error) {
        console.error('Error loading count:', error);
    }
}

// Render logs in table
function renderLogs(logs) {
    hideLoading();

    if (logs.length === 0) {
        showNoResults();
        return;
    }

    hideNoResults();
    logsBody.innerHTML = '';

    logs.forEach(log => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td class="timestamp">${formatTimestamp(log.timestamp)}</td>
            <td class="mac">${log.mac_address}</td>
            <td>${log.source_ip}:${log.source_port}</td>
            <td><span class="badge badge-${log.message_type.toLowerCase()}">${log.message_type}</span></td>
            <td class="os-info">${log.os_name ? log.os_name + (log.device_class ? ' <span class="device-class">(' + log.device_class + ')</span>' : '') : '-'}</td>
            <td class="vendor">${log.vendor_class || '-'}</td>
            <td class="xid">${log.xid}</td>
            <td class="fingerprint">${log.fingerprint}</td>
        `;
        logsBody.appendChild(row);
    });
}

// Render pagination controls
function renderPagination() {
    const totalPages = Math.ceil(totalRecords / pageSize);

    if (totalPages <= 1) {
        pagination.innerHTML = '';
        return;
    }

    let html = '<div class="page-controls">';

    // Previous button
    if (currentPage > 1) {
        html += `<button class="page-btn" data-page="${currentPage - 1}">← Previous</button>`;
    }

    // Page numbers
    const startPage = Math.max(1, currentPage - 2);
    const endPage = Math.min(totalPages, currentPage + 2);

    if (startPage > 1) {
        html += `<button class="page-btn" data-page="1">1</button>`;
        if (startPage > 2) html += '<span class="page-ellipsis">...</span>';
    }

    for (let i = startPage; i <= endPage; i++) {
        const activeClass = i === currentPage ? 'active' : '';
        html += `<button class="page-btn ${activeClass}" data-page="${i}">${i}</button>`;
    }

    if (endPage < totalPages) {
        if (endPage < totalPages - 1) html += '<span class="page-ellipsis">...</span>';
        html += `<button class="page-btn" data-page="${totalPages}">${totalPages}</button>`;
    }

    // Next button
    if (currentPage < totalPages) {
        html += `<button class="page-btn" data-page="${currentPage + 1}">Next →</button>`;
    }

    html += '</div>';
    pagination.innerHTML = html;

    // Add event listeners to page buttons
    document.querySelectorAll('.page-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            currentPage = parseInt(btn.dataset.page);
            loadLogs();
        });
    });
}

// Apply filters
function applyFilters() {
    currentFilters = {
        start_date: startDate.value ? new Date(startDate.value).toISOString() : null,
        end_date: endDate.value ? new Date(endDate.value).toISOString() : null,
        mac_address: filterMac.value || null,
        vendor_class: filterVendor.value || null,
        message_type: filterType.value || null,
        xid: filterXid.value || null,
    };
    currentPage = 1;
    loadLogs();
}

// Clear filters
function clearFilters() {
    startDate.value = '';
    endDate.value = '';
    filterMac.value = '';
    filterVendor.value = '';
    filterType.value = '';
    filterXid.value = '';
    currentFilters = {
        start_date: null,
        end_date: null,
        mac_address: null,
        vendor_class: null,
        message_type: null,
        xid: null,
    };
    currentPage = 1;
    loadLogs();
}

// Change sort
function changeSort(column) {
    if (currentSort.sort_by === column) {
        // Toggle order
        currentSort.sort_order = currentSort.sort_order === 'DESC' ? 'ASC' : 'DESC';
    } else {
        currentSort.sort_by = column;
        currentSort.sort_order = 'DESC';
    }
    currentPage = 1;
    updateSortIcons();
    loadLogs();
}

// Update sort icons
function updateSortIcons() {
    document.querySelectorAll('.sortable').forEach(th => {
        const icon = th.querySelector('.sort-icon');
        const column = th.dataset.sort;

        if (column === currentSort.sort_by) {
            icon.textContent = currentSort.sort_order === 'DESC' ? '↓' : '↑';
            th.classList.add('sorted');
        } else {
            icon.textContent = '⇅';
            th.classList.remove('sorted');
        }
    });
}

// Export data
async function exportData(format) {
    const params = new URLSearchParams({ format });

    // Add filters
    if (currentFilters.start_date) params.append('start_date', currentFilters.start_date);
    if (currentFilters.end_date) params.append('end_date', currentFilters.end_date);
    if (currentFilters.mac_address) params.append('mac_address', currentFilters.mac_address);
    if (currentFilters.vendor_class) params.append('vendor_class', currentFilters.vendor_class);
    if (currentFilters.message_type) params.append('message_type', currentFilters.message_type);
    if (currentFilters.xid) params.append('xid', currentFilters.xid);

    window.location.href = `/api/logs/export?${params}`;
}

// Format timestamp
function formatTimestamp(timestamp) {
    const date = new Date(timestamp);
    return date.toLocaleString();
}

// UI helpers
function showLoading() {
    loading.style.display = 'block';
    logsBody.style.display = 'none';
    noResults.style.display = 'none';
}

function hideLoading() {
    loading.style.display = 'none';
    logsBody.style.display = '';
}

function showNoResults() {
    noResults.style.display = 'block';
    logsBody.style.display = 'none';
}

function hideNoResults() {
    noResults.style.display = 'none';
}

// Event listeners
btnApplyFilters.addEventListener('click', applyFilters);
btnClearFilters.addEventListener('click', clearFilters);
btnExportCsv.addEventListener('click', () => exportData('csv'));
btnExportJson.addEventListener('click', () => exportData('json'));
pageSizeSelect.addEventListener('change', () => {
    pageSize = parseInt(pageSizeSelect.value);
    currentPage = 1;
    loadLogs();
});

// Add sort listeners to table headers
document.querySelectorAll('.sortable').forEach(th => {
    th.addEventListener('click', () => {
        changeSort(th.dataset.sort);
    });
});

// Initialize
updateSortIcons();
loadLogs();
